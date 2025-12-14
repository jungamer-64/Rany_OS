// ============================================================================
// src/shell/graphical/async_runtime.rs - Graphical Shell Async Runtime
// ============================================================================
//!
//! # グラフィカルシェル非同期ランタイム
//!
//! グローバルインスタンスと非同期コマンドシステムの管理
//!
//! ## Async-First設計
//! - Waker駆動のコマンドキュー
//! - 割り込みベースのキーボード入力
//! - 省電力（C-state対応）

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::format;
use alloc::vec;
use spin::Mutex;

use crate::graphics::Color;
use crate::io::hid::{keyboard, poll_input_event, KeyEvent, KeyCode, KeyState, Modifiers};
#[cfg(feature = "mouse")]
use crate::io::hid::poll_mouse_event;
use crate::shell::exoshell::{ExoShell, ExoValue};
use kernel_api::gui::{InputEvent, KeyEvent as KapiKeyEvent, KeyState as KapiKeyState};
use kernel_api::services::kernel;

use super::shell::GraphicalShell;
use super::streams::{CommandQueueStream, CommandResult, poll_result, push_result};

// ============================================================================
// Global State
// ============================================================================

static GRAPHICAL_SHELL: Mutex<Option<GraphicalShell>> = Mutex::new(None);
static ASYNC_EXOSHELL: Mutex<Option<ExoShell>> = Mutex::new(None);

// ============================================================================
// Public API
// ============================================================================

/// グラフィカルシェルを初期化
pub fn init() {
    use kernel_api::services::kernel;
    use log::info;

    info!(target: "gshell", "Initializing graphical shell...");

    // 非同期ExoShellを初期化
    *ASYNC_EXOSHELL.lock() = Some(ExoShell::new());
    info!(target: "gshell", "Async ExoShell initialized");

    // GuiServices経由でフレームバッファ可用性をチェック
    let gui_services = kernel().gui();
    if gui_services.is_none() {
        info!(target: "gshell", "No GUI services available - skipping graphical shell");
        return;
    }
    
    // CapabilityでFramebufferInfoを取得（デモ用: カーネル権限を使用）
    let fb_info = {
        // SAFETY: Kernel context has full capabilities
        let caps = unsafe { kernel_api::security::kernel_only::grant_all() };
        gui_services.unwrap().request_framebuffer(&caps)
    };
    
    if let Err(e) = fb_info {
        info!(target: "gshell", "Failed to request framebuffer via GuiServices: {:?}", e);
        return;
    }
    
    let fb_info = fb_info.unwrap();
    info!(target: "gshell", "Framebuffer via GuiServices: {}x{} stride={}", 
          fb_info.width, fb_info.height, fb_info.stride);

    // グラフィカルシェルを作成（既存のdims取得を継続）
    let shell = GraphicalShell::new(fb_info.width as u32, fb_info.height as u32);

    *GRAPHICAL_SHELL.lock() = Some(shell);
    info!(target: "gshell", "Graphical shell created successfully");
}

/// グラフィカルシェルを開始
pub fn start() {
    use log::info;

    // 1. 必要なバッファサイズを取得（ロックは一瞬だけ）
    let buffer_size = crate::graphics::with_framebuffer(|fb| fb.info().size()).unwrap_or(0);

    // 2. バッファを確保（ロック外で行うため、アロケーションログによるデッドロックを回避）
    let backing_buffer = if buffer_size > 0 {
        Some(vec![0u8; buffer_size])
    } else {
        None
    };

    // 3. シェルを開始（バッファを渡す）
    crate::graphics::with_framebuffer(|fb| {
        // 確保したバッファがあれば設定
        if let Some(buf) = backing_buffer {
            fb.enable_double_buffering_from_vec(buf);
        } else {
            // サイズ取得失敗時は従来通り（リスクありだがフォールバック）
            fb.enable_double_buffering();
        }

        if let Some(ref mut shell) = *GRAPHICAL_SHELL.lock() {
            shell.start(fb);
            info!(target: "gshell", "Graphical shell started");
        } else {
            info!(target: "gshell", "Cannot start - no shell instance");
        }
    });
}

/// グラフィカルシェルにアクセス
pub fn with_shell<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut GraphicalShell) -> R,
{
    GRAPHICAL_SHELL.lock().as_mut().map(f)
}

/// 非同期タスクとしてグラフィカルシェルを実行
///
/// ## 設計
/// - コマンドキューは Waker 駆動（イベント到着時のみ起床）
/// - キーボードは KeyboardStream で Waker 駆動
/// - マウスは従来のポーリング（TODO: MouseStream化）
/// - カーソル点滅は定期的なyieldで処理
pub async fn run_async_shell() {
    use crate::io::hid::poll_input_event;
    use log::info;

    info!(target: "gshell", "Starting async graphical shell task (event-driven)...");

    let mut cmd_stream = CommandQueueStream::new();
    let mut input_poll_counter = 0u32;

    loop {
        // ========================================
        // Phase 1: 入力イベント処理
        // ========================================
        // Get current tick via GuiServices before entering framebuffer lock
        let current_time = kernel().gui().map(|g| g.current_tick()).unwrap_or(0);
        
        crate::graphics::with_framebuffer(|fb| {
            let mut guard = GRAPHICAL_SHELL.lock();
            if let Some(ref mut shell) = *guard {
                // キーボード: KeyboardStreamを試行
                if let Ok(mut stream) = keyboard().take_stream() {
                    if let Some(key_event) = stream.poll() {
                        shell.handle_key(key_event, fb);
                    }
                } else {
                    // フォールバック: GuiServices経由でポーリング (Cell分離アーキテクチャ)
                    if let Some(gui_services) = kernel().gui() {
                        for _ in 0..8 {
                            if let Some(input_event) = gui_services.poll_input_event() {
                                match input_event {
                                    InputEvent::Key(kapi_key) => {
                                        // Convert kernel_api::gui::KeyEvent to internal HID KeyEvent
                                        let state = match kapi_key.state {
                                            KapiKeyState::Pressed => KeyState::Pressed,
                                            KapiKeyState::Released => KeyState::Released,
                                        };
                                        let modifiers = Modifiers {
                                            shift: (kapi_key.modifiers & 0x01) != 0,
                                            ctrl: (kapi_key.modifiers & 0x02) != 0,
                                            alt: (kapi_key.modifiers & 0x04) != 0,
                                            alt_gr: (kapi_key.modifiers & 0x08) != 0,
                                            caps_lock: (kapi_key.modifiers & 0x10) != 0,
                                            num_lock: false,
                                            scroll_lock: false,
                                        };
                                        let hid_event = KeyEvent {
                                            key: KeyCode::Unknown,
                                            state,
                                            modifiers,
                                            raw_scancode: kapi_key.scancode,
                                        };
                                        shell.handle_key(hid_event, fb);
                                    }
                                    InputEvent::Mouse(_mouse) => {
                                        // Mouse handled below via feature flag
                                    }
                                }
                            } else {
                                break;
                            }
                        }
                    } else {
                        // No GuiServices - fallback to direct HID polling
                        for _ in 0..8 {
                            if let Some(event) = poll_input_event() {
                                shell.handle_key(event, fb);
                            } else {
                                break;
                            }
                        }
                    }
                }


                #[cfg(feature = "mouse")]
                {
                    // マウス: ポーリング（TODO: GuiServices経由）
                    for _ in 0..8 {
                        if let Some(event) = poll_mouse_event() {
                            shell.handle_mouse(event, fb);
                        } else {
                            break;
                        }
                    }
                }

                // 結果キューをチェックして表示
                while let Some(result) = poll_result() {
                    let output = format!("{}\n", result.output);

                    if result.is_error {
                        let error_color = shell.resources.theme.error;
                        shell.print_colored(&output, error_color);
                    } else {
                        let fg_color = shell.resources.theme.foreground;
                        shell.print_colored(&output, fg_color);
                    }

                    shell.state.is_executing = false;
                    shell.redraw(fb);
                }

                // カーソル点滅を更新（定期的）
                input_poll_counter = input_poll_counter.wrapping_add(1);
                if input_poll_counter % 10 == 0 {
                    shell.update_cursor(current_time, fb);
                }
            }
        });

        // ========================================
        // Phase 2: コマンド実行（Waker駆動）
        // ========================================
        // 非ブロッキングでコマンドキューをポーリング
        // Context はawaitをまたげないので、ポーリング結果を先に取得
        let maybe_request = {
            use core::future::Future;
            use core::pin::Pin;
            use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

            fn dummy_raw_waker() -> RawWaker {
                fn no_op(_: *const ()) {}
                fn clone_fn(ptr: *const ()) -> RawWaker {
                    RawWaker::new(ptr, &VTABLE)
                }
                static VTABLE: RawWakerVTable = RawWakerVTable::new(clone_fn, no_op, no_op, no_op);
                RawWaker::new(core::ptr::null(), &VTABLE)
            }

            let waker = unsafe { Waker::from_raw(dummy_raw_waker()) };
            let mut cx = Context::from_waker(&waker);

            let mut cmd_future = cmd_stream.next();
            match Pin::new(&mut cmd_future).poll(&mut cx) {
                Poll::Ready(req) => Some(req),
                Poll::Pending => None,
            }
            // waker と cx はここでドロップ
        };

        // awaitの外でコマンドを実行
        if let Some(req) = maybe_request {
            let shell_opt = {
                let mut guard = ASYNC_EXOSHELL.lock();
                guard.take()
            };

            if let Some(mut exoshell) = shell_opt {
                let result = exoshell.eval(&req.command).await;
                let output = format!("{}", result);
                let is_error = matches!(result, ExoValue::Error(_));

                *ASYNC_EXOSHELL.lock() = Some(exoshell);

                push_result(CommandResult {
                    id: req.id,
                    output,
                    is_error,
                });
            } else {
                // ExoShellがビジー - リクエストを再キュー
                super::streams::submit_command(req.command);
            }
        }

        // ========================================
        // Phase 3: 他のタスクに譲る
        // ========================================
        crate::task::yield_now().await;
    }
}

/// テキストを出力
pub fn print(text: &str) {
    if let Some(ref mut shell) = *GRAPHICAL_SHELL.lock() {
        shell.print(text);
    }
}

/// 色付きテキストを出力
pub fn print_colored(text: &str, color: Color) {
    if let Some(ref mut shell) = *GRAPHICAL_SHELL.lock() {
        shell.print_colored(text, color);
    }
}
