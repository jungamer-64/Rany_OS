// ============================================================================
// src/shell/graphical/async_runtime.rs - Graphical Shell Async Runtime
// ============================================================================
//!
//! # グラフィカルシェル非同期ランタイム
//!
//! グローバルインスタンスと非同期コマンドシステムの管理
//! fb は with_framebuffer で取得し、shell メソッドに渡す（unsafe なし）

#![allow(dead_code)]

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use spin::Mutex;

use crate::graphics::Color;
use crate::io::hid::{poll_input_event, poll_mouse_event};
use crate::shell::exoshell::{ExoShell, ExoValue};

use super::shell::GraphicalShell;

// ============================================================================
// Async Command Types
// ============================================================================

/// 非同期コマンドリクエスト
struct AsyncCommandRequest {
    command: String,
    id: u64,
}

/// 非同期コマンド結果
struct AsyncCommandResult {
    id: u64,
    output: String,
    is_error: bool,
}

// ============================================================================
// Global State
// ============================================================================

static GRAPHICAL_SHELL: Mutex<Option<GraphicalShell>> = Mutex::new(None);
static ASYNC_EXOSHELL: Mutex<Option<ExoShell>> = Mutex::new(None);
static COMMAND_QUEUE: Mutex<VecDeque<AsyncCommandRequest>> = Mutex::new(VecDeque::new());
static RESULT_QUEUE: Mutex<VecDeque<AsyncCommandResult>> = Mutex::new(VecDeque::new());
static NEXT_REQUEST_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

// ============================================================================
// Public API
// ============================================================================

/// グラフィカルシェルを初期化
pub fn init() {
    use log::info;
    
    info!(target: "gshell", "Initializing graphical shell...");
    
    // 非同期ExoShellを初期化
    *ASYNC_EXOSHELL.lock() = Some(ExoShell::new());
    info!(target: "gshell", "Async ExoShell initialized");
    
    // フレームバッファを取得
    let fb = crate::graphics::framebuffer();
    if fb.is_none() {
        info!(target: "gshell", "No framebuffer available - skipping graphical shell");
        return;
    }
    
    info!(target: "gshell", "Framebuffer found, creating shell...");

    // グラフィカルシェルを作成
    let dims = crate::graphics::with_framebuffer(|fb| {
        (fb.width(), fb.height())
    });
    
    let shell = dims.map(|(w, h)| GraphicalShell::new(w, h));

    if let Some(shell) = shell {
        *GRAPHICAL_SHELL.lock() = Some(shell);
        info!(target: "gshell", "Graphical shell created successfully");
    } else {
        info!(target: "gshell", "Failed to create graphical shell");
    }
}

/// グラフィカルシェルを開始
pub fn start() {
    use log::info;
    use alloc::vec;

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

/// コマンドを非同期キューに追加
pub fn submit_command(command: String) -> u64 {
    use core::sync::atomic::Ordering;
    
    let id = NEXT_REQUEST_ID.fetch_add(1, Ordering::SeqCst);
    COMMAND_QUEUE.lock().push_back(AsyncCommandRequest {
        command,
        id,
    });
    id
}

/// 非同期タスクとしてグラフィカルシェルを実行
pub async fn run_async_shell() {
    use log::info;
    
    info!(target: "gshell", "Starting async graphical shell task...");
    
    loop {
        // フェーズ1: キー/マウスイベントとUI更新
        crate::graphics::with_framebuffer(|fb| {
            let mut guard = GRAPHICAL_SHELL.lock();
            if let Some(ref mut shell) = *guard {
                // キーイベントを処理（最大16イベントずつ）
                for _ in 0..16 {
                    if let Some(event) = poll_input_event() {
                        shell.handle_key(event, fb);
                    } else {
                        break;
                    }
                }
                
                // マウスイベントを処理（最大16イベントずつ）
                for _ in 0..16 {
                    if let Some(event) = poll_mouse_event() {
                        shell.handle_mouse(event, fb);
                    } else {
                        break;
                    }
                }
                
                // 結果キューをチェックして表示
                process_results(shell, fb);
                
                // カーソル点滅を更新
                let current_time = crate::task::timer::current_tick();
                shell.update_cursor(current_time, fb);
            }
        });
        
        // フェーズ2: 非同期コマンド実行（ロック外）
        let request = COMMAND_QUEUE.lock().pop_front();
        
        if let Some(req) = request {
            let shell_opt = {
                let mut guard = ASYNC_EXOSHELL.lock();
                guard.take()
            };
            
            if let Some(mut exoshell) = shell_opt {
                let result = exoshell.eval(&req.command).await;
                let output = format!("{}", result);
                let is_error = matches!(result, ExoValue::Error(_));
                
                *ASYNC_EXOSHELL.lock() = Some(exoshell);
                
                RESULT_QUEUE.lock().push_back(AsyncCommandResult {
                    id: req.id,
                    output,
                    is_error,
                });
            } else {
                COMMAND_QUEUE.lock().push_front(req);
                crate::task::yield_now().await;
                continue;
            }
        }
        
        crate::task::yield_now().await;
    }
}

/// 結果キューを処理してGraphicalShellに表示
fn process_results(shell: &mut GraphicalShell, fb: &mut crate::graphics::Framebuffer) {
    while let Some(result) = RESULT_QUEUE.lock().pop_front() {
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
