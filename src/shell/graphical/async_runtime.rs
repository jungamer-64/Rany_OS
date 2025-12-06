// ============================================================================
// src/shell/graphical/async_runtime.rs - Graphical Shell Async Runtime
// ============================================================================
//!
//! # グラフィカルシェル非同期ランタイム
//!
//! グローバルインスタンスと非同期コマンドシステムの管理

#![allow(dead_code)]

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use spin::Mutex;

use crate::graphics::Color;
use crate::input::{poll_event, poll_mouse_event};
use crate::shell::exoshell::{ExoShell, ExoValue};

use super::shell::GraphicalShell;

// ============================================================================
// Async Command Types
// ============================================================================

/// 非同期コマンドリクエスト
struct AsyncCommandRequest {
    /// コマンド文字列
    command: String,
    /// リクエストID
    id: u64,
}

/// 非同期コマンド結果
struct AsyncCommandResult {
    /// 対応するリクエストID
    id: u64,
    /// 結果文字列
    output: String,
    /// エラーかどうか
    is_error: bool,
}

// ============================================================================
// Global State
// ============================================================================

static GRAPHICAL_SHELL: Mutex<Option<GraphicalShell>> = Mutex::new(None);

/// 非同期評価用のExoShell（別Mutexで管理）
static ASYNC_EXOSHELL: Mutex<Option<ExoShell>> = Mutex::new(None);

/// コマンドリクエストキュー（GraphicalShell -> async task）
static COMMAND_QUEUE: Mutex<VecDeque<AsyncCommandRequest>> = Mutex::new(VecDeque::new());

/// コマンド結果キュー（async task -> GraphicalShell）
static RESULT_QUEUE: Mutex<VecDeque<AsyncCommandResult>> = Mutex::new(VecDeque::new());

/// 次のリクエストID
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
    let shell = crate::graphics::with_framebuffer(|fb| {
        GraphicalShell::new(fb)
    });

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
    
    if let Some(ref mut shell) = *GRAPHICAL_SHELL.lock() {
        shell.start();
        info!(target: "gshell", "Graphical shell started");
    } else {
        info!(target: "gshell", "Cannot start - no shell instance");
    }
}

/// グラフィカルシェルにアクセス
pub fn with_shell<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut GraphicalShell) -> R,
{
    GRAPHICAL_SHELL.lock().as_mut().map(f)
}

/// ポーリング処理（デバッグ用・非推奨）
/// 通常は run_async_shell() を使用してください
#[allow(dead_code)]
pub fn poll() {
    if let Some(ref mut shell) = *GRAPHICAL_SHELL.lock() {
        shell.poll();
    }
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
/// ExoShellの所有権を一時的に取り出してasync eval()を呼び出す
pub async fn run_async_shell() {
    use log::info;
    
    info!(target: "gshell", "Starting async graphical shell task...");
    
    loop {
        // フェーズ1: キー/マウスイベントとUI更新（GraphicalShellロック内）
        {
            let mut guard = GRAPHICAL_SHELL.lock();
            if let Some(ref mut shell) = *guard {
                // キーイベントを処理（最大16イベントずつ処理してUIの応答性を保つ）
                for _ in 0..16 {
                    if let Some(event) = poll_event() {
                        shell.handle_key(event);
                    } else {
                        break;
                    }
                }
                
                // マウスイベントを処理（最大16イベントずつ）
                for _ in 0..16 {
                    if let Some(event) = poll_mouse_event() {
                        shell.handle_mouse(event);
                    } else {
                        break;
                    }
                }
                
                // 結果キューをチェックして表示
                process_results(shell);
                
                // カーソル点滅を更新
                let current_time = crate::task::timer::current_tick();
                shell.update_cursor(current_time);
            }
        }
        
        // フェーズ2: 非同期コマンド実行（ロック外）
        let request = COMMAND_QUEUE.lock().pop_front();
        
        if let Some(req) = request {
            // ExoShellを一時的に取り出す（ノンブロッキング）
            let shell_opt = {
                let mut guard = ASYNC_EXOSHELL.lock();
                guard.take()
            };
            
            if let Some(mut exoshell) = shell_opt {
                // ロック外でasync eval()を呼び出し
                let result = exoshell.eval(&req.command).await;
                let output = format!("{}", result);
                let is_error = matches!(result, ExoValue::Error(_));
                
                // ExoShellを戻す
                *ASYNC_EXOSHELL.lock() = Some(exoshell);
                
                // 結果をキューに入れる
                RESULT_QUEUE.lock().push_back(AsyncCommandResult {
                    id: req.id,
                    output,
                    is_error,
                });
            } else {
                // ExoShellがない場合 - コマンドをキューに戻す
                COMMAND_QUEUE.lock().push_front(req);
                // 短い待機後にリトライ
                crate::task::yield_now().await;
                continue;
            }
        }
        
        // 他のタスクに譲る
        crate::task::yield_now().await;
    }
}

/// 結果キューを処理してGraphicalShellに表示
fn process_results(shell: &mut GraphicalShell) {
    while let Some(result) = RESULT_QUEUE.lock().pop_front() {
        let output = format!("{}\n", result.output);
        
        if result.is_error {
            let error_color = shell.theme.error;
            shell.print_colored(&output, error_color);
        } else {
            let fg_color = shell.theme.foreground;
            shell.print_colored(&output, fg_color);
        }
        
        shell.is_executing = false;
        shell.draw_prompt();
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
