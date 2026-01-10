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

use spin::Mutex;
use alloc::vec;

use crate::graphics::Color;
use crate::shell::exoshell::ExoShell;

use super::shell::GraphicalShell;

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

    // Create owned Framebuffer from KAPI info
    let framebuffer = unsafe { crate::graphics::Framebuffer::from_kapi_info(&fb_info) };

    // グラフィカルシェルを作成（フレームバッファを所有）
    let shell = GraphicalShell::new(framebuffer);

    *GRAPHICAL_SHELL.lock() = Some(shell);
    info!(target: "gshell", "Graphical shell created successfully");
}

/// グラフィカルシェルを開始
pub fn start() {
    use log::info;

    let mut guard = GRAPHICAL_SHELL.lock();
    if let Some(ref mut shell) = *guard {
        // Enable double buffering on the shell's owned framebuffer
        let buffer_size = shell.framebuffer.info().size();
        if buffer_size > 0 {
            let backing_buffer = vec![0u8; buffer_size];
            shell
                .framebuffer
                .enable_double_buffering_from_vec(backing_buffer);
        } else {
            shell.framebuffer.enable_double_buffering();
        }

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

/// 非同期タスクとしてグラフィカルシェルを実行
///
/// ## 設計
/// - `GraphicalFrontend` が入力ループと描画を駆動 (ShellFrontendトレイト)
/// - `ExoShell` でコマンド実行
pub async fn run_async_shell() {
    use log::info;
    use crate::shell::exoshell::frontend::graphical::GraphicalFrontend;
    use crate::shell::exoshell::frontend::ShellFrontend;

    info!(target: "gshell", "Starting async graphical shell task (frontend-driven)...");

    let mut frontend = GraphicalFrontend::new();

    // Acquire ExoShell (take ownership for this task)
    let mut exoshell = {
        let mut guard = ASYNC_EXOSHELL.lock();
        if guard.is_none() {
             // Fallback if not initialized (should stay in init, but safe guard)
             *guard = Some(ExoShell::new());
        }
        guard.take().unwrap()
    };

    loop {
        // Block until line is entered (while handling UI events internally)
        if let Some(line) = frontend.read_line(&mut exoshell).await {
            // Execute command
            let result = exoshell.eval(&line).await;
            
            // Display result
            frontend.print_result(&Ok(result));
            
            // Loop automatically handles next prompt via read_line syncing
        }
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
