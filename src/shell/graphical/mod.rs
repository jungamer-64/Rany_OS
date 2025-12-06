// ============================================================================
// src/shell/graphical/mod.rs - Graphical Shell Module
// ============================================================================
//!
//! # グラフィカルシェル
//!
//! フレームバッファ上で動作するグラフィカルなシェル環境。
//! テキストコンソールとExoShellを統合し、視覚的なREPL体験を提供。
//!
//! ## 機能
//! - フレームバッファへのテキスト描画
//! - 行編集（カーソル移動、削除、挿入）
//! - コマンド履歴（上下キー）
//! - Tab補完
//! - ANSIカラーサポート
//! - スクロールバック

mod types;
mod shell;
mod render;
mod input;
mod async_runtime;

// Re-export types
pub use types::{
    ShellTheme, LineBuffer, ConsoleLine, MouseState,
    MAX_HISTORY, MAX_LINE_LENGTH, SCROLLBACK_LINES, CURSOR_BLINK_MS,
    FONT_WIDTH, FONT_HEIGHT,
};

// Re-export shell
pub use shell::GraphicalShell;

// Re-export async runtime functions
pub use async_runtime::{
    init, start, with_shell, poll,
    submit_command, run_async_shell,
    print, print_colored,
};
