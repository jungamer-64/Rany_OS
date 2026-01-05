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

mod async_runtime;
mod input;
mod render;
mod shell;
pub mod streams;
mod types;
pub mod utils;

// Re-export types
#[cfg(feature = "mouse")]
pub use types::{MouseState, RenderMouseState};

// Re-export shell

// Re-export async runtime functions
pub use async_runtime::{init, run_async_shell, start};

// Re-export stream types (for submit_command)
