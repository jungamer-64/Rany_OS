// ============================================================================
// src/application/editor/mod.rs - GUI Text Editor Module
// ============================================================================
//!
//! # GUI Text Editor
//!
//! マウス操作とキーボード入力に対応したGUIベースのテキストエディタ
//!
//! ## 機能
//! - Rope構造体による効率的なテキストバッファ
//! - キャレット制御（矢印キー、マウスクリック）
//! - ファイルI/O（Open / Save）
//! - Rustシンタックスハイライト

#![allow(dead_code)]
#![allow(unused_variables)]

mod constants;
mod rope;
mod buffer;
mod cursor;
mod syntax;
mod font;
mod types;
mod editor_core;

// Re-exports
pub use constants::*;
pub use rope::RopeNode;
pub use buffer::TextBuffer;
pub use cursor::{Cursor, Selection};
pub use syntax::{SyntaxHighlighter, Token, TokenType, RUST_KEYWORDS, RUST_TYPES};
pub use types::{EditorMode, ToolbarButton};
pub use editor_core::{Editor, SpecialKey};
pub use font::get_char_bitmap;
