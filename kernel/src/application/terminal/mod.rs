// ============================================================================
// src/application/terminal/mod.rs - Terminal Module
// ============================================================================
//!
//! # Terminal Emulator Module
//!
//! VT100/ANSI互換ターミナルエミュレータの実装
//!
//! ## サブモジュール
//! - `ansi`: ANSIエスケープシーケンスパーサー
//! - `buffer`: スクロールバック付きリングバッファ
//! - `cell`: ターミナルセルと行
//! - `completer`: タブ補完
//! - `constants`: 定数とカラー定義
//! - `font`: ビットマップフォント
//! - `history`: コマンド履歴とラインエディタ
//! - `keys`: 特殊キー定義
//! - `selection`: テキスト選択とクリップボード
//! - `terminal`: ターミナルエミュレータ本体
//! - `app`: 完全なターミナルアプリケーション
//!
//! ## 機能
//! - VT100/ANSIエスケープシーケンス: 色、カーソル移動、画面クリア
//! - スクロールバック: 1000行のリングバッファ
//! - カーソル点滅: タイマーベース
//! - シェル統合: ExoShellとの連携
//! - readline風ラインエディタ
//! - タブ補完
//! - テキスト選択・クリップボード

#![allow(dead_code)]
#![allow(unused_variables)]

pub mod ansi;
pub mod app;
pub mod buffer;
pub mod cell;
pub mod completer;
pub mod constants;
pub mod font;
pub mod history;
pub mod keys;
pub mod selection;
pub mod terminal;

// Re-exports
pub use ansi::{AnsiParser, ParseAction};
pub use app::TerminalApp;
pub use buffer::TerminalBuffer;
pub use cell::{Cell, TerminalLine};
pub use completer::{CompletionCallback, TabCompleter};
pub use constants::*;
pub use font::get_char_bitmap_8x16;
pub use history::{CommandHistory, LineEditor};
pub use keys::SpecialKey;
pub use selection::{Clipboard, Selection, CLIPBOARD};
pub use terminal::Terminal;

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terminal_creation() {
        let term = Terminal::new();
        assert!(term.is_running());
        assert_eq!(term.cursor_position(), (0, 0));
    }

    #[test]
    fn test_ansi_parser_colors() {
        let mut parser = AnsiParser::new();
        
        // ESC[31m (赤色)
        assert!(matches!(parser.feed('\x1b'), ParseAction::None));
        assert!(matches!(parser.feed('['), ParseAction::None));
        assert!(matches!(parser.feed('3'), ParseAction::None));
        assert!(matches!(parser.feed('1'), ParseAction::None));
        
        if let ParseAction::Sgr(params) = parser.feed('m') {
            assert_eq!(params, vec![31]);
        } else {
            panic!("Expected SGR action");
        }
    }

    #[test]
    fn test_ansi_parser_cursor() {
        let mut parser = AnsiParser::new();
        
        // ESC[5A (カーソルを5行上に)
        parser.feed('\x1b');
        parser.feed('[');
        parser.feed('5');
        
        if let ParseAction::CursorUp(n) = parser.feed('A') {
            assert_eq!(n, 5);
        } else {
            panic!("Expected CursorUp action");
        }
    }

    #[test]
    fn test_terminal_write() {
        let mut term = Terminal::new();
        
        term.write_str("Hello");
        assert_eq!(term.cursor_position(), (5, 0));
        
        term.write_char('\n');
        assert_eq!(term.cursor_position(), (5, 1));
        
        term.write_char('\r');
        assert_eq!(term.cursor_position(), (0, 1));
    }

    #[test]
    fn test_cell_default() {
        let cell = Cell::default();
        assert_eq!(cell.ch, ' ');
        assert!(!cell.bold);
        assert!(!cell.underline);
        assert!(!cell.inverse);
    }

    #[test]
    fn test_color_from_256() {
        // 標準色
        let c0 = color_from_256(0);
        assert_eq!(c0.red, ANSI_COLORS[0].red);
        
        // 高輝度色
        let c8 = color_from_256(8);
        assert_eq!(c8.red, ANSI_BRIGHT_COLORS[0].red);
        
        // グレースケール
        let gray = color_from_256(232);
        assert_eq!(gray.red, gray.green);
        assert_eq!(gray.green, gray.blue);
    }
}
