// ============================================================================
// src/application/editor/cursor.rs - Cursor and Selection Management
// ============================================================================
//!
//! # Cursor & Selection - カーソル/キャレット管理と選択範囲

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::{max, min};

use super::buffer::TextBuffer;

/// カーソル位置
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    /// 文字位置（バッファ内のインデックス）
    pub position: usize,
    /// 目標カラム（上下移動時に使用）
    pub target_column: usize,
}

impl Cursor {
    /// 新しいカーソルを作成
    pub fn new() -> Self {
        Self {
            position: 0,
            target_column: 0,
        }
    }

    /// 位置を設定
    pub fn set_position(&mut self, pos: usize, buffer: &TextBuffer) {
        self.position = min(pos, buffer.len());
        self.target_column = buffer.column_of(self.position);
    }

    /// 行と列から位置を設定
    pub fn set_line_col(&mut self, line: usize, col: usize, buffer: &TextBuffer) {
        let line = min(line, buffer.line_count().saturating_sub(1));
        self.position = buffer.pos_from_line_col(line, col);
        self.target_column = col;
    }

    /// 現在の行を取得
    pub fn line(&self, buffer: &TextBuffer) -> usize {
        buffer.line_of(self.position)
    }

    /// 現在の列を取得
    pub fn column(&self, buffer: &TextBuffer) -> usize {
        buffer.column_of(self.position)
    }

    /// 左に移動
    pub fn move_left(&mut self, buffer: &TextBuffer) {
        if self.position > 0 {
            self.position -= 1;
            self.target_column = buffer.column_of(self.position);
        }
    }

    /// 右に移動
    pub fn move_right(&mut self, buffer: &TextBuffer) {
        if self.position < buffer.len() {
            self.position += 1;
            self.target_column = buffer.column_of(self.position);
        }
    }

    /// 上に移動
    pub fn move_up(&mut self, buffer: &TextBuffer) {
        let line = self.line(buffer);
        if line > 0 {
            self.position = buffer.pos_from_line_col(line - 1, self.target_column);
        }
    }

    /// 下に移動
    pub fn move_down(&mut self, buffer: &TextBuffer) {
        let line = self.line(buffer);
        if line < buffer.line_count().saturating_sub(1) {
            self.position = buffer.pos_from_line_col(line + 1, self.target_column);
        }
    }

    /// 行頭に移動
    pub fn move_to_line_start(&mut self, buffer: &TextBuffer) {
        let line = self.line(buffer);
        self.position = buffer.line_start(line);
        self.target_column = 0;
    }

    /// 行末に移動
    pub fn move_to_line_end(&mut self, buffer: &TextBuffer) {
        let line = self.line(buffer);
        self.position = buffer.line_end(line);
        self.target_column = buffer.column_of(self.position);
    }

    /// ファイル先頭に移動
    pub fn move_to_start(&mut self) {
        self.position = 0;
        self.target_column = 0;
    }

    /// ファイル末尾に移動
    pub fn move_to_end(&mut self, buffer: &TextBuffer) {
        self.position = buffer.len();
        self.target_column = buffer.column_of(self.position);
    }

    /// 単語単位で左に移動
    pub fn move_word_left(&mut self, buffer: &TextBuffer) {
        if self.position == 0 {
            return;
        }
        
        let text = buffer.text();
        let chars: Vec<char> = text.chars().collect();
        let mut pos = self.position - 1;
        
        // 空白をスキップ
        while pos > 0 && chars[pos].is_whitespace() {
            pos -= 1;
        }
        
        // 単語の先頭まで移動
        while pos > 0 && !chars[pos - 1].is_whitespace() {
            pos -= 1;
        }
        
        self.position = pos;
        self.target_column = buffer.column_of(self.position);
    }

    /// 単語単位で右に移動
    pub fn move_word_right(&mut self, buffer: &TextBuffer) {
        let text = buffer.text();
        let chars: Vec<char> = text.chars().collect();
        let len = chars.len();
        let mut pos = self.position;
        
        // 現在の単語をスキップ
        while pos < len && !chars[pos].is_whitespace() {
            pos += 1;
        }
        
        // 空白をスキップ
        while pos < len && chars[pos].is_whitespace() {
            pos += 1;
        }
        
        self.position = pos;
        self.target_column = buffer.column_of(self.position);
    }

    /// ページアップ
    pub fn page_up(&mut self, buffer: &TextBuffer, page_size: usize) {
        let line = self.line(buffer);
        let new_line = line.saturating_sub(page_size);
        self.position = buffer.pos_from_line_col(new_line, self.target_column);
    }

    /// ページダウン
    pub fn page_down(&mut self, buffer: &TextBuffer, page_size: usize) {
        let line = self.line(buffer);
        let max_line = buffer.line_count().saturating_sub(1);
        let new_line = min(line + page_size, max_line);
        self.position = buffer.pos_from_line_col(new_line, self.target_column);
    }
}

impl Default for Cursor {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Selection - 選択範囲
// ============================================================================

/// 選択範囲
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selection {
    /// 選択開始位置（アンカー）
    pub anchor: usize,
    /// 選択終了位置（カーソル位置）
    pub cursor: usize,
}

impl Selection {
    /// 新しい選択範囲を作成
    pub fn new(anchor: usize, cursor: usize) -> Self {
        Self { anchor, cursor }
    }

    /// 開始位置を取得
    pub fn start(&self) -> usize {
        min(self.anchor, self.cursor)
    }

    /// 終了位置を取得
    pub fn end(&self) -> usize {
        max(self.anchor, self.cursor)
    }

    /// 選択範囲が空かどうか
    pub fn is_empty(&self) -> bool {
        self.anchor == self.cursor
    }

    /// 指定位置が選択範囲内かどうか
    pub fn contains(&self, pos: usize) -> bool {
        pos >= self.start() && pos < self.end()
    }

    /// 選択されたテキストを取得
    pub fn get_text(&self, buffer: &TextBuffer) -> String {
        let text = buffer.text();
        text.chars().skip(self.start()).take(self.end() - self.start()).collect()
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cursor_movement() {
        let buffer = TextBuffer::from_str("Hello\nWorld");
        let mut cursor = Cursor::new();
        
        cursor.move_right(&buffer);
        assert_eq!(cursor.position, 1);
        
        cursor.move_down(&buffer);
        assert!(cursor.line(&buffer) == 1);
    }

    #[test]
    fn test_selection() {
        let sel = Selection::new(5, 10);
        assert_eq!(sel.start(), 5);
        assert_eq!(sel.end(), 10);
        assert!(sel.contains(7));
        assert!(!sel.contains(3));
    }
}
