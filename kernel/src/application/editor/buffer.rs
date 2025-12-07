// ============================================================================
// src/application/editor/buffer.rs - Text Buffer
// ============================================================================
//!
//! # TextBuffer - エディタ用テキストバッファ

extern crate alloc;

use alloc::string::String;
use core::cmp::min;

use crate::fs::memfs::{read_file_content, write_file_content};
use super::rope::RopeNode;

/// テキストバッファ
pub struct TextBuffer {
    /// Ropeデータ構造
    rope: RopeNode,
    /// 変更フラグ
    modified: bool,
    /// ファイルパス
    file_path: Option<String>,
}

impl TextBuffer {
    /// 新しい空のバッファを作成
    pub fn new() -> Self {
        Self {
            rope: RopeNode::new(),
            modified: false,
            file_path: None,
        }
    }

    /// テキストからバッファを作成
    pub fn from_str(s: &str) -> Self {
        Self {
            rope: RopeNode::from_str(s),
            modified: false,
            file_path: None,
        }
    }

    /// ファイルを開く
    pub fn open(path: &str, cwd: &str) -> Result<Self, &'static str> {
        match read_file_content(path, cwd) {
            Ok(content) => {
                let text = String::from_utf8(content).map_err(|_| "Invalid UTF-8")?;
                let mut buffer = Self::from_str(&text);
                buffer.file_path = Some(String::from(path));
                buffer.modified = false;
                Ok(buffer)
            }
            Err(_) => Err("Failed to read file"),
        }
    }

    /// ファイルに保存
    pub fn save(&mut self, cwd: &str) -> Result<(), &'static str> {
        let path = self.file_path.as_ref().ok_or("No file path set")?;
        let content = self.rope.to_string();
        write_file_content(path, cwd, content.as_bytes())
            .map_err(|_| "Failed to write file")?;
        self.modified = false;
        Ok(())
    }

    /// 名前を付けて保存
    pub fn save_as(&mut self, path: &str, cwd: &str) -> Result<(), &'static str> {
        self.file_path = Some(String::from(path));
        self.save(cwd)
    }

    /// 文字を挿入
    pub fn insert_char(&mut self, pos: usize, ch: char) {
        let mut s = String::new();
        s.push(ch);
        self.rope.insert(pos, &s);
        self.modified = true;
    }

    /// 文字列を挿入
    pub fn insert_str(&mut self, pos: usize, s: &str) {
        self.rope.insert(pos, s);
        self.modified = true;
    }

    /// 文字を削除
    pub fn delete_char(&mut self, pos: usize) {
        if pos < self.rope.len() {
            self.rope.delete(pos, pos + 1);
            self.modified = true;
        }
    }

    /// 範囲を削除
    pub fn delete_range(&mut self, start: usize, end: usize) {
        self.rope.delete(start, end);
        self.modified = true;
    }

    /// 全テキストを取得
    pub fn text(&self) -> String {
        self.rope.to_string()
    }

    /// 行のテキストを取得
    pub fn get_line(&self, line: usize) -> String {
        self.rope.get_line(line)
    }

    /// 行数を取得
    pub fn line_count(&self) -> usize {
        self.rope.lines()
    }

    /// 文字数を取得
    pub fn len(&self) -> usize {
        self.rope.len()
    }

    /// 空かどうか
    pub fn is_empty(&self) -> bool {
        self.rope.is_empty()
    }

    /// 変更されているか
    pub fn is_modified(&self) -> bool {
        self.modified
    }

    /// ファイルパスを取得
    pub fn path(&self) -> Option<&String> {
        self.file_path.as_ref()
    }

    /// ファイルパスを設定
    pub fn set_path(&mut self, path: &str) {
        self.file_path = Some(String::from(path));
    }

    /// 保存済みとしてマーク
    pub fn mark_saved(&mut self) {
        self.modified = false;
    }

    /// ファイルパスを取得 (deref版)
    pub fn file_path(&self) -> Option<&str> {
        self.file_path.as_deref()
    }

    /// ファイル名を取得
    pub fn file_name(&self) -> Option<&str> {
        self.file_path.as_ref().and_then(|p| p.rsplit('/').next())
    }

    /// 行の開始位置を取得
    pub fn line_start(&self, line: usize) -> usize {
        self.rope.line_start(line)
    }

    /// 行の終了位置を取得
    pub fn line_end(&self, line: usize) -> usize {
        self.rope.line_end(line)
    }

    /// 位置から行番号を取得
    pub fn line_of(&self, pos: usize) -> usize {
        self.rope.line_of(pos)
    }

    /// 位置から列番号を取得
    pub fn column_of(&self, pos: usize) -> usize {
        self.rope.column_of(pos)
    }

    /// 行と列から位置を取得
    pub fn pos_from_line_col(&self, line: usize, col: usize) -> usize {
        let line_start = self.line_start(line);
        let line_len = self.line_end(line) - line_start;
        line_start + min(col, line_len)
    }
}

impl Default for TextBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_text_buffer_insert() {
        let mut buf = TextBuffer::new();
        buf.insert_char(0, 'H');
        buf.insert_char(1, 'i');
        assert_eq!(buf.text(), "Hi");
        assert!(buf.is_modified());
    }
}
