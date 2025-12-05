// ============================================================================
// src/application/editor.rs - GUI Text Editor Application
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

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use alloc::vec;
use alloc::format;
use core::cmp::{min, max};

use crate::graphics::{Color, image::Image, Rect};
use crate::fs::memfs::{read_file_content, write_file_content};

// ============================================================================
// Constants
// ============================================================================

/// エディタウィンドウの幅
pub const EDITOR_WIDTH: u32 = 900;
/// エディタウィンドウの高さ
pub const EDITOR_HEIGHT: u32 = 700;

/// 文字幅 (ピクセル)
const CHAR_WIDTH: u32 = 8;
/// 文字高さ (ピクセル)
const CHAR_HEIGHT: u32 = 16;

/// ツールバーの高さ
const TOOLBAR_HEIGHT: u32 = 28;
/// 行番号の幅（文字数）
const LINE_NUMBER_WIDTH: usize = 5;
/// 行番号表示に使うピクセル幅
const LINE_NUMBER_PIXEL_WIDTH: u32 = (LINE_NUMBER_WIDTH as u32 + 1) * CHAR_WIDTH;

/// 編集エリアの開始X座標
const EDIT_AREA_X: u32 = LINE_NUMBER_PIXEL_WIDTH;
/// 編集エリアの開始Y座標
const EDIT_AREA_Y: u32 = TOOLBAR_HEIGHT;

/// 編集エリアの幅
const EDIT_AREA_WIDTH: u32 = EDITOR_WIDTH - EDIT_AREA_X;
/// 編集エリアの高さ
const EDIT_AREA_HEIGHT: u32 = EDITOR_HEIGHT - EDIT_AREA_Y;

/// 表示可能な行数
const VISIBLE_LINES: usize = (EDIT_AREA_HEIGHT / CHAR_HEIGHT) as usize;
/// 表示可能なカラム数
const VISIBLE_COLS: usize = (EDIT_AREA_WIDTH / CHAR_WIDTH) as usize;

/// タブ幅
const TAB_WIDTH: usize = 4;

// ============================================================================
// Colors
// ============================================================================

/// 背景色
const BG_COLOR: Color = Color { red: 30, green: 30, blue: 30, alpha: 255 };
/// テキスト色
const TEXT_COLOR: Color = Color { red: 220, green: 220, blue: 220, alpha: 255 };
/// 行番号の色
const LINE_NUMBER_COLOR: Color = Color { red: 100, green: 100, blue: 100, alpha: 255 };
/// 行番号背景色
const LINE_NUMBER_BG: Color = Color { red: 40, green: 40, blue: 40, alpha: 255 };
/// 現在行のハイライト色
const CURRENT_LINE_BG: Color = Color { red: 45, green: 45, blue: 45, alpha: 255 };
/// カーソル色
const CURSOR_COLOR: Color = Color { red: 255, green: 255, blue: 255, alpha: 255 };
/// 選択範囲の色
const SELECTION_COLOR: Color = Color { red: 70, green: 100, blue: 150, alpha: 255 };
/// ツールバー背景色
const TOOLBAR_BG: Color = Color { red: 50, green: 50, blue: 50, alpha: 255 };
/// ボタン色
const BUTTON_COLOR: Color = Color { red: 70, green: 70, blue: 70, alpha: 255 };
/// ボタンホバー色
const BUTTON_HOVER_COLOR: Color = Color { red: 90, green: 90, blue: 90, alpha: 255 };

// シンタックスハイライト色
/// キーワード色 (fn, let, mut, etc.)
const KEYWORD_COLOR: Color = Color { red: 198, green: 120, blue: 221, alpha: 255 };
/// 型の色
const TYPE_COLOR: Color = Color { red: 86, green: 182, blue: 194, alpha: 255 };
/// 文字列の色
const STRING_COLOR: Color = Color { red: 152, green: 195, blue: 121, alpha: 255 };
/// コメントの色
const COMMENT_COLOR: Color = Color { red: 92, green: 99, blue: 112, alpha: 255 };
/// 数値の色
const NUMBER_COLOR: Color = Color { red: 209, green: 154, blue: 102, alpha: 255 };
/// マクロの色
const MACRO_COLOR: Color = Color { red: 97, green: 175, blue: 239, alpha: 255 };

// ============================================================================
// Rope - 効率的なテキストデータ構造
// ============================================================================

/// Ropeノード - テキストを効率的に管理
/// 
/// 小さいチャンクに分割することで、挿入・削除を効率化
#[derive(Clone)]
pub struct RopeNode {
    /// テキストチャンク（リーフノードの場合）
    text: Option<String>,
    /// 左の子ノード
    left: Option<Box<RopeNode>>,
    /// 右の子ノード
    right: Option<Box<RopeNode>>,
    /// このノード以下の総文字数
    length: usize,
    /// このノード以下の総行数
    line_count: usize,
}

/// チャンクの最大サイズ
const CHUNK_SIZE: usize = 512;

impl RopeNode {
    /// 空のノードを作成
    pub fn new() -> Self {
        Self {
            text: Some(String::new()),
            left: None,
            right: None,
            length: 0,
            line_count: 1,
        }
    }

    /// テキストからノードを作成
    pub fn from_str(s: &str) -> Self {
        if s.len() <= CHUNK_SIZE {
            let line_count = s.chars().filter(|&c| c == '\n').count() + 1;
            Self {
                text: Some(String::from(s)),
                left: None,
                right: None,
                length: s.len(),
                line_count,
            }
        } else {
            // 大きいテキストは分割
            let mid = s.len() / 2;
            // 改行位置で分割を試みる
            let split_pos = s[..mid].rfind('\n')
                .map(|p| p + 1)
                .unwrap_or(mid);
            
            let left = Box::new(RopeNode::from_str(&s[..split_pos]));
            let right = Box::new(RopeNode::from_str(&s[split_pos..]));
            
            let length = left.length + right.length;
            let line_count = left.line_count + right.line_count - 1;
            
            Self {
                text: None,
                left: Some(left),
                right: Some(right),
                length,
                line_count,
            }
        }
    }

    /// 長さを取得
    pub fn len(&self) -> usize {
        self.length
    }

    /// 空かどうか
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// 行数を取得
    pub fn lines(&self) -> usize {
        self.line_count
    }

    /// 指定位置の文字を取得
    pub fn char_at(&self, index: usize) -> Option<char> {
        if index >= self.length {
            return None;
        }

        if let Some(ref text) = self.text {
            text.chars().nth(index)
        } else {
            let left = self.left.as_ref()?;
            if index < left.length {
                left.char_at(index)
            } else {
                self.right.as_ref()?.char_at(index - left.length)
            }
        }
    }

    /// 指定範囲のテキストを取得
    pub fn slice(&self, start: usize, end: usize) -> String {
        if start >= end || start >= self.length {
            return String::new();
        }
        let end = min(end, self.length);

        if let Some(ref text) = self.text {
            text.chars().skip(start).take(end - start).collect()
        } else {
            let left = self.left.as_ref().unwrap();
            let right = self.right.as_ref().unwrap();
            
            let mut result = String::new();
            
            if start < left.length {
                result.push_str(&left.slice(start, min(end, left.length)));
            }
            if end > left.length {
                let right_start = start.saturating_sub(left.length);
                let right_end = end - left.length;
                result.push_str(&right.slice(right_start, right_end));
            }
            
            result
        }
    }

    /// 指定位置に文字列を挿入
    pub fn insert(&mut self, index: usize, s: &str) {
        if s.is_empty() {
            return;
        }

        let new_lines = s.chars().filter(|&c| c == '\n').count();

        if let Some(ref mut text) = self.text {
            // リーフノードへの挿入
            let byte_index = text.chars().take(index).map(|c| c.len_utf8()).sum();
            text.insert_str(byte_index, s);
            self.length += s.len();
            self.line_count += new_lines;

            // チャンクが大きくなりすぎたら分割
            if text.len() > CHUNK_SIZE * 2 {
                self.split_node();
            }
        } else {
            // 内部ノード
            let left = self.left.as_mut().unwrap();
            if index <= left.length {
                left.insert(index, s);
            } else {
                self.right.as_mut().unwrap().insert(index - left.length, s);
            }
            self.length += s.len();
            self.line_count += new_lines;
        }
    }

    /// ノードを分割
    fn split_node(&mut self) {
        if let Some(text) = self.text.take() {
            let mid = text.len() / 2;
            let split_pos = text[..mid].rfind('\n')
                .map(|p| p + 1)
                .unwrap_or(mid);
            
            let (left_text, right_text) = text.split_at(split_pos);
            
            self.left = Some(Box::new(RopeNode::from_str(left_text)));
            self.right = Some(Box::new(RopeNode::from_str(right_text)));
        }
    }

    /// 指定範囲を削除
    pub fn delete(&mut self, start: usize, end: usize) {
        if start >= end || start >= self.length {
            return;
        }
        let end = min(end, self.length);
        
        // 削除される改行数をカウント
        let deleted = self.slice(start, end);
        let deleted_lines = deleted.chars().filter(|&c| c == '\n').count();

        if let Some(ref mut text) = self.text {
            let byte_start: usize = text.chars().take(start).map(|c| c.len_utf8()).sum();
            let byte_end: usize = text.chars().take(end).map(|c| c.len_utf8()).sum();
            text.replace_range(byte_start..byte_end, "");
            self.length = text.chars().count();
            self.line_count = self.line_count.saturating_sub(deleted_lines);
        } else {
            let left = self.left.as_mut().unwrap();
            let right = self.right.as_mut().unwrap();
            
            if end <= left.length {
                left.delete(start, end);
            } else if start >= left.length {
                right.delete(start - left.length, end - left.length);
            } else {
                // 両方にまたがる削除
                left.delete(start, left.length);
                right.delete(0, end - left.length);
            }
            
            self.length = left.length + right.length;
            self.line_count = left.line_count + right.line_count - 1;
            
            // ノードが小さくなったらマージ
            if self.length <= CHUNK_SIZE {
                self.merge_nodes();
            }
        }
    }

    /// 子ノードをマージ
    fn merge_nodes(&mut self) {
        if self.text.is_none() {
            let left_text = self.left.as_ref().map(|n| n.to_string()).unwrap_or_default();
            let right_text = self.right.as_ref().map(|n| n.to_string()).unwrap_or_default();
            
            self.text = Some(format!("{}{}", left_text, right_text));
            self.left = None;
            self.right = None;
        }
    }

    /// 全テキストを文字列として取得
    pub fn to_string(&self) -> String {
        if let Some(ref text) = self.text {
            text.clone()
        } else {
            let left = self.left.as_ref().map(|n| n.to_string()).unwrap_or_default();
            let right = self.right.as_ref().map(|n| n.to_string()).unwrap_or_default();
            format!("{}{}", left, right)
        }
    }

    /// 行のテキストを取得
    pub fn get_line(&self, line_index: usize) -> String {
        let text = self.to_string();
        text.lines().nth(line_index).map(String::from).unwrap_or_default()
    }

    /// 行の開始位置（文字インデックス）を取得
    pub fn line_start(&self, line_index: usize) -> usize {
        if line_index == 0 {
            return 0;
        }
        
        let text = self.to_string();
        let mut pos = 0;
        let mut current_line = 0;
        
        for ch in text.chars() {
            if current_line == line_index {
                return pos;
            }
            if ch == '\n' {
                current_line += 1;
            }
            pos += 1;
        }
        
        pos
    }

    /// 行の終了位置（文字インデックス）を取得
    pub fn line_end(&self, line_index: usize) -> usize {
        let start = self.line_start(line_index);
        let text = self.to_string();
        
        let mut pos = start;
        for ch in text.chars().skip(start) {
            if ch == '\n' {
                return pos;
            }
            pos += 1;
        }
        
        pos
    }

    /// 文字位置から行番号を取得
    pub fn line_of(&self, char_index: usize) -> usize {
        let text = self.to_string();
        text.chars().take(char_index).filter(|&c| c == '\n').count()
    }

    /// 文字位置から列番号を取得
    pub fn column_of(&self, char_index: usize) -> usize {
        let line = self.line_of(char_index);
        let line_start = self.line_start(line);
        char_index - line_start
    }
}

impl Default for RopeNode {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// TextBuffer - エディタ用テキストバッファ
// ============================================================================

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
// Unit Tests (Part 1)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rope_new() {
        let rope = RopeNode::new();
        assert_eq!(rope.len(), 0);
        assert_eq!(rope.lines(), 1);
    }

    #[test]
    fn test_rope_from_str() {
        let rope = RopeNode::from_str("Hello\nWorld");
        assert_eq!(rope.len(), 11);
        assert_eq!(rope.lines(), 2);
    }

    #[test]
    fn test_rope_insert() {
        let mut rope = RopeNode::from_str("Hello");
        rope.insert(5, " World");
        assert_eq!(rope.to_string(), "Hello World");
    }

    #[test]
    fn test_rope_delete() {
        let mut rope = RopeNode::from_str("Hello World");
        rope.delete(5, 11);
        assert_eq!(rope.to_string(), "Hello");
    }

    #[test]
    fn test_text_buffer_insert() {
        let mut buf = TextBuffer::new();
        buf.insert_char(0, 'H');
        buf.insert_char(1, 'i');
        assert_eq!(buf.text(), "Hi");
        assert!(buf.is_modified());
    }
}

// ============================================================================
// Cursor - カーソル/キャレット管理
// ============================================================================

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
// SyntaxHighlighter - Rust用シンタックスハイライト
// ============================================================================

/// トークンの種類
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenType {
    /// 通常のテキスト
    Normal,
    /// キーワード
    Keyword,
    /// 型
    Type,
    /// 文字列リテラル
    String,
    /// コメント
    Comment,
    /// 数値
    Number,
    /// マクロ
    Macro,
}

/// ハイライトされたトークン
#[derive(Clone, Debug)]
pub struct Token {
    /// テキスト
    pub text: String,
    /// トークンの種類
    pub token_type: TokenType,
}

/// Rustキーワード
const RUST_KEYWORDS: &[&str] = &[
    "as", "async", "await", "break", "const", "continue", "crate", "dyn",
    "else", "enum", "extern", "false", "fn", "for", "if", "impl", "in",
    "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
    "self", "Self", "static", "struct", "super", "trait", "true", "type",
    "unsafe", "use", "where", "while", "async", "yield",
];

/// Rust組み込み型
const RUST_TYPES: &[&str] = &[
    "bool", "char", "str", "u8", "u16", "u32", "u64", "u128", "usize",
    "i8", "i16", "i32", "i64", "i128", "isize", "f32", "f64",
    "String", "Vec", "Option", "Result", "Box", "Rc", "Arc", "Cell",
    "RefCell", "Mutex", "RwLock", "HashMap", "HashSet", "BTreeMap",
];

/// シンタックスハイライター
pub struct SyntaxHighlighter {
    /// 現在の状態（複数行コメント/文字列用）
    in_block_comment: bool,
    in_string: bool,
}

impl SyntaxHighlighter {
    /// 新しいハイライターを作成
    pub fn new() -> Self {
        Self {
            in_block_comment: false,
            in_string: false,
        }
    }

    /// 状態をリセット
    pub fn reset(&mut self) {
        self.in_block_comment = false;
        self.in_string = false;
    }

    /// 行をハイライト
    pub fn highlight_line(&mut self, line: &str) -> Vec<Token> {
        let mut tokens = Vec::new();
        let chars: Vec<char> = line.chars().collect();
        let len = chars.len();
        let mut i = 0;

        while i < len {
            // ブロックコメント中
            if self.in_block_comment {
                let start = i;
                while i < len {
                    if i + 1 < len && chars[i] == '*' && chars[i + 1] == '/' {
                        i += 2;
                        self.in_block_comment = false;
                        break;
                    }
                    i += 1;
                }
                tokens.push(Token {
                    text: chars[start..i].iter().collect(),
                    token_type: TokenType::Comment,
                });
                continue;
            }

            // 文字列中
            if self.in_string {
                let start = i;
                while i < len {
                    if chars[i] == '"' && (i == 0 || chars[i - 1] != '\\') {
                        i += 1;
                        self.in_string = false;
                        break;
                    }
                    i += 1;
                }
                tokens.push(Token {
                    text: chars[start..i].iter().collect(),
                    token_type: TokenType::String,
                });
                continue;
            }

            // 行コメント
            if i + 1 < len && chars[i] == '/' && chars[i + 1] == '/' {
                tokens.push(Token {
                    text: chars[i..].iter().collect(),
                    token_type: TokenType::Comment,
                });
                break;
            }

            // ブロックコメント開始
            if i + 1 < len && chars[i] == '/' && chars[i + 1] == '*' {
                self.in_block_comment = true;
                i += 2;
                let start = i - 2;
                while i < len {
                    if i + 1 < len && chars[i] == '*' && chars[i + 1] == '/' {
                        i += 2;
                        self.in_block_comment = false;
                        break;
                    }
                    i += 1;
                }
                tokens.push(Token {
                    text: chars[start..i].iter().collect(),
                    token_type: TokenType::Comment,
                });
                continue;
            }

            // 文字列
            if chars[i] == '"' {
                let start = i;
                i += 1;
                while i < len {
                    if chars[i] == '"' && chars[i - 1] != '\\' {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                if i >= len && chars.last() != Some(&'"') {
                    self.in_string = true;
                }
                tokens.push(Token {
                    text: chars[start..i].iter().collect(),
                    token_type: TokenType::String,
                });
                continue;
            }

            // 文字リテラル
            if chars[i] == '\'' && i + 2 < len {
                let start = i;
                i += 1;
                if chars[i] == '\\' {
                    i += 2;
                } else {
                    i += 1;
                }
                if i < len && chars[i] == '\'' {
                    i += 1;
                    tokens.push(Token {
                        text: chars[start..i].iter().collect(),
                        token_type: TokenType::String,
                    });
                    continue;
                }
                // ライフタイム
                i = start + 1;
            }

            // 数値
            if chars[i].is_ascii_digit() || (chars[i] == '-' && i + 1 < len && chars[i + 1].is_ascii_digit()) {
                let start = i;
                if chars[i] == '-' {
                    i += 1;
                }
                // 16進数
                if i + 1 < len && chars[i] == '0' && (chars[i + 1] == 'x' || chars[i + 1] == 'X') {
                    i += 2;
                    while i < len && (chars[i].is_ascii_hexdigit() || chars[i] == '_') {
                        i += 1;
                    }
                }
                // 2進数
                else if i + 1 < len && chars[i] == '0' && (chars[i + 1] == 'b' || chars[i + 1] == 'B') {
                    i += 2;
                    while i < len && (chars[i] == '0' || chars[i] == '1' || chars[i] == '_') {
                        i += 1;
                    }
                }
                // 10進数・浮動小数点
                else {
                    while i < len && (chars[i].is_ascii_digit() || chars[i] == '_' || chars[i] == '.') {
                        i += 1;
                    }
                    // 指数部
                    if i < len && (chars[i] == 'e' || chars[i] == 'E') {
                        i += 1;
                        if i < len && (chars[i] == '+' || chars[i] == '-') {
                            i += 1;
                        }
                        while i < len && chars[i].is_ascii_digit() {
                            i += 1;
                        }
                    }
                }
                // 型サフィックス
                let suffixes = ["u8", "u16", "u32", "u64", "u128", "usize", 
                               "i8", "i16", "i32", "i64", "i128", "isize", "f32", "f64"];
                for suffix in &suffixes {
                    let suffix_chars: Vec<char> = suffix.chars().collect();
                    if i + suffix_chars.len() <= len {
                        let slice: String = chars[i..i + suffix_chars.len()].iter().collect();
                        if slice == *suffix {
                            i += suffix_chars.len();
                            break;
                        }
                    }
                }
                tokens.push(Token {
                    text: chars[start..i].iter().collect(),
                    token_type: TokenType::Number,
                });
                continue;
            }

            // 識別子・キーワード
            if chars[i].is_alphabetic() || chars[i] == '_' {
                let start = i;
                while i < len && (chars[i].is_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                
                // マクロ
                if i < len && chars[i] == '!' {
                    i += 1;
                    tokens.push(Token {
                        text: chars[start..i].iter().collect(),
                        token_type: TokenType::Macro,
                    });
                    continue;
                }
                
                // キーワード
                if RUST_KEYWORDS.contains(&word.as_str()) {
                    tokens.push(Token {
                        text: word,
                        token_type: TokenType::Keyword,
                    });
                    continue;
                }
                
                // 型
                if RUST_TYPES.contains(&word.as_str()) || word.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
                    tokens.push(Token {
                        text: word,
                        token_type: TokenType::Type,
                    });
                    continue;
                }
                
                // 通常の識別子
                tokens.push(Token {
                    text: word,
                    token_type: TokenType::Normal,
                });
                continue;
            }

            // その他の文字
            let mut char_str = String::new();
            char_str.push(chars[i]);
            tokens.push(Token {
                text: char_str,
                token_type: TokenType::Normal,
            });
            i += 1;
        }

        tokens
    }

    /// トークンタイプに対応する色を取得
    pub fn color_for_token(token_type: TokenType) -> Color {
        match token_type {
            TokenType::Normal => TEXT_COLOR,
            TokenType::Keyword => KEYWORD_COLOR,
            TokenType::Type => TYPE_COLOR,
            TokenType::String => STRING_COLOR,
            TokenType::Comment => COMMENT_COLOR,
            TokenType::Number => NUMBER_COLOR,
            TokenType::Macro => MACRO_COLOR,
        }
    }
}

impl Default for SyntaxHighlighter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// 8x16 ビットマップフォント
// ============================================================================

/// 8x16ビットマップフォントから文字データを取得
fn get_char_bitmap(ch: char) -> Option<[u8; 16]> {
    // Basic ASCII (0x20-0x7E)
    static FONT_8X16: [[u8; 16]; 95] = [
        // Space (0x20)
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        // ! (0x21)
        [0x00, 0x00, 0x18, 0x3C, 0x3C, 0x3C, 0x18, 0x18, 0x18, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00],
        // " (0x22)
        [0x00, 0x66, 0x66, 0x66, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        // # (0x23)
        [0x00, 0x00, 0x00, 0x6C, 0x6C, 0xFE, 0x6C, 0x6C, 0x6C, 0xFE, 0x6C, 0x6C, 0x00, 0x00, 0x00, 0x00],
        // $ (0x24)
        [0x18, 0x18, 0x7C, 0xC6, 0xC2, 0xC0, 0x7C, 0x06, 0x06, 0x86, 0xC6, 0x7C, 0x18, 0x18, 0x00, 0x00],
        // % (0x25)
        [0x00, 0x00, 0x00, 0x00, 0xC2, 0xC6, 0x0C, 0x18, 0x30, 0x60, 0xC6, 0x86, 0x00, 0x00, 0x00, 0x00],
        // & (0x26)
        [0x00, 0x00, 0x38, 0x6C, 0x6C, 0x38, 0x76, 0xDC, 0xCC, 0xCC, 0xCC, 0x76, 0x00, 0x00, 0x00, 0x00],
        // ' (0x27)
        [0x00, 0x30, 0x30, 0x30, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        // ( (0x28)
        [0x00, 0x00, 0x0C, 0x18, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x18, 0x0C, 0x00, 0x00, 0x00, 0x00],
        // ) (0x29)
        [0x00, 0x00, 0x30, 0x18, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x18, 0x30, 0x00, 0x00, 0x00, 0x00],
        // * (0x2A)
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x3C, 0xFF, 0x3C, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        // + (0x2B)
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x7E, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        // , (0x2C)
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x18, 0x30, 0x00, 0x00, 0x00],
        // - (0x2D)
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        // . (0x2E)
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00],
        // / (0x2F)
        [0x00, 0x00, 0x00, 0x00, 0x02, 0x06, 0x0C, 0x18, 0x30, 0x60, 0xC0, 0x80, 0x00, 0x00, 0x00, 0x00],
        // 0 (0x30)
        [0x00, 0x00, 0x38, 0x6C, 0xC6, 0xC6, 0xD6, 0xD6, 0xC6, 0xC6, 0x6C, 0x38, 0x00, 0x00, 0x00, 0x00],
        // 1 (0x31)
        [0x00, 0x00, 0x18, 0x38, 0x78, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00, 0x00, 0x00, 0x00],
        // 2 (0x32)
        [0x00, 0x00, 0x7C, 0xC6, 0x06, 0x0C, 0x18, 0x30, 0x60, 0xC0, 0xC6, 0xFE, 0x00, 0x00, 0x00, 0x00],
        // 3 (0x33)
        [0x00, 0x00, 0x7C, 0xC6, 0x06, 0x06, 0x3C, 0x06, 0x06, 0x06, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00],
        // 4 (0x34)
        [0x00, 0x00, 0x0C, 0x1C, 0x3C, 0x6C, 0xCC, 0xFE, 0x0C, 0x0C, 0x0C, 0x1E, 0x00, 0x00, 0x00, 0x00],
        // 5 (0x35)
        [0x00, 0x00, 0xFE, 0xC0, 0xC0, 0xC0, 0xFC, 0x06, 0x06, 0x06, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00],
        // 6 (0x36)
        [0x00, 0x00, 0x38, 0x60, 0xC0, 0xC0, 0xFC, 0xC6, 0xC6, 0xC6, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00],
        // 7 (0x37)
        [0x00, 0x00, 0xFE, 0xC6, 0x06, 0x06, 0x0C, 0x18, 0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00],
        // 8 (0x38)
        [0x00, 0x00, 0x7C, 0xC6, 0xC6, 0xC6, 0x7C, 0xC6, 0xC6, 0xC6, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00],
        // 9 (0x39)
        [0x00, 0x00, 0x7C, 0xC6, 0xC6, 0xC6, 0x7E, 0x06, 0x06, 0x06, 0x0C, 0x78, 0x00, 0x00, 0x00, 0x00],
        // : (0x3A)
        [0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00],
        // ; (0x3B)
        [0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x18, 0x18, 0x30, 0x00, 0x00, 0x00, 0x00],
        // < (0x3C)
        [0x00, 0x00, 0x00, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x30, 0x18, 0x0C, 0x06, 0x00, 0x00, 0x00, 0x00],
        // = (0x3D)
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        // > (0x3E)
        [0x00, 0x00, 0x00, 0x60, 0x30, 0x18, 0x0C, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x00, 0x00, 0x00, 0x00],
        // ? (0x3F)
        [0x00, 0x00, 0x7C, 0xC6, 0xC6, 0x0C, 0x18, 0x18, 0x18, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00],
        // @ (0x40)
        [0x00, 0x00, 0x00, 0x7C, 0xC6, 0xC6, 0xDE, 0xDE, 0xDE, 0xDC, 0xC0, 0x7C, 0x00, 0x00, 0x00, 0x00],
        // A (0x41)
        [0x00, 0x00, 0x10, 0x38, 0x6C, 0xC6, 0xC6, 0xFE, 0xC6, 0xC6, 0xC6, 0xC6, 0x00, 0x00, 0x00, 0x00],
        // B (0x42)
        [0x00, 0x00, 0xFC, 0x66, 0x66, 0x66, 0x7C, 0x66, 0x66, 0x66, 0x66, 0xFC, 0x00, 0x00, 0x00, 0x00],
        // C (0x43)
        [0x00, 0x00, 0x3C, 0x66, 0xC2, 0xC0, 0xC0, 0xC0, 0xC0, 0xC2, 0x66, 0x3C, 0x00, 0x00, 0x00, 0x00],
        // D (0x44)
        [0x00, 0x00, 0xF8, 0x6C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x6C, 0xF8, 0x00, 0x00, 0x00, 0x00],
        // E (0x45)
        [0x00, 0x00, 0xFE, 0x66, 0x62, 0x68, 0x78, 0x68, 0x60, 0x62, 0x66, 0xFE, 0x00, 0x00, 0x00, 0x00],
        // F (0x46)
        [0x00, 0x00, 0xFE, 0x66, 0x62, 0x68, 0x78, 0x68, 0x60, 0x60, 0x60, 0xF0, 0x00, 0x00, 0x00, 0x00],
        // G (0x47)
        [0x00, 0x00, 0x3C, 0x66, 0xC2, 0xC0, 0xC0, 0xDE, 0xC6, 0xC6, 0x66, 0x3A, 0x00, 0x00, 0x00, 0x00],
        // H (0x48)
        [0x00, 0x00, 0xC6, 0xC6, 0xC6, 0xC6, 0xFE, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0x00, 0x00, 0x00, 0x00],
        // I (0x49)
        [0x00, 0x00, 0x3C, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00, 0x00, 0x00, 0x00],
        // J (0x4A)
        [0x00, 0x00, 0x1E, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0xCC, 0xCC, 0xCC, 0x78, 0x00, 0x00, 0x00, 0x00],
        // K (0x4B)
        [0x00, 0x00, 0xE6, 0x66, 0x66, 0x6C, 0x78, 0x78, 0x6C, 0x66, 0x66, 0xE6, 0x00, 0x00, 0x00, 0x00],
        // L (0x4C)
        [0x00, 0x00, 0xF0, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x62, 0x66, 0xFE, 0x00, 0x00, 0x00, 0x00],
        // M (0x4D)
        [0x00, 0x00, 0xC6, 0xEE, 0xFE, 0xFE, 0xD6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0x00, 0x00, 0x00, 0x00],
        // N (0x4E)
        [0x00, 0x00, 0xC6, 0xE6, 0xF6, 0xFE, 0xDE, 0xCE, 0xC6, 0xC6, 0xC6, 0xC6, 0x00, 0x00, 0x00, 0x00],
        // O (0x4F)
        [0x00, 0x00, 0x7C, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00],
        // P (0x50)
        [0x00, 0x00, 0xFC, 0x66, 0x66, 0x66, 0x7C, 0x60, 0x60, 0x60, 0x60, 0xF0, 0x00, 0x00, 0x00, 0x00],
        // Q (0x51)
        [0x00, 0x00, 0x7C, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xD6, 0xDE, 0x7C, 0x0C, 0x0E, 0x00, 0x00],
        // R (0x52)
        [0x00, 0x00, 0xFC, 0x66, 0x66, 0x66, 0x7C, 0x6C, 0x66, 0x66, 0x66, 0xE6, 0x00, 0x00, 0x00, 0x00],
        // S (0x53)
        [0x00, 0x00, 0x7C, 0xC6, 0xC6, 0x60, 0x38, 0x0C, 0x06, 0xC6, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00],
        // T (0x54)
        [0x00, 0x00, 0x7E, 0x7E, 0x5A, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00, 0x00, 0x00, 0x00],
        // U (0x55)
        [0x00, 0x00, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00],
        // V (0x56)
        [0x00, 0x00, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0x6C, 0x38, 0x10, 0x00, 0x00, 0x00, 0x00],
        // W (0x57)
        [0x00, 0x00, 0xC6, 0xC6, 0xC6, 0xC6, 0xD6, 0xD6, 0xD6, 0xFE, 0xEE, 0x6C, 0x00, 0x00, 0x00, 0x00],
        // X (0x58)
        [0x00, 0x00, 0xC6, 0xC6, 0x6C, 0x7C, 0x38, 0x38, 0x7C, 0x6C, 0xC6, 0xC6, 0x00, 0x00, 0x00, 0x00],
        // Y (0x59)
        [0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00, 0x00, 0x00, 0x00],
        // Z (0x5A)
        [0x00, 0x00, 0xFE, 0xC6, 0x86, 0x0C, 0x18, 0x30, 0x60, 0xC2, 0xC6, 0xFE, 0x00, 0x00, 0x00, 0x00],
        // [ (0x5B)
        [0x00, 0x00, 0x3C, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x3C, 0x00, 0x00, 0x00, 0x00],
        // \ (0x5C)
        [0x00, 0x00, 0x00, 0x80, 0xC0, 0xE0, 0x70, 0x38, 0x1C, 0x0E, 0x06, 0x02, 0x00, 0x00, 0x00, 0x00],
        // ] (0x5D)
        [0x00, 0x00, 0x3C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x3C, 0x00, 0x00, 0x00, 0x00],
        // ^ (0x5E)
        [0x10, 0x38, 0x6C, 0xC6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        // _ (0x5F)
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00],
        // ` (0x60)
        [0x30, 0x30, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        // a (0x61)
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x0C, 0x7C, 0xCC, 0xCC, 0xCC, 0x76, 0x00, 0x00, 0x00, 0x00],
        // b (0x62)
        [0x00, 0x00, 0xE0, 0x60, 0x60, 0x78, 0x6C, 0x66, 0x66, 0x66, 0x66, 0x7C, 0x00, 0x00, 0x00, 0x00],
        // c (0x63)
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x7C, 0xC6, 0xC0, 0xC0, 0xC0, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00],
        // d (0x64)
        [0x00, 0x00, 0x1C, 0x0C, 0x0C, 0x3C, 0x6C, 0xCC, 0xCC, 0xCC, 0xCC, 0x76, 0x00, 0x00, 0x00, 0x00],
        // e (0x65)
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x7C, 0xC6, 0xFE, 0xC0, 0xC0, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00],
        // f (0x66)
        [0x00, 0x00, 0x38, 0x6C, 0x64, 0x60, 0xF0, 0x60, 0x60, 0x60, 0x60, 0xF0, 0x00, 0x00, 0x00, 0x00],
        // g (0x67)
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x7C, 0x0C, 0xCC, 0x78, 0x00],
        // h (0x68)
        [0x00, 0x00, 0xE0, 0x60, 0x60, 0x6C, 0x76, 0x66, 0x66, 0x66, 0x66, 0xE6, 0x00, 0x00, 0x00, 0x00],
        // i (0x69)
        [0x00, 0x00, 0x18, 0x18, 0x00, 0x38, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00, 0x00, 0x00, 0x00],
        // j (0x6A)
        [0x00, 0x00, 0x06, 0x06, 0x00, 0x0E, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x66, 0x66, 0x3C, 0x00],
        // k (0x6B)
        [0x00, 0x00, 0xE0, 0x60, 0x60, 0x66, 0x6C, 0x78, 0x78, 0x6C, 0x66, 0xE6, 0x00, 0x00, 0x00, 0x00],
        // l (0x6C)
        [0x00, 0x00, 0x38, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00, 0x00, 0x00, 0x00],
        // m (0x6D)
        [0x00, 0x00, 0x00, 0x00, 0x00, 0xE6, 0xFF, 0xDB, 0xDB, 0xDB, 0xDB, 0xDB, 0x00, 0x00, 0x00, 0x00],
        // n (0x6E)
        [0x00, 0x00, 0x00, 0x00, 0x00, 0xDC, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00],
        // o (0x6F)
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x7C, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00],
        // p (0x70)
        [0x00, 0x00, 0x00, 0x00, 0x00, 0xDC, 0x66, 0x66, 0x66, 0x66, 0x66, 0x7C, 0x60, 0x60, 0xF0, 0x00],
        // q (0x71)
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x7C, 0x0C, 0x0C, 0x1E, 0x00],
        // r (0x72)
        [0x00, 0x00, 0x00, 0x00, 0x00, 0xDC, 0x76, 0x66, 0x60, 0x60, 0x60, 0xF0, 0x00, 0x00, 0x00, 0x00],
        // s (0x73)
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x7C, 0xC6, 0x60, 0x38, 0x0C, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00],
        // t (0x74)
        [0x00, 0x00, 0x10, 0x30, 0x30, 0xFC, 0x30, 0x30, 0x30, 0x30, 0x36, 0x1C, 0x00, 0x00, 0x00, 0x00],
        // u (0x75)
        [0x00, 0x00, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x76, 0x00, 0x00, 0x00, 0x00],
        // v (0x76)
        [0x00, 0x00, 0x00, 0x00, 0x00, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0x6C, 0x38, 0x00, 0x00, 0x00, 0x00],
        // w (0x77)
        [0x00, 0x00, 0x00, 0x00, 0x00, 0xC6, 0xC6, 0xD6, 0xD6, 0xD6, 0xFE, 0x6C, 0x00, 0x00, 0x00, 0x00],
        // x (0x78)
        [0x00, 0x00, 0x00, 0x00, 0x00, 0xC6, 0x6C, 0x38, 0x38, 0x38, 0x6C, 0xC6, 0x00, 0x00, 0x00, 0x00],
        // y (0x79)
        [0x00, 0x00, 0x00, 0x00, 0x00, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0x7E, 0x06, 0x0C, 0xF8, 0x00],
        // z (0x7A)
        [0x00, 0x00, 0x00, 0x00, 0x00, 0xFE, 0xCC, 0x18, 0x30, 0x60, 0xC6, 0xFE, 0x00, 0x00, 0x00, 0x00],
        // { (0x7B)
        [0x00, 0x00, 0x0E, 0x18, 0x18, 0x18, 0x70, 0x18, 0x18, 0x18, 0x18, 0x0E, 0x00, 0x00, 0x00, 0x00],
        // | (0x7C)
        [0x00, 0x00, 0x18, 0x18, 0x18, 0x18, 0x00, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00],
        // } (0x7D)
        [0x00, 0x00, 0x70, 0x18, 0x18, 0x18, 0x0E, 0x18, 0x18, 0x18, 0x18, 0x70, 0x00, 0x00, 0x00, 0x00],
        // ~ (0x7E)
        [0x00, 0x00, 0x76, 0xDC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    ];

    let code = ch as u32;
    if code >= 0x20 && code <= 0x7E {
        Some(FONT_8X16[(code - 0x20) as usize])
    } else {
        None
    }
}

// ============================================================================
// Editor - メインエディタ構造体
// ============================================================================

/// エディタの状態
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EditorMode {
    /// 通常モード
    Normal,
    /// ファイルダイアログ（開く）
    OpenDialog,
    /// ファイルダイアログ（保存）
    SaveDialog,
}

/// ツールバーボタン
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolbarButton {
    New,
    Open,
    Save,
    SaveAs,
    Undo,
    Redo,
    Cut,
    Copy,
    Paste,
}

/// テキストエディタ
pub struct Editor {
    /// テキストバッファ
    buffer: TextBuffer,
    /// カーソル
    cursor: Cursor,
    /// 選択範囲
    selection: Option<Selection>,
    /// スクロール位置（行）
    scroll_line: usize,
    /// スクロール位置（カラム）
    scroll_col: usize,
    /// エディタモード
    mode: EditorMode,
    /// シンタックスハイライター
    highlighter: SyntaxHighlighter,
    /// カーソル表示フラグ
    cursor_visible: bool,
    /// 最後のカーソル点滅時刻
    last_blink: u64,
    /// ホバー中のボタン
    hover_button: Option<ToolbarButton>,
    /// ダイアログ入力バッファ
    dialog_input: String,
    /// Undo履歴
    undo_stack: Vec<(String, usize)>,
    /// Redo履歴
    redo_stack: Vec<(String, usize)>,
    /// 現在のワーキングディレクトリ
    cwd: String,
}

impl Editor {
    /// 新しいエディタを作成
    pub fn new() -> Self {
        Self {
            buffer: TextBuffer::new(),
            cursor: Cursor::new(),
            selection: None,
            scroll_line: 0,
            scroll_col: 0,
            mode: EditorMode::Normal,
            highlighter: SyntaxHighlighter::new(),
            cursor_visible: true,
            last_blink: 0,
            hover_button: None,
            dialog_input: String::new(),
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            cwd: String::from("/"),
        }
    }

    /// ファイルからエディタを作成
    pub fn from_file(path: &str, cwd: &str) -> Result<Self, &'static str> {
        let mut editor = Self::new();
        editor.cwd = String::from(cwd);
        editor.open_file(path)?;
        Ok(editor)
    }

    /// ファイルを開く
    pub fn open_file(&mut self, path: &str) -> Result<(), &'static str> {
        match read_file_content(path, &self.cwd) {
            Ok(content) => {
                let text = String::from_utf8_lossy(&content);
                self.buffer = TextBuffer::from_str(&text);
                self.buffer.set_path(path);
                self.buffer.mark_saved();
                self.cursor = Cursor::new();
                self.selection = None;
                self.scroll_line = 0;
                self.scroll_col = 0;
                self.undo_stack.clear();
                self.redo_stack.clear();
                Ok(())
            }
            Err(_) => Err("Failed to open file"),
        }
    }

    /// ファイルを保存
    pub fn save_file(&mut self) -> Result<(), &'static str> {
        let path = match self.buffer.path() {
            Some(p) => p.clone(),
            None => return Err("No file path set"),
        };
        self.save_file_as(&path)
    }

    /// 名前を付けて保存
    pub fn save_file_as(&mut self, path: &str) -> Result<(), &'static str> {
        let content = self.buffer.text();
        match write_file_content(path, &self.cwd, content.as_bytes()) {
            Ok(_) => {
                self.buffer.set_path(path);
                self.buffer.mark_saved();
                Ok(())
            }
            Err(_) => Err("Failed to save file"),
        }
    }

    /// カーソルを表示範囲内に保つ
    fn ensure_cursor_visible(&mut self) {
        let line = self.cursor.line(&self.buffer);
        let col = self.cursor.column(&self.buffer);

        // 垂直スクロール
        if line < self.scroll_line {
            self.scroll_line = line;
        } else if line >= self.scroll_line + VISIBLE_LINES {
            self.scroll_line = line - VISIBLE_LINES + 1;
        }

        // 水平スクロール
        if col < self.scroll_col {
            self.scroll_col = col;
        } else if col >= self.scroll_col + VISIBLE_COLS {
            self.scroll_col = col - VISIBLE_COLS + 1;
        }
    }

    /// 現在の状態をUndo履歴に保存
    fn save_undo_state(&mut self) {
        let text = self.buffer.text();
        let pos = self.cursor.position;
        self.undo_stack.push((text, pos));
        self.redo_stack.clear();
        
        // 履歴のサイズ制限
        if self.undo_stack.len() > 100 {
            self.undo_stack.remove(0);
        }
    }

    /// Undo
    pub fn undo(&mut self) {
        if let Some((text, pos)) = self.undo_stack.pop() {
            // 現在の状態をRedo履歴に保存
            let current_text = self.buffer.text();
            let current_pos = self.cursor.position;
            self.redo_stack.push((current_text, current_pos));
            
            self.buffer = TextBuffer::from_str(&text);
            self.cursor.set_position(pos, &self.buffer);
            self.ensure_cursor_visible();
        }
    }

    /// Redo
    pub fn redo(&mut self) {
        if let Some((text, pos)) = self.redo_stack.pop() {
            // 現在の状態をUndo履歴に保存
            let current_text = self.buffer.text();
            let current_pos = self.cursor.position;
            self.undo_stack.push((current_text, current_pos));
            
            self.buffer = TextBuffer::from_str(&text);
            self.cursor.set_position(pos, &self.buffer);
            self.ensure_cursor_visible();
        }
    }

    /// 文字を挿入
    pub fn insert_char(&mut self, ch: char) {
        self.save_undo_state();
        self.delete_selection();
        
        if ch == '\n' {
            self.buffer.insert_char(self.cursor.position, '\n');
            self.cursor.position += 1;
        } else if ch == '\t' {
            // タブをスペースに変換
            let col = self.cursor.column(&self.buffer);
            let spaces = TAB_WIDTH - (col % TAB_WIDTH);
            for _ in 0..spaces {
                self.buffer.insert_char(self.cursor.position, ' ');
                self.cursor.position += 1;
            }
        } else {
            self.buffer.insert_char(self.cursor.position, ch);
            self.cursor.position += 1;
        }
        
        self.cursor.target_column = self.cursor.column(&self.buffer);
        self.ensure_cursor_visible();
    }

    /// バックスペース
    pub fn backspace(&mut self) {
        if self.delete_selection() {
            return;
        }
        
        if self.cursor.position > 0 {
            self.save_undo_state();
            self.cursor.position -= 1;
            self.buffer.delete_char(self.cursor.position);
            self.cursor.target_column = self.cursor.column(&self.buffer);
            self.ensure_cursor_visible();
        }
    }

    /// Delete
    pub fn delete(&mut self) {
        if self.delete_selection() {
            return;
        }
        
        if self.cursor.position < self.buffer.len() {
            self.save_undo_state();
            self.buffer.delete_char(self.cursor.position);
        }
    }

    /// 選択範囲を削除
    fn delete_selection(&mut self) -> bool {
        if let Some(sel) = self.selection.take() {
            if !sel.is_empty() {
                self.save_undo_state();
                let start = sel.start();
                let end = sel.end();
                for _ in start..end {
                    self.buffer.delete_char(start);
                }
                self.cursor.set_position(start, &self.buffer);
                self.ensure_cursor_visible();
                return true;
            }
        }
        false
    }

    /// 選択範囲のテキストを取得
    pub fn get_selection_text(&self) -> Option<String> {
        self.selection.as_ref().map(|sel| sel.get_text(&self.buffer))
    }

    /// カット
    pub fn cut(&mut self) -> Option<String> {
        if let Some(sel) = &self.selection {
            let text = sel.get_text(&self.buffer);
            self.delete_selection();
            Some(text)
        } else {
            None
        }
    }

    /// コピー
    pub fn copy(&self) -> Option<String> {
        self.get_selection_text()
    }

    /// ペースト
    pub fn paste(&mut self, text: &str) {
        self.save_undo_state();
        self.delete_selection();
        
        for ch in text.chars() {
            self.buffer.insert_char(self.cursor.position, ch);
            self.cursor.position += 1;
        }
        
        self.cursor.target_column = self.cursor.column(&self.buffer);
        self.ensure_cursor_visible();
    }

    /// 全選択
    pub fn select_all(&mut self) {
        self.selection = Some(Selection::new(0, self.buffer.len()));
        self.cursor.set_position(self.buffer.len(), &self.buffer);
    }

    /// 行を選択
    pub fn select_line(&mut self) {
        let line = self.cursor.line(&self.buffer);
        let start = self.buffer.line_start(line);
        let end = if line + 1 < self.buffer.line_count() {
            self.buffer.line_start(line + 1)
        } else {
            self.buffer.len()
        };
        self.selection = Some(Selection::new(start, end));
        self.cursor.set_position(end, &self.buffer);
    }

    // ========================================================================
    // キーボード入力処理
    // ========================================================================

    /// キー入力を処理
    pub fn handle_key(&mut self, key: char, ctrl: bool, shift: bool, alt: bool) {
        // ダイアログモード
        if self.mode != EditorMode::Normal {
            self.handle_dialog_key(key, ctrl);
            return;
        }

        // Ctrl+キー
        if ctrl {
            match key {
                'n' | 'N' => self.new_file(),
                'o' | 'O' => self.mode = EditorMode::OpenDialog,
                's' | 'S' => {
                    if shift {
                        self.mode = EditorMode::SaveDialog;
                    } else {
                        let _ = self.save_file();
                    }
                }
                'z' | 'Z' => {
                    if shift {
                        self.redo();
                    } else {
                        self.undo();
                    }
                }
                'y' | 'Y' => self.redo(),
                'a' | 'A' => self.select_all(),
                'l' | 'L' => self.select_line(),
                'd' | 'D' => self.duplicate_line(),
                _ => {}
            }
            return;
        }

        // 通常のキー入力
        match key {
            '\x08' => self.backspace(),  // Backspace
            '\x7F' => self.delete(),      // Delete
            '\r' | '\n' => self.insert_char('\n'),
            '\t' => self.insert_char('\t'),
            '\x1B' => self.selection = None, // Escape
            _ if key >= ' ' => self.insert_char(key),
            _ => {}
        }
    }

    /// スペシャルキー入力を処理
    pub fn handle_special_key(&mut self, key: SpecialKey, shift: bool, ctrl: bool) {
        let extend_selection = shift;

        if extend_selection && self.selection.is_none() {
            self.selection = Some(Selection::new(self.cursor.position, self.cursor.position));
        }

        match key {
            SpecialKey::Up => {
                if ctrl {
                    self.scroll_up(1);
                } else {
                    self.cursor.move_up(&self.buffer);
                }
            }
            SpecialKey::Down => {
                if ctrl {
                    self.scroll_down(1);
                } else {
                    self.cursor.move_down(&self.buffer);
                }
            }
            SpecialKey::Left => {
                if ctrl {
                    self.cursor.move_word_left(&self.buffer);
                } else {
                    self.cursor.move_left(&self.buffer);
                }
            }
            SpecialKey::Right => {
                if ctrl {
                    self.cursor.move_word_right(&self.buffer);
                } else {
                    self.cursor.move_right(&self.buffer);
                }
            }
            SpecialKey::Home => {
                if ctrl {
                    self.cursor.move_to_start();
                } else {
                    self.cursor.move_to_line_start(&self.buffer);
                }
            }
            SpecialKey::End => {
                if ctrl {
                    self.cursor.move_to_end(&self.buffer);
                } else {
                    self.cursor.move_to_line_end(&self.buffer);
                }
            }
            SpecialKey::PageUp => self.cursor.page_up(&self.buffer, VISIBLE_LINES),
            SpecialKey::PageDown => self.cursor.page_down(&self.buffer, VISIBLE_LINES),
        }

        if extend_selection {
            if let Some(sel) = &mut self.selection {
                sel.cursor = self.cursor.position;
            }
        } else if !extend_selection {
            self.selection = None;
        }

        self.ensure_cursor_visible();
    }

    /// ダイアログのキー入力を処理
    fn handle_dialog_key(&mut self, key: char, ctrl: bool) {
        match key {
            '\x1B' => {
                // Escape - ダイアログを閉じる
                self.mode = EditorMode::Normal;
                self.dialog_input.clear();
            }
            '\r' | '\n' => {
                // Enter - 確定
                let input = self.dialog_input.clone();
                match self.mode {
                    EditorMode::OpenDialog => {
                        let _ = self.open_file(&input);
                    }
                    EditorMode::SaveDialog => {
                        let _ = self.save_file_as(&input);
                    }
                    _ => {}
                }
                self.mode = EditorMode::Normal;
                self.dialog_input.clear();
            }
            '\x08' => {
                // Backspace
                self.dialog_input.pop();
            }
            _ if key >= ' ' && !ctrl => {
                self.dialog_input.push(key);
            }
            _ => {}
        }
    }

    /// 新規ファイル
    pub fn new_file(&mut self) {
        self.buffer = TextBuffer::new();
        self.cursor = Cursor::new();
        self.selection = None;
        self.scroll_line = 0;
        self.scroll_col = 0;
        self.undo_stack.clear();
        self.redo_stack.clear();
    }

    /// 行を複製
    pub fn duplicate_line(&mut self) {
        self.save_undo_state();
        
        let line = self.cursor.line(&self.buffer);
        let line_start = self.buffer.line_start(line);
        let line_end = self.buffer.line_end(line);
        
        // 行のテキストを取得
        let text = self.buffer.text();
        let line_text: String = text.chars()
            .skip(line_start)
            .take(line_end - line_start)
            .collect();
        
        // 行末に移動して改行と行を挿入
        self.cursor.set_position(line_end, &self.buffer);
        self.buffer.insert_char(self.cursor.position, '\n');
        self.cursor.position += 1;
        
        for ch in line_text.chars() {
            self.buffer.insert_char(self.cursor.position, ch);
            self.cursor.position += 1;
        }
        
        self.ensure_cursor_visible();
    }

    /// スクロールアップ
    pub fn scroll_up(&mut self, lines: usize) {
        self.scroll_line = self.scroll_line.saturating_sub(lines);
    }

    /// スクロールダウン
    pub fn scroll_down(&mut self, lines: usize) {
        let max_scroll = self.buffer.line_count().saturating_sub(1);
        self.scroll_line = min(self.scroll_line + lines, max_scroll);
    }

    // ========================================================================
    // マウス入力処理
    // ========================================================================

    /// マウスクリックを処理
    pub fn handle_mouse_click(&mut self, x: u32, y: u32, shift: bool) {
        // ツールバー領域
        if y < TOOLBAR_HEIGHT {
            self.handle_toolbar_click(x);
            return;
        }

        // 行番号領域
        if x < EDIT_AREA_X {
            // 行選択
            let click_line = self.scroll_line + ((y - TOOLBAR_HEIGHT) / CHAR_HEIGHT) as usize;
            self.select_line_at(click_line);
            return;
        }

        // 編集エリア
        let click_col = self.scroll_col + ((x - EDIT_AREA_X) / CHAR_WIDTH) as usize;
        let click_line = self.scroll_line + ((y - TOOLBAR_HEIGHT) / CHAR_HEIGHT) as usize;
        let pos = self.buffer.pos_from_line_col(click_line, click_col);

        if shift && self.selection.is_some() {
            // Shift+クリックで選択範囲を拡張
            if let Some(sel) = &mut self.selection {
                sel.cursor = pos;
            }
        } else if shift {
            // 新しい選択を開始
            self.selection = Some(Selection::new(self.cursor.position, pos));
        } else {
            self.selection = None;
        }

        self.cursor.set_position(pos, &self.buffer);
    }

    /// ツールバークリックを処理
    fn handle_toolbar_click(&mut self, x: u32) {
        // ボタンの位置を計算（各ボタン60px幅、5px間隔）
        let button_width = 60u32;
        let button_spacing = 5u32;
        let button_index = x / (button_width + button_spacing);

        match button_index {
            0 => self.new_file(),
            1 => self.mode = EditorMode::OpenDialog,
            2 => { let _ = self.save_file(); }
            3 => self.mode = EditorMode::SaveDialog,
            4 => self.undo(),
            5 => self.redo(),
            _ => {}
        }
    }

    /// 指定行を選択
    fn select_line_at(&mut self, line: usize) {
        let line = min(line, self.buffer.line_count().saturating_sub(1));
        let start = self.buffer.line_start(line);
        let end = if line + 1 < self.buffer.line_count() {
            self.buffer.line_start(line + 1)
        } else {
            self.buffer.len()
        };
        self.selection = Some(Selection::new(start, end));
        self.cursor.set_position(end, &self.buffer);
    }

    /// マウスドラッグを処理
    pub fn handle_mouse_drag(&mut self, x: u32, y: u32) {
        if y < TOOLBAR_HEIGHT || x < EDIT_AREA_X {
            return;
        }

        let drag_col = self.scroll_col + ((x - EDIT_AREA_X) / CHAR_WIDTH) as usize;
        let drag_line = self.scroll_line + ((y - TOOLBAR_HEIGHT) / CHAR_HEIGHT) as usize;
        let pos = self.buffer.pos_from_line_col(drag_line, drag_col);

        if let Some(sel) = &mut self.selection {
            sel.cursor = pos;
        } else {
            self.selection = Some(Selection::new(self.cursor.position, pos));
        }

        self.cursor.set_position(pos, &self.buffer);
        self.ensure_cursor_visible();
    }

    /// マウスホバーを処理
    pub fn handle_mouse_move(&mut self, x: u32, y: u32) {
        if y < TOOLBAR_HEIGHT {
            let button_width = 60u32;
            let button_spacing = 5u32;
            let button_index = x / (button_width + button_spacing);
            
            self.hover_button = match button_index {
                0 => Some(ToolbarButton::New),
                1 => Some(ToolbarButton::Open),
                2 => Some(ToolbarButton::Save),
                3 => Some(ToolbarButton::SaveAs),
                4 => Some(ToolbarButton::Undo),
                5 => Some(ToolbarButton::Redo),
                _ => None,
            };
        } else {
            self.hover_button = None;
        }
    }

    /// マウスホイールを処理
    pub fn handle_mouse_wheel(&mut self, delta: i32) {
        if delta > 0 {
            self.scroll_up(3);
        } else {
            self.scroll_down(3);
        }
    }

    // ========================================================================
    // レンダリング
    // ========================================================================

    /// エディタを描画
    pub fn render(&mut self, image: &mut Image) {
        // カーソル点滅の更新
        #[cfg(feature = "timer")]
        {
            let now = crate::task::current_tick();
            if now - self.last_blink > 500 {
                self.cursor_visible = !self.cursor_visible;
                self.last_blink = now;
            }
        }

        // 背景をクリア
        self.fill_rect(image, 0, 0, EDITOR_WIDTH, EDITOR_HEIGHT, BG_COLOR);

        // ツールバーを描画
        self.render_toolbar(image);

        // 行番号エリアの背景
        self.fill_rect(image, 0, TOOLBAR_HEIGHT, EDIT_AREA_X, EDIT_AREA_HEIGHT, LINE_NUMBER_BG);

        // テキストと行番号を描画
        self.render_text(image);

        // カーソルを描画
        if self.cursor_visible && self.mode == EditorMode::Normal {
            self.render_cursor(image);
        }

        // ダイアログを描画
        if self.mode != EditorMode::Normal {
            self.render_dialog(image);
        }
    }

    /// ツールバーを描画
    fn render_toolbar(&self, image: &mut Image) {
        self.fill_rect(image, 0, 0, EDITOR_WIDTH, TOOLBAR_HEIGHT, TOOLBAR_BG);

        let buttons = [
            ("New", ToolbarButton::New),
            ("Open", ToolbarButton::Open),
            ("Save", ToolbarButton::Save),
            ("SaveAs", ToolbarButton::SaveAs),
            ("Undo", ToolbarButton::Undo),
            ("Redo", ToolbarButton::Redo),
        ];

        let button_width = 60u32;
        let button_height = 20u32;
        let button_spacing = 5u32;
        let button_y = (TOOLBAR_HEIGHT - button_height) / 2;

        for (i, (label, btn)) in buttons.iter().enumerate() {
            let x = button_spacing + i as u32 * (button_width + button_spacing);
            let color = if self.hover_button == Some(*btn) {
                BUTTON_HOVER_COLOR
            } else {
                BUTTON_COLOR
            };

            self.fill_rect(image, x, button_y, button_width, button_height, color);
            self.draw_text(image, label, x + 4, button_y + 2, TEXT_COLOR);
        }

        // ファイル名を表示
        let file_info = match self.buffer.path() {
            Some(path) => {
                let modified = if self.buffer.is_modified() { " *" } else { "" };
                format!("{}{}", path, modified)
            }
            None => {
                let modified = if self.buffer.is_modified() { " *" } else { "" };
                format!("Untitled{}", modified)
            }
        };
        
        let info_x = 400u32;
        self.draw_text(image, &file_info, info_x, button_y + 2, TEXT_COLOR);
    }

    /// テキストを描画
    fn render_text(&mut self, image: &mut Image) {
        self.highlighter.reset();

        let text = self.buffer.text();
        let lines: Vec<&str> = text.split('\n').collect();

        for i in 0..VISIBLE_LINES {
            let line_idx = self.scroll_line + i;
            if line_idx >= lines.len() {
                break;
            }

            let y = TOOLBAR_HEIGHT + i as u32 * CHAR_HEIGHT;

            // 現在行のハイライト
            if line_idx == self.cursor.line(&self.buffer) {
                self.fill_rect(image, EDIT_AREA_X, y, EDIT_AREA_WIDTH, CHAR_HEIGHT, CURRENT_LINE_BG);
            }

            // 行番号を描画
            let line_num = format!("{:>4} ", line_idx + 1);
            self.draw_text(image, &line_num, 0, y, LINE_NUMBER_COLOR);

            // 行のテキストを描画（シンタックスハイライト付き）
            let line = lines[line_idx];
            let tokens = self.highlighter.highlight_line(line);

            let mut x = EDIT_AREA_X;
            let mut col = 0usize;

            for token in tokens {
                for ch in token.text.chars() {
                    if col >= self.scroll_col && col < self.scroll_col + VISIBLE_COLS {
                        let char_x = x + ((col - self.scroll_col) as u32 * CHAR_WIDTH);
                        let pos = self.buffer.pos_from_line_col(line_idx, col);

                        // 選択範囲のハイライト
                        if let Some(sel) = &self.selection {
                            if sel.contains(pos) {
                                self.fill_rect(image, char_x, y, CHAR_WIDTH, CHAR_HEIGHT, SELECTION_COLOR);
                            }
                        }

                        // 文字を描画
                        let color = SyntaxHighlighter::color_for_token(token.token_type);
                        self.draw_char(image, ch, char_x, y, color);
                    }
                    col += 1;
                }
            }
        }
    }

    /// カーソルを描画
    fn render_cursor(&self, image: &mut Image) {
        let cursor_line = self.cursor.line(&self.buffer);
        let cursor_col = self.cursor.column(&self.buffer);

        if cursor_line >= self.scroll_line
            && cursor_line < self.scroll_line + VISIBLE_LINES
            && cursor_col >= self.scroll_col
            && cursor_col < self.scroll_col + VISIBLE_COLS
        {
            let x = EDIT_AREA_X + ((cursor_col - self.scroll_col) as u32 * CHAR_WIDTH);
            let y = TOOLBAR_HEIGHT + ((cursor_line - self.scroll_line) as u32 * CHAR_HEIGHT);

            // 縦線カーソル
            self.fill_rect(image, x, y, 2, CHAR_HEIGHT, CURSOR_COLOR);
        }
    }

    /// ダイアログを描画
    fn render_dialog(&self, image: &mut Image) {
        let dialog_width = 400u32;
        let dialog_height = 100u32;
        let dialog_x = (EDITOR_WIDTH - dialog_width) / 2;
        let dialog_y = (EDITOR_HEIGHT - dialog_height) / 2;

        // ダイアログ背景
        self.fill_rect(image, dialog_x, dialog_y, dialog_width, dialog_height, TOOLBAR_BG);

        // 枠線
        let border_color = Color { red: 100, green: 100, blue: 100, alpha: 255 };
        self.draw_rect_border(image, dialog_x, dialog_y, dialog_width, dialog_height, border_color);

        // タイトル
        let title = match self.mode {
            EditorMode::OpenDialog => "Open File",
            EditorMode::SaveDialog => "Save File As",
            EditorMode::Normal => "",
        };
        self.draw_text(image, title, dialog_x + 10, dialog_y + 10, TEXT_COLOR);

        // 入力フィールド
        let input_x = dialog_x + 10;
        let input_y = dialog_y + 40;
        let input_width = dialog_width - 20;
        let input_height = 24u32;

        self.fill_rect(image, input_x, input_y, input_width, input_height, BG_COLOR);
        self.draw_rect_border(image, input_x, input_y, input_width, input_height, border_color);
        
        // 入力テキスト
        self.draw_text(image, &self.dialog_input, input_x + 4, input_y + 4, TEXT_COLOR);

        // カーソル
        let cursor_x = input_x + 4 + self.dialog_input.len() as u32 * CHAR_WIDTH;
        self.fill_rect(image, cursor_x, input_y + 4, 2, CHAR_HEIGHT, CURSOR_COLOR);

        // ヒント
        self.draw_text(image, "Press Enter to confirm, Escape to cancel", dialog_x + 10, dialog_y + 75, LINE_NUMBER_COLOR);
    }

    /// 矩形を塗りつぶす
    fn fill_rect(&self, image: &mut Image, x: u32, y: u32, width: u32, height: u32, color: Color) {
        for dy in 0..height {
            for dx in 0..width {
                let px = x + dx;
                let py = y + dy;
                if px < image.width() && py < image.height() {
                    image.set_pixel(px, py, color);
                }
            }
        }
    }

    /// 矩形の枠線を描画
    fn draw_rect_border(&self, image: &mut Image, x: u32, y: u32, width: u32, height: u32, color: Color) {
        // 上辺
        for dx in 0..width {
            if x + dx < image.width() && y < image.height() {
                image.set_pixel(x + dx, y, color);
            }
        }
        // 下辺
        for dx in 0..width {
            if x + dx < image.width() && y + height - 1 < image.height() {
                image.set_pixel(x + dx, y + height - 1, color);
            }
        }
        // 左辺
        for dy in 0..height {
            if x < image.width() && y + dy < image.height() {
                image.set_pixel(x, y + dy, color);
            }
        }
        // 右辺
        for dy in 0..height {
            if x + width - 1 < image.width() && y + dy < image.height() {
                image.set_pixel(x + width - 1, y + dy, color);
            }
        }
    }

    /// 文字を描画
    fn draw_char(&self, image: &mut Image, ch: char, x: u32, y: u32, color: Color) {
        if let Some(bitmap) = get_char_bitmap(ch) {
            for (row, &bits) in bitmap.iter().enumerate() {
                for col in 0..8 {
                    if (bits >> (7 - col)) & 1 == 1 {
                        let px = x + col;
                        let py = y + row as u32;
                        if px < image.width() && py < image.height() {
                            image.set_pixel(px, py, color);
                        }
                    }
                }
            }
        }
    }

    /// テキストを描画
    fn draw_text(&self, image: &mut Image, text: &str, x: u32, y: u32, color: Color) {
        let mut cx = x;
        for ch in text.chars() {
            self.draw_char(image, ch, cx, y, color);
            cx += CHAR_WIDTH;
        }
    }

    // ========================================================================
    // アクセサ
    // ========================================================================

    /// バッファへの参照を取得
    pub fn buffer(&self) -> &TextBuffer {
        &self.buffer
    }

    /// カーソル位置を取得
    pub fn cursor_position(&self) -> usize {
        self.cursor.position
    }

    /// カーソルの行を取得
    pub fn cursor_line(&self) -> usize {
        self.cursor.line(&self.buffer)
    }

    /// カーソルの列を取得
    pub fn cursor_column(&self) -> usize {
        self.cursor.column(&self.buffer)
    }

    /// 選択範囲があるかどうか
    pub fn has_selection(&self) -> bool {
        self.selection.map(|s| !s.is_empty()).unwrap_or(false)
    }

    /// 変更されているかどうか
    pub fn is_modified(&self) -> bool {
        self.buffer.is_modified()
    }

    /// ファイルパスを取得
    pub fn file_path(&self) -> Option<&str> {
        self.buffer.path().map(|s| s.as_str())
    }
}

impl Default for Editor {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SpecialKey - 特殊キー定義
// ============================================================================

/// 特殊キー
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpecialKey {
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rope_new() {
        let rope = RopeNode::new();
        assert_eq!(rope.len(), 0);
        assert_eq!(rope.lines(), 1);
    }

    #[test]
    fn test_rope_from_str() {
        let rope = RopeNode::from_str("Hello\nWorld");
        assert_eq!(rope.len(), 11);
        assert_eq!(rope.lines(), 2);
    }

    #[test]
    fn test_rope_insert() {
        let mut rope = RopeNode::from_str("Hello");
        rope.insert(5, " World");
        assert_eq!(rope.to_string(), "Hello World");
    }

    #[test]
    fn test_rope_delete() {
        let mut rope = RopeNode::from_str("Hello World");
        rope.delete(5, 11);
        assert_eq!(rope.to_string(), "Hello");
    }

    #[test]
    fn test_text_buffer_insert() {
        let mut buf = TextBuffer::new();
        buf.insert_char(0, 'H');
        buf.insert_char(1, 'i');
        assert_eq!(buf.text(), "Hi");
        assert!(buf.is_modified());
    }

    #[test]
    fn test_cursor_movement() {
        let buf = TextBuffer::from_str("Hello\nWorld");
        let mut cursor = Cursor::new();
        
        cursor.move_right(&buf);
        assert_eq!(cursor.position, 1);
        
        cursor.move_down(&buf);
        assert_eq!(cursor.line(&buf), 1);
        
        cursor.move_to_line_start(&buf);
        assert_eq!(cursor.column(&buf), 0);
    }

    #[test]
    fn test_selection() {
        let buf = TextBuffer::from_str("Hello World");
        let sel = Selection::new(0, 5);
        
        assert_eq!(sel.start(), 0);
        assert_eq!(sel.end(), 5);
        assert!(!sel.is_empty());
        assert!(sel.contains(3));
        assert!(!sel.contains(6));
        assert_eq!(sel.get_text(&buf), "Hello");
    }

    #[test]
    fn test_syntax_highlighter() {
        let mut hl = SyntaxHighlighter::new();
        let tokens = hl.highlight_line("fn main() {}");
        
        assert!(tokens.len() > 0);
        assert_eq!(tokens[0].text, "fn");
        assert_eq!(tokens[0].token_type, TokenType::Keyword);
    }

    #[test]
    fn test_editor_new() {
        let editor = Editor::new();
        assert_eq!(editor.cursor_position(), 0);
        assert!(!editor.is_modified());
    }

    #[test]
    fn test_editor_insert() {
        let mut editor = Editor::new();
        editor.insert_char('H');
        editor.insert_char('i');
        
        assert_eq!(editor.buffer().text(), "Hi");
        assert!(editor.is_modified());
    }

    #[test]
    fn test_editor_undo_redo() {
        let mut editor = Editor::new();
        editor.insert_char('A');
        editor.insert_char('B');
        
        assert_eq!(editor.buffer().text(), "AB");
        
        editor.undo();
        assert_eq!(editor.buffer().text(), "A");
        
        editor.redo();
        assert_eq!(editor.buffer().text(), "AB");
    }
}
