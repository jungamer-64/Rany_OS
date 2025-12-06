// ============================================================================
// src/shell/graphical/types.rs - Graphical Shell Types
// ============================================================================
//!
//! # グラフィカルシェル型定義

#![allow(dead_code)]

use alloc::string::{String, ToString};
use crate::graphics::Color;
use crate::input::MouseEvent;

// ============================================================================
// Configuration Constants
// ============================================================================

/// 最大履歴エントリ数
pub const MAX_HISTORY: usize = 100;

/// 最大行バッファサイズ
pub const MAX_LINE_LENGTH: usize = 256;

/// スクロールバック行数
pub const SCROLLBACK_LINES: usize = 500;

/// カーソル点滅間隔（ミリ秒）
pub const CURSOR_BLINK_MS: u64 = 500;

/// フォント幅（定数）
pub const FONT_WIDTH: usize = 8;

/// フォント高さ（定数）
pub const FONT_HEIGHT: usize = 16;

// ============================================================================
// Theme Colors
// ============================================================================

/// シェルのカラーテーマ
#[derive(Clone, Copy)]
pub struct ShellTheme {
    /// 背景色
    pub background: Color,
    /// 通常テキスト色
    pub foreground: Color,
    /// プロンプト色
    pub prompt: Color,
    /// 入力テキスト色
    pub input: Color,
    /// エラー色
    pub error: Color,
    /// 成功色
    pub success: Color,
    /// 情報色
    pub info: Color,
    /// 警告色
    pub warning: Color,
    /// カーソル色
    pub cursor: Color,
    /// 選択色
    pub selection: Color,
}

impl Default for ShellTheme {
    fn default() -> Self {
        Self {
            background: Color::new(24, 24, 32),      // ダークブルーグレー
            foreground: Color::new(220, 220, 220),   // ライトグレー
            prompt: Color::new(80, 200, 255),        // シアン
            input: Color::WHITE,                     // 白
            error: Color::new(255, 80, 80),          // 赤
            success: Color::new(80, 255, 80),        // 緑
            info: Color::new(100, 180, 255),         // 青
            warning: Color::new(255, 200, 80),       // オレンジ
            cursor: Color::new(255, 255, 255),       // 白
            selection: Color::new(60, 80, 120),      // 選択背景
        }
    }
}

// ============================================================================
// Line Buffer
// ============================================================================

/// 行バッファ（編集中の入力）
#[derive(Clone)]
pub struct LineBuffer {
    /// バッファ内容
    pub content: String,
    /// カーソル位置（文字単位）
    pub cursor: usize,
}

impl LineBuffer {
    pub fn new() -> Self {
        Self {
            content: String::new(),
            cursor: 0,
        }
    }

    pub fn clear(&mut self) {
        self.content.clear();
        self.cursor = 0;
    }

    pub fn insert(&mut self, c: char) {
        if self.content.len() < MAX_LINE_LENGTH {
            self.content.insert(self.cursor, c);
            self.cursor += 1;
        }
    }

    pub fn insert_str(&mut self, s: &str) {
        for c in s.chars() {
            self.insert(c);
        }
    }

    pub fn backspace(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            self.content.remove(self.cursor);
        }
    }

    pub fn delete(&mut self) {
        if self.cursor < self.content.len() {
            self.content.remove(self.cursor);
        }
    }

    pub fn move_left(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }

    pub fn move_right(&mut self) {
        if self.cursor < self.content.len() {
            self.cursor += 1;
        }
    }

    pub fn move_home(&mut self) {
        self.cursor = 0;
    }

    pub fn move_end(&mut self) {
        self.cursor = self.content.len();
    }

    pub fn move_word_left(&mut self) {
        // 空白をスキップ
        while self.cursor > 0 && self.content.chars().nth(self.cursor - 1) == Some(' ') {
            self.cursor -= 1;
        }
        // 単語の先頭まで移動
        while self.cursor > 0 && self.content.chars().nth(self.cursor - 1) != Some(' ') {
            self.cursor -= 1;
        }
    }

    pub fn move_word_right(&mut self) {
        let len = self.content.len();
        // 単語の終わりまで移動
        while self.cursor < len && self.content.chars().nth(self.cursor) != Some(' ') {
            self.cursor += 1;
        }
        // 空白をスキップ
        while self.cursor < len && self.content.chars().nth(self.cursor) == Some(' ') {
            self.cursor += 1;
        }
    }

    pub fn delete_word(&mut self) {
        let start = self.cursor;
        self.move_word_left();
        let end = self.cursor;
        if start > end {
            self.content.drain(end..start);
        }
    }

    pub fn clear_to_end(&mut self) {
        self.content.truncate(self.cursor);
    }

    pub fn clear_to_start(&mut self) {
        self.content = self.content[self.cursor..].to_string();
        self.cursor = 0;
    }

    pub fn set(&mut self, s: &str) {
        self.content = s.to_string();
        self.cursor = self.content.len();
    }

    pub fn as_str(&self) -> &str {
        &self.content
    }

    pub fn len(&self) -> usize {
        self.content.len()
    }

    pub fn is_empty(&self) -> bool {
        self.content.is_empty()
    }
}

impl Default for LineBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Console Line
// ============================================================================

/// コンソール行（表示用）
#[derive(Clone)]
pub struct ConsoleLine {
    /// テキスト内容
    pub text: String,
    /// 色
    pub color: Color,
}

impl ConsoleLine {
    pub fn new(text: String, color: Color) -> Self {
        Self { text, color }
    }
}

// ============================================================================
// Mouse State
// ============================================================================

/// マウスカーソルの状態
#[derive(Clone, Copy)]
pub struct MouseState {
    /// X座標（ピクセル）
    pub x: i32,
    /// Y座標（ピクセル）
    pub y: i32,
    /// 左ボタンが押されているか
    pub left_down: bool,
    /// 右ボタンが押されているか
    pub right_down: bool,
    /// 中ボタンが押されているか
    pub middle_down: bool,
}

impl MouseState {
    pub fn new() -> Self {
        Self {
            x: 400, // 画面中央付近で開始
            y: 300,
            left_down: false,
            right_down: false,
            middle_down: false,
        }
    }
    
    /// イベントから状態を更新し、新しい位置を返す
    pub fn update(&mut self, event: &MouseEvent, max_x: i32, max_y: i32) {
        // 位置の更新（境界チェック付き）
        self.x = (self.x + event.dx).clamp(0, max_x - 1);
        self.y = (self.y + event.dy).clamp(0, max_y - 1);
        
        // ボタン状態の更新
        self.left_down = event.left_down;
        self.right_down = event.right_down;
        self.middle_down = event.middle_down;
    }
}

impl Default for MouseState {
    fn default() -> Self {
        Self::new()
    }
}
