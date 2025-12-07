// ============================================================================
// src/application/terminal/selection.rs - Text Selection and Clipboard
// ============================================================================
//!
//! テキスト選択とクリップボード

extern crate alloc;

use alloc::string::String;
use spin::Mutex;

// ============================================================================
// Selection
// ============================================================================

/// 選択範囲
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selection {
    /// 開始位置 (col, row)
    pub start: (usize, usize),
    /// 終了位置 (col, row)
    pub end: (usize, usize),
}

impl Selection {
    /// 新しい選択を作成
    pub fn new(start: (usize, usize), end: (usize, usize)) -> Self {
        Self { start, end }
    }

    /// 正規化された選択を取得 (start <= end)
    pub fn normalized(&self) -> Self {
        if self.start.1 > self.end.1 || 
           (self.start.1 == self.end.1 && self.start.0 > self.end.0) {
            Self { start: self.end, end: self.start }
        } else {
            *self
        }
    }

    /// 位置が選択範囲内かどうか
    pub fn contains(&self, col: usize, row: usize) -> bool {
        let norm = self.normalized();
        if row < norm.start.1 || row > norm.end.1 {
            return false;
        }
        if row == norm.start.1 && col < norm.start.0 {
            return false;
        }
        if row == norm.end.1 && col > norm.end.0 {
            return false;
        }
        true
    }
}

// ============================================================================
// Clipboard
// ============================================================================

/// シンプルなクリップボード
pub struct Clipboard {
    /// 内容
    content: Mutex<String>,
}

impl Clipboard {
    /// 新しいクリップボードを作成
    pub const fn new() -> Self {
        Self {
            content: Mutex::new(String::new()),
        }
    }

    /// テキストをコピー
    pub fn copy(&self, text: &str) {
        let mut content = self.content.lock();
        content.clear();
        content.push_str(text);
    }

    /// テキストをペースト
    pub fn paste(&self) -> String {
        self.content.lock().clone()
    }

    /// クリア
    pub fn clear(&self) {
        self.content.lock().clear();
    }

    /// 空かどうか
    pub fn is_empty(&self) -> bool {
        self.content.lock().is_empty()
    }
}

/// グローバルクリップボード
pub static CLIPBOARD: Clipboard = Clipboard::new();
