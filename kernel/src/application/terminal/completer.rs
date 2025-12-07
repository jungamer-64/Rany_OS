// ============================================================================
// src/application/terminal/completer.rs - Tab Completion
// ============================================================================
//!
//! タブ補完機能

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

// ============================================================================
// TabCompleter
// ============================================================================

/// タブ補完のコールバック型
pub type CompletionCallback = fn(&str) -> Vec<String>;

/// タブ補完ヘルパー
pub struct TabCompleter {
    /// 候補リスト
    candidates: Vec<String>,
    /// 現在のインデックス
    index: usize,
    /// 補完中のプレフィックス
    prefix: String,
}

impl Default for TabCompleter {
    fn default() -> Self {
        Self::new()
    }
}

impl TabCompleter {
    /// 新しいTabCompleterを作成
    pub fn new() -> Self {
        Self {
            candidates: Vec::new(),
            index: 0,
            prefix: String::new(),
        }
    }

    /// 候補を設定
    pub fn set_candidates(&mut self, prefix: &str, candidates: Vec<String>) {
        self.prefix = String::from(prefix);
        self.candidates = candidates;
        self.index = 0;
    }

    /// 次の候補を取得
    pub fn next(&mut self) -> Option<&str> {
        if self.candidates.is_empty() {
            return None;
        }
        let result = self.candidates.get(self.index).map(|s| s.as_str());
        self.index = (self.index + 1) % self.candidates.len();
        result
    }

    /// 前の候補を取得
    pub fn previous(&mut self) -> Option<&str> {
        if self.candidates.is_empty() {
            return None;
        }
        if self.index == 0 {
            self.index = self.candidates.len() - 1;
        } else {
            self.index -= 1;
        }
        self.candidates.get(self.index).map(|s| s.as_str())
    }

    /// 候補数を取得
    pub fn count(&self) -> usize {
        self.candidates.len()
    }

    /// リセット
    pub fn reset(&mut self) {
        self.candidates.clear();
        self.index = 0;
        self.prefix.clear();
    }

    /// 補完中のプレフィックス
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// 全候補を取得
    pub fn all_candidates(&self) -> &[String] {
        &self.candidates
    }
}
