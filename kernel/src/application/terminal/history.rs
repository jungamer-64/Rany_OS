// ============================================================================
// src/application/terminal/history.rs - Command History and Line Editor
// ============================================================================
//!
//! コマンド履歴とラインエディタ

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;

use super::constants::HISTORY_MAX_SIZE;

// ============================================================================
// CommandHistory
// ============================================================================

/// コマンド履歴
pub struct CommandHistory {
    /// 履歴エントリ
    entries: Vec<String>,
    /// 現在の位置 (None = 新規入力中)
    pub position: Option<usize>,
    /// 最大サイズ
    max_size: usize,
}

impl Default for CommandHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandHistory {
    /// 新しい履歴を作成
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            position: None,
            max_size: HISTORY_MAX_SIZE,
        }
    }

    /// エントリを追加
    pub fn add(&mut self, command: &str) {
        let cmd = command.trim();
        if cmd.is_empty() {
            return;
        }
        
        // 重複を避ける (最後のエントリと同じなら追加しない)
        if self.entries.last().map(|s| s.as_str()) == Some(cmd) {
            return;
        }
        
        self.entries.push(String::from(cmd));
        
        // 最大サイズを超えたら古いエントリを削除
        if self.entries.len() > self.max_size {
            self.entries.remove(0);
        }
        
        // 位置をリセット
        self.position = None;
    }

    /// 前の履歴を取得 (↑キー)
    pub fn previous(&mut self) -> Option<&str> {
        if self.entries.is_empty() {
            return None;
        }
        
        let pos = match self.position {
            None => self.entries.len().saturating_sub(1),
            Some(p) => p.saturating_sub(1),
        };
        
        self.position = Some(pos);
        self.entries.get(pos).map(|s| s.as_str())
    }

    /// 次の履歴を取得 (↓キー)
    pub fn next(&mut self) -> Option<&str> {
        if self.entries.is_empty() {
            return None;
        }
        
        match self.position {
            None => None,
            Some(p) => {
                if p + 1 >= self.entries.len() {
                    self.position = None;
                    None
                } else {
                    self.position = Some(p + 1);
                    self.entries.get(p + 1).map(|s| s.as_str())
                }
            }
        }
    }

    /// 位置をリセット
    pub fn reset_position(&mut self) {
        self.position = None;
    }

    /// 履歴を検索
    pub fn search(&self, prefix: &str) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|e| e.starts_with(prefix))
            .map(|s| s.as_str())
            .collect()
    }

    /// 履歴の件数
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 履歴が空かどうか
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 全履歴を取得
    pub fn entries(&self) -> &[String] {
        &self.entries
    }
}

// ============================================================================
// LineEditor
// ============================================================================

/// ラインエディタ (readline風)
pub struct LineEditor {
    /// 現在の入力行
    buffer: String,
    /// カーソル位置 (文字数)
    cursor: usize,
    /// コマンド履歴
    history: CommandHistory,
    /// 一時保存された入力 (履歴ナビゲーション用)
    saved_input: Option<String>,
}

impl Default for LineEditor {
    fn default() -> Self {
        Self::new()
    }
}

impl LineEditor {
    /// 新しいラインエディタを作成
    pub fn new() -> Self {
        Self {
            buffer: String::new(),
            cursor: 0,
            history: CommandHistory::new(),
            saved_input: None,
        }
    }

    /// 現在の入力を取得
    pub fn buffer(&self) -> &str {
        &self.buffer
    }

    /// カーソル位置を取得
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// 文字を挿入
    pub fn insert(&mut self, ch: char) {
        if self.cursor >= self.buffer.len() {
            self.buffer.push(ch);
        } else {
            self.buffer.insert(self.cursor, ch);
        }
        self.cursor += 1;
    }

    /// 文字列を挿入
    pub fn insert_str(&mut self, s: &str) {
        for ch in s.chars() {
            self.insert(ch);
        }
    }

    /// カーソル位置の文字を削除 (Delete)
    pub fn delete(&mut self) {
        if self.cursor < self.buffer.len() {
            self.buffer.remove(self.cursor);
        }
    }

    /// カーソル前の文字を削除 (Backspace)
    pub fn backspace(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            self.buffer.remove(self.cursor);
        }
    }

    /// カーソルを左に移動
    pub fn move_left(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }

    /// カーソルを右に移動
    pub fn move_right(&mut self) {
        if self.cursor < self.buffer.len() {
            self.cursor += 1;
        }
    }

    /// カーソルを行頭に移動 (Home / Ctrl+A)
    pub fn move_home(&mut self) {
        self.cursor = 0;
    }

    /// カーソルを行末に移動 (End / Ctrl+E)
    pub fn move_end(&mut self) {
        self.cursor = self.buffer.len();
    }

    /// 単語単位で左に移動 (Ctrl+←)
    pub fn move_word_left(&mut self) {
        // 空白をスキップ
        while self.cursor > 0 && self.buffer.chars().nth(self.cursor - 1) == Some(' ') {
            self.cursor -= 1;
        }
        // 単語の先頭まで移動
        while self.cursor > 0 && self.buffer.chars().nth(self.cursor - 1) != Some(' ') {
            self.cursor -= 1;
        }
    }

    /// 単語単位で右に移動 (Ctrl+→)
    pub fn move_word_right(&mut self) {
        let len = self.buffer.len();
        // 現在の単語をスキップ
        while self.cursor < len && self.buffer.chars().nth(self.cursor) != Some(' ') {
            self.cursor += 1;
        }
        // 空白をスキップ
        while self.cursor < len && self.buffer.chars().nth(self.cursor) == Some(' ') {
            self.cursor += 1;
        }
    }

    /// カーソルから行末までを削除 (Ctrl+K)
    pub fn kill_to_end(&mut self) -> String {
        let killed = String::from(&self.buffer[self.cursor..]);
        self.buffer.truncate(self.cursor);
        killed
    }

    /// カーソルから行頭までを削除 (Ctrl+U)
    pub fn kill_to_start(&mut self) -> String {
        let killed = String::from(&self.buffer[..self.cursor]);
        self.buffer = String::from(&self.buffer[self.cursor..]);
        self.cursor = 0;
        killed
    }

    /// 単語を削除 (Ctrl+W)
    pub fn kill_word(&mut self) -> String {
        let start = self.cursor;
        self.move_word_left();
        let killed = String::from(&self.buffer[self.cursor..start]);
        self.buffer = format!("{}{}", &self.buffer[..self.cursor], &self.buffer[start..]);
        killed
    }

    /// 行をクリア
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.cursor = 0;
    }

    /// 入力を確定して取得
    pub fn submit(&mut self) -> String {
        let line = core::mem::take(&mut self.buffer);
        self.cursor = 0;
        self.history.add(&line);
        self.history.reset_position();
        self.saved_input = None;
        line
    }

    /// 履歴の前へ (↑)
    pub fn history_previous(&mut self) -> bool {
        // 初回は現在の入力を保存
        if self.history.position.is_none() {
            self.saved_input = Some(self.buffer.clone());
        }
        
        if let Some(entry) = self.history.previous() {
            self.buffer = String::from(entry);
            self.cursor = self.buffer.len();
            true
        } else {
            false
        }
    }

    /// 履歴の次へ (↓)
    pub fn history_next(&mut self) -> bool {
        if let Some(entry) = self.history.next() {
            self.buffer = String::from(entry);
            self.cursor = self.buffer.len();
            true
        } else {
            // 履歴の最後を超えたら保存した入力を復元
            if let Some(saved) = self.saved_input.take() {
                self.buffer = saved;
                self.cursor = self.buffer.len();
            }
            false
        }
    }

    /// 履歴への参照を取得
    pub fn history(&self) -> &CommandHistory {
        &self.history
    }

    /// 履歴への可変参照を取得
    pub fn history_mut(&mut self) -> &mut CommandHistory {
        &mut self.history
    }
}
