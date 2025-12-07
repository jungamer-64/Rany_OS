// ============================================================================
// src/application/terminal/buffer.rs - Terminal Ring Buffer
// ============================================================================
//!
//! スクロールバック付きターミナルバッファ

extern crate alloc;

use alloc::vec::Vec;

use super::cell::TerminalLine;
use super::constants::{SCROLLBACK_LINES, TERM_ROWS};

// ============================================================================
// TerminalBuffer - リングバッファ
// ============================================================================

/// スクロールバック付きターミナルバッファ
pub struct TerminalBuffer {
    /// 行バッファ (リングバッファ)
    lines: Vec<TerminalLine>,
    /// バッファの先頭インデックス
    head: usize,
    /// 現在の表示行数
    line_count: usize,
    /// スクロール位置 (0 = 最新)
    scroll_offset: usize,
}

impl Default for TerminalBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl TerminalBuffer {
    /// 新しいバッファを作成
    pub fn new() -> Self {
        let mut lines = Vec::with_capacity(SCROLLBACK_LINES);
        for _ in 0..SCROLLBACK_LINES {
            lines.push(TerminalLine::new());
        }
        Self {
            lines,
            head: 0,
            line_count: TERM_ROWS,
            scroll_offset: 0,
        }
    }

    /// 論理行インデックスを物理インデックスに変換
    fn physical_index(&self, logical: usize) -> usize {
        (self.head + logical) % SCROLLBACK_LINES
    }

    /// 指定行を取得
    pub fn get_line(&self, row: usize) -> &TerminalLine {
        let idx = self.physical_index(row + self.scroll_offset);
        &self.lines[idx]
    }

    /// 指定行を取得 (可変)
    pub fn get_line_mut(&mut self, row: usize) -> &mut TerminalLine {
        let idx = self.physical_index(row);
        &mut self.lines[idx]
    }

    /// 新しい行を追加 (スクロール)
    pub fn scroll_up(&mut self) {
        // 新しい行を追加
        if self.line_count < SCROLLBACK_LINES {
            self.line_count += 1;
        } else {
            // バッファが満杯なので先頭を進める
            self.head = (self.head + 1) % SCROLLBACK_LINES;
        }
        
        // 最終行をクリア
        let last_idx = self.physical_index(self.line_count - 1);
        self.lines[last_idx].clear();
    }

    /// スクロールバックを上に移動
    pub fn scroll_back_up(&mut self, lines: usize) {
        let max_scroll = self.line_count.saturating_sub(TERM_ROWS);
        self.scroll_offset = (self.scroll_offset + lines).min(max_scroll);
    }

    /// スクロールバックを下に移動
    pub fn scroll_back_down(&mut self, lines: usize) {
        self.scroll_offset = self.scroll_offset.saturating_sub(lines);
    }

    /// スクロールバックをリセット (最新に戻る)
    pub fn reset_scroll(&mut self) {
        self.scroll_offset = 0;
    }

    /// 全画面クリア
    pub fn clear_all(&mut self) {
        for line in &mut self.lines {
            line.clear();
        }
        self.head = 0;
        self.line_count = TERM_ROWS;
        self.scroll_offset = 0;
    }
}
