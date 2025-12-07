// ============================================================================
// src/application/terminal/cell.rs - Terminal Cell and Line
// ============================================================================
//!
//! ターミナルセルと行の定義

extern crate alloc;

use alloc::vec::Vec;
use alloc::vec;

use crate::graphics::Color;
use super::constants::{DEFAULT_FG, DEFAULT_BG, TERM_COLS};

// ============================================================================
// Cell - ターミナルセル
// ============================================================================

/// 文字セル
#[derive(Clone, Copy)]
pub struct Cell {
    /// 文字 (ASCIIまたはUnicode)
    pub ch: char,
    /// 前景色
    pub fg: Color,
    /// 背景色
    pub bg: Color,
    /// 太字
    pub bold: bool,
    /// 下線
    pub underline: bool,
    /// 反転
    pub inverse: bool,
}

impl Default for Cell {
    fn default() -> Self {
        Self {
            ch: ' ',
            fg: DEFAULT_FG,
            bg: DEFAULT_BG,
            bold: false,
            underline: false,
            inverse: false,
        }
    }
}

impl Cell {
    /// 新しいセルを作成
    pub fn new(ch: char, fg: Color, bg: Color) -> Self {
        Self {
            ch,
            fg,
            bg,
            bold: false,
            underline: false,
            inverse: false,
        }
    }

    /// 描画時の実際の前景色と背景色を取得
    pub fn effective_colors(&self) -> (Color, Color) {
        if self.inverse {
            (self.bg, self.fg)
        } else {
            (self.fg, self.bg)
        }
    }
}

// ============================================================================
// TerminalLine - ターミナル行
// ============================================================================

/// ターミナル1行分のデータ
#[derive(Clone)]
pub struct TerminalLine {
    /// セル配列
    cells: Vec<Cell>,
    /// 折り返しフラグ
    pub wrapped: bool,
}

impl Default for TerminalLine {
    fn default() -> Self {
        Self::new()
    }
}

impl TerminalLine {
    /// 新しい行を作成
    pub fn new() -> Self {
        Self {
            cells: vec![Cell::default(); TERM_COLS],
            wrapped: false,
        }
    }

    /// 指定位置のセルを取得 (コピーを返す)
    pub fn get(&self, col: usize) -> Cell {
        self.cells.get(col).copied().unwrap_or_default()
    }

    /// 指定位置のセルへの参照を取得
    pub fn get_ref(&self, col: usize) -> Option<&Cell> {
        self.cells.get(col)
    }

    /// 指定位置のセルを設定
    pub fn set(&mut self, col: usize, cell: Cell) {
        if col < self.cells.len() {
            self.cells[col] = cell;
        }
    }

    /// 行をクリア
    pub fn clear(&mut self) {
        for cell in &mut self.cells {
            *cell = Cell::default();
        }
        self.wrapped = false;
    }

    /// 指定位置以降をクリア
    pub fn clear_from(&mut self, col: usize) {
        for i in col..self.cells.len() {
            self.cells[i] = Cell::default();
        }
    }

    /// 指定位置以前をクリア
    pub fn clear_to(&mut self, col: usize) {
        for i in 0..=col.min(self.cells.len() - 1) {
            self.cells[i] = Cell::default();
        }
    }
}
