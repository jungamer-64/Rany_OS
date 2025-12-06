// ============================================================================
// src/graphics/console.rs - Text Console Implementation
// ============================================================================
//!
//! テキストコンソール実装
//!
//! フレームバッファベースのテキストモードコンソール

#![allow(dead_code)]

use alloc::vec;
use alloc::vec::Vec;

use super::types::Color;
use super::framebuffer::Framebuffer;
use super::font::BitmapFont;

// ============================================================================
// Text Console
// ============================================================================

/// テキストコンソール
pub struct TextConsole {
    /// フレームバッファへの参照
    fb: *mut Framebuffer,
    /// フォント
    font: BitmapFont,
    /// 現在のカーソル位置（文字単位）
    cursor_x: u32,
    cursor_y: u32,
    /// コンソールサイズ（文字単位）
    cols: u32,
    rows: u32,
    /// 文字色
    fg_color: Color,
    /// 背景色
    bg_color: Color,
    /// テキストバッファ
    buffer: Vec<char>,
}

unsafe impl Send for TextConsole {}
unsafe impl Sync for TextConsole {}

impl TextConsole {
    /// 新しいコンソールを作成
    pub fn new(fb: &mut Framebuffer) -> Self {
        let font = BitmapFont::default_8x16();
        let cols = fb.width() / font.width();
        let rows = fb.height() / font.height();

        let buffer_size = (cols * rows) as usize;
        let buffer = vec![' '; buffer_size];

        Self {
            fb,
            font,
            cursor_x: 0,
            cursor_y: 0,
            cols,
            rows,
            fg_color: Color::WHITE,
            bg_color: Color::BLACK,
            buffer,
        }
    }

    /// 画面をクリア
    pub fn clear(&mut self) {
        unsafe {
            (*self.fb).clear(self.bg_color);
        }
        self.cursor_x = 0;
        self.cursor_y = 0;
        self.buffer.fill(' ');
    }

    /// 色を設定
    pub fn set_colors(&mut self, fg: Color, bg: Color) {
        self.fg_color = fg;
        self.bg_color = bg;
    }

    /// 文字を出力
    pub fn put_char(&mut self, c: char) {
        match c {
            '\n' => {
                self.cursor_x = 0;
                self.cursor_y += 1;
            }
            '\r' => {
                self.cursor_x = 0;
            }
            '\t' => {
                let spaces = 4 - (self.cursor_x % 4);
                for _ in 0..spaces {
                    self.put_char(' ');
                }
            }
            '\x08' => {
                // バックスペース
                if self.cursor_x > 0 {
                    self.cursor_x -= 1;
                    self.draw_char_at(self.cursor_x, self.cursor_y, ' ');
                }
            }
            _ => {
                if self.cursor_x >= self.cols {
                    self.cursor_x = 0;
                    self.cursor_y += 1;
                }

                self.draw_char_at(self.cursor_x, self.cursor_y, c);
                self.cursor_x += 1;
            }
        }

        // スクロールが必要な場合
        if self.cursor_y >= self.rows {
            self.scroll_up();
            self.cursor_y = self.rows - 1;
        }
    }

    /// 指定位置に文字を描画
    fn draw_char_at(&mut self, col: u32, row: u32, c: char) {
        let x = (col * self.font.width()) as i32;
        let y = (row * self.font.height()) as i32;

        // バッファを更新
        let idx = (row * self.cols + col) as usize;
        if idx < self.buffer.len() {
            self.buffer[idx] = c;
        }

        unsafe {
            self.font
                .draw_char(&mut *self.fb, x, y, c, self.fg_color, Some(self.bg_color));
        }
    }

    /// 画面を1行スクロールアップ
    fn scroll_up(&mut self) {
        // バッファをシフト
        for row in 1..self.rows {
            for col in 0..self.cols {
                let src_idx = (row * self.cols + col) as usize;
                let dst_idx = ((row - 1) * self.cols + col) as usize;
                if src_idx < self.buffer.len() && dst_idx < self.buffer.len() {
                    self.buffer[dst_idx] = self.buffer[src_idx];
                }
            }
        }

        // 最後の行をクリア
        let last_row_start = ((self.rows - 1) * self.cols) as usize;
        for i in 0..self.cols as usize {
            if last_row_start + i < self.buffer.len() {
                self.buffer[last_row_start + i] = ' ';
            }
        }

        // 画面を再描画
        self.redraw();
    }

    /// 画面全体を再描画
    fn redraw(&mut self) {
        unsafe {
            (*self.fb).clear(self.bg_color);
        }

        for row in 0..self.rows {
            for col in 0..self.cols {
                let idx = (row * self.cols + col) as usize;
                if idx < self.buffer.len() {
                    let c = self.buffer[idx];
                    if c != ' ' {
                        let x = (col * self.font.width()) as i32;
                        let y = (row * self.font.height()) as i32;
                        unsafe {
                            self.font
                                .draw_char(&mut *self.fb, x, y, c, self.fg_color, None);
                        }
                    }
                }
            }
        }
    }

    /// 文字列を出力
    pub fn write_str(&mut self, s: &str) {
        for c in s.chars() {
            self.put_char(c);
        }
    }

    /// カーソル位置を設定
    pub fn set_cursor(&mut self, col: u32, row: u32) {
        self.cursor_x = col.min(self.cols - 1);
        self.cursor_y = row.min(self.rows - 1);
    }

    /// カーソル位置を取得
    pub fn cursor(&self) -> (u32, u32) {
        (self.cursor_x, self.cursor_y)
    }
}

impl core::fmt::Write for TextConsole {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        TextConsole::write_str(self, s);
        Ok(())
    }
}
