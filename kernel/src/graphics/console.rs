// ============================================================================
// src/graphics/console.rs - Text Console Implementation
// ============================================================================
//!
//! テキストコンソール実装
//!
//! フレームバッファベースのテキストモードコンソール

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use crate::console::{ConsoleDriver, TerminalBuffer};
use super::framebuffer::Framebuffer;
use super::{BitmapFont, Color, Font};
// ============================================================================
// Text Console
// ============================================================================

/// テキストコンソール
///
/// `ConsoleManager`のドライバーとして機能し、`TerminalBuffer`の内容を
/// フレームバッファに描画します。
pub struct TextConsole {
    /// フレームバッファへの参照
    fb: *mut Framebuffer,
    /// フォント (dynamic dispatch for polyglot support)
    font: Box<dyn Font + Send + Sync>,
}

unsafe impl Send for TextConsole {}
unsafe impl Sync for TextConsole {}

impl TextConsole {
    /// 新しいコンソールを作成
    ///
    /// # Returns
    /// (TextConsole, cols, rows) - コンソールと計算された桁数・行数
    pub fn new(fb: &mut Framebuffer) -> (Self, usize, usize) {
        let font = Box::new(BitmapFont::default_8x16());
        let cols = fb.width() / font.width();
        let rows = fb.height() / font.height();

        (
            Self {
                fb,
                font,
            },
            cols as usize,
            rows as usize,
        )
    }

    /// フォントを変更
    pub fn set_font(&mut self, font: Box<dyn Font + Send + Sync>) {
        self.font = font;
        // 注意: フォント変更によるリサイズは ConsoleManager 側でハンドルする必要があります
        // ここでは単にフォントを差し替えるだけです
    }
}

impl ConsoleDriver for TextConsole {
    /// 画面を描画
    fn flush(&mut self, buffer: &TerminalBuffer) {
        // 背景色（デフォルト）でクリアしたいが、TerminalBufferはセルごとに背景色を持つ
        // ここでは一旦黒でクリアしてから描画する
        unsafe {
            (*self.fb).clear(Color::BLACK);
        }

        let rows = buffer.rows();
        let cols = buffer.cols();

        for row in 0..rows {
            for col in 0..cols {
                if let Some(cell) = buffer.get_cell(col, row) {
                    if cell.ch == ' ' && cell.attr.bg_color == crate::console::AnsiColor::Black {
                        continue;
                    }

                    let x = (col as u32 * self.font.width()) as i32;
                    let y = (row as u32 * self.font.height()) as i32;
                    
                    let (fg_ansi, bg_ansi) = cell.attr.effective_colors();
                    
                    let fc = fg_ansi.to_rgb();
                    let fg = Color { red: (fc >> 16) as u8, green: (fc >> 8) as u8, blue: fc as u8, alpha: 0xFF };
                    
                    let bc = bg_ansi.to_rgb();
                    let bg = Color { red: (bc >> 16) as u8, green: (bc >> 8) as u8, blue: bc as u8, alpha: 0xFF };

                    unsafe {
                        // 背景色描画が必要（フォント描画はグリフのみの場合があるため）
                         // Font::draw_char の仕様に合わせた呼び出し
                         self.font.draw_char(&mut *self.fb, x, y, cell.ch, fg, Some(bg));
                    }
                }
            }
        }
        
        // Draw cursor
        let (cx, cy) = buffer.cursor();
        let cx_px = (cx as u32 * self.font.width()) as i32;
        let cy_px = (cy as u32 * self.font.height()) as i32;
        
        // Simple block cursor (inverse colors)
        // Since we can't read back easily, just draw a block or underscore
        unsafe {
             // Draw a simple underline cursor
             let h = self.font.height();
             let w = self.font.width();
             // Draw a white rect at bottom of cell
             (*self.fb).fill_rect(super::Rect::new(cx_px, (cy_px + h as i32 - 2).max(0), w as u32, 2), Color::WHITE);
        }
    }
}


