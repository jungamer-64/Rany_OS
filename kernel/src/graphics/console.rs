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

use super::framebuffer::Framebuffer;
use super::{BitmapFont, Color, Font};
// ============================================================================
// Text Console
// ============================================================================

/// テキストコンソール
pub struct TextConsole {
    /// フレームバッファへの参照
    fb: *mut Framebuffer,
    /// フォント (dynamic dispatch for polyglot support)
    font: Box<dyn Font + Send + Sync>,
    /// 仮想コンソールバックエンド
    vc: crate::console::VirtualConsole,
}

unsafe impl Send for TextConsole {}
unsafe impl Sync for TextConsole {}

impl TextConsole {
    /// 新しいコンソールを作成
    pub fn new(fb: &mut Framebuffer) -> Self {
        let font = Box::new(BitmapFont::default_8x16());
        let cols = fb.width() / font.width();
        let rows = fb.height() / font.height();

        let vc = crate::console::VirtualConsole::new(0, cols as usize, rows as usize);

        Self {
            fb,
            font,
            vc,
        }
    }

    /// フォントを変更
    pub fn set_font(&mut self, font: Box<dyn Font + Send + Sync>) {
        self.font = font;
        // Recalculate dimensions
        unsafe {
            let fb = &*self.fb;
            let cols = fb.width() / self.font.width();
            let rows = fb.height() / self.font.height();
            // Re-initialize VC with new dimensions
            // Note: This clears the buffer, which is consistent with previous behavior
            self.vc = crate::console::VirtualConsole::new(0, cols as usize, rows as usize);
        }
        self.clear();
    }

    /// 画面をクリア
    pub fn clear(&mut self) {
        self.vc.write("\x1b[2J\x1b[1;1H"); // Clear screen and home cursor
        self.redraw();
    }

    /// 色を設定
    /// 注意: 完全なRGBカラーはサポートされていません。最も近いANSIカラーにマッピングするか、
    /// デフォルトの白/黒などの主要色のみがサポートされます。
    pub fn set_colors(&mut self, fg: Color, bg: Color) {
        // Simple mapping for common colors
        let fg_code = self.color_to_ansi_code(fg, true);
        let bg_code = self.color_to_ansi_code(bg, false);
        
        // Construct ANSI sequence
        use alloc::format;
        let seq = format!("\x1b[{};{}m", fg_code, bg_code);
        self.vc.write(&seq);
    }
    
    fn color_to_ansi_code(&self, color: Color, is_fg: bool) -> u8 {
        let base = if is_fg { 30 } else { 40 };
        // Very basic mapping
        match (color.r, color.g, color.b) {
            (0, 0, 0) => base + 0, // Black
            (255, 0, 0) | (170, 0, 0) => base + 1, // Red
            (0, 255, 0) | (0, 170, 0) => base + 2, // Green
            (255, 255, 0) | (170, 170, 0) => base + 3, // Yellow
            (0, 0, 255) | (0, 0, 170) => base + 4, // Blue
            (255, 0, 255) | (170, 0, 170) => base + 5, // Magenta
            (0, 255, 255) | (0, 170, 170) => base + 6, // Cyan
            (255, 255, 255) | (170, 170, 170) => base + 7, // White
            _ => base + 7, // Default to White
        }
    }

    /// 文字を出力
    pub fn put_char(&mut self, c: char) {
        let mut buf = [0u8; 4];
        self.vc.write(c.encode_utf8(&mut buf));
        self.redraw();
    }

    /// 画面全体を再描画
    /// 非効率ですが、確実な表示を保証します。
    fn redraw(&mut self) {
        // 背景色（デフォルト）でクリアしたいが、TerminalBufferはセルごとに背景色を持つ
        // ここでは一旦黒でクリアしてから描画する
        unsafe {
            (*self.fb).clear(Color::BLACK);
        }

        let buffer = self.vc.buffer();
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
                    let fg = Color { r: (fc >> 16) as u8, g: (fc >> 8) as u8, b: fc as u8 };
                    
                    let bc = bg_ansi.to_rgb();
                    let bg = Color { r: (bc >> 16) as u8, g: (bc >> 8) as u8, b: bc as u8 };

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
             (*self.fb).fill_rect(cx_px, cy_px + h as i32 - 2, w, 2, Color::WHITE);
        }
    }

    /// 文字列を出力
    pub fn write_str(&mut self, s: &str) {
        self.vc.write(s);
        self.redraw();
    }

    /// カーソル位置設定（ANSIを使用）
    pub fn set_cursor(&mut self, col: u32, row: u32) {
        use alloc::format;
        // ANSI: CUP - Cursor Position: ESC [ line ; column H
        // 1-based index
        let seq = format!("\x1b[{};{}H", row + 1, col + 1);
        self.vc.write(&seq);
        self.redraw();
    }

    /// カーソル位置を取得
    pub fn cursor(&self) -> (u32, u32) {
        let (x, y) = self.vc.buffer().cursor();
        (x as u32, y as u32)
    }
}

impl core::fmt::Write for TextConsole {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        TextConsole::write_str(self, s);
        Ok(())
    }
}

