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
    /// 前回のバッファ状態（差分描画用）
    prev_buffer: Vec<crate::console::CharCell>,
    /// 前回のカーソル位置
    prev_cursor: Option<(usize, usize)>,
}

unsafe impl Send for TextConsole {}
unsafe impl Sync for TextConsole {}

impl TextConsole {
    /// 新しいコンソールを作成
    ///
    /// # Returns
    /// (TextConsole, cols, rows) - コンソールと計算された桁数・行数
    pub fn new(fb: &mut Framebuffer) -> (Self, usize, usize) {
        // デフォルトフォント: 8x16
        let font = Box::new(BitmapFont::default_8x16());
        let cols = fb.width() / font.width();
        let rows = fb.height() / font.height();
        
        let screen_size = (cols * rows) as usize;

        (
            Self {
                fb,
                font,
                prev_buffer: vec![crate::console::CharCell::default(); screen_size],
                prev_cursor: None,
            },
            cols as usize,
            rows as usize,
        )
    }

    /// フォントを変更
    pub fn set_font(&mut self, font: Box<dyn Font + Send + Sync>) {
        self.font = font;
        // フォント変更時は画面全体を再描画するため、キャッシュをクリア（リサイズはConsoleManagerが担当）
        // ここでは前回バッファをクリアして不整合を防ぐ
        self.prev_buffer.clear(); 
        unsafe { (*self.fb).clear(Color::BLACK); }
    }
}

impl ConsoleDriver for TextConsole {
    /// 画面を描画 (差分更新による最適化)
    fn flush(&mut self, buffer: &TerminalBuffer) {
        let rows = buffer.rows();
        let cols = buffer.cols();
        let total_cells = rows * cols;

        // 解像度変更や初期化直後の整合性チェック
        if self.prev_buffer.len() != total_cells {
            self.prev_buffer = vec![crate::console::CharCell::default(); total_cells];
            self.prev_cursor = None;
            unsafe { (*self.fb).clear(Color::BLACK); }
        }

        let (cx, cy) = buffer.cursor();
        let cursor_pos = (cx, cy);

        // カーソル移動前の位置にある文字を強制再描画（カーソルの消去）
        let mut force_redraw_idx = None;
        if let Some(old_pos) = self.prev_cursor {
            if old_pos != cursor_pos {
                // 古いカーソル位置は必ず再描画して、アンダースコア等を消す必要がある
                if old_pos.0 < cols && old_pos.1 < rows {
                    force_redraw_idx = Some(old_pos.1 * cols + old_pos.0);
                }
            }
        }

        // スクロール検出 (1行分のシフト)
        // 現在のバッファの[0..last_row]が、直前バッファの[1..last]と一致するか確認
        let scroll_count = cols; // 1行
        let len_to_check = total_cells.saturating_sub(scroll_count);
        
        if len_to_check > 0 && self.prev_buffer.len() == total_cells {
            let prev_slice = &self.prev_buffer[scroll_count..total_cells];
            let curr_slice = &buffer.chars()[0..len_to_check];
            
            if prev_slice == curr_slice {
                // スクロール検出！ハードウェアアクセラレーションを使用
                let font_h = self.font.height() as i32;
                let fb_width = (cols as u32 * self.font.width()) as i32;
                let fb_height = (rows as u32 * self.font.height()) as i32;
                
                // 1行分コピー (下から上へ)
                let src_rect = super::Rect::new(0, font_h, fb_width as u32, (fb_height - font_h) as u32);
                unsafe {
                    (*self.fb).copy_rect(src_rect, 0, 0);
                }

                // シャドウバッファもシフトして状態を同期
                self.prev_buffer.copy_within(scroll_count..total_cells, 0);
                
                // 最終行の無効化（前回バッファの末尾をダミーデータで埋めて再描画を強制）
                // ただし、もし新しいバッファの末尾が偶然古いゴミと同じなら描画されないリスクがある。
                // 念のため末尾領域は確実に不一致になるような値を書き込むか、
                // あるいは単にcopy_withinした時点で末尾は「複製されたデータ」が入っている。
                // 新しいデータとは違うはずなので通常は問題ない。
            }
        }

        for row in 0..rows {
            for col in 0..cols {
                let idx = row * cols + col;
                
                if let Some(cell) = buffer.get_display_cell(col, row) {
                    let is_force_redraw = force_redraw_idx == Some(idx);
                    // 変更がある場合、または強制再描画の場合のみ描画
                    if is_force_redraw || self.prev_buffer[idx] != cell {
                        let x = (col as u32 * self.font.width()) as i32;
                        let y = (row as u32 * self.font.height()) as i32;
                        
                        let (fg_ansi, bg_ansi) = cell.attr.effective_colors();
                        
                        let fc = fg_ansi.to_rgb();
                        let fg = Color { red: (fc >> 16) as u8, green: (fc >> 8) as u8, blue: fc as u8, alpha: 0xFF };
                        
                        let bc = bg_ansi.to_rgb();
                        let bg = Color { red: (bc >> 16) as u8, green: (bc >> 8) as u8, blue: bc as u8, alpha: 0xFF };

                        unsafe {
                            // 背景色描画が必要（フォント描画はグリフのみの場合があるため）
                             self.font.draw_char(&mut *self.fb, x, y, cell.ch, fg, Some(bg));
                        }
                        
                        // キャッシュを更新
                        self.prev_buffer[idx] = *cell;
                    }
                }
            }
        }
        
        // 新しいカーソルを描画
        self.prev_cursor = Some(cursor_pos);
        
        let cx_px = (cx as u32 * self.font.width()) as i32;
        let cy_px = (cy as u32 * self.font.height()) as i32;
        
        unsafe {
             let h = self.font.height();
             let w = self.font.width();
             // カーソルを描画（文字の下に線）
             (*self.fb).fill_rect(super::Rect::new(cx_px, (cy_px + h as i32 - 2).max(0), w as u32, 2), Color::WHITE);
        }
    }
}


