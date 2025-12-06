// ============================================================================
// src/graphics/framebuffer.rs - Framebuffer Implementation
// ============================================================================
//!
//! フレームバッファ描画実装
//!
//! ピクセル描画、図形描画、テキスト描画などのフレームバッファ操作

#![allow(dead_code)]

use alloc::vec;
use alloc::vec::Vec;
use core::ptr;

use super::types::{Color, FramebufferInfo, PixelFormat, Point, Rect};
use super::font::BitmapFont;

// ============================================================================
// Framebuffer
// ============================================================================

/// フレームバッファ
pub struct Framebuffer {
    /// フレームバッファ情報
    info: FramebufferInfo,
    /// フレームバッファへのポインタ
    buffer: *mut u8,
    /// バックバッファ（ダブルバッファリング用）
    back_buffer: Option<Vec<u8>>,
    /// クリップ領域
    clip: Rect,
}

unsafe impl Send for Framebuffer {}
unsafe impl Sync for Framebuffer {}

impl Framebuffer {
    /// 新しいフレームバッファを作成
    pub unsafe fn new(info: FramebufferInfo) -> Self {
        let clip = Rect::new(0, 0, info.width, info.height);
        Self {
            buffer: info.address as *mut u8,
            info,
            back_buffer: None,
            clip,
        }
    }

    /// ダブルバッファリングを有効化
    pub fn enable_double_buffering(&mut self) {
        let size = self.info.size();
        self.back_buffer = Some(vec![0u8; size]);
    }

    /// ダブルバッファリングが有効かどうかを取得
    pub fn is_double_buffered(&self) -> bool {
        self.back_buffer.is_some()
    }

    /// バックバッファをフロントにコピー
    pub fn swap_buffers(&mut self) {
        if let Some(ref back) = self.back_buffer {
            unsafe {
                ptr::copy_nonoverlapping(back.as_ptr(), self.buffer, self.info.size());
            }
        }
    }

    /// 描画先バッファを取得
    fn draw_buffer(&mut self) -> *mut u8 {
        if let Some(ref mut back) = self.back_buffer {
            back.as_mut_ptr()
        } else {
            self.buffer
        }
    }

    /// フレームバッファ情報を取得
    pub fn info(&self) -> &FramebufferInfo {
        &self.info
    }

    /// 幅を取得
    pub fn width(&self) -> u32 {
        self.info.width
    }

    /// 高さを取得
    pub fn height(&self) -> u32 {
        self.info.height
    }

    /// クリップ領域を設定
    pub fn set_clip(&mut self, rect: Rect) {
        self.clip = rect;
    }

    /// クリップ領域をリセット
    pub fn reset_clip(&mut self) {
        self.clip = Rect::new(0, 0, self.info.width, self.info.height);
    }

    /// ピクセルをセット
    pub fn set_pixel(&mut self, x: i32, y: i32, color: Color) {
        if x < 0 || y < 0 {
            return;
        }
        let x = x as u32;
        let y = y as u32;

        if x >= self.info.width || y >= self.info.height {
            return;
        }

        if !self.clip.contains(Point::new(x as i32, y as i32)) {
            return;
        }

        let offset =
            (y * self.info.stride) as usize + (x as usize * self.info.format.bytes_per_pixel());

        let buffer = self.draw_buffer();

        match self.info.format {
            PixelFormat::Bgra8888 | PixelFormat::Rgba8888 => unsafe {
                let pixel = buffer.add(offset) as *mut u32;
                ptr::write_volatile(pixel, color.to_u32());
            },
            PixelFormat::Bgr888 | PixelFormat::Rgb888 => unsafe {
                ptr::write_volatile(buffer.add(offset), color.blue);
                ptr::write_volatile(buffer.add(offset + 1), color.green);
                ptr::write_volatile(buffer.add(offset + 2), color.red);
            },
            PixelFormat::Rgb565 => unsafe {
                let r = (color.red as u16 >> 3) & 0x1F;
                let g = (color.green as u16 >> 2) & 0x3F;
                let b = (color.blue as u16 >> 3) & 0x1F;
                let pixel = (r << 11) | (g << 5) | b;
                let ptr = buffer.add(offset) as *mut u16;
                ptr::write_volatile(ptr, pixel);
            },
        }
    }

    /// ピクセルを取得
    pub fn get_pixel(&self, x: u32, y: u32) -> Color {
        if x >= self.info.width || y >= self.info.height {
            return Color::BLACK;
        }

        let offset =
            (y * self.info.stride) as usize + (x as usize * self.info.format.bytes_per_pixel());

        match self.info.format {
            PixelFormat::Bgra8888 | PixelFormat::Rgba8888 => unsafe {
                let pixel = *(self.buffer.add(offset) as *const u32);
                Color::from_u32(pixel)
            },
            PixelFormat::Bgr888 | PixelFormat::Rgb888 => unsafe {
                let b = *self.buffer.add(offset);
                let g = *self.buffer.add(offset + 1);
                let r = *self.buffer.add(offset + 2);
                Color::new(r, g, b)
            },
            PixelFormat::Rgb565 => unsafe {
                let pixel = *(self.buffer.add(offset) as *const u16);
                let r = ((pixel >> 11) & 0x1F) as u8 * 8;
                let g = ((pixel >> 5) & 0x3F) as u8 * 4;
                let b = (pixel & 0x1F) as u8 * 8;
                Color::new(r, g, b)
            },
        }
    }

    /// 画面をクリア
    pub fn clear(&mut self, color: Color) {
        let buffer = self.draw_buffer();
        let bytes_per_pixel = self.info.format.bytes_per_pixel();

        for y in 0..self.info.height {
            for x in 0..self.info.width {
                let offset = (y * self.info.stride) as usize + x as usize * bytes_per_pixel;

                match self.info.format {
                    PixelFormat::Bgra8888 | PixelFormat::Rgba8888 => unsafe {
                        let pixel = buffer.add(offset) as *mut u32;
                        ptr::write_volatile(pixel, color.to_u32());
                    },
                    PixelFormat::Bgr888 | PixelFormat::Rgb888 => unsafe {
                        ptr::write_volatile(buffer.add(offset), color.blue);
                        ptr::write_volatile(buffer.add(offset + 1), color.green);
                        ptr::write_volatile(buffer.add(offset + 2), color.red);
                    },
                    PixelFormat::Rgb565 => unsafe {
                        let r = (color.red as u16 >> 3) & 0x1F;
                        let g = (color.green as u16 >> 2) & 0x3F;
                        let b = (color.blue as u16 >> 3) & 0x1F;
                        let pixel = (r << 11) | (g << 5) | b;
                        let ptr = buffer.add(offset) as *mut u16;
                        ptr::write_volatile(ptr, pixel);
                    },
                }
            }
        }
    }

    /// 水平線を描画
    pub fn draw_hline(&mut self, x1: i32, x2: i32, y: i32, color: Color) {
        let start = x1.min(x2);
        let end = x1.max(x2);

        for x in start..=end {
            self.set_pixel(x, y, color);
        }
    }

    /// 垂直線を描画
    pub fn draw_vline(&mut self, x: i32, y1: i32, y2: i32, color: Color) {
        let start = y1.min(y2);
        let end = y1.max(y2);

        for y in start..=end {
            self.set_pixel(x, y, color);
        }
    }

    /// 線を描画（Bresenhamアルゴリズム）
    pub fn draw_line(&mut self, x1: i32, y1: i32, x2: i32, y2: i32, color: Color) {
        let dx = (x2 - x1).abs();
        let dy = -(y2 - y1).abs();
        let sx = if x1 < x2 { 1 } else { -1 };
        let sy = if y1 < y2 { 1 } else { -1 };
        let mut err = dx + dy;

        let mut x = x1;
        let mut y = y1;

        loop {
            self.set_pixel(x, y, color);

            if x == x2 && y == y2 {
                break;
            }

            let e2 = 2 * err;

            if e2 >= dy {
                if x == x2 {
                    break;
                }
                err += dy;
                x += sx;
            }

            if e2 <= dx {
                if y == y2 {
                    break;
                }
                err += dx;
                y += sy;
            }
        }
    }

    /// 矩形を描画（枠のみ）
    pub fn draw_rect(&mut self, rect: Rect, color: Color) {
        self.draw_hline(rect.x, rect.right() - 1, rect.y, color);
        self.draw_hline(rect.x, rect.right() - 1, rect.bottom() - 1, color);
        self.draw_vline(rect.x, rect.y, rect.bottom() - 1, color);
        self.draw_vline(rect.right() - 1, rect.y, rect.bottom() - 1, color);
    }

    /// 塗りつぶし矩形を描画
    pub fn fill_rect(&mut self, rect: Rect, color: Color) {
        for y in rect.y..rect.bottom() {
            for x in rect.x..rect.right() {
                self.set_pixel(x, y, color);
            }
        }
    }

    /// 円を描画（Midpointアルゴリズム）
    pub fn draw_circle(&mut self, cx: i32, cy: i32, radius: i32, color: Color) {
        let mut x = radius;
        let mut y = 0;
        let mut err = 0;

        while x >= y {
            self.set_pixel(cx + x, cy + y, color);
            self.set_pixel(cx + y, cy + x, color);
            self.set_pixel(cx - y, cy + x, color);
            self.set_pixel(cx - x, cy + y, color);
            self.set_pixel(cx - x, cy - y, color);
            self.set_pixel(cx - y, cy - x, color);
            self.set_pixel(cx + y, cy - x, color);
            self.set_pixel(cx + x, cy - y, color);

            y += 1;
            if err <= 0 {
                err += 2 * y + 1;
            }
            if err > 0 {
                x -= 1;
                err -= 2 * x + 1;
            }
        }
    }

    /// 塗りつぶし円を描画
    pub fn fill_circle(&mut self, cx: i32, cy: i32, radius: i32, color: Color) {
        let mut x = radius;
        let mut y = 0;
        let mut err = 0;

        while x >= y {
            self.draw_hline(cx - x, cx + x, cy + y, color);
            self.draw_hline(cx - y, cx + y, cy + x, color);
            self.draw_hline(cx - x, cx + x, cy - y, color);
            self.draw_hline(cx - y, cx + y, cy - x, color);

            y += 1;
            if err <= 0 {
                err += 2 * y + 1;
            }
            if err > 0 {
                x -= 1;
                err -= 2 * x + 1;
            }
        }
    }

    /// テキストを描画（組み込み8x16フォントを使用）
    /// 
    /// # Arguments
    /// * `x` - 開始X座標
    /// * `y` - 開始Y座標
    /// * `text` - 描画するテキスト
    /// * `color` - 文字色
    /// * `bg_color` - 背景色
    pub fn draw_text(&mut self, x: i32, y: i32, text: &str, color: Color, bg_color: Color) {
        let font = BitmapFont::default_8x16();
        let mut cx = x;

        for c in text.chars() {
            if c == '\n' {
                continue;
            }

            // 文字を描画
            let c_index = c as usize;
            if c_index < 128 {
                let glyph_start = c_index * font.height() as usize;
                
                for row in 0..font.height() {
                    let glyph_row = glyph_start + row as usize;
                    if glyph_row < font.data_len() {
                        let byte = font.get_data(glyph_row);
                        for col in 0..font.width() {
                            let pixel_on = (byte >> (7 - col)) & 1 != 0;
                            let px = cx + col as i32;
                            let py = y + row as i32;
                            
                            if pixel_on {
                                self.set_pixel(px, py, color);
                            } else {
                                self.set_pixel(px, py, bg_color);
                            }
                        }
                    }
                }
            }
            
            cx += font.width() as i32;
        }
    }
}
