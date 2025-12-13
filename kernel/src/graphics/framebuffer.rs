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

use super::font::BitmapFont;
use super::{Color, FramebufferInfo, PixelFormat, Point, Rect};

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

    /// ダブルバッファリングを外部バッファで有効化（デッドロック回避用）
    pub fn enable_double_buffering_from_vec(&mut self, buffer: Vec<u8>) {
        if buffer.len() == self.info.size() {
            self.back_buffer = Some(buffer);
        } else {
            // サイズ不一致だけどパニックさせるとまたロックの問題が出るかも？
            // ログ出さずにリターンするか、あるいはパニック（ロック保持中なのでパニックハンドラがデッドロックするリスクあり）
            // ここはリターンしてエラー状態にするのが安全
        }
    }

    /// ダブルバッファリングが有効かどうかを取得
    pub fn is_double_buffered(&self) -> bool {
        self.back_buffer.is_some()
    }

    /// バックバッファをフロントにコピー（全画面）
    pub fn swap_buffers(&mut self) {
        if let Some(ref back) = self.back_buffer {
            unsafe {
                ptr::copy_nonoverlapping(back.as_ptr(), self.buffer, self.info.size());
            }
        }
    }

    /// 指定領域のみバックバッファからVRAMへコピー（部分Blit）
    /// 全画面コピーより効率的
    /// 注: "Swap"ではなく"Blit"（一方向コピー）
    pub fn blit_rect(&mut self, rect: Rect) {
        if let Some(ref back) = self.back_buffer {
            let stride = self.info.stride as usize;
            let bytes_per_pixel = (self.info.bpp / 8) as usize;

            // 境界チェック
            let x = (rect.x.max(0) as u32).min(self.info.width) as usize;
            let y = (rect.y.max(0) as u32).min(self.info.height) as usize;
            let w = (rect.width as usize).min(self.info.width as usize - x);
            let h = (rect.height as usize).min(self.info.height as usize - y);

            if w == 0 || h == 0 {
                return;
            }

            let row_bytes = w * bytes_per_pixel;

            unsafe {
                for row in 0..h {
                    let offset = (y + row) * stride + x * bytes_per_pixel;
                    ptr::copy_nonoverlapping(
                        back.as_ptr().add(offset),
                        self.buffer.add(offset),
                        row_bytes,
                    );
                }
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

    /// 現在のクリップ領域を取得
    pub fn clip_rect(&self) -> Rect {
        self.clip
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
                let pixel_addr = buffer.add(offset) as usize;
                crate::io::mmio::mmio_write_u32(pixel_addr, color.to_u32());
            },
            PixelFormat::Bgr888 | PixelFormat::Rgb888 => unsafe {
                crate::io::mmio::volatile_write::<u8>(buffer.add(offset) as usize, color.blue);
                crate::io::mmio::volatile_write::<u8>(buffer.add(offset + 1) as usize, color.green);
                crate::io::mmio::volatile_write::<u8>(buffer.add(offset + 2) as usize, color.red);
            },
            PixelFormat::Rgb565 => unsafe {
                let r = (color.red as u16 >> 3) & 0x1F;
                let g = (color.green as u16 >> 2) & 0x3F;
                let b = (color.blue as u16 >> 3) & 0x1F;
                let pixel = (r << 11) | (g << 5) | b;
                let ptr_addr = buffer.add(offset) as usize;
                crate::io::mmio::mmio_write_u16(ptr_addr, pixel);
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
                let pixel = crate::io::mmio::mmio_read_u32(self.buffer.add(offset) as usize);
                Color::from_u32(pixel)
            },
            PixelFormat::Bgr888 | PixelFormat::Rgb888 => unsafe {
                let b = crate::io::mmio::volatile_read::<u8>(self.buffer.add(offset) as usize);
                let g = crate::io::mmio::volatile_read::<u8>(self.buffer.add(offset + 1) as usize);
                let r = crate::io::mmio::volatile_read::<u8>(self.buffer.add(offset + 2) as usize);
                Color::new(r, g, b)
            },
            PixelFormat::Rgb565 => unsafe {
                let pixel = crate::io::mmio::mmio_read_u16(self.buffer.add(offset) as usize);
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
                        let pixel_addr = buffer.add(offset) as usize;
                        crate::io::mmio::mmio_write_u32(pixel_addr, color.to_u32());
                    },
                    PixelFormat::Bgr888 | PixelFormat::Rgb888 => unsafe {
                        crate::io::mmio::volatile_write::<u8>(
                            buffer.add(offset) as usize,
                            color.blue,
                        );
                        crate::io::mmio::volatile_write::<u8>(
                            buffer.add(offset + 1) as usize,
                            color.green,
                        );
                        crate::io::mmio::volatile_write::<u8>(
                            buffer.add(offset + 2) as usize,
                            color.red,
                        );
                    },
                    PixelFormat::Rgb565 => unsafe {
                        let r = (color.red as u16 >> 3) & 0x1F;
                        let g = (color.green as u16 >> 2) & 0x3F;
                        let b = (color.blue as u16 >> 3) & 0x1F;
                        let pixel = (r << 11) | (g << 5) | b;
                        let ptr_addr = buffer.add(offset) as usize;
                        crate::io::mmio::mmio_write_u16(ptr_addr, pixel);
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

    /// 矩形領域をコピー（スクロール等に使用）
    pub fn copy_rect(&mut self, src: Rect, dst_x: i32, dst_y: i32) {
        // クリップ処理
        let mut s = src;
        // srcのクリップ
        s.x = s.x.max(self.clip.x);
        s.y = s.y.max(self.clip.y);
        let s_right = s.right().min(self.clip.right());
        let s_bottom = s.bottom().min(self.clip.bottom());
        s.width = (s_right - s.x).max(0) as u32;
        s.height = (s_bottom - s.y).max(0) as u32;

        // dstのクリップ（srcと連動）
        let mut d_x = dst_x + (s.x - src.x);
        let mut d_y = dst_y + (s.y - src.y);

        // dstが画面外にはみ出す場合の調整
        let clip_left = self.clip.x;
        let clip_top = self.clip.y;
        let clip_right = self.clip.right();
        let clip_bottom = self.clip.bottom();

        if d_x < clip_left {
            let diff = clip_left - d_x;
            s.x += diff;
            s.width = s.width.saturating_sub(diff as u32);
            d_x = clip_left;
        }
        if d_y < clip_top {
            let diff = clip_top - d_y;
            s.y += diff;
            s.height = s.height.saturating_sub(diff as u32);
            d_y = clip_top;
        }

        // 右/下のはみ出し
        let d_right = d_x + s.width as i32;
        if d_right > clip_right {
            let diff = d_right - clip_right;
            s.width = s.width.saturating_sub(diff as u32);
        }
        let d_bottom = d_y + s.height as i32;
        if d_bottom > clip_bottom {
            let diff = d_bottom - clip_bottom;
            s.height = s.height.saturating_sub(diff as u32);
        }

        if s.width == 0 || s.height == 0 {
            return;
        }

        let buffer = self.draw_buffer();
        let stride = self.info.stride as usize;
        let bpp = self.info.format.bytes_per_pixel();
        let copy_bytes = s.width as usize * bpp;

        unsafe {
            if d_y > s.y {
                // 下方向へのコピー（後ろから）
                for i in (0..s.height).rev() {
                    let src_row_y = s.y + i as i32;
                    let dst_row_y = d_y + i as i32;

                    let src_offset = (src_row_y as usize * stride) + (s.x as usize * bpp);
                    let dst_offset = (dst_row_y as usize * stride) + (d_x as usize * bpp);

                    ptr::copy(buffer.add(src_offset), buffer.add(dst_offset), copy_bytes);
                }
            } else {
                // 上方向へのコピー（前から）
                for i in 0..s.height {
                    let src_row_y = s.y + i as i32;
                    let dst_row_y = d_y + i as i32;

                    let src_offset = (src_row_y as usize * stride) + (s.x as usize * bpp);
                    let dst_offset = (dst_row_y as usize * stride) + (d_x as usize * bpp);

                    ptr::copy(buffer.add(src_offset), buffer.add(dst_offset), copy_bytes);
                }
            }
        }
    }

    /// 塗りつぶし矩形を描画（高速化版）
    pub fn fill_rect(&mut self, rect: Rect, color: Color) {
        // クリップ処理
        let mut r = rect;
        r.x = r.x.max(self.clip.x);
        r.y = r.y.max(self.clip.y);
        let right = r.right().min(self.clip.right());
        let bottom = r.bottom().min(self.clip.bottom());
        r.width = (right - r.x).max(0) as u32;
        r.height = (bottom - r.y).max(0) as u32;

        if r.width == 0 || r.height == 0 {
            return;
        }

        let buffer = self.draw_buffer();
        let bytes_per_pixel = self.info.format.bytes_per_pixel();
        let stride = self.info.stride;

        match self.info.format {
            PixelFormat::Bgra8888 | PixelFormat::Rgba8888 => unsafe {
                let color_u32 = color.to_u32();
                for y in r.y..r.bottom() {
                    let offset = (y as usize * stride as usize) + (r.x as usize * 4);
                    let row_ptr = buffer.add(offset) as *mut u32;
                    let row_slice = core::slice::from_raw_parts_mut(row_ptr, r.width as usize);
                    row_slice.fill(color_u32);
                }
            },
            _ => {
                // その他のフォーマットはピクセルごとに描画 (簡易実装)
                for y in r.y..r.bottom() {
                    for x in r.x..r.right() {
                        self.set_pixel(x, y, color);
                    }
                }
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

    /// 画像を描画
    pub fn draw_image(&mut self, image: &super::image::Image, x: i32, y: i32) {
        for py in 0..image.height() as i32 {
            for px in 0..image.width() as i32 {
                let color = image.get_pixel(px as u32, py as u32);
                if color.alpha > 0 {
                    self.set_pixel(x + px, y + py, color);
                }
            }
        }
    }
}
