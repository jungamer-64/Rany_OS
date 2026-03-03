// ============================================================================
// kernel/src/graphics/framebuffer/text.rs
// ============================================================================
//! Text and glyph rendering methods for `Framebuffer`.
//!
//! This module contains bitmap font rendering, glyph drawing, and related
//! clipping/run helpers extracted from the main framebuffer implementation.

use super::*;
use hal::mmio;
use core::ptr;

impl Framebuffer {
    /// Check if a rectangle is fully contained in the clip rectangle.
    #[inline]
    fn clip_contains_rect(&self, x: i32, y: i32, w: i32, h: i32) -> bool {
        x >= self.clip.x && (x + w) <= self.clip.right() && y >= self.clip.y && (y + h) <= self.clip.bottom()
    }

    /// Check if a Y coordinate is within the clip vertical range.
    #[inline]
    fn clip_y_visible(&self, y: i32) -> bool {
        y >= self.clip.y && y < self.clip.bottom()
    }

    /// Find a run of ON bits in `byte` starting from `col`, bounded by `max_bits`.
    /// Returns `(run_start, run_len, new_col)`.
    #[inline]
    fn next_on_run(byte: u8, mut col: usize, max_bits: usize) -> (usize, usize, usize) {
        // Skip OFF pixels
        while col < max_bits {
            if (byte >> (7 - col)) & 1 != 0 {
                break;
            }
            col += 1;
        }
        let run_start = col;
        // Count ON pixels
        while col < max_bits {
            if (byte >> (7 - col)) & 1 == 0 {
                break;
            }
            col += 1;
        }
        (run_start, col - run_start, col)
    }

    /// Find a run of ON bits with extra width bound: `(byte_idx * 8 + col) < width`.
    #[inline]
    fn next_on_run_bounded(byte: u8, mut col: usize, byte_idx: usize, width: usize) -> (usize, usize, usize) {
        while col < 8 && (byte_idx * 8 + col) < width {
            if (byte >> (7 - col)) & 1 != 0 {
                break;
            }
            col += 1;
        }
        let run_start = col;
        while col < 8 && (byte_idx * 8 + col) < width {
            if (byte >> (7 - col)) & 1 == 0 {
                break;
            }
            col += 1;
        }
        (run_start, col - run_start, col)
    }

    /// Write a clipped run of foreground pixels at 24bpp using `write_bgr_run`.
    fn write_clipped_bgr_run(
        &mut self,
        dst_x: i32,
        run_len: usize,
        dst_y: i32,
        stride: usize,
        color: Color,
    ) {
        let dst_start_x = dst_x.max(self.clip.x);
        let dst_end_x = (dst_x + run_len as i32 - 1).min(self.clip.right() - 1);
        if dst_end_x >= dst_start_x {
            let clipped_len = (dst_end_x - dst_start_x + 1) as usize;
            let start_offset = (dst_y as usize * stride) + (dst_start_x as usize * 3);
            self.write_bgr_run(start_offset, clipped_len, color);
        }
    }

    /// Write a clipped run of foreground pixels at 16bpp (RGB565) using MMIO streaming.
    fn write_clipped_rgb565_run_nofence(
        &mut self,
        dst_x: i32,
        run_len: usize,
        dst_y: i32,
        stride: usize,
        color: Color,
    ) -> bool {
        let dst_start_x = dst_x.max(self.clip.x);
        let dst_end_x = (dst_x + run_len as i32 - 1).min(self.clip.right() - 1);
        if dst_end_x < dst_start_x {
            return false;
        }

        let clipped_len = (dst_end_x - dst_start_x + 1) as usize;
        let start_offset = (dst_y as usize * stride) + (dst_start_x as usize * 2);
        let pixel = Self::color_to_rgb565(color);

        if self.back_buffer.is_some() {
            debug_assert!(false, "16bpp draw called on u32 backbuffer");
            false
        } else {
            let addr = self.buffer as usize + start_offset;
            self.write_u16_run_streaming_nofence(addr, clipped_len, pixel);
            true
        }
    }

    fn write_clipped_rgb565_run(
        &mut self,
        dst_x: i32,
        run_len: usize,
        dst_y: i32,
        stride: usize,
        color: Color,
    ) {
        if self.write_clipped_rgb565_run_nofence(dst_x, run_len, dst_y, stride, color) {
            self.counted_sfence();
        }
    }

    /// Process one byte of glyph data at 24bpp, writing clipped runs.
    fn glyph_byte_runs_24bpp(
        &mut self,
        byte: u8,
        byte_idx: usize,
        width: u32,
        px_start: i32,
        dst_y: i32,
        stride: usize,
        color: Color,
    ) {
        let mut col = 0usize;
        while col < 8 && (byte_idx * 8 + col) < width as usize {
            let (run_start, run_len, new_col) =
                Self::next_on_run_bounded(byte, col, byte_idx, width as usize);
            col = new_col;
            if run_len == 0 {
                continue;
            }
            let dst_x = px_start + run_start as i32;
            self.write_clipped_bgr_run(dst_x, run_len, dst_y, stride, color);
        }
    }

    /// Process one byte of glyph data at 16bpp, writing clipped runs.
    fn glyph_byte_runs_16bpp(
        &mut self,
        byte: u8,
        byte_idx: usize,
        width: u32,
        px_start: i32,
        dst_y: i32,
        stride: usize,
        color: Color,
    ) -> bool {
        let mut wrote_mmio = false;
        let mut col = 0usize;
        while col < 8 && (byte_idx * 8 + col) < width as usize {
            let (run_start, run_len, new_col) =
                Self::next_on_run_bounded(byte, col, byte_idx, width as usize);
            col = new_col;
            if run_len == 0 {
                continue;
            }
            let dst_x = px_start + run_start as i32;
            wrote_mmio |= self.write_clipped_rgb565_run_nofence(dst_x, run_len, dst_y, stride, color);
        }
        wrote_mmio
    }

    /// Flush a horizontal run during Bresenham line drawing.
    fn flush_hrun(
        &mut self,
        run_start: i32,
        run_len: usize,
        run_y: i32,
        sx: i32,
        color: Color,
    ) {
        if run_y < self.clip.y || run_y >= self.clip.bottom() {
            return;
        }
        let (s, e) = if run_len <= 1 {
            (run_start, run_start)
        } else if sx > 0 {
            (run_start, run_start + (run_len as i32 - 1))
        } else {
            (run_start - (run_len as i32 - 1), run_start)
        };
        let s_clamped = s.max(self.clip.x).min(self.clip.right() - 1);
        let e_clamped = e.max(self.clip.x).min(self.clip.right() - 1);
        if s_clamped <= e_clamped {
            self.draw_hline_raw(s_clamped, e_clamped, run_y, color);
        }
    }

    // ─── End shared helpers ────────────────────────────────────────────────

    /// Process a single byte of glyph bitmap data, dispatching by bpp.
    /// Returns `true` if MMIO writes occurred (needs fence).
    #[allow(clippy::too_many_arguments)]
    fn glyph_process_byte(
        &mut self,
        byte: u8,
        byte_idx: usize,
        bpp: usize,
        stride: usize,
        px_start: i32,
        dst_y: i32,
        glyph_x: i32,
        width: u32,
        color: Color,
        has_bg: bool,
        fg_u32: u32,
        bg_u32: u32,
    ) -> bool {
        match bpp {
            4 if has_bg
                && px_start >= self.clip.x
                && (px_start + 8) <= self.clip.right()
                && (px_start + 8) <= (glyph_x + width as i32) =>
            {
                let dst_offset = (dst_y as usize * stride) + (px_start as usize * 4);
                self.write_glyph_row_32bit_nofence(byte, dst_offset, fg_u32, bg_u32)
            }
            3 => {
                self.glyph_byte_runs_24bpp(byte, byte_idx, width, px_start, dst_y, stride, color);
                false
            }
            2 => {
                self.glyph_byte_runs_16bpp(byte, byte_idx, width, px_start, dst_y, stride, color)
            }
            _ => {
                self.glyph_byte_fallback(byte, px_start, dst_y, glyph_x, width, color);
                false
            }
        }
    }

    /// Fallback per-pixel write for a single byte of glyph data.
    fn glyph_byte_fallback(
        &mut self,
        byte: u8,
        px_start: i32,
        dst_y: i32,
        glyph_x: i32,
        width: u32,
        color: Color,
    ) {
        for bit in 0..8 {
            let px = px_start + bit;
            if px < self.clip.x || px >= self.clip.right() || px >= glyph_x + width as i32 {
                continue;
            }
            if (byte >> (7 - bit)) & 1 != 0 {
                self.set_pixel_raw(px, dst_y, color);
            }
        }
    }

    /// Draw a single character using the 32bpp fast path in draw_text.
    /// Returns `true` if MMIO writes occurred.
    fn draw_text_char_32bpp_fast(
        &mut self,
        cx: i32,
        y: i32,
        c: char,
        font: &BitmapFont,
        stride: usize,
        format: PixelFormat,
        color: Color,
        bg_color: Color,
    ) -> bool {
        let char_w = font.width() as i32;
        let char_h = font.height() as i32;
        self.mark_dirty(Rect::new(cx, y, char_w as u32, char_h as u32));

        let fg_u32 = format.encode_u32(color).unwrap_or(color.to_u32());
        let bg_u32 = format.encode_u32(bg_color).unwrap_or(bg_color.to_u32());

        let data = font.glyph(c).unwrap_or(&[0u8; 16]);
        let mut wrote = false;
        for (row, &byte) in data.iter().enumerate() {
            let offset = ((y + row as i32) as usize * stride) + (cx as usize * 4);
            wrote |= self.write_glyph_row_32bit_nofence(byte, offset, fg_u32, bg_u32);
        }
        wrote
    }

    /// Draw a single character using the 16bpp fg+bg single-pass fast path.
    /// Writes all 8 pixels per row using branchless selection — no prefill needed.
    fn draw_text_char_16bpp_fast(
        &mut self,
        cx: i32,
        y: i32,
        c: char,
        font: &BitmapFont,
        stride: usize,
        color: Color,
        bg_color: Color,
    ) -> bool {
        let char_w = font.width() as i32;
        let char_h = font.height() as i32;
        self.mark_dirty(Rect::new(cx, y, char_w as u32, char_h as u32));

        let fg_u16 = Self::color_to_rgb565(color);
        let bg_u16 = Self::color_to_rgb565(bg_color);

        let data = font.glyph(c).unwrap_or(&[0u8; 16]);
        let mut wrote = false;
        for (row, &byte) in data.iter().enumerate() {
            let offset = ((y + row as i32) as usize * stride) + (cx as usize * 2);
            wrote |= self.write_glyph_row_16bit_nofence(byte, offset, fg_u16, bg_u16);
        }
        wrote
    }

    /// Draw a single character using the 24bpp fg+bg single-pass fast path.
    fn draw_text_char_24bpp_fast(
        &mut self,
        cx: i32,
        y: i32,
        c: char,
        font: &BitmapFont,
        stride: usize,
        color: Color,
        bg_color: Color,
    ) -> bool {
        let char_w = font.width() as i32;
        let char_h = font.height() as i32;
        self.mark_dirty(Rect::new(cx, y, char_w as u32, char_h as u32));

        let fg_bytes = self.bgr_color_order(color);
        let bg_bytes = self.bgr_color_order(bg_color);

        let data = font.glyph(c).unwrap_or(&[0u8; 16]);
        let mut wrote = false;
        for (row, &byte) in data.iter().enumerate() {
            let offset = ((y + row as i32) as usize * stride) + (cx as usize * 3);
            wrote |= self.write_glyph_row_24bit_nofence(byte, offset, fg_bytes, bg_bytes);
        }
        wrote
    }

    /// Draw one glyph row (non-32bpp path) with run detection and bpp dispatch.
    fn draw_text_glyph_row(
        &mut self,
        byte: u8,
        font_width: usize,
        cx: i32,
        dst_y: i32,
        stride: usize,
        bpp: usize,
        color: Color,
    ) -> bool {
        let mut need_fence = false;
        let mut col = 0usize;
        while col < font_width {
            let (run_start, run_len, new_col) = Self::next_on_run(byte, col, font_width);
            col = new_col;
            if run_len == 0 {
                continue;
            }
            let dst_x = cx + run_start as i32;
            let dst_run_end_x = dst_x + run_len as i32 - 1;
            if dst_run_end_x < self.clip.x || dst_x >= self.clip.right() {
                continue;
            }
            need_fence |= self.draw_text_write_run(dst_x, dst_run_end_x, dst_y, stride, bpp, color);
        }
        need_fence
    }

    /// Write a single run of ON-pixels for draw_text, dispatching by bpp.
    fn draw_text_write_run(
        &mut self,
        dst_x: i32,
        dst_run_end_x: i32,
        dst_y: i32,
        stride: usize,
        bpp: usize,
        color: Color,
    ) -> bool {
        let clipped_start = dst_x.max(self.clip.x);
        let clipped_end = dst_run_end_x.min(self.clip.right() - 1);
        let clipped_len = (clipped_end - clipped_start + 1) as usize;
        let start_offset = (dst_y as usize * stride) + (clipped_start as usize * bpp);
        match bpp {
            3 => {
                self.write_bgr_run(start_offset, clipped_len, color);
                true
            }
            2 => {
                let pixel = Self::color_to_rgb565(color);

                if self.back_buffer.is_some() {
                    let base = unsafe { self.draw_buffer().add(start_offset) };
                    let pair = (pixel as u32) | ((pixel as u32) << 16);
                    let mut i = 0usize;

                    while i + 1 < clipped_len {
                        unsafe {
                            ptr::write_unaligned(base.add(i * 2) as *mut u32, pair);
                        }
                        i += 2;
                    }

                    if i < clipped_len {
                        unsafe {
                            ptr::write_unaligned(base.add(i * 2) as *mut u16, pixel);
                        }
                    }
                    false
                } else {
                    let addr = self.draw_buffer() as usize + start_offset;
                    self.write_u16_run_streaming_nofence(addr, clipped_len, pixel);
                    true
                }
            }
            _ => {
                for i in 0..clipped_len {
                    self.set_pixel_raw(clipped_start + i as i32, dst_y, color);
                }
                false
            }
        }
    }

    /// Compute stride, format and bpp for text drawing.
    fn draw_text_setup(&self) -> (usize, PixelFormat, usize) {
        let stride = if self.back_buffer.is_some() {
            (self.info.width * 4) as usize
        } else {
            self.info.stride as usize
        };
        let format = if self.back_buffer.is_some() {
            PixelFormat::Bgra8888
        } else {
            self.info.format
        };
        let bpp = format.bytes_per_pixel() as usize;
        (stride, format, bpp)
    }

    /// Draw a single non-32bpp character glyph, returning whether MMIO writes occurred.
    fn draw_text_char_generic(
        &mut self,
        cx: i32,
        y: i32,
        c: char,
        font: &BitmapFont,
        stride: usize,
        bpp: usize,
        color: Color,
    ) -> bool {
        let glyph = match font.glyph(c) {
            Some(g) => g,
            None => return false,
        };
        let mut need_fence = false;
        for (row, &byte) in glyph.iter().enumerate() {
            let dst_y = y + row as i32;
            if !self.clip_y_visible(dst_y) {
                continue;
            }
            need_fence |= self.draw_text_glyph_row(byte, font.width() as usize, cx, dst_y, stride, bpp, color);
        }
        need_fence
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
        let (stride, format, bpp) = self.draw_text_setup();
        
        let char_count = text.chars().filter(|&c| c != '\n').count() as i32;
        let total_w = char_count * font.width() as i32;
        let char_h = font.height() as u32;

        // Determine if we can use single-pass fg+bg rendering (no prefill needed)
        let use_single_pass = (bpp == 4 || bpp == 2 || bpp == 3) && self.back_buffer.is_none();

        // Only pre-fill background for paths that don't do single-pass fg+bg
        if total_w > 0 && !use_single_pass {
            self.fill_rect(Rect::new(x, y, total_w as u32, char_h), bg_color);
        }

        let mut cx = x;
        let mut need_fence = false;
        for c in text.chars() {
            if c == '\n' {
                continue;
            }

            let char_w = font.width() as i32;
            let char_h = font.height() as i32;
            let fully_visible = self.clip_contains_rect(cx, y, char_w, char_h);

            // Single-pass fast paths: write fg+bg together, no prefill needed
            if fully_visible && use_single_pass {
                match bpp {
                    4 => {
                        need_fence |= self.draw_text_char_32bpp_fast(cx, y, c, &font, stride, format, color, bg_color);
                        cx += char_w;
                        continue;
                    }
                    2 => {
                        need_fence |= self.draw_text_char_16bpp_fast(cx, y, c, &font, stride, color, bg_color);
                        cx += char_w;
                        continue;
                    }
                    3 => {
                        need_fence |= self.draw_text_char_24bpp_fast(cx, y, c, &font, stride, color, bg_color);
                        cx += char_w;
                        continue;
                    }
                    _ => {}
                }
            }

            // For 16/24bpp single-pass not fully visible: fill bg for this char, then draw fg only
            if use_single_pass && !fully_visible && (bpp == 2 || bpp == 3) {
                self.fill_rect(Rect::new(cx, y, char_w as u32, char_h as u32), bg_color);
            }

            need_fence |= self.draw_text_char_generic(cx, y, c, &font, stride, bpp, color);
            cx += font.width() as i32;
        }

        if need_fence {
            self.counted_sfence();
        }
    }

    /// Draw a generic bitmap glyph.
    ///
    /// Optimized for 32bpp and 24bpp formats using bulk writes/runs where possible.
    /// `glyph` is expected to be row-major, byte-aligned (stride = (width + 7) / 8).
    pub fn draw_glyph_bitmap(
        &mut self,
        x: i32,
        y: i32,
        glyph: &[u8],
        width: u32,
        height: u32,
        color: Color,
        bg: Option<Color>,
    ) {
        let (stride, bpp) = if self.back_buffer.is_some() {
            ((self.info.width * 4) as usize, 4)
        } else {
            (self.info.stride as usize, self.info.format.bytes_per_pixel())
        };

        // Mark dirty
        self.mark_dirty(Rect::new(x, y, width, height));

        // Fill background if specified
        if let Some(bg_color) = bg {
            self.fill_rect(Rect::new(x, y, width, height), bg_color);
        }

        let bytes_per_row = ((width + 7) / 8) as usize;

        // Pre-encode colors for 32-bit optimization
        let (fg_u32, bg_u32) = self.preencode_glyph_fg_bg(bpp, color, bg);

        let mut mmio_wrote = false;
        for row in 0..height {
            let dst_y = y + row as i32;
            if !self.clip_y_visible(dst_y) {
                continue;
            }

            let row_offset = row as usize * bytes_per_row;
            if row_offset >= glyph.len() {
                break;
            }
            let row_data =
                &glyph[row_offset..core::cmp::min(row_offset + bytes_per_row, glyph.len())];

            for (byte_idx, &byte) in row_data.iter().enumerate() {
                let px_start = x + (byte_idx * 8) as i32;
                mmio_wrote |= self.glyph_process_byte(
                    byte, byte_idx, bpp, stride, px_start, dst_y, x, width, color, bg.is_some(), fg_u32, bg_u32,
                );
            }
        }

        if mmio_wrote {
            mmio::sfence();
        }
    }

    fn preencode_glyph_fg_bg(&self, bpp: usize, color: Color, bg: Option<Color>) -> (u32, u32) {
        if bpp == 4 {
            if self.back_buffer.is_some() {
                (color.to_u32(), bg.map(|c| c.to_u32()).unwrap_or(0))
            } else {
                (
                    self.info.format.encode_u32(color).unwrap_or(color.to_u32()),
                    bg.map(|c| self.info.format.encode_u32(c).unwrap_or(c.to_u32())).unwrap_or(0),
                )
            }
        } else {
            (0, 0)
        }
    }

    /// Pre-encode foreground/background colors for the 32bpp MMIO path.
    fn preencode_colors_32(&self, color: Color, bg_color: Color) -> (u32, u32) {
        let fg = self.info.format.encode_u32(color).unwrap_or(color.to_u32());
        let bg_v = self.info.format.encode_u32(bg_color).unwrap_or(bg_color.to_u32());
        (fg, bg_v)
    }

    /// Write one glyph row at 16bpp (RGB565) with branchless fg/bg selection.
    /// Writes all 8 pixels in one pass using streaming u64 writes (16 bytes total).
    /// Returns `true` if MMIO writes occurred.
    fn write_glyph_row_16bit_nofence(
        &self,
        bits: u8,
        dst_offset_bytes: usize,
        fg_u16: u16,
        bg_u16: u16,
    ) -> bool {
        if self.buffer.is_null() {
            return false;
        }
        let addr = self.buffer as usize + dst_offset_bytes;

        // Branchless pixel selection: for each bit, mask selects fg or bg
        #[inline(always)]
        fn sel16(mask: u16, fg: u16, bg: u16) -> u16 {
            bg ^ ((bg ^ fg) & mask)
        }

        let b = bits as i32;
        let m0 = ((b << 24) >> 31) as u16;
        let m1 = ((b << 25) >> 31) as u16;
        let m2 = ((b << 26) >> 31) as u16;
        let m3 = ((b << 27) >> 31) as u16;
        let m4 = ((b << 28) >> 31) as u16;
        let m5 = ((b << 29) >> 31) as u16;
        let m6 = ((b << 30) >> 31) as u16;
        let m7 = ((b << 31) >> 31) as u16;

        // Pack 4 pixels into one u64 (LE: pixel0 at low bits)
        let p0 = sel16(m0, fg_u16, bg_u16) as u64;
        let p1 = sel16(m1, fg_u16, bg_u16) as u64;
        let p2 = sel16(m2, fg_u16, bg_u16) as u64;
        let p3 = sel16(m3, fg_u16, bg_u16) as u64;
        let v0 = p0 | (p1 << 16) | (p2 << 32) | (p3 << 48);

        let p4 = sel16(m4, fg_u16, bg_u16) as u64;
        let p5 = sel16(m5, fg_u16, bg_u16) as u64;
        let p6 = sel16(m6, fg_u16, bg_u16) as u64;
        let p7 = sel16(m7, fg_u16, bg_u16) as u64;
        let v1 = p4 | (p5 << 16) | (p6 << 32) | (p7 << 48);

        mmio::stream_write_u64(addr, v0);
        mmio::stream_write_u64(addr + 8, v1);
        true
    }

    /// Write one glyph row at 24bpp (BGR888/RGB888) with branchless fg/bg selection.
    /// Writes all 8 pixels (24 bytes) via streaming store.
    /// Returns `true` if MMIO writes occurred.
    fn write_glyph_row_24bit_nofence(
        &mut self,
        bits: u8,
        dst_offset_bytes: usize,
        fg_bytes: (u8, u8, u8),
        bg_bytes: (u8, u8, u8),
    ) -> bool {
        if self.buffer.is_null() {
            return false;
        }
        let addr = self.buffer as usize + dst_offset_bytes;

        // Build 24 bytes in a stack buffer, then streaming write
        let mut buf = [0u8; 24];
        let b = bits as i32;
        for bit in 0..8u32 {
            let mask = ((b << (24 + bit)) >> 31) as u8;
            // mask is 0xFF for fg, 0x00 for bg
            let c0 = bg_bytes.0 ^ ((bg_bytes.0 ^ fg_bytes.0) & mask);
            let c1 = bg_bytes.1 ^ ((bg_bytes.1 ^ fg_bytes.1) & mask);
            let c2 = bg_bytes.2 ^ ((bg_bytes.2 ^ fg_bytes.2) & mask);
            let off = bit as usize * 3;
            buf[off] = c0;
            buf[off + 1] = c1;
            buf[off + 2] = c2;
        }

        // Stream 24 bytes: 3 u64 writes (covers 24 bytes exactly)
        let v0 = u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]);
        let v1 = u64::from_le_bytes([buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]]);
        let v2 = u64::from_le_bytes([buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23]]);
        mmio::stream_write_u64(addr, v0);
        mmio::stream_write_u64(addr + 8, v1);
        mmio::stream_write_u64(addr + 16, v2);
        true
    }

    /// Render glyph rows dispatching between fast-32bpp and generic paths.
    fn render_char_rows(
        &mut self,
        glyph: &[u8],
        x: i32,
        y: i32,
        use_fast_path_32: bool,
        fg_u32: u32,
        bg_u32: u32,
        bpp: usize,
        stride: usize,
        color: Color,
    ) -> bool {
        let mut mmio_written = false;
        for (row, &byte) in glyph.iter().enumerate() {
            let dst_y = y + row as i32;
            if !self.clip_y_visible(dst_y) {
                continue;
            }
            if use_fast_path_32 {
                let dst_offset = (dst_y as usize * stride) + (x as usize * 4);
                mmio_written |= self.write_glyph_row_32bit_nofence(byte, dst_offset, fg_u32, bg_u32);
            } else {
                mmio_written |= self.draw_char_8x16_row(byte, bpp, x, dst_y, stride, color);
            }
        }
        mmio_written
    }

    /// Draw a single 8x16 bitmap glyph (convenience optimized path).
    ///
    /// This method exposes a compact and faster path for single-character
    /// drawing used by `BitmapFont::draw_char`. It attempts to use
    /// 64-bit writes on 32-bit framebuffers and `write_bgr_run` on 24-bit
    /// framebuffers to minimize per-pixel overhead.
    /// Determine fast-path rendering mode for draw_char_8x16.
    /// Returns 0 (none), 2 (16bpp), 3 (24bpp), or 4 (32bpp).
    #[inline]
    fn determine_char_fast_mode(
        bg: Option<Color>,
        is_fully_visible: bool,
        no_backbuf: bool,
        bpp: usize,
    ) -> usize {
        if bg.is_some() && is_fully_visible && no_backbuf {
            match bpp {
                4 | 2 | 3 => bpp,
                _ => 0,
            }
        } else if bg.is_some() && is_fully_visible && bpp == 4 {
            4
        } else {
            0
        }
    }

    /// Render glyph rows in 16-bit (RGB565) fast path.
    fn render_glyph_16bit(
        &mut self,
        glyph: &[u8],
        x: i32,
        y: i32,
        stride: usize,
        color: Color,
        bg_color: Color,
    ) -> bool {
        let fg_u16 = Self::color_to_rgb565(color);
        let bg_u16 = Self::color_to_rgb565(bg_color);
        let mut wrote = false;
        for (row, &byte) in glyph.iter().enumerate() {
            let dst_y = y + row as i32;
            if !self.clip_y_visible(dst_y) { continue; }
            let offset = (dst_y as usize * stride) + (x as usize * 2);
            wrote |= self.write_glyph_row_16bit_nofence(byte, offset, fg_u16, bg_u16);
        }
        wrote
    }

    /// Render glyph rows in 24-bit (BGR) fast path.
    fn render_glyph_24bit(
        &mut self,
        glyph: &[u8],
        x: i32,
        y: i32,
        stride: usize,
        color: Color,
        bg_color: Color,
    ) -> bool {
        let fg_bytes = self.bgr_color_order(color);
        let bg_bytes = self.bgr_color_order(bg_color);
        let mut wrote = false;
        for (row, &byte) in glyph.iter().enumerate() {
            let dst_y = y + row as i32;
            if !self.clip_y_visible(dst_y) { continue; }
            let offset = (dst_y as usize * stride) + (x as usize * 3);
            wrote |= self.write_glyph_row_24bit_nofence(byte, offset, fg_bytes, bg_bytes);
        }
        wrote
    }

    pub fn draw_char_8x16(&mut self, x: i32, y: i32, c: char, color: Color, bg: Option<Color>) {
        let font = BitmapFont::default_8x16();
        let glyph = match font.glyph(c) {
            Some(g) => g,
            None => return,
        };
        let stride = self.info.stride as usize;
        let bpp = self.info.format.bytes_per_pixel();

        let char_w_i32 = font.width() as i32;
        let char_w = font.width() as u32;
        let char_h = font.height() as u32;
        self.mark_dirty(Rect::new(x, y, char_w, char_h));

        let is_fully_visible = x >= self.clip.x && (x + char_w_i32) <= self.clip.right();
        let no_backbuf = self.back_buffer.is_none();
        let fast_mode = Self::determine_char_fast_mode(bg, is_fully_visible, no_backbuf, bpp);

        // Pre-fill background only when not using single-pass fast path
        if let Some(bg_color) = bg {
            if fast_mode == 0 {
                self.fill_rect(Rect::new(x, y, char_w, char_h), bg_color);
            }
        }

        let mmio_written = match fast_mode {
            4 => {
                let (fg_u32, bg_u32) = self.preencode_colors_32(color, bg.unwrap());
                self.render_char_rows(glyph, x, y, true, fg_u32, bg_u32, bpp, stride, color)
            }
            2 => self.render_glyph_16bit(glyph, x, y, stride, color, bg.unwrap()),
            3 => self.render_glyph_24bit(glyph, x, y, stride, color, bg.unwrap()),
            _ => {
                self.render_char_rows(glyph, x, y, false, 0, 0, bpp, stride, color)
            }
        };

        if mmio_written {
            self.counted_sfence();
        }
    }

    /// Process one row of draw_char_8x16 for non-fast-path bpp values.
    fn draw_char_8x16_row(
        &mut self,
        byte: u8,
        bpp: usize,
        x: i32,
        dst_y: i32,
        stride: usize,
        color: Color,
    ) -> bool {
        match bpp {
            4 | 0 => {
                // 32bpp partial/no-bg: per-pixel fallback
                self.glyph_byte_fallback(byte, x, dst_y, x, 8, color);
                false
            }
            3 => {
                // 24bpp: run-coalesced writes
                let mut col = 0usize;
                while col < 8 {
                    let (run_start, run_len, new_col) = Self::next_on_run(byte, col, 8);
                    col = new_col;
                    if run_len == 0 {
                        continue;
                    }
                    let dst_x = x + run_start as i32;
                    if dst_x >= self.clip.right() {
                        continue;
                    }
                    self.write_clipped_bgr_run(dst_x, run_len, dst_y, stride, color);
                }
                false
            }
            2 => {
                let mut wrote_mmio = false;
                let mut col = 0usize;
                while col < 8 {
                    let (run_start, run_len, new_col) = Self::next_on_run(byte, col, 8);
                    col = new_col;
                    if run_len == 0 {
                        continue;
                    }
                    let dst_x = x + run_start as i32;
                    if dst_x >= self.clip.right() {
                        continue;
                    }
                    wrote_mmio |= self.write_clipped_rgb565_run_nofence(dst_x, run_len, dst_y, stride, color);
                }
                wrote_mmio
            }
            _ => {
                self.glyph_byte_fallback(byte, x, dst_y, x, 8, color);
                false
            }
        }
    }
}
