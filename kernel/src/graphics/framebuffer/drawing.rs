// ============================================================================
// kernel/src/graphics/framebuffer/drawing.rs - Drawing Methods
// ============================================================================
//!
//! フレームバッファ描画メソッド
//!
//! 線、矩形、円などの図形描画メソッドを提供する。
//! `framebuffer.rs` から抽出された描画ロジック。

use super::*;
use core::ptr;
use hal::mmio;

impl Framebuffer {
    /// 水平線を描画
    pub fn draw_hline(&mut self, x1: i32, x2: i32, y: i32, color: Color) {
        if y < self.clip.y || y >= self.clip.bottom() {
            return;
        }

        let start_x = x1.min(x2).max(self.clip.x);
        let end_x = x1.max(x2).min(self.clip.right() - 1);

        if start_x > end_x {
            return;
        }

        // Mark dirty
        self.mark_dirty(Rect::new(start_x, y, (end_x - start_x + 1) as u32, 1));
        self.draw_hline_raw(start_x, end_x, y, color);
    }

    /// Dirty Rectangle更新を行わない水平線描画（クリッピング済み前提）
    pub(super) fn draw_hline_raw(&mut self, start_x: i32, end_x: i32, y: i32, color: Color) {
        let (bytes_per_pixel, stride) = if self.back_buffer.is_some() {
            (4, (self.info.width * 4) as usize)
        } else {
            (
                self.info.format.bytes_per_pixel(),
                self.info.stride as usize,
            )
        };
        let x_start = start_x as usize;
        let run_len = (end_x - start_x + 1) as usize;
        let offset = (y as usize * stride) + x_start * bytes_per_pixel;

        match bytes_per_pixel {
            4 => {
                let color_u32 = color.to_u32();
                // Delegate to write_u32_run which already handles backbuffer/MMIO paths efficiently
                self.write_u32_run(offset, run_len, color_u32);
            }
            3 => {
                self.write_bgr_run(offset, run_len, color);
            }
            2 => {
                // rgb565 per-pixel write. Branch once on presence of back buffer
                let pixel = Self::color_to_rgb565(color);
                if let Some(_) = self.back_buffer {
                    debug_assert!(false, "16bpp hline called on u32 backbuffer");
                } else {
                    let addr = self.draw_buffer() as usize + offset;
                    self.write_u16_run_streaming(addr, run_len, pixel);
                }
            }
            _ => {
                // Fallback (use set_pixel_raw)
                for x in start_x..=end_x {
                    self.set_pixel_raw(x, y, color);
                }
            }
        }
    }

    /// 垂直線を描画
    pub fn draw_vline(&mut self, x: i32, y1: i32, y2: i32, color: Color) {
        if x < self.clip.x || x >= self.clip.right() {
            return;
        }

        let start_y = y1.min(y2).max(self.clip.y);
        let end_y = y1.max(y2).min(self.clip.bottom() - 1);

        if start_y > end_y {
            return;
        }

        // Mark dirty
        self.mark_dirty(Rect::new(x, start_y, 1, (end_y - start_y + 1) as u32));
        self.draw_vline_raw(x, start_y, end_y, color);
    }

    /// 4bpp垂直線描画ヘルパー
    fn draw_vline_4bpp(
        &mut self,
        x_off: usize,
        start_y: usize,
        run_len: usize,
        stride: usize,
        color: Color,
    ) {
        let color_u32 = color.to_u32();
        let mut off = start_y * stride + x_off * 4;
        if self.back_buffer.is_some() {
            let base = self.draw_buffer();
            for i in 0..run_len {
                unsafe {
                    ptr::write(base.add(off) as *mut u32, color_u32);
                }
                if i + 1 < run_len {
                    off += stride;
                }
            }
        } else {
            let base_addr = self.draw_buffer() as usize;
            for i in 0..run_len {
                mmio::mmio_write_u32(base_addr + off, color_u32);
                if i + 1 < run_len {
                    off += stride;
                }
            }
            if run_len > 0 {
                mmio::sfence();
            }
        }
    }

    /// 3bpp垂直線描画ヘルパー
    fn draw_vline_3bpp(
        &mut self,
        x_off: usize,
        start_y: usize,
        run_len: usize,
        stride: usize,
        color: Color,
    ) {
        let is_bgr = matches!(self.info.format, PixelFormat::Bgr888);
        let (c0, c1, c2) = if is_bgr {
            (color.blue, color.green, color.red)
        } else {
            (color.red, color.green, color.blue)
        };

        if let Some(ref mut _back) = self.back_buffer {
            debug_assert!(false, "24bpp vline called on u32 backbuffer");
        } else {
            let base_addr = self.draw_buffer() as usize;
            let mut off = base_addr + start_y * stride + x_off * 3;
            for i in 0..run_len {
                mmio::volatile_write(off, c0);
                mmio::volatile_write(off + 1, c1);
                mmio::volatile_write(off + 2, c2);
                if i + 1 < run_len {
                    off += stride;
                }
            }
            if run_len > 0 {
                mmio::sfence();
            }
        }
    }

    /// 2bpp垂直線描画ヘルパー
    fn draw_vline_2bpp(
        &mut self,
        x_off: usize,
        start_y: usize,
        run_len: usize,
        stride: usize,
        color: Color,
    ) {
        let pixel = Self::color_to_rgb565(color);
        if let Some(ref mut _back) = self.back_buffer {
            debug_assert!(false, "16bpp vline called on u32 backbuffer");
        } else {
            let base_addr = self.draw_buffer() as usize;
            let mut off = base_addr + start_y * stride + x_off * 2;
            for i in 0..run_len {
                mmio::mmio_write_u16(off, pixel);
                if i + 1 < run_len {
                    off += stride;
                }
            }
            if run_len > 0 {
                mmio::sfence();
            }
        }
    }

    /// Dirty Rectangle更新を行わない垂直線描画（クリッピング済み前提）
    fn draw_vline_raw(&mut self, x: i32, start_y: i32, end_y: i32, color: Color) {
        let (bytes_per_pixel, stride) = if self.back_buffer.is_some() {
            (4, (self.info.width * 4) as usize)
        } else {
            (
                self.info.format.bytes_per_pixel(),
                self.info.stride as usize,
            )
        };
        let x_off = x as usize;
        let run_len = (end_y - start_y + 1) as usize;

        match bytes_per_pixel {
            4 => self.draw_vline_4bpp(x_off, start_y as usize, run_len, stride, color),
            3 => self.draw_vline_3bpp(x_off, start_y as usize, run_len, stride, color),
            2 => self.draw_vline_2bpp(x_off, start_y as usize, run_len, stride, color),
            _ => {
                for y in start_y..=end_y {
                    self.set_pixel_raw(x, y, color);
                }
            }
        }
    }

    /// 線を描画（Bresenhamアルゴリズム） - Optimized
    pub fn draw_line(&mut self, x1: i32, y1: i32, x2: i32, y2: i32, color: Color) {
        // Fast-path horizontal/vertical lines to use bulk writers (already optimized internally)
        if y1 == y2 {
            self.draw_hline(x1, x2, y1, color);
            return;
        }
        if x1 == x2 {
            self.draw_vline(x1, y1, y2, color);
            return;
        }

        // Calculate bounding box and mark dirty once
        let min_x = x1.min(x2);
        let min_y = y1.min(y2);
        let max_x = x1.max(x2);
        let max_y = y1.max(y2);
        self.mark_dirty(Rect::new(
            min_x,
            min_y,
            (max_x - min_x + 1) as u32,
            (max_y - min_y + 1) as u32,
        ));

        let abs_dx = (x2 - x1).abs();
        let abs_dy = (y2 - y1).abs();

        if abs_dx < abs_dy {
            self.draw_line_steep(x1, y1, x2, y2, color);
        } else {
            self.draw_line_shallow(x1, y1, x2, y2, color);
        }
    }

    /// Steep Bresenham: coalesce vertical runs (|dy| > |dx|).
    fn draw_line_steep(&mut self, x1: i32, y1: i32, x2: i32, y2: i32, color: Color) {
        let dx = (x2 - x1).abs();
        let dy = -(y2 - y1).abs();
        let sx = if x1 < x2 { 1 } else { -1 };
        let sy = if y1 < y2 { 1 } else { -1 };
        let mut err = dx + dy;
        let mut x = x1;
        let mut y = y1;

        // Track current vertical run for coalescing
        let mut run_x = x;
        let mut run_start = y;
        let mut run_end = y;

        // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
        loop {
            if x == x2 && y == y2 {
                self.flush_steep_run(run_x, run_start, run_end, color);
                return;
            }

            let mut next_x = x;
            let mut next_y = y;
            let e2 = 2 * err;
            if e2 >= dy {
                err += dy;
                next_x += sx;
            }
            if e2 <= dx {
                err += dx;
                next_y += sy;
            }

            if next_x == run_x {
                // Same column — extend current vertical run
                run_end = next_y;
            } else {
                // Column changed — flush current run and start new one
                self.flush_steep_run(run_x, run_start, run_end, color);
                run_x = next_x;
                run_start = next_y;
                run_end = next_y;
            }
            x = next_x;
            y = next_y;
        }
    }

    /// Flush one vertical run collected by steep Bresenham.
    #[inline]
    fn flush_steep_run(&mut self, run_x: i32, run_start: i32, run_end: i32, color: Color) {
        if run_x < self.clip.x || run_x >= self.clip.right() {
            return;
        }

        let mut start = run_start.min(run_end);
        let mut end = run_start.max(run_end);
        start = start.max(self.clip.y);
        end = end.min(self.clip.bottom() - 1);

        if start <= end {
            self.draw_vline_raw(run_x, start, end, color);
        }
    }

    /// Flush one horizontal run collected by shallow Bresenham.
    #[inline]
    fn flush_shallow_run(&mut self, run_y: i32, run_start: i32, run_end: i32, color: Color) {
        if run_y < self.clip.y || run_y >= self.clip.bottom() {
            return;
        }

        let mut start = run_start.min(run_end);
        let mut end = run_start.max(run_end);
        start = start.max(self.clip.x);
        end = end.min(self.clip.right() - 1);

        if start <= end {
            self.draw_hline_raw(start, end, run_y, color);
        }
    }

    /// Shallow Bresenham: coalesce horizontal runs (|dx| >= |dy|).
    fn draw_line_shallow(&mut self, x1: i32, y1: i32, x2: i32, y2: i32, color: Color) {
        let dx = (x2 - x1).abs();
        let dy = -(y2 - y1).abs();
        let sx = if x1 < x2 { 1 } else { -1 };
        let sy = if y1 < y2 { 1 } else { -1 };
        let mut err = dx + dy;
        let mut x = x1;
        let mut y = y1;

        let mut run_y = y;
        let mut run_start = x;
        let mut run_end = x;

        // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
        loop {
            if x == x2 && y == y2 {
                self.flush_shallow_run(run_y, run_start, run_end, color);
                return;
            }

            // Compute next Bresenham point first, then decide whether it
            // belongs to the current horizontal run or starts a new row run.
            let mut next_x = x;
            let mut next_y = y;
            let e2 = 2 * err;
            if e2 >= dy {
                err += dy;
                next_x += sx;
            }
            if e2 <= dx {
                err += dx;
                next_y += sy;
            }

            if next_y == run_y {
                run_end = next_x;
            } else {
                self.flush_shallow_run(run_y, run_start, run_end, color);
                run_y = next_y;
                run_start = next_x;
                run_end = next_x;
            }

            x = next_x;
            y = next_y;
        }
    }

    /// Naive per-pixel Bresenham implementation useful for benchmarking and
    /// correctness comparisons. Enabled when `bench` feature is active.
    #[cfg(feature = "bench")]
    pub fn draw_line_naive(&mut self, x1: i32, y1: i32, x2: i32, y2: i32, color: Color) {
        if y1 == y2 {
            self.draw_hline(x1, x2, y1, color);
            return;
        }
        if x1 == x2 {
            self.draw_vline(x1, y1, y2, color);
            return;
        }

        let dx = (x2 - x1).abs();
        let dy = -(y2 - y1).abs();
        let sx = if x1 < x2 { 1 } else { -1 };
        let sy = if y1 < y2 { 1 } else { -1 };
        let mut err = dx + dy;

        let mut x = x1;
        let mut y = y1;

        // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
        loop {
            self.set_pixel(x, y, color);
            if x == x2 && y == y2 {
                break;
            }
            let e2 = 2 * err;
            if e2 >= dy {
                err += dy;
                x += sx;
            }
            if e2 <= dx {
                err += dx;
                y += sy;
            }
        }
    }

    /// 矩形を描画（枠のみ）
    pub fn draw_rect(&mut self, rect: Rect, color: Color) {
        if rect.width == 0 || rect.height == 0 {
            return;
        }
        // Pre-mark entire bounding box dirty once instead of 4 separate mark_dirty calls
        self.mark_dirty(rect);

        let x0 = rect.x;
        let x1 = rect.right() - 1;
        let y0 = rect.y;
        let y1 = rect.bottom() - 1;

        // Clip and use raw variants (skip per-call mark_dirty)
        // Top hline
        if y0 >= self.clip.y && y0 < self.clip.bottom() {
            let s = x0.max(self.clip.x);
            let e = x1.min(self.clip.right() - 1);
            if s <= e {
                self.draw_hline_raw(s, e, y0, color);
            }
        }
        // Bottom hline
        if y1 >= self.clip.y && y1 < self.clip.bottom() && y1 != y0 {
            let s = x0.max(self.clip.x);
            let e = x1.min(self.clip.right() - 1);
            if s <= e {
                self.draw_hline_raw(s, e, y1, color);
            }
        }
        // Left vline (exclude corners already drawn by hlines)
        if x0 >= self.clip.x && x0 < self.clip.right() {
            let vs = (y0 + 1).max(self.clip.y);
            let ve = (y1 - 1).min(self.clip.bottom() - 1);
            if vs <= ve {
                self.draw_vline_raw(x0, vs, ve, color);
            }
        }
        // Right vline (exclude corners)
        if x1 >= self.clip.x && x1 < self.clip.right() && x1 != x0 {
            let vs = (y0 + 1).max(self.clip.y);
            let ve = (y1 - 1).min(self.clip.bottom() - 1);
            if vs <= ve {
                self.draw_vline_raw(x1, vs, ve, color);
            }
        }
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

        // Mark destination dirty
        self.mark_dirty(Rect::new(d_x, d_y, s.width, s.height));

        // Fast path: backbuffer is tightly packed u32 pixels.
        // Use slice-level copy_within (memmove semantics) per row.
        if let Some(ref mut back) = self.back_buffer {
            let row_pixels = self.info.width as usize;
            let copy_pixels = s.width as usize;
            if d_y > s.y {
                for i in (0..s.height as usize).rev() {
                    let src_row_y = s.y as usize + i;
                    let dst_row_y = d_y as usize + i;
                    let src_start = src_row_y * row_pixels + s.x as usize;
                    let dst_start = dst_row_y * row_pixels + d_x as usize;
                    back.copy_within(src_start..src_start + copy_pixels, dst_start);
                }
            } else {
                for i in 0..s.height as usize {
                    let src_row_y = s.y as usize + i;
                    let dst_row_y = d_y as usize + i;
                    let src_start = src_row_y * row_pixels + s.x as usize;
                    let dst_start = dst_row_y * row_pixels + d_x as usize;
                    back.copy_within(src_start..src_start + copy_pixels, dst_start);
                }
            }
            return;
        }

        let buffer = self.draw_buffer();
        let (stride, bpp) = (
            self.info.stride as usize,
            self.info.format.bytes_per_pixel(),
        );
        let copy_bytes = s.width as usize * bpp;
        // When source and destination rows are different, row slices do not overlap
        // in the normal framebuffer layout (stride >= row bytes). In that case we
        // can use copy_nonoverlapping for a slightly faster path.
        let use_nonoverlap_rows = d_y != s.y && copy_bytes <= stride;

        unsafe {
            if d_y > s.y {
                // 下方向へのコピー（後ろから）
                for i in (0..s.height).rev() {
                    let src_row_y = s.y + i as i32;
                    let dst_row_y = d_y + i as i32;

                    let src_offset = (src_row_y as usize * stride) + (s.x as usize * bpp);
                    let dst_offset = (dst_row_y as usize * stride) + (d_x as usize * bpp);

                    let src_ptr = buffer.add(src_offset);
                    let dst_ptr = buffer.add(dst_offset);
                    if use_nonoverlap_rows {
                        ptr::copy_nonoverlapping(src_ptr, dst_ptr, copy_bytes);
                    } else {
                        ptr::copy(src_ptr, dst_ptr, copy_bytes);
                    }
                }
            } else {
                // 上方向へのコピー（前から）
                for i in 0..s.height {
                    let src_row_y = s.y + i as i32;
                    let dst_row_y = d_y + i as i32;

                    let src_offset = (src_row_y as usize * stride) + (s.x as usize * bpp);
                    let dst_offset = (dst_row_y as usize * stride) + (d_x as usize * bpp);

                    let src_ptr = buffer.add(src_offset);
                    let dst_ptr = buffer.add(dst_offset);
                    if use_nonoverlap_rows {
                        ptr::copy_nonoverlapping(src_ptr, dst_ptr, copy_bytes);
                    } else {
                        ptr::copy(src_ptr, dst_ptr, copy_bytes);
                    }
                }
            }
            // Ensure writes to WC-mapped VRAM are globally visible
            mmio::sfence();
        }
    }

    /// Returns `None` if the rectangle is fully clipped away.
    fn clip_intersection(&self, rect: Rect) -> Option<Rect> {
        let mut r = rect;
        r.x = r.x.max(self.clip.x);
        r.y = r.y.max(self.clip.y);
        let right = r.right().min(self.clip.right());
        let bottom = r.bottom().min(self.clip.bottom());
        r.width = (right - r.x).max(0) as u32;
        r.height = (bottom - r.y).max(0) as u32;
        if r.width == 0 || r.height == 0 {
            None
        } else {
            Some(r)
        }
    }

    /// Fill a clipped rectangle into the u32 backbuffer.
    fn fill_rect_backbuffer(&mut self, r: Rect, color: Color) {
        if let Some(ref mut back) = self.back_buffer {
            let val = color.to_u32();
            let fb_width = self.info.width as usize;

            // Fast path: full-width span is contiguous in backbuffer.
            if r.x == 0 && r.width as usize == fb_width {
                let start = r.y as usize * fb_width;
                let len = r.height as usize * fb_width;
                back[start..start + len].fill(val);
                return;
            }

            let w = r.width as usize;
            for y in r.y..r.bottom() {
                let idx = (y as usize * fb_width) + r.x as usize;
                back[idx..idx + w].fill(val);
            }
        }
    }

    /// 32bpp MMIO streaming fill (Bgra8888 / Rgba8888).
    fn fill_rect_32bpp_mmio(&mut self, r: Rect, color_u32: u32) {
        let stride = self.info.stride as usize;
        for y in r.y..r.bottom() {
            let offset = (y as usize * stride) + (r.x as usize * 4);
            let addr = self.buffer as usize + offset;
            self.write_u32_run_streaming_nofence(addr, r.width as usize, color_u32);
        }
        mmio::sfence();
    }

    /// 24bpp MMIO streaming fill (Bgr888 / Rgb888).
    fn fill_rect_24bpp_mmio(&mut self, r: Rect, color: Color) {
        let width = r.width as usize;
        let row_bytes = width * 3;
        if row_bytes == 0 {
            return;
        }

        let is_bgr = matches!(self.info.format, PixelFormat::Bgr888);
        let (c0, c1, c2) = if is_bgr {
            (color.blue, color.green, color.red)
        } else {
            (color.red, color.green, color.blue)
        };

        self.ensure_scratch_u8(row_bytes);
        if width > 0 {
            Self::fill_scratch_bgr_exponential(&mut self.scratch_u8, width, c0, c1, c2);
        }

        let stride = self.info.stride as usize;
        for y in r.y..r.bottom() {
            let offset = y as usize * stride + r.x as usize * 3;
            let addr = self.buffer as usize + offset;
            self.write_bytes_mmio_streaming(addr, &self.scratch_u8[..row_bytes]);
        }
        mmio::sfence();
    }

    /// 16bpp MMIO streaming fill (Rgb565).
    fn fill_rect_16bpp_mmio(&mut self, r: Rect, color: Color) {
        let stride = self.info.stride as usize;
        let pixel = Self::color_to_rgb565(color);
        let width = r.width as usize;

        for y in r.y..r.bottom() {
            let offset = y as usize * stride + r.x as usize * 2;
            let addr = self.buffer as usize + offset;
            self.write_u16_run_streaming_nofence(addr, width, pixel);
        }
        mmio::sfence();
    }

    /// Per-pixel fallback fill for other pixel formats.
    fn fill_rect_pixel_fallback(&mut self, r: Rect, color: Color) {
        for y in r.y..r.bottom() {
            for x in r.x..r.right() {
                self.set_pixel_raw(x, y, color);
            }
        }
    }

    pub fn fill_rect(&mut self, rect: Rect, color: Color) {
        let r = match self.clip_intersection(rect) {
            Some(r) => r,
            None => return,
        };

        if self.back_buffer.is_none() && self.buffer.is_null() {
            return;
        }

        self.stats.rectangles_drawn += 1;
        self.stats.pixels_drawn += (r.width * r.height) as usize;

        // Mark dirty
        self.mark_dirty(r);

        let _buffer = self.draw_buffer();

        #[cfg(feature = "std")]
        if std::env::var("RANY_DEBUG_DRAW").ok().as_deref() == Some("1") {
            eprintln!(
                "fill_rect start: back_present={} buffer_ptr=0x{:x} info_size={} stride={} rect={:?}",
                self.back_buffer.is_some(),
                self.buffer as usize,
                self.info.size(),
                self.info.stride,
                r
            );
        }

        if self.back_buffer.is_some() {
            self.fill_rect_backbuffer(r, color);
            return;
        }

        match self.info.format {
            PixelFormat::Bgra8888 | PixelFormat::Rgba8888 => {
                self.fill_rect_32bpp_mmio(r, color.to_u32());
            }
            PixelFormat::Bgr888 | PixelFormat::Rgb888 => {
                self.fill_rect_24bpp_mmio(r, color);
            }
            PixelFormat::Rgb565 => {
                self.fill_rect_16bpp_mmio(r, color);
            }
        }
    }

    /// 円を描画（Midpointアルゴリズム）
    pub fn draw_circle(&mut self, cx: i32, cy: i32, radius: i32, color: Color) {
        if radius <= 0 {
            self.set_pixel(cx, cy, color);
            return;
        }
        // Pre-mark bounding box dirty once instead of per-pixel
        self.mark_dirty(Rect::new(
            cx - radius,
            cy - radius,
            (radius * 2 + 1) as u32,
            (radius * 2 + 1) as u32,
        ));
        let mut x = radius;
        let mut y = 0;
        let mut err = 0;

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while x >= y {
            // Use set_pixel_raw (skip per-pixel dirty mark + clip re-check)
            // Only draw if within clip bounds
            let pts = [
                (cx + x, cy + y),
                (cx + y, cy + x),
                (cx - y, cy + x),
                (cx - x, cy + y),
                (cx - x, cy - y),
                (cx - y, cy - x),
                (cx + y, cy - x),
                (cx + x, cy - y),
            ];
            for &(px, py) in &pts {
                if self.clip_contains_point(px, py) {
                    self.set_pixel_raw(px, py, color);
                }
            }

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
        if radius <= 0 {
            self.set_pixel(cx, cy, color);
            return;
        }
        // Pre-mark bounding box dirty once
        self.mark_dirty(Rect::new(
            cx - radius,
            cy - radius,
            (radius * 2 + 1) as u32,
            (radius * 2 + 1) as u32,
        ));

        let mut x = radius;
        let mut y = 0;
        let mut err = 0;
        // Track last drawn y-coordinates to eliminate duplicate hlines
        let mut last_y1: i32 = i32::MIN;
        let mut last_y2: i32 = i32::MIN;
        let mut last_y3: i32 = i32::MIN;
        let mut last_y4: i32 = i32::MIN;

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while x >= y {
            // Use draw_hline_raw (skip per-hline dirty mark — already pre-marked)
            let rows = [
                (cx - x, cx + x, cy + y),
                (cx - y, cx + y, cy + x),
                (cx - x, cx + x, cy - y),
                (cx - y, cx + y, cy - x),
            ];
            let last = [&mut last_y1, &mut last_y2, &mut last_y3, &mut last_y4];
            for (i, &(x0, x1, ry)) in rows.iter().enumerate() {
                if ry != *last[i] {
                    *last[i] = ry;
                    // Clip and draw raw
                    let sy = ry;
                    if sy >= self.clip.y && sy < self.clip.bottom() {
                        let start = x0.max(self.clip.x);
                        let end = x1.min(self.clip.right() - 1);
                        if start <= end {
                            self.draw_hline_raw(start, end, sy, color);
                        }
                    }
                }
            }

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

    // ─── Shared pixel-run helpers ───────────────────────────────────────────

    /// Check if a point is inside the clip rectangle.
    #[inline]
    fn clip_contains_point(&self, x: i32, y: i32) -> bool {
        x >= self.clip.x && x < self.clip.right() && y >= self.clip.y && y < self.clip.bottom()
    }
}
