// ============================================================================
// kernel/src/graphics/framebuffer/drawing.rs - Drawing Methods
// ============================================================================
//!
//! フレームバッファ描画メソッド
//!
//! 線、矩形、円などの図形描画メソッドを提供する。
//! `framebuffer.rs` から抽出された描画ロジック。

use super::*;

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
        self.counted_sfence();
    }

    /// Dirty Rectangle更新を行わない水平線描画（クリッピング済み前提）
    pub(super) fn draw_hline_raw(&mut self, start_x: i32, end_x: i32, y: i32, color: Color) {
        let (bytes_per_pixel, stride) = if self.back_buffer.is_some() {
            (4, (self.info.width() * 4) as usize)
        } else {
            (
                self.info.format().bytes_per_pixel(),
                self.info.stride() as usize,
            )
        };
        let x_start = start_x as usize;
        let run_len = (end_x - start_x + 1) as usize;
        let offset = (y as usize * stride) + x_start * bytes_per_pixel;

        match bytes_per_pixel {
            4 => {
                let color_u32 = self
                    .drawing_format()
                    .encode_u32(color)
                    .expect("32 bit drawing format");
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
                    self.write_u16_run_streaming_nofence(offset, run_len, pixel);
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

    fn draw_vline_raw(&mut self, x: i32, start: i32, end: i32, color: Color) {
        // LOOP_PROOF: mode=bounded; reason=The clipped column has a finite row count.;
        for y in start..=end {
            self.set_pixel_raw(x, y, color);
        }
        self.counted_sfence();
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
        // Clip source and destination in the same displacement coordinates.
        // i64 edges keep arbitrary public i32 origins/u32 extents from wrapping.
        let axis = |source: i32, destination: i32, length: u32, low: i32, high: i32| {
            let start = 0i64
                .max(low as i64 - source as i64)
                .max(low as i64 - destination as i64);
            let end = (length as i64)
                .min(high as i64 - source as i64)
                .min(high as i64 - destination as i64);
            (start < end).then_some((
                source as i64 + start,
                destination as i64 + start,
                end - start,
            ))
        };
        let Some((sx, dx, width)) = axis(src.x, dst_x, src.width, self.clip.x, self.clip.right())
        else {
            return;
        };
        let Some((sy, dy, height)) =
            axis(src.y, dst_y, src.height, self.clip.y, self.clip.bottom())
        else {
            return;
        };
        // Every coordinate lies in the validated canvas after displacement clipping.
        let s = Rect::new(sx as i32, sy as i32, width as u32, height as u32);
        let d_x = dx as i32;
        let d_y = dy as i32;

        // Mark destination dirty
        self.mark_dirty(Rect::new(d_x, d_y, s.width, s.height));

        // Fast path: backbuffer is tightly packed u32 pixels.
        // Use slice-level copy_within (memmove semantics) per row.
        if let Some(ref mut back) = self.back_buffer {
            let row_pixels = self.info.width() as usize;
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

        let bpp = self.info.format().bytes_per_pixel();
        let stride = self.info.stride() as usize;
        let count = s.width as usize * bpp;
        // LOOP_PROOF: mode=bounded; reason=Each clipped row is copied once in the direction preserving source pixels.;
        for step in 0..s.height as usize {
            let row = if d_y > s.y {
                s.height as usize - step - 1
            } else {
                step
            };
            let source = (s.y as usize + row) * stride + s.x as usize * bpp;
            let destination = (d_y as usize + row) * stride + d_x as usize * bpp;
            self.pixels.copy_within(source..source + count, destination);
        }
        self.counted_sfence();
    }

    fn clip_intersection(&self, rect: Rect) -> Option<Rect> {
        bounded_intersection(rect, self.clip)
    }

    /// Fill a clipped rectangle into the u32 backbuffer.
    fn fill_rect_backbuffer(&mut self, r: Rect, color: Color) {
        if let Some(ref mut back) = self.back_buffer {
            let val = color.to_u32();
            let fb_width = self.info.width() as usize;

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

    pub fn fill_rect(&mut self, rect: Rect, color: Color) {
        let Some(r) = self.clip_intersection(rect) else {
            return;
        };
        self.stats.rectangles_drawn += 1;
        self.stats.pixels_drawn += r.width as usize * r.height as usize;
        self.mark_dirty(r);
        if self.back_buffer.is_some() {
            self.fill_rect_backbuffer(r, color);
            return;
        }
        let bpp = self.info.format().bytes_per_pixel();
        let mut pixel = [0; 4];
        self.info.format().encode_color_bytes(color, &mut pixel);
        // LOOP_PROOF: mode=bounded; reason=Each clipped scanline is filled once without touching row padding.;
        for y in r.y..r.bottom() {
            self.pixels.fill(
                y as usize * self.info.stride() as usize + r.x as usize * bpp,
                r.width as usize,
                &pixel[..bpp],
            );
        }
        self.counted_sfence();
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
