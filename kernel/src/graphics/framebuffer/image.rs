// ============================================================================
// kernel/src/graphics/framebuffer/image.rs
// ============================================================================
//! Image drawing and blitting operations for the Framebuffer.
//!
//! This module contains methods for drawing images (or parts of images) onto
//! the framebuffer, including clipping, alpha-blending, scanline-based opaque
//! run detection, and format-specific pixel packing (32-bit, 24-bit, 16-bit).

use super::*;
use core::ptr;
use hal::mmio;

impl Framebuffer {
    /// Draw entire image at (dst_x, dst_y)
    pub fn draw_image(&mut self, image: &crate::graphics::image::Image, dst_x: i32, dst_y: i32) {
        self.draw_image_part(
            image,
            Rect::new(0, 0, image.width(), image.height()),
            dst_x,
            dst_y,
        );
    }

    /// Draw a part of an image
    pub fn draw_image_part(
        &mut self,
        image: &crate::graphics::image::Image,
        src_rect: Rect,
        dst_x: i32,
        dst_y: i32,
    ) {
        let (s_x, s_y, s_w, s_h) = Self::clip_src_to_image(&src_rect, image);
        if s_w == 0 || s_h == 0 {
            return;
        }

        let clip_result = self.clip_dst_to_screen(s_x, s_y, s_w, s_h, dst_x, dst_y);
        let (d_x, d_y, r_x, r_y, r_w, r_h) = match clip_result {
            Some(v) => v,
            None => return,
        };

        if r_w == 0 || r_h == 0 {
            return;
        }

        // Mark dirty
        self.mark_dirty(Rect::new(d_x, d_y, r_w, r_h));

        // Perform blit
        self.blit_image_rows(image, d_x, d_y, r_x, r_y, r_w, r_h);
    }

    fn clip_src_to_image(
        src_rect: &Rect,
        image: &crate::graphics::image::Image,
    ) -> (i32, i32, u32, u32) {
        let s_x = src_rect.x.max(0);
        let s_y = src_rect.y.max(0);
        let s_w = (src_rect.width as i32)
            .min(image.width() as i32 - s_x)
            .max(0) as u32;
        let s_h = (src_rect.height as i32)
            .min(image.height() as i32 - s_y)
            .max(0) as u32;
        (s_x, s_y, s_w, s_h)
    }

    fn clip_dst_to_screen(
        &self,
        s_x: i32,
        s_y: i32,
        s_w: u32,
        s_h: u32,
        dst_x: i32,
        dst_y: i32,
    ) -> Option<(i32, i32, i32, i32, u32, u32)> {
        let mut d_x = dst_x;
        let mut d_y = dst_y;
        let mut r_x = s_x;
        let mut r_y = s_y;
        let mut r_w = s_w;
        let mut r_h = s_h;

        // Left clip
        if d_x < self.clip.x {
            let diff = self.clip.x - d_x;
            if diff >= r_w as i32 {
                return None;
            }
            d_x += diff;
            r_x += diff;
            r_w -= diff as u32;
        }
        // Top clip
        if d_y < self.clip.y {
            let diff = self.clip.y - d_y;
            if diff >= r_h as i32 {
                return None;
            }
            d_y += diff;
            r_y += diff;
            r_h -= diff as u32;
        }
        // Right clip
        let over_x = (d_x + r_w as i32) - self.clip.right();
        if over_x > 0 {
            if over_x >= r_w as i32 {
                return None;
            }
            r_w -= over_x as u32;
        }
        // Bottom clip
        let over_y = (d_y + r_h as i32) - self.clip.bottom();
        if over_y > 0 {
            if over_y >= r_h as i32 {
                return None;
            }
            r_h -= over_y as u32;
        }

        Some((d_x, d_y, r_x, r_y, r_w, r_h))
    }

    fn blit_image_rows(
        &mut self,
        image: &crate::graphics::image::Image,
        d_x: i32,
        d_y: i32,
        r_x: i32,
        r_y: i32,
        r_w: u32,
        r_h: u32,
    ) {
        let src_stride = image.width() * 4;
        let src_data = image.data();
        let dst_stride = if self.back_buffer.is_some() {
            self.info.width * 4
        } else {
            self.info.stride
        } as usize;
        let dst_bpp = if self.back_buffer.is_some() {
            4
        } else {
            self.info.format.bytes_per_pixel()
        } as usize;

        let buf_ptr = self.draw_buffer();

        let needs_swizzle = match (self.back_buffer.is_some(), self.info.format) {
            (true, _) => true,
            (false, PixelFormat::Bgra8888 | PixelFormat::Bgr888) => true,
            _ => false,
        };

        for i in 0..r_h {
            let src_row_offset = ((r_y as u32 + i as u32) * src_stride + (r_x as u32 * 4)) as usize;
            let dst_row_offset =
                (d_y as usize + i as usize) * dst_stride + (d_x as usize * dst_bpp as usize);

            let src_row = &src_data[src_row_offset..src_row_offset + (r_w as usize * 4)];

            unsafe {
                let dst_ptr = buf_ptr.add(dst_row_offset);

                if self.back_buffer.is_some() {
                    let dst_slice = core::slice::from_raw_parts_mut(dst_ptr, r_w as usize * 4);
                    crate::graphics::packer::pack_rgba_to_bgra(src_row, dst_slice);
                } else {
                    self.blit_mmio_row(dst_ptr, src_row, r_w, dst_bpp, needs_swizzle, i == r_h - 1);
                }
            }
        }
    }

    unsafe fn blit_mmio_row(
        &mut self,
        dst_ptr: *mut u8,
        src_row: &[u8],
        r_w: u32,
        dst_bpp: usize,
        needs_swizzle: bool,
        is_last_row: bool,
    ) {
        match dst_bpp {
            4 => {
                if needs_swizzle {
                    let dst_slice =
                        unsafe { core::slice::from_raw_parts_mut(dst_ptr, r_w as usize * 4) };
                    crate::graphics::packer::pack_rgba_to_bgra(src_row, dst_slice);
                } else {
                    self.write_bytes_mmio_streaming(dst_ptr as usize, src_row);
                }
            }
            3 => {
                let dst_slice =
                    unsafe { core::slice::from_raw_parts_mut(dst_ptr, r_w as usize * 3) };
                crate::graphics::packer::pack_rgba_to_bgr24(src_row, dst_slice, needs_swizzle);
            }
            2 => {
                // RGB565 direct path: convert RGBA pixels to RGB565 and stream-write
                let pixel_count = r_w as usize;
                self.ensure_scratch_u8(pixel_count * 2);
                let src_pixels = unsafe {
                    core::slice::from_raw_parts(src_row.as_ptr() as *const u32, pixel_count)
                };
                // Convert RGBA u32 -> RGB565 u16 into scratch buffer
                {
                    let dst_u16 = unsafe {
                        core::slice::from_raw_parts_mut(
                            self.scratch_u8.as_mut_ptr() as *mut u16,
                            pixel_count,
                        )
                    };
                    for (i, &rgba) in src_pixels.iter().enumerate() {
                        let r = (rgba & 0xFF) as u16;
                        let g = ((rgba >> 8) & 0xFF) as u16;
                        let b = ((rgba >> 16) & 0xFF) as u16;
                        dst_u16[i] = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3);
                    }
                }
                let addr = dst_ptr as usize;
                self.write_bytes_mmio_streaming(addr, &self.scratch_u8[..pixel_count * 2]);
            }
            _ => {}
        }
        if is_last_row {
            mmio::sfence();
        }
    }

    fn calculate_image_clip(
        &self,
        image: &crate::graphics::image::Image,
        x: i32,
        y: i32,
    ) -> Option<(Rect, u32, u32)> {
        // Compute intersection between image destination rect and clip/bounds
        let dst_x0 = x.max(self.clip.x).max(0);
        let dst_y0 = y.max(self.clip.y).max(0);
        let dst_x1 = (x + image.width() as i32)
            .min(self.clip.right())
            .min(self.info.width as i32);
        let dst_y1 = (y + image.height() as i32)
            .min(self.clip.bottom())
            .min(self.info.height as i32);

        if dst_x1 <= dst_x0 || dst_y1 <= dst_y0 {
            return None;
        }

        let width = (dst_x1 - dst_x0) as u32;
        let height = (dst_y1 - dst_y0) as u32;
        let draw_rect = Rect::new(dst_x0, dst_y0, width, height);

        // Source offsets
        let src_off_x = (dst_x0 - x) as u32;
        let src_off_y = (dst_y0 - y) as u32;

        Some((draw_rect, src_off_x, src_off_y))
    }

    /// 32-bit不透明ランの描画
    fn write_opaque_run_32bit(
        &mut self,
        image: &crate::graphics::image::Image,
        src_row: u32,
        run_start: u32,
        run_len: usize,
        dst_byte_offset: usize,
        avx2_available: bool,
    ) -> bool {
        let src_base = (src_row * image.width() + run_start) as usize;
        let imgdata = image.data();
        let mut mmio_written = false;

        // If backbuffer (fixed u32/BGRA) is active, use SIMD packer for RGBA->BGRA swizzle
        if let Some(ref mut back) = self.back_buffer {
            let src_offset = src_base * 4;
            let byte_len = run_len * 4;
            // Ensure bounds
            if src_offset + byte_len <= imgdata.len() {
                let src_slice = &imgdata[src_offset..src_offset + byte_len];
                let dst_slice = unsafe {
                    core::slice::from_raw_parts_mut(
                        (back.as_mut_ptr() as *mut u8).add(dst_byte_offset),
                        byte_len,
                    )
                };
                // SIMD-accelerated RGBA→BGRA (AVX2/SSSE3/scalar auto-dispatch)
                crate::graphics::packer::pack_rgba_to_bgra(src_slice, dst_slice);
            }
            return false;
        }

        // Allow tuning... (omitted for brevity, keep existing logic if possible, or just copy-paste)
        /* ... keeping variable declarations ... */
        #[cfg(feature = "std")]
        let stream_threshold_pixels: usize = std::env::var("RANY_STREAM_THRESHOLD_PIXELS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(2048);
        #[cfg(not(feature = "std"))]
        let stream_threshold_pixels: usize = 2048;

        if self.info.format == PixelFormat::Rgba8888 {
            let byte_len = run_len * 4;
            let src_slice = &imgdata[src_base * 4..src_base * 4 + byte_len];

            let addr = self.buffer as usize + dst_byte_offset;
            self.write_bytes_mmio_streaming(addr, src_slice);
            // mmio::sfence(); // DEFERRED
            mmio_written = true;
        } else if self.info.format == PixelFormat::Bgra8888 {
            let src_slice = &imgdata[src_base * 4..src_base * 4 + run_len * 4];

            if avx2_available && run_len >= stream_threshold_pixels {
                let addr = self.buffer as usize + dst_byte_offset;
                self.write_rgba_packed_to_mmio_stream(addr, src_slice);
                // return; // DEFERRED
                return true;
            }

            self.ensure_scratch_u32(run_len);
            let dst_bytes = unsafe {
                core::slice::from_raw_parts_mut(
                    self.scratch_u32.as_mut_ptr() as *mut u8,
                    run_len * 4,
                )
            };
            Self::pack_rgba_to_bgra(src_slice, dst_bytes);
            let addr = self.buffer as usize + dst_byte_offset;
            self.write_u32_slice_mmio(addr, &self.scratch_u32[..run_len]);
            mmio_written = true; // Volatile writes technically don't need sfence but we signal activity
        }
        mmio_written
    }

    /// 24-bitチャンクサイズ選択
    fn choose_chunk_24_pixels(run_len: usize) -> usize {
        if run_len >= 8192 {
            4096
        } else if run_len >= 2048 {
            1024
        } else {
            512
        }
    }

    /// scratchバッファからバック/MMIOへチャンク書き込み
    fn flush_scratch_24bit(&mut self, run_len: usize, dst_byte_offset: usize) {
        // Tunable chunk size for 24-bit writes
        #[cfg(feature = "std")]
        let chunk_24_pixels: usize = std::env::var("RANY_CHUNK_24_PIXELS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or_else(|| Self::choose_chunk_24_pixels(run_len));
        #[cfg(not(feature = "std"))]
        let chunk_24_pixels: usize = Self::choose_chunk_24_pixels(run_len);

        let mut processed = 0usize;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while processed < run_len {
            let chunk = core::cmp::min(chunk_24_pixels, run_len - processed);
            let chunk_bytes = chunk * 3;
            let start = processed * 3;
            let end = start + chunk_bytes;
            if let Some(ref mut back) = self.back_buffer {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        self.scratch_u8.as_ptr().add(start),
                        (back.as_mut_ptr() as *mut u8).add(dst_byte_offset + start),
                        chunk_bytes,
                    );
                }
            } else {
                let addr = self.buffer as usize + dst_byte_offset + start;
                self.write_bytes_mmio_streaming(addr, &self.scratch_u8[start..end]);
            }
            processed += chunk;
        }
    }

    /// 16-bit (RGB565) 不透明ランの描画
    fn write_opaque_run_16bit(
        &mut self,
        image: &crate::graphics::image::Image,
        src_row: u32,
        run_start: u32,
        run_len: usize,
        dst_byte_offset: usize,
        _x: i32,
        _dst_row: i32,
    ) -> bool {
        let src_base = (src_row * image.width() + run_start) as usize;
        let imgdata = image.data();

        // Backbuffer is always u32/BGRA — 16bpp write_run should not reach here
        // with backbuffer active; handled by the 4bpp (backbuffer) path.
        if self.back_buffer.is_some() {
            debug_assert!(false, "16bpp write_run called on u32 backbuffer");
            return false;
        }

        // Convert RGBA pixels to RGB565 and stream-write
        let addr = self.buffer as usize + dst_byte_offset;
        // Use scratch_u8 as u16 buffer to batch the conversion
        let byte_len = run_len * 2;
        self.ensure_scratch_u8(byte_len);
        {
            let dst_u16 = unsafe {
                core::slice::from_raw_parts_mut(self.scratch_u8.as_mut_ptr() as *mut u16, run_len)
            };
            for i in 0..run_len {
                let idx = (src_base + i) * 4;
                let r = imgdata[idx] as u16;
                let g = imgdata[idx + 1] as u16;
                let b = imgdata[idx + 2] as u16;
                dst_u16[i] = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3);
            }
        }
        self.write_bytes_mmio_streaming(addr, &self.scratch_u8[..byte_len]);
        true
    }

    /// 24-bit不透明ランの描画
    fn write_opaque_run_24bit(
        &mut self,
        image: &crate::graphics::image::Image,
        src_row: u32,
        run_start: u32,
        run_len: usize,
        dst_byte_offset: usize,
        x: i32,
        dst_row: i32,
        _avx2_available: bool,
    ) -> bool {
        let total_bytes = run_len * 3;
        self.ensure_scratch_u8(total_bytes);
        let src_base = (src_row * image.width() + run_start) as usize;
        let imgdata = image.data();
        let mut handled_in_scratch = false;

        // let mut i = 0usize;
        // let mut src_idx = src_base * 4;
        // let mut dst_off = 0usize;

        match self.info.format {
            PixelFormat::Bgr888 | PixelFormat::Rgb888 => {
                handled_in_scratch = true;
                let is_bgr = matches!(self.info.format, PixelFormat::Bgr888);

                // Pack directly into scratch buffer using optimized dispatcher
                let src_slice = unsafe {
                    core::slice::from_raw_parts(imgdata.as_ptr().add(src_base * 4), run_len * 4)
                };
                let dst_slice = unsafe {
                    core::slice::from_raw_parts_mut(self.scratch_u8.as_mut_ptr(), run_len * 3)
                };

                Self::pack_rgba_to_bgr24(src_slice, dst_slice, is_bgr);
            }
            _ => {
                // Fallback — use raw writes since caller has already marked dirty
                for j in 0..run_len {
                    let idx2 = (src_base + j) * 4;
                    let c = Color::with_alpha(
                        imgdata[idx2],
                        imgdata[idx2 + 1],
                        imgdata[idx2 + 2],
                        imgdata[idx2 + 3],
                    );
                    self.set_pixel_raw(x + (run_start as i32 + j as i32), dst_row, c);
                }
            }
        }

        if handled_in_scratch {
            self.flush_scratch_24bit(run_len, dst_byte_offset);
            // Ensure streaming stores are globally visible after the full run
            if self.back_buffer.is_none() {
                // mmio::sfence(); // DEFERRED
                return true;
            }
        }
        false
    }

    /// ピクセルをブレンドして描画
    pub fn blend_pixel(&mut self, x: i32, y: i32, color: Color) {
        if color.alpha == 255 {
            self.set_pixel(x, y, color);
            return;
        }
        if color.alpha == 0 {
            return;
        }

        if let Some(ref _back) = self.back_buffer {
            if !self.clip.contains(Point::new(x, y)) {
                return;
            }
            // Use get_pixel to retrieve background color seamlessly from backbuffer (asserts checks etc)
            let bg = self.get_pixel(x as u32, y as u32);
            let result = color.blend(bg);
            self.set_pixel(x, y, result);
        } else {
            // Fallback for MMIO: just overwrite (no readback)
            self.set_pixel(x, y, color);
        }
    }

    /// 透明ピクセルをスキップし、アルファ>0のピクセルはブレンド描画する
    fn skip_transparent_pixels(
        &mut self,
        image: &crate::graphics::image::Image,
        src_row: u32,
        col: &mut u32,
        row_end: u32,
        x: i32,
        dst_row: i32,
        img_ptr: *const u8,
    ) {
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while *col < row_end {
            let idx = ((src_row * image.width() + *col) * 4) as usize;
            let alpha = unsafe { *img_ptr.add(idx + 3) };
            if alpha == 255 {
                break;
            }
            if alpha > 0 {
                let c = image.get_pixel(*col, src_row);
                self.blend_pixel(x + *col as i32, dst_row, c);
            }
            *col += 1;
        }
    }

    /// 不透明ピクセルの連続走査長を検出
    fn find_opaque_run_len(
        image: &crate::graphics::image::Image,
        src_row: u32,
        col: &mut u32,
        row_end: u32,
        img_ptr: *const u8,
    ) -> usize {
        let run_start = *col;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while *col < row_end {
            let idx = ((src_row * image.width() + *col) * 4) as usize;
            let alpha = unsafe { *img_ptr.add(idx + 3) };
            if alpha != 255 {
                break;
            }
            *col += 1;
        }
        (*col - run_start) as usize
    }

    /// 不透明ランをフレームバッファに書き込む
    fn write_run(
        &mut self,
        image: &crate::graphics::image::Image,
        src_row: u32,
        run_start: u32,
        run_len: usize,
        dst_byte_offset: usize,
        bytes_per_pixel: usize,
        x: i32,
        dst_row: i32,
        avx2_available: bool,
    ) -> bool {
        match bytes_per_pixel {
            4 => self.write_opaque_run_32bit(
                image,
                src_row,
                run_start,
                run_len,
                dst_byte_offset,
                avx2_available,
            ),
            3 => self.write_opaque_run_24bit(
                image,
                src_row,
                run_start,
                run_len,
                dst_byte_offset,
                x,
                dst_row,
                avx2_available,
            ),
            2 => self.write_opaque_run_16bit(
                image,
                src_row,
                run_start,
                run_len,
                dst_byte_offset,
                x,
                dst_row,
            ),
            _ => {
                for i in 0..run_len {
                    let c = image.get_pixel(run_start + i as u32, src_row);
                    self.set_pixel(x + (run_start as i32 + i as i32), dst_row, c);
                }
                self.back_buffer.is_none()
            }
        }
    }

    /// 画像描画用のスキャンライン処理
    fn draw_image_scanline(
        &mut self,
        image: &crate::graphics::image::Image,
        src_row: u32,
        dst_row: i32,
        row_start: u32,
        row_end: u32,
        x: i32,
        avx2_available: bool,
    ) -> bool {
        let mut mmio_written = false;
        let (bytes_per_pixel, stride) = if self.back_buffer.is_some() {
            (4, (self.info.width * 4) as u32)
        } else {
            (self.info.format.bytes_per_pixel(), self.info.stride)
        };

        let dst_row_offset = (dst_row as u32 * stride) as usize;
        let mut col = row_start;
        let img_ptr = image.data().as_ptr();

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while col < row_end {
            self.skip_transparent_pixels(image, src_row, &mut col, row_end, x, dst_row, img_ptr);

            let run_start = col;
            let run_len = Self::find_opaque_run_len(image, src_row, &mut col, row_end, img_ptr);
            if run_len == 0 {
                continue;
            }

            let abs_x = (x + run_start as i32) as usize;
            let dst_byte_offset = dst_row_offset + abs_x * bytes_per_pixel;

            if self.write_run(
                image,
                src_row,
                run_start,
                run_len,
                dst_byte_offset,
                bytes_per_pixel,
                x,
                dst_row,
                avx2_available,
            ) {
                mmio_written = true;
            }
        }
        mmio_written
    }

    /// helper: detect AVX2 availability (used by draw_image)
    fn get_avx2_available() -> bool {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            #[cfg(feature = "std")]
            {
                std::is_x86_feature_detected!("avx2")
            }
            #[cfg(not(feature = "std"))]
            {
                hal::mmio::get_simd_level() >= hal::mmio::simd_level::AVX2
            }
        }
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        {
            false
        }
    }
}
