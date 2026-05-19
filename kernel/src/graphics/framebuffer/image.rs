// ============================================================================
// kernel/src/graphics/framebuffer/image.rs
// ============================================================================
//! Image drawing and blitting operations for the Framebuffer.
//!
//! This module contains methods for drawing images (or parts of images) onto
//! the framebuffer, including clipping, alpha-blending, scanline-based opaque
//! run detection, and format-specific pixel packing (32-bit, 24-bit, 16-bit).

use super::*;
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
}
