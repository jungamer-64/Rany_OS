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
            self.info.width() * 4
        } else {
            self.info.stride()
        } as usize;
        let dst_bpp = if self.back_buffer.is_some() {
            4
        } else {
            self.info.format().bytes_per_pixel()
        } as usize;

        let width = r_w as usize;
        let needs_swizzle = matches!(
            self.info.format(),
            PixelFormat::Bgra8888 | PixelFormat::Bgr888
        );
        // LOOP_PROOF: mode=bounded; reason=The clipped image rectangle has a finite row count.;
        for row in 0..r_h as usize {
            let source_offset = (r_y as usize + row) * src_stride as usize + r_x as usize * 4;
            let source = &src_data[source_offset..source_offset + width * 4];
            let destination = (d_y as usize + row) * dst_stride + d_x as usize * dst_bpp;
            if let Some(back) = self.back_buffer.as_mut() {
                let first = destination / 4;
                // LOOP_PROOF: mode=bounded; reason=Each source row has exactly width initialized RGBA pixels.;
                for (rgba, pixel) in source
                    .chunks_exact(4)
                    .zip(back[first..first + width].iter_mut())
                {
                    *pixel = Color::with_alpha(rgba[0], rgba[1], rgba[2], rgba[3]).to_u32();
                }
                continue;
            }
            let output = &mut self.scratch_u8[..width * dst_bpp];
            match self.info.format() {
                PixelFormat::Bgra8888 => crate::graphics::packer::pack_rgba_to_bgra(source, output),
                PixelFormat::Rgba8888 => output.copy_from_slice(source),
                PixelFormat::Bgr888 | PixelFormat::Rgb888 => {
                    crate::graphics::packer::pack_rgba_to_bgr24(source, output, needs_swizzle)
                }
                PixelFormat::Rgb565 => {
                    // LOOP_PROOF: mode=bounded; reason=Each complete RGBA pixel produces one complete two byte output pixel.;
                    for (rgba, bytes) in source.chunks_exact(4).zip(output.chunks_exact_mut(2)) {
                        bytes.copy_from_slice(
                            &Self::color_to_rgb565(Color::new(rgba[0], rgba[1], rgba[2]))
                                .to_le_bytes(),
                        );
                    }
                }
            }
            self.pixels.write(destination, output);
        }
        mmio::sfence();
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
