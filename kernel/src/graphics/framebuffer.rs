// ============================================================================
// src/graphics/framebuffer.rs - Framebuffer Implementation
// ============================================================================
//!
//! フレームバッファ描画実装
//!
//! ピクセル描画、図形描画、テキスト描画などのフレームバッファ操作

#![allow(dead_code)]

#[cfg(not(test))]
extern crate alloc;

#[cfg(not(test))]
use alloc::vec::Vec;
#[cfg(not(test))]
use alloc::vec;

#[cfg(test)]
use std::vec::Vec;

use hal::mmio as mmio;
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
    /// 再利用用スクラッチバッファ（バイト列）
    scratch_u8: Vec<u8>,
    /// 再利用用スクラッチバッファ（32-bit単位）
    scratch_u32: Vec<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graphics::image::Image;

    #[test]
    fn test_draw_image_32bit_bgra_backbuffer() {
        let width = 4u32;
        let height = 4u32;
        let info = FramebufferInfo {
            address: 0,
            width,
            height,
            stride: width * 4,
            format: PixelFormat::Bgra8888,
            bpp: 32,
        };

        let mut fb = unsafe { Framebuffer::new(info.clone()) };
        let mut back = vec![0u8; info.size()];
        fb.enable_double_buffering_from_vec(back);

        let img = Image::filled(width, height, Color::with_alpha(10, 20, 30, 255));
        fb.draw_image(&img, 0, 0);

        // Check that back buffer contains BGRA bytes per pixel
        let back_ref = fb.back_buffer.as_ref().unwrap();
        for i in (0..back_ref.len()).step_by(4) {
            assert_eq!(back_ref[i], 30); // blue
            assert_eq!(back_ref[i + 1], 20); // green
            assert_eq!(back_ref[i + 2], 10); // red
            assert_eq!(back_ref[i + 3], 255); // alpha
        }
    }

    #[test]
    fn test_draw_image_24bit_bgr_backbuffer() {
        let width = 3u32;
        let height = 2u32;
        let info = FramebufferInfo {
            address: 0,
            width,
            height,
            stride: width * 3,
            format: PixelFormat::Bgr888,
            bpp: 24,
        };

        let mut fb = unsafe { Framebuffer::new(info.clone()) };
        let mut back = vec![0u8; info.size()];
        fb.enable_double_buffering_from_vec(back);

        let img = Image::filled(width, height, Color::with_alpha(255, 0, 0, 255));
        fb.draw_image(&img, 0, 0);

        let back_ref = fb.back_buffer.as_ref().unwrap();
        for i in (0..back_ref.len()).step_by(3) {
            assert_eq!(back_ref[i], 0); // blue
            assert_eq!(back_ref[i + 1], 0); // green
            assert_eq!(back_ref[i + 2], 255); // red
        }
    }

    #[test]
    #[ignore]
    fn bench_draw_image_bulk() {
        use std::time::Instant;
        let width = 800u32;
        let height = 600u32;
        let info = FramebufferInfo {
            address: 0,
            width,
            height,
            stride: width * 4,
            format: PixelFormat::Bgra8888,
            bpp: 32,
        };

        let mut fb = unsafe { Framebuffer::new(info.clone()) };
        let back = vec![0u8; info.size()];
        fb.enable_double_buffering_from_vec(back);

        let img = Image::filled(width, height, Color::with_alpha(64, 128, 192, 255));

        let start = Instant::now();
        for _ in 0..10 {
            fb.draw_image(&img, 0, 0);
        }
        let elapsed = start.elapsed();
        log::info!("bench_draw_image_bulk: {:?}", elapsed);
    }

    #[test]
    #[ignore]
    fn bench_draw_image_24bit_bulk() {
        use std::time::Instant;
        let width = 800u32;
        let height = 600u32;
        let info = FramebufferInfo {
            address: 0,
            width,
            height,
            stride: width * 3,
            format: PixelFormat::Bgr888,
            bpp: 24,
        };

        let mut fb = unsafe { Framebuffer::new(info.clone()) };
        let back = vec![0u8; info.size()];
        fb.enable_double_buffering_from_vec(back);

        let img = Image::filled(width, height, Color::with_alpha(64, 128, 192, 255));

        let start = Instant::now();
        for _ in 0..10 {
            fb.draw_image(&img, 0, 0);
        }
        let elapsed = start.elapsed();
        log::info!("bench_draw_image_24bit_bulk: {:?}", elapsed);
    }

    #[test]
    #[ignore]
    fn bench_draw_image_rgba_bulk() {
        use std::time::Instant;
        let width = 800u32;
        let height = 600u32;
        let info = FramebufferInfo {
            address: 0,
            width,
            height,
            stride: width * 4,
            format: PixelFormat::Rgba8888,
            bpp: 32,
        };

        let mut fb = unsafe { Framebuffer::new(info.clone()) };
        let back = vec![0u8; info.size()];
        fb.enable_double_buffering_from_vec(back);

        let img = Image::filled(width, height, Color::with_alpha(64, 128, 192, 255));

        let start = Instant::now();
        for _ in 0..10 {
            fb.draw_image(&img, 0, 0);
        }
        let elapsed = start.elapsed();
        log::info!("bench_draw_image_rgba_bulk: {:?}", elapsed);
    }

    #[test]
    #[ignore]
    fn bench_draw_hline_bulk() {
        use std::time::Instant;
        let width = 1920u32;
        let height = 1080u32;
        let info = FramebufferInfo {
            address: 0,
            width,
            height,
            stride: width * 4,
            format: PixelFormat::Bgra8888,
            bpp: 32,
        };

        let mut fb = unsafe { Framebuffer::new(info.clone()) };
        let back = vec![0u8; info.size()];
        fb.enable_double_buffering_from_vec(back);

        let start = Instant::now();
        for y in 0..height {
            fb.draw_hline(0, width as i32 - 1, y as i32, Color::with_alpha(10, 20, 30, 255));
        }
        let elapsed = start.elapsed();
        log::info!("bench_draw_hline_bulk: {:?}", elapsed);
    }

    #[test]
    #[ignore]
    fn bench_draw_text_bulk() {
        use std::time::Instant;
        let width = 800u32;
        let height = 600u32;
        let info = FramebufferInfo {
            address: 0,
            width,
            height,
            stride: width * 4,
            format: PixelFormat::Bgra8888,
            bpp: 32,
        };

        let mut fb = unsafe { Framebuffer::new(info.clone()) };
        let back = vec![0u8; info.size()];
        fb.enable_double_buffering_from_vec(back);

        let start = Instant::now();
        for _ in 0..50 {
            fb.draw_text(0, 0, "The quick brown fox jumps over the lazy dog", Color::with_alpha(1, 2, 3, 255), Color::with_alpha(100, 110, 120, 255));
        }
        let elapsed = start.elapsed();
        log::info!("bench_draw_text_bulk: {:?}", elapsed);
    }

    #[test]
    fn test_draw_hline_32bit_backbuffer() {
        let width = 10u32;
        let height = 3u32;
        let info = FramebufferInfo {
            address: 0,
            width,
            height,
            stride: width * 4,
            format: PixelFormat::Bgra8888,
            bpp: 32,
        };

        let mut fb = unsafe { Framebuffer::new(info.clone()) };
        let mut back = vec![0u8; info.size()];
        fb.enable_double_buffering_from_vec(back);

        let color = Color::with_alpha(10, 20, 30, 255);
        fb.draw_hline(1, 8, 1, color);

        let back_ref = fb.back_buffer.as_ref().unwrap();
        let stride = info.stride as usize;
        for x in 1..=8 {
            let off = (1usize * stride) + x as usize * 4;
            assert_eq!(back_ref[off], 30);
            assert_eq!(back_ref[off + 1], 20);
            assert_eq!(back_ref[off + 2], 10);
            assert_eq!(back_ref[off + 3], 255);
        }
    }

    #[test]
    fn test_draw_vline_32bit_backbuffer() {
        let width = 3u32;
        let height = 6u32;
        let info = FramebufferInfo {
            address: 0,
            width,
            height,
            stride: width * 4,
            format: PixelFormat::Bgra8888,
            bpp: 32,
        };

        let mut fb = unsafe { Framebuffer::new(info.clone()) };
        let mut back = vec![0u8; info.size()];
        fb.enable_double_buffering_from_vec(back);

        let color = Color::with_alpha(1, 2, 3, 255);
        fb.draw_vline(1, 0, 5, color);

        let back_ref = fb.back_buffer.as_ref().unwrap();
        let stride = info.stride as usize;
        for y in 0..6 {
            let off = (y as usize * stride) + 1usize * 4;
            assert_eq!(back_ref[off], 3);
            assert_eq!(back_ref[off + 1], 2);
            assert_eq!(back_ref[off + 2], 1);
            assert_eq!(back_ref[off + 3], 255);
        }
    }

    #[test]
    fn test_draw_text_space_32bit_backbuffer() {
        let width = 16u32;
        let height = 16u32;
        let info = FramebufferInfo {
            address: 0,
            width,
            height,
            stride: width * 4,
            format: PixelFormat::Bgra8888,
            bpp: 32,
        };

        let mut fb = unsafe { Framebuffer::new(info.clone()) };
        let mut back = vec![0u8; info.size()];
        fb.enable_double_buffering_from_vec(back);

        let fg = Color::with_alpha(1, 2, 3, 255);
        let bg = Color::with_alpha(100, 110, 120, 255);

        fb.draw_text(0, 0, " ", fg, bg);

        let back_ref = fb.back_buffer.as_ref().unwrap();
        let stride = info.stride as usize;
        // Space glyph is blank; entire 8x16 area should be background
        for y in 0..16 {
            for x in 0..8 {
                let off = (y as usize * stride) + (x as usize * 4);
                assert_eq!(back_ref[off], 120);
                assert_eq!(back_ref[off + 1], 110);
                assert_eq!(back_ref[off + 2], 100);
                assert_eq!(back_ref[off + 3], 255);
            }
        }
    }

    #[test]
    fn test_draw_line_matches_naive_32bit_backbuffer() {
        let width = 16u32;
        let height = 16u32;
        let info = FramebufferInfo {
            address: 0,
            width,
            height,
            stride: width * 4,
            format: PixelFormat::Bgra8888,
            bpp: 32,
        };

        let mut fb_opt = unsafe { Framebuffer::new(info.clone()) };
        let mut fb_naive = unsafe { Framebuffer::new(info.clone()) };
        let back = vec![0u8; info.size()];
        fb_opt.enable_double_buffering_from_vec(back.clone());
        fb_naive.enable_double_buffering_from_vec(back);

        let color = Color::with_alpha(10, 20, 30, 255);

        // Test various line endpoints
        let cases = [
            (0, 0, 15, 3),
            (0, 0, 3, 15),
            (15, 0, 0, 15),
            (2, 14, 13, 4),
            (7, 0, 7, 15), // vertical
            (0, 8, 15, 8), // horizontal
        ];

        for (x1, y1, x2, y2) in cases.iter() {
            // draw with optimized method
            fb_opt.draw_line(*x1, *y1, *x2, *y2, color);

            // draw with naive per-pixel method
            let mut x = *x1;
            let mut y = *y1;
            let dx = (*x2 - *x1).abs();
            let dy = -(*y2 - *y1).abs();
            let sx = if *x1 < *x2 { 1 } else { -1 };
            let sy = if *y1 < *y2 { 1 } else { -1 };
            let mut err = dx + dy;

            loop {
                fb_naive.set_pixel(x, y, color);
                if x == *x2 && y == *y2 {
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

            // Compare back buffers
            let buf_opt = fb_opt.back_buffer.as_ref().unwrap();
            let buf_naive = fb_naive.back_buffer.as_ref().unwrap();
            assert_eq!(buf_opt.len(), buf_naive.len());
            assert_eq!(buf_opt, buf_naive);

            // clear buffers for next case
            for b in fb_opt.back_buffer.as_mut().unwrap().iter_mut() {
                *b = 0;
            }
            for b in fb_naive.back_buffer.as_mut().unwrap().iter_mut() {
                *b = 0;
            }
        }
    }

    #[test]
    fn test_draw_line_matches_naive_24bit_backbuffer() {
        let width = 16u32;
        let height = 16u32;
        let info = FramebufferInfo {
            address: 0,
            width,
            height,
            stride: width * 3,
            format: PixelFormat::Bgr888,
            bpp: 24,
        };

        let mut fb_opt = unsafe { Framebuffer::new(info.clone()) };
        let mut fb_naive = unsafe { Framebuffer::new(info.clone()) };
        let back = vec![0u8; info.size()];
        fb_opt.enable_double_buffering_from_vec(back.clone());
        fb_naive.enable_double_buffering_from_vec(back);

        let color = Color::with_alpha(11, 22, 33, 255);

        let cases = [
            (0, 0, 15, 3),
            (0, 0, 3, 15),
            (15, 0, 0, 15),
            (2, 14, 13, 4),
        ];

        for (x1, y1, x2, y2) in cases.iter() {
            fb_opt.draw_line(*x1, *y1, *x2, *y2, color);

            // naive
            let mut x = *x1;
            let mut y = *y1;
            let dx = (*x2 - *x1).abs();
            let dy = -(*y2 - *y1).abs();
            let sx = if *x1 < *x2 { 1 } else { -1 };
            let sy = if *y1 < *y2 { 1 } else { -1 };
            let mut err = dx + dy;

            loop {
                fb_naive.set_pixel(x, y, color);
                if x == *x2 && y == *y2 {
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

            let buf_opt = fb_opt.back_buffer.as_ref().unwrap();
            let buf_naive = fb_naive.back_buffer.as_ref().unwrap();
            assert_eq!(buf_opt.len(), buf_naive.len());
            assert_eq!(buf_opt, buf_naive);

            for b in fb_opt.back_buffer.as_mut().unwrap().iter_mut() {
                *b = 0;
            }
            for b in fb_naive.back_buffer.as_mut().unwrap().iter_mut() {
                *b = 0;
            }
        }
    }

    #[test]
    fn test_draw_text_space_24bit_backbuffer() {
        let width = 16u32;
        let height = 16u32;
        let info = FramebufferInfo {
            address: 0,
            width,
            height,
            stride: width * 3,
            format: PixelFormat::Bgr888,
            bpp: 24,
        };

        let mut fb = unsafe { Framebuffer::new(info.clone()) };
        let mut back = vec![0u8; info.size()];
        fb.enable_double_buffering_from_vec(back);

        let fg = Color::with_alpha(1, 2, 3, 255);
        let bg = Color::with_alpha(100, 110, 120, 255);

        fb.draw_text(0, 0, " ", fg, bg);

        let back_ref = fb.back_buffer.as_ref().unwrap();
        let stride = info.stride as usize;
        // Space glyph is blank; entire 8x16 area should be background
        for y in 0..16 {
            for x in 0..8 {
                let off = (y as usize * stride) + (x as usize * 3);
                assert_eq!(back_ref[off], 120);
                assert_eq!(back_ref[off + 1], 110);
                assert_eq!(back_ref[off + 2], 100);
            }
        }
    }

    #[test]
    fn test_draw_image_32bit_mmio() {
        let width = 4u32;
        let height = 4u32;
        let info = FramebufferInfo {
            address: 0,
            width,
            height,
            stride: width * 4,
            format: PixelFormat::Bgra8888,
            bpp: 32,
        };

        let mut mem = vec![0u8; info.size()];
        let addr = mem.as_mut_ptr() as u64;
        let mut info2 = info.clone();
        info2.address = addr;

        let mut fb = unsafe { Framebuffer::new(info2) };

        let img = Image::filled(width, height, Color::with_alpha(10, 20, 30, 255));
        fb.draw_image(&img, 0, 0);

        for i in (0..mem.len()).step_by(4) {
            assert_eq!(mem[i], 30);
            assert_eq!(mem[i + 1], 20);
            assert_eq!(mem[i + 2], 10);
            assert_eq!(mem[i + 3], 255);
        }
    }

    #[test]
    fn test_draw_image_24bit_mmio() {
        let width = 3u32;
        let height = 2u32;
        let info = FramebufferInfo {
            address: 0,
            width,
            height,
            stride: width * 3,
            format: PixelFormat::Bgr888,
            bpp: 24,
        };

        let mut mem = vec![0u8; info.size()];
        let addr = mem.as_mut_ptr() as u64;
        let mut info2 = info.clone();
        info2.address = addr;

        let mut fb = unsafe { Framebuffer::new(info2) };

        let img = Image::filled(width, height, Color::with_alpha(255, 0, 0, 255));
        fb.draw_image(&img, 0, 0);

        for i in (0..mem.len()).step_by(3) {
            assert_eq!(mem[i], 0);
            assert_eq!(mem[i + 1], 0);
            assert_eq!(mem[i + 2], 255);
        }
    }

    #[test]
    fn test_draw_image_32bit_mmio_rgba() {
        let width = 4u32;
        let height = 4u32;
        let info = FramebufferInfo {
            address: 0,
            width,
            height,
            stride: width * 4,
            format: PixelFormat::Rgba8888,
            bpp: 32,
        };

        let mut mem = vec![0u8; info.size()];
        let addr = mem.as_mut_ptr() as u64;
        let mut info2 = info.clone();
        info2.address = addr;

        let mut fb = unsafe { Framebuffer::new(info2) };

        let img = Image::filled(width, height, Color::with_alpha(10, 20, 30, 255));
        fb.draw_image(&img, 0, 0);

        for i in (0..mem.len()).step_by(4) {
            assert_eq!(mem[i], 10);
            assert_eq!(mem[i + 1], 20);
            assert_eq!(mem[i + 2], 30);
            assert_eq!(mem[i + 3], 255);
        }
    }

    #[test]
    fn test_write_bytes_mmio_alignment() {
        // Ensure write_bytes_mmio uses u64 writes when destination is 8-byte aligned
        let width = 8u32;
        let height = 1u32;
        let info = FramebufferInfo {
            address: 0,
            width,
            height,
            stride: width * 3,
            format: PixelFormat::Bgr888,
            bpp: 24,
        };

        // Add padding to be able to adjust base pointer alignment
        let mut mem = vec![0u8; info.size() + 16];
        let base = mem.as_mut_ptr() as usize;

        // Find an offset that yields 8-byte alignment
        let mut offset = None;
        for off in 0..8usize {
            if ((base + off) & 7) == 0 {
                offset = Some(off);
                break;
            }
        }
        let offset = offset.expect("couldn't find alignment offset");

        let addr = (base + offset) as u64;
        let mut info2 = info.clone();
        info2.address = addr;
        let mut fb = unsafe { Framebuffer::new(info2) };

        // Write three pixels (9 bytes) so we exercise u64 + tail byte
        fb.write_bgr_run(0, 3, Color::with_alpha(1, 2, 3, 255));

        // Verify bytes
        let start = offset;
        assert_eq!(mem[start], 3); // b
        assert_eq!(mem[start + 1], 2);
        assert_eq!(mem[start + 2], 1);
        assert_eq!(mem[start + 3], 3);
        assert_eq!(mem[start + 4], 2);
        assert_eq!(mem[start + 5], 1);
        assert_eq!(mem[start + 6], 3);
        assert_eq!(mem[start + 7], 2);
        assert_eq!(mem[start + 8], 1);
    }

    #[test]
    fn test_write_bgr_run_large() {
        // Ensure large runs of a single color are written correctly
        let width = 1024u32;
        let height = 1u32;
        let info = FramebufferInfo {
            address: 0,
            width,
            height,
            stride: width * 3,
            format: PixelFormat::Bgr888,
            bpp: 24,
        };

        let mut mem = vec![0u8; info.size()];
        let addr = mem.as_mut_ptr() as u64;
        let mut info2 = info.clone();
        info2.address = addr;

        let mut fb = unsafe { Framebuffer::new(info2) };

        fb.write_bgr_run(0, width as usize, Color::with_alpha(5, 6, 7, 255));

        for x in 0..(width as usize) {
            let off = x * 3;
            assert_eq!(mem[off], 7); // b
            assert_eq!(mem[off + 1], 6); // g
            assert_eq!(mem[off + 2], 5); // r
        }
    }

    #[test]
    fn test_pack_rgba_to_bgra_basic() {
        // Build a simple RGBA pattern and verify BGRA result matches expected
        let mut src = Vec::new();
        for i in 0..32 {
            // r,g,b,a = i, i+1, i+2, 255
            src.push(i as u8);
            src.push((i + 1) as u8);
            src.push((i + 2) as u8);
            src.push(255u8);
        }

        let mut dst = vec![0u8; src.len()];
        Framebuffer::pack_rgba_to_bgra(&src, &mut dst);

        for i in 0..(src.len() / 4) {
            let s = i * 4;
            assert_eq!(dst[s], src[s + 2]);
            assert_eq!(dst[s + 1], src[s + 1]);
            assert_eq!(dst[s + 2], src[s + 0]);
            assert_eq!(dst[s + 3], src[s + 3]);
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_pack_rgba_to_bgra_ssse3_matches_scalar() {
        // Only run the detailed SSSE3 check when the feature is available
        if !std::is_x86_feature_detected!("ssse3") {
            return;
        }

        // Test multiple sizes including non-16 multiples to exercise tail path
        for len in [4usize, 12, 16, 20, 48, 64, 100].iter() {
            let mut src = vec![0u8; *len * 4];
            for i in 0..(src.len()) {
                src[i] = (i * 37 % 251) as u8;
            }
            let mut dst_simd = vec![0u8; src.len()];
            let mut dst_scalar = vec![0u8; src.len()];

            unsafe { Framebuffer::pack_rgba_to_bgra_ssse3(src.as_ptr(), dst_simd.as_mut_ptr(), src.len()); }
            Framebuffer::pack_rgba_to_bgra(&src, &mut dst_scalar);

            assert_eq!(dst_simd, dst_scalar);
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_pack_rgba_to_bgra_avx2_matches_scalar() {
        // Only run AVX2 check when available
        if !std::is_x86_feature_detected!("avx2") {
            return;
        }

        for len in [4usize, 12, 16, 20, 48, 64, 100].iter() {
            let mut src = vec![0u8; *len * 4];
            for i in 0..(src.len()) {
                src[i] = (i * 97 % 251) as u8;
            }
            let mut dst_avx = vec![0u8; src.len()];
            let mut dst_scalar = vec![0u8; src.len()];

            unsafe { Framebuffer::pack_rgba_to_bgra_avx2(src.as_ptr(), dst_avx.as_mut_ptr(), src.len()); }
            Framebuffer::pack_rgba_to_bgra_scalar(&src, &mut dst_scalar);

            assert_eq!(dst_avx, dst_scalar);
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_pack_rgba_to_bgra_neon_matches_scalar() {
        // Only run NEON check when available (bench/test builds)
        if !std::is_aarch64_feature_detected!("neon") {
            return;
        }

        for len in [4usize, 12, 16, 20, 48, 64, 100].iter() {
            let mut src = vec![0u8; *len * 4];
            for i in 0..(src.len()) {
                src[i] = (i * 61 % 251) as u8;
            }
            let mut dst_neon = vec![0u8; src.len()];
            let mut dst_scalar = vec![0u8; src.len()];

            unsafe { Framebuffer::pack_rgba_to_bgra_neon(src.as_ptr(), dst_neon.as_mut_ptr(), src.len()); }
            Framebuffer::pack_rgba_to_bgra_scalar(&src, &mut dst_scalar);

            assert_eq!(dst_neon, dst_scalar);
        }

        #[test]
        fn test_draw_image_bgra_stream_matches_backbuffer() {
            use crate::super::image::Image;

            let width = 16u32;
            let height = 4u32;
            let mut img = Image::new(width, height);

            // Fill with a pattern of opaque pixels
            for y in 0..height {
                for x in 0..width {
                    let r = ((x * 13 + y * 7) & 0xFF) as u8;
                    let g = ((x * 17 + y * 11) & 0xFF) as u8;
                    let b = ((x * 19 + y * 23) & 0xFF) as u8;
                    img.set_pixel(x, y, Color::with_alpha(r, g, b, 255));
                }
            }

            let mut info = FramebufferInfo {
                address: 0,
                width,
                height,
                stride: width * 4,
                format: PixelFormat::Bgra8888,
                bpp: 32,
            };

            // Back-buffered framebuffer
            let mut mem_back = vec![0u8; info.size()];
            info.address = mem_back.as_mut_ptr() as u64;
            let mut fb_back = unsafe { Framebuffer::new(info.clone()) };
            fb_back.enable_double_buffering();
            fb_back.draw_image(&img, 0, 0);
            fb_back.swap_buffers();

            // MMIO-path framebuffer (no back buffer)
            let mut mem_mmio = vec![0u8; info.size()];
            info.address = mem_mmio.as_mut_ptr() as u64;
            let mut fb_mmio = unsafe { Framebuffer::new(info) };
            fb_mmio.draw_image(&img, 0, 0);

            // Compare byte-by-byte
            assert_eq!(mem_back, mem_mmio);
        }
    }

    #[test]
    fn test_fill_rect_32bit_mmio() {
        let width = 8u32;
        let height = 8u32;
        let info = FramebufferInfo {
            address: 0,
            width,
            height,
            stride: width * 4,
            format: PixelFormat::Bgra8888,
            bpp: 32,
        };

        let mut mem = vec![0u8; info.size()];
        let addr = mem.as_mut_ptr() as u64;
        let mut info2 = info.clone();
        info2.address = addr;

        let mut fb = unsafe { Framebuffer::new(info2) };

        fb.fill_rect(Rect::new(1, 1, 6, 6), Color::with_alpha(1, 2, 3, 255));

        for y in 1..7 {
            for x in 1..7 {
                let off = (y as usize * info.stride as usize) + (x as usize * 4);
                assert_eq!(mem[off], 3);
                assert_eq!(mem[off + 1], 2);
                assert_eq!(mem[off + 2], 1);
                assert_eq!(mem[off + 3], 255);
            }
        }
    }
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
            scratch_u8: Vec::new(),
            scratch_u32: Vec::new(),
        }
    }

    /// Create a framebuffer from kernel_api::gui::FramebufferInfo
    ///
    /// # Safety
    /// The vaddr in kapi_info must be a valid readable/writable framebuffer address
    pub unsafe fn from_kapi_info(kapi_info: &kernel_api::gui::FramebufferInfo) -> Self {
        use kernel_api::gui::PixelFormat as KapiPixelFormat;
        
        // Convert pixel format
        let format = match kapi_info.format {
            KapiPixelFormat::Rgb32 => PixelFormat::Rgba8888,
            KapiPixelFormat::Bgr32 => PixelFormat::Bgra8888,
            KapiPixelFormat::Rgb24 => PixelFormat::Rgb888,
            KapiPixelFormat::Bgr24 => PixelFormat::Bgr888,
            KapiPixelFormat::Unknown => PixelFormat::Bgra8888, // Default fallback
        };
        
        let bpp = match format.bytes_per_pixel() {
            4 => 32,
            3 => 24,
            2 => 16,
            _ => 32,
        };
        
        let info = FramebufferInfo {
            address: kapi_info.vaddr as u64,
            width: kapi_info.width as u32,
            height: kapi_info.height as u32,
            stride: kapi_info.stride as u32,
            format,
            bpp,
        };
        
        Self::new(info)
    }

    /// Ensure scratch_u32 has at least `capacity` elements
    fn ensure_scratch_u32(&mut self, capacity: usize) {
        // Avoid frequent reallocs: grow capacity geometrically
        if self.scratch_u32.len() < capacity {
            let mut new_cap = self.scratch_u32.len().max(1);
            while new_cap < capacity {
                new_cap *= 2;
            }
            self.scratch_u32.resize(new_cap, 0);
        }
    }

    /// Ensure scratch_u8 has at least `capacity` bytes
    fn ensure_scratch_u8(&mut self, capacity: usize) {
        // Avoid frequent reallocs: grow capacity geometrically
        if self.scratch_u8.len() < capacity {
            let mut new_cap = self.scratch_u8.len().max(1);
            while new_cap < capacity {
                new_cap *= 2;
            }
            self.scratch_u8.resize(new_cap, 0);
        }
    }

    /// Write a slice of bytes to MMIO region efficiently.
    ///
    /// This will attempt to perform aligned 32-bit writes when possible to
    /// reduce the number of volatile writes. It never performs unaligned
    /// u32 writes: any leading bytes to reach 4-byte alignment are emitted
    /// as u8 writes.
    fn write_bytes_mmio(&self, addr: usize, data: &[u8]) {
        let mut ptr = addr;
        let mut i = 0usize;
        let len = data.len();

        // Align to 8-bytes boundary by writing 1..=7 initial bytes
        let align8 = ptr & 7;
        if align8 != 0 {
            let to_align = core::cmp::min(8 - align8, len);
            for _ in 0..to_align {
                mmio::volatile_write::<u8>(ptr, data[i]);
                ptr += 1;
                i += 1;
            }
        }

        // Bulk write u64 when possible. Unroll 4 u64 writes per iteration.
        while i + 32 <= len {
            let v0 = u64::from_le_bytes([
                data[i], data[i + 1], data[i + 2], data[i + 3], data[i + 4], data[i + 5],
                data[i + 6], data[i + 7],
            ]);
            let v1 = u64::from_le_bytes([
                data[i + 8], data[i + 9], data[i + 10], data[i + 11], data[i + 12], data[i + 13],
                data[i + 14], data[i + 15],
            ]);
            let v2 = u64::from_le_bytes([
                data[i + 16], data[i + 17], data[i + 18], data[i + 19], data[i + 20], data[i + 21],
                data[i + 22], data[i + 23],
            ]);
            let v3 = u64::from_le_bytes([
                data[i + 24], data[i + 25], data[i + 26], data[i + 27], data[i + 28], data[i + 29],
                data[i + 30], data[i + 31],
            ]);
            mmio::mmio_write_u64(ptr, v0);
            mmio::mmio_write_u64(ptr + 8, v1);
            mmio::mmio_write_u64(ptr + 16, v2);
            mmio::mmio_write_u64(ptr + 24, v3);
            ptr += 32;
            i += 32;
        }

        while i + 8 <= len {
            let v = u64::from_le_bytes([
                data[i], data[i + 1], data[i + 2], data[i + 3], data[i + 4], data[i + 5],
                data[i + 6], data[i + 7],
            ]);
            mmio::mmio_write_u64(ptr, v);
            ptr += 8;
            i += 8;
        }

        // Remaining u32-aligned writes; unroll 4 at a time
        while i + 16 <= len {
            let v0 = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            let v1 = u32::from_le_bytes([data[i + 4], data[i + 5], data[i + 6], data[i + 7]]);
            let v2 = u32::from_le_bytes([data[i + 8], data[i + 9], data[i + 10], data[i + 11]]);
            let v3 = u32::from_le_bytes([data[i + 12], data[i + 13], data[i + 14], data[i + 15]]);
            mmio::mmio_write_u32(ptr, v0);
            mmio::mmio_write_u32(ptr + 4, v1);
            mmio::mmio_write_u32(ptr + 8, v2);
            mmio::mmio_write_u32(ptr + 12, v3);
            ptr += 16;
            i += 16;
        }

        while i + 4 <= len {
            let v = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            mmio::mmio_write_u32(ptr, v);
            ptr += 4;
            i += 4;
        }

        // Remaining tail bytes
        while i < len {
            mmio::volatile_write::<u8>(ptr, data[i]);
            ptr += 1;
            i += 1;
        }
    }

    /// Write a slice of u32 pixels to an MMIO destination, using u64 pair writes
    /// when possible for improved throughput.
    fn write_u32_slice_mmio(&self, addr: usize, data: &[u32]) {
        let mut ptr = addr;
        let mut i = 0usize;
        let len = data.len();

        // If ptr is 4 mod 8, write a single u32 to reach 8-byte alignment
        if (ptr & 7) == 4 && i < len {
            mmio::mmio_write_u32(ptr, data[i]);
            ptr += 4;
            i += 1;
        }

        // Write u64 pairs; unroll 4 pairs at a time for throughput.
        while i + 7 < len {
            let p0 = (data[i] as u64) | ((data[i + 1] as u64) << 32);
            let p1 = (data[i + 2] as u64) | ((data[i + 3] as u64) << 32);
            let p2 = (data[i + 4] as u64) | ((data[i + 5] as u64) << 32);
            let p3 = (data[i + 6] as u64) | ((data[i + 7] as u64) << 32);
            mmio::mmio_write_u64(ptr, p0);
            mmio::mmio_write_u64(ptr + 8, p1);
            mmio::mmio_write_u64(ptr + 16, p2);
            mmio::mmio_write_u64(ptr + 24, p3);
            ptr += 32;
            i += 8;
        }

        while i + 1 < len {
            let pair = (data[i] as u64) | ((data[i + 1] as u64) << 32);
            mmio::mmio_write_u64(ptr, pair);
            ptr += 8;
            i += 2;
        }

        if i < len {
            mmio::mmio_write_u32(ptr, data[i]);
        }
    }

    /// Stream-pack RGBA bytes into BGRA bytes and write them to MMIO in
    /// moderate-size chunks. This avoids allocating a large `scratch_u32`
    /// buffer for very long runs and allows SIMD packers to operate on
    /// small temporaries which are then emitted via `write_bytes_mmio`.
    fn write_rgba_packed_to_mmio_stream(&mut self, addr: usize, src: &[u8]) {
        // Process in pixel-based chunks to allow direct u32 writes. Use
        // 512 pixels per chunk (512 * 4 = 2048 bytes) as a trade-off between
        // temporary buffer size and write granularity; larger chunks can reduce
        // per-chunk overhead for very large runs.
        const CHUNK_PIXELS: usize = 512;

        if src.is_empty() {
            return;
        }

        let total_pixels = src.len() / 4;
        let mut processed_pixels = 0usize;

        while processed_pixels < total_pixels {
            let remaining_pixels = total_pixels - processed_pixels;
            let chunk_pixels = core::cmp::min(CHUNK_PIXELS, remaining_pixels);

            // Ensure a u32-backed scratch buffer for this chunk
            self.ensure_scratch_u32(chunk_pixels);
            let src_offset = processed_pixels * 4;

            {
                // Mutable borrow scope for packer
                let src_chunk = &src[src_offset..src_offset + chunk_pixels * 4];
                let dst_bytes = unsafe { core::slice::from_raw_parts_mut(self.scratch_u32.as_mut_ptr() as *mut u8, chunk_pixels * 4) };
                Self::pack_rgba_to_bgra(src_chunk, dst_bytes);
            }

            // Emit packed u32 words as aligned u64/u32 writes
            let addr_chunk = addr + processed_pixels * 4;
            self.write_u32_slice_mmio(addr_chunk, &self.scratch_u32[..chunk_pixels]);

            processed_pixels += chunk_pixels;
        }
    }

    /// Pack RGBA byte buffer into BGRA byte buffer. Prefer SIMD (SSSE3) when
    /// available on x86/x86_64; otherwise use scalar fallback.
    /// Pack RGBA byte buffer into BGRA byte buffer. Prefer SIMD (SSSE3) when
    /// available on x86/x86_64; otherwise use scalar fallback.
    ///
    /// Note: made an associated function (no &self) so callers can pass a
    /// mutable borrow of scratch buffers without conflicting with an immutable
    /// borrow of `self` during method calls.
    /// Public packer: RGBA -> BGRA. Dispatches to AVX2/SSSE3/NEON implementations
    /// when available; otherwise falls back to a scalar implementation.
    pub fn pack_rgba_to_bgra(src: &[u8], dst: &mut [u8]) {
        let pixels = core::cmp::min(src.len(), dst.len()) / 4;
        let bytes = pixels * 4;
        use core::sync::atomic::{AtomicU8, Ordering};

        // Quick scalar path for very small buffers to avoid SIMD call/dispatch overhead.
        // Keep this small so streaming chunks (e.g., 1024 bytes) still use SIMD.
        const SMALL_BYTES_THRESHOLD: usize = 256; // 64 pixels
        if bytes <= SMALL_BYTES_THRESHOLD {
            Self::pack_rgba_to_bgra_scalar(src, dst);
            return;
        }

        // Runtime-detected, cached packer selection to minimize dispatch overhead.
        // 0 = unknown, 1 = scalar, 2 = ssse3, 3 = avx2, 4 = neon
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            static PACKER_MODE: AtomicU8 = AtomicU8::new(0);
            let mut mode = PACKER_MODE.load(Ordering::Relaxed);
            if mode == 0 {
                // Detect in first call only (restricted to bench/test builds where
                // runtime cpuid detection is available). Fallback to scalar
                // if detection is not enabled for the current build.
                #[cfg(all(any(test, feature = "bench")))]
                {
                    if std::is_x86_feature_detected!("avx2") {
                        mode = 3;
                    } else if std::is_x86_feature_detected!("ssse3") {
                        mode = 2;
                    } else {
                        mode = 1;
                    }
                }
                #[cfg(not(any(test, feature = "bench")))]
                {
                    mode = 1; // stable scalar-only builds
                }
                PACKER_MODE.store(mode, Ordering::Relaxed);
            }

            match mode {
                3 => unsafe { Self::pack_rgba_to_bgra_avx2(src.as_ptr(), dst.as_mut_ptr(), bytes); },
                2 => unsafe { Self::pack_rgba_to_bgra_ssse3(src.as_ptr(), dst.as_mut_ptr(), bytes); },
                _ => Self::pack_rgba_to_bgra_scalar(src, dst),
            }
            return;
        }

        #[cfg(target_arch = "aarch64")]
        {
            static PACKER_MODE: AtomicU8 = AtomicU8::new(0);
            let mut mode = PACKER_MODE.load(Ordering::Relaxed);
            if mode == 0 {
                #[cfg(all(any(test, feature = "bench")))]
                {
                    if std::is_aarch64_feature_detected!("neon") {
                        mode = 4;
                    } else {
                        mode = 1;
                    }
                }
                #[cfg(not(any(test, feature = "bench")))]
                {
                    mode = 1;
                }
                PACKER_MODE.store(mode, Ordering::Relaxed);
            }

            match mode {
                4 => unsafe { Self::pack_rgba_to_bgra_neon(src.as_ptr(), dst.as_mut_ptr(), bytes); },
                _ => Self::pack_rgba_to_bgra_scalar(src, dst),
            }
            return;
        }

        // Fallback scalar for other platforms
        Self::pack_rgba_to_bgra_scalar(src, dst);
    }

    /// Scalar packer implementation (public so benches can call it directly).
    pub fn pack_rgba_to_bgra_scalar(src: &[u8], dst: &mut [u8]) {
        let pixels = core::cmp::min(src.len(), dst.len()) / 4;
        for i in 0..pixels {
            let s = i * 4;
            dst[s] = src[s + 2];
            dst[s + 1] = src[s + 1];
            dst[s + 2] = src[s + 0];
            dst[s + 3] = src[s + 3];
        }
    }

    /// AVX2 implementation (unsafe). Processes 32-byte blocks using 256-bit
    /// byte shuffles and falls back to SSSE3 / scalar for tails.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[target_feature(enable = "avx2")]
    unsafe fn pack_rgba_to_bgra_avx2(src: *const u8, dst: *mut u8, bytes: usize) {
        use core::arch::x86_64::*;
        // 32-byte shuffle mask: for each 4-byte lane [r,g,b,a] -> [b,g,r,a]
        let mask = _mm256_setr_epi8(
            2, 1, 0, 3, 6, 5, 4, 7, 10, 9, 8, 11, 14, 13, 12, 15,
            18, 17, 16, 19, 22, 21, 20, 23, 26, 25, 24, 27, 30, 29, 28, 31,
        );

        let mut i = 0usize;

        // Fast path when both src and dst are 32-byte aligned: use aligned loads/stores
        let src_aligned = (src as usize) & 31 == 0;
        let dst_aligned = (dst as usize) & 31 == 0;

        if src_aligned && dst_aligned {
            // Unroll 64-byte per iteration to reduce loop overhead
            while i + 64 <= bytes {
                let v0 = _mm256_load_si256(src.add(i) as *const __m256i);
                let v1 = _mm256_load_si256(src.add(i + 32) as *const __m256i);
                let r0 = _mm256_shuffle_epi8(v0, mask);
                let r1 = _mm256_shuffle_epi8(v1, mask);
                _mm256_store_si256(dst.add(i) as *mut __m256i, r0);
                _mm256_store_si256(dst.add(i + 32) as *mut __m256i, r1);
                i += 64;
            }

            while i + 32 <= bytes {
                let v = _mm256_load_si256(src.add(i) as *const __m256i);
                let r = _mm256_shuffle_epi8(v, mask);
                _mm256_store_si256(dst.add(i) as *mut __m256i, r);
                i += 32;
            }
        } else {
            // Unaligned (general) path
            while i + 64 <= bytes {
                let v0 = _mm256_loadu_si256(src.add(i) as *const __m256i);
                let v1 = _mm256_loadu_si256(src.add(i + 32) as *const __m256i);
                let r0 = _mm256_shuffle_epi8(v0, mask);
                let r1 = _mm256_shuffle_epi8(v1, mask);
                _mm256_storeu_si256(dst.add(i) as *mut __m256i, r0);
                _mm256_storeu_si256(dst.add(i + 32) as *mut __m256i, r1);
                i += 64;
            }

            while i + 32 <= bytes {
                let v = _mm256_loadu_si256(src.add(i) as *const __m256i);
                let r = _mm256_shuffle_epi8(v, mask);
                _mm256_storeu_si256(dst.add(i) as *mut __m256i, r);
                i += 32;
            }
        }

        // Process remaining 16-byte block(s) via SSSE3-style shuffle
        while i + 16 <= bytes {
            let v = _mm_loadu_si128(src.add(i) as *const __m128i);
            let m = _mm_setr_epi8(2, 1, 0, 3, 6, 5, 4, 7, 10, 9, 8, 11, 14, 13, 12, 15);
            let r = _mm_shuffle_epi8(v, m);
            _mm_storeu_si128(dst.add(i) as *mut __m128i, r);
            i += 16;
        }

        // Tail: scalar
        while i < bytes {
            let pixel_idx = i / 4;
            let s = pixel_idx * 4;
            let r = *src.add(s + 0);
            let g = *src.add(s + 1);
            let b = *src.add(s + 2);
            let a = *src.add(s + 3);
            *dst.add(s + 0) = b;
            *dst.add(s + 1) = g;
            *dst.add(s + 2) = r;
            *dst.add(s + 3) = a;
            i += 4;
        }
    }

    /// NEON implementation placeholder (aarch64). For now this falls back to
    /// a scalar loop for correctness; a NEON tbl-based implementation can be
    /// added later for further speedups.
    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn pack_rgba_to_bgra_neon(src: *const u8, dst: *mut u8, bytes: usize) {
        use core::arch::aarch64::*;

        // Vectorized 32-bit lane byte-swizzle:
        // For each u32 lane (little-endian RGBA), produce BGRA by shifting
        // low and high byte lanes and OR-ing the parts.
        let mut i = 0usize;

        // Process 4 pixels (16 bytes) per iteration using 32-bit vector ops
        while i + 16 <= bytes {
            // Load 4 lanes (may be unaligned)
            let v = vld1q_u32(src.add(i) as *const u32);

            // Masks
            let low_mask = vdupq_n_u32(0x000000FF);
            let mid_mask = vdupq_n_u32(0x0000FF00);
            let high_mask = vdupq_n_u32(0x00FF0000);
            let alpha_mask = vdupq_n_u32(0xFF000000);

            let low = vandq_u32(v, low_mask);
            let mid = vandq_u32(v, mid_mask);
            let high = vandq_u32(v, high_mask);
            let alpha = vandq_u32(v, alpha_mask);

            // swap: low << 16 | mid | high >> 16 | alpha
            let low_shift = vshlq_n_u32(low, 16);
            let high_shift = vshrq_n_u32(high, 16);
            let tmp = vorrq_u32(low_shift, mid);
            let swapped = vorrq_u32(vorrq_u32(tmp, high_shift), alpha);

            vst1q_u32(dst.add(i) as *mut u32, swapped);
            i += 16;
        }

        // Tail: scalar per-pixel
        while i + 4 <= bytes {
            let p = core::ptr::read_unaligned(src.add(i) as *const u32);
            let swapped = ((p & 0x000000FF) << 16) | (p & 0x0000FF00) | ((p & 0x00FF0000) >> 16) | (p & 0xFF000000);
            core::ptr::write_unaligned(dst.add(i) as *mut u32, swapped);
            i += 4;
        }
    }

    /// SSSE3 implementation (unsafe). Processes `bytes` bytes (must be multiple
    /// of 4). Uses pshufb to permute bytes inside 16-byte lanes.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[target_feature(enable = "ssse3")]
    unsafe fn pack_rgba_to_bgra_ssse3(src: *const u8, dst: *mut u8, bytes: usize) {
        use core::arch::x86_64::*;

        // shuffle mask: for each 4-byte lane [r,g,b,a] -> [b,g,r,a]
        let mask = _mm_setr_epi8(
            2, 1, 0, 3, 6, 5, 4, 7, 10, 9, 8, 11, 14, 13, 12, 15,
        );

        let mut i = 0usize;

        // Unroll 32-byte per iteration (two 16-byte lanes) to reduce loop overhead
        while i + 32 <= bytes {
            let v0 = _mm_loadu_si128(src.add(i) as *const __m128i);
            let v1 = _mm_loadu_si128(src.add(i + 16) as *const __m128i);
            let r0 = _mm_shuffle_epi8(v0, mask);
            let r1 = _mm_shuffle_epi8(v1, mask);
            _mm_storeu_si128(dst.add(i) as *mut __m128i, r0);
            _mm_storeu_si128(dst.add(i + 16) as *mut __m128i, r1);
            i += 32;
        }

        while i + 16 <= bytes {
            let v = _mm_loadu_si128(src.add(i) as *const __m128i);
            let r = _mm_shuffle_epi8(v, mask);
            _mm_storeu_si128(dst.add(i) as *mut __m128i, r);
            i += 16;
        }

        // Tail: scalar for remaining (will be multiple of 4)
        while i < bytes {
            let pixel_idx = i / 4;
            let s = pixel_idx * 4;
            let r = *src.add(s + 0);
            let g = *src.add(s + 1);
            let b = *src.add(s + 2);
            let a = *src.add(s + 3);
            *dst.add(s + 0) = b;
            *dst.add(s + 1) = g;
            *dst.add(s + 2) = r;
            *dst.add(s + 3) = a;
            i += 4;
        }
    }

    /// Write a run of u32 pixels (color already packed) to destination offset
    fn write_u32_run(&mut self, dst_offset_bytes: usize, run_len_pixels: usize, color_u32: u32) {
        if let Some(ref mut back) = self.back_buffer {
            // Backed by a Vec -> safe to write via slice
            let row_ptr = unsafe { back.as_mut_ptr().add(dst_offset_bytes) } as *mut u32;
            let row_slice = unsafe { core::slice::from_raw_parts_mut(row_ptr, run_len_pixels) };
            row_slice.fill(color_u32);
        } else {
            // MMIO path: alignment-aware writes (prefer u64 pairs)
            let mut addr = self.buffer as usize + dst_offset_bytes;
            let mut remaining = run_len_pixels;

            // If addr is 4 mod 8, write a single u32 first to reach 8-byte alignment
            if (addr & 7) == 4 && remaining >= 1 {
                mmio::mmio_write_u32(addr, color_u32);
                addr += 4;
                remaining -= 1;
            }

            if remaining >= 2 {
                let mut pair_count = remaining / 2;
                let pair_val = (color_u32 as u64) | ((color_u32 as u64) << 32);

                // Unroll 4 writes at a time to reduce loop overhead
                while pair_count >= 4 {
                    mmio::mmio_write_u64(addr, pair_val);
                    mmio::mmio_write_u64(addr + 8, pair_val);
                    mmio::mmio_write_u64(addr + 16, pair_val);
                    mmio::mmio_write_u64(addr + 24, pair_val);
                    addr += 32;
                    pair_count -= 4;
                }

                while pair_count > 0 {
                    mmio::mmio_write_u64(addr, pair_val);
                    addr += 8;
                    pair_count -= 1;
                }

                remaining -= (remaining / 2) * 2;
            }

            if remaining == 1 {
                mmio::mmio_write_u32(addr, color_u32);
            }
        }
    }

    /// Write a run of BGR(3-byte) pixels
    fn write_bgr_run(&mut self, dst_offset_bytes: usize, run_len_pixels: usize, color: Color) {
        let b = color.blue;
        let g = color.green;
        let r = color.red;

        let total = run_len_pixels * 3;
        // Prepare scratch buffer first to avoid holding a mutable borrow to self
        self.ensure_scratch_u8(total);
        if run_len_pixels > 0 {
            // Exponential fill: write first pixel then copy already-filled region
            // repeatedly to build the rest of the buffer. This reduces per-pixel
            // overhead for large fills of a single color.
            self.scratch_u8[0] = b;
            self.scratch_u8[1] = g;
            self.scratch_u8[2] = r;

            let mut filled = 1usize;
            while filled < run_len_pixels {
                let copy_pixels = core::cmp::min(filled, run_len_pixels - filled);
                let copy_bytes = copy_pixels * 3;
                let dst_offset = filled * 3;
                unsafe {
                    // Use ptr::copy for overlapping-safe copy
                    ptr::copy(self.scratch_u8.as_ptr(), self.scratch_u8.as_mut_ptr().add(dst_offset), copy_bytes);
                }
                filled += copy_pixels;
            }
        }

        if let Some(ref mut back) = self.back_buffer {
            unsafe {
                ptr::copy_nonoverlapping(self.scratch_u8.as_ptr(), back.as_mut_ptr().add(dst_offset_bytes), total);
            }
        } else {
            // MMIO path: write bytes using bulk u32 when possible
            let addr = self.buffer as usize + dst_offset_bytes;
            self.write_bytes_mmio(addr, &self.scratch_u8[..total]);
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
                mmio::mmio_write_u32(pixel_addr, color.to_u32());
            },
            PixelFormat::Bgr888 | PixelFormat::Rgb888 => unsafe {
                mmio::volatile_write::<u8>(buffer.add(offset) as usize, color.blue);
                mmio::volatile_write::<u8>(buffer.add(offset + 1) as usize, color.green);
                mmio::volatile_write::<u8>(buffer.add(offset + 2) as usize, color.red);
            },
            PixelFormat::Rgb565 => unsafe {
                let r = (color.red as u16 >> 3) & 0x1F;
                let g = (color.green as u16 >> 2) & 0x3F;
                let b = (color.blue as u16 >> 3) & 0x1F;
                let pixel = (r << 11) | (g << 5) | b;
                let ptr_addr = buffer.add(offset) as usize;
                mmio::mmio_write_u16(ptr_addr, pixel);
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
                let pixel = mmio::mmio_read_u32(self.buffer.add(offset) as usize);
                Color::from_u32(pixel)
            },
            PixelFormat::Bgr888 | PixelFormat::Rgb888 => unsafe {
                let b = mmio::volatile_read::<u8>(self.buffer.add(offset) as usize);
                let g = mmio::volatile_read::<u8>(self.buffer.add(offset + 1) as usize);
                let r = mmio::volatile_read::<u8>(self.buffer.add(offset + 2) as usize);
                Color::new(r, g, b)
            },
            PixelFormat::Rgb565 => unsafe {
                let pixel = mmio::mmio_read_u16(self.buffer.add(offset) as usize);
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
                        mmio::mmio_write_u32(pixel_addr, color.to_u32());
                    },
                    PixelFormat::Bgr888 | PixelFormat::Rgb888 => unsafe {
                                mmio::volatile_write::<u8>(
                                    buffer.add(offset) as usize,
                                    color.blue,
                                );
                                mmio::volatile_write::<u8>(
                                    buffer.add(offset + 1) as usize,
                                    color.green,
                                );
                                mmio::volatile_write::<u8>(
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
                                mmio::mmio_write_u16(ptr_addr, pixel);
                    },
                }
            }
        }
    }

    /// 水平線を描画
    pub fn draw_hline(&mut self, x1: i32, x2: i32, y: i32, color: Color) {
        // Clip against current clip rect
        let mut start = x1.min(x2);
        let mut end = x1.max(x2);

        if y < self.clip.y || y >= self.clip.bottom() {
            return;
        }

        start = start.max(self.clip.x);
        end = end.min(self.clip.right() - 1);

        if start > end {
            return;
        }

        let bytes_per_pixel = self.info.format.bytes_per_pixel();
        let stride = self.info.stride as usize;
        let x_start = start as usize;
        let run_len = (end - start + 1) as usize;
        let offset = (y as usize * stride) + x_start * bytes_per_pixel;

        match bytes_per_pixel {
            4 => {
                let color_u32 = color.to_u32();
                self.write_u32_run(offset, run_len, color_u32);
            }
            3 => {
                self.write_bgr_run(offset, run_len, color);
            }
            2 => {
                // rgb565 per-pixel write
                let mut addr = self.draw_buffer();
                for i in 0..run_len {
                    let off = offset + i * 2;
                    let r = (color.red as u16 >> 3) & 0x1F;
                    let g = (color.green as u16 >> 2) & 0x3F;
                    let b = (color.blue as u16 >> 3) & 0x1F;
                    let pixel = (r << 11) | (g << 5) | b;
                    if self.back_buffer.is_some() {
                        unsafe {
                            let ptr = addr.add(off) as *mut u16;
                            ptr::write(ptr, pixel);
                        }
                    } else {
                        unsafe { mmio::mmio_write_u16(addr.add(off) as usize, pixel); }
                    }
                }
            }
            _ => {
                // Fallback
                for x in start..=end {
                    self.set_pixel(x, y, color);
                }
            }
        }
    }

    /// 垂直線を描画
    pub fn draw_vline(&mut self, x: i32, y1: i32, y2: i32, color: Color) {
        // Clip against current clip rect
        let mut start = y1.min(y2);
        let mut end = y1.max(y2);

        if x < self.clip.x || x >= self.clip.right() {
            return;
        }

        start = start.max(self.clip.y);
        end = end.min(self.clip.bottom() - 1);

        if start > end {
            return;
        }

        let bytes_per_pixel = self.info.format.bytes_per_pixel();
        let stride = self.info.stride as usize;
        let x_off = x as usize;
        let run_len = (end - start + 1) as usize;

        match bytes_per_pixel {
            4 => {
                let color_u32 = color.to_u32();
                // For vertical lines we must step by stride for each row
                for i in 0..run_len {
                    let y = (start as usize) + i;
                    let off = y * stride + x_off * 4;
                    if self.back_buffer.is_some() {
                        unsafe {
                            let ptr = self.draw_buffer().add(off) as *mut u32;
                            ptr::write(ptr, color_u32);
                        }
                    } else {
                        unsafe { mmio::mmio_write_u32(self.draw_buffer().add(off) as usize, color_u32); }
                    }
                }
            }
            3 => {
                for i in 0..run_len {
                    let y = (start as usize) + i;
                    let off = y * stride + x_off * 3;
                    if self.back_buffer.is_some() {
                        unsafe {
                            let ptr = self.draw_buffer().add(off);
                            ptr::write(ptr, color.blue);
                            ptr::write(ptr.add(1), color.green);
                            ptr::write(ptr.add(2), color.red);
                        }
                    } else {
                        unsafe {
                            mmio::volatile_write(self.draw_buffer().add(off) as usize, color.blue);
                            mmio::volatile_write(self.draw_buffer().add(off + 1) as usize, color.green);
                            mmio::volatile_write(self.draw_buffer().add(off + 2) as usize, color.red);
                        }
                    }
                }
            }
            2 => {
                for i in 0..run_len {
                    let y = (start as usize) + i;
                    let off = y * stride + x_off * 2;
                    let r = (color.red as u16 >> 3) & 0x1F;
                    let g = (color.green as u16 >> 2) & 0x3F;
                    let b = (color.blue as u16 >> 3) & 0x1F;
                    let pixel = (r << 11) | (g << 5) | b;
                    if self.back_buffer.is_some() {
                        unsafe { ptr::write(self.draw_buffer().add(off) as *mut u16, pixel); }
                    } else {
                        unsafe { mmio::mmio_write_u16(self.draw_buffer().add(off) as usize, pixel); }
                    }
                }
            }
            _ => {
                for y in start..=end {
                    self.set_pixel(x, y, color);
                }
            }
        }
    }

    /// 線を描画（Bresenhamアルゴリズム）
    pub fn draw_line(&mut self, x1: i32, y1: i32, x2: i32, y2: i32, color: Color) {
        // Fast-path horizontal/vertical lines to use bulk writers
        if y1 == y2 {
            self.draw_hline(x1, x2, y1, color);
            return;
        }
        if x1 == x2 {
            self.draw_vline(x1, y1, y2, color);
            return;
        }
        // We'll use Bresenham's algorithm but coalesce consecutive horizontal
        // runs into fast `draw_hline` calls when possible to leverage bulk writers.
        let abs_dx = (x2 - x1).abs();
        let abs_dy = (y2 - y1).abs();

        // Heuristic: coalesce horizontal runs only for primarily-horizontal lines.
        if abs_dx < abs_dy {
            // Steep line: fallback to naive per-pixel algorithm to avoid extra
            // branching overhead when horizontal runs are uncommon.
            #[cfg(feature = "bench")]
            {
                self.draw_line_naive(x1, y1, x2, y2, color);
                return;
            }
            #[cfg(not(feature = "bench"))]
            {
                // If bench feature not enabled, perform the naive walk inline.
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
                        return;
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
        }

        let dx = abs_dx;
        let dy = -(abs_dy);
        let sx = if x1 < x2 { 1 } else { -1 };
        let sy = if y1 < y2 { 1 } else { -1 };
        let mut err = dx + dy;

        let mut x = x1;
        let mut y = y1;

        // Track a current horizontal run starting at `run_start` on row `run_y`.
        let mut run_start = x;
        let mut run_y = y;
        let mut run_len = 1usize;

        loop {
            // If we've reached the destination, flush the pending run and exit.
            if x == x2 && y == y2 {
                if run_len == 1 {
                    self.set_pixel(x, y, color);
                } else {
                    self.draw_hline(run_start, run_start + (run_len as i32 - 1), run_y, color);
                }
                break;
            }

            let e2 = 2 * err;
            let mut nx = x;
            let mut ny = y;

            if e2 >= dy {
                err += dy;
                nx += sx;
            }
            if e2 <= dx {
                err += dx;
                ny += sy;
            }

            // If the next point is on the same row and adjacent in X, extend the run.
            if ny == run_y && nx == x + sx {
                run_len += 1;
                x = nx;
                y = ny;
                continue;
            }

            // Flush the current run.
            if run_len == 1 {
                self.set_pixel(x, y, color);
            } else {
                self.draw_hline(run_start, run_start + (run_len as i32 - 1), run_y, color);
            }

            // Start a new run at the next point.
            x = nx;
            y = ny;
            run_start = x;
            run_y = y;
            run_len = 1;
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
            PixelFormat::Bgra8888 | PixelFormat::Rgba8888 => {
                let color_u32 = color.to_u32();
                if self.back_buffer.is_some() {
                    // Backed buffer: safe bulk fill via slice
                    for y in r.y..r.bottom() {
                        let offset = (y as usize * stride as usize) + (r.x as usize * 4);
                        let row_ptr = unsafe { buffer.add(offset) as *mut u32 };
                        let row_slice = unsafe { core::slice::from_raw_parts_mut(row_ptr, r.width as usize) };
                        row_slice.fill(color_u32);
                    }
                } else {
                    // MMIO path: use aligned write helper
                    for y in r.y..r.bottom() {
                        let offset = (y as usize * stride as usize) + (r.x as usize * 4);
                        self.write_u32_run(offset, r.width as usize, color_u32);
                    }
                }
            }
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
        // First fill the background rectangle for the whole text span. This
        // leverages the optimized `fill_rect` path for broad formats.
        let char_count = text.chars().filter(|&c| c != '\n').count() as u32;
        if char_count == 0 {
            return;
        }

        let text_w = char_count * font.width() as u32;
        let text_h = font.height() as u32;
        self.fill_rect(Rect::new(x, y, text_w, text_h), bg_color);

        // Now draw glyph foreground pixels in runs to minimize per-pixel writes.
        let stride = self.info.stride as usize;
        let bpp = self.info.format.bytes_per_pixel();

        let mut cx = x;
        for c in text.chars() {
            if c == '\n' {
                continue;
            }

            let c_index = c as usize;
            if c_index >= 128 {
                cx += font.width() as i32;
                continue;
            }

            let glyph_start = c_index * font.height() as usize;

            for row in 0..font.height() {
                let glyph_row = glyph_start + row as usize;
                if glyph_row >= font.data_len() {
                    continue;
                }

                let byte = font.get_data(glyph_row);

                let mut col = 0usize;
                while col < font.width() as usize {
                    // Skip off pixels
                    while col < font.width() as usize {
                        let pixel_on = (byte >> (7 - col)) & 1 != 0;
                        if pixel_on {
                            break;
                        }
                        col += 1;
                    }

                    let run_start = col;
                    while col < font.width() as usize {
                        let pixel_on = (byte >> (7 - col)) & 1 != 0;
                        if !pixel_on {
                            break;
                        }
                        col += 1;
                    }

                    let run_len = col.saturating_sub(run_start);
                    if run_len == 0 {
                        continue;
                    }

                    // Compute absolute destination and apply clipping
                    let dst_x = cx + run_start as i32;
                    let dst_y = y + row as i32;
                    if dst_y < self.clip.y || dst_y >= self.clip.bottom() {
                        continue;
                    }

                    let dst_run_end_x = dst_x + run_len as i32 - 1;
                    if dst_run_end_x < self.clip.x || dst_x >= self.clip.right() {
                        continue;
                    }

                    let clipped_start = dst_x.max(self.clip.x);
                    let clipped_end = dst_run_end_x.min(self.clip.right() - 1);
                    let clipped_len = (clipped_end - clipped_start + 1) as usize;
                    let start_offset = (dst_y as usize * stride) + (clipped_start as usize * bpp);

                    match bpp {
                        4 => {
                            self.write_u32_run(start_offset, clipped_len, color.to_u32());
                        }
                        3 => {
                            self.write_bgr_run(start_offset, clipped_len, color);
                        }
                        2 => {
                            for i in 0..clipped_len {
                                let off = start_offset + i * 2;
                                let r = (color.red as u16 >> 3) & 0x1F;
                                let g = (color.green as u16 >> 2) & 0x3F;
                                let b = (color.blue as u16 >> 3) & 0x1F;
                                let pixel = (r << 11) | (g << 5) | b;
                                if self.back_buffer.is_some() {
                                    unsafe { ptr::write(self.draw_buffer().add(off) as *mut u16, pixel); }
                                } else {
                                    unsafe { mmio::mmio_write_u16(self.draw_buffer().add(off) as usize, pixel); }
                                }
                            }
                        }
                        _ => {
                            for i in 0..clipped_len {
                                self.set_pixel(clipped_start + i as i32, dst_y, color);
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
            return;
        }

        let bytes_per_pixel = self.info.format.bytes_per_pixel();

        // Pre-detect CPU features once per draw to avoid repeated CPUID calls
        let mut avx2_available = false;
        #[cfg(all(any(test, feature = "bench"), any(target_arch = "x86", target_arch = "x86_64")))]
        {
            avx2_available = std::is_x86_feature_detected!("avx2");
        }

        // Threshold to prefer streaming packing for sufficiently long opaque runs.
        const STREAM_THRESHOLD_PIXELS: usize = 256;

        for dst_row in dst_y0..dst_y1 {
            let src_row = (dst_row - y) as u32;
            let row_start = (dst_x0 - x) as u32;
            let row_end = (dst_x1 - x) as u32; // exclusive

            // Pre-compute row offsets
            let dst_row_offset = (dst_row as u32 * self.info.stride) as usize;

            let mut col = row_start;
            while col < row_end {
                // Skip non-opaque pixels (alpha != 255) by falling back to per-pixel set_pixel
                while col < row_end {
                    let idx = ((src_row * image.width() + col) * 4) as usize;
                    let alpha = image.data()[idx + 3];
                    if alpha == 255 {
                        break;
                    }
                    // fallback: preserve original semantic (write if alpha > 0)
                    if alpha > 0 {
                        let c = image.get_pixel(col, src_row);
                        self.set_pixel((x + col as i32), dst_row, c);
                    }
                    col += 1;
                }

                // Now col is at start of an opaque run (or at row_end)
                let run_start = col;
                while col < row_end {
                    let idx = ((src_row * image.width() + col) * 4) as usize;
                    let alpha = image.data()[idx + 3];
                    if alpha != 255 {
                        break;
                    }
                    col += 1;
                }

                let run_len = (col - run_start) as usize;
                if run_len == 0 {
                    continue;
                }

                let dst_x = (dst_x0 as usize) + (run_start as usize);
                let dst_byte_offset = dst_row_offset + dst_x * bytes_per_pixel;

                match bytes_per_pixel {
                    4 => {
                        // If framebuffer format equals the image format (both RGBA order),
                        // we can copy bytes directly without per-pixel packing.
                        let src_base = (src_row * image.width() + run_start) as usize;
                        let imgdata = image.data();

                        if self.info.format == PixelFormat::Rgba8888 {
                            let byte_len = run_len * 4;
                            let src_slice = &imgdata[src_base * 4..src_base * 4 + byte_len];

                            if let Some(ref mut back) = self.back_buffer {
                                unsafe { ptr::copy_nonoverlapping(src_slice.as_ptr(), back.as_mut_ptr().add(dst_byte_offset), byte_len); }
                            } else {
                                let addr = self.buffer as usize + dst_byte_offset;
                                self.write_bytes_mmio(addr, src_slice);
                            }
                        } else {
                            // Fallback conversion paths (e.g., BGRA target). We try to
                            // prepare a u8 buffer (byte order in memory) so we can use
                            // the optimized write_bytes_mmio which prefers u64 writes.
                            match self.info.format {
                                PixelFormat::Bgra8888 => {
                                                // Pack RGBA -> BGRA into bytes and copy. When MMIO
                                                // is used (no back buffer) and AVX2 is available,
                                                // stream-pack into a small temporary buffer and
                                                // emit via `write_bytes_mmio` in chunks to avoid
                                                // allocating a large scratch_u32 for long runs.
                                                let src_slice = &imgdata[src_base * 4..src_base * 4 + run_len * 4];

                                                if self.back_buffer.is_some() {
                                                    // Back-buffered path: pack into u32 scratch then copy
                                                    self.ensure_scratch_u32(run_len);
                                                    {
                                                        let dst_bytes = unsafe { core::slice::from_raw_parts_mut(self.scratch_u32.as_mut_ptr() as *mut u8, run_len * 4) };
                                                        Self::pack_rgba_to_bgra(src_slice, dst_bytes);
                                                    }
                                                    let back = self.back_buffer.as_mut().unwrap();
                                                    let dst_ptr = unsafe { back.as_mut_ptr().add(dst_byte_offset) as *mut u32 };
                                                    unsafe { ptr::copy_nonoverlapping(self.scratch_u32.as_ptr(), dst_ptr, run_len); }
                                                } else {
                                                    // Prefer a streaming AVX2-assisted path in bench/test
                                                    // builds when runtime CPU features are present.
                                                    if avx2_available && run_len >= STREAM_THRESHOLD_PIXELS {
                                                        let addr = self.buffer as usize + dst_byte_offset;
                                                        self.write_rgba_packed_to_mmio_stream(addr, src_slice);
                                                        continue;
                                                    }

                                                    // Fallback: pack into u32 scratch and write as u32 slice
                                                    self.ensure_scratch_u32(run_len);
                                                    let dst_bytes = unsafe { core::slice::from_raw_parts_mut(self.scratch_u32.as_mut_ptr() as *mut u8, run_len * 4) };
                                                    Self::pack_rgba_to_bgra(src_slice, dst_bytes);
                                                    let addr = self.buffer as usize + dst_byte_offset;
                                                    self.write_u32_slice_mmio(addr, &self.scratch_u32[..run_len]);
                                                }
                                }
                                PixelFormat::Rgba8888 => {
                                    let byte_len = run_len * 4;
                                    let src_slice = &imgdata[src_base * 4..src_base * 4 + byte_len];

                                    if let Some(ref mut back) = self.back_buffer {
                                        unsafe { ptr::copy_nonoverlapping(src_slice.as_ptr(), back.as_mut_ptr().add(dst_byte_offset), byte_len); }
                                    } else {
                                        let addr = self.buffer as usize + dst_byte_offset;
                                        // If source is 4-byte aligned we can reinterpret as u32 slice
                                        if (src_slice.as_ptr() as usize) & 3 == 0 {
                                            let src_u32 = unsafe { core::slice::from_raw_parts(src_slice.as_ptr() as *const u32, run_len) };
                                            self.write_u32_slice_mmio(addr, src_u32);
                                        } else {
                                            // Fallback: pack into aligned scratch_u32 then write
                                            self.ensure_scratch_u32(run_len);
                                            for i in 0..run_len {
                                                let idx = (src_base + i) * 4;
                                                let r = imgdata[idx];
                                                let g = imgdata[idx + 1];
                                                let b = imgdata[idx + 2];
                                                let a = imgdata[idx + 3];
                                                self.scratch_u32[i] = u32::from_le_bytes([r, g, b, a]);
                                            }
                                            self.write_u32_slice_mmio(addr, &self.scratch_u32[..run_len]);
                                        }
                                    }
                                }
                                _ => {
                                    // unsupported 32-bit format; fallback to per-pixel writes
                                    for j in 0..run_len {
                                        let idx2 = (src_base + j) * 4;
                                        let c = Color::with_alpha(imgdata[idx2], imgdata[idx2 + 1], imgdata[idx2 + 2], imgdata[idx2 + 3]);
                                        self.set_pixel(x + (run_start as i32 + j as i32), dst_row, c);
                                    }
                                }
                            }
                        }
                    }
                    3 => {
                        // 24-bit targets: pack bytes into scratch_u8
                        let total_bytes = run_len * 3;
                        self.ensure_scratch_u8(total_bytes);
                        let src_base = (src_row * image.width() + run_start) as usize;
                        let imgdata = image.data();

                        // Unrolled packing loop for 24-bit formats to reduce per-iteration overhead
                        let mut i = 0usize;
                        let mut src_idx = src_base * 4;
                        let mut dst_off = 0usize;

                        match self.info.format {
                            PixelFormat::Bgr888 => {
                                // Process 4 pixels per iteration when possible
                                while i + 3 < run_len {
                                    // pixel 0
                                    self.scratch_u8[dst_off] = imgdata[src_idx + 2];
                                    self.scratch_u8[dst_off + 1] = imgdata[src_idx + 1];
                                    self.scratch_u8[dst_off + 2] = imgdata[src_idx + 0];
                                    // pixel 1
                                    self.scratch_u8[dst_off + 3] = imgdata[src_idx + 6];
                                    self.scratch_u8[dst_off + 4] = imgdata[src_idx + 5];
                                    self.scratch_u8[dst_off + 5] = imgdata[src_idx + 4];
                                    // pixel 2
                                    self.scratch_u8[dst_off + 6] = imgdata[src_idx + 10];
                                    self.scratch_u8[dst_off + 7] = imgdata[src_idx + 9];
                                    self.scratch_u8[dst_off + 8] = imgdata[src_idx + 8];
                                    // pixel 3
                                    self.scratch_u8[dst_off + 9] = imgdata[src_idx + 14];
                                    self.scratch_u8[dst_off + 10] = imgdata[src_idx + 13];
                                    self.scratch_u8[dst_off + 11] = imgdata[src_idx + 12];

                                    src_idx += 16;
                                    dst_off += 12;
                                    i += 4;
                                }

                                // Remainder
                                while i < run_len {
                                    self.scratch_u8[dst_off] = imgdata[src_idx + 2];
                                    self.scratch_u8[dst_off + 1] = imgdata[src_idx + 1];
                                    self.scratch_u8[dst_off + 2] = imgdata[src_idx + 0];
                                    src_idx += 4;
                                    dst_off += 3;
                                    i += 1;
                                }
                            }
                            PixelFormat::Rgb888 => {
                                while i + 3 < run_len {
                                    // pixel 0
                                    self.scratch_u8[dst_off] = imgdata[src_idx + 0];
                                    self.scratch_u8[dst_off + 1] = imgdata[src_idx + 1];
                                    self.scratch_u8[dst_off + 2] = imgdata[src_idx + 2];
                                    // pixel 1
                                    self.scratch_u8[dst_off + 3] = imgdata[src_idx + 4];
                                    self.scratch_u8[dst_off + 4] = imgdata[src_idx + 5];
                                    self.scratch_u8[dst_off + 5] = imgdata[src_idx + 6];
                                    // pixel 2
                                    self.scratch_u8[dst_off + 6] = imgdata[src_idx + 8];
                                    self.scratch_u8[dst_off + 7] = imgdata[src_idx + 9];
                                    self.scratch_u8[dst_off + 8] = imgdata[src_idx + 10];
                                    // pixel 3
                                    self.scratch_u8[dst_off + 9] = imgdata[src_idx + 12];
                                    self.scratch_u8[dst_off + 10] = imgdata[src_idx + 13];
                                    self.scratch_u8[dst_off + 11] = imgdata[src_idx + 14];

                                    src_idx += 16;
                                    dst_off += 12;
                                    i += 4;
                                }

                                while i < run_len {
                                    self.scratch_u8[dst_off] = imgdata[src_idx + 0];
                                    self.scratch_u8[dst_off + 1] = imgdata[src_idx + 1];
                                    self.scratch_u8[dst_off + 2] = imgdata[src_idx + 2];
                                    src_idx += 4;
                                    dst_off += 3;
                                    i += 1;
                                }
                            }
                            _ => {
                                // unsupported 24-bit format; fallback
                                while i < run_len {
                                    let r = imgdata[src_idx + 0];
                                    let g = imgdata[src_idx + 1];
                                    let b = imgdata[src_idx + 2];
                                    let c = Color::with_alpha(r, g, b, imgdata[src_idx + 3]);
                                    self.set_pixel(x + (run_start as i32 + i as i32), dst_row, c);
                                    src_idx += 4;
                                    i += 1;
                                }
                            }
                        }

                        // 24-bit handled above (Bgr/Rgb branches)
                        // For large runs, process and emit in chunks to reduce peak
                        // scratch buffer usage and improve cache locality.
                        const CHUNK_24_PIXELS: usize = 512;
                        let mut processed = 0usize;
                        while processed < run_len {
                            let chunk = core::cmp::min(CHUNK_24_PIXELS, run_len - processed);
                            let chunk_bytes = chunk * 3;
                            // Ensure scratch capacity for this chunk
                            self.ensure_scratch_u8(chunk_bytes);
                            // Re-pack the chunk into scratch_u8
                            let mut src_idx = (src_base + processed) * 4;
                            let mut dst_off = 0usize;
                            match self.info.format {
                                PixelFormat::Bgr888 => {
                                    let mut i = 0usize;
                                    while i + 3 < chunk {
                                        self.scratch_u8[dst_off] = imgdata[src_idx + 2];
                                        self.scratch_u8[dst_off + 1] = imgdata[src_idx + 1];
                                        self.scratch_u8[dst_off + 2] = imgdata[src_idx + 0];

                                        self.scratch_u8[dst_off + 3] = imgdata[src_idx + 6];
                                        self.scratch_u8[dst_off + 4] = imgdata[src_idx + 5];
                                        self.scratch_u8[dst_off + 5] = imgdata[src_idx + 4];

                                        self.scratch_u8[dst_off + 6] = imgdata[src_idx + 10];
                                        self.scratch_u8[dst_off + 7] = imgdata[src_idx + 9];
                                        self.scratch_u8[dst_off + 8] = imgdata[src_idx + 8];

                                        self.scratch_u8[dst_off + 9] = imgdata[src_idx + 14];
                                        self.scratch_u8[dst_off + 10] = imgdata[src_idx + 13];
                                        self.scratch_u8[dst_off + 11] = imgdata[src_idx + 12];

                                        src_idx += 16;
                                        dst_off += 12;
                                        i += 4;
                                    }

                                    while i < chunk {
                                        self.scratch_u8[dst_off] = imgdata[src_idx + 2];
                                        self.scratch_u8[dst_off + 1] = imgdata[src_idx + 1];
                                        self.scratch_u8[dst_off + 2] = imgdata[src_idx + 0];
                                        src_idx += 4;
                                        dst_off += 3;
                                        i += 1;
                                    }
                                }
                                PixelFormat::Rgb888 => {
                                    let mut i = 0usize;
                                    while i + 3 < chunk {
                                        self.scratch_u8[dst_off] = imgdata[src_idx + 0];
                                        self.scratch_u8[dst_off + 1] = imgdata[src_idx + 1];
                                        self.scratch_u8[dst_off + 2] = imgdata[src_idx + 2];

                                        self.scratch_u8[dst_off + 3] = imgdata[src_idx + 4];
                                        self.scratch_u8[dst_off + 4] = imgdata[src_idx + 5];
                                        self.scratch_u8[dst_off + 5] = imgdata[src_idx + 6];

                                        self.scratch_u8[dst_off + 6] = imgdata[src_idx + 8];
                                        self.scratch_u8[dst_off + 7] = imgdata[src_idx + 9];
                                        self.scratch_u8[dst_off + 8] = imgdata[src_idx + 10];

                                        self.scratch_u8[dst_off + 9] = imgdata[src_idx + 12];
                                        self.scratch_u8[dst_off + 10] = imgdata[src_idx + 13];
                                        self.scratch_u8[dst_off + 11] = imgdata[src_idx + 14];

                                        src_idx += 16;
                                        dst_off += 12;
                                        i += 4;
                                    }

                                    while i < chunk {
                                        self.scratch_u8[dst_off] = imgdata[src_idx + 0];
                                        self.scratch_u8[dst_off + 1] = imgdata[src_idx + 1];
                                        self.scratch_u8[dst_off + 2] = imgdata[src_idx + 2];
                                        src_idx += 4;
                                        dst_off += 3;
                                        i += 1;
                                    }
                                }
                                _ => unreachable!(),
                            }

                            // Emit the chunk
                            let chunk_bytes = chunk * 3;
                            if let Some(ref mut back) = self.back_buffer {
                                unsafe { ptr::copy_nonoverlapping(self.scratch_u8.as_ptr(), back.as_mut_ptr().add(dst_byte_offset + processed * 3), chunk_bytes); }
                            } else {
                                let addr = self.buffer as usize + dst_byte_offset + processed * 3;
                                self.write_bytes_mmio(addr, &self.scratch_u8[..chunk_bytes]);
                            }

                            processed += chunk;
                        }
                    }
                    _ => {
                        // Unsupported format for bulk copy: fallback to per-pixel set_pixel
                        let src_base = (src_row * image.width() + run_start) as usize;
                        let imgdata = image.data();
                        for i in 0..run_len {
                            let idx = (src_base + i) * 4;
                            let c = Color::with_alpha(imgdata[idx], imgdata[idx + 1], imgdata[idx + 2], imgdata[idx + 3]);
                            self.set_pixel(x + (run_start as i32 + i as i32), dst_row, c);
                        }
                    }
                }
            }
        }
    }
}
