// ============================================================================
// src/graphics/framebuffer.rs - Framebuffer Implementation
// ============================================================================
//!
//! フレームバッファ描画実装
//!
//! ピクセル描画、図形描画、テキスト描画などのフレームバッファ操作

#![allow(dead_code)]

extern crate alloc;

use super::{BitmapFont, Color, FramebufferInfo, PixelFormat, Point, Rect};
use alloc::vec;
use alloc::vec::Vec;
use core::ptr;
use hal::mmio;

// Packer selection cache. Only one of these statics will be compiled in for a
// given target architecture (x86/x86_64 or aarch64). 0 = unknown, 1 = scalar,
// 2 = ssse3, 3 = avx2, 4 = neon.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
static PACKER_MODE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

// Cache AVX2 availability to avoid repeated CPUID queries during heavy
// drawing loops (e.g., per-row detection is expensive). 0 = unknown,
// 1 = not available, 2 = available.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
static AVX2_AVAILABLE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

#[cfg(target_arch = "aarch64")]
static PACKER_MODE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

// Bench-time helpers to force or query the packer mode deterministically.
// Guarded by `bench` feature to avoid exposing this API in production builds.
#[cfg(feature = "bench")]
pub fn force_packer_mode(mode: u8) {
    use core::sync::atomic::Ordering;
    PACKER_MODE.store(mode, Ordering::Relaxed);
}

#[cfg(feature = "bench")]
pub fn current_packer_mode() -> u8 {
    use core::sync::atomic::Ordering;
    PACKER_MODE.load(Ordering::Relaxed)
}

/// フレームバッファの内部状態
pub struct Framebuffer {
    buffer: *mut u8,
    info: FramebufferInfo,
    back_buffer: Option<Vec<u8>>,
    clip: Rect,
    scratch_u8: Vec<u8>,
    scratch_u32: Vec<u32>,
    /// Dirty rectangle tracking for optimized partial updates
    dirty_rect: Option<Rect>,
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
            fb.draw_hline(
                0,
                width as i32 - 1,
                y as i32,
                Color::with_alpha(10, 20, 30, 255),
            );
        }
        let elapsed = start.elapsed();
        log::info!("bench_draw_hline_bulk: {:?}", elapsed);
    }

    #[test]
    fn test_write_bgr_run_small_mmio() {
        let width = 10u32;
        let height = 1u32;
        let stride = width * 3;
        let mut vram = vec![0u8; (stride * height) as usize];
        let info = FramebufferInfo {
            address: vram.as_mut_ptr() as u64,
            width,
            height,
            stride,
            format: PixelFormat::Bgr888,
            bpp: 24,
        };

        let mut fb = unsafe { Framebuffer::new(info.clone()) };

        // small run (<= SMALL_BGR_DIRECT_MMIO)
        fb.draw_hline(2, 5, 0, Color::with_alpha(10, 20, 30, 255));

        for px in 2..=5 {
            let off = px as usize * 3;
            assert_eq!(vram[off], 30);
            assert_eq!(vram[off + 1], 20);
            assert_eq!(vram[off + 2], 10);
        }
    }

    #[test]
    fn test_write_bgr_run_large_mmio() {
        let width = 80u32;
        let height = 1u32;
        let stride = width * 3;
        let mut vram = vec![0u8; (stride * height) as usize];
        let info = FramebufferInfo {
            address: vram.as_mut_ptr() as u64,
            width,
            height,
            stride,
            format: PixelFormat::Bgr888,
            bpp: 24,
        };

        let mut fb = unsafe { Framebuffer::new(info.clone()) };

        fb.draw_hline(0, width as i32 - 1, 0, Color::with_alpha(1, 2, 3, 255));

        // check first and last pixel
        assert_eq!(vram[0], 3);
        assert_eq!(vram[1], 2);
        assert_eq!(vram[2], 1);

        let last_off = (width as usize - 1) * 3;
        assert_eq!(vram[last_off], 3);
        assert_eq!(vram[last_off + 1], 2);
        assert_eq!(vram[last_off + 2], 1);
    }

    #[test]
    fn test_write_bgr_run_large_mmio_full() {
        // Verify full buffer contents for a large BGR run to catch alignment
        // and pattern rotation bugs in the direct-MMIO path.
        let width = 200usize;
        let height = 1usize;
        let stride = width * 3;
        let mut vram = vec![0u8; stride * height];
        let info = FramebufferInfo {
            address: vram.as_mut_ptr() as u64,
            width: width as u32,
            height: height as u32,
            stride: stride as u32,
            format: PixelFormat::Bgr888,
            bpp: 24,
        };

        let mut fb = unsafe { Framebuffer::new(info.clone()) };

        fb.draw_hline(0, width as i32 - 1, 0, Color::with_alpha(1, 2, 3, 255));

        for px in 0..width {
            let off = px * 3;
            assert_eq!(vram[off], 3);
            assert_eq!(vram[off + 1], 2);
            assert_eq!(vram[off + 2], 1);
        }
    }

    #[test]
    fn test_write_bgr_run_large_mmio_full_unaligned() {
        // Starting at an unaligned byte offset should still produce the
        // canonical repeating BGR pattern across the buffer.
        let width = 200usize;
        let height = 1usize;
        // Add extra bytes at the start to allow an unaligned offset
        let mut vram = vec![0u8; width * 3 + 8];
        let base = 1usize; // unaligned start
        let info = FramebufferInfo {
            address: (vram.as_mut_ptr() as usize + base) as u64,
            width: width as u32,
            height: height as u32,
            stride: (width * 3) as u32,
            format: PixelFormat::Bgr888,
            bpp: 24,
        };

        let mut fb = unsafe { Framebuffer::new(info.clone()) };

        // Draw full-width run starting at the unaligned base
        fb.write_bgr_run(0, width, Color::with_alpha(1, 2, 3, 255));

        for px in 0..width {
            let off = base + px * 3;
            assert_eq!(vram[off], 3);
            assert_eq!(vram[off + 1], 2);
            assert_eq!(vram[off + 2], 1);
        }
    }

    #[test]
    fn test_write_bgr_run_small_mmio_pairs_aligned() {
        // Test pair-based fast-path when address is 4-byte aligned
        let mut vram = vec![0u8; 32];
        let info = FramebufferInfo {
            address: vram.as_mut_ptr() as u64,
            width: 10,
            height: 1,
            stride: 10 * 3,
            format: PixelFormat::Bgr888,
            bpp: 24,
        };

        let mut fb = unsafe { Framebuffer::new(info.clone()) };

        // Choose dst_offset_bytes = 4 (which is 4-byte aligned)
        fb.write_bgr_run(4, 3, Color::with_alpha(11, 22, 33, 255));

        // Expect three pixels of (b=33,g=22,r=11)
        for i in 0..3 {
            let off = 4 + i * 3;
            assert_eq!(vram[off], 33);
            assert_eq!(vram[off + 1], 22);
            assert_eq!(vram[off + 2], 11);
        }
    }

    #[test]
    fn test_write_bgr_run_small_mmio_generic_unaligned() {
        // Non-4-byte aligned address should fall back to per-byte writes
        let mut vram = vec![0u8; 32];
        let info = FramebufferInfo {
            address: vram.as_mut_ptr() as u64,
            width: 10,
            height: 1,
            stride: 10 * 3,
            format: PixelFormat::Bgr888,
            bpp: 24,
        };

        let mut fb = unsafe { Framebuffer::new(info.clone()) };

        // Choose offset 1 (unaligned)
        fb.write_bgr_run(1, 2, Color::with_alpha(2, 3, 4, 255));

        for i in 0..2 {
            let off = 1 + i * 3;
            assert_eq!(vram[off], 4);
            assert_eq!(vram[off + 1], 3);
            assert_eq!(vram[off + 2], 2);
        }
    }

    #[cfg(test)]
    pub fn _test_get_packer_mode() -> u8 {
        use core::sync::atomic::Ordering;
        PACKER_MODE.load(Ordering::Relaxed)
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_packer_env_override() {
        // Ensure RANY_PACKER override sets the PACKER_MODE
        std::env::set_var("RANY_PACKER", "scalar");
        let src = vec![0u8; 1024];
        let mut dst = vec![0u8; 1024];
        Framebuffer::pack_rgba_to_bgra(&src, &mut dst);
        assert_eq!(_test_get_packer_mode(), 1);
        std::env::remove_var("RANY_PACKER");
    }

    #[test]
    #[cfg(not(feature = "std"))]
    fn test_packer_env_override_no_std() {
        // When std is not available we at least ensure packer runs without
        // attempting to read environment variables.
        let src = vec![0u8; 1024];
        let mut dst = vec![0u8; 1024];
        Framebuffer::pack_rgba_to_bgra(&src, &mut dst);
        // PACKER_MODE may be 0/1 depending on platform; just ensure function completed.
        assert!(dst.len() == 1024);
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
            fb.draw_text(
                0,
                0,
                "The quick brown fox jumps over the lazy dog",
                Color::with_alpha(1, 2, 3, 255),
                Color::with_alpha(100, 110, 120, 255),
            );
        }
        let elapsed = start.elapsed();
        log::info!("bench_draw_text_bulk: {:?}", elapsed);
    }

    #[test]
    fn test_draw_hline_32bit_backbuffer() {
        let width = 10u32;
        let height = 6u32;
        let info = FramebufferInfo {
            address: 0,
            width,
            height,
            stride: width * 4,
            format: PixelFormat::Bgra8888,
            bpp: 32,
        };
        // Simple correctness check: draw a few representative lines with both
        // the optimized and naive implementations and compare backbuffers.
        let mut fb_opt = unsafe { Framebuffer::new(info.clone()) };
        let mut fb_naive = unsafe { Framebuffer::new(info.clone()) };
        let back = vec![0u8; info.size()];
        fb_opt.enable_double_buffering_from_vec(back.clone());
        fb_naive.enable_double_buffering_from_vec(back);

        let color = Color::with_alpha(10, 20, 30, 255);
        let test_lines = [
            (0, 0, 15, 15),
            (0, 0, 15, 0),
            (0, 0, 0, 15),
            (5, 1, 10, 12),
            (2, 14, 13, 3),
        ];

        for &(x1, y1, x2, y2) in &test_lines {
            fb_opt.draw_line(x1, y1, x2, y2, color);
            // naive implementation (do not rely on bench-only helpers here)
            let mut x = x1;
            let mut y = y1;
            let dx = (x2 - x1).abs();
            let dy = -(y2 - y1).abs();
            let sx = if x1 < x2 { 1 } else { -1 };
            let sy = if y1 < y2 { 1 } else { -1 };
            let mut err = dx + dy;

            loop {
                fb_naive.set_pixel(x, y, color);
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

            let buf_opt = fb_opt.back_buffer.as_ref().unwrap();
            let buf_naive = fb_naive.back_buffer.as_ref().unwrap();
            if buf_opt != buf_naive {
                // Provide a concise diff to aid debugging
                let diffs: Vec<usize> = buf_opt
                    .iter()
                    .zip(buf_naive.iter())
                    .enumerate()
                    .filter_map(|(i, (a, b))| if a != b { Some(i) } else { None })
                    .collect();
                // For clarity, list coordinates & colors of non-zero pixels in each buffer
                let stride = info.stride as usize;
                let mut opt_pixels = Vec::new();
                let mut naive_pixels = Vec::new();
                for y in 0..info.height as usize {
                    for x in 0..info.width as usize {
                        let off = y * stride + x * 4;
                        let o = (
                            buf_opt[off],
                            buf_opt[off + 1],
                            buf_opt[off + 2],
                            buf_opt[off + 3],
                        );
                        let n = (
                            buf_naive[off],
                            buf_naive[off + 1],
                            buf_naive[off + 2],
                            buf_naive[off + 3],
                        );
                        if o != (0, 0, 0, 0) {
                            opt_pixels.push((x as i32, y as i32, o));
                        }
                        if n != (0, 0, 0, 0) {
                            naive_pixels.push((x as i32, y as i32, n));
                        }
                    }
                }
                panic!(
                    "buffers differ for line ({},{})-({},{}) at {} indices: {:?}\nopt_nonzero: {:?}\nnaive_nonzero: {:?}",
                    x1,
                    y1,
                    x2,
                    y2,
                    diffs.len(),
                    &diffs[..core::cmp::min(diffs.len(), 16)],
                    opt_pixels,
                    naive_pixels,
                );
            }

            // Clear buffers for next iteration
            for b in fb_opt.back_buffer.as_mut().unwrap().iter_mut() {
                *b = 0;
            }
            for b in fb_naive.back_buffer.as_mut().unwrap().iter_mut() {
                *b = 0;
            }
        }
        let color = Color::with_alpha(1, 2, 3, 255);
        fb_opt.draw_vline(1, 0, 5, color);

        let back_ref = fb_opt.back_buffer.as_ref().unwrap();
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

        let cases = [(0, 0, 15, 3), (0, 0, 3, 15), (15, 0, 0, 15), (2, 14, 13, 4)];

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
    fn test_write_opaque_run_24bit_even_odd_mmio() {
        use crate::graphics::image::Image;

        let width = 5u32;
        let height = 1u32;
        let mut img = Image::new(width, height);

        // Set distinct colors per pixel
        let cols = [
            Color::with_alpha(1, 2, 3, 255),
            Color::with_alpha(4, 5, 6, 255),
            Color::with_alpha(7, 8, 9, 255),
            Color::with_alpha(10, 11, 12, 255),
            Color::with_alpha(13, 14, 15, 255),
        ];

        for x in 0..width {
            img.set_pixel(x, 0, cols[x as usize]);
        }

        let info = FramebufferInfo {
            address: 0,
            width,
            height,
            stride: width * 3,
            format: PixelFormat::Bgr888,
            bpp: 24,
        };

        // MMIO path
        let mut mem = vec![0u8; info.size()];
        let addr = mem.as_mut_ptr() as u64;
        let mut info2 = info.clone();
        info2.address = addr;
        let mut fb = unsafe { Framebuffer::new(info2) };
        fb.draw_image(&img, 0, 0);

        for x in 0..(width as usize) {
            let off = x * 3;
            let c = cols[x];
            assert_eq!(mem[off], c.blue);
            assert_eq!(mem[off + 1], c.green);
            assert_eq!(mem[off + 2], c.red);
        }

        // Backbuffer path
        let mut fb2 = unsafe { Framebuffer::new(info.clone()) };
        let back = vec![0u8; info.size()];
        fb2.enable_double_buffering_from_vec(back);
        fb2.draw_image(&img, 0, 0);
        let back_ref = fb2.back_buffer.as_ref().unwrap();
        for x in 0..(width as usize) {
            let off = x * 3;
            let c = cols[x];
            assert_eq!(back_ref[off], c.blue);
            assert_eq!(back_ref[off + 1], c.green);
            assert_eq!(back_ref[off + 2], c.red);
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

            unsafe {
                Framebuffer::pack_rgba_to_bgra_ssse3(
                    src.as_ptr(),
                    dst_simd.as_mut_ptr(),
                    src.len(),
                );
            }
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

            unsafe {
                Framebuffer::pack_rgba_to_bgra_avx2(src.as_ptr(), dst_avx.as_mut_ptr(), src.len());
            }
            Framebuffer::pack_rgba_to_bgra_scalar(&src, &mut dst_scalar);

            assert_eq!(dst_avx, dst_scalar);
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_pack_rgba_to_bgr24_avx2_matches_scalar() {
        // Only run AVX2 check when available
        if !std::is_x86_feature_detected!("avx2") {
            return;
        }

        // 8 pixels (24 bytes) input
        let len = 8usize;
        let mut src = vec![0u8; len * 4];
        for i in 0..src.len() {
            src[i] = (i * 97 % 251) as u8;
        }
        let mut dst_simd = vec![0u8; len * 3];
        unsafe {
            Framebuffer::pack_rgba_to_bgr24_avx2_8pixels(src.as_ptr(), dst_simd.as_mut_ptr(), true);
        }

        // scalar pack
        let mut dst_scalar = vec![0u8; len * 3];
        for p in 0..len {
            let s = p * 4;
            dst_scalar[p * 3] = src[s + 2];
            dst_scalar[p * 3 + 1] = src[s + 1];
            dst_scalar[p * 3 + 2] = src[s + 0];
        }

        assert_eq!(dst_simd, dst_scalar);
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_pack_rgba_to_bgr24_ssse3_matches_scalar() {
        if !std::is_x86_feature_detected!("ssse3") {
            return;
        }

        let len = 8usize;
        let mut src = vec![0u8; len * 4];
        for i in 0..src.len() {
            src[i] = (i * 61 % 251) as u8;
        }
        let mut dst_simd = vec![0u8; len * 3];
        unsafe {
            Framebuffer::pack_rgba_to_bgr24_ssse3_8pixels(
                src.as_ptr(),
                dst_simd.as_mut_ptr(),
                true,
            );
        }

        let mut dst_scalar = vec![0u8; len * 3];
        for p in 0..len {
            let s = p * 4;
            dst_scalar[p * 3] = src[s + 2];
            dst_scalar[p * 3 + 1] = src[s + 1];
            dst_scalar[p * 3 + 2] = src[s + 0];
        }

        assert_eq!(dst_simd, dst_scalar);
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

            unsafe {
                Framebuffer::pack_rgba_to_bgra_neon(src.as_ptr(), dst_neon.as_mut_ptr(), src.len());
            }
            Framebuffer::pack_rgba_to_bgra_scalar(&src, &mut dst_scalar);

            assert_eq!(dst_neon, dst_scalar);
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_pack_rgba_to_bgr24_neon_matches_scalar() {
        // Only run NEON check when available
        if !std::is_aarch64_feature_detected!("neon") {
            return;
        }

        let len = 8usize;
        let mut src = vec![0u8; len * 4];
        for i in 0..src.len() {
            src[i] = (i * 97 % 251) as u8;
        }
        let mut dst_simd = vec![0u8; len * 3];
        unsafe {
            Framebuffer::pack_rgba_to_bgr24_neon_8pixels(src.as_ptr(), dst_simd.as_mut_ptr(), true);
        }

        let mut dst_scalar = vec![0u8; len * 3];
        for p in 0..len {
            let s = p * 4;
            dst_scalar[p * 3] = src[s + 2];
            dst_scalar[p * 3 + 1] = src[s + 1];
            dst_scalar[p * 3 + 2] = src[s + 0];
        }

        assert_eq!(dst_simd, dst_scalar);
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_pack_rgba_to_bgr24_neon_matches_scalar_rgb() {
        if !std::is_aarch64_feature_detected!("neon") {
            return;
        }

        let len = 8usize;
        let mut src = vec![0u8; len * 4];
        for i in 0..src.len() {
            src[i] = (i * 113 % 251) as u8;
        }
        let mut dst_simd = vec![0u8; len * 3];
        unsafe {
            Framebuffer::pack_rgba_to_bgr24_neon_8pixels(
                src.as_ptr(),
                dst_simd.as_mut_ptr(),
                false,
            );
        }

        let mut dst_scalar = vec![0u8; len * 3];
        // RGB order: r,g,b triplets
        for p in 0..len {
            let s = p * 4;
            dst_scalar[p * 3] = src[s + 0];
            dst_scalar[p * 3 + 1] = src[s + 1];
            dst_scalar[p * 3 + 2] = src[s + 2];
        }

        assert_eq!(dst_simd, dst_scalar);
    }

    #[test]
    fn test_pack_rgba_to_bgra_scalar_random() {
        // Randomized verification to guard against bit-twiddling regressions
        let mut src = vec![0u8; 256];
        for seed in 0..16u8 {
            for i in 0..src.len() {
                src[i] = (i.wrapping_mul(seed as usize) as u8).wrapping_add(i as u8);
            }
            let mut dst1 = vec![0u8; src.len()];
            let mut dst2 = vec![0u8; src.len()];

            // naive copy
            for p in 0..(src.len() / 4) {
                let s = p * 4;
                dst1[s] = src[s + 2];
                dst1[s + 1] = src[s + 1];
                dst1[s + 2] = src[s + 0];
                dst1[s + 3] = src[s + 3];
            }

            Framebuffer::pack_rgba_to_bgra_scalar(&src, &mut dst2);
            assert_eq!(dst1, dst2);
        }
    }

    #[test]
    fn test_draw_image_bgra_stream_matches_backbuffer() {
        use crate::graphics::image::Image;

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

    #[test]
    fn test_dirty_rect_tracking() {
        let width = 100u32;
        let height = 100u32;
        let info = FramebufferInfo {
            address: 0,
            width,
            height,
            stride: width * 4,
            format: PixelFormat::Bgra8888,
            bpp: 32,
        };

        let mut fb = unsafe { Framebuffer::new(info.clone()) };

        // Initial state: dirty_rect is None
        assert!(fb.dirty_rect.is_none());

        // Draw a pixel
        fb.set_pixel(10, 10, Color::RED);
        assert!(fb.dirty_rect.is_some());
        let d = fb.dirty_rect.unwrap();
        assert_eq!(d, Rect::new(10, 10, 1, 1));

        // Draw another pixel
        fb.set_pixel(20, 20, Color::BLUE);
        let d = fb.dirty_rect.unwrap();
        // Should be union of (10,10,1,1) and (20,20,1,1) -> (10,10, 11, 11)
        assert_eq!(d, Rect::new(10, 10, 11, 11));

        // Flush
        fb.flush_dirty_area();
        assert!(fb.dirty_rect.is_none());
    }

    #[test]
    fn test_dirty_rect_flush_only_marked_area() {
        // Verify that flush_dirty_area only copies the marked region
        let width = 10u32;
        let height = 10u32;
        let info = FramebufferInfo {
            address: 0,
            width,
            height,
            stride: width * 4,
            format: PixelFormat::Bgra8888,
            bpp: 32,
        };

        // Create a "VRAM" buffer
        let mut vram = vec![0u8; info.size()];
        let addr = vram.as_mut_ptr() as u64;
        let mut info2 = info.clone();
        info2.address = addr;

        let mut fb = unsafe { Framebuffer::new(info2) };
        let mut back = vec![0u8; info.size()];
        // Fill back buffer with white
        for i in 0..back.len() {
            back[i] = 255;
        }
        fb.enable_double_buffering_from_vec(back);

        // Clear vram to black (simulating initial state)
        for i in 0..vram.len() {
            vram[i] = 0;
        }

        // Mark a small area as dirty manually (to simulate drawing)
        // Let's modify back buffer at (5,5)
        let offset = (5 * 10 + 5) * 4;
        let dst = unsafe { fb.back_buffer.as_mut().unwrap().as_mut_ptr().add(offset) };
        unsafe {
            *dst = 0xAA;
            *dst.add(1) = 0xBB;
        }

        // Mark ONLY 1 pixel dirty
        fb.mark_dirty(Rect::new(5, 5, 1, 1));

        // Flush
        fb.flush_dirty_area();

        // Check that VRAM at (5,5) is updated
        assert_eq!(vram[offset], 0xAA);
        assert_eq!(vram[offset + 1], 0xBB);

        // Check that other VRAM areas are STILL 0 (not overwritten by the 255s in backbuffer)
        // e.g. (0,0)
        assert_eq!(vram[0], 0);
    }

    #[test]
    fn test_draw_text_partial_left_clip_32bit_backbuffer() {
        // Draw a '!' partially off the left edge and ensure visible pixels
        // come from the glyph foreground where expected.
        let width = 6u32;
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

        let fg = Color::with_alpha(10, 20, 30, 255);
        let bg = Color::with_alpha(100, 110, 120, 255);

        // Position the char at x = -3 so that glyph columns 3 and 4 map to
        // framebuffer x = 0 and x = 1 respectively for row where '!' has
        // bits (font row index 2 contains 0x18 => bits at cols 3 and 4).
        fb.draw_text(-3, 0, "!", fg, bg);

        let stride = info.stride as usize;
        let row = 2usize;
        let off0 = row * stride + 0 * 4;
        let off1 = row * stride + 1 * 4;
        let off2 = row * stride + 2 * 4;

        let back_ref = fb.back_buffer.as_ref().unwrap();

        // px 0 should be fg (column 3 of glyph)
        assert_eq!(back_ref[off0], fg.blue);
        assert_eq!(back_ref[off0 + 1], fg.green);
        assert_eq!(back_ref[off0 + 2], fg.red);

        // px 1 should be fg (column 4 of glyph)
        assert_eq!(back_ref[off1], fg.blue);
        assert_eq!(back_ref[off1 + 1], fg.green);
        assert_eq!(back_ref[off1 + 2], fg.red);

        // px 2 should be background
        assert_eq!(back_ref[off2], bg.blue);
        assert_eq!(back_ref[off2 + 1], bg.green);
        assert_eq!(back_ref[off2 + 2], bg.red);
    }
}

unsafe impl Send for Framebuffer {}
unsafe impl Sync for Framebuffer {}

impl Framebuffer {
    /// 新しいフレームバッファを作成
    pub unsafe fn new(info: FramebufferInfo) -> Self {
        let clip = Rect::new(0, 0, info.width, info.height);
        // Compute sizes before moving `info` into the struct
        let width_usize = info.width as usize;
        Self {
            buffer: info.address as *mut u8,
            info,
            back_buffer: None,
            clip,
            scratch_u8: Vec::with_capacity(width_usize * 4),
            scratch_u32: Vec::with_capacity(width_usize),
            dirty_rect: None,
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

        unsafe { Self::new(info) }
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
            #[cfg(target_endian = "little")]
            {
                let v0 = unsafe { core::ptr::read_unaligned(data.as_ptr().add(i) as *const u64) };
                let v1 =
                    unsafe { core::ptr::read_unaligned(data.as_ptr().add(i + 8) as *const u64) };
                let v2 =
                    unsafe { core::ptr::read_unaligned(data.as_ptr().add(i + 16) as *const u64) };
                let v3 =
                    unsafe { core::ptr::read_unaligned(data.as_ptr().add(i + 24) as *const u64) };
                mmio::mmio_write_u64(ptr, v0);
                mmio::mmio_write_u64(ptr + 8, v1);
                mmio::mmio_write_u64(ptr + 16, v2);
                mmio::mmio_write_u64(ptr + 24, v3);
            }
            #[cfg(not(target_endian = "little"))]
            {
                let v0 = u64::from_le_bytes([
                    data[i],
                    data[i + 1],
                    data[i + 2],
                    data[i + 3],
                    data[i + 4],
                    data[i + 5],
                    data[i + 6],
                    data[i + 7],
                ]);
                let v1 = u64::from_le_bytes([
                    data[i + 8],
                    data[i + 9],
                    data[i + 10],
                    data[i + 11],
                    data[i + 12],
                    data[i + 13],
                    data[i + 14],
                    data[i + 15],
                ]);
                let v2 = u64::from_le_bytes([
                    data[i + 16],
                    data[i + 17],
                    data[i + 18],
                    data[i + 19],
                    data[i + 20],
                    data[i + 21],
                    data[i + 22],
                    data[i + 23],
                ]);
                let v3 = u64::from_le_bytes([
                    data[i + 24],
                    data[i + 25],
                    data[i + 26],
                    data[i + 27],
                    data[i + 28],
                    data[i + 29],
                    data[i + 30],
                    data[i + 31],
                ]);
                mmio::mmio_write_u64(ptr, v0);
                mmio::mmio_write_u64(ptr + 8, v1);
                mmio::mmio_write_u64(ptr + 16, v2);
                mmio::mmio_write_u64(ptr + 24, v3);
            }
            ptr += 32;
            i += 32;
        }

        while i + 8 <= len {
            #[cfg(target_endian = "little")]
            {
                let v = unsafe { core::ptr::read_unaligned(data.as_ptr().add(i) as *const u64) };
                mmio::mmio_write_u64(ptr, v);
            }
            #[cfg(not(target_endian = "little"))]
            {
                let v = u64::from_le_bytes([
                    data[i],
                    data[i + 1],
                    data[i + 2],
                    data[i + 3],
                    data[i + 4],
                    data[i + 5],
                    data[i + 6],
                    data[i + 7],
                ]);
                mmio::mmio_write_u64(ptr, v);
            }
            ptr += 8;
            i += 8;
        }

        // Remaining u32-aligned writes; unroll 4 at a time
        while i + 16 <= len {
            #[cfg(target_endian = "little")]
            {
                let v0 = unsafe { core::ptr::read_unaligned(data.as_ptr().add(i) as *const u32) };
                let v1 =
                    unsafe { core::ptr::read_unaligned(data.as_ptr().add(i + 4) as *const u32) };
                let v2 =
                    unsafe { core::ptr::read_unaligned(data.as_ptr().add(i + 8) as *const u32) };
                let v3 =
                    unsafe { core::ptr::read_unaligned(data.as_ptr().add(i + 12) as *const u32) };
                mmio::mmio_write_u32(ptr, v0);
                mmio::mmio_write_u32(ptr + 4, v1);
                mmio::mmio_write_u32(ptr + 8, v2);
                mmio::mmio_write_u32(ptr + 12, v3);
            }
            #[cfg(not(target_endian = "little"))]
            {
                let v0 = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
                let v1 = u32::from_le_bytes([data[i + 4], data[i + 5], data[i + 6], data[i + 7]]);
                let v2 = u32::from_le_bytes([data[i + 8], data[i + 9], data[i + 10], data[i + 11]]);
                let v3 =
                    u32::from_le_bytes([data[i + 12], data[i + 13], data[i + 14], data[i + 15]]);
                mmio::mmio_write_u32(ptr, v0);
                mmio::mmio_write_u32(ptr + 4, v1);
                mmio::mmio_write_u32(ptr + 8, v2);
                mmio::mmio_write_u32(ptr + 12, v3);
            }
            ptr += 16;
            i += 16;
        }

        while i + 4 <= len {
            #[cfg(target_endian = "little")]
            {
                let v = unsafe { core::ptr::read_unaligned(data.as_ptr().add(i) as *const u32) };
                mmio::mmio_write_u32(ptr, v);
            }
            #[cfg(not(target_endian = "little"))]
            {
                let v = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
                mmio::mmio_write_u32(ptr, v);
            }
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
        // Process in pixel-based chunks to allow direct u32 writes. Default
        // chunk size is 512 pixels (2048 bytes); bench runs may override this
        // via the `RANY_CHUNK_PIXELS` environment variable for tuning.
        #[cfg(all(feature = "std", feature = "bench"))]
        let chunk_pixels: usize = std::env::var("RANY_CHUNK_PIXELS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(512);
        #[cfg(not(all(feature = "std", feature = "bench")))]
        let chunk_pixels: usize = 512;

        if src.is_empty() {
            return;
        }

        let total_pixels = src.len() / 4;
        let mut processed_pixels = 0usize;

        while processed_pixels < total_pixels {
            let remaining_pixels = total_pixels - processed_pixels;
            let chunk_pixels = core::cmp::min(chunk_pixels, remaining_pixels);

            // Ensure a u32-backed scratch buffer for this chunk
            self.ensure_scratch_u32(chunk_pixels);
            let src_offset = processed_pixels * 4;

            {
                // Mutable borrow scope for packer
                let src_chunk = &src[src_offset..src_offset + chunk_pixels * 4];
                let dst_bytes = unsafe {
                    core::slice::from_raw_parts_mut(
                        self.scratch_u32.as_mut_ptr() as *mut u8,
                        chunk_pixels * 4,
                    )
                };
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
        use core::sync::atomic::Ordering;

        // Quick scalar path for very small buffers to avoid SIMD call/dispatch overhead.
        // Keep this small so streaming chunks (e.g., 1024 bytes) still use SIMD.
        #[cfg(feature = "std")]
        let small_bytes_threshold: usize = std::env::var("RANY_SMALL_BYTES_THRESHOLD")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(256);
        #[cfg(not(feature = "std"))]
        let small_bytes_threshold: usize = 256;
        if bytes <= small_bytes_threshold {
            Self::pack_rgba_to_bgra_scalar(src, dst);
            return;
        }

        // Runtime-detected, cached packer selection to minimize dispatch overhead.
        // 0 = unknown, 1 = scalar, 2 = ssse3, 3 = avx2, 4 = neon
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            // Use module-level PACKER_MODE static declared at file scope
            let mut mode = PACKER_MODE.load(Ordering::Relaxed);

            // Allow environment override for deterministic benching / CI.
            #[cfg(feature = "std")]
            if let Ok(val) = std::env::var("RANY_PACKER") {
                // Accept names or numeric values
                let forced = match val.to_ascii_lowercase().as_str() {
                    "scalar" => Some(1u8),
                    "ssse3" => Some(2u8),
                    "avx2" => Some(3u8),
                    "neon" => Some(4u8),
                    s => s.parse::<u8>().ok(),
                };
                if let Some(f) = forced {
                    PACKER_MODE.store(f, Ordering::Relaxed);
                    mode = f;
                }
            }

            if mode == 0 {
                // Detect in first call only. In bench/test builds we run a tiny
                // micro-benchmark to pick the fastest implementation on the
                // current hardware (AVX2 can be slower on some CPUs due to
                // frequency/thermal effects). For regular builds prefer the
                // safe scalar path to avoid runtime feature probing.
                #[cfg(not(any(test, feature = "bench")))]
                {
                    mode = 1; // stable scalar-only builds
                }

                #[cfg(test)]
                {
                    // Simple feature-based detection during normal unit tests.
                    #[cfg(feature = "std")]
                    if std::is_x86_feature_detected!("avx2") {
                        mode = 3;
                    } else if std::is_x86_feature_detected!("ssse3") {
                        mode = 2;
                    } else {
                        mode = 1;
                    }
                    #[cfg(not(feature = "std"))]
                    {
                        mode = 1;
                    }
                }

                // Micro-benchmarking: only run when the crate is built with the
                // `bench` feature (so CI/bench runs can opt-in) to avoid
                // non-deterministic runtime probing in normal builds.
                #[cfg(all(feature = "std", feature = "bench"))]
                {
                    use std::time::Instant;

                    // Small deterministic sample for micro-benchmarking (4k
                    // pixels, 16 KiB). Keep runs small to avoid long startup
                    // cost while still giving a meaningful signal.
                    const SAMPLE_BYTES: usize = 16 * 1024;
                    let mut src_sample = vec![0u8; SAMPLE_BYTES];
                    for i in 0..SAMPLE_BYTES {
                        src_sample[i] = (i * 73 % 251) as u8;
                    }

                    // Baseline: scalar
                    let mut dst = vec![0u8; SAMPLE_BYTES];
                    let mut best = 1u8;
                    let mut best_time = core::time::Duration::MAX;
                    {
                        let mut m = core::time::Duration::MAX;
                        for _ in 0..2 {
                            let s = Instant::now();
                            Self::pack_rgba_to_bgra_scalar(&src_sample, &mut dst);
                            let d = s.elapsed();
                            if d < m {
                                m = d;
                            }
                        }
                        best_time = m;
                    }

                    // SSSE3 candidate
                    if std::is_x86_feature_detected!("ssse3") {
                        let mut dst_s = vec![0u8; SAMPLE_BYTES];
                        // warm-up
                        unsafe {
                            Self::pack_rgba_to_bgra_ssse3(
                                src_sample.as_ptr(),
                                dst_s.as_mut_ptr(),
                                SAMPLE_BYTES,
                            );
                        }
                        let mut m = core::time::Duration::MAX;
                        for _ in 0..2 {
                            let s = Instant::now();
                            unsafe {
                                Self::pack_rgba_to_bgra_ssse3(
                                    src_sample.as_ptr(),
                                    dst_s.as_mut_ptr(),
                                    SAMPLE_BYTES,
                                );
                            }
                            let d = s.elapsed();
                            if d < m {
                                m = d;
                            }
                        }
                        if m < best_time {
                            best_time = m;
                            best = 2;
                        }
                    }

                    // AVX2 candidate
                    if std::is_x86_feature_detected!("avx2") {
                        let mut dst_a = vec![0u8; SAMPLE_BYTES];
                        // warm-up
                        unsafe {
                            Self::pack_rgba_to_bgra_avx2(
                                src_sample.as_ptr(),
                                dst_a.as_mut_ptr(),
                                SAMPLE_BYTES,
                            );
                        }
                        let mut m = core::time::Duration::MAX;
                        for _ in 0..2 {
                            let s = Instant::now();
                            unsafe {
                                Self::pack_rgba_to_bgra_avx2(
                                    src_sample.as_ptr(),
                                    dst_a.as_mut_ptr(),
                                    SAMPLE_BYTES,
                                );
                            }
                            let d = s.elapsed();
                            if d < m {
                                m = d;
                            }
                        }
                        if m < best_time {
                            best_time = m;
                            best = 3;
                        }
                    }

                    mode = best;
                }

                PACKER_MODE.store(mode, Ordering::Relaxed);
            }

            match mode {
                3 => unsafe {
                    Self::pack_rgba_to_bgra_avx2(src.as_ptr(), dst.as_mut_ptr(), bytes);
                },
                2 => unsafe {
                    Self::pack_rgba_to_bgra_ssse3(src.as_ptr(), dst.as_mut_ptr(), bytes);
                },
                _ => Self::pack_rgba_to_bgra_scalar(src, dst),
            }
            return;
        }

        #[cfg(target_arch = "aarch64")]
        {
            // Use module-level PACKER_MODE static
            let mut mode = PACKER_MODE.load(Ordering::Relaxed);
            if mode == 0 {
                #[cfg(feature = "std")]
                {
                    if std::is_aarch64_feature_detected!("neon") {
                        mode = 4;
                    } else {
                        mode = 1;
                    }
                }
                #[cfg(not(feature = "std"))]
                {
                    mode = 1;
                }
                PACKER_MODE.store(mode, Ordering::Relaxed);
            }

            match mode {
                4 => unsafe {
                    Self::pack_rgba_to_bgra_neon(src.as_ptr(), dst.as_mut_ptr(), bytes);
                },
                _ => Self::pack_rgba_to_bgra_scalar(src, dst),
            }
            return;
        }

        // Fallback scalar for other platforms
        Self::pack_rgba_to_bgra_scalar(src, dst);
    }

    /// Query AVX2 availability once and cache result to avoid repeated
    /// CPUID calls. Only used on x86-family builds and when `std` is
    /// available for runtime detection.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_avx2_available() -> bool {
        use core::sync::atomic::Ordering;
        let v = AVX2_AVAILABLE.load(Ordering::Relaxed);
        if v == 0 {
            #[cfg(feature = "std")]
            {
                let avail = std::is_x86_feature_detected!("avx2");
                AVX2_AVAILABLE.store(if avail { 2 } else { 1 }, Ordering::Relaxed);
                avail
            }
            #[cfg(not(feature = "std"))]
            {
                AVX2_AVAILABLE.store(1, Ordering::Relaxed);
                false
            }
        } else {
            v == 2
        }
    }

    /// Scalar packer implementation (public so benches can call it directly).
    #[inline(always)]
    pub fn pack_rgba_to_bgra_scalar(src: &[u8], dst: &mut [u8]) {
        let pixels = core::cmp::min(src.len(), dst.len()) / 4;
        let bytes = pixels * 4;

        // Fast scalar path: operate on u32 words using bit manipulations to
        // swap the R and B bytes in each 32-bit lane. Unroll two pixels at a
        // time to reduce loop overhead.
        let mut i = 0usize;

        // Process two pixels at a time and write as a single u64 when
        // possible. This reduces the number of memory writes and loop
        // overhead compared to writing two u32 values separately.
        // Process 16-byte blocks by computing four swapped u32 words and
        // emitting as two u64 unaligned writes. This halves the number of
        // memory writes compared to four separate u32 writes.
        while i + 16 <= bytes {
            let v0 = unsafe { core::ptr::read_unaligned(src.as_ptr().add(i) as *const u32) };
            let v1 = unsafe { core::ptr::read_unaligned(src.as_ptr().add(i + 4) as *const u32) };
            let v2 = unsafe { core::ptr::read_unaligned(src.as_ptr().add(i + 8) as *const u32) };
            let v3 = unsafe { core::ptr::read_unaligned(src.as_ptr().add(i + 12) as *const u32) };

            let s0 = (v0 & 0xFF00FF00) | ((v0 & 0x000000FF) << 16) | ((v0 & 0x00FF0000) >> 16);
            let s1 = (v1 & 0xFF00FF00) | ((v1 & 0x000000FF) << 16) | ((v1 & 0x00FF0000) >> 16);
            let s2 = (v2 & 0xFF00FF00) | ((v2 & 0x000000FF) << 16) | ((v2 & 0x00FF0000) >> 16);
            let s3 = (v3 & 0xFF00FF00) | ((v3 & 0x000000FF) << 16) | ((v3 & 0x00FF0000) >> 16);

            let p0 = (s0 as u64) | ((s1 as u64) << 32);
            let p1 = (s2 as u64) | ((s3 as u64) << 32);

            unsafe {
                core::ptr::write_unaligned(dst.as_mut_ptr().add(i) as *mut u64, p0);
                core::ptr::write_unaligned(dst.as_mut_ptr().add(i + 8) as *mut u64, p1);
            }
            i += 16;
        }

        while i + 8 <= bytes {
            let v0 = unsafe { core::ptr::read_unaligned(src.as_ptr().add(i) as *const u32) };
            let v1 = unsafe { core::ptr::read_unaligned(src.as_ptr().add(i + 4) as *const u32) };
            let s0 = (v0 & 0xFF00FF00) | ((v0 & 0x000000FF) << 16) | ((v0 & 0x00FF0000) >> 16);
            let s1 = (v1 & 0xFF00FF00) | ((v1 & 0x000000FF) << 16) | ((v1 & 0x00FF0000) >> 16);
            let p = (s0 as u64) | ((s1 as u64) << 32);
            unsafe {
                core::ptr::write_unaligned(dst.as_mut_ptr().add(i) as *mut u64, p);
            }
            i += 8;
        }

        while i + 4 <= bytes {
            let v = unsafe { core::ptr::read_unaligned(src.as_ptr().add(i) as *const u32) };
            let swapped = (v & 0xFF00FF00) | ((v & 0x000000FF) << 16) | ((v & 0x00FF0000) >> 16);
            unsafe {
                core::ptr::write_unaligned(dst.as_mut_ptr().add(i) as *mut u32, swapped);
            }
            i += 4;
        }
    }

    /// AVX2 implementation (unsafe). Processes 32-byte blocks using 256-bit
    /// byte shuffles and falls back to SSSE3 / scalar for tails.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[target_feature(enable = "avx2")]
    unsafe fn pack_rgba_to_bgra_avx2(src: *const u8, dst: *mut u8, bytes: usize) {
        unsafe {
            use core::arch::x86_64::*;
            // 32-byte shuffle mask: for each 4-byte lane [r,g,b,a] -> [b,g,r,a]
            let mask = _mm256_setr_epi8(
                2, 1, 0, 3, 6, 5, 4, 7, 10, 9, 8, 11, 14, 13, 12, 15, 18, 17, 16, 19, 22, 21, 20,
                23, 26, 25, 24, 27, 30, 29, 28, 31,
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
    }

    /// AVX2 helper: pack exactly 8 RGBA pixels (32 bytes) into 24 BGR bytes.
    /// `is_bgr` selects whether output order is BGR (true) or RGB (false).
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[target_feature(enable = "avx2")]
    unsafe fn pack_rgba_to_bgr24_avx2_8pixels(src: *const u8, dst: *mut u8, is_bgr: bool) {
        use core::arch::x86_64::*;

        // Masks select bytes per 128-bit lane. For BGR each pixel maps [r,g,b,a] -> [b,g,r]
        let mask_bgr = _mm256_setr_epi8(
            2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1, 2, 1, 0, 6, 5, 4, 10, 9, 8, 14,
            13, 12, -1, -1, -1, -1,
        );

        // Masks for RGB ordering: [r,g,b]
        let mask_rgb = _mm256_setr_epi8(
            0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, -1, -1, -1, -1, 0, 1, 2, 4, 5, 6, 8, 9, 10, 12,
            13, 14, -1, -1, -1, -1,
        );

        let v = unsafe { _mm256_loadu_si256(src as *const __m256i) };
        let mask = if is_bgr { mask_bgr } else { mask_rgb };
        let shuffled = unsafe { _mm256_shuffle_epi8(v, mask) };

        // Extract lanes and write: store lane0 at dst, lane1 at dst+12 (overlap)
        let lane0 = unsafe { _mm256_extracti128_si256(shuffled, 0) };
        let lane1 = unsafe { _mm256_extracti128_si256(shuffled, 1) };

        // Store 24 bytes safely without overrunning the destination buffer:
        // - store low 8 bytes of lane0 -> dst[0..7]
        // - store next 8 bytes of lane0 -> dst[8..15]
        // - store low 4 bytes of lane1 -> dst[12..15] (overwrite middle)
        // - store low 8 bytes of lane1 -> dst[16..23]
        unsafe { _mm_storel_epi64(dst as *mut __m128i, lane0) };
        let lane0_hi = unsafe { _mm_srli_si128(lane0, 8) };
        unsafe { _mm_storel_epi64(dst.add(8) as *mut __m128i, lane0_hi) };

        // low 32 bits of lane1 -> bytes 12..15
        let low32 = unsafe { _mm_cvtsi128_si32(lane1) } as i32;
        unsafe { core::ptr::write_unaligned(dst.add(12) as *mut i32, low32) };

        // store bytes 16..23: use lane1 >> 4 bytes so we get r1[4..11]
        let lane1_shift = unsafe { _mm_srli_si128(lane1, 4) };
        unsafe { _mm_storel_epi64(dst.add(16) as *mut __m128i, lane1_shift) };
    }

    /// SSSE3 implementation of 8-pixel RGBA -> 24-byte BGR/RGB compression.
    /// Uses pshufb on 16-byte lanes and overlapping stores to emit 24 bytes.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[target_feature(enable = "ssse3")]
    unsafe fn pack_rgba_to_bgr24_ssse3_8pixels(src: *const u8, dst: *mut u8, is_bgr: bool) {
        use core::arch::x86_64::*;

        // Masks select bytes per 128-bit lane. For BGR each pixel maps [r,g,b,a] -> [b,g,r]
        let mask_bgr = _mm_setr_epi8(2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1);

        // Masks for RGB ordering: [r,g,b]
        let mask_rgb = _mm_setr_epi8(0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, -1, -1, -1, -1);

        let v0 = _mm_loadu_si128(src as *const __m128i);
        let v1 = _mm_loadu_si128(src.add(16) as *const __m128i);
        let mask = if is_bgr { mask_bgr } else { mask_rgb };
        let r0 = _mm_shuffle_epi8(v0, mask);
        let r1 = _mm_shuffle_epi8(v1, mask);

        // Store 24 bytes safely as described in AVX2 helper to avoid overruns
        _mm_storel_epi64(dst as *mut __m128i, r0);
        let r0_hi = _mm_srli_si128(r0, 8);
        _mm_storel_epi64(dst.add(8) as *mut __m128i, r0_hi);
        let low32 = _mm_cvtsi128_si32(r1) as i32;
        unsafe { core::ptr::write_unaligned(dst.add(12) as *mut i32, low32) };
        let r1_shift = _mm_srli_si128(r1, 4);
        _mm_storel_epi64(dst.add(16) as *mut __m128i, r1_shift);
    }

    /// NEON implementation (aarch64) for packing exactly 8 RGBA pixels into
    /// 24 BGR or RGB bytes. Implemented as a small, unrolled scalar loop for
    /// correctness initially; can be replaced with a table-based tbl variant
    /// later for better performance.
    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn pack_rgba_to_bgr24_neon_8pixels(src: *const u8, dst: *mut u8, is_bgr: bool) {
        use core::arch::aarch64::*;

        // Table masks: for each 16-byte lane pick bytes [2,1,0,6,5,4,10,9,8,14,13,12, -1,-1,-1,-1]
        // -1 (255) picks zero when using tbl/vqtbl intrinsics.
        let mask_bgr: [u8; 16] = [2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, 255, 255, 255, 255];
        let mask_rgb: [u8; 16] = [0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, 255, 255, 255, 255];

        let tbl = vld1q_u8(if is_bgr {
            mask_bgr.as_ptr()
        } else {
            mask_rgb.as_ptr()
        });

        // Load 8 pixels (32 bytes)
        let v0 = vld1q_u8(src as *const u8);
        let v1 = vld1q_u8(src.add(16) as *const u8);

        // Shuffle each 16-byte lane to compress RGBA->BGR triples
        // Use vqtbl1q_u8 to perform a byte-wise table lookup; out-of-range
        // indices (255) produce zero bytes (which we overwrite or ignore).
        let r0 = vqtbl1q_u8(v0, tbl);
        let r1 = vqtbl1q_u8(v1, tbl);

        // Store bytes safely as in SSSE3/AVX2 helpers:
        // - store low 8 bytes of r0 -> dst[0..7]
        // - store next 8 bytes of r0 -> dst[8..15]
        // - store low 4 bytes of r1 -> dst[12..15] (overwrite middle)
        // - store low 8 bytes of (r1 >> 4) -> dst[16..23]

        // dst[0..7]
        vst1_u8(dst, vget_low_u8(r0));
        // dst[8..15]
        let r0_hi = vextq_u8(r0, r0, 8);
        vst1_u8(dst.add(8), vget_low_u8(r0_hi));

        // materialize r1 into a temp buffer so we can copy the required slices
        let mut tmp: [u8; 16] = core::mem::MaybeUninit::uninit().assume_init();
        vst1q_u8(tmp.as_mut_ptr(), r1);

        // low 4 bytes of r1 -> dst[12..15]
        let low32 = u32::from_le_bytes([tmp[0], tmp[1], tmp[2], tmp[3]]);
        core::ptr::write_unaligned(dst.add(12) as *mut u32, low32);

        // dst[16..23] <- tmp[4..12]
        core::ptr::copy_nonoverlapping(tmp.as_ptr().add(4), dst.add(16), 8);
    }

    /// NEON implementation placeholder (aarch64). For now this falls back to
    /// a scalar loop for correctness; a NEON tbl-based implementation can be
    /// added later for further speedups.
    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn pack_rgba_to_bgra_neon(src: *const u8, dst: *mut u8, bytes: usize) {
        unsafe {
            use core::arch::aarch64::*;

            // Vectorized 32-bit lane byte-swizzle:
            // For each u32 lane (little-endian RGBA), produce BGRA by shifting
            // low and high byte lanes and OR-ing the parts.
            let mut i = 0usize;

            // Prepare masks once to avoid redundant vdupq calls in the loop
            let low_mask = vdupq_n_u32(0x000000FF);
            let mid_mask = vdupq_n_u32(0x0000FF00);
            let high_mask = vdupq_n_u32(0x00FF0000);
            let alpha_mask = vdupq_n_u32(0xFF000000);

            // Process 4 pixels (16 bytes) per iteration using 32-bit vector ops
            while i + 16 <= bytes {
                // Load 4 lanes (may be unaligned)
                let v = vld1q_u32(src.add(i) as *const u32);

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
                let swapped = ((p & 0x000000FF) << 16)
                    | (p & 0x0000FF00)
                    | ((p & 0x00FF0000) >> 16)
                    | (p & 0xFF000000);
                core::ptr::write_unaligned(dst.add(i) as *mut u32, swapped);
                i += 4;
            }
        }
    }

    /// SSSE3 implementation (unsafe). Processes `bytes` bytes (must be multiple
    /// of 4). Uses pshufb to permute bytes inside 16-byte lanes.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[target_feature(enable = "ssse3")]
    unsafe fn pack_rgba_to_bgra_ssse3(src: *const u8, dst: *mut u8, bytes: usize) {
        unsafe {
            use core::arch::x86_64::*;

            // shuffle mask: for each 4-byte lane [r,g,b,a] -> [b,g,r,a]
            let mask = _mm_setr_epi8(2, 1, 0, 3, 6, 5, 4, 7, 10, 9, 8, 11, 14, 13, 12, 15);

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
        // Small-run fast-path for MMIO: avoid preparing a large scratch buffer
        // when the run is short (reduces overhead for short lines). The
        // threshold is tunable via `RANY_SMALL_BGR_DIRECT_MMIO` in bench runs.
        #[inline]
        fn small_bgr_direct_threshold() -> usize {
            #[cfg(all(feature = "std", feature = "bench"))]
            {
                std::env::var("RANY_SMALL_BGR_DIRECT_MMIO")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(16)
            }
            #[cfg(not(all(feature = "std", feature = "bench")))]
            {
                16
            }
        }

        if self.back_buffer.is_none() && run_len_pixels <= small_bgr_direct_threshold() {
            let addr = self.buffer as usize + dst_offset_bytes;
            if addr != 0 {
                // Architecture-specific fast-path: on x86-family, if the start
                // address is 4-byte aligned we can write pairs of pixels using
                // a single u32 + u16 for every two pixels (6 bytes total). This
                // reduces volatile write overhead from 6 to 2 per pair.
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                {
                    if (addr & 3) == 0 && run_len_pixels >= 2 {
                        let pairs = run_len_pixels / 2;
                        let pair_u32 = (b as u32)
                            | ((g as u32) << 8)
                            | ((r as u32) << 16)
                            | ((b as u32) << 24);
                        let pair_u16 = (g as u16) | ((r as u16) << 8);
                        let mut off = addr;
                        for _ in 0..pairs {
                            mmio::mmio_write_u32(off, pair_u32);
                            mmio::mmio_write_u16(off + 4, pair_u16);
                            off += 6;
                        }
                        if (run_len_pixels & 1) == 1 {
                            mmio::volatile_write::<u8>(off, b);
                            mmio::volatile_write::<u8>(off + 1, g);
                            mmio::volatile_write::<u8>(off + 2, r);
                        }
                        return;
                    }
                }

                // Generic fallback: per-pixel byte writes
                for i in 0..run_len_pixels {
                    let off = addr + i * 3;
                    mmio::volatile_write::<u8>(off, b);
                    mmio::volatile_write::<u8>(off + 1, g);
                    mmio::volatile_write::<u8>(off + 2, r);
                }
                return;
            }
        }

        // Large-run direct MMIO path: write repeated byte patterns directly
        // to MMIO using u64 writes when the run is long. The threshold is
        // tunable via `RANY_LARGE_BGR_DIRECT_MMIO` in bench builds.
        #[inline]
        fn large_bgr_direct_threshold() -> usize {
            #[cfg(all(feature = "std", feature = "bench"))]
            {
                // Increase default threshold: empirical benches showed
                // regressions for moderate-large runs (1k..8k). Use a
                // conservative default so most workloads use the
                // scratch+write_bytes_mmio path which is more stable.
                std::env::var("RANY_LARGE_BGR_DIRECT_MMIO")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(4096)
            }
            #[cfg(not(all(feature = "std", feature = "bench")))]
            {
                128
            }
        }

        if self.back_buffer.is_none() && run_len_pixels >= large_bgr_direct_threshold() {
            let mut addr = self.buffer as usize + dst_offset_bytes;
            if addr != 0 {
                let mut remaining = run_len_pixels * 3;

                // Align to 8-byte boundary by writing up to 7 initial bytes
                let align8 = addr & 7;
                let mut comp_idx = 0usize;
                let mut to_align_total = 0usize;
                if align8 != 0 {
                    let to_align = core::cmp::min(8 - align8, remaining);
                    to_align_total = to_align;
                    for i in 0..to_align {
                        let comp = match i % 3 {
                            0 => b,
                            1 => g,
                            _ => r,
                        };
                        mmio::volatile_write::<u8>(addr + i, comp);
                    }
                    addr += to_align;
                    remaining -= to_align;
                }
                comp_idx = to_align_total % 3;

                // Precompute 8-byte patterns for each possible component
                // starting index (0..2). This allows us to emit correctly
                // rotated 8-byte patterns for the repeating BGR stream
                // without rebuilding the pattern on every iteration.
                let mut patterns = [0u64; 3];
                for k in 0..3 {
                    let mut patt = 0u64;
                    for j in 0..8 {
                        let byte = match (k + j) % 3 {
                            0 => b,
                            1 => g,
                            _ => r,
                        } as u64;
                        patt |= byte << (8 * j);
                    }
                    patterns[k] = patt;
                }

                // Write groups of 24 bytes (three 8-byte patterns) when
                // possible. Writing three patterns per loop keeps the
                // component rotation aligned (24 % 3 == 0).
                while remaining >= 24 {
                    mmio::mmio_write_u64(addr, patterns[comp_idx % 3]);
                    mmio::mmio_write_u64(addr + 8, patterns[(comp_idx + 8) % 3]);
                    mmio::mmio_write_u64(addr + 16, patterns[(comp_idx + 16) % 3]);
                    addr += 24;
                    remaining -= 24;
                    // comp_idx cycles back to same value after +24
                }

                // Handle remaining full 8-byte blocks
                while remaining >= 8 {
                    mmio::mmio_write_u64(addr, patterns[comp_idx % 3]);
                    addr += 8;
                    remaining -= 8;
                    comp_idx = (comp_idx + 8) % 3;
                }

                // Handle remaining bytes
                while remaining > 0 {
                    let comp = match comp_idx % 3 {
                        0 => b,
                        1 => g,
                        _ => r,
                    };
                    mmio::volatile_write::<u8>(addr, comp);
                    addr += 1;
                    remaining -= 1;
                    comp_idx = (comp_idx + 1) % 3;
                }

                return;
            }
        }
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
                    ptr::copy(
                        self.scratch_u8.as_ptr(),
                        self.scratch_u8.as_mut_ptr().add(dst_offset),
                        copy_bytes,
                    );
                }
                filled += copy_pixels;
            }
        }

        if let Some(ref mut back) = self.back_buffer {
            unsafe {
                ptr::copy_nonoverlapping(
                    self.scratch_u8.as_ptr(),
                    back.as_mut_ptr().add(dst_offset_bytes),
                    total,
                );
            }
        } else {
            // MMIO path: write bytes using bulk u32 when possible
            let addr = self.buffer as usize + dst_offset_bytes;
            self.write_bytes_mmio(addr, &self.scratch_u8[..total]);
        }
    }

    /// Bench helper: expose targeted BGR run write for micro-bench timing.
    /// Only compiled when the `bench` feature is enabled.
    #[cfg(feature = "bench")]
    pub fn bench_write_bgr_run_pixels(
        &mut self,
        x: usize,
        y: usize,
        run_len_pixels: usize,
        color: Color,
    ) {
        let dst_offset = y * self.info.stride as usize + x * 3;
        self.write_bgr_run(dst_offset, run_len_pixels, color);
    }

    /// Bench helper: call internal write_bytes_mmio path directly.
    #[cfg(feature = "bench")]
    pub fn bench_write_bytes_mmio(&mut self, x: usize, y: usize, data: &[u8]) {
        let dst_offset = y * self.info.stride as usize + x * self.info.format.bytes_per_pixel();
        let addr = self.buffer as usize + dst_offset;
        // Call private method directly
        self.write_bytes_mmio(addr, data);
    }

    /// bitマスクを32bitカラーアレイに展開して書き込む（テキスト描画用）
    /// AVX2最適化のための構造を備えるが、現在はスカラ実装（unrolled loop & u64 writes）を使用。
    #[inline(always)]
    fn write_glyph_row_32bit(
        &mut self,
        bits: u8,
        dst_offset_bytes: usize,
        fg_u32: u32,
        bg_u32: u32,
    ) {
        let mut addr = self.buffer as usize + dst_offset_bytes;

        if let Some(ref mut back) = self.back_buffer {
            // Write to back buffer: pack into u64 writes to reduce the
            // number of memory operations compared to eight separate u32 writes.
            let base = unsafe { back.as_mut_ptr().add(dst_offset_bytes) } as *mut u8;
            unsafe {
                let s0 = if (bits & 0x80) != 0 { fg_u32 } else { bg_u32 };
                let s1 = if (bits & 0x40) != 0 { fg_u32 } else { bg_u32 };
                let s2 = if (bits & 0x20) != 0 { fg_u32 } else { bg_u32 };
                let s3 = if (bits & 0x10) != 0 { fg_u32 } else { bg_u32 };
                let s4 = if (bits & 0x08) != 0 { fg_u32 } else { bg_u32 };
                let s5 = if (bits & 0x04) != 0 { fg_u32 } else { bg_u32 };
                let s6 = if (bits & 0x02) != 0 { fg_u32 } else { bg_u32 };
                let s7 = if (bits & 0x01) != 0 { fg_u32 } else { bg_u32 };

                let v0 = (s0 as u64) | ((s1 as u64) << 32);
                let v1 = (s2 as u64) | ((s3 as u64) << 32);
                let v2 = (s4 as u64) | ((s5 as u64) << 32);
                let v3 = (s6 as u64) | ((s7 as u64) << 32);

                core::ptr::write_unaligned(base as *mut u64, v0);
                core::ptr::write_unaligned(base.add(8) as *mut u64, v1);
                core::ptr::write_unaligned(base.add(16) as *mut u64, v2);
                core::ptr::write_unaligned(base.add(24) as *mut u64, v3);
            }
        } else {
            // Write to MMIO using 64-bit writes where possible
            // 0x80 -> pixel 0, 0x40 -> pixel 1
            let p0 = if (bits & 0x80) != 0 { fg_u32 } else { bg_u32 };
            let p1 = if (bits & 0x40) != 0 { fg_u32 } else { bg_u32 };
            let v0 = (p0 as u64) | ((p1 as u64) << 32);
            mmio::mmio_write_u64(addr, v0);

            // 0x20 -> pixel 2, 0x10 -> pixel 3
            let p2 = if (bits & 0x20) != 0 { fg_u32 } else { bg_u32 };
            let p3 = if (bits & 0x10) != 0 { fg_u32 } else { bg_u32 };
            let v1 = (p2 as u64) | ((p3 as u64) << 32);
            mmio::mmio_write_u64(addr + 8, v1);

            // 0x08 -> pixel 4, 0x04 -> pixel 5
            let p4 = if (bits & 0x08) != 0 { fg_u32 } else { bg_u32 };
            let p5 = if (bits & 0x04) != 0 { fg_u32 } else { bg_u32 };
            let v2 = (p4 as u64) | ((p5 as u64) << 32);
            mmio::mmio_write_u64(addr + 16, v2);

            // 0x02 -> pixel 6, 0x01 -> pixel 7
            let p6 = if (bits & 0x02) != 0 { fg_u32 } else { bg_u32 };
            let p7 = if (bits & 0x01) != 0 { fg_u32 } else { bg_u32 };
            let v3 = (p6 as u64) | ((p7 as u64) << 32);
            mmio::mmio_write_u64(addr + 24, v3);
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

    /// 描画領域を「汚れ」としてマーク
    fn mark_dirty(&mut self, rect: Rect) {
        // クリップ領域との共通部分をとる
        let draw_rect = match rect.intersection(&self.clip) {
            Some(r) => r,
            None => return,
        };

        if !draw_rect.is_valid() {
            return;
        }

        if let Some(current) = self.dirty_rect {
            // 既存の汚れ領域とマージ（包含する矩形に拡張）
            self.dirty_rect = Some(current.union(&draw_rect));
        } else {
            self.dirty_rect = Some(draw_rect);
        }
    }

    /// 最適化されたバッファ転送
    pub fn flush_dirty_area(&mut self) {
        if let Some(rect) = self.dirty_rect.take() {
            // 全画面ではなく、汚れた部分だけを転送
            self.blit_rect(rect);
        }
    }

    /// バックバッファをフロントにコピー（全画面または汚れた部分）
    pub fn swap_buffers(&mut self) {
        if self.back_buffer.is_some() {
            self.flush_dirty_area();
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
                    let addr = self.buffer.add(offset) as usize;

                    // Use optimized per-format writers to leverage aligned MMIO
                    // write helpers where possible (u32/u64 writes) instead of
                    // a generic memcpy which may be suboptimal for volatile MMIO.
                    match bytes_per_pixel {
                        4 => {
                            let src_ptr = back.as_ptr().add(offset) as *const u32;
                            let src_slice = core::slice::from_raw_parts(src_ptr, w);
                            self.write_u32_slice_mmio(addr, src_slice);
                        }
                        3 => {
                            let src_bytes = &back[offset..offset + row_bytes];
                            self.write_bytes_mmio(addr, src_bytes);
                        }
                        _ => {
                            ptr::copy_nonoverlapping(
                                back.as_ptr().add(offset),
                                self.buffer.add(offset),
                                row_bytes,
                            );
                        }
                    }
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

        // Mark the single-pixel area as dirty first
        self.mark_dirty(Rect::new(x as i32, y as i32, 1, 1));

        self.set_pixel_raw(x as i32, y as i32, color);
    }

    /// Dirty Rectangle更新を行わない内部用メソッド
    fn set_pixel_raw(&mut self, x: i32, y: i32, color: Color) {
        // No debug printing in production; tests may provide diagnostics when needed
        let offset = (y as usize * self.info.stride as usize)
            + (x as usize * self.info.format.bytes_per_pixel());

        if let Some(ref mut back) = self.back_buffer {
            // Write to back buffer: use simple pointer writes (no volatile needed)
            unsafe {
                let ptr = back.as_mut_ptr().add(offset);
                match self.info.format {
                    PixelFormat::Bgra8888 | PixelFormat::Rgba8888 => {
                        *(ptr as *mut u32) = color.to_u32();
                    }
                    PixelFormat::Bgr888 | PixelFormat::Rgb888 => {
                        *ptr = color.blue;
                        *ptr.add(1) = color.green;
                        *ptr.add(2) = color.red;
                    }
                    PixelFormat::Rgb565 => {
                        let r = (color.red as u16 >> 3) & 0x1F;
                        let g = (color.green as u16 >> 2) & 0x3F;
                        let b = (color.blue as u16 >> 3) & 0x1F;
                        let pixel = (r << 11) | (g << 5) | b;
                        *(ptr as *mut u16) = pixel;
                    }
                }
            }
        } else {
            // Write to MMIO: use volatile writes via mmio module
            let buffer = self.buffer;

            // Safety check for tests or unmapped framebuffer
            if buffer.is_null() {
                return;
            }

            match self.info.format {
                PixelFormat::Bgra8888 | PixelFormat::Rgba8888 => unsafe {
                    let pixel_addr = buffer.add(offset) as usize;
                    mmio::mmio_write_u32(pixel_addr, color.to_u32());
                },
                PixelFormat::Bgr888 | PixelFormat::Rgb888 => unsafe {
                    let addr = buffer.add(offset) as usize;
                    mmio::volatile_write::<u8>(addr, color.blue);
                    mmio::volatile_write::<u8>(addr + 1, color.green);
                    mmio::volatile_write::<u8>(addr + 2, color.red);
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
        // Mark entire screen as dirty
        self.mark_dirty(Rect::new(0, 0, self.info.width, self.info.height));

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
        }
    }

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
    fn draw_hline_raw(&mut self, start_x: i32, end_x: i32, y: i32, color: Color) {
        let bytes_per_pixel = self.info.format.bytes_per_pixel();
        let stride = self.info.stride as usize;
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
                let r = (color.red as u16 >> 3) & 0x1F;
                let g = (color.green as u16 >> 2) & 0x3F;
                let b = (color.blue as u16 >> 3) & 0x1F;
                let pixel = (r << 11) | (g << 5) | b;
                if let Some(_) = self.back_buffer {
                    let base = self.draw_buffer();
                    for i in 0..run_len {
                        let off = offset + i * 2;
                        unsafe {
                            ptr::write(base.add(off) as *mut u16, pixel);
                        }
                    }
                } else {
                    let base_addr = self.draw_buffer() as usize;
                    for i in 0..run_len {
                        let off = base_addr + offset + i * 2;
                        unsafe {
                            mmio::mmio_write_u16(off, pixel);
                        }
                    }
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

    /// Dirty Rectangle更新を行わない垂直線描画（クリッピング済み前提）
    fn draw_vline_raw(&mut self, x: i32, start_y: i32, end_y: i32, color: Color) {
        let bytes_per_pixel = self.info.format.bytes_per_pixel();
        let stride = self.info.stride as usize;
        let x_off = x as usize;
        let run_len = (end_y - start_y + 1) as usize;

        match bytes_per_pixel {
            4 => {
                let color_u32 = color.to_u32();
                // Branch once: either write to back buffer (fast pointer writes)
                // or write via MMIO helper.
                if let Some(_) = self.back_buffer {
                    let base = self.draw_buffer();
                    for i in 0..run_len {
                        let y = (start_y as usize) + i;
                        let off = y * stride + x_off * 4;
                        unsafe {
                            ptr::write(base.add(off) as *mut u32, color_u32);
                        }
                    }
                } else {
                    let base_addr = self.draw_buffer() as usize;
                    for i in 0..run_len {
                        let y = (start_y as usize) + i;
                        let off = base_addr + y * stride + x_off * 4;
                        unsafe {
                            mmio::mmio_write_u32(off, color_u32);
                        }
                    }
                }
            }
            3 => {
                if let Some(_) = self.back_buffer {
                    let base = self.draw_buffer();
                    for i in 0..run_len {
                        let y = (start_y as usize) + i;
                        let off = y * stride + x_off * 3;
                        unsafe {
                            let ptr = base.add(off);
                            ptr::write(ptr, color.blue);
                            ptr::write(ptr.add(1), color.green);
                            ptr::write(ptr.add(2), color.red);
                        }
                    }
                } else {
                    let base_addr = self.draw_buffer() as usize;
                    for i in 0..run_len {
                        let y = (start_y as usize) + i;
                        let off = base_addr + y * stride + x_off * 3;
                        unsafe {
                            mmio::volatile_write(off, color.blue);
                            mmio::volatile_write(off + 1, color.green);
                            mmio::volatile_write(off + 2, color.red);
                        }
                    }
                }
            }
            2 => {
                let r = (color.red as u16 >> 3) & 0x1F;
                let g = (color.green as u16 >> 2) & 0x3F;
                let b = (color.blue as u16 >> 3) & 0x1F;
                let pixel = (r << 11) | (g << 5) | b;
                if let Some(_) = self.back_buffer {
                    let base = self.draw_buffer();
                    for i in 0..run_len {
                        let y = (start_y as usize) + i;
                        let off = y * stride + x_off * 2;
                        unsafe {
                            ptr::write(base.add(off) as *mut u16, pixel);
                        }
                    }
                } else {
                    let base_addr = self.draw_buffer() as usize;
                    for i in 0..run_len {
                        let y = (start_y as usize) + i;
                        let off = base_addr + y * stride + x_off * 2;
                        unsafe {
                            mmio::mmio_write_u16(off, pixel);
                        }
                    }
                }
            }
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
        let width = (max_x - min_x + 1) as u32;
        let height = (max_y - min_y + 1) as u32;

        self.mark_dirty(Rect::new(min_x, min_y, width, height));

        // We'll use Bresenham's algorithm but coalesce consecutive horizontal
        // runs into fast `draw_hline_raw` calls when possible to leverage bulk writers.
        let abs_dx = (x2 - x1).abs();
        let abs_dy = (y2 - y1).abs();

        // Heuristic: coalesce horizontal runs only for primarily-horizontal lines.
        if abs_dx < abs_dy {
            // Steep line: fallback to naive per-pixel algorithm to avoid extra
            // branching overhead when horizontal runs are uncommon.
            // Steep line: fallback to naive per-pixel algorithm to avoid extra
            // branching overhead when horizontal runs are uncommon.
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
                    // Ensure we only call raw write for pixels inside clip
                    if x >= self.clip.x
                        && x < self.clip.right()
                        && y >= self.clip.y
                        && y < self.clip.bottom()
                    {
                        self.set_pixel_raw(x, y, color);
                    }
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
        } else {
            // Primarily horizontal
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
                        // Single-pixel run: ensure it's inside clip before raw write
                        if x >= self.clip.x
                            && x < self.clip.right()
                            && y >= self.clip.y
                            && y < self.clip.bottom()
                        {
                            self.set_pixel_raw(x, y, color);
                        }
                    } else {
                        // Normalize coordinates
                        let (s, e) = if sx > 0 {
                            (run_start, run_start + (run_len as i32 - 1))
                        } else {
                            (run_start - (run_len as i32 - 1), run_start)
                        };
                        // Clip horizontally to avoid writing out of bounds
                        if run_y >= self.clip.y && run_y < self.clip.bottom() {
                            let clip_left = self.clip.x;
                            let clip_right_incl = self.clip.right() - 1;
                            let s_clamped = s.max(clip_left).min(clip_right_incl);
                            let e_clamped = e.max(clip_left).min(clip_right_incl);
                            if s_clamped <= e_clamped {
                                self.draw_hline_raw(s_clamped, e_clamped, run_y, color);
                            }
                        }
                    }
                    break;
                }

                let e2 = 2 * err;
                if e2 >= dy {
                    err += dy;
                    x += sx;
                    // X changed.
                    // If Y also changes (diagonal step) or just X changes?
                    // Bresenham logic:
                    // if e2 >= dy { err += dy; x += sx; }
                    // if e2 <= dx { err += dx; y += sy; }
                    // If ONLY x changes, we extend run.
                    // If y changes, we flush run.
                }

                let y_changed = if e2 <= dx {
                    err += dx;
                    y += sy;
                    true
                } else {
                    false
                };

                if y_changed {
                    // Flush current run
                    if run_len == 1 {
                        // Ensure single-pixel run is within clip before raw write
                        if run_start >= self.clip.x
                            && run_start < self.clip.right()
                            && run_y >= self.clip.y
                            && run_y < self.clip.bottom()
                        {
                            self.set_pixel_raw(run_start, run_y, color);
                        }
                    } else {
                        let (s, e) = if sx > 0 {
                            (run_start, run_start + (run_len as i32 - 1))
                        } else {
                            (run_start - (run_len as i32 - 1), run_start)
                        };
                        // Clip run to prevent out-of-bounds writes
                        if run_y >= self.clip.y && run_y < self.clip.bottom() {
                            let clip_left = self.clip.x;
                            let clip_right_incl = self.clip.right() - 1;
                            let s_clamped = s.max(clip_left).min(clip_right_incl);
                            let e_clamped = e.max(clip_left).min(clip_right_incl);
                            if s_clamped <= e_clamped {
                                self.draw_hline_raw(s_clamped, e_clamped, run_y, color);
                            }
                        }
                    }
                    // Start new run
                    run_start = x;
                    run_y = y;
                    run_len = 1;
                } else {
                    // Only X changed, extend run
                    run_len += 1;
                }
            }
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

        // Mark destination dirty
        self.mark_dirty(Rect::new(d_x, d_y, s.width, s.height));

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

        // Mark dirty
        self.mark_dirty(r);

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
                        let row_slice =
                            unsafe { core::slice::from_raw_parts_mut(row_ptr, r.width as usize) };
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
        // First fill the background rectangle for the whole text span. This
        // leverages the optimized `fill_rect` path for broad formats.
        let char_count = text.chars().filter(|&c| c != '\n').count() as u32;
        if char_count == 0 {
            return;
        }

        let text_w = char_count * font.width() as u32;
        let text_h = font.height() as u32;

        // Mark dirty (background + foreground)
        self.mark_dirty(Rect::new(x, y, text_w, text_h));

        self.fill_rect(Rect::new(x, y, text_w, text_h), bg_color);

        // Now draw glyph foreground pixels in runs to minimize per-pixel writes.
        let stride = self.info.stride as usize;
        let bpp = self.info.format.bytes_per_pixel();

        // Optimized path for 32-bit formats (RGBA/BGRA)
        if bpp == 4 {
            let fg_u32 = color.to_u32();
            let bg_u32 = bg_color.to_u32();

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

                // Determine clipping for this character
                let char_x = cx;
                let char_w = font.width() as i32; // Assuming 8

                // Simple clipping check: if fully visible and aligned to 8 pixels?
                // Actually, `write_glyph_row_32bit` handles 8 pixels.
                // We just need to check if the char is fully within clip on X axis
                // to avoid per-pixel clipping logic.
                if char_x >= self.clip.x && (char_x + char_w) <= self.clip.right() {
                    // Fully visible horizontally
                    for row in 0..font.height() {
                        let dst_y = y + row as i32;
                        if dst_y < self.clip.y || dst_y >= self.clip.bottom() {
                            continue;
                        }

                        let glyph_row = glyph_start + row as usize;
                        if glyph_row >= font.data_len() {
                            continue;
                        }
                        let byte = font.get_data(glyph_row);

                        let dst_offset = (dst_y as usize * stride) + (char_x as usize * 4);
                        self.write_glyph_row_32bit(byte, dst_offset, fg_u32, bg_u32);
                    }
                } else {
                    // Partially clipped horizontally: fallback to slow path for this char
                    // Re-implement simplified version of original slow loop just for this char?
                    // Or we could execute the original logic for clipped chars.
                    // To do this cleanly without code duplication is tricky.
                    // For now, let's just duplicate the bit-check logic here for clipped case.
                    for row in 0..font.height() {
                        let dst_y = y + row as i32;
                        if dst_y < self.clip.y || dst_y >= self.clip.bottom() {
                            continue;
                        }

                        let glyph_row = glyph_start + row as usize;
                        if glyph_row >= font.data_len() {
                            continue;
                        }
                        let byte = font.get_data(glyph_row);

                        for col in 0..8 {
                            // Check clipping for each pixel
                            let px = char_x + col;
                            if px < self.clip.x || px >= self.clip.right() {
                                continue;
                            }

                            let is_on = (byte >> (7 - col)) & 1 != 0;
                            let c_val = if is_on { color } else { bg_color };
                            // We've already marked the whole text region dirty; use
                            // the raw pixel writer to avoid redundant dirty updates
                            // and extra bounds checks.
                            self.set_pixel_raw(px, dst_y, c_val);
                        }
                    }
                }

                cx += font.width() as i32;
            }
            return;
        }

        // Original slow path for non-32bit formats
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
                                    unsafe {
                                        ptr::write(self.draw_buffer().add(off) as *mut u16, pixel);
                                    }
                                } else {
                                    unsafe {
                                        mmio::mmio_write_u16(
                                            self.draw_buffer().add(off) as usize,
                                            pixel,
                                        );
                                    }
                                }
                            }
                        }
                        _ => {
                            // Fallback
                            for i in 0..clipped_len {
                                // We have already marked the text region dirty above;
                                // use raw pixel write to avoid redundant dirty updates.
                                self.set_pixel_raw(clipped_start + i as i32, dst_y, color);
                            }
                        }
                    }
                }
            }

            cx += font.width() as i32;
        }
    }

    /// 画像描画用のクリッピング計算 helper
    fn calculate_image_clip(
        &self,
        image: &super::image::Image,
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
        image: &super::image::Image,
        src_row: u32,
        run_start: u32,
        run_len: usize,
        dst_byte_offset: usize,
        avx2_available: bool,
    ) {
        let src_base = (src_row * image.width() + run_start) as usize;
        let imgdata = image.data();
        // Allow tuning the stream threshold via environment variable for
        // bench-driven experiments (RANY_STREAM_THRESHOLD_PIXELS). Use a
        // sensible default when `std` is not available.
        #[cfg(feature = "std")]
        let stream_threshold_pixels: usize = std::env::var("RANY_STREAM_THRESHOLD_PIXELS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(2048);
        #[cfg(not(feature = "std"))]
        let stream_threshold_pixels: usize = 2048;

        if self.info.format == PixelFormat::Rgba8888 {
            let byte_len = run_len * 4;
            let src_slice = &imgdata[src_base * 4..src_base * 4 + byte_len];

            if let Some(ref mut back) = self.back_buffer {
                unsafe {
                    ptr::copy_nonoverlapping(
                        src_slice.as_ptr(),
                        back.as_mut_ptr().add(dst_byte_offset),
                        byte_len,
                    );
                }
            } else {
                let addr = self.buffer as usize + dst_byte_offset;
                self.write_bytes_mmio(addr, src_slice);
            }
        } else if self.info.format == PixelFormat::Bgra8888 {
            let src_slice = &imgdata[src_base * 4..src_base * 4 + run_len * 4];

            if self.back_buffer.is_some() {
                self.ensure_scratch_u32(run_len);
                {
                    let dst_bytes = unsafe {
                        core::slice::from_raw_parts_mut(
                            self.scratch_u32.as_mut_ptr() as *mut u8,
                            run_len * 4,
                        )
                    };
                    Self::pack_rgba_to_bgra(src_slice, dst_bytes);
                }
                let back = self.back_buffer.as_mut().unwrap();
                let dst_ptr = unsafe { back.as_mut_ptr().add(dst_byte_offset) as *mut u32 };
                unsafe {
                    ptr::copy_nonoverlapping(self.scratch_u32.as_ptr(), dst_ptr, run_len);
                }
            } else {
                if avx2_available && run_len >= stream_threshold_pixels {
                    let addr = self.buffer as usize + dst_byte_offset;
                    self.write_rgba_packed_to_mmio_stream(addr, src_slice);
                    return;
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
            }
        }
    }

    /// 24-bit不透明ランの描画
    fn write_opaque_run_24bit(
        &mut self,
        image: &super::image::Image,
        src_row: u32,
        run_start: u32,
        run_len: usize,
        dst_byte_offset: usize,
        x: i32,
        dst_row: i32,
        avx2_available: bool,
    ) {
        let total_bytes = run_len * 3;
        self.ensure_scratch_u8(total_bytes);
        let src_base = (src_row * image.width() + run_start) as usize;
        let imgdata = image.data();
        let mut handled_in_scratch = false;

        let mut i = 0usize;
        let mut src_idx = src_base * 4;
        let mut dst_off = 0usize;

        match self.info.format {
            PixelFormat::Bgr888 => {
                handled_in_scratch = true;
                // AVX2 fast-path: process 8 pixels (24 bytes) per iteration using
                // byte-shuffle (pshufb) to compress RGBA -> BGR triplets. This
                // writes overlapping 16-byte stores (at dst and dst+12) to
                // produce contiguous 24-byte output for 8 pixels.
                #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "std"))]
                {
                    if avx2_available && run_len >= 8 {
                        // AVX2: Process chunks of 8 pixels
                        let mut processed = 0usize;
                        let src_ptr = unsafe { imgdata.as_ptr().add(src_base * 4) };
                        let dst_ptr = self.scratch_u8.as_mut_ptr();
                        while processed + 8 <= run_len {
                            unsafe {
                                Self::pack_rgba_to_bgr24_avx2_8pixels(
                                    src_ptr.add(processed * 4),
                                    dst_ptr.add(processed * 3),
                                    true,
                                );
                            }
                            processed += 8;
                        }

                        // Advance indices to account for SIMD-processed pixels
                        src_idx += processed * 4;
                        dst_off += processed * 3;
                        i += processed;
                    } else if std::is_x86_feature_detected!("ssse3") && run_len >= 8 {
                        // SSSE3 fallback: process 8-pixel chunks using 128-bit shuffles
                        let mut processed = 0usize;
                        let src_ptr = unsafe { imgdata.as_ptr().add(src_base * 4) };
                        let dst_ptr = self.scratch_u8.as_mut_ptr();
                        while processed + 8 <= run_len {
                            unsafe {
                                Self::pack_rgba_to_bgr24_ssse3_8pixels(
                                    src_ptr.add(processed * 4),
                                    dst_ptr.add(processed * 3),
                                    true,
                                );
                            }
                            processed += 8;
                        }

                        src_idx += processed * 4;
                        dst_off += processed * 3;
                        i += processed;
                    }
                }

                // AArch64 NEON fast-path: process 8-pixel chunks using an
                // unrolled 8-pixel packer. Requires `std` for runtime feature
                // detection; on `no_std` builds this will fall back to scalar.
                #[cfg(all(target_arch = "aarch64", feature = "std"))]
                {
                    if std::is_aarch64_feature_detected!("neon") && run_len >= 8 {
                        let mut processed = 0usize;
                        let src_ptr = unsafe { imgdata.as_ptr().add(src_base * 4) };
                        let dst_ptr = self.scratch_u8.as_mut_ptr();
                        while processed + 8 <= run_len {
                            unsafe {
                                Self::pack_rgba_to_bgr24_neon_8pixels(
                                    src_ptr.add(processed * 4),
                                    dst_ptr.add(processed * 3),
                                    true,
                                );
                            }
                            processed += 8;
                        }

                        src_idx += processed * 4;
                        dst_off += processed * 3;
                        i += processed;
                    }
                }
                // Process pairs of pixels at a time to emit 6-byte chunks using
                // one u32 + one u16 write (b0 g0 r0 b1) + (g1 r1)
                let src_ptr = imgdata.as_ptr();
                let dst_ptr = self.scratch_u8.as_mut_ptr();
                // Unroll pair processing to handle two pairs (4 pixels) per iteration
                while i + 3 < run_len {
                    let p0 =
                        unsafe { core::ptr::read_unaligned(src_ptr.add(src_idx) as *const u32) };
                    let p1 = unsafe {
                        core::ptr::read_unaligned(src_ptr.add(src_idx + 4) as *const u32)
                    };
                    let p2 = unsafe {
                        core::ptr::read_unaligned(src_ptr.add(src_idx + 8) as *const u32)
                    };
                    let p3 = unsafe {
                        core::ptr::read_unaligned(src_ptr.add(src_idx + 12) as *const u32)
                    };

                    let b0 = ((p0 >> 16) & 0xFF) as u32;
                    let g0 = ((p0 >> 8) & 0xFF) as u32;
                    let r0 = (p0 & 0xFF) as u32;

                    let b1 = ((p1 >> 16) & 0xFF) as u32;
                    let g1 = ((p1 >> 8) & 0xFF) as u32;
                    let r1 = (p1 & 0xFF) as u32;

                    let b2 = ((p2 >> 16) & 0xFF) as u32;
                    let g2 = ((p2 >> 8) & 0xFF) as u32;
                    let r2 = (p2 & 0xFF) as u32;

                    let b3 = ((p3 >> 16) & 0xFF) as u32;
                    let g3 = ((p3 >> 8) & 0xFF) as u32;
                    let r3 = (p3 & 0xFF) as u32;

                    // First pair
                    let v32_0 = (b0) | (g0 << 8) | (r0 << 16) | (b1 << 24);
                    let v16_0 = (g1 as u16) | ((r1 as u16) << 8);
                    // Second pair
                    let v32_1 = (b2) | (g2 << 8) | (r2 << 16) | (b3 << 24);
                    let v16_1 = (g3 as u16) | ((r3 as u16) << 8);

                    unsafe {
                        core::ptr::write_unaligned(dst_ptr.add(dst_off) as *mut u32, v32_0);
                        core::ptr::write_unaligned(dst_ptr.add(dst_off + 4) as *mut u16, v16_0);
                        core::ptr::write_unaligned(dst_ptr.add(dst_off + 6) as *mut u32, v32_1);
                        core::ptr::write_unaligned(dst_ptr.add(dst_off + 10) as *mut u16, v16_1);
                    }

                    src_idx += 16;
                    dst_off += 12;
                    i += 4;
                }

                // Remaining pairs
                while i + 1 < run_len {
                    let p0 =
                        unsafe { core::ptr::read_unaligned(src_ptr.add(src_idx) as *const u32) };
                    let p1 = unsafe {
                        core::ptr::read_unaligned(src_ptr.add(src_idx + 4) as *const u32)
                    };

                    let b0 = ((p0 >> 16) & 0xFF) as u32;
                    let g0 = ((p0 >> 8) & 0xFF) as u32;
                    let r0 = (p0 & 0xFF) as u32;

                    let b1 = ((p1 >> 16) & 0xFF) as u32;
                    let g1 = ((p1 >> 8) & 0xFF) as u32;
                    let r1 = (p1 & 0xFF) as u32;

                    let v32 = (b0) | (g0 << 8) | (r0 << 16) | (b1 << 24);
                    let v16 = (g1 as u16) | ((r1 as u16) << 8);

                    unsafe {
                        core::ptr::write_unaligned(dst_ptr.add(dst_off) as *mut u32, v32);
                        core::ptr::write_unaligned(dst_ptr.add(dst_off + 4) as *mut u16, v16);
                    }

                    src_idx += 8;
                    dst_off += 6;
                    i += 2;
                }
                // Tail pixel
                while i < run_len {
                    let p0 = unsafe {
                        core::ptr::read_unaligned(imgdata.as_ptr().add(src_idx) as *const u32)
                    };
                    let b0 = ((p0 >> 16) & 0xFF) as u8;
                    let g0 = ((p0 >> 8) & 0xFF) as u8;
                    let r0 = (p0 & 0xFF) as u8;
                    unsafe {
                        *dst_ptr.add(dst_off) = b0;
                        *dst_ptr.add(dst_off + 1) = g0;
                        *dst_ptr.add(dst_off + 2) = r0;
                    }
                    src_idx += 4;
                    dst_off += 3;
                    i += 1;
                }
            }
            PixelFormat::Rgb888 => {
                handled_in_scratch = true;
                #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "std"))]
                {
                    if avx2_available && run_len >= 8 {
                        // AVX2: process chunks of 8 pixels
                        let mut processed = 0usize;
                        let src_ptr = unsafe { imgdata.as_ptr().add(src_base * 4) };
                        let dst_ptr = self.scratch_u8.as_mut_ptr();
                        while processed + 8 <= run_len {
                            unsafe {
                                Self::pack_rgba_to_bgr24_avx2_8pixels(
                                    src_ptr.add(processed * 4),
                                    dst_ptr.add(processed * 3),
                                    false,
                                );
                            }
                            processed += 8;
                        }

                        src_idx += processed * 4;
                        dst_off += processed * 3;
                        i += processed;
                    } else if std::is_x86_feature_detected!("ssse3") && run_len >= 8 {
                        // SSSE3 fallback
                        let mut processed = 0usize;
                        let src_ptr = unsafe { imgdata.as_ptr().add(src_base * 4) };
                        let dst_ptr = self.scratch_u8.as_mut_ptr();
                        while processed + 8 <= run_len {
                            unsafe {
                                Self::pack_rgba_to_bgr24_ssse3_8pixels(
                                    src_ptr.add(processed * 4),
                                    dst_ptr.add(processed * 3),
                                    false,
                                );
                            }
                            processed += 8;
                        }

                        src_idx += processed * 4;
                        dst_off += processed * 3;
                        i += processed;
                    }
                }
                // Unroll pair processing for RGB order to handle two pairs (4 pixels) per iteration
                let src_ptr = imgdata.as_ptr();
                let dst_ptr = self.scratch_u8.as_mut_ptr();
                while i + 3 < run_len {
                    let p0 =
                        unsafe { core::ptr::read_unaligned(src_ptr.add(src_idx) as *const u32) };
                    let p1 = unsafe {
                        core::ptr::read_unaligned(src_ptr.add(src_idx + 4) as *const u32)
                    };
                    let p2 = unsafe {
                        core::ptr::read_unaligned(src_ptr.add(src_idx + 8) as *const u32)
                    };
                    let p3 = unsafe {
                        core::ptr::read_unaligned(src_ptr.add(src_idx + 12) as *const u32)
                    };

                    let r0 = (p0 & 0xFF) as u32;
                    let g0 = ((p0 >> 8) & 0xFF) as u32;
                    let b0 = ((p0 >> 16) & 0xFF) as u32;

                    let r1 = (p1 & 0xFF) as u32;
                    let g1 = ((p1 >> 8) & 0xFF) as u32;
                    let b1 = ((p1 >> 16) & 0xFF) as u32;

                    let r2 = (p2 & 0xFF) as u32;
                    let g2 = ((p2 >> 8) & 0xFF) as u32;
                    let b2 = ((p2 >> 16) & 0xFF) as u32;

                    let r3 = (p3 & 0xFF) as u32;
                    let g3 = ((p3 >> 8) & 0xFF) as u32;
                    let b3 = ((p3 >> 16) & 0xFF) as u32;

                    // First pair
                    let v32_0 = (r0) | (g0 << 8) | (b0 << 16) | (r1 << 24);
                    let v16_0 = (g1 as u16) | ((b1 as u16) << 8);
                    // Second pair
                    let v32_1 = (r2) | (g2 << 8) | (b2 << 16) | (r3 << 24);
                    let v16_1 = (g3 as u16) | ((b3 as u16) << 8);

                    unsafe {
                        core::ptr::write_unaligned(dst_ptr.add(dst_off) as *mut u32, v32_0);
                        core::ptr::write_unaligned(dst_ptr.add(dst_off + 4) as *mut u16, v16_0);
                        core::ptr::write_unaligned(dst_ptr.add(dst_off + 6) as *mut u32, v32_1);
                        core::ptr::write_unaligned(dst_ptr.add(dst_off + 10) as *mut u16, v16_1);
                    }

                    src_idx += 16;
                    dst_off += 12;
                    i += 4;
                }

                // Remaining pairs
                while i + 1 < run_len {
                    let p0 =
                        unsafe { core::ptr::read_unaligned(src_ptr.add(src_idx) as *const u32) };
                    let p1 = unsafe {
                        core::ptr::read_unaligned(src_ptr.add(src_idx + 4) as *const u32)
                    };

                    let r0 = (p0 & 0xFF) as u32;
                    let g0 = ((p0 >> 8) & 0xFF) as u32;
                    let b0 = ((p0 >> 16) & 0xFF) as u32;

                    let r1 = (p1 & 0xFF) as u32;
                    let g1 = ((p1 >> 8) & 0xFF) as u32;
                    let b1 = ((p1 >> 16) & 0xFF) as u32;

                    let v32 = (r0) | (g0 << 8) | (b0 << 16) | (r1 << 24);
                    let v16 = (g1 as u16) | ((b1 as u16) << 8);

                    unsafe {
                        core::ptr::write_unaligned(dst_ptr.add(dst_off) as *mut u32, v32);
                        core::ptr::write_unaligned(dst_ptr.add(dst_off + 4) as *mut u16, v16);
                    }

                    src_idx += 8;
                    dst_off += 6;
                    i += 2;
                }

                while i < run_len {
                    let p0 = unsafe {
                        core::ptr::read_unaligned(imgdata.as_ptr().add(src_idx) as *const u32)
                    };
                    let r0 = (p0 & 0xFF) as u8;
                    let g0 = ((p0 >> 8) & 0xFF) as u8;
                    let b0 = ((p0 >> 16) & 0xFF) as u8;
                    unsafe {
                        *dst_ptr.add(dst_off) = r0;
                        *dst_ptr.add(dst_off + 1) = g0;
                        *dst_ptr.add(dst_off + 2) = b0;
                    }
                    src_idx += 4;
                    dst_off += 3;
                    i += 1;
                }
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
            // Tunable chunk size for 24-bit writes; use `RANY_CHUNK_24_PIXELS`
            // to experiment with different chunk sizes when benching.
            #[cfg(feature = "std")]
            let chunk_24_pixels: usize = std::env::var("RANY_CHUNK_24_PIXELS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1024);
            #[cfg(not(feature = "std"))]
            let chunk_24_pixels: usize = 1024;

            let mut processed = 0usize;
            while processed < run_len {
                let chunk = core::cmp::min(chunk_24_pixels, run_len - processed);
                let chunk_bytes = chunk * 3;
                let start = processed * 3;
                let end = start + chunk_bytes;
                if let Some(ref mut back) = self.back_buffer {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            self.scratch_u8.as_ptr().add(start),
                            back.as_mut_ptr().add(dst_byte_offset + start),
                            chunk_bytes,
                        );
                    }
                } else {
                    let addr = self.buffer as usize + dst_byte_offset + start;
                    self.write_bytes_mmio(addr, &self.scratch_u8[start..end]);
                }
                processed += chunk;
            }
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

        if let Some(ref back) = self.back_buffer {
            if !self.clip.contains(Point::new(x, y)) {
                return;
            }
            let offset = (y as usize * self.info.stride as usize)
                + (x as usize * self.info.format.bytes_per_pixel());
            let bpp = self.info.format.bytes_per_pixel();
            let bg_bytes = &back[offset..offset + bpp];
            let bg = self.info.format.decode_color_bytes(bg_bytes);
            let result = color.blend(bg);
            self.set_pixel(x, y, result);
        } else {
            // Fallback for MMIO: just overwrite (no readback)
            self.set_pixel(x, y, color);
        }
    }

    /// 画像描画用のスキャンライン処理
    fn draw_image_scanline(
        &mut self,
        image: &super::image::Image,
        src_row: u32,
        dst_row: i32,
        row_start: u32,
        row_end: u32,
        x: i32,
        avx2_available: bool,
    ) {
        let bytes_per_pixel = self.info.format.bytes_per_pixel();
        let dst_row_offset = (dst_row as u32 * self.info.stride) as usize;
        let mut col = row_start;
        let img_ptr = image.data().as_ptr();

        while col < row_end {
            // Skip non-opaque pixels (alpha != 255) by falling back to per-pixel set_pixel
            while col < row_end {
                let idx = ((src_row * image.width() + col) * 4) as usize;
                let alpha = unsafe { *img_ptr.add(idx + 3) };
                if alpha == 255 {
                    break;
                }
                // fallback: preserve original semantic (write if alpha > 0)
                if alpha > 0 {
                    let c = image.get_pixel(col, src_row);
                    self.blend_pixel(x + col as i32, dst_row, c);
                }
                col += 1;
            }

            // Now col is at start of an opaque run (or at row_end)
            let run_start = col;
            while col < row_end {
                let idx = ((src_row * image.width() + col) * 4) as usize;
                let alpha = unsafe { *img_ptr.add(idx + 3) };
                if alpha != 255 {
                    break;
                }
                col += 1;
            }

            let run_len = (col - run_start) as usize;
            if run_len == 0 {
                continue;
            }

            // The absolute x-coordinate on the framebuffer for the start of this run.
            // `x` is the image's top-left x. `run_start` is the column relative to the image's x.
            let abs_x = (x + run_start as i32) as usize;
            let dst_byte_offset = dst_row_offset + abs_x * bytes_per_pixel;

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
                _ => {
                    // Fallback
                    for i in 0..run_len {
                        let c = image.get_pixel(run_start + i as u32, src_row);
                        self.set_pixel(x + (run_start as i32 + i as i32), dst_row, c);
                    }
                }
            }
        }
    }

    /// 画像を描画
    pub fn draw_image(&mut self, image: &super::image::Image, x: i32, y: i32) {
        let (draw_rect, _src_off_x, _src_off_y) = match self.calculate_image_clip(image, x, y) {
            Some(v) => v,
            None => return,
        };

        // Mark dirty
        self.mark_dirty(draw_rect);

        let dst_x0 = draw_rect.x;
        let dst_y0 = draw_rect.y;
        let dst_x1 = draw_rect.right();
        let dst_y1 = draw_rect.bottom();

        // Pre-detect CPU features once per draw to avoid repeated CPUID calls
        let avx2_available = {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                Self::get_avx2_available()
            }
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            {
                false
            }
        };
        for dst_row in dst_y0..dst_y1 {
            let src_row = (dst_row - y) as u32;
            let row_start = (dst_x0 - x) as u32;
            let row_end = (dst_x1 - x) as u32; // exclusive

            self.draw_image_scanline(
                image,
                src_row,
                dst_row,
                row_start,
                row_end,
                x,
                avx2_available,
            );
        }
    }
}
