use super::*;
use crate::graphics::image::Image;

#[test_case]
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
    let back = vec![0u32; (info.width * info.height) as usize];
    fb.enable_double_buffering_from_vec(back);

    let img = Image::filled(width, height, Color::with_alpha(10, 20, 30, 255));
    fb.draw_image(&img, 0, 0);

    // Check that back buffer contains BGRA per-pixel u32 values
    let back_ref = fb.back_buffer.as_ref().unwrap();
    for &pixel in back_ref.iter() {
        let c = Color::from_u32(pixel);
        assert_eq!(c.blue, 30); // blue
        assert_eq!(c.green, 20); // green
        assert_eq!(c.red, 10); // red
        assert_eq!(c.alpha, 255); // alpha
    }
}

#[test_case]
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
    let back = vec![0u32; (info.width * info.height) as usize];
    fb.enable_double_buffering_from_vec(back);

    let img = Image::filled(width, height, Color::with_alpha(255, 0, 0, 255));
    fb.draw_image(&img, 0, 0);

    let back_ref = fb.back_buffer.as_ref().unwrap();
    for &pixel in back_ref.iter() {
        let c = Color::from_u32(pixel);
        assert_eq!(c.blue, 0);
        assert_eq!(c.green, 0);
        assert_eq!(c.red, 255);
    }
}

#[test_case]
#[ignore]
#[cfg(feature = "std")]
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
    let back = vec![0u32; (info.width * info.height) as usize];
    fb.enable_double_buffering_from_vec(back);

    let img = Image::filled(width, height, Color::with_alpha(64, 128, 192, 255));

    let start = Instant::now();
    for _ in 0..10 {
        fb.draw_image(&img, 0, 0);
    }
    let elapsed = start.elapsed();
    log::info!("bench_draw_image_bulk: {:?}", elapsed);
}

#[test_case]
#[ignore]
#[cfg(feature = "std")]
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
    let back = vec![0u32; (info.width * info.height) as usize];
    fb.enable_double_buffering_from_vec(back);

    let img = Image::filled(width, height, Color::with_alpha(64, 128, 192, 255));

    let start = Instant::now();
    for _ in 0..10 {
        fb.draw_image(&img, 0, 0);
    }
    let elapsed = start.elapsed();
    log::info!("bench_draw_image_24bit_bulk: {:?}", elapsed);
}

#[test_case]
#[ignore]
#[cfg(feature = "std")]
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
    let back = vec![0u32; (info.width * info.height) as usize];
    fb.enable_double_buffering_from_vec(back);

    let img = Image::filled(width, height, Color::with_alpha(64, 128, 192, 255));

    let start = Instant::now();
    for _ in 0..10 {
        fb.draw_image(&img, 0, 0);
    }
    let elapsed = start.elapsed();
    log::info!("bench_draw_image_rgba_bulk: {:?}", elapsed);
}

#[test_case]
#[ignore]
#[cfg(feature = "std")]
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
    let back = vec![0u32; (info.width * info.height) as usize];
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

#[test_case]
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

#[test_case]
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

#[test_case]
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

#[test_case]
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

#[test_case]
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

#[test_case]
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
    use crate::graphics::packer::PACKER_MODE;
    PACKER_MODE.load(Ordering::Relaxed)
}

#[test_case]
#[cfg(feature = "std")]
fn test_packer_env_override() {
    // Ensure RANY_PACKER override sets the PACKER_MODE
    unsafe { std::env::set_var("RANY_PACKER", "scalar"); }
    let src = vec![0u8; 1024];
    let mut dst = vec![0u8; 1024];
    Framebuffer::pack_rgba_to_bgra(&src, &mut dst);
    assert_eq!(_test_get_packer_mode(), 1);
    unsafe { std::env::remove_var("RANY_PACKER"); }
}

#[test_case]
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

#[test_case]
#[ignore]
#[cfg(feature = "std")]
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
    let back = vec![0u32; (info.width * info.height) as usize];
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

#[test_case]
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
    let back = vec![0u32; (info.width * info.height) as usize];
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
            let mut opt_pixels = Vec::new();
            let mut naive_pixels = Vec::new();
            for y in 0..info.height as usize {
                for x in 0..info.width as usize {
                    let idx = y * info.width as usize + x;
                    let o_pixel = buf_opt[idx];
                    let n_pixel = buf_naive[idx];
                    if o_pixel != 0 {
                        let o = Color::from_u32(o_pixel);
                        opt_pixels.push((x as i32, y as i32, o));
                    }
                    if n_pixel != 0 {
                        let n = Color::from_u32(n_pixel);
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
    for y in 0..6 {
        let idx = (y as usize * info.width as usize) + 1usize;
        let c = Color::from_u32(back_ref[idx]);
        assert_eq!(c.blue, 3);
        assert_eq!(c.green, 2);
        assert_eq!(c.red, 1);
        assert_eq!(c.alpha, 255);
    }
}

#[test_case]
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
    let back = vec![0u32; (info.width * info.height) as usize];
    fb.enable_double_buffering_from_vec(back);

    let fg = Color::with_alpha(1, 2, 3, 255);
    let bg = Color::with_alpha(100, 110, 120, 255);

    fb.draw_text(0, 0, " ", fg, bg);

    let back_ref = fb.back_buffer.as_ref().unwrap();
    // Space glyph is blank; entire 8x16 area should be background
    for y in 0..16 {
        for x in 0..8 {
            let idx = (y as usize * info.width as usize) + x as usize;
            let c = Color::from_u32(back_ref[idx]);
            assert_eq!(c.blue, 120);
            assert_eq!(c.green, 110);
            assert_eq!(c.red, 100);
            assert_eq!(c.alpha, 255);
        }
    }
}

#[test_case]
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
    let back = vec![0u32; (info.width * info.height) as usize];
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

#[test_case]
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
    let back = vec![0u32; (info.width * info.height) as usize];
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

#[test_case]
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
    let back = vec![0u32; (info.width * info.height) as usize];
    fb.enable_double_buffering_from_vec(back);

    let fg = Color::with_alpha(1, 2, 3, 255);
    let bg = Color::with_alpha(100, 110, 120, 255);

    fb.draw_text(0, 0, " ", fg, bg);

    let back_ref = fb.back_buffer.as_ref().unwrap();
    // Space glyph is blank; entire 8x16 area should be background
    for y in 0..16 {
        for x in 0..8 {
            let idx = (y as usize * info.width as usize) + x as usize;
            let c = Color::from_u32(back_ref[idx]);
            assert_eq!(c.blue, 120);
            assert_eq!(c.green, 110);
            assert_eq!(c.red, 100);
        }
    }
}

#[test_case]
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

#[test_case]
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

#[test_case]
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

#[test_case]
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

#[test_case]
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

#[test_case]
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
    let back = vec![0u32; (info.width * info.height) as usize];
    fb2.enable_double_buffering_from_vec(back);
    fb2.draw_image(&img, 0, 0);
    let back_ref = fb2.back_buffer.as_ref().unwrap();
    for x in 0..(width as usize) {
        let idx = x;
        let pixel_c = Color::from_u32(back_ref[idx]);
        let c = cols[x];
        assert_eq!(pixel_c.blue, c.blue);
        assert_eq!(pixel_c.green, c.green);
        assert_eq!(pixel_c.red, c.red);
    }
}

#[test_case]
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

#[cfg(all(target_arch = "x86_64", target_feature = "ssse3"))]
#[test_case]
fn test_pack_rgba_to_bgra_ssse3_matches_scalar() {
    // Only run the detailed SSSE3 check when the feature is available
    #[cfg(feature = "std")]
    if !std::is_x86_feature_detected!("ssse3") { return; }
    #[cfg(not(feature = "std"))]
    if hal::mmio::get_simd_level() < hal::mmio::simd_level::SSSE3 { return; }

    // Test multiple sizes including non-16 multiples to exercise tail path
    for len in [4usize, 12, 16, 20, 48, 64, 100].iter() {
        let mut src = vec![0u8; *len * 4];
        for i in 0..(src.len()) {
            src[i] = (i * 37 % 251) as u8;
        }
        let mut dst_simd = vec![0u8; src.len()];
        let mut dst_scalar = vec![0u8; src.len()];

        unsafe {
            Framebuffer::pack_rgba_to_bgra_ssse3(src.as_ptr(), dst_simd.as_mut_ptr(), src.len());
        }
        Framebuffer::pack_rgba_to_bgra(&src, &mut dst_scalar);

        assert_eq!(dst_simd, dst_scalar);
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[test_case]
fn test_pack_rgba_to_bgra_avx2_matches_scalar() {
    // Only run AVX2 check when available
    #[cfg(feature = "std")]
    if !std::is_x86_feature_detected!("avx2") { return; }
    #[cfg(not(feature = "std"))]
    if hal::mmio::get_simd_level() < hal::mmio::simd_level::AVX2 { return; }

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

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[test_case]
fn test_pack_rgba_to_bgr24_avx2_matches_scalar() {
    // Only run AVX2 check when available
    #[cfg(feature = "std")]
    if !std::is_x86_feature_detected!("avx2") { return; }
    #[cfg(not(feature = "std"))]
    if hal::mmio::get_simd_level() < hal::mmio::simd_level::AVX2 { return; }

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

#[cfg(all(target_arch = "x86_64", target_feature = "ssse3"))]
#[test_case]
fn test_pack_rgba_to_bgr24_ssse3_matches_scalar() {
    #[cfg(feature = "std")]
    if !std::is_x86_feature_detected!("ssse3") { return; }
    #[cfg(not(feature = "std"))]
    if hal::mmio::get_simd_level() < hal::mmio::simd_level::SSSE3 { return; }

    let len = 8usize;
    let mut src = vec![0u8; len * 4];
    for i in 0..src.len() {
        src[i] = (i * 61 % 251) as u8;
    }
    let mut dst_simd = vec![0u8; len * 3];
    unsafe {
        Framebuffer::pack_rgba_to_bgr24_ssse3_8pixels(src.as_ptr(), dst_simd.as_mut_ptr(), true);
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
#[test_case]
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
#[test_case]
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
#[test_case]
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
        Framebuffer::pack_rgba_to_bgr24_neon_8pixels(src.as_ptr(), dst_simd.as_mut_ptr(), false);
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

#[test_case]
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

#[test_case]
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

#[test_case]
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

#[test_case]
fn test_fill_rect_rgb565_mmio() {
    let width = 8u32;
    let height = 4u32;
    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 2,
        format: PixelFormat::Rgb565,
        bpp: 16,
    };

    let mut mem = vec![0u8; info.size()];
    let addr = mem.as_mut_ptr() as u64;
    let mut info2 = info.clone();
    info2.address = addr;

    let mut fb = unsafe { Framebuffer::new(info2) };
    fb.fill_rect(Rect::new(1, 1, 6, 2), Color::RED);

    // RED in RGB565 little-endian: 0xF800 -> [0x00, 0xF8]
    for y in 0..height as usize {
        for x in 0..width as usize {
            let off = y * info.stride as usize + x * 2;
            if (1..=2).contains(&y) && (1..=6).contains(&x) {
                assert_eq!(mem[off], 0x00, "x={}, y={}", x, y);
                assert_eq!(mem[off + 1], 0xF8, "x={}, y={}", x, y);
            } else {
                assert_eq!(mem[off], 0x00, "x={}, y={}", x, y);
                assert_eq!(mem[off + 1], 0x00, "x={}, y={}", x, y);
            }
        }
    }
}

#[test_case]
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
    assert!(fb.dirty_rect().is_none());

    // Draw a pixel
    fb.set_pixel(10, 10, Color::RED);
    assert!(fb.dirty_rect().is_some());
    let d = fb.dirty_rect().unwrap();
    assert_eq!(d, Rect::new(10, 10, 1, 1));

    // Draw another pixel
    fb.set_pixel(20, 20, Color::BLUE);
    let d = fb.dirty_rect().unwrap();
    // Should be union of (10,10,1,1) and (20,20,1,1) -> (10,10, 11, 11)
    assert_eq!(d, Rect::new(10, 10, 11, 11));

    // Flush
    fb.flush_dirty_area();
    assert!(fb.dirty_rect().is_none());
}

#[test_case]
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
    let mut back = vec![0u32; (info.width * info.height) as usize];
    // Fill back buffer with white (opaque white in BGRA)
    let white = Color::with_alpha(255, 255, 255, 255).to_u32();
    for i in 0..back.len() {
        back[i] = white;
    }
    fb.enable_double_buffering_from_vec(back);

    // Clear vram to black (simulating initial state)
    for i in 0..vram.len() {
        vram[i] = 0;
    }

    // Mark a small area as dirty manually (to simulate drawing)
    // Let's modify back buffer at (5,5)
    let offset = (5 * 10 + 5) * 4; // byte offset used for VM checks below
    let idx = 5 * info.width as usize + 5; // pixel index in back buffer
    let dst = unsafe { (fb.back_buffer.as_mut().unwrap().as_mut_ptr() as *mut u8).add(idx * 4) };
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

#[test_case]
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
    let back = vec![0u32; (info.width * info.height) as usize];
    fb.enable_double_buffering_from_vec(back);

    let fg = Color::with_alpha(10, 20, 30, 255);
    let bg = Color::with_alpha(100, 110, 120, 255);

    // Position the char at x = -3 so that glyph columns 3 and 4 map to
    // framebuffer x = 0 and x = 1 respectively for row where '!' has
    // bits (font row index 2 contains 0x18 => bits at cols 3 and 4).
    fb.draw_text(-3, 0, "!", fg, bg);

    let row = 2usize;
    let idx0 = row * info.width as usize + 0;
    let idx1 = row * info.width as usize + 1;
    let idx2 = row * info.width as usize + 2;

    let back_ref = fb.back_buffer.as_ref().unwrap();

    // px 0 should be fg (column 3 of glyph)
    let c0 = Color::from_u32(back_ref[idx0]);
    assert_eq!(c0.blue, fg.blue);
    assert_eq!(c0.green, fg.green);
    assert_eq!(c0.red, fg.red);

    // px 1 should be fg (column 4 of glyph)
    let c1 = Color::from_u32(back_ref[idx1]);
    assert_eq!(c1.blue, fg.blue);
    assert_eq!(c1.green, fg.green);
    assert_eq!(c1.red, fg.red);

    // px 2 should be background
    let c2 = Color::from_u32(back_ref[idx2]);
    assert_eq!(c2.blue, bg.blue);
    assert_eq!(c2.green, bg.green);
    assert_eq!(c2.red, bg.red);
}

#[test_case]
fn test_draw_image_24bit_rgb888_backbuffer() {
    use crate::graphics::image::Image;

    let width = 8u32;
    let height = 2u32;
    let mut img = Image::new(width, height);

    // Fill with pattern
    // Pixel 0: Red (255, 0, 0)
    img.set_pixel(0, 0, Color::RED);
    // Pixel 1: Green (0, 255, 0)
    img.set_pixel(1, 0, Color::GREEN);
    // Pixel 2: Blue (0, 0, 255)
    img.set_pixel(2, 0, Color::BLUE);

    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 3,
        format: PixelFormat::Rgb888, // Testing RGB format
        bpp: 24,
    };

    let mut fb = unsafe { Framebuffer::new(info.clone()) };
    let back = vec![0u32; (info.width * info.height) as usize];
    fb.enable_double_buffering_from_vec(back);

    fb.draw_image(&img, 0, 0);

    let back_ref = fb.back_buffer.as_ref().unwrap();

    // Verify Pixel 0 (Red)
    let p0 = Color::from_u32(back_ref[0]);
    assert_eq!(p0.red, 255);
    assert_eq!(p0.green, 0);
    assert_eq!(p0.blue, 0);

    // Verify Pixel 1 (Green)
    let p1 = Color::from_u32(back_ref[1]);
    assert_eq!(p1.red, 0);
    assert_eq!(p1.green, 255);
    assert_eq!(p1.blue, 0);

    // Verify Pixel 2 (Blue)
    let p2 = Color::from_u32(back_ref[2]);
    assert_eq!(p2.red, 0);
    assert_eq!(p2.green, 0);
    assert_eq!(p2.blue, 255);
}

#[test_case]
fn test_draw_hline_24bit_rgb888_mmio() {
    let width = 10u32;
    let height = 2u32;
    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 3,
        format: PixelFormat::Rgb888,
        bpp: 24,
    };

    let mut vram = vec![0u8; info.size()];
    let addr = vram.as_mut_ptr() as u64;
    let mut info2 = info.clone();
    info2.address = addr;

    let mut fb = unsafe { Framebuffer::new(info2) };

    // Draw Blue line: Color(0, 0, 255)
    // Rgb888 memory should be [0, 0, 255] repeatedly
    fb.draw_hline(0, 4, 0, Color::BLUE);

    for i in 0..5 {
        let off = i * 3;
        assert_eq!(vram[off], 0, "Pixel {} R", i);
        assert_eq!(vram[off + 1], 0, "Pixel {} G", i);
        assert_eq!(vram[off + 2], 255, "Pixel {} B", i);
    }
}

#[test_case]
fn test_draw_hline_rgb565_mmio() {
    let width = 8u32;
    let height = 1u32;
    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 2,
        format: PixelFormat::Rgb565,
        bpp: 16,
    };

    let mut vram = vec![0u8; info.size()];
    let addr = vram.as_mut_ptr() as u64;
    let mut info2 = info.clone();
    info2.address = addr;

    let mut fb = unsafe { Framebuffer::new(info2) };

    fb.draw_hline(1, 6, 0, Color::GREEN);

    // GREEN in RGB565 little-endian: 0x07E0 -> [0xE0, 0x07]
    for x in 0..width as usize {
        let off = x * 2;
        if (1..=6).contains(&x) {
            assert_eq!(vram[off], 0xE0, "x={}", x);
            assert_eq!(vram[off + 1], 0x07, "x={}", x);
        } else {
            assert_eq!(vram[off], 0x00, "x={}", x);
            assert_eq!(vram[off + 1], 0x00, "x={}", x);
        }
    }
}

#[test_case]
fn test_blit_rect_24bit_rgb888_backbuffer_flush() {
    let width = 4u32;
    let height = 1u32;
    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 3,
        format: PixelFormat::Rgb888,
        bpp: 24,
    };

    let mut vram = vec![0u8; info.size()];
    let mut info2 = info.clone();
    info2.address = vram.as_mut_ptr() as u64;

    let mut fb = unsafe { Framebuffer::new(info2) };
    fb.enable_double_buffering_from_vec(vec![0u32; (width * height) as usize]);

    fb.set_pixel(0, 0, Color::RED);
    fb.set_pixel(1, 0, Color::GREEN);
    fb.set_pixel(2, 0, Color::BLUE);
    fb.flush_dirty_area();

    // RGB888 memory layout: [R, G, B]
    assert_eq!(vram[0], 255);
    assert_eq!(vram[1], 0);
    assert_eq!(vram[2], 0);

    assert_eq!(vram[3], 0);
    assert_eq!(vram[4], 255);
    assert_eq!(vram[5], 0);

    assert_eq!(vram[6], 0);
    assert_eq!(vram[7], 0);
    assert_eq!(vram[8], 255);
}

#[test_case]
fn test_blit_rect_24bit_rgb888_backbuffer_flush_odd_width() {
    let width = 5u32;
    let height = 1u32;
    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 3,
        format: PixelFormat::Rgb888,
        bpp: 24,
    };

    let mut vram = vec![0u8; info.size()];
    let mut info2 = info.clone();
    info2.address = vram.as_mut_ptr() as u64;

    let mut fb = unsafe { Framebuffer::new(info2) };
    fb.enable_double_buffering_from_vec(vec![0u32; (width * height) as usize]);

    let colors = [
        Color::RED,
        Color::GREEN,
        Color::BLUE,
        Color::WHITE,
        Color::BLACK,
    ];

    for (x, c) in colors.iter().enumerate() {
        fb.set_pixel(x as i32, 0, *c);
    }
    fb.flush_dirty_area();

    // RGB888 memory layout: [R, G, B]
    assert_eq!(&vram[0..3], &[255, 0, 0]);
    assert_eq!(&vram[3..6], &[0, 255, 0]);
    assert_eq!(&vram[6..9], &[0, 0, 255]);
    assert_eq!(&vram[9..12], &[255, 255, 255]);
    assert_eq!(&vram[12..15], &[0, 0, 0]);
}

#[test_case]
fn test_blit_rect_24bit_bgr888_backbuffer_flush() {
    let width = 3u32;
    let height = 1u32;
    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 3,
        format: PixelFormat::Bgr888,
        bpp: 24,
    };

    let mut vram = vec![0u8; info.size()];
    let mut info2 = info.clone();
    info2.address = vram.as_mut_ptr() as u64;

    let mut fb = unsafe { Framebuffer::new(info2) };
    fb.enable_double_buffering_from_vec(vec![0u32; (width * height) as usize]);

    fb.set_pixel(0, 0, Color::RED);
    fb.set_pixel(1, 0, Color::GREEN);
    fb.set_pixel(2, 0, Color::BLUE);
    fb.flush_dirty_area();

    // BGR888 memory layout: [B, G, R]
    assert_eq!(vram[0], 0);
    assert_eq!(vram[1], 0);
    assert_eq!(vram[2], 255);

    assert_eq!(vram[3], 0);
    assert_eq!(vram[4], 255);
    assert_eq!(vram[5], 0);

    assert_eq!(vram[6], 255);
    assert_eq!(vram[7], 0);
    assert_eq!(vram[8], 0);
}

#[test_case]
fn test_blit_rect_16bit_rgb565_backbuffer_flush() {
    let width = 2u32;
    let height = 1u32;
    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 2,
        format: PixelFormat::Rgb565,
        bpp: 16,
    };

    let mut vram = vec![0u8; info.size()];
    let mut info2 = info.clone();
    info2.address = vram.as_mut_ptr() as u64;

    let mut fb = unsafe { Framebuffer::new(info2) };
    fb.enable_double_buffering_from_vec(vec![0u32; (width * height) as usize]);

    fb.set_pixel(0, 0, Color::RED);
    fb.set_pixel(1, 0, Color::GREEN);
    fb.flush_dirty_area();

    // RGB565 little-endian bytes
    // RED   = 0xF800 -> [0x00, 0xF8]
    // GREEN = 0x07E0 -> [0xE0, 0x07]
    assert_eq!(vram[0], 0x00);
    assert_eq!(vram[1], 0xF8);
    assert_eq!(vram[2], 0xE0);
    assert_eq!(vram[3], 0x07);
}

#[test_case]
fn test_blit_rect_16bit_rgb565_backbuffer_flush_odd_width() {
    let width = 3u32;
    let height = 1u32;
    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 2,
        format: PixelFormat::Rgb565,
        bpp: 16,
    };

    let mut vram = vec![0u8; info.size()];
    let mut info2 = info.clone();
    info2.address = vram.as_mut_ptr() as u64;

    let mut fb = unsafe { Framebuffer::new(info2) };
    fb.enable_double_buffering_from_vec(vec![0u32; (width * height) as usize]);

    fb.set_pixel(0, 0, Color::RED);
    fb.set_pixel(1, 0, Color::GREEN);
    fb.set_pixel(2, 0, Color::BLUE);
    fb.flush_dirty_area();

    // RGB565 little-endian bytes
    // RED   = 0xF800 -> [0x00, 0xF8]
    // GREEN = 0x07E0 -> [0xE0, 0x07]
    // BLUE  = 0x001F -> [0x1F, 0x00]
    assert_eq!(vram[0], 0x00);
    assert_eq!(vram[1], 0xF8);
    assert_eq!(vram[2], 0xE0);
    assert_eq!(vram[3], 0x07);
    assert_eq!(vram[4], 0x1F);
    assert_eq!(vram[5], 0x00);
}

#[test_case]
fn test_copy_rect_backbuffer_same_row_overlap() {
    let width = 8u32;
    let height = 1u32;
    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 4,
        format: PixelFormat::Bgra8888,
        bpp: 32,
    };

    let mut fb = unsafe { Framebuffer::new(info.clone()) };
    fb.enable_double_buffering_from_vec(vec![0u32; (width * height) as usize]);

    {
        let back = fb.back_buffer.as_mut().unwrap();
        for x in 0..width as usize {
            back[x] = Color::with_alpha(x as u8, 0, 0, 255).to_u32();
        }
    }

    // same-row overlap: [0..4) -> starts at 2
    fb.copy_rect(Rect::new(0, 0, 4, 1), 2, 0);

    let back = fb.back_buffer.as_ref().unwrap();
    let expected_red = [0u8, 1, 0, 1, 2, 3, 6, 7];
    for (x, &exp) in expected_red.iter().enumerate() {
        let c = Color::from_u32(back[x]);
        assert_eq!(c.red, exp, "x={}", x);
    }
}

#[test_case]
fn test_copy_rect_backbuffer_vertical_copy() {
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
    fb.enable_double_buffering_from_vec(vec![0u32; (width * height) as usize]);

    {
        let back = fb.back_buffer.as_mut().unwrap();
        for y in 0..height as usize {
            for x in 0..width as usize {
                let idx = y * width as usize + x;
                let red = (y * 10 + x) as u8;
                back[idx] = Color::with_alpha(red, 0, 0, 255).to_u32();
            }
        }
    }

    // vertical non-overlap copy: row0 -> row2
    fb.copy_rect(Rect::new(0, 0, width, 1), 0, 2);

    let back = fb.back_buffer.as_ref().unwrap();
    for x in 0..width as usize {
        let src = Color::from_u32(back[x]);
        let dst = Color::from_u32(back[2 * width as usize + x]);
        assert_eq!(dst.red, src.red, "x={}", x);
    }
}

#[test_case]
fn test_copy_rect_mmio_same_row_overlap() {
    let width = 8u32;
    let height = 1u32;
    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 4,
        format: PixelFormat::Bgra8888,
        bpp: 32,
    };

    let mut vram = vec![0u8; info.size()];
    let mut info2 = info.clone();
    info2.address = vram.as_mut_ptr() as u64;
    let mut fb = unsafe { Framebuffer::new(info2) };

    for x in 0..width as i32 {
        fb.set_pixel(x, 0, Color::with_alpha(x as u8, 0, 0, 255));
    }

    // same-row overlap: [0..4) -> starts at 2
    fb.copy_rect(Rect::new(0, 0, 4, 1), 2, 0);

    let expected_red = [0u8, 1, 0, 1, 2, 3, 6, 7];
    for (x, &exp) in expected_red.iter().enumerate() {
        let off = x * 4;
        // BGRA layout in memory: [B,G,R,A]
        assert_eq!(vram[off + 2], exp, "x={}", x);
    }
}

#[test_case]
fn test_fill_rect_backbuffer_full_width_span() {
    let width = 6u32;
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
    fb.enable_double_buffering_from_vec(vec![0u32; (width * height) as usize]);

    let c = Color::with_alpha(12, 34, 56, 255);
    fb.fill_rect(Rect::new(0, 1, width, 2), c);

    let back = fb.back_buffer.as_ref().unwrap();
    for y in 0..height as usize {
        for x in 0..width as usize {
            let px = Color::from_u32(back[y * width as usize + x]);
            if (1..=2).contains(&y) {
                assert_eq!(px.red, 12, "({}, {})", x, y);
                assert_eq!(px.green, 34, "({}, {})", x, y);
                assert_eq!(px.blue, 56, "({}, {})", x, y);
            } else {
                assert_eq!(px.to_u32(), 0, "({}, {})", x, y);
            }
        }
    }
}

#[test_case]
fn test_draw_text_rgb565_mmio_run_write() {
    let width = 8u32;
    let height = 16u32;
    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 2,
        format: PixelFormat::Rgb565,
        bpp: 16,
    };

    let mut vram = vec![0u8; info.size()];
    let mut info2 = info.clone();
    info2.address = vram.as_mut_ptr() as u64;

    let mut fb = unsafe { Framebuffer::new(info2) };
    let fg = Color::with_alpha(255, 0, 0, 255); // red
    let bg = Color::with_alpha(0, 0, 0, 255); // black

    fb.draw_text(0, 0, "!", fg, bg);

    // 8x16 font '!' row index 2 is 0x18 -> bits at columns 3 and 4 are ON.
    // So pixels x=3,4 on row y=2 should be foreground red, neighbors remain black.
    let row = 2usize;
    let off = |x: usize| row * info.stride as usize + x * 2;

    // RGB565 little-endian bytes
    // red   = 0xF800 -> [0x00, 0xF8]
    // black = 0x0000 -> [0x00, 0x00]
    assert_eq!(&vram[off(2)..off(2) + 2], &[0x00, 0x00]);
    assert_eq!(&vram[off(3)..off(3) + 2], &[0x00, 0xF8]);
    assert_eq!(&vram[off(4)..off(4) + 2], &[0x00, 0xF8]);
    assert_eq!(&vram[off(5)..off(5) + 2], &[0x00, 0x00]);
}

#[test_case]
fn test_clear_rgb565_mmio() {
    let width = 6u32;
    let height = 3u32;
    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 2,
        format: PixelFormat::Rgb565,
        bpp: 16,
    };

    let mut vram = vec![0u8; info.size()];
    let mut info2 = info.clone();
    info2.address = vram.as_mut_ptr() as u64;
    let mut fb = unsafe { Framebuffer::new(info2) };

    fb.clear(Color::BLUE);

    // BLUE in RGB565 little-endian: 0x001F -> [0x1F, 0x00]
    for y in 0..height as usize {
        for x in 0..width as usize {
            let off = y * info.stride as usize + x * 2;
            assert_eq!(vram[off], 0x1F, "x={}, y={}", x, y);
            assert_eq!(vram[off + 1], 0x00, "x={}, y={}", x, y);
        }
    }
}

#[test_case]
fn test_draw_char_8x16_rgb565_mmio() {
    let width = 8u32;
    let height = 16u32;
    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 2,
        format: PixelFormat::Rgb565,
        bpp: 16,
    };

    let mut vram = vec![0u8; info.size()];
    let mut info2 = info.clone();
    info2.address = vram.as_mut_ptr() as u64;
    let mut fb = unsafe { Framebuffer::new(info2) };

    let fg = Color::RED;
    let bg = Color::BLACK;
    fb.draw_char_8x16(0, 0, '!', fg, Some(bg));

    // Row 2 of '!' has ON bits at columns 3,4.
    let row = 2usize;
    let off = |x: usize| row * info.stride as usize + x * 2;

    // red   = 0xF800 -> [0x00, 0xF8]
    // black = 0x0000 -> [0x00, 0x00]
    assert_eq!(&vram[off(2)..off(2) + 2], &[0x00, 0x00]);
    assert_eq!(&vram[off(3)..off(3) + 2], &[0x00, 0xF8]);
    assert_eq!(&vram[off(4)..off(4) + 2], &[0x00, 0xF8]);
    assert_eq!(&vram[off(5)..off(5) + 2], &[0x00, 0x00]);
}

// ── Session-3 regression tests ──────────────────────────────────────

/// draw_circle: symmetric 8-pixel pattern check on 32-bit backbuffer
#[test_case]
fn test_draw_circle_symmetric_32bit_backbuffer() {
    let width = 32u32;
    let height = 32u32;
    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 4,
        format: PixelFormat::Bgra8888,
        bpp: 32,
    };
    let mut fb = unsafe { Framebuffer::new(info.clone()) };
    fb.enable_double_buffering_from_vec(vec![0u32; (width * height) as usize]);

    let color = Color::with_alpha(0, 255, 0, 255);
    fb.draw_circle(16, 16, 8, color);

    // Verify 8-fold symmetry: for each pixel (cx+dx, cy+dy) there must be
    // pixels at all 8 mirrored positions.
    let buf = fb.back_buffer.as_ref().unwrap();
    let px = |x: i32, y: i32| -> bool {
        if x < 0 || y < 0 || x >= width as i32 || y >= height as i32 { return false; }
        buf[y as usize * width as usize + x as usize] != 0
    };

    let mut any_on = false;
    for dy in 0..=8i32 {
        for dx in 0..=8i32 {
            if px(16 + dx, 16 + dy) {
                any_on = true;
                assert!(px(16 - dx, 16 + dy), "sym -dx,+dy failed ({dx},{dy})");
                assert!(px(16 + dx, 16 - dy), "sym +dx,-dy failed ({dx},{dy})");
                assert!(px(16 - dx, 16 - dy), "sym -dx,-dy failed ({dx},{dy})");
                assert!(px(16 + dy, 16 + dx), "sym +dy,+dx failed ({dx},{dy})");
                assert!(px(16 - dy, 16 + dx), "sym -dy,+dx failed ({dx},{dy})");
                assert!(px(16 + dy, 16 - dx), "sym +dy,-dx failed ({dx},{dy})");
                assert!(px(16 - dy, 16 - dx), "sym -dy,-dx failed ({dx},{dy})");
            }
        }
    }
    assert!(any_on, "circle must set at least one pixel");
}

/// fill_circle: all pixels inside radius must be set, no gaps
#[test_case]
fn test_fill_circle_no_gaps_32bit_backbuffer() {
    let width = 32u32;
    let height = 32u32;
    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 4,
        format: PixelFormat::Bgra8888,
        bpp: 32,
    };
    let mut fb = unsafe { Framebuffer::new(info.clone()) };
    fb.enable_double_buffering_from_vec(vec![0u32; (width * height) as usize]);

    let color = Color::with_alpha(0, 0, 255, 255);
    let cx = 16i32;
    let cy = 16i32;
    let r = 7i32;
    fb.fill_circle(cx, cy, r as u32, color);

    let buf = fb.back_buffer.as_ref().unwrap();
    // Every pixel strictly inside the circle must be coloured
    for y in (cy - r)..=(cy + r) {
        for x in (cx - r)..=(cx + r) {
            let dist_sq = (x - cx) * (x - cx) + (y - cy) * (y - cy);
            if dist_sq < (r - 1) * (r - 1) {
                let idx = y as usize * width as usize + x as usize;
                assert_ne!(buf[idx], 0, "gap at ({x},{y}), dist_sq={dist_sq}");
            }
        }
    }
}

/// draw_rect: outline must have exactly the border pixels set
#[test_case]
fn test_draw_rect_outline_32bit_backbuffer() {
    let width = 20u32;
    let height = 20u32;
    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 4,
        format: PixelFormat::Bgra8888,
        bpp: 32,
    };
    let mut fb = unsafe { Framebuffer::new(info.clone()) };
    fb.enable_double_buffering_from_vec(vec![0u32; (width * height) as usize]);

    let color = Color::with_alpha(255, 0, 0, 255);
    fb.draw_rect(Rect::new(2, 3, 10, 8), color);

    let buf = fb.back_buffer.as_ref().unwrap();
    let px = |x: i32, y: i32| buf[y as usize * width as usize + x as usize] != 0;

    // top edge y=3, bottom edge y=10
    for x in 2..12 {
        assert!(px(x, 3), "top edge missing at x={x}");
        assert!(px(x, 10), "bottom edge missing at x={x}");
    }
    // left edge x=2, right edge x=11
    for y in 3..=10 {
        assert!(px(2, y), "left edge missing at y={y}");
        assert!(px(11, y), "right edge missing at y={y}");
    }
    // interior must be empty
    for y in 4..10 {
        for x in 3..11 {
            assert!(!px(x, y), "interior set at ({x},{y})");
        }
    }
}

/// draw_line steep: matches naive Bresenham on MMIO (RGB565)
#[test_case]
fn test_draw_line_steep_rgb565_mmio() {
    let width = 20u32;
    let height = 20u32;
    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 2,
        format: PixelFormat::Rgb565,
        bpp: 16,
    };

    let mut vram_opt = vec![0u8; info.size()];
    let mut vram_naive = vec![0u8; info.size()];
    let mut info_opt = info.clone();
    info_opt.address = vram_opt.as_mut_ptr() as u64;
    let mut info_naive = info.clone();
    info_naive.address = vram_naive.as_mut_ptr() as u64;

    let mut fb_opt = unsafe { Framebuffer::new(info_opt) };
    let mut fb_naive = unsafe { Framebuffer::new(info_naive) };

    let color = Color::with_alpha(0, 255, 0, 255);

    // steep lines (dy > dx)
    let cases: [(i32, i32, i32, i32); 4] = [
        (5, 0, 7, 19),
        (10, 19, 8, 0),
        (3, 2, 5, 18),
        (15, 15, 12, 0),
    ];

    for (x1, y1, x2, y2) in cases {
        fb_opt.draw_line(x1, y1, x2, y2, color);

        // naive Bresenham
        let mut x = x1;
        let mut y = y1;
        let dx = (x2 - x1).abs();
        let dy = -(y2 - y1).abs();
        let sx = if x1 < x2 { 1 } else { -1 };
        let sy = if y1 < y2 { 1 } else { -1 };
        let mut err = dx + dy;
        loop {
            fb_naive.set_pixel(x, y, color);
            if x == x2 && y == y2 { break; }
            let e2 = 2 * err;
            if e2 >= dy { err += dy; x += sx; }
            if e2 <= dx { err += dx; y += sy; }
        }

        assert_eq!(vram_opt, vram_naive, "steep line ({x1},{y1})->({x2},{y2}) mismatch");

        // reset
        vram_opt.fill(0);
        vram_naive.fill(0);
    }
}

/// copy_rect overlapping on MMIO: verify data integrity
#[test_case]
fn test_copy_rect_mmio_overlap_integrity() {
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

    let mut vram = vec![0u8; info.size()];
    let mut info2 = info.clone();
    info2.address = vram.as_mut_ptr() as u64;
    let mut fb = unsafe { Framebuffer::new(info2) };

    // Paint a 4x4 block at (0,0) with known pattern
    for y in 0..4u32 {
        for x in 0..4u32 {
            let c = Color::with_alpha((x * 60) as u8, (y * 60) as u8, 128, 255);
            fb.set_pixel(x as i32, y as i32, c);
        }
    }

    // Copy overlapping: (0,0) 4x4 → (2,0) — overlapping by 2 columns
    fb.copy_rect(Rect::new(0, 0, 4, 4), 2, 0);

    // Original columns 0-1 should remain, columns 2-5 should have the copy
    for y in 0..4u32 {
        for x in 0..4u32 {
            let expected = Color::with_alpha((x * 60) as u8, (y * 60) as u8, 128, 255);
            let off = (y as usize * width as usize + (x as usize + 2)) * 4;
            let b = vram[off];
            let g = vram[off + 1];
            let r = vram[off + 2];
            let a = vram[off + 3];
            let actual = Color::with_alpha(r, g, b, a);
            assert_eq!(
                (actual.red, actual.green, actual.blue),
                (expected.red, expected.green, expected.blue),
                "copy_rect mismatch at dest ({},{y})", x + 2
            );
        }
    }
}

/// draw_text 24bpp single-pass MMIO: verify fg/bg pattern for '!'
#[test_case]
fn test_draw_text_24bit_mmio_single_pass() {
    let width = 8u32;
    let height = 16u32;
    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 3,
        format: PixelFormat::Bgr888,
        bpp: 24,
    };

    let mut vram = vec![0u8; info.size()];
    let mut info2 = info.clone();
    info2.address = vram.as_mut_ptr() as u64;
    let mut fb = unsafe { Framebuffer::new(info2) };

    let fg = Color::with_alpha(255, 0, 0, 255); // red
    let bg = Color::with_alpha(0, 0, 255, 255); // blue

    fb.draw_text(0, 0, "!", fg, bg);

    // Row 2, '!' glyph = 0x18 -> bits 3,4 ON
    let row = 2usize;
    let off = |x: usize| row * info.stride as usize + x * 3;

    // Bgr888: fg red = [0x00, 0x00, 0xFF], bg blue = [0xFF, 0x00, 0x00]
    assert_eq!(&vram[off(2)..off(2) + 3], &[0xFF, 0x00, 0x00], "bg at x=2");
    assert_eq!(&vram[off(3)..off(3) + 3], &[0x00, 0x00, 0xFF], "fg at x=3");
    assert_eq!(&vram[off(4)..off(4) + 3], &[0x00, 0x00, 0xFF], "fg at x=4");
    assert_eq!(&vram[off(5)..off(5) + 3], &[0xFF, 0x00, 0x00], "bg at x=5");
}

/// draw_char_8x16 24bpp MMIO single-pass: verify fg/bg pattern
#[test_case]
fn test_draw_char_8x16_24bit_mmio() {
    let width = 8u32;
    let height = 16u32;
    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 3,
        format: PixelFormat::Bgr888,
        bpp: 24,
    };

    let mut vram = vec![0u8; info.size()];
    let mut info2 = info.clone();
    info2.address = vram.as_mut_ptr() as u64;
    let mut fb = unsafe { Framebuffer::new(info2) };

    let fg = Color::GREEN;
    let bg = Color::BLACK;
    fb.draw_char_8x16(0, 0, '!', fg, Some(bg));

    // Row 2, 0x18 -> bits 3,4 ON
    let row = 2usize;
    let off = |x: usize| row * info.stride as usize + x * 3;

    // Bgr888: green = [0x00, 0x80, 0x00], black = [0x00, 0x00, 0x00]
    assert_eq!(&vram[off(2)..off(2) + 3], &[0x00, 0x00, 0x00], "bg");
    assert_eq!(&vram[off(3)..off(3) + 3], &[0x00, 0x80, 0x00], "fg");
    assert_eq!(&vram[off(4)..off(4) + 3], &[0x00, 0x80, 0x00], "fg");
    assert_eq!(&vram[off(5)..off(5) + 3], &[0x00, 0x00, 0x00], "bg");
}

/// draw_image 16bpp MMIO: blit_mmio_row RGB565 path
#[test_case]
fn test_draw_image_rgb565_mmio() {
    let width = 4u32;
    let height = 2u32;
    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 2,
        format: PixelFormat::Rgb565,
        bpp: 16,
    };

    let mut vram = vec![0u8; info.size()];
    let mut info2 = info.clone();
    info2.address = vram.as_mut_ptr() as u64;
    let mut fb = unsafe { Framebuffer::new(info2) };

    let img = Image::filled(width, height, Color::with_alpha(255, 0, 0, 255));
    fb.draw_image(&img, 0, 0);

    // Red in RGB565 = 0xF800, LE = [0x00, 0xF8]
    for y in 0..height as usize {
        for x in 0..width as usize {
            let off = y * info.stride as usize + x * 2;
            assert_eq!(&vram[off..off + 2], &[0x00, 0xF8], "pixel ({x},{y})");
        }
    }
}

/// write_opaque_run_32bit: verify SIMD pack_rgba_to_bgra path
#[test_case]
fn test_write_opaque_run_32bit_simd_pack() {
    let width = 64u32;
    let height = 4u32;
    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 4,
        format: PixelFormat::Bgra8888,
        bpp: 32,
    };

    let mut vram = vec![0u8; info.size()];
    let mut info2 = info.clone();
    info2.address = vram.as_mut_ptr() as u64;
    let mut fb = unsafe { Framebuffer::new(info2) };

    // Build a 64-wide RGBA image row
    let img = Image::filled(width, 1, Color::with_alpha(10, 20, 30, 255));
    fb.draw_image(&img, 0, 0);

    // Verify BGRA in VRAM: B=30, G=20, R=10, A=255
    for x in 0..width as usize {
        let off = x * 4;
        assert_eq!(vram[off], 30, "B at x={x}");
        assert_eq!(vram[off + 1], 20, "G at x={x}");
        assert_eq!(vram[off + 2], 10, "R at x={x}");
        assert_eq!(vram[off + 3], 255, "A at x={x}");
    }
}
