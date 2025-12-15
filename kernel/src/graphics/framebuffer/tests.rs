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
    unsafe { std::env::set_var("RANY_PACKER", "scalar"); }
    let src = vec![0u8; 1024];
    let mut dst = vec![0u8; 1024];
    Framebuffer::pack_rgba_to_bgra(&src, &mut dst);
    assert_eq!(_test_get_packer_mode(), 1);
    unsafe { std::env::remove_var("RANY_PACKER"); }
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
            Framebuffer::pack_rgba_to_bgra_ssse3(src.as_ptr(), dst_simd.as_mut_ptr(), src.len());
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
