use super::*;
use crate::graphics::FramebufferInfo;
use crate::graphics::image::Image;
use alloc::vec;

// ---- Shared helpers to reduce duplication across FB test files ----

/// Build a `FramebufferInfo` for the given format.
fn fb_info(w: u32, h: u32, fmt: PixelFormat) -> FramebufferInfo {
    let bpp: u8 = match fmt {
        PixelFormat::Bgra8888 | PixelFormat::Rgba8888 => 32,
        PixelFormat::Bgr888 | PixelFormat::Rgb888 => 24,
        PixelFormat::Rgb565 => 16,
    };
    FramebufferInfo {
        address: 0,
        width: w,
        height: h,
        stride: w * (bpp as u32 / 8),
        format: fmt,
        bpp,
    }
}

fn make_memory_fb(info: &FramebufferInfo) -> Framebuffer {
    let layout = FramebufferLayout::new(info.width, info.height, info.stride, info.format).unwrap();
    Framebuffer::new(layout, PixelBuffer::Memory(vec![0; info.size()])).unwrap()
}

fn memory_bytes(framebuffer: &Framebuffer) -> &[u8] {
    match &framebuffer.pixels {
        PixelBuffer::Memory(bytes) => bytes,
        PixelBuffer::Scanout(_) => panic!("RAM fixture"),
    }
}

/// Create a double-buffered Framebuffer (no MMIO memory).
fn make_backbuf_fb(info: &FramebufferInfo) -> Framebuffer {
    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vec![0u8; info.size()]),
    )
    .expect("framebuffer workspace");
    let back = vec![0u32; (info.width * info.height) as usize];
    fb.enable_double_buffering_from_vec(back)
        .expect("valid back plane");
    fb
}

/// Naive Bresenham line draw for comparison testing.
fn draw_line_naive(fb: &mut Framebuffer, x1: i32, y1: i32, x2: i32, y2: i32, color: Color) {
    let mut x = x1;
    let mut y = y1;
    let dx = (x2 - x1).abs();
    let dy = -(y2 - y1).abs();
    let sx = if x1 < x2 { 1 } else { -1 };
    let sy = if y1 < y2 { 1 } else { -1 };
    let mut err = dx + dy;
    // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
    loop {
        fb.set_pixel(x, y, color);
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

/// Create a framebuffer with MMIO backing AND a backbuffer (for flush tests).
fn make_flush_fb(info: &FramebufferInfo) -> Framebuffer {
    let mut fb = make_memory_fb(info);
    fb.enable_double_buffering_from_vec(vec![0u32; (info.width * info.height) as usize])
        .expect("valid back plane");
    fb
}

mod draw_and_pack;
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
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

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vec![0u8; info.size()]),
    )
    .expect("framebuffer workspace");
    let back = vec![0u32; (info.width * info.height) as usize];
    fb.enable_double_buffering_from_vec(back)
        .expect("valid back plane");

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

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
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

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vec![0u8; info.size()]),
    )
    .expect("framebuffer workspace");
    let back = vec![0u32; (info.width * info.height) as usize];
    fb.enable_double_buffering_from_vec(back)
        .expect("valid back plane");

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

#[cfg(any(feature = "std", target_os = "linux"))]
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(
    all(test, any(feature = "std", target_os = "linux")),
    ignore = "benchmark-style helper"
)]
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

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vec![0u8; info.size()]),
    )
    .expect("framebuffer workspace");
    let back = vec![0u32; (info.width * info.height) as usize];
    fb.enable_double_buffering_from_vec(back)
        .expect("valid back plane");

    let img = Image::filled(width, height, Color::with_alpha(64, 128, 192, 255));

    let start = Instant::now();
    for _ in 0..10 {
        fb.draw_image(&img, 0, 0);
    }
    let elapsed = start.elapsed();
    log::info!("bench_draw_image_bulk: {:?}", elapsed);
}

#[cfg(any(feature = "std", target_os = "linux"))]
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(
    all(test, any(feature = "std", target_os = "linux")),
    ignore = "benchmark-style helper"
)]
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

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vec![0u8; info.size()]),
    )
    .expect("framebuffer workspace");
    let back = vec![0u32; (info.width * info.height) as usize];
    fb.enable_double_buffering_from_vec(back)
        .expect("valid back plane");

    let img = Image::filled(width, height, Color::with_alpha(64, 128, 192, 255));

    let start = Instant::now();
    for _ in 0..10 {
        fb.draw_image(&img, 0, 0);
    }
    let elapsed = start.elapsed();
    log::info!("bench_draw_image_24bit_bulk: {:?}", elapsed);
}

#[cfg(any(feature = "std", target_os = "linux"))]
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(
    all(test, any(feature = "std", target_os = "linux")),
    ignore = "benchmark-style helper"
)]
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

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vec![0u8; info.size()]),
    )
    .expect("framebuffer workspace");
    let back = vec![0u32; (info.width * info.height) as usize];
    fb.enable_double_buffering_from_vec(back)
        .expect("valid back plane");

    let img = Image::filled(width, height, Color::with_alpha(64, 128, 192, 255));

    let start = Instant::now();
    for _ in 0..10 {
        fb.draw_image(&img, 0, 0);
    }
    let elapsed = start.elapsed();
    log::info!("bench_draw_image_rgba_bulk: {:?}", elapsed);
}

#[cfg(any(feature = "std", target_os = "linux"))]
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(
    all(test, any(feature = "std", target_os = "linux")),
    ignore = "benchmark-style helper"
)]
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

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vec![0u8; info.size()]),
    )
    .expect("framebuffer workspace");
    let back = vec![0u32; (info.width * info.height) as usize];
    fb.enable_double_buffering_from_vec(back)
        .expect("valid back plane");

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

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_write_bgr_run_small_mmio() {
    let width = 10u32;
    let height = 1u32;
    let stride = width * 3;
    let vram = vec![0u8; (stride * height) as usize];
    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride,
        format: PixelFormat::Bgr888,
        bpp: 24,
    };

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vram),
    )
    .expect("framebuffer workspace");

    // small run (<= SMALL_BGR_DIRECT_MMIO)
    fb.draw_hline(2, 5, 0, Color::with_alpha(10, 20, 30, 255));

    for px in 2..=5 {
        let off = px as usize * 3;
        assert_eq!(memory_bytes(&fb)[off], 30);
        assert_eq!(memory_bytes(&fb)[off + 1], 20);
        assert_eq!(memory_bytes(&fb)[off + 2], 10);
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_write_bgr_run_large_mmio() {
    let width = 80u32;
    let height = 1u32;
    let stride = width * 3;
    let vram = vec![0u8; (stride * height) as usize];
    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride,
        format: PixelFormat::Bgr888,
        bpp: 24,
    };

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vram),
    )
    .expect("framebuffer workspace");

    fb.draw_hline(0, width as i32 - 1, 0, Color::with_alpha(1, 2, 3, 255));

    // check first and last pixel
    assert_eq!(memory_bytes(&fb)[0], 3);
    assert_eq!(memory_bytes(&fb)[1], 2);
    assert_eq!(memory_bytes(&fb)[2], 1);

    let last_off = (width as usize - 1) * 3;
    assert_eq!(memory_bytes(&fb)[last_off], 3);
    assert_eq!(memory_bytes(&fb)[last_off + 1], 2);
    assert_eq!(memory_bytes(&fb)[last_off + 2], 1);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_write_bgr_run_large_mmio_full() {
    // Verify full buffer contents for a large BGR run to catch alignment
    // and pattern rotation bugs in the direct-MMIO path.
    let width = 200usize;
    let height = 1usize;
    let stride = width * 3;
    let vram = vec![0u8; stride * height];
    let info = FramebufferInfo {
        address: 0,
        width: width as u32,
        height: height as u32,
        stride: stride as u32,
        format: PixelFormat::Bgr888,
        bpp: 24,
    };

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vram),
    )
    .expect("framebuffer workspace");

    fb.draw_hline(0, width as i32 - 1, 0, Color::with_alpha(1, 2, 3, 255));

    for px in 0..width {
        let off = px * 3;
        assert_eq!(memory_bytes(&fb)[off], 3);
        assert_eq!(memory_bytes(&fb)[off + 1], 2);
        assert_eq!(memory_bytes(&fb)[off + 2], 1);
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_write_bgr_run_large_mmio_full_unaligned() {
    // Starting at an unaligned byte offset should still produce the
    // canonical repeating BGR pattern across the buffer.
    let width = 200usize;
    let height = 1usize;
    let info = FramebufferInfo {
        address: 0,
        width: width as u32,
        height: height as u32,
        stride: (width * 3) as u32,
        format: PixelFormat::Bgr888,
        bpp: 24,
    };

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vec![0u8; info.size()]),
    )
    .expect("framebuffer workspace");

    // Draw full-width run starting at the unaligned base
    fb.write_bgr_run(0, width, Color::with_alpha(1, 2, 3, 255));

    for px in 0..width {
        let off = px * 3;
        assert_eq!(memory_bytes(&fb)[off], 3);
        assert_eq!(memory_bytes(&fb)[off + 1], 2);
        assert_eq!(memory_bytes(&fb)[off + 2], 1);
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_write_bgr_run_small_mmio_pairs_aligned() {
    // Test pair-based fast-path when address is 4-byte aligned
    let vram = vec![0u8; 32];
    let info = FramebufferInfo {
        address: 0,
        width: 10,
        height: 1,
        stride: 10 * 3,
        format: PixelFormat::Bgr888,
        bpp: 24,
    };

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vram),
    )
    .expect("framebuffer workspace");

    // Choose dst_offset_bytes = 4 (which is 4-byte aligned)
    fb.write_bgr_run(4, 3, Color::with_alpha(11, 22, 33, 255));

    // Expect three pixels of (b=33,g=22,r=11)
    for i in 0..3 {
        let off = 4 + i * 3;
        assert_eq!(memory_bytes(&fb)[off], 33);
        assert_eq!(memory_bytes(&fb)[off + 1], 22);
        assert_eq!(memory_bytes(&fb)[off + 2], 11);
    }
}

#[cfg(any(feature = "std", target_os = "linux"))]
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(
    all(test, any(feature = "std", target_os = "linux")),
    ignore = "benchmark-style helper"
)]
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

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vec![0u8; info.size()]),
    )
    .expect("framebuffer workspace");
    let back = vec![0u32; (info.width * info.height) as usize];
    fb.enable_double_buffering_from_vec(back)
        .expect("valid back plane");

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

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
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
    let mut fb_opt = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vec![0u8; info.size()]),
    )
    .expect("framebuffer workspace");
    let mut fb_naive = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vec![0u8; info.size()]),
    )
    .expect("framebuffer workspace");
    let back = vec![0u32; (info.width * info.height) as usize];
    fb_opt
        .enable_double_buffering_from_vec(back.clone())
        .expect("valid back plane");
    fb_naive
        .enable_double_buffering_from_vec(back)
        .expect("valid back plane");

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

        // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
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

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
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

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vec![0u8; info.size()]),
    )
    .expect("framebuffer workspace");
    let back = vec![0u32; (info.width * info.height) as usize];
    fb.enable_double_buffering_from_vec(back)
        .expect("valid back plane");

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

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn owned_planes_preserve_padding_and_format_bytes() {
    let color = Color::with_alpha(0x12, 0x34, 0x56, 0x78);
    for (format, expected) in [
        (PixelFormat::Bgra8888, &[0x56, 0x34, 0x12, 0x78][..]),
        (PixelFormat::Rgba8888, &[0x12, 0x34, 0x56, 0x78][..]),
        (PixelFormat::Bgr888, &[0x56, 0x34, 0x12][..]),
        (PixelFormat::Rgb888, &[0x12, 0x34, 0x56][..]),
        (PixelFormat::Rgb565, &[0xAA, 0x11][..]),
    ] {
        for buffered in [false, true] {
            let stride = 5 * expected.len() + 3;
            let layout = FramebufferLayout::new(5, 3, stride as u32, format).unwrap();
            let mut fb =
                Framebuffer::new(layout, PixelBuffer::Memory(vec![0xCC; layout.size()])).unwrap();
            if buffered {
                fb.enable_double_buffering().unwrap();
            }
            fb.fill_rect(Rect::new(-2, -1, 20, 20), color);
            fb.flush_dirty_area();
            let PixelBuffer::Memory(bytes) = fb.into_pixels() else {
                panic!("owned RAM destination");
            };
            for row in bytes.chunks_exact(stride) {
                for pixel in row[..5 * expected.len()].chunks_exact(expected.len()) {
                    assert_eq!(pixel, expected);
                }
                assert_eq!(&row[5 * expected.len()..], &[0xCC; 3]);
            }
        }
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn displacement_clipping_and_overlap_match_a_source_snapshot() {
    for buffered in [false, true] {
        for (source, dx, dy) in [
            (Rect::new(-2, -1, 7, 5), 0, 1),
            (Rect::new(1, 1, 5, 4), -2, -1),
            (Rect::new(0, 0, 6, 5), 1, 1),
            (Rect::new(i32::MIN, i32::MIN, u32::MAX, u32::MAX), 0, 0),
            (Rect::new(0, 0, u32::MAX, u32::MAX), i32::MAX, i32::MAX),
        ] {
            let info = fb_info(7, 6, PixelFormat::Bgra8888);
            let mut fb = make_memory_fb(&info);
            if buffered {
                fb.enable_double_buffering().unwrap();
            }
            for y in 0..6 {
                for x in 0..7 {
                    fb.set_pixel(
                        x,
                        y,
                        Color::with_alpha(x as u8, y as u8, (x + y * 7) as u8, 255),
                    );
                }
            }
            let mut snapshot = Vec::new();
            for y in 0..6 {
                for x in 0..7 {
                    snapshot.push(fb.get_pixel(x, y));
                }
            }
            fb.copy_rect(source, dx, dy);
            // Independent destination-to-source translation avoids production clipping helpers.
            for y in 0..6 {
                for x in 0..7 {
                    let ox = x as i64 - dx as i64;
                    let oy = y as i64 - dy as i64;
                    let sx = source.x as i64 + ox;
                    let sy = source.y as i64 + oy;
                    let expected = if ox >= 0
                        && oy >= 0
                        && ox < source.width as i64
                        && oy < source.height as i64
                        && (0..7).contains(&sx)
                        && (0..6).contains(&sy)
                    {
                        snapshot[sy as usize * 7 + sx as usize]
                    } else {
                        snapshot[y as usize * 7 + x as usize]
                    };
                    assert_eq!(fb.get_pixel(x, y), expected);
                }
            }
        }
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn invalid_plane_admission_keeps_the_existing_back_plane() {
    let info = fb_info(4, 3, PixelFormat::Bgra8888);
    let layout = FramebufferLayout::new(4, 3, 16, info.format).unwrap();
    assert!(matches!(
        Framebuffer::new(layout, PixelBuffer::Memory(vec![0; 47])),
        Err(FramebufferError::BufferTooSmall)
    ));
    let mut fb = make_backbuf_fb(&info);
    fb.set_pixel(1, 1, Color::BLUE);
    assert_eq!(
        fb.enable_double_buffering_from_vec(vec![0; 11]),
        Err(FramebufferError::BufferTooSmall)
    );
    assert_eq!(fb.get_pixel(1, 1), Color::BLUE);
}
