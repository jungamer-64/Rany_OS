use super::*;
use crate::graphics::image::Image;

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

/// Create an MMIO-backed Framebuffer and its backing memory.
/// Returns `(framebuffer, backing_vec)`. The Vec must outlive the Framebuffer.
fn make_mmio_fb(info: &FramebufferInfo) -> (Framebuffer, Vec<u8>) {
    let mut mem = vec![0u8; info.size()];
    let addr = mem.as_mut_ptr() as u64;
    let mut info2 = info.clone();
    info2.address = addr;
    let fb = unsafe { Framebuffer::new(info2) };
    (fb, mem)
}

/// Create a double-buffered Framebuffer (no MMIO memory).
fn make_backbuf_fb(info: &FramebufferInfo) -> Framebuffer {
    let mut fb = unsafe { Framebuffer::new(info.clone()) };
    let back = vec![0u32; (info.width * info.height) as usize];
    fb.enable_double_buffering_from_vec(back);
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

/// Compare SIMD pack function against scalar reference for multiple sizes.
/// `simd_fn` receives (src_ptr, dst_ptr, byte_len).
/// `scalar_fn` receives (&[u8], &mut [u8]).
fn assert_simd_matches_scalar(
    sizes: &[usize],
    seed_mul: usize,
    simd_fn: unsafe fn(*const u8, *mut u8, usize),
    scalar_fn: fn(&[u8], &mut [u8]),
) {
    for &len in sizes {
        let mut src = vec![0u8; len * 4];
        for (i, b) in src.iter_mut().enumerate() {
            *b = (i * seed_mul % 251) as u8;
        }
        let mut dst_simd = vec![0u8; src.len()];
        let mut dst_scalar = vec![0u8; src.len()];
        unsafe {
            simd_fn(src.as_ptr(), dst_simd.as_mut_ptr(), src.len());
        }
        scalar_fn(&src, &mut dst_scalar);
        assert_eq!(dst_simd, dst_scalar, "mismatch at size {len}");
    }
}

/// Create a framebuffer with MMIO backing AND a backbuffer (for flush tests).
fn make_flush_fb(info: &FramebufferInfo) -> (Framebuffer, Vec<u8>) {
    let (mut fb, vram) = make_mmio_fb(info);
    fb.enable_double_buffering_from_vec(vec![0u32; (info.width * info.height) as usize]);
    (fb, vram)
}

/// Compare SIMD BGR24 8-pixel pack against scalar reference.
fn assert_bgr24_8px_matches_scalar(
    seed_mul: usize,
    is_bgr: bool,
    simd_fn: unsafe fn(*const u8, *mut u8, bool),
) {
    let len = 8usize;
    let mut src = vec![0u8; len * 4];
    for (i, b) in src.iter_mut().enumerate() {
        *b = (i * seed_mul % 251) as u8;
    }
    let mut dst_simd = vec![0u8; len * 3];
    unsafe {
        simd_fn(src.as_ptr(), dst_simd.as_mut_ptr(), is_bgr);
    }
    let mut dst_scalar = vec![0u8; len * 3];
    for p in 0..len {
        let s = p * 4;
        if is_bgr {
            dst_scalar[p * 3] = src[s + 2];
            dst_scalar[p * 3 + 1] = src[s + 1];
            dst_scalar[p * 3 + 2] = src[s];
        } else {
            dst_scalar[p * 3] = src[s];
            dst_scalar[p * 3 + 1] = src[s + 1];
            dst_scalar[p * 3 + 2] = src[s + 2];
        }
    }
    assert_eq!(dst_simd, dst_scalar);
}

mod draw_and_pack;
pub use draw_and_pack::*;
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

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
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

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
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

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
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

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
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

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
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

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
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
    use crate::graphics::packer::PACKER_MODE;
    use core::sync::atomic::Ordering;
    PACKER_MODE.load(Ordering::Relaxed)
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
#[cfg(feature = "std")]
fn test_packer_env_override() {
    // Reset cached mode so get_packer_mode() re-detects with env override
    use crate::graphics::packer::PACKER_MODE;
    use core::sync::atomic::Ordering;
    PACKER_MODE.store(0, Ordering::Relaxed);
    // Ensure RANY_PACKER override sets the PACKER_MODE
    unsafe {
        std::env::set_var("RANY_PACKER", "scalar");
    }
    let src = vec![0u8; 1024];
    let mut dst = vec![0u8; 1024];
    Framebuffer::pack_rgba_to_bgra(&src, &mut dst);
    assert_eq!(_test_get_packer_mode(), 1);
    unsafe {
        std::env::remove_var("RANY_PACKER");
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
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
