use super::*;


mod blit_fill_dirty;
#[test_case]
pub(crate) fn test_draw_line_matches_naive_32bit_backbuffer() {
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
pub(crate) fn test_draw_line_matches_naive_24bit_backbuffer() {
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
pub(crate) fn test_draw_text_space_24bit_backbuffer() {
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
pub(crate) fn test_draw_image_32bit_mmio() {
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
pub(crate) fn test_draw_image_24bit_mmio() {
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
pub(crate) fn test_draw_image_32bit_mmio_rgba() {
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
pub(crate) fn test_write_bytes_mmio_alignment() {
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
pub(crate) fn test_write_bgr_run_large() {
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
pub(crate) fn test_write_opaque_run_24bit_even_odd_mmio() {
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
pub(crate) fn test_pack_rgba_to_bgra_basic() {
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
pub(crate) fn test_pack_rgba_to_bgra_ssse3_matches_scalar() {
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
pub(crate) fn test_pack_rgba_to_bgra_avx2_matches_scalar() {
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
pub(crate) fn test_pack_rgba_to_bgr24_avx2_matches_scalar() {
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
pub(crate) fn test_pack_rgba_to_bgr24_ssse3_matches_scalar() {
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
pub(crate) fn test_pack_rgba_to_bgra_neon_matches_scalar() {
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
