use super::*;


mod _split_1;
pub use _split_1::*;
#[cfg(target_arch = "aarch64")]
#[test_case]
pub(crate) fn test_pack_rgba_to_bgr24_neon_matches_scalar() {
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
pub(crate) fn test_pack_rgba_to_bgr24_neon_matches_scalar_rgb() {
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
pub(crate) fn test_pack_rgba_to_bgra_scalar_random() {
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
pub(crate) fn test_draw_image_bgra_stream_matches_backbuffer() {
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
pub(crate) fn test_fill_rect_32bit_mmio() {
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
pub(crate) fn test_fill_rect_rgb565_mmio() {
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
pub(crate) fn test_dirty_rect_tracking() {
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
pub(crate) fn test_dirty_rect_flush_only_marked_area() {
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
pub(crate) fn test_draw_text_partial_left_clip_32bit_backbuffer() {
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
pub(crate) fn test_draw_image_24bit_rgb888_backbuffer() {
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
pub(crate) fn test_draw_hline_24bit_rgb888_mmio() {
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
pub(crate) fn test_draw_hline_rgb565_mmio() {
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
pub(crate) fn test_blit_rect_24bit_rgb888_backbuffer_flush() {
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
pub(crate) fn test_blit_rect_24bit_rgb888_backbuffer_flush_odd_width() {
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
pub(crate) fn test_blit_rect_24bit_bgr888_backbuffer_flush() {
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
pub(crate) fn test_blit_rect_16bit_rgb565_backbuffer_flush() {
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
