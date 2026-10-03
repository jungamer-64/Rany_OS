use super::*;

pub use crate::graphics::packer::qemu_tests::*;

pub fn wave6_packer_env_override_no_std_smoke() -> bool {
    let previous_override = crate::graphics::packer::qemu_test_get_packer_mode_override();

    crate::graphics::packer::qemu_test_set_packer_mode_override(1);

    let mode_forced_scalar = crate::graphics::packer::get_packer_mode() == 1;
    let mut packer_runs = false;
    if mode_forced_scalar {
        let src = vec![0u8, 1, 2, 3, 10, 20, 30, 40, 90, 80, 70, 60];
        let mut dst = vec![0u8; src.len()];
        crate::graphics::packer::pack_rgba_to_bgra(&src, &mut dst);
        packer_runs = dst == vec![2, 1, 0, 3, 30, 20, 10, 40, 70, 80, 90, 60];
    }

    crate::graphics::packer::qemu_test_clear_packer_mode_override();
    if previous_override != 0 {
        crate::graphics::packer::qemu_test_set_packer_mode_override(previous_override);
    }

    mode_forced_scalar && packer_runs
}

// ── Wave 9: session-3 optimisation regression smoke tests ───────────

/// draw_circle 8-fold symmetry check
pub fn wave9_draw_circle_symmetric_smoke() -> bool {
    let (w, h) = (32u32, 32u32);
    let info = FramebufferInfo {
        address: 0,
        width: w,
        height: h,
        stride: w * 4,
        format: PixelFormat::Bgra8888,
        bpp: 32,
    };
    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vec![0u8; info.size()]),
    )
    .expect("framebuffer workspace");
    fb.enable_double_buffering_from_vec(vec![0u32; (w * h) as usize]);
    fb.draw_circle(16, 16, 8, Color::with_alpha(0, 255, 0, 255));
    let buf = fb.back_buffer.as_ref().unwrap();
    let px = |x: i32, y: i32| -> bool {
        if x < 0 || y < 0 || x >= w as i32 || y >= h as i32 {
            return false;
        }
        buf[y as usize * w as usize + x as usize] != 0
    };
    let mut any = false;
    for dy in 0..=8i32 {
        for dx in 0..=8i32 {
            if px(16 + dx, 16 + dy) {
                any = true;
                if !(px(16 - dx, 16 + dy)
                    && px(16 + dx, 16 - dy)
                    && px(16 - dx, 16 - dy)
                    && px(16 + dy, 16 + dx)
                    && px(16 - dy, 16 + dx)
                    && px(16 + dy, 16 - dx)
                    && px(16 - dy, 16 - dx))
                {
                    return false;
                }
            }
        }
    }
    any
}

/// fill_circle: no interior gaps
pub fn wave9_fill_circle_no_gaps_smoke() -> bool {
    let (w, h) = (32u32, 32u32);
    let info = FramebufferInfo {
        address: 0,
        width: w,
        height: h,
        stride: w * 4,
        format: PixelFormat::Bgra8888,
        bpp: 32,
    };
    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vec![0u8; info.size()]),
    )
    .expect("framebuffer workspace");
    fb.enable_double_buffering_from_vec(vec![0u32; (w * h) as usize]);
    let (cx, cy, r) = (16i32, 16i32, 7i32);
    fb.fill_circle(cx, cy, r, Color::with_alpha(0, 0, 255, 255));
    let buf = fb.back_buffer.as_ref().unwrap();
    for y in (cy - r)..=(cy + r) {
        for x in (cx - r)..=(cx + r) {
            let d = (x - cx) * (x - cx) + (y - cy) * (y - cy);
            if d < (r - 1) * (r - 1) {
                if buf[y as usize * w as usize + x as usize] == 0 {
                    return false;
                }
            }
        }
    }
    true
}

/// draw_rect: outline correctness
pub fn wave9_draw_rect_outline_smoke() -> bool {
    let (w, h) = (20u32, 20u32);
    let info = FramebufferInfo {
        address: 0,
        width: w,
        height: h,
        stride: w * 4,
        format: PixelFormat::Bgra8888,
        bpp: 32,
    };
    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vec![0u8; info.size()]),
    )
    .expect("framebuffer workspace");
    fb.enable_double_buffering_from_vec(vec![0u32; (w * h) as usize]);
    fb.draw_rect(Rect::new(2, 3, 10, 8), Color::with_alpha(255, 0, 0, 255));
    let buf = fb.back_buffer.as_ref().unwrap();
    let px = |x: i32, y: i32| buf[y as usize * w as usize + x as usize] != 0;
    // top/bottom edges
    for x in 2..12 {
        if !px(x, 3) || !px(x, 10) {
            return false;
        }
    }
    // left/right edges
    for y in 3..=10 {
        if !px(2, y) || !px(11, y) {
            return false;
        }
    }
    // interior empty
    for y in 4..10 {
        for x in 3..11 {
            if px(x, y) {
                return false;
            }
        }
    }
    true
}

/// draw_line steep: matches naive Bresenham
pub fn wave9_draw_line_steep_smoke() -> bool {
    let (w, h) = (20u32, 20u32);
    let info = FramebufferInfo {
        address: 0,
        width: w,
        height: h,
        stride: w * 4,
        format: PixelFormat::Bgra8888,
        bpp: 32,
    };
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
    fb_opt.enable_double_buffering_from_vec(vec![0u32; (w * h) as usize]);
    fb_naive.enable_double_buffering_from_vec(vec![0u32; (w * h) as usize]);

    let color = Color::with_alpha(0, 255, 0, 255);
    let cases: [(i32, i32, i32, i32); 4] = [
        (5, 0, 7, 19),
        (10, 19, 8, 0),
        (3, 2, 5, 18),
        (15, 15, 12, 0),
    ];
    for (x1, y1, x2, y2) in cases {
        fb_opt.draw_line(x1, y1, x2, y2, color);
        // naive Bresenham
        let (mut x, mut y) = (x1, y1);
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
        if fb_opt.back_buffer.as_ref().unwrap() != fb_naive.back_buffer.as_ref().unwrap() {
            return false;
        }
        for b in fb_opt.back_buffer.as_mut().unwrap().iter_mut() {
            *b = 0;
        }
        for b in fb_naive.back_buffer.as_mut().unwrap().iter_mut() {
            *b = 0;
        }
    }
    true
}

/// draw_text 24bpp single-pass MMIO fg/bg
pub fn wave9_draw_text_24bit_single_pass_smoke() -> bool {
    let (w, h) = (8u32, 16u32);
    let stride = w * 3;
    let info = FramebufferInfo {
        address: 0,
        width: w,
        height: h,
        stride,
        format: PixelFormat::Bgr888,
        bpp: 24,
    };
    let vram = vec![0u8; info.size()];
    let info2 = info.clone();

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info2.width, info2.height, info2.stride, info2.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vram),
    )
    .expect("framebuffer workspace");
    fb.draw_text(
        0,
        0,
        "!",
        Color::with_alpha(255, 0, 0, 255),
        Color::with_alpha(0, 0, 255, 255),
    );
    // Row 2, '!' glyph = 0x18 -> bits 3,4 ON
    let off = |x: usize| 2 * stride as usize + x * 3;
    // Bgr888: red=[0x00,0x00,0xFF], blue=[0xFF,0x00,0x00]
    memory_bytes(&fb)[off(2)] == 0xFF
        && memory_bytes(&fb)[off(2) + 1] == 0x00
        && memory_bytes(&fb)[off(2) + 2] == 0x00
        && memory_bytes(&fb)[off(3)] == 0x00
        && memory_bytes(&fb)[off(3) + 1] == 0x00
        && memory_bytes(&fb)[off(3) + 2] == 0xFF
        && memory_bytes(&fb)[off(4)] == 0x00
        && memory_bytes(&fb)[off(4) + 1] == 0x00
        && memory_bytes(&fb)[off(4) + 2] == 0xFF
        && memory_bytes(&fb)[off(5)] == 0xFF
        && memory_bytes(&fb)[off(5) + 1] == 0x00
        && memory_bytes(&fb)[off(5) + 2] == 0x00
}

/// draw_char_8x16 24bpp MMIO single-pass
pub fn wave9_draw_char_8x16_24bit_smoke() -> bool {
    let (w, h) = (8u32, 16u32);
    let stride = w * 3;
    let info = FramebufferInfo {
        address: 0,
        width: w,
        height: h,
        stride,
        format: PixelFormat::Bgr888,
        bpp: 24,
    };
    let vram = vec![0u8; info.size()];
    let info2 = info.clone();

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info2.width, info2.height, info2.stride, info2.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vram),
    )
    .expect("framebuffer workspace");
    fb.draw_char_8x16(0, 0, '!', Color::GREEN, Some(Color::BLACK));
    // Row 2 0x18 -> bits 3,4 ON. Bgr888: green=[0x00,0xFF,0x00], black=[0,0,0]
    let off = |x: usize| 2 * stride as usize + x * 3;
    memory_bytes(&fb)[off(2)] == 0
        && memory_bytes(&fb)[off(2) + 1] == 0
        && memory_bytes(&fb)[off(2) + 2] == 0
        && memory_bytes(&fb)[off(3)] == 0x00
        && memory_bytes(&fb)[off(3) + 1] == 0xFF
        && memory_bytes(&fb)[off(3) + 2] == 0x00
        && memory_bytes(&fb)[off(4)] == 0x00
        && memory_bytes(&fb)[off(4) + 1] == 0xFF
        && memory_bytes(&fb)[off(4) + 2] == 0x00
        && memory_bytes(&fb)[off(5)] == 0
        && memory_bytes(&fb)[off(5) + 1] == 0
        && memory_bytes(&fb)[off(5) + 2] == 0
}

/// draw_image RGB565 MMIO path
pub fn wave9_draw_image_rgb565_mmio_smoke() -> bool {
    let (w, h) = (4u32, 2u32);
    let info = FramebufferInfo {
        address: 0,
        width: w,
        height: h,
        stride: w * 2,
        format: PixelFormat::Rgb565,
        bpp: 16,
    };
    let vram = vec![0u8; info.size()];
    let info2 = info.clone();

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info2.width, info2.height, info2.stride, info2.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vram),
    )
    .expect("framebuffer workspace");
    let img = Image::filled(w, h, Color::with_alpha(255, 0, 0, 255));
    fb.draw_image(&img, 0, 0);
    // Red in RGB565 = 0xF800, LE = [0x00, 0xF8]
    for y in 0..h as usize {
        for x in 0..w as usize {
            let o = y * info.stride as usize + x * 2;
            if memory_bytes(&fb)[o] != 0x00 || memory_bytes(&fb)[o + 1] != 0xF8 {
                return false;
            }
        }
    }
    true
}

/// write_opaque_run_32bit SIMD pack check
pub fn wave9_write_opaque_run_32bit_simd_smoke() -> bool {
    let (w, h) = (64u32, 1u32);
    let info = FramebufferInfo {
        address: 0,
        width: w,
        height: h,
        stride: w * 4,
        format: PixelFormat::Bgra8888,
        bpp: 32,
    };
    let vram = vec![0u8; info.size()];
    let info2 = info.clone();

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info2.width, info2.height, info2.stride, info2.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vram),
    )
    .expect("framebuffer workspace");
    let img = Image::filled(w, 1, Color::with_alpha(10, 20, 30, 255));
    fb.draw_image(&img, 0, 0);
    // BGRA in VRAM: B=30, G=20, R=10, A=255
    for x in 0..w as usize {
        let o = x * 4;
        if memory_bytes(&fb)[o] != 30
            || memory_bytes(&fb)[o + 1] != 20
            || memory_bytes(&fb)[o + 2] != 10
            || memory_bytes(&fb)[o + 3] != 255
        {
            return false;
        }
    }
    true
}

/// draw_text RGB565 MMIO single-pass
pub fn wave9_draw_text_rgb565_mmio_smoke() -> bool {
    let (w, h) = (8u32, 16u32);
    let info = FramebufferInfo {
        address: 0,
        width: w,
        height: h,
        stride: w * 2,
        format: PixelFormat::Rgb565,
        bpp: 16,
    };
    let vram = vec![0u8; info.size()];
    let info2 = info.clone();

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info2.width, info2.height, info2.stride, info2.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vram),
    )
    .expect("framebuffer workspace");
    fb.draw_text(0, 0, "!", Color::with_alpha(255, 0, 0, 255), Color::BLACK);
    let off = |x: usize| 2 * info.stride as usize + x * 2;
    // red=0xF800=[0x00,0xF8], black=0x0000=[0x00,0x00]
    memory_bytes(&fb)[off(2)] == 0x00
        && memory_bytes(&fb)[off(2) + 1] == 0x00
        && memory_bytes(&fb)[off(3)] == 0x00
        && memory_bytes(&fb)[off(3) + 1] == 0xF8
        && memory_bytes(&fb)[off(4)] == 0x00
        && memory_bytes(&fb)[off(4) + 1] == 0xF8
        && memory_bytes(&fb)[off(5)] == 0x00
        && memory_bytes(&fb)[off(5) + 1] == 0x00
}

/// draw_char_8x16 RGB565 MMIO single-pass
pub fn wave9_draw_char_8x16_rgb565_smoke() -> bool {
    let (w, h) = (8u32, 16u32);
    let info = FramebufferInfo {
        address: 0,
        width: w,
        height: h,
        stride: w * 2,
        format: PixelFormat::Rgb565,
        bpp: 16,
    };
    let vram = vec![0u8; info.size()];
    let info2 = info.clone();

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info2.width, info2.height, info2.stride, info2.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vram),
    )
    .expect("framebuffer workspace");
    fb.draw_char_8x16(0, 0, '!', Color::RED, Some(Color::BLACK));
    let off = |x: usize| 2 * info.stride as usize + x * 2;
    memory_bytes(&fb)[off(2)] == 0x00
        && memory_bytes(&fb)[off(2) + 1] == 0x00
        && memory_bytes(&fb)[off(3)] == 0x00
        && memory_bytes(&fb)[off(3) + 1] == 0xF8
        && memory_bytes(&fb)[off(4)] == 0x00
        && memory_bytes(&fb)[off(4) + 1] == 0xF8
        && memory_bytes(&fb)[off(5)] == 0x00
        && memory_bytes(&fb)[off(5) + 1] == 0x00
}
