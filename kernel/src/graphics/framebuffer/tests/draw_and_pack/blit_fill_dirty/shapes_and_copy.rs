use super::*;

mod simd_pack_32bit;
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_blit_rect_16bit_rgb565_backbuffer_flush_odd_width() {
    let info = fb_info(3, 1, PixelFormat::Rgb565);
    let (mut fb, mut vram) = make_flush_fb(&info);

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

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_copy_rect_backbuffer_same_row_overlap() {
    let info = fb_info(8, 1, PixelFormat::Bgra8888);
    let mut fb = make_backbuf_fb(&info);

    {
        let back = fb.back_buffer.as_mut().unwrap();
        for x in 0..info.width as usize {
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

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_copy_rect_backbuffer_vertical_copy() {
    let info = fb_info(4, 4, PixelFormat::Bgra8888);
    let mut fb = make_backbuf_fb(&info);

    {
        let back = fb.back_buffer.as_mut().unwrap();
        for y in 0..info.height as usize {
            for x in 0..info.width as usize {
                let idx = y * info.width as usize + x;
                let red = (y * 10 + x) as u8;
                back[idx] = Color::with_alpha(red, 0, 0, 255).to_u32();
            }
        }
    }

    // vertical non-overlap copy: row0 -> row2
    fb.copy_rect(Rect::new(0, 0, info.width, 1), 0, 2);

    let back = fb.back_buffer.as_ref().unwrap();
    for x in 0..info.width as usize {
        let src = Color::from_u32(back[x]);
        let dst = Color::from_u32(back[2 * info.width as usize + x]);
        assert_eq!(dst.red, src.red, "x={}", x);
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_copy_rect_mmio_same_row_overlap() {
    let info = fb_info(8, 1, PixelFormat::Bgra8888);
    let (mut fb, mut vram) = make_mmio_fb(&info);

    for x in 0..info.width as i32 {
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

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_fill_rect_backbuffer_full_width_span() {
    let info = fb_info(6, 4, PixelFormat::Bgra8888);
    let mut fb = make_backbuf_fb(&info);
    let width = info.width;
    let height = info.height;

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

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_draw_text_rgb565_mmio_run_write() {
    let info = fb_info(8, 16, PixelFormat::Rgb565);
    let (mut fb, mut vram) = make_mmio_fb(&info);
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

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_clear_rgb565_mmio() {
    let info = fb_info(6, 3, PixelFormat::Rgb565);
    let (mut fb, mut vram) = make_mmio_fb(&info);

    fb.clear(Color::BLUE);

    // BLUE in RGB565 little-endian: 0x001F -> [0x1F, 0x00]
    for y in 0..info.height as usize {
        for x in 0..info.width as usize {
            let off = y * info.stride as usize + x * 2;
            assert_eq!(vram[off], 0x1F, "x={}, y={}", x, y);
            assert_eq!(vram[off + 1], 0x00, "x={}, y={}", x, y);
        }
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_draw_char_8x16_rgb565_mmio() {
    let info = fb_info(8, 16, PixelFormat::Rgb565);
    let (mut fb, mut vram) = make_mmio_fb(&info);

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
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_draw_circle_symmetric_32bit_backbuffer() {
    let info = fb_info(32, 32, PixelFormat::Bgra8888);
    let mut fb = make_backbuf_fb(&info);

    let color = Color::with_alpha(0, 255, 0, 255);
    fb.draw_circle(16, 16, 8, color);

    // Verify 8-fold symmetry: for each pixel (cx+dx, cy+dy) there must be
    // pixels at all 8 mirrored positions.
    let buf = fb.back_buffer.as_ref().unwrap();
    let px = |x: i32, y: i32| -> bool {
        if x < 0 || y < 0 || x >= info.width as i32 || y >= info.height as i32 {
            return false;
        }
        buf[y as usize * info.width as usize + x as usize] != 0
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
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_fill_circle_no_gaps_32bit_backbuffer() {
    let info = fb_info(32, 32, PixelFormat::Bgra8888);
    let mut fb = make_backbuf_fb(&info);
    let width = info.width;

    let color = Color::with_alpha(0, 0, 255, 255);
    let cx = 16i32;
    let cy = 16i32;
    let r = 7i32;
    fb.fill_circle(cx, cy, r as i32, color);

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
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_draw_rect_outline_32bit_backbuffer() {
    let info = fb_info(20, 20, PixelFormat::Bgra8888);
    let mut fb = make_backbuf_fb(&info);
    let width = info.width;

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
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_draw_line_steep_rgb565_mmio() {
    let info = fb_info(20, 20, PixelFormat::Rgb565);

    let (mut fb_opt, mut vram_opt) = make_mmio_fb(&info);
    let (mut fb_naive, mut vram_naive) = make_mmio_fb(&info);

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

        assert_eq!(
            vram_opt, vram_naive,
            "steep line ({x1},{y1})->({x2},{y2}) mismatch"
        );

        // reset
        vram_opt.fill(0);
        vram_naive.fill(0);
    }
}

/// copy_rect overlapping on MMIO: verify data integrity
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_copy_rect_mmio_overlap_integrity() {
    let info = fb_info(16, 16, PixelFormat::Bgra8888);
    let (mut fb, mut vram) = make_mmio_fb(&info);
    let width = info.width;

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
                "copy_rect mismatch at dest ({},{y})",
                x + 2
            );
        }
    }
}

/// draw_text 24bpp single-pass MMIO: verify fg/bg pattern for '!'
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_draw_text_24bit_mmio_single_pass() {
    let info = fb_info(8, 16, PixelFormat::Bgr888);
    let (mut fb, mut vram) = make_mmio_fb(&info);

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
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_draw_char_8x16_24bit_mmio() {
    let info = fb_info(8, 16, PixelFormat::Bgr888);
    let (mut fb, mut vram) = make_mmio_fb(&info);

    let fg = Color::GREEN;
    let bg = Color::BLACK;
    fb.draw_char_8x16(0, 0, '!', fg, Some(bg));

    // Row 2, 0x18 -> bits 3,4 ON
    let row = 2usize;
    let off = |x: usize| row * info.stride as usize + x * 3;

    // Bgr888: green = [0x00, 0xFF, 0x00], black = [0x00, 0x00, 0x00]
    assert_eq!(&vram[off(2)..off(2) + 3], &[0x00, 0x00, 0x00], "bg");
    assert_eq!(&vram[off(3)..off(3) + 3], &[0x00, 0xFF, 0x00], "fg");
    assert_eq!(&vram[off(4)..off(4) + 3], &[0x00, 0xFF, 0x00], "fg");
    assert_eq!(&vram[off(5)..off(5) + 3], &[0x00, 0x00, 0x00], "bg");
}

/// draw_image 16bpp MMIO: blit_mmio_row RGB565 path
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_draw_image_rgb565_mmio() {
    let info = fb_info(4, 2, PixelFormat::Rgb565);
    let (mut fb, mut vram) = make_mmio_fb(&info);

    let img = Image::filled(info.width, info.height, Color::with_alpha(255, 0, 0, 255));
    fb.draw_image(&img, 0, 0);

    // Red in RGB565 = 0xF800, LE = [0x00, 0xF8]
    for y in 0..info.height as usize {
        for x in 0..info.width as usize {
            let off = y * info.stride as usize + x * 2;
            assert_eq!(&vram[off..off + 2], &[0x00, 0xF8], "pixel ({x},{y})");
        }
    }
}
