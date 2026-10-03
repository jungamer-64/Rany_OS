use super::*;

mod blit_fill_dirty;
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_draw_line_matches_naive_32bit_backbuffer() {
    let info = fb_info(16, 16, PixelFormat::Bgra8888);
    let mut fb_opt = make_backbuf_fb(&info);
    let mut fb_naive = make_backbuf_fb(&info);
    let color = Color::with_alpha(10, 20, 30, 255);

    let cases = [
        (0, 0, 15, 3),
        (0, 0, 3, 15),
        (15, 0, 0, 15),
        (2, 14, 13, 4),
        (7, 0, 7, 15),
        (0, 8, 15, 8),
    ];

    for &(x1, y1, x2, y2) in &cases {
        fb_opt.draw_line(x1, y1, x2, y2, color);
        draw_line_naive(&mut fb_naive, x1, y1, x2, y2, color);

        let buf_opt = fb_opt.back_buffer.as_ref().unwrap();
        let buf_naive = fb_naive.back_buffer.as_ref().unwrap();
        assert_eq!(buf_opt, buf_naive);

        for b in fb_opt.back_buffer.as_mut().unwrap().iter_mut() {
            *b = 0;
        }
        for b in fb_naive.back_buffer.as_mut().unwrap().iter_mut() {
            *b = 0;
        }
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_draw_line_matches_naive_24bit_backbuffer() {
    let info = fb_info(16, 16, PixelFormat::Bgr888);
    let mut fb_opt = make_backbuf_fb(&info);
    let mut fb_naive = make_backbuf_fb(&info);
    let color = Color::with_alpha(11, 22, 33, 255);

    let cases = [(0, 0, 15, 3), (0, 0, 3, 15), (15, 0, 0, 15), (2, 14, 13, 4)];

    for &(x1, y1, x2, y2) in &cases {
        fb_opt.draw_line(x1, y1, x2, y2, color);
        draw_line_naive(&mut fb_naive, x1, y1, x2, y2, color);

        let buf_opt = fb_opt.back_buffer.as_ref().unwrap();
        let buf_naive = fb_naive.back_buffer.as_ref().unwrap();
        assert_eq!(buf_opt, buf_naive);

        for b in fb_opt.back_buffer.as_mut().unwrap().iter_mut() {
            *b = 0;
        }
        for b in fb_naive.back_buffer.as_mut().unwrap().iter_mut() {
            *b = 0;
        }
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_draw_text_space_24bit_backbuffer() {
    let info = fb_info(16, 16, PixelFormat::Bgr888);
    let mut fb = make_backbuf_fb(&info);

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

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_draw_image_32bit_mmio() {
    let info = fb_info(4, 4, PixelFormat::Bgra8888);
    let mut fb = make_memory_fb(&info);

    let img = Image::filled(info.width, info.height, Color::with_alpha(10, 20, 30, 255));
    fb.draw_image(&img, 0, 0);

    for i in (0..memory_bytes(&fb).len()).step_by(4) {
        assert_eq!(memory_bytes(&fb)[i], 30);
        assert_eq!(memory_bytes(&fb)[i + 1], 20);
        assert_eq!(memory_bytes(&fb)[i + 2], 10);
        assert_eq!(memory_bytes(&fb)[i + 3], 255);
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_draw_image_24bit_mmio() {
    let info = fb_info(3, 2, PixelFormat::Bgr888);
    let mut fb = make_memory_fb(&info);

    let img = Image::filled(info.width, info.height, Color::with_alpha(255, 0, 0, 255));
    fb.draw_image(&img, 0, 0);

    for i in (0..memory_bytes(&fb).len()).step_by(3) {
        assert_eq!(memory_bytes(&fb)[i], 0);
        assert_eq!(memory_bytes(&fb)[i + 1], 0);
        assert_eq!(memory_bytes(&fb)[i + 2], 255);
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_draw_image_32bit_mmio_rgba() {
    let info = fb_info(4, 4, PixelFormat::Rgba8888);
    let mut fb = make_memory_fb(&info);

    let img = Image::filled(info.width, info.height, Color::with_alpha(10, 20, 30, 255));
    fb.draw_image(&img, 0, 0);

    for i in (0..memory_bytes(&fb).len()).step_by(4) {
        assert_eq!(memory_bytes(&fb)[i], 10);
        assert_eq!(memory_bytes(&fb)[i + 1], 20);
        assert_eq!(memory_bytes(&fb)[i + 2], 30);
        assert_eq!(memory_bytes(&fb)[i + 3], 255);
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_write_bytes_mmio_alignment() {
    let info = fb_info(8, 1, PixelFormat::Bgr888);

    let mut fb = make_memory_fb(&info);
    fb.write_bgr_run(0, 3, Color::with_alpha(1, 2, 3, 255));

    // Verify bytes
    assert_eq!(&memory_bytes(&fb)[..9], &[3, 2, 1, 3, 2, 1, 3, 2, 1]);
    assert!(memory_bytes(&fb)[9..].iter().all(|&byte| byte == 0));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_write_bgr_run_large() {
    // Ensure large runs of a single color are written correctly
    let info = fb_info(1024, 1, PixelFormat::Bgr888);
    let mut fb = make_memory_fb(&info);

    fb.write_bgr_run(0, info.width as usize, Color::with_alpha(5, 6, 7, 255));

    for x in 0..(info.width as usize) {
        let off = x * 3;
        assert_eq!(memory_bytes(&fb)[off], 7); // b
        assert_eq!(memory_bytes(&fb)[off + 1], 6); // g
        assert_eq!(memory_bytes(&fb)[off + 2], 5); // r
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_write_opaque_run_24bit_even_odd_mmio() {
    use crate::graphics::image::Image;

    let info = fb_info(5, 1, PixelFormat::Bgr888);
    let mut img = Image::new(info.width, info.height);

    let cols = [
        Color::with_alpha(1, 2, 3, 255),
        Color::with_alpha(4, 5, 6, 255),
        Color::with_alpha(7, 8, 9, 255),
        Color::with_alpha(10, 11, 12, 255),
        Color::with_alpha(13, 14, 15, 255),
    ];

    for x in 0..info.width {
        img.set_pixel(x, 0, cols[x as usize]);
    }

    // MMIO path
    let mut fb = make_memory_fb(&info);
    fb.draw_image(&img, 0, 0);

    for x in 0..(info.width as usize) {
        let off = x * 3;
        let c = cols[x];
        assert_eq!(memory_bytes(&fb)[off], c.blue);
        assert_eq!(memory_bytes(&fb)[off + 1], c.green);
        assert_eq!(memory_bytes(&fb)[off + 2], c.red);
    }

    // Backbuffer path
    let mut fb2 = make_backbuf_fb(&info);
    fb2.draw_image(&img, 0, 0);
    let back_ref = fb2.back_buffer.as_ref().unwrap();
    for x in 0..(info.width as usize) {
        let pixel_c = Color::from_u32(back_ref[x]);
        let c = cols[x];
        assert_eq!(pixel_c.blue, c.blue);
        assert_eq!(pixel_c.green, c.green);
        assert_eq!(pixel_c.red, c.red);
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
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
    crate::graphics::packer::pack_rgba_to_bgra(&src, &mut dst);

    for i in 0..(src.len() / 4) {
        let s = i * 4;
        assert_eq!(dst[s], src[s + 2]);
        assert_eq!(dst[s + 1], src[s + 1]);
        assert_eq!(dst[s + 2], src[s + 0]);
        assert_eq!(dst[s + 3], src[s + 3]);
    }
}
