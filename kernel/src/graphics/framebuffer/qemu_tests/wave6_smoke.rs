use super::*;

mod wave6_simd_smoke;
pub use wave6_simd_smoke::*;
mod wave6_bench_smoke;
pub use wave6_bench_smoke::*;
pub fn wave6_draw_image_24bit_mmio_smoke() -> bool {
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

    let mem = vec![0u8; info.size()];
    let info2 = info.clone();

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info2.width, info2.height, info2.stride, info2.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(mem),
    )
    .expect("framebuffer workspace");

    let img = Image::filled(width, height, Color::with_alpha(255, 0, 0, 255));
    fb.draw_image(&img, 0, 0);

    for i in (0..memory_bytes(&fb).len()).step_by(3) {
        if memory_bytes(&fb)[i] != 0
            || memory_bytes(&fb)[i + 1] != 0
            || memory_bytes(&fb)[i + 2] != 255
        {
            return false;
        }
    }
    true
}

pub fn wave6_draw_image_32bit_mmio_rgba_smoke() -> bool {
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

    let mem = vec![0u8; info.size()];
    let info2 = info.clone();

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info2.width, info2.height, info2.stride, info2.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(mem),
    )
    .expect("framebuffer workspace");

    let img = Image::filled(width, height, Color::with_alpha(10, 20, 30, 255));
    fb.draw_image(&img, 0, 0);

    for i in (0..memory_bytes(&fb).len()).step_by(4) {
        if memory_bytes(&fb)[i] != 10
            || memory_bytes(&fb)[i + 1] != 20
            || memory_bytes(&fb)[i + 2] != 30
            || memory_bytes(&fb)[i + 3] != 255
        {
            return false;
        }
    }
    true
}

pub fn wave6_write_bytes_mmio_alignment_smoke() -> bool {
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

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("fixture geometry"),
        PixelBuffer::Memory(vec![0; info.size()]),
    )
    .expect("fixture workspace");
    fb.write_bgr_run(0, 3, Color::with_alpha(1, 2, 3, 255));

    memory_bytes(&fb)[..9] == [3, 2, 1, 3, 2, 1, 3, 2, 1]
        && memory_bytes(&fb)[9..].iter().all(|&byte| byte == 0)
}

pub fn wave6_write_opaque_run_24bit_even_odd_mmio_smoke() -> bool {
    let width = 5u32;
    let height = 1u32;
    let mut img = Image::new(width, height);
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

    let mem = vec![0u8; info.size()];
    let info2 = info.clone();

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info2.width, info2.height, info2.stride, info2.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(mem),
    )
    .expect("framebuffer workspace");
    fb.draw_image(&img, 0, 0);

    for x in 0..(width as usize) {
        let off = x * 3;
        let c = cols[x];
        if memory_bytes(&fb)[off] != c.blue
            || memory_bytes(&fb)[off + 1] != c.green
            || memory_bytes(&fb)[off + 2] != c.red
        {
            return false;
        }
    }

    let mut fb2 = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vec![0u8; info.size()]),
    )
    .expect("framebuffer workspace");
    fb2.enable_double_buffering_from_vec(vec![0u32; (width * height) as usize]);
    fb2.draw_image(&img, 0, 0);
    let back_ref = match fb2.back_buffer.as_ref() {
        Some(v) => v,
        None => return false,
    };
    for x in 0..(width as usize) {
        let pixel_c = Color::from_u32(back_ref[x]);
        let c = cols[x];
        if pixel_c.blue != c.blue || pixel_c.green != c.green || pixel_c.red != c.red {
            return false;
        }
    }
    true
}

pub fn wave6_pack_rgba_to_bgra_basic_smoke() -> bool {
    let mut src = Vec::new();
    for i in 0..32 {
        src.push(i as u8);
        src.push((i + 1) as u8);
        src.push((i + 2) as u8);
        src.push(255u8);
    }

    let mut dst = vec![0u8; src.len()];
    crate::graphics::packer::pack_rgba_to_bgra(&src, &mut dst);
    for i in 0..(src.len() / 4) {
        let s = i * 4;
        if dst[s] != src[s + 2]
            || dst[s + 1] != src[s + 1]
            || dst[s + 2] != src[s]
            || dst[s + 3] != src[s + 3]
        {
            return false;
        }
    }
    true
}

pub fn wave6_pack_rgba_to_bgra_scalar_random_smoke() -> bool {
    let mut src = vec![0u8; 256];
    for seed in 0..16u8 {
        for i in 0..src.len() {
            src[i] = (i.wrapping_mul(seed as usize) as u8).wrapping_add(i as u8);
        }
        let mut dst1 = vec![0u8; src.len()];
        let mut dst2 = vec![0u8; src.len()];
        for p in 0..(src.len() / 4) {
            let s = p * 4;
            dst1[s] = src[s + 2];
            dst1[s + 1] = src[s + 1];
            dst1[s + 2] = src[s];
            dst1[s + 3] = src[s + 3];
        }
        crate::graphics::packer::pack_rgba_to_bgra_scalar(&src, &mut dst2);
        if dst1 != dst2 {
            return false;
        }
    }
    true
}

pub fn wave6_draw_image_bgra_stream_matches_backbuffer_smoke() -> bool {
    let width = 16u32;
    let height = 4u32;
    let mut img = Image::new(width, height);
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

    let mut mem_back = vec![0u8; info.size()];

    let mut fb_back = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(mem_back),
    )
    .expect("framebuffer workspace");
    fb_back.enable_double_buffering();
    fb_back.draw_image(&img, 0, 0);
    fb_back.swap_buffers();

    let mut mem_mmio = vec![0u8; info.size()];

    let mut fb_mmio = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(mem_mmio),
    )
    .expect("framebuffer workspace");
    fb_mmio.draw_image(&img, 0, 0);

    memory_bytes(&fb_back) == memory_bytes(&fb_mmio)
}

pub fn wave6_fill_rect_32bit_mmio_smoke() -> bool {
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

    let mem = vec![0u8; info.size()];
    let info2 = info.clone();

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info2.width, info2.height, info2.stride, info2.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(mem),
    )
    .expect("framebuffer workspace");
    fb.fill_rect(Rect::new(1, 1, 6, 6), Color::with_alpha(1, 2, 3, 255));

    for y in 1..7 {
        for x in 1..7 {
            let off = (y as usize * info.stride as usize) + (x as usize * 4);
            if memory_bytes(&fb)[off] != 3
                || memory_bytes(&fb)[off + 1] != 2
                || memory_bytes(&fb)[off + 2] != 1
                || memory_bytes(&fb)[off + 3] != 255
            {
                return false;
            }
        }
    }
    true
}

pub fn wave6_dirty_rect_tracking_smoke() -> bool {
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

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vec![0u8; info.size()]),
    )
    .expect("framebuffer workspace");
    if fb.dirty_rect().is_some() {
        return false;
    }

    fb.set_pixel(10, 10, Color::RED);
    if fb.dirty_rect() != Some(Rect::new(10, 10, 1, 1)) {
        return false;
    }

    fb.set_pixel(20, 20, Color::BLUE);
    if fb.dirty_rect() != Some(Rect::new(10, 10, 11, 11)) {
        return false;
    }

    fb.flush_dirty_area();
    fb.dirty_rect().is_none()
}

pub fn wave6_dirty_rect_flush_only_marked_area_smoke() -> bool {
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

    let vram = vec![0u8; info.size()];
    let info2 = info.clone();

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info2.width, info2.height, info2.stride, info2.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vram),
    )
    .expect("framebuffer workspace");
    let mut back = vec![0u32; (info.width * info.height) as usize];
    let white = Color::with_alpha(255, 255, 255, 255).to_u32();
    for slot in &mut back {
        *slot = white;
    }
    fb.enable_double_buffering_from_vec(back)
        .expect("valid back plane");

    let idx = 5 * info.width as usize + 5;
    let Some(back) = fb.back_buffer.as_mut() else {
        return false;
    };
    back[idx] = u32::from_le_bytes([0xAA, 0xBB, 0xFF, 0xFF]);

    fb.mark_dirty(Rect::new(5, 5, 1, 1));
    fb.flush_dirty_area();

    let offset = (5 * 10 + 5) * 4;
    memory_bytes(&fb)[offset] == 0xAA
        && memory_bytes(&fb)[offset + 1] == 0xBB
        && memory_bytes(&fb)[0] == 0
}

pub fn wave6_draw_text_partial_left_clip_32bit_backbuffer_smoke() -> bool {
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

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vec![0u8; info.size()]),
    )
    .expect("framebuffer workspace");
    fb.enable_double_buffering_from_vec(vec![0u32; (info.width * info.height) as usize]);

    let fg = Color::with_alpha(10, 20, 30, 255);
    let bg = Color::with_alpha(100, 110, 120, 255);
    fb.draw_text(-3, 0, "!", fg, bg);

    let row = 2usize;
    let idx0 = row * info.width as usize;
    let idx1 = row * info.width as usize + 1;
    let idx2 = row * info.width as usize + 2;
    let back_ref = match fb.back_buffer.as_ref() {
        Some(v) => v,
        None => return false,
    };

    let c0 = Color::from_u32(back_ref[idx0]);
    let c1 = Color::from_u32(back_ref[idx1]);
    let c2 = Color::from_u32(back_ref[idx2]);
    eq_color(c0, fg.red, fg.green, fg.blue, fg.alpha)
        && eq_color(c1, fg.red, fg.green, fg.blue, fg.alpha)
        && eq_color(c2, bg.red, bg.green, bg.blue, bg.alpha)
}

pub fn wave6_write_bgr_run_large_mmio_smoke() -> bool {
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

    if memory_bytes(&fb)[0] != 3 || memory_bytes(&fb)[1] != 2 || memory_bytes(&fb)[2] != 1 {
        return false;
    }
    let last_off = (width as usize - 1) * 3;
    memory_bytes(&fb)[last_off] == 3
        && memory_bytes(&fb)[last_off + 1] == 2
        && memory_bytes(&fb)[last_off + 2] == 1
}

pub fn wave6_write_bgr_run_large_smoke() -> bool {
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

    let mem = vec![0u8; info.size()];
    let info2 = info.clone();

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info2.width, info2.height, info2.stride, info2.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(mem),
    )
    .expect("framebuffer workspace");

    fb.write_bgr_run(0, width as usize, Color::with_alpha(5, 6, 7, 255));

    for x in 0..(width as usize) {
        let off = x * 3;
        if memory_bytes(&fb)[off] != 7
            || memory_bytes(&fb)[off + 1] != 6
            || memory_bytes(&fb)[off + 2] != 5
        {
            return false;
        }
    }
    true
}

pub fn wave6_draw_image_24bit_rgb888_backbuffer_smoke() -> bool {
    let width = 8u32;
    let height = 2u32;
    let mut img = Image::new(width, height);

    img.set_pixel(0, 0, Color::RED);
    img.set_pixel(1, 0, Color::GREEN);
    img.set_pixel(2, 0, Color::BLUE);

    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 3,
        format: PixelFormat::Rgb888,
        bpp: 24,
    };

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vec![0u8; info.size()]),
    )
    .expect("framebuffer workspace");
    fb.enable_double_buffering_from_vec(vec![0u32; (info.width * info.height) as usize]);
    fb.draw_image(&img, 0, 0);

    let back_ref = match fb.back_buffer.as_ref() {
        Some(v) => v,
        None => return false,
    };

    let p0 = Color::from_u32(back_ref[0]);
    let p1 = Color::from_u32(back_ref[1]);
    let p2 = Color::from_u32(back_ref[2]);
    p0.red == 255
        && p0.green == 0
        && p0.blue == 0
        && p1.red == 0
        && p1.green == 255
        && p1.blue == 0
        && p2.red == 0
        && p2.green == 0
        && p2.blue == 255
}

pub fn wave6_draw_hline_24bit_rgb888_mmio_smoke() -> bool {
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

    let vram = vec![0u8; info.size()];
    let info2 = info;

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info2.width, info2.height, info2.stride, info2.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vram),
    )
    .expect("framebuffer workspace");

    fb.draw_hline(0, 4, 0, Color::BLUE);

    for i in 0..5usize {
        let off = i * 3;
        if memory_bytes(&fb)[off] != 0
            || memory_bytes(&fb)[off + 1] != 0
            || memory_bytes(&fb)[off + 2] != 255
        {
            return false;
        }
    }
    true
}
