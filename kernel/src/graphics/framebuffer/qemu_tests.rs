use super::*;
use crate::graphics::image::Image;
use alloc::vec;
use alloc::vec::Vec;

#[inline]
fn eq_color(c: Color, red: u8, green: u8, blue: u8, alpha: u8) -> bool {
    c.red == red && c.green == green && c.blue == blue && c.alpha == alpha
}

#[inline]
fn eq_color_rgb(c: Color, red: u8, green: u8, blue: u8) -> bool {
    c.red == red && c.green == green && c.blue == blue
}

pub fn wave6_draw_image_32bit_bgra_backbuffer_smoke() -> bool {
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
    fb.enable_double_buffering_from_vec(vec![0u32; (info.width * info.height) as usize]);

    let img = Image::filled(width, height, Color::with_alpha(10, 20, 30, 255));
    fb.draw_image(&img, 0, 0);

    let back_ref = match fb.back_buffer.as_ref() {
        Some(back_ref) => back_ref,
        None => return false,
    };
    for &pixel in back_ref {
        let c = Color::from_u32(pixel);
        if !eq_color(c, 10, 20, 30, 255) {
            return false;
        }
    }
    true
}

pub fn wave6_draw_image_24bit_bgr_backbuffer_smoke() -> bool {
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
    fb.enable_double_buffering_from_vec(vec![0u32; (info.width * info.height) as usize]);

    let img = Image::filled(width, height, Color::with_alpha(255, 0, 0, 255));
    fb.draw_image(&img, 0, 0);

    let back_ref = match fb.back_buffer.as_ref() {
        Some(back_ref) => back_ref,
        None => return false,
    };
    for &pixel in back_ref {
        let c = Color::from_u32(pixel);
        if !eq_color_rgb(c, 255, 0, 0) {
            return false;
        }
    }
    true
}

pub fn wave6_write_bgr_run_small_mmio_smoke() -> bool {
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

    let mut fb = unsafe { Framebuffer::new(info) };
    fb.draw_hline(2, 5, 0, Color::with_alpha(10, 20, 30, 255));

    for px in 2..=5 {
        let off = px as usize * 3;
        if vram[off] != 30 || vram[off + 1] != 20 || vram[off + 2] != 10 {
            return false;
        }
    }
    true
}

pub fn wave6_write_bgr_run_large_mmio_full_smoke() -> bool {
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

    let mut fb = unsafe { Framebuffer::new(info) };
    fb.draw_hline(0, width as i32 - 1, 0, Color::with_alpha(1, 2, 3, 255));

    for px in 0..width {
        let off = px * 3;
        if vram[off] != 3 || vram[off + 1] != 2 || vram[off + 2] != 1 {
            return false;
        }
    }
    true
}

pub fn wave6_write_bgr_run_large_mmio_full_unaligned_smoke() -> bool {
    let width = 200usize;
    let mut vram = vec![0u8; width * 3 + 8];
    let base = 1usize;
    let info = FramebufferInfo {
        address: (vram.as_mut_ptr() as usize + base) as u64,
        width: width as u32,
        height: 1,
        stride: (width * 3) as u32,
        format: PixelFormat::Bgr888,
        bpp: 24,
    };

    let mut fb = unsafe { Framebuffer::new(info) };
    fb.write_bgr_run(0, width, Color::with_alpha(1, 2, 3, 255));

    for px in 0..width {
        let off = base + px * 3;
        if vram[off] != 3 || vram[off + 1] != 2 || vram[off + 2] != 1 {
            return false;
        }
    }
    true
}

pub fn wave6_write_bgr_run_small_mmio_pairs_aligned_smoke() -> bool {
    let mut vram = vec![0u8; 32];
    let info = FramebufferInfo {
        address: vram.as_mut_ptr() as u64,
        width: 10,
        height: 1,
        stride: 10 * 3,
        format: PixelFormat::Bgr888,
        bpp: 24,
    };

    let mut fb = unsafe { Framebuffer::new(info) };
    fb.write_bgr_run(4, 3, Color::with_alpha(11, 22, 33, 255));

    for i in 0..3 {
        let off = 4 + i * 3;
        if vram[off] != 33 || vram[off + 1] != 22 || vram[off + 2] != 11 {
            return false;
        }
    }
    true
}

pub fn wave6_write_bgr_run_small_mmio_generic_unaligned_smoke() -> bool {
    let mut vram = vec![0u8; 32];
    let info = FramebufferInfo {
        address: vram.as_mut_ptr() as u64,
        width: 10,
        height: 1,
        stride: 10 * 3,
        format: PixelFormat::Bgr888,
        bpp: 24,
    };

    let mut fb = unsafe { Framebuffer::new(info) };
    fb.write_bgr_run(1, 2, Color::with_alpha(2, 3, 4, 255));

    for i in 0..2 {
        let off = 1 + i * 3;
        if vram[off] != 4 || vram[off + 1] != 3 || vram[off + 2] != 2 {
            return false;
        }
    }
    true
}

pub fn wave6_draw_hline_32bit_backbuffer_smoke() -> bool {
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

    let mut fb_opt = unsafe { Framebuffer::new(info.clone()) };
    let mut fb_naive = unsafe { Framebuffer::new(info.clone()) };
    let back = vec![0u32; (info.width * info.height) as usize];
    fb_opt.enable_double_buffering_from_vec(back.clone());
    fb_naive.enable_double_buffering_from_vec(back);

    let color = Color::with_alpha(10, 20, 30, 255);
    let test_lines = [(0, 0, 15, 15), (0, 0, 15, 0), (0, 0, 0, 15), (5, 1, 10, 12), (2, 14, 13, 3)];
    for &(x1, y1, x2, y2) in &test_lines {
        fb_opt.draw_line(x1, y1, x2, y2, color);
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

        let buf_opt = match fb_opt.back_buffer.as_ref() {
            Some(v) => v,
            None => return false,
        };
        let buf_naive = match fb_naive.back_buffer.as_ref() {
            Some(v) => v,
            None => return false,
        };
        if buf_opt != buf_naive {
            return false;
        }

        if let Some(buf) = fb_opt.back_buffer.as_mut() {
            for b in buf.iter_mut() {
                *b = 0;
            }
        } else {
            return false;
        }
        if let Some(buf) = fb_naive.back_buffer.as_mut() {
            for b in buf.iter_mut() {
                *b = 0;
            }
        } else {
            return false;
        }
    }

    let color = Color::with_alpha(1, 2, 3, 255);
    fb_opt.draw_vline(1, 0, 5, color);
    let back_ref = match fb_opt.back_buffer.as_ref() {
        Some(v) => v,
        None => return false,
    };
    for y in 0..6 {
        let idx = (y as usize * info.width as usize) + 1usize;
        let c = Color::from_u32(back_ref[idx]);
        if !eq_color(c, 1, 2, 3, 255) {
            return false;
        }
    }
    true
}

pub fn wave6_draw_text_space_32bit_backbuffer_smoke() -> bool {
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
    fb.enable_double_buffering_from_vec(vec![0u32; (info.width * info.height) as usize]);

    let fg = Color::with_alpha(1, 2, 3, 255);
    let bg = Color::with_alpha(100, 110, 120, 255);
    fb.draw_text(0, 0, " ", fg, bg);

    let back_ref = match fb.back_buffer.as_ref() {
        Some(v) => v,
        None => return false,
    };
    for y in 0..16 {
        for x in 0..8 {
            let idx = (y as usize * info.width as usize) + x as usize;
            let c = Color::from_u32(back_ref[idx]);
            if !eq_color(c, 100, 110, 120, 255) {
                return false;
            }
        }
    }
    true
}

pub fn wave6_draw_line_matches_naive_32bit_backbuffer_smoke() -> bool {
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
    let cases = [
        (0, 0, 15, 3),
        (0, 0, 3, 15),
        (15, 0, 0, 15),
        (2, 14, 13, 4),
        (7, 0, 7, 15),
        (0, 8, 15, 8),
    ];

    for (x1, y1, x2, y2) in cases {
        fb_opt.draw_line(x1, y1, x2, y2, color);
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

        let buf_opt = match fb_opt.back_buffer.as_ref() {
            Some(v) => v,
            None => return false,
        };
        let buf_naive = match fb_naive.back_buffer.as_ref() {
            Some(v) => v,
            None => return false,
        };
        if buf_opt.len() != buf_naive.len() || buf_opt != buf_naive {
            return false;
        }

        if let Some(buf) = fb_opt.back_buffer.as_mut() {
            for b in buf.iter_mut() {
                *b = 0;
            }
        } else {
            return false;
        }
        if let Some(buf) = fb_naive.back_buffer.as_mut() {
            for b in buf.iter_mut() {
                *b = 0;
            }
        } else {
            return false;
        }
    }
    true
}

pub fn wave6_draw_line_matches_naive_24bit_backbuffer_smoke() -> bool {
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

    for (x1, y1, x2, y2) in cases {
        fb_opt.draw_line(x1, y1, x2, y2, color);

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

        let buf_opt = match fb_opt.back_buffer.as_ref() {
            Some(v) => v,
            None => return false,
        };
        let buf_naive = match fb_naive.back_buffer.as_ref() {
            Some(v) => v,
            None => return false,
        };
        if buf_opt.len() != buf_naive.len() || buf_opt != buf_naive {
            return false;
        }

        if let Some(buf) = fb_opt.back_buffer.as_mut() {
            for b in buf.iter_mut() {
                *b = 0;
            }
        } else {
            return false;
        }
        if let Some(buf) = fb_naive.back_buffer.as_mut() {
            for b in buf.iter_mut() {
                *b = 0;
            }
        } else {
            return false;
        }
    }
    true
}

pub fn wave6_draw_text_space_24bit_backbuffer_smoke() -> bool {
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
    fb.enable_double_buffering_from_vec(vec![0u32; (info.width * info.height) as usize]);

    let fg = Color::with_alpha(1, 2, 3, 255);
    let bg = Color::with_alpha(100, 110, 120, 255);
    fb.draw_text(0, 0, " ", fg, bg);

    let back_ref = match fb.back_buffer.as_ref() {
        Some(v) => v,
        None => return false,
    };
    for y in 0..16 {
        for x in 0..8 {
            let idx = (y as usize * info.width as usize) + x as usize;
            let c = Color::from_u32(back_ref[idx]);
            if !eq_color_rgb(c, 100, 110, 120) {
                return false;
            }
        }
    }
    true
}

pub fn wave6_draw_image_32bit_mmio_smoke() -> bool {
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
    let mut info2 = info.clone();
    info2.address = mem.as_mut_ptr() as u64;
    let mut fb = unsafe { Framebuffer::new(info2) };

    let img = Image::filled(width, height, Color::with_alpha(10, 20, 30, 255));
    fb.draw_image(&img, 0, 0);

    for i in (0..mem.len()).step_by(4) {
        if mem[i] != 30 || mem[i + 1] != 20 || mem[i + 2] != 10 || mem[i + 3] != 255 {
            return false;
        }
    }
    true
}

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

    let mut mem = vec![0u8; info.size()];
    let mut info2 = info.clone();
    info2.address = mem.as_mut_ptr() as u64;
    let mut fb = unsafe { Framebuffer::new(info2) };

    let img = Image::filled(width, height, Color::with_alpha(255, 0, 0, 255));
    fb.draw_image(&img, 0, 0);

    for i in (0..mem.len()).step_by(3) {
        if mem[i] != 0 || mem[i + 1] != 0 || mem[i + 2] != 255 {
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

    let mut mem = vec![0u8; info.size()];
    let mut info2 = info.clone();
    info2.address = mem.as_mut_ptr() as u64;
    let mut fb = unsafe { Framebuffer::new(info2) };

    let img = Image::filled(width, height, Color::with_alpha(10, 20, 30, 255));
    fb.draw_image(&img, 0, 0);

    for i in (0..mem.len()).step_by(4) {
        if mem[i] != 10 || mem[i + 1] != 20 || mem[i + 2] != 30 || mem[i + 3] != 255 {
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

    let mut mem = vec![0u8; info.size() + 16];
    let base = mem.as_mut_ptr() as usize;
    let mut offset = None;
    for off in 0..8usize {
        if ((base + off) & 7) == 0 {
            offset = Some(off);
            break;
        }
    }
    let offset = match offset {
        Some(off) => off,
        None => return false,
    };

    let mut info2 = info.clone();
    info2.address = (base + offset) as u64;
    let mut fb = unsafe { Framebuffer::new(info2) };
    fb.write_bgr_run(0, 3, Color::with_alpha(1, 2, 3, 255));

    let start = offset;
    mem[start] == 3
        && mem[start + 1] == 2
        && mem[start + 2] == 1
        && mem[start + 3] == 3
        && mem[start + 4] == 2
        && mem[start + 5] == 1
        && mem[start + 6] == 3
        && mem[start + 7] == 2
        && mem[start + 8] == 1
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

    let mut mem = vec![0u8; info.size()];
    let mut info2 = info.clone();
    info2.address = mem.as_mut_ptr() as u64;
    let mut fb = unsafe { Framebuffer::new(info2) };
    fb.draw_image(&img, 0, 0);

    for x in 0..(width as usize) {
        let off = x * 3;
        let c = cols[x];
        if mem[off] != c.blue || mem[off + 1] != c.green || mem[off + 2] != c.red {
            return false;
        }
    }

    let mut fb2 = unsafe { Framebuffer::new(info) };
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
    Framebuffer::pack_rgba_to_bgra(&src, &mut dst);
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
        Framebuffer::pack_rgba_to_bgra_scalar(&src, &mut dst2);
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
    info.address = mem_back.as_mut_ptr() as u64;
    let mut fb_back = unsafe { Framebuffer::new(info.clone()) };
    fb_back.enable_double_buffering();
    fb_back.draw_image(&img, 0, 0);
    fb_back.swap_buffers();

    let mut mem_mmio = vec![0u8; info.size()];
    info.address = mem_mmio.as_mut_ptr() as u64;
    let mut fb_mmio = unsafe { Framebuffer::new(info) };
    fb_mmio.draw_image(&img, 0, 0);

    mem_back == mem_mmio
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

    let mut mem = vec![0u8; info.size()];
    let mut info2 = info.clone();
    info2.address = mem.as_mut_ptr() as u64;
    let mut fb = unsafe { Framebuffer::new(info2) };
    fb.fill_rect(Rect::new(1, 1, 6, 6), Color::with_alpha(1, 2, 3, 255));

    for y in 1..7 {
        for x in 1..7 {
            let off = (y as usize * info.stride as usize) + (x as usize * 4);
            if mem[off] != 3 || mem[off + 1] != 2 || mem[off + 2] != 1 || mem[off + 3] != 255 {
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

    let mut fb = unsafe { Framebuffer::new(info) };
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

    let mut vram = vec![0u8; info.size()];
    let mut info2 = info.clone();
    info2.address = vram.as_mut_ptr() as u64;

    let mut fb = unsafe { Framebuffer::new(info2) };
    let mut back = vec![0u32; (info.width * info.height) as usize];
    let white = Color::with_alpha(255, 255, 255, 255).to_u32();
    for slot in &mut back {
        *slot = white;
    }
    fb.enable_double_buffering_from_vec(back);

    for b in &mut vram {
        *b = 0;
    }

    let idx = 5 * info.width as usize + 5;
    let dst = match fb.back_buffer.as_mut() {
        Some(back) => unsafe { (back.as_mut_ptr() as *mut u8).add(idx * 4) },
        None => return false,
    };
    unsafe {
        *dst = 0xAA;
        *dst.add(1) = 0xBB;
    }

    fb.mark_dirty(Rect::new(5, 5, 1, 1));
    fb.flush_dirty_area();

    let offset = (5 * 10 + 5) * 4;
    vram[offset] == 0xAA && vram[offset + 1] == 0xBB && vram[0] == 0
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

    let mut fb = unsafe { Framebuffer::new(info.clone()) };
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
    let mut vram = vec![0u8; (stride * height) as usize];
    let info = FramebufferInfo {
        address: vram.as_mut_ptr() as u64,
        width,
        height,
        stride,
        format: PixelFormat::Bgr888,
        bpp: 24,
    };

    let mut fb = unsafe { Framebuffer::new(info) };
    fb.draw_hline(0, width as i32 - 1, 0, Color::with_alpha(1, 2, 3, 255));

    if vram[0] != 3 || vram[1] != 2 || vram[2] != 1 {
        return false;
    }
    let last_off = (width as usize - 1) * 3;
    vram[last_off] == 3 && vram[last_off + 1] == 2 && vram[last_off + 2] == 1
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

    let mut mem = vec![0u8; info.size()];
    let mut info2 = info.clone();
    info2.address = mem.as_mut_ptr() as u64;
    let mut fb = unsafe { Framebuffer::new(info2) };

    fb.write_bgr_run(0, width as usize, Color::with_alpha(5, 6, 7, 255));

    for x in 0..(width as usize) {
        let off = x * 3;
        if mem[off] != 7 || mem[off + 1] != 6 || mem[off + 2] != 5 {
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

    let mut fb = unsafe { Framebuffer::new(info.clone()) };
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

    let mut vram = vec![0u8; info.size()];
    let mut info2 = info;
    info2.address = vram.as_mut_ptr() as u64;
    let mut fb = unsafe { Framebuffer::new(info2) };

    fb.draw_hline(0, 4, 0, Color::BLUE);

    for i in 0..5usize {
        let off = i * 3;
        if vram[off] != 0 || vram[off + 1] != 0 || vram[off + 2] != 255 {
            return false;
        }
    }
    true
}

pub fn wave6_pack_rgba_to_bgra_ssse3_matches_scalar_smoke() -> bool {
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "ssse3"))]
    {
        if hal::mmio::get_simd_level() < hal::mmio::simd_level::SSSE3 {
            return true;
        }
        for &len in &[4usize, 12, 16, 20, 48, 64, 100] {
            let mut src = vec![0u8; len * 4];
            for (i, slot) in src.iter_mut().enumerate() {
                *slot = (i * 37 % 251) as u8;
            }
            let mut dst_simd = vec![0u8; src.len()];
            let mut dst_scalar = vec![0u8; src.len()];
            unsafe {
                Framebuffer::pack_rgba_to_bgra_ssse3(
                    src.as_ptr(),
                    dst_simd.as_mut_ptr(),
                    src.len(),
                );
            }
            Framebuffer::pack_rgba_to_bgra_scalar(&src, &mut dst_scalar);
            if dst_simd != dst_scalar {
                return false;
            }
        }
        return true;
    }
    #[cfg(not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "ssse3")))]
    {
        true
    }
}

pub fn wave6_pack_rgba_to_bgra_avx2_matches_scalar_smoke() -> bool {
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "avx2"))]
    {
        if hal::mmio::get_simd_level() < hal::mmio::simd_level::AVX2 {
            return true;
        }
        for &len in &[4usize, 12, 16, 20, 48, 64, 100] {
            let mut src = vec![0u8; len * 4];
            for (i, slot) in src.iter_mut().enumerate() {
                *slot = (i * 97 % 251) as u8;
            }
            let mut dst_simd = vec![0u8; src.len()];
            let mut dst_scalar = vec![0u8; src.len()];
            unsafe {
                Framebuffer::pack_rgba_to_bgra_avx2(
                    src.as_ptr(),
                    dst_simd.as_mut_ptr(),
                    src.len(),
                );
            }
            Framebuffer::pack_rgba_to_bgra_scalar(&src, &mut dst_scalar);
            if dst_simd != dst_scalar {
                return false;
            }
        }
        return true;
    }
    #[cfg(not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "avx2")))]
    {
        true
    }
}

pub fn wave6_pack_rgba_to_bgr24_avx2_matches_scalar_smoke() -> bool {
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "avx2"))]
    {
        if hal::mmio::get_simd_level() < hal::mmio::simd_level::AVX2 {
            return true;
        }
        let len = 8usize;
        let mut src = vec![0u8; len * 4];
        for (i, slot) in src.iter_mut().enumerate() {
            *slot = (i * 97 % 251) as u8;
        }
        let mut dst_simd = vec![0u8; len * 3];
        unsafe {
            Framebuffer::pack_rgba_to_bgr24_avx2_8pixels(src.as_ptr(), dst_simd.as_mut_ptr(), true);
        }
        let mut dst_scalar = vec![0u8; len * 3];
        for p in 0..len {
            let s = p * 4;
            dst_scalar[p * 3] = src[s + 2];
            dst_scalar[p * 3 + 1] = src[s + 1];
            dst_scalar[p * 3 + 2] = src[s];
        }
        return dst_simd == dst_scalar;
    }
    #[cfg(not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "avx2")))]
    {
        true
    }
}

pub fn wave6_pack_rgba_to_bgr24_ssse3_matches_scalar_smoke() -> bool {
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "ssse3"))]
    {
        if hal::mmio::get_simd_level() < hal::mmio::simd_level::SSSE3 {
            return true;
        }
        let len = 8usize;
        let mut src = vec![0u8; len * 4];
        for (i, slot) in src.iter_mut().enumerate() {
            *slot = (i * 61 % 251) as u8;
        }
        let mut dst_simd = vec![0u8; len * 3];
        unsafe {
            Framebuffer::pack_rgba_to_bgr24_ssse3_8pixels(
                src.as_ptr(),
                dst_simd.as_mut_ptr(),
                true,
            );
        }
        let mut dst_scalar = vec![0u8; len * 3];
        for p in 0..len {
            let s = p * 4;
            dst_scalar[p * 3] = src[s + 2];
            dst_scalar[p * 3 + 1] = src[s + 1];
            dst_scalar[p * 3 + 2] = src[s];
        }
        return dst_simd == dst_scalar;
    }
    #[cfg(not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "ssse3")))]
    {
        true
    }
}

pub fn wave6_pack_rgba_to_bgra_neon_matches_scalar_smoke() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        for &len in &[4usize, 12, 16, 20, 48, 64, 100] {
            let mut src = vec![0u8; len * 4];
            for (i, slot) in src.iter_mut().enumerate() {
                *slot = (i * 61 % 251) as u8;
            }
            let mut dst_neon = vec![0u8; src.len()];
            let mut dst_scalar = vec![0u8; src.len()];
            unsafe {
                Framebuffer::pack_rgba_to_bgra_neon(src.as_ptr(), dst_neon.as_mut_ptr(), src.len());
            }
            Framebuffer::pack_rgba_to_bgra_scalar(&src, &mut dst_scalar);
            if dst_neon != dst_scalar {
                return false;
            }
        }
        return true;
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        true
    }
}

pub fn wave6_pack_rgba_to_bgr24_neon_matches_scalar_smoke() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        let len = 8usize;
        let mut src = vec![0u8; len * 4];
        for (i, slot) in src.iter_mut().enumerate() {
            *slot = (i * 97 % 251) as u8;
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
            dst_scalar[p * 3 + 2] = src[s];
        }
        return dst_simd == dst_scalar;
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        true
    }
}

pub fn wave6_pack_rgba_to_bgr24_neon_matches_scalar_rgb_smoke() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        let len = 8usize;
        let mut src = vec![0u8; len * 4];
        for (i, slot) in src.iter_mut().enumerate() {
            *slot = (i * 113 % 251) as u8;
        }
        let mut dst_simd = vec![0u8; len * 3];
        unsafe {
            Framebuffer::pack_rgba_to_bgr24_neon_8pixels(
                src.as_ptr(),
                dst_simd.as_mut_ptr(),
                false,
            );
        }
        let mut dst_scalar = vec![0u8; len * 3];
        for p in 0..len {
            let s = p * 4;
            dst_scalar[p * 3] = src[s];
            dst_scalar[p * 3 + 1] = src[s + 1];
            dst_scalar[p * 3 + 2] = src[s + 2];
        }
        return dst_simd == dst_scalar;
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        true
    }
}

pub fn wave6_packer_env_override_no_std_smoke() -> bool {
    let previous_simd = hal::mmio::get_simd_level();
    let previous_override = crate::graphics::packer::qemu_test_get_packer_mode_override();

    unsafe {
        hal::mmio::set_simd_level(hal::mmio::simd_level::AVX2);
    }
    crate::graphics::packer::qemu_test_set_packer_mode_override(1);

    let mode_forced_scalar = crate::graphics::packer::get_packer_mode() == 1;
    let mut packer_runs = false;
    if mode_forced_scalar {
        let src = vec![0u8, 1, 2, 3, 10, 20, 30, 40, 90, 80, 70, 60];
        let mut dst = vec![0u8; src.len()];
        Framebuffer::pack_rgba_to_bgra(&src, &mut dst);
        packer_runs = dst == vec![2, 1, 0, 3, 30, 20, 10, 40, 70, 80, 90, 60];
    }

    crate::graphics::packer::qemu_test_clear_packer_mode_override();
    if previous_override != 0 {
        crate::graphics::packer::qemu_test_set_packer_mode_override(previous_override);
    }
    unsafe {
        hal::mmio::set_simd_level(previous_simd);
    }

    mode_forced_scalar && packer_runs
}

// ── Wave 9: session-3 optimisation regression smoke tests ───────────

/// draw_circle 8-fold symmetry check
pub fn wave9_draw_circle_symmetric_smoke() -> bool {
    let (w, h) = (32u32, 32u32);
    let info = FramebufferInfo { address: 0, width: w, height: h, stride: w * 4, format: PixelFormat::Bgra8888, bpp: 32 };
    let mut fb = unsafe { Framebuffer::new(info) };
    fb.enable_double_buffering_from_vec(vec![0u32; (w * h) as usize]);
    fb.draw_circle(16, 16, 8, Color::with_alpha(0, 255, 0, 255));
    let buf = fb.back_buffer.as_ref().unwrap();
    let px = |x: i32, y: i32| -> bool {
        if x < 0 || y < 0 || x >= w as i32 || y >= h as i32 { return false; }
        buf[y as usize * w as usize + x as usize] != 0
    };
    let mut any = false;
    for dy in 0..=8i32 {
        for dx in 0..=8i32 {
            if px(16 + dx, 16 + dy) {
                any = true;
                if !(px(16 - dx, 16 + dy) && px(16 + dx, 16 - dy) && px(16 - dx, 16 - dy)
                    && px(16 + dy, 16 + dx) && px(16 - dy, 16 + dx)
                    && px(16 + dy, 16 - dx) && px(16 - dy, 16 - dx))
                { return false; }
            }
        }
    }
    any
}

/// fill_circle: no interior gaps
pub fn wave9_fill_circle_no_gaps_smoke() -> bool {
    let (w, h) = (32u32, 32u32);
    let info = FramebufferInfo { address: 0, width: w, height: h, stride: w * 4, format: PixelFormat::Bgra8888, bpp: 32 };
    let mut fb = unsafe { Framebuffer::new(info) };
    fb.enable_double_buffering_from_vec(vec![0u32; (w * h) as usize]);
    let (cx, cy, r) = (16i32, 16i32, 7i32);
    fb.fill_circle(cx, cy, r, Color::with_alpha(0, 0, 255, 255));
    let buf = fb.back_buffer.as_ref().unwrap();
    for y in (cy - r)..=(cy + r) {
        for x in (cx - r)..=(cx + r) {
            let d = (x - cx) * (x - cx) + (y - cy) * (y - cy);
            if d < (r - 1) * (r - 1) {
                if buf[y as usize * w as usize + x as usize] == 0 { return false; }
            }
        }
    }
    true
}

/// draw_rect: outline correctness
pub fn wave9_draw_rect_outline_smoke() -> bool {
    let (w, h) = (20u32, 20u32);
    let info = FramebufferInfo { address: 0, width: w, height: h, stride: w * 4, format: PixelFormat::Bgra8888, bpp: 32 };
    let mut fb = unsafe { Framebuffer::new(info) };
    fb.enable_double_buffering_from_vec(vec![0u32; (w * h) as usize]);
    fb.draw_rect(Rect::new(2, 3, 10, 8), Color::with_alpha(255, 0, 0, 255));
    let buf = fb.back_buffer.as_ref().unwrap();
    let px = |x: i32, y: i32| buf[y as usize * w as usize + x as usize] != 0;
    // top/bottom edges
    for x in 2..12 { if !px(x, 3) || !px(x, 10) { return false; } }
    // left/right edges
    for y in 3..=10 { if !px(2, y) || !px(11, y) { return false; } }
    // interior empty
    for y in 4..10 { for x in 3..11 { if px(x, y) { return false; } } }
    true
}

/// draw_line steep: matches naive Bresenham
pub fn wave9_draw_line_steep_smoke() -> bool {
    let (w, h) = (20u32, 20u32);
    let info = FramebufferInfo { address: 0, width: w, height: h, stride: w * 4, format: PixelFormat::Bgra8888, bpp: 32 };
    let mut fb_opt = unsafe { Framebuffer::new(info.clone()) };
    let mut fb_naive = unsafe { Framebuffer::new(info.clone()) };
    fb_opt.enable_double_buffering_from_vec(vec![0u32; (w * h) as usize]);
    fb_naive.enable_double_buffering_from_vec(vec![0u32; (w * h) as usize]);

    let color = Color::with_alpha(0, 255, 0, 255);
    let cases: [(i32, i32, i32, i32); 4] = [(5,0,7,19),(10,19,8,0),(3,2,5,18),(15,15,12,0)];
    for (x1, y1, x2, y2) in cases {
        fb_opt.draw_line(x1, y1, x2, y2, color);
        // naive Bresenham
        let (mut x, mut y) = (x1, y1);
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
        if fb_opt.back_buffer.as_ref().unwrap() != fb_naive.back_buffer.as_ref().unwrap() {
            return false;
        }
        for b in fb_opt.back_buffer.as_mut().unwrap().iter_mut() { *b = 0; }
        for b in fb_naive.back_buffer.as_mut().unwrap().iter_mut() { *b = 0; }
    }
    true
}

/// draw_text 24bpp single-pass MMIO fg/bg
pub fn wave9_draw_text_24bit_single_pass_smoke() -> bool {
    let (w, h) = (8u32, 16u32);
    let stride = w * 3;
    let info = FramebufferInfo { address: 0, width: w, height: h, stride, format: PixelFormat::Bgr888, bpp: 24 };
    let mut vram = vec![0u8; info.size()];
    let mut info2 = info.clone();
    info2.address = vram.as_mut_ptr() as u64;
    let mut fb = unsafe { Framebuffer::new(info2) };
    fb.draw_text(0, 0, "!", Color::with_alpha(255, 0, 0, 255), Color::with_alpha(0, 0, 255, 255));
    // Row 2, '!' glyph = 0x18 -> bits 3,4 ON
    let off = |x: usize| 2 * stride as usize + x * 3;
    // Bgr888: red=[0x00,0x00,0xFF], blue=[0xFF,0x00,0x00]
    vram[off(2)] == 0xFF && vram[off(2)+1] == 0x00 && vram[off(2)+2] == 0x00
        && vram[off(3)] == 0x00 && vram[off(3)+1] == 0x00 && vram[off(3)+2] == 0xFF
        && vram[off(4)] == 0x00 && vram[off(4)+1] == 0x00 && vram[off(4)+2] == 0xFF
        && vram[off(5)] == 0xFF && vram[off(5)+1] == 0x00 && vram[off(5)+2] == 0x00
}

/// draw_char_8x16 24bpp MMIO single-pass
pub fn wave9_draw_char_8x16_24bit_smoke() -> bool {
    let (w, h) = (8u32, 16u32);
    let stride = w * 3;
    let info = FramebufferInfo { address: 0, width: w, height: h, stride, format: PixelFormat::Bgr888, bpp: 24 };
    let mut vram = vec![0u8; info.size()];
    let mut info2 = info.clone();
    info2.address = vram.as_mut_ptr() as u64;
    let mut fb = unsafe { Framebuffer::new(info2) };
    fb.draw_char_8x16(0, 0, '!', Color::GREEN, Some(Color::BLACK));
    // Row 2 0x18 -> bits 3,4 ON. Bgr888: green=[0x00,0x80,0x00], black=[0,0,0]
    let off = |x: usize| 2 * stride as usize + x * 3;
    vram[off(2)] == 0 && vram[off(2)+1] == 0 && vram[off(2)+2] == 0
        && vram[off(3)] == 0x00 && vram[off(3)+1] == 0x80 && vram[off(3)+2] == 0x00
        && vram[off(4)] == 0x00 && vram[off(4)+1] == 0x80 && vram[off(4)+2] == 0x00
        && vram[off(5)] == 0 && vram[off(5)+1] == 0 && vram[off(5)+2] == 0
}

/// draw_image RGB565 MMIO path
pub fn wave9_draw_image_rgb565_mmio_smoke() -> bool {
    let (w, h) = (4u32, 2u32);
    let info = FramebufferInfo { address: 0, width: w, height: h, stride: w * 2, format: PixelFormat::Rgb565, bpp: 16 };
    let mut vram = vec![0u8; info.size()];
    let mut info2 = info.clone();
    info2.address = vram.as_mut_ptr() as u64;
    let mut fb = unsafe { Framebuffer::new(info2) };
    let img = Image::filled(w, h, Color::with_alpha(255, 0, 0, 255));
    fb.draw_image(&img, 0, 0);
    // Red in RGB565 = 0xF800, LE = [0x00, 0xF8]
    for y in 0..h as usize {
        for x in 0..w as usize {
            let o = y * info.stride as usize + x * 2;
            if vram[o] != 0x00 || vram[o+1] != 0xF8 { return false; }
        }
    }
    true
}

/// write_opaque_run_32bit SIMD pack check
pub fn wave9_write_opaque_run_32bit_simd_smoke() -> bool {
    let (w, h) = (64u32, 1u32);
    let info = FramebufferInfo { address: 0, width: w, height: h, stride: w * 4, format: PixelFormat::Bgra8888, bpp: 32 };
    let mut vram = vec![0u8; info.size()];
    let mut info2 = info.clone();
    info2.address = vram.as_mut_ptr() as u64;
    let mut fb = unsafe { Framebuffer::new(info2) };
    let img = Image::filled(w, 1, Color::with_alpha(10, 20, 30, 255));
    fb.draw_image(&img, 0, 0);
    // BGRA in VRAM: B=30, G=20, R=10, A=255
    for x in 0..w as usize {
        let o = x * 4;
        if vram[o] != 30 || vram[o+1] != 20 || vram[o+2] != 10 || vram[o+3] != 255 {
            return false;
        }
    }
    true
}

/// draw_text RGB565 MMIO single-pass
pub fn wave9_draw_text_rgb565_mmio_smoke() -> bool {
    let (w, h) = (8u32, 16u32);
    let info = FramebufferInfo { address: 0, width: w, height: h, stride: w * 2, format: PixelFormat::Rgb565, bpp: 16 };
    let mut vram = vec![0u8; info.size()];
    let mut info2 = info.clone();
    info2.address = vram.as_mut_ptr() as u64;
    let mut fb = unsafe { Framebuffer::new(info2) };
    fb.draw_text(0, 0, "!", Color::with_alpha(255, 0, 0, 255), Color::BLACK);
    let off = |x: usize| 2 * info.stride as usize + x * 2;
    // red=0xF800=[0x00,0xF8], black=0x0000=[0x00,0x00]
    vram[off(2)] == 0x00 && vram[off(2)+1] == 0x00
        && vram[off(3)] == 0x00 && vram[off(3)+1] == 0xF8
        && vram[off(4)] == 0x00 && vram[off(4)+1] == 0xF8
        && vram[off(5)] == 0x00 && vram[off(5)+1] == 0x00
}

/// draw_char_8x16 RGB565 MMIO single-pass
pub fn wave9_draw_char_8x16_rgb565_smoke() -> bool {
    let (w, h) = (8u32, 16u32);
    let info = FramebufferInfo { address: 0, width: w, height: h, stride: w * 2, format: PixelFormat::Rgb565, bpp: 16 };
    let mut vram = vec![0u8; info.size()];
    let mut info2 = info.clone();
    info2.address = vram.as_mut_ptr() as u64;
    let mut fb = unsafe { Framebuffer::new(info2) };
    fb.draw_char_8x16(0, 0, '!', Color::RED, Some(Color::BLACK));
    let off = |x: usize| 2 * info.stride as usize + x * 2;
    vram[off(2)] == 0x00 && vram[off(2)+1] == 0x00
        && vram[off(3)] == 0x00 && vram[off(3)+1] == 0xF8
        && vram[off(4)] == 0x00 && vram[off(4)+1] == 0xF8
        && vram[off(5)] == 0x00 && vram[off(5)+1] == 0x00
}
