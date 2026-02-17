use super::*;
use crate::graphics::image::Image;
use alloc::vec;
use alloc::vec::Vec;

mod _split_1;
use _split_1::*;
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
