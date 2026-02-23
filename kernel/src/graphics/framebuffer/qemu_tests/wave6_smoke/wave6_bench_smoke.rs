use crate::graphics::framebuffer::{Color, Framebuffer, FramebufferInfo, PixelFormat};
use crate::graphics::image::Image;
use alloc::vec;

fn back_buffer_ref(fb: &Framebuffer) -> Option<&[u32]> {
    fb.back_buffer.as_deref()
}

fn checksum_u32(buf: &[u32]) -> u64 {
    let mut acc = 0xcbf2_9ce4_8422_2325u64;
    for &v in buf {
        acc ^= v as u64;
        acc = acc.wrapping_mul(0x1000_0000_01b3);
        acc ^= (v as u64).rotate_left(13);
    }
    acc
}

fn all_pixels_match(buf: &[u32], expected: Color) -> bool {
    buf.iter().all(|&pixel| {
        let c = Color::from_u32(pixel);
        super::eq_color(c, expected.red, expected.green, expected.blue, expected.alpha)
    })
}

fn all_pixels_match_rgb(buf: &[u32], expected: Color) -> bool {
    buf.iter().all(|&pixel| {
        let c = Color::from_u32(pixel);
        super::eq_color_rgb(c, expected.red, expected.green, expected.blue)
    })
}

fn has_pixel_exact(buf: &[u32], expected: Color) -> bool {
    let target = expected.to_u32();
    buf.iter().any(|&p| p == target)
}

pub fn wave6_bench_draw_image_bulk_smoke() -> bool {
    let width = 96u32;
    let height = 64u32;
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

    let expected = Color::with_alpha(64, 128, 192, 255);
    let img = Image::filled(width, height, expected);

    let mut prev = None;
    let mut stable_tail = false;
    for _ in 0..8 {
        fb.draw_image(&img, 0, 0);
        let back = match back_buffer_ref(&fb) {
            Some(v) => v,
            None => return false,
        };
        let sum = checksum_u32(back);
        stable_tail = prev == Some(sum);
        prev = Some(sum);
    }

    let back = match back_buffer_ref(&fb) {
        Some(v) => v,
        None => return false,
    };
    stable_tail && all_pixels_match(back, expected)
}

pub fn wave6_bench_draw_image_24bit_bulk_smoke() -> bool {
    let width = 96u32;
    let height = 64u32;
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

    let expected = Color::with_alpha(64, 128, 192, 255);
    let img = Image::filled(width, height, expected);

    let mut prev = None;
    let mut stable_tail = false;
    for _ in 0..8 {
        fb.draw_image(&img, 0, 0);
        let back = match back_buffer_ref(&fb) {
            Some(v) => v,
            None => return false,
        };
        let sum = checksum_u32(back);
        stable_tail = prev == Some(sum);
        prev = Some(sum);
    }

    let back = match back_buffer_ref(&fb) {
        Some(v) => v,
        None => return false,
    };
    stable_tail && all_pixels_match_rgb(back, expected)
}

pub fn wave6_bench_draw_image_rgba_bulk_smoke() -> bool {
    let width = 96u32;
    let height = 64u32;
    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 4,
        format: PixelFormat::Rgba8888,
        bpp: 32,
    };

    let mut fb = unsafe { Framebuffer::new(info.clone()) };
    fb.enable_double_buffering_from_vec(vec![0u32; (info.width * info.height) as usize]);

    let expected = Color::with_alpha(64, 128, 192, 255);
    let img = Image::filled(width, height, expected);

    let mut prev = None;
    let mut stable_tail = false;
    for _ in 0..8 {
        fb.draw_image(&img, 0, 0);
        let back = match back_buffer_ref(&fb) {
            Some(v) => v,
            None => return false,
        };
        let sum = checksum_u32(back);
        stable_tail = prev == Some(sum);
        prev = Some(sum);
    }

    let back = match back_buffer_ref(&fb) {
        Some(v) => v,
        None => return false,
    };
    stable_tail && all_pixels_match(back, expected)
}

pub fn wave6_bench_draw_hline_bulk_smoke() -> bool {
    let width = 160u32;
    let height = 64u32;
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

    let expected = Color::with_alpha(10, 20, 30, 255);
    let mut prev = None;
    let mut stable_tail = false;

    for _ in 0..2 {
        for y in 0..height {
            fb.draw_hline(0, width as i32 - 1, y as i32, expected);
        }
        let back = match back_buffer_ref(&fb) {
            Some(v) => v,
            None => return false,
        };
        let sum = checksum_u32(back);
        stable_tail = prev == Some(sum);
        prev = Some(sum);
    }

    let back = match back_buffer_ref(&fb) {
        Some(v) => v,
        None => return false,
    };
    if !stable_tail {
        return false;
    }

    for y in 0..height as usize {
        let row = y * width as usize;
        let left = Color::from_u32(back[row]);
        let mid = Color::from_u32(back[row + (width as usize / 2)]);
        let right = Color::from_u32(back[row + width as usize - 1]);
        if !super::eq_color(left, expected.red, expected.green, expected.blue, expected.alpha)
            || !super::eq_color(mid, expected.red, expected.green, expected.blue, expected.alpha)
            || !super::eq_color(right, expected.red, expected.green, expected.blue, expected.alpha)
        {
            return false;
        }
    }
    true
}

pub fn wave6_bench_draw_text_bulk_smoke() -> bool {
    let width = 320u32;
    let height = 64u32;
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
    let text = "The quick brown fox jumps";

    let mut checksums = [0u64; 2];
    for i in 0..16 {
        fb.draw_text(0, 0, text, fg, bg);
        let back = match back_buffer_ref(&fb) {
            Some(v) => v,
            None => return false,
        };
        checksums[i % 2] = checksum_u32(back);
    }

    let back = match back_buffer_ref(&fb) {
        Some(v) => v,
        None => return false,
    };

    checksums[0] == checksums[1] && has_pixel_exact(back, fg) && has_pixel_exact(back, bg)
}
