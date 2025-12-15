// framebuffer_bench/benches/framebuffer.rs
use criterion::{criterion_group, criterion_main, Criterion};
use std::time::Duration;

use rany_os::graphics::framebuffer::Framebuffer;
use rany_os::graphics::font::BitmapFont;
use rany_os::graphics::image::Image;
use rany_os::graphics::{FramebufferInfo, PixelFormat, Color};

fn bench_draw_image_bgra(c: &mut Criterion) {
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
    let back = vec![0u8; info.size()];
    fb.enable_double_buffering_from_vec(back);

    let img = Image::filled(width, height, Color::with_alpha(64, 128, 192, 255));

    c.bench_function("draw_image_bgra", |b| b.iter(|| {
        fb.draw_image(&img, 0, 0);
    }));
}

fn bench_draw_image_24bit(c: &mut Criterion) {
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
    let back = vec![0u8; info.size()];
    fb.enable_double_buffering_from_vec(back);

    let img = Image::filled(width, height, Color::with_alpha(64, 128, 192, 255));

    c.bench_function("draw_image_bgr24", |b| b.iter(|| {
        fb.draw_image(&img, 0, 0);
    }));
}

fn bench_write_u32_streams(c: &mut Criterion) {
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
    let back = vec![0u8; info.size()];
    fb.enable_double_buffering_from_vec(back);

    // small and large runs to isolate u32 streaming write performance
    for &sz in &[1usize, 1024usize, 8192usize] {
        let mut vec_u32 = vec![0u32; sz];
        for i in 0..sz { vec_u32[i] = i as u32; }
        let name = format!("write_u32_stream_{}", sz);
        c.bench_function(&name, |b| b.iter(|| {
            fb.bench_write_u32_slice_streaming(0, 0, &vec_u32);
        }));
    }
}
fn bench_draw_image_rgba(c: &mut Criterion) {
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
    let back = vec![0u8; info.size()];
    fb.enable_double_buffering_from_vec(back);

    let img = Image::filled(width, height, Color::with_alpha(64, 128, 192, 255));

    c.bench_function("draw_image_rgba", |b| b.iter(|| {
        fb.draw_image(&img, 0, 0);
    }));
}

fn bench_draw_text_32bit(c: &mut Criterion) {
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
    let back = vec![0u8; info.size()];
    fb.enable_double_buffering_from_vec(back);

    let text = "The quick brown fox jumps over the lazy dog. 0123456789!@#$%^&*()";
    c.bench_function("draw_text_32bit", |b| b.iter(|| {
        fb.draw_text(100, 100, text, Color::WHITE, Color::BLACK);
    }));
}

fn bench_draw_text_32bit_mmio_batch(c: &mut Criterion) {
    let width = 800u32;
    let height = 600u32;
    let mut info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 4,
        format: PixelFormat::Bgra8888,
        bpp: 32,
    };

    // Create a front buffer region to safely perform streaming MMIO writes
    let mut front = vec![0u8; info.size()];
    info.address = front.as_mut_ptr() as u64;

    let mut fb = unsafe { Framebuffer::new(info.clone()) };

    let text = "The quick brown fox jumps over the lazy dog. 0123456789!@#$%^&*()";
    c.bench_function("draw_text_32bit_mmio_batch", |b| b.iter(|| {
        fb.draw_text(100, 100, text, Color::WHITE, Color::BLACK);
    }));
}

fn bench_draw_text_32bit_mmio_per_glyph_fenced(c: &mut Criterion) {
    let width = 800u32;
    let height = 600u32;
    let mut info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 4,
        format: PixelFormat::Bgra8888,
        bpp: 32,
    };

    // Front buffer for MMIO-like streaming writes
    let mut front = vec![0u8; info.size()];
    info.address = front.as_mut_ptr() as u64;

    let mut fb = unsafe { Framebuffer::new(info.clone()) };

    let text = "The quick brown fox jumps over the lazy dog. 0123456789!@#$%^&*()";
    c.bench_function("draw_text_32bit_mmio_per_glyph_fenced", |b| b.iter(|| {
        fb.bench_draw_text_per_glyph_fenced(100, 100, text, Color::WHITE, Color::BLACK);
    }));
}

fn bench_draw_image_alpha(c: &mut Criterion) {
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
    let back = vec![0u8; info.size()];
    fb.enable_double_buffering_from_vec(back);

    let img = Image::filled(width, height, Color::with_alpha(64, 128, 192, 128));
    c.bench_function("draw_image_alpha", |b| b.iter(|| {
        fb.draw_image(&img, 0, 0);
    }));
}

fn bench_draw_char_with_bg(c: &mut Criterion) {
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
    let back = vec![0u8; info.size()];
    fb.enable_double_buffering_from_vec(back);

    c.bench_function("draw_char_with_bg", |b| b.iter(|| {
        fb.draw_char_8x16(100, 100, 'A', Color::WHITE, Some(Color::BLACK));
    }));
}

fn bench_draw_char_no_bg(c: &mut Criterion) {
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
    let back = vec![0u8; info.size()];
    fb.enable_double_buffering_from_vec(back);

    c.bench_function("draw_char_no_bg", |b| b.iter(|| {
        fb.draw_char_8x16(100, 100, 'A', Color::WHITE, None);
    }));
}

fn bench_draw_text_manual(c: &mut Criterion) {
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
    let back = vec![0u8; info.size()];
    fb.enable_double_buffering_from_vec(back);

    let text = "The quick brown fox jumps over the lazy dog. 0123456789!@#$%^&*()";
    let font = BitmapFont::default_8x16();

    c.bench_function("draw_text_manual", |b| b.iter(|| {
        // Fill background for the whole span (same as draw_text)
        let char_count = text.chars().filter(|&c| c != '\n').count() as u32;
        let text_w = char_count * font.width() as u32;
        let text_h = font.height() as u32;
        fb.fill_rect(rany_os::graphics::Rect::new(100, 100, text_w, text_h), Color::BLACK);

        // Draw each glyph without per-char dirty updates (bench helper)
        let mut cx = 100i32;
        for ch in text.chars() {
            if ch == '\n' { continue; }
            fb.bench_draw_char_no_dirty(cx, 100, ch, Color::WHITE, Some(Color::BLACK));
            cx += font.width() as i32;
        }
    }));
}

fn bench_fill_rect_full(c: &mut Criterion) {
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
    let back = vec![0u8; info.size()];
    fb.enable_double_buffering_from_vec(back);

    c.bench_function("fill_rect_full", |b| b.iter(|| {
        fb.fill_rect(rany_os::graphics::Rect::new(0, 0, width, height), Color::BLUE);
    }));
}

fn bench_fill_rect_full_mmio_batch(c: &mut Criterion) {
    let width = 800u32;
    let height = 600u32;
    let mut info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 4,
        format: PixelFormat::Bgra8888,
        bpp: 32,
    };

    let mut front = vec![0u8; info.size()];
    info.address = front.as_mut_ptr() as u64;
    let mut fb = unsafe { Framebuffer::new(info.clone()) };

    c.bench_function("fill_rect_full_mmio_batch", |b| b.iter(|| {
        fb.fill_rect(rany_os::graphics::Rect::new(0, 0, width, height), Color::BLUE);
    }));
}

fn bench_fill_rect_full_mmio_per_row_fenced(c: &mut Criterion) {
    let width = 800u32;
    let height = 600u32;
    let mut info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 4,
        format: PixelFormat::Bgra8888,
        bpp: 32,
    };

    let mut front = vec![0u8; info.size()];
    info.address = front.as_mut_ptr() as u64;
    let mut fb = unsafe { Framebuffer::new(info.clone()) };

    c.bench_function("fill_rect_full_mmio_per_row_fenced", |b| b.iter(|| {
        fb.bench_fill_rect_per_row_fenced(rany_os::graphics::Rect::new(0, 0, width, height), Color::BLUE);
    }));
}

fn criterion_config() -> Criterion {
    // Longer measurement time and moderate sample size to reduce noise in CI
    Criterion::default()
        .measurement_time(Duration::from_secs(6))
        .sample_size(60)
}

criterion_group!{
    name = framebuffer_benches;
    config = criterion_config();
    targets = bench_draw_image_bgra, 
              bench_draw_image_24bit, 
              bench_draw_image_rgba,
              bench_draw_text_32bit,
              bench_draw_text_32bit_mmio_batch,
              bench_draw_text_32bit_mmio_per_glyph_fenced,
              bench_draw_text_manual,
              bench_draw_image_alpha,
              bench_write_u32_streams,
              bench_fill_rect_full,
              bench_fill_rect_full_mmio_batch,
              bench_fill_rect_full_mmio_per_row_fenced,
              bench_draw_char_with_bg,
              bench_draw_char_no_bg
}
criterion_main!(framebuffer_benches);
