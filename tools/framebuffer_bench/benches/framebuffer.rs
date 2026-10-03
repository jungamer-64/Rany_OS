#[path = "../src/fixtures.rs"]
mod fixtures;
// framebuffer_bench/benches/framebuffer.rs
use criterion::{Criterion, criterion_group, criterion_main};
use rany_os::graphics::framebuffer::{FramebufferLayout, PixelBuffer};
use std::time::Duration;

use rany_os::graphics::font::BitmapFont;
use rany_os::graphics::framebuffer::Framebuffer;
use rany_os::graphics::image::Image;
use rany_os::graphics::{Color, FramebufferInfo, PixelFormat};

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

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vec![0u8; info.size()]),
    )
    .expect("framebuffer workspace");
    let back = vec![0u32; (width * height) as usize];
    fb.enable_double_buffering_from_vec(back)
        .expect("valid back plane");

    let img = Image::filled(width, height, Color::with_alpha(64, 128, 192, 255));

    c.bench_function("draw_image_bgra", |b| {
        b.iter(|| {
            fb.draw_image(&img, 0, 0);
        })
    });
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

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vec![0u8; info.size()]),
    )
    .expect("framebuffer workspace");
    let back = vec![0u32; (width * height) as usize];
    fb.enable_double_buffering_from_vec(back)
        .expect("valid back plane");

    let img = Image::filled(width, height, Color::with_alpha(64, 128, 192, 255));

    c.bench_function("draw_image_bgr24", |b| {
        b.iter(|| {
            fb.draw_image(&img, 0, 0);
        })
    });
}

fn bench_scanout_stores(c: &mut Criterion) {
    let mut storage = fixtures::scanout_storage(8192 * 4);
    for pixels in [1, 1024, 8192] {
        let data = vec![0xA5u8; pixels * 4];
        c.bench_function(&format!("scanout_host_store_{pixels}_pixels"), |b| {
            b.iter(|| {
                storage
                    .region_mut(0, data.len())
                    .expect("benchmark span")
                    .write_bytes(&data)
                    .expect("complete store span");
                rany_os::hal::mmio::sfence();
            });
        });
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

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vec![0u8; info.size()]),
    )
    .expect("framebuffer workspace");
    let back = vec![0u32; (width * height) as usize];
    fb.enable_double_buffering_from_vec(back)
        .expect("valid back plane");

    let img = Image::filled(width, height, Color::with_alpha(64, 128, 192, 255));

    c.bench_function("draw_image_rgba", |b| {
        b.iter(|| {
            fb.draw_image(&img, 0, 0);
        })
    });
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
    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vec![0u8; info.size()]),
    )
    .expect("framebuffer workspace");
    let back = vec![0u32; (width * height) as usize];
    fb.enable_double_buffering_from_vec(back)
        .expect("valid back plane");

    let text = "The quick brown fox jumps over the lazy dog. 0123456789!@#$%^&*()";
    c.bench_function("draw_text_32bit", |b| {
        b.iter(|| {
            fb.draw_text(100, 100, text, Color::WHITE, Color::BLACK);
        })
    });
}

fn bench_draw_text_host_scanout(c: &mut Criterion) {
    let layout = FramebufferLayout::new(800, 600, 800 * 4, PixelFormat::Bgra8888)
        .expect("benchmark geometry");
    let mut fb = fixtures::scanout_framebuffer(layout);
    let text = "The quick brown fox jumps over the lazy dog. 0123456789!@#$%^&*()";
    c.bench_function("draw_text_host_scanout_batch", |b| {
        b.iter(|| fb.draw_text(100, 100, text, Color::WHITE, Color::BLACK));
    });
    c.bench_function("draw_text_host_scanout_per_glyph", |b| {
        b.iter(|| {
            for (index, glyph) in text.chars().enumerate() {
                fb.draw_char_8x16(
                    100 + index as i32 * 8,
                    100,
                    glyph,
                    Color::WHITE,
                    Some(Color::BLACK),
                );
            }
        });
    });
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
    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vec![0u8; info.size()]),
    )
    .expect("framebuffer workspace");
    let back = vec![0u32; (width * height) as usize];
    fb.enable_double_buffering_from_vec(back)
        .expect("valid back plane");

    let img = Image::filled(width, height, Color::with_alpha(64, 128, 192, 128));
    c.bench_function("draw_image_alpha", |b| {
        b.iter(|| {
            fb.draw_image(&img, 0, 0);
        })
    });
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
    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vec![0u8; info.size()]),
    )
    .expect("framebuffer workspace");
    let back = vec![0u32; (width * height) as usize];
    fb.enable_double_buffering_from_vec(back)
        .expect("valid back plane");

    c.bench_function("draw_char_with_bg", |b| {
        b.iter(|| {
            fb.draw_char_8x16(100, 100, 'A', Color::WHITE, Some(Color::BLACK));
        })
    });
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
    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vec![0u8; info.size()]),
    )
    .expect("framebuffer workspace");
    let back = vec![0u32; (width * height) as usize];
    fb.enable_double_buffering_from_vec(back)
        .expect("valid back plane");

    c.bench_function("draw_char_no_bg", |b| {
        b.iter(|| {
            fb.draw_char_8x16(100, 100, 'A', Color::WHITE, None);
        })
    });
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

    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vec![0u8; info.size()]),
    )
    .expect("framebuffer workspace");
    let back = vec![0u32; (width * height) as usize];
    fb.enable_double_buffering_from_vec(back)
        .expect("valid back plane");

    let text = "The quick brown fox jumps over the lazy dog. 0123456789!@#$%^&*()";
    let font = BitmapFont::default_8x16();

    c.bench_function("draw_text_manual", |b| {
        b.iter(|| {
            // Fill background for the whole span (same as draw_text)
            let char_count = text.chars().filter(|&c| c != '\n').count() as u32;
            let text_w = char_count * font.width() as u32;
            let text_h = font.height() as u32;
            fb.fill_rect(
                rany_os::graphics::Rect::new(100, 100, text_w, text_h),
                Color::BLACK,
            );

            // Draw each glyph through the normal synchronous rendering boundary
            let mut cx = 100i32;
            for ch in text.chars() {
                if ch == '\n' {
                    continue;
                }
                fb.draw_char_8x16(cx, 100, ch, Color::WHITE, Some(Color::BLACK));
                cx += font.width() as i32;
            }
        })
    });
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
    let mut fb = Framebuffer::new(
        FramebufferLayout::new(info.width, info.height, info.stride, info.format)
            .expect("valid fixture geometry"),
        PixelBuffer::Memory(vec![0u8; info.size()]),
    )
    .expect("framebuffer workspace");
    let back = vec![0u32; (width * height) as usize];
    fb.enable_double_buffering_from_vec(back)
        .expect("valid back plane");

    c.bench_function("fill_rect_full", |b| {
        b.iter(|| {
            fb.fill_rect(
                rany_os::graphics::Rect::new(0, 0, width, height),
                Color::BLUE,
            );
        })
    });
}

fn bench_fill_rect_host_scanout(c: &mut Criterion) {
    let layout = FramebufferLayout::new(800, 600, 800 * 4, PixelFormat::Bgra8888)
        .expect("benchmark geometry");
    let mut fb = fixtures::scanout_framebuffer(layout);
    c.bench_function("fill_rect_host_scanout_batch", |b| {
        b.iter(|| fb.fill_rect(rany_os::graphics::Rect::new(0, 0, 800, 600), Color::BLUE));
    });
    c.bench_function("fill_rect_host_scanout_per_row", |b| {
        b.iter(|| {
            for row in 0..600 {
                fb.fill_rect(rany_os::graphics::Rect::new(0, row, 800, 1), Color::BLUE);
            }
        });
    });
}

fn criterion_config() -> Criterion {
    // Longer measurement time and moderate sample size to reduce noise in CI
    Criterion::default()
        .measurement_time(Duration::from_secs(6))
        .sample_size(60)
}

criterion_group! {
    name = framebuffer_benches;
    config = criterion_config();
    targets = bench_draw_image_bgra,
              bench_draw_image_24bit,
              bench_draw_image_rgba,
              bench_draw_text_32bit,
              bench_draw_text_host_scanout,
              bench_draw_text_manual,
              bench_draw_image_alpha,
              bench_scanout_stores,
              bench_fill_rect_full,
              bench_fill_rect_host_scanout,
              bench_draw_char_with_bg,
              bench_draw_char_no_bg
}
criterion_main!(framebuffer_benches);
