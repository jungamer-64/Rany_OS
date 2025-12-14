use criterion::{criterion_group, criterion_main, Criterion};

use rany_os::graphics::framebuffer::Framebuffer;
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

criterion_group!(framebuffer_benches, bench_draw_image_bgra, bench_draw_image_24bit, bench_draw_image_rgba);
criterion_main!(framebuffer_benches);
