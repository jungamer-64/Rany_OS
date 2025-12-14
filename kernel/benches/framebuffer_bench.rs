use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rany_os::graphics::framebuffer::Framebuffer;
use rany_os::graphics::framebuffer::FramebufferInfo;
use rany_os::graphic_types::types::{PixelFormat, Color};
use rany_os::graphics::image::Image;

fn bench_draw_image_bgra_mmio(c: &mut Criterion) {
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

    let mut mem = vec![0u8; info.size()];
    let addr = mem.as_mut_ptr() as u64;
    let mut info2 = info.clone();
    info2.address = addr;

    let mut fb = unsafe { Framebuffer::new(info2) };
    let img = Image::filled(width, height, Color::with_alpha(64, 128, 192, 255));

    c.bench_function("draw_image_bgra_mmio", |b| {
        b.iter(|| fb.draw_image(black_box(&img), 0, 0))
    });
}

fn bench_draw_image_rgba_mmio(c: &mut Criterion) {
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

    let mut mem = vec![0u8; info.size()];
    let addr = mem.as_mut_ptr() as u64;
    let mut info2 = info.clone();
    info2.address = addr;

    let mut fb = unsafe { Framebuffer::new(info2) };
    let img = Image::filled(width, height, Color::with_alpha(64, 128, 192, 255));

    c.bench_function("draw_image_rgba_mmio", |b| {
        b.iter(|| fb.draw_image(black_box(&img), 0, 0))
    });
}

fn bench_draw_image_bgr24_mmio(c: &mut Criterion) {
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

    let mut mem = vec![0u8; info.size()];
    let addr = mem.as_mut_ptr() as u64;
    let mut info2 = info.clone();
    info2.address = addr;

    let mut fb = unsafe { Framebuffer::new(info2) };
    let img = Image::filled(width, height, Color::with_alpha(64, 128, 192, 255));

    c.bench_function("draw_image_bgr24_mmio", |b| {
        b.iter(|| fb.draw_image(black_box(&img), 0, 0))
    });
}

criterion_group!(framebuffer_benches, bench_draw_image_bgra_mmio, bench_draw_image_rgba_mmio, bench_draw_image_bgr24_mmio);
criterion_main!(framebuffer_benches);
