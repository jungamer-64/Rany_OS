use criterion::{black_box, Criterion};
use std::env;

use rany_os::graphics::framebuffer::Framebuffer;
use rany_os::graphics::image::Image;
use rany_os::graphics::{FramebufferInfo, PixelFormat, Color};

fn setup_fb(info: &FramebufferInfo) -> (Vec<u8>, Framebuffer, Image) {
    let mut mem = vec![0u8; info.size()];
    let addr = mem.as_mut_ptr() as u64;
    let mut info2 = info.clone();
    info2.address = addr;

    let fb = unsafe { Framebuffer::new(info2) };
    let img = Image::filled(info.width, info.height, Color::with_alpha(64, 128, 192, 255));
    (mem, fb, img)
}

fn bench_draw_image_with_criterion(c: &mut Criterion) {
    let width = 800u32;
    let height = 600u32;

    let info_bgra = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 4,
        format: PixelFormat::Bgra8888,
        bpp: 32,
    };

    let info_bgr24 = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 3,
        format: PixelFormat::Bgr888,
        bpp: 24,
    };

    let info_rgba = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 4,
        format: PixelFormat::Rgba8888,
        bpp: 32,
    };

    let (_mem_bgra, mut fb_bgra, img_bgra) = setup_fb(&info_bgra);
    c.bench_function("draw_image_bgra", |b| b.iter(|| fb_bgra.draw_image(black_box(&img_bgra), 0, 0)));

    let (_mem_bgr24, mut fb_bgr24, img_bgr24) = setup_fb(&info_bgr24);
    c.bench_function("draw_image_bgr24", |b| b.iter(|| fb_bgr24.draw_image(black_box(&img_bgr24), 0, 0)));

    let (_mem_rgba, mut fb_rgba, img_rgba) = setup_fb(&info_rgba);
    c.bench_function("draw_image_rgba", |b| b.iter(|| fb_rgba.draw_image(black_box(&img_rgba), 0, 0)));

    // Draw-line micro-benchmark: many short/long lines across the framebuffer
    let (_mem_lines, mut fb_lines, _img) = setup_fb(&info_bgra);
    // Precompute deterministic list of lines
    let mut lines = Vec::new();
    for i in 0..1000u32 {
        let x1 = (i % width) as i32;
        let y1 = ((i * 3) % height) as i32;
        let x2 = ((i * 7 + 13) % width) as i32;
        let y2 = ((i * 11 + 29) % height) as i32;
        lines.push((x1, y1, x2, y2));
    }
    c.bench_function("draw_line_many", |b| b.iter(|| {
        for &(x1, y1, x2, y2) in &lines {
            fb_lines.draw_line(x1, y1, x2, y2, Color::with_alpha(10, 20, 30, 255));
        }
    }));

    // Also run the naive version when available (bench feature exposes it) to compare
    c.bench_function("draw_line_many_naive", |b| b.iter(|| {
        for &(x1, y1, x2, y2) in &lines {
            fb_lines.draw_line_naive(x1, y1, x2, y2, Color::with_alpha(10, 20, 30, 255));
        }
    }));
}

fn main() {
    // If the user runs `cargo run`, accept optional argument "criterion" to run Criterion benches,
    // otherwise fall back to a small custom micro-benchmark for quick numbers.
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "criterion") {
        let mut c = Criterion::default();
        bench_draw_image_with_criterion(&mut c);
        c.final_summary();
    } else {
        // fallback: quick micro-bench using Criterion's simple bench to get a summary-like output
        println!("Running quick Criterion benches (use `cargo run --release -- criterion` for full results)");
        let mut c = Criterion::default();
        bench_draw_image_with_criterion(&mut c);
        c.final_summary();
    }
}
