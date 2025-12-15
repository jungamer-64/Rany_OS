#![cfg(feature = "bench")]

use rany_os::graphics::{Color, Framebuffer, FramebufferInfo, PixelFormat};
use rany_os::image::Image;

#[test]
#[ignore]
fn bench_draw_image_integration() {
    use std::time::Instant;

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

    let img_opaque = Image::filled(width, height, Color::with_alpha(64, 128, 192, 255));
    let img_alpha = Image::filled(width, height, Color::with_alpha(64, 128, 192, 128));

    // 1. Opaque Image Draw
    let start = Instant::now();
    for _ in 0..10 {
        fb.draw_image(&img_opaque, 0, 0);
    }
    let elapsed = start.elapsed();
    println!("bench_draw_image (opaque): {:?}", elapsed);

    // 2. Alpha Image Draw
    let start = Instant::now();
    for _ in 0..10 {
        fb.draw_image(&img_alpha, 0, 0);
    }
    let elapsed = start.elapsed();
    println!("bench_draw_image (alpha):  {:?}", elapsed);

    // 3. Text Draw
    let start = Instant::now();
    for _ in 0..100 {
        fb.draw_text(
            10,
            10,
            "Hello, World! This is a benchmark for text rendering.",
            Color::WHITE,
        );
    }
    let elapsed = start.elapsed();
    println!("bench_draw_text:         {:?}", elapsed);

    // 4. Line Draw (Batching check)
    let start = Instant::now();
    for i in 0..1000 {
        fb.draw_line(0, 0, width as i32, (i % height) as i32, Color::RED);
    }
    let elapsed = start.elapsed();
    println!("bench_draw_line:         {:?}", elapsed);
}
