use rany_kernel::graphics::{Framebuffer, FramebufferInfo, PixelFormat, Color};
use rany_kernel::image::Image;

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

    let img = Image::filled(width, height, Color::with_alpha(64, 128, 192, 255));

    let start = Instant::now();
    for _ in 0..10 {
        fb.draw_image(&img, 0, 0);
    }
    let elapsed = start.elapsed();
    println!("integration bench_draw_image: {:?}", elapsed);
}
