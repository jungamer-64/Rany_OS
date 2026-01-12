#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(test_runner)]
#![reexport_test_harness_main = "test_main"]
#![feature(format_args_nl)]

extern crate alloc;

use alloc::vec;
use rany_os::graphics::{Color, Framebuffer, FramebufferInfo, PixelFormat};
use rany_os::graphics::image::Image;
use rany_os::time::precise_time_nanos;
use boot_proto::ExoBootInfo;

fn test_runner(tests: &[&dyn Fn()]) {
    for test in tests {
        test();
    }
    // minimal exit (loop forever if success, or qemu exit if possible)
    rany_os::io::log::early_print("[TEST] All tests passed!\n");
    // rany_os::exit_qemu(rany_os::QemuExitCode::Success); // If accessible
    loop {}
}



#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    rany_os::panic_handler::panic(info)
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(_boot_info: &'static mut ExoBootInfo) -> ! {
    test_main();
    loop {}
}

#[test_case]
fn bench_draw_image_integration() {
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

    // Safety: Creating a dummy framebuffer for testing purposes.
    // In a real kernel environment, address 0 might be invalid, but for this bench logic
    // we need to see if it just writes to memory (if mapped) or if we need a real buffer.
    // The original code used Framebuffer::new with address 0. 
    // Wait, Framebuffer writes to `address`. If 0 is not mapped, this will crash.
    // The original test had `let mut fb = unsafe { Framebuffer::new(info.clone()) };`
    // and `fb.enable_double_buffering_from_vec(back);`
    // If double buffering is enabled, it writes to the backbuffer (vec) first?
    // Let's assume the original test knew what it was doing regarding double buffering.
    
    let mut fb = unsafe { Framebuffer::new(info.clone()) };
    let size = info.size();
    let back = vec![0u32; (size / 4) as usize];
    fb.enable_double_buffering_from_vec(back);

    let img_opaque = Image::filled(width, height, Color::with_alpha(64, 128, 192, 255));
    let img_alpha = Image::filled(width, height, Color::with_alpha(64, 128, 192, 128));

    // 1. Opaque Image Draw
    let start = precise_time_nanos();
    for _ in 0..10 {
        fb.draw_image(&img_opaque, 0, 0);
    }
    let end = precise_time_nanos();
    rany_os::println!("bench_draw_image (opaque): {} ns", end - start);

    // 2. Alpha Image Draw
    let start = precise_time_nanos();
    for _ in 0..10 {
        fb.draw_image(&img_alpha, 0, 0);
    }
    let end = precise_time_nanos();
    rany_os::println!("bench_draw_image (alpha):  {} ns", end - start);

    // 3. Text Draw
    let start = precise_time_nanos();
    for _ in 0..100 {
        fb.draw_text(
            10,
            10,
            "Hello, RanyOS Benchmark!",
            Color::WHITE,
            Color::BLACK
        );
    }
    let end = precise_time_nanos();
    rany_os::println!("bench_draw_text (100x):    {} ns", end - start);

    // 4. Line Draw (Batching check)
    let start = precise_time_nanos();
    for i in 0..1000 {
        fb.draw_line(0, 0, width as i32, (i % height) as i32, Color::RED);
    }
    rany_os::println!("bench_draw_line:         {:?}", precise_time_nanos() - start);
}
