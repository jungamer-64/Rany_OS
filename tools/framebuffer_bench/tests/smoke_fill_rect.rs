use rany_os::graphics::{FramebufferInfo, PixelFormat, Rect, Color};
use rany_os::graphics::framebuffer::Framebuffer;

#[test]
fn fill_rect_mmio_writes_to_heap_buffer() {
    let width = 100u32;
    let height = 100u32;
    let info = FramebufferInfo {
        address: 0, // will be patched by test
        width,
        height,
        stride: width * 4,
        format: PixelFormat::Bgra8888,
        bpp: 32,
    };

    // Create a heap-backed framebuffer memory and point Framebuffer at it
    let mut mem = vec![0u8; (info.size() as usize)];
    let addr = mem.as_mut_ptr() as u64;
    let mut info2 = info.clone();
    info2.address = addr;

    let mut fb = unsafe { Framebuffer::new(info2) };

    // Fill a small rectangle of known coords and check memory changed
    let rect = Rect::new(10, 10, 20, 20);
    fb.fill_rect(rect, Color::with_alpha(0xAA, 0xBB, 0xCC, 0xFF));

    // Calculate offset of a pixel we expect to be modified
    let stride = info.stride as usize;
    let px_offset = (11usize * stride) + (11usize * 4);
    let pixel = &mem[px_offset..px_offset + 4];
    // Ensure pixel is not all zeros
    assert!(pixel.iter().any(|&b| b != 0));
}
