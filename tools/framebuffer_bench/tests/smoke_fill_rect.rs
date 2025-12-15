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

#[test]
fn draw_text_writes_to_heap_buffer() {
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

    // Heap-backed framebuffer
    let mut mem = vec![0u8; (info.size() as usize)];
    let addr = mem.as_mut_ptr() as u64;
    let mut info2 = info.clone();
    info2.address = addr;

    let mut fb = unsafe { Framebuffer::new(info2) };

    // Draw a single glyph and ensure it modified framebuffer memory
    fb.draw_text(10, 10, "A", Color::with_alpha(0xFF, 0xFF, 0xFF, 0xFF), Color::BLACK);

    let stride = info.stride as usize;
    let mut found = false;
    for y in 10..(10 + 16) {
        for x in 10..(10 + 8) {
            let px_offset = (y as usize * stride) + (x as usize * 4);
            let pixel = &mem[px_offset..px_offset + 4];
            if pixel.iter().any(|&b| b != 0) {
                found = true;
                break;
            }
        }
        if found {
            break;
        }
    }

    assert!(found, "draw_text did not modify any pixels in glyph box");
}

#[test]
#[cfg(feature = "bench")]
fn draw_text_sfence_batching() {
    let width = 200u32;
    let height = 200u32;
    let mut info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 4,
        format: PixelFormat::Bgra8888,
        bpp: 32,
    };

    let mut front = vec![0u8; info.size() as usize];
    info.address = front.as_mut_ptr() as u64;
    let mut fb = unsafe { Framebuffer::new(info.clone()) };

    fb.bench_reset_sfence_count();
    fb.draw_text(10, 10, "The quick brown fox jumps", Color::WHITE, Color::BLACK);
    let batched = fb.bench_get_sfence_count();

    fb.bench_reset_sfence_count();
    fb.bench_draw_text_per_glyph_fenced(10, 10, "The quick brown fox jumps", Color::WHITE, Color::BLACK);
    let per_glyph = fb.bench_get_sfence_count();

    // Expect at least as many fences in per-glyph version as batched
    assert!(per_glyph >= batched, "expected per-glyph fenced >= batched ({} >= {})", per_glyph, batched);
    // Expect batching to result in fewer fences than per-glyph in typical case
    assert!(batched < per_glyph, "expected batching to reduce sfence calls ({} < {})", batched, per_glyph);
}
