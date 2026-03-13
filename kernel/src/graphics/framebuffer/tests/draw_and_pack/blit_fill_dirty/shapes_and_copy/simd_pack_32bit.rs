use super::*;

/// write_opaque_run_32bit: verify SIMD pack_rgba_to_bgra path
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_write_opaque_run_32bit_simd_pack() {
    let width = 64u32;
    let height = 4u32;
    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 4,
        format: PixelFormat::Bgra8888,
        bpp: 32,
    };

    let mut vram = vec![0u8; info.size()];
    let mut info2 = info.clone();
    info2.address = vram.as_mut_ptr() as u64;
    let mut fb = unsafe { Framebuffer::new(info2) };

    // Build a 64-wide RGBA image row
    let img = Image::filled(width, 1, Color::with_alpha(10, 20, 30, 255));
    fb.draw_image(&img, 0, 0);

    // Verify BGRA in VRAM: B=30, G=20, R=10, A=255
    for x in 0..width as usize {
        let off = x * 4;
        assert_eq!(vram[off], 30, "B at x={x}");
        assert_eq!(vram[off + 1], 20, "G at x={x}");
        assert_eq!(vram[off + 2], 10, "R at x={x}");
        assert_eq!(vram[off + 3], 255, "A at x={x}");
    }
}
