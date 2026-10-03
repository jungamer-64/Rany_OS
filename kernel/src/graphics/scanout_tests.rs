use super::{
    Color, PixelFormat, Rect,
    framebuffer::{Framebuffer, FramebufferLayout, PixelBuffer},
};
use alloc::{sync::Arc, vec};
use hal::scanout::ScanoutBuffer;

/// A private fixture retains initialized RAM without any competing byte view.
/// Device admission itself remains the boot/resource registry's responsibility.
fn plane(length: usize) -> (ScanoutBuffer, alloc::sync::Weak<alloc::vec::Vec<u8>>) {
    let mut bytes = vec![0xCCu8; length];
    let address = bytes.as_mut_ptr().expose_provenance();
    let owner = Arc::new(bytes);
    let observer = Arc::downgrade(&owner);
    // SAFETY: moving the only owner into the mapping retains this initialized,
    // writable allocation. No Rust reference, pointer, or device aliases the bytes.
    let mapping =
        unsafe { ScanoutBuffer::from_raw_parts(owner, address, length) }.expect("owned fixture");
    (mapping, observer)
}

#[test]
fn retained_scanout_renders_and_copies_in_every_destination_format() {
    for format in [
        PixelFormat::Bgra8888,
        PixelFormat::Rgba8888,
        PixelFormat::Bgr888,
        PixelFormat::Rgb888,
        PixelFormat::Rgb565,
    ] {
        let bpp = format.bytes_per_pixel();
        let stride = 8 * bpp + 3;
        let layout = FramebufferLayout::new(8, 16, stride as u32, format).unwrap();
        let (storage, owner) = plane(layout.size());
        let mut fb = Framebuffer::new(layout, PixelBuffer::Scanout(storage)).unwrap();
        fb.fill_rect(Rect::new(0, 0, 8, 16), Color::BLACK);
        fb.draw_text(0, 0, "!", Color::RED, Color::BLUE);
        let reference: alloc::vec::Vec<_> = (0..8).map(|x| fb.get_pixel(x, 2)).collect();
        fb.copy_rect(Rect::new(0, 2, 7, 1), 1, 2);
        for x in 1..8 {
            assert_eq!(fb.get_pixel(x, 2), reference[x as usize - 1]);
        }
        assert!(owner.upgrade().is_some());
        let PixelBuffer::Scanout(storage) = fb.into_pixels() else {
            panic!("scanout transfer");
        };
        let mut bytes = vec![0; layout.size()];
        storage.read(0, &mut bytes).unwrap();
        for row in bytes.chunks_exact(stride) {
            assert_eq!(&row[8 * bpp..], &[0xCC; 3]);
        }
        drop(storage);
        assert!(owner.upgrade().is_none());
    }
}

#[test]
fn rejected_renderer_admission_releases_the_unpublished_mapping_owner() {
    let layout = FramebufferLayout::new(8, 16, 32, PixelFormat::Bgra8888).unwrap();
    let (storage, owner) = plane(layout.size() - 1);
    assert!(matches!(
        Framebuffer::new(layout, PixelBuffer::Scanout(storage)),
        Err(super::framebuffer::FramebufferError::BufferTooSmall)
    ));
    assert!(owner.upgrade().is_none());
}

#[test]
fn synchronous_gui_batches_borrow_only_the_requested_write_span() {
    let layout = FramebufferLayout::new(8, 2, 32, PixelFormat::Bgra8888).unwrap();
    let (storage, owner) = plane(layout.size());
    let mut fb = Framebuffer::new(layout, PixelBuffer::Scanout(storage)).unwrap();
    {
        let mut batch = fb.scanout_region().expect("retained scanout");
        batch
            .subregion_mut(4, 4)
            .unwrap()
            .write_bytes(&[1, 2, 3, 4])
            .unwrap();
        assert!(batch.subregion_mut(usize::MAX, 1).is_err());
    }
    let PixelBuffer::Scanout(storage) = fb.into_pixels() else {
        panic!("scanout transfer");
    };
    let mut bytes = vec![0; layout.size()];
    storage.read(0, &mut bytes).unwrap();
    assert_eq!(&bytes[..4], &[0xCC; 4]);
    assert_eq!(&bytes[4..8], &[1, 2, 3, 4]);
    assert!(bytes[8..].iter().all(|&byte| byte == 0xCC));
    drop(storage);
    assert!(owner.upgrade().is_none());
}
