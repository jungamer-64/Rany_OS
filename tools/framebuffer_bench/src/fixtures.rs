use rany_os::graphics::framebuffer::{Framebuffer, FramebufferLayout, PixelBuffer};
use rany_os::hal::scanout::ScanoutBuffer;
use std::sync::Arc;

pub(crate) fn ram_framebuffer(layout: FramebufferLayout) -> Framebuffer {
    Framebuffer::new(layout, PixelBuffer::Memory(vec![0; layout.size()]))
        .expect("benchmark framebuffer workspace")
}

/// Host allocation exercising the scanout store algorithm. This measures CPU
/// stores to host RAM; it does not measure a GPU aperture or WC memory bandwidth.
pub(crate) fn scanout_storage(length: usize) -> ScanoutBuffer {
    let mut storage = vec![0u8; length];
    let address = storage.as_mut_ptr().expose_provenance();
    let owner = Arc::new(storage);
    // SAFETY: the moved allocation stays initialized and writable through owner.
    // No other reference or pointer is retained or used to access its bytes.
    unsafe { ScanoutBuffer::from_raw_parts(owner, address, length) }
        .expect("owned benchmark allocation")
}

pub(crate) fn scanout_framebuffer(layout: FramebufferLayout) -> Framebuffer {
    Framebuffer::new(layout, PixelBuffer::Scanout(scanout_storage(layout.size())))
        .expect("benchmark framebuffer workspace")
}
