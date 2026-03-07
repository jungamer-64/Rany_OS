// ============================================================================
// kernel_api/src/graphics.rs - Graphics provider traits
// ============================================================================

extern crate alloc;

use crate::service::{
    gui::{FramebufferInfo, PixelFormat},
    kernel,
};
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayInfo {
    pub display_id: u64,
    pub width: usize,
    pub height: usize,
    pub format: PixelFormat,
    pub flags: u32,
}

pub trait GraphicsServices: Send + Sync {
    fn displays(&self) -> Vec<DisplayInfo>;
    fn primary_framebuffer(&self) -> Option<FramebufferInfo>;
}

#[inline]
pub fn try_instance() -> Option<&'static dyn GraphicsServices> {
    if !kernel::is_installed() {
        return None;
    }

    kernel::instance().graphics()
}

#[inline]
pub fn instance() -> &'static dyn GraphicsServices {
    try_instance().expect("GraphicsServices not installed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_instance_is_none_before_kernel_install() {
        assert!(try_instance().is_none());
    }
}
