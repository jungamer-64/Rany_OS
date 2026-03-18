// ============================================================================
// kernel_api/src/audio.rs - Audio provider traits
// ============================================================================

extern crate alloc;

use crate::service::kernel;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioDeviceInfo {
    pub device_id: u64,
    pub output_channels: u16,
    pub input_channels: u16,
    pub sample_rate_hz: u32,
    pub flags: u32,
}

pub trait AudioServices: Send + Sync {
    fn devices(&self) -> Vec<AudioDeviceInfo>;
}

#[inline]
pub fn try_instance() -> Option<&'static dyn AudioServices> {
    let _ = kernel::is_installed();
    None
}

#[inline]
pub fn instance() -> &'static dyn AudioServices {
    try_instance().expect("AudioServices not installed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_instance_is_none_before_kernel_install() {
        assert!(try_instance().is_none());
    }
}
