// ============================================================================
// kernel_api/src/input.rs - Input provider traits
// ============================================================================

extern crate alloc;

use crate::service::{gui::InputEvent, kernel};
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputDeviceKind {
    Keyboard,
    Mouse,
    Touch,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputDeviceInfo {
    pub device_id: u64,
    pub kind: InputDeviceKind,
    pub flags: u32,
}

pub trait InputServices: Send + Sync {
    fn devices(&self) -> Vec<InputDeviceInfo>;
    fn poll_event(&self) -> Option<InputEvent>;
}

#[inline]
pub fn try_instance() -> Option<&'static dyn InputServices> {
    if !kernel::is_installed() {
        return None;
    }

    kernel::instance().input()
}

#[inline]
pub fn instance() -> &'static dyn InputServices {
    try_instance().expect("InputServices not installed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_instance_is_none_before_kernel_install() {
        assert!(try_instance().is_none());
    }
}
