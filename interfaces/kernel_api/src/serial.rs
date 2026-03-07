// ============================================================================
// kernel_api/src/serial.rs - Serial provider traits
// ============================================================================

extern crate alloc;

use crate::{KapiResult, service::kernel};
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialPortInfo {
    pub port_id: u32,
    pub base_port: u16,
    pub irq: u8,
    pub flags: u32,
}

pub trait SerialServices: Send + Sync {
    fn ports(&self) -> Vec<SerialPortInfo>;
    fn write(&self, port_id: u32, bytes: &[u8]) -> KapiResult<usize>;
}

#[inline]
pub fn try_instance() -> Option<&'static dyn SerialServices> {
    if !kernel::is_installed() {
        return None;
    }

    kernel::instance().serial()
}

#[inline]
pub fn instance() -> &'static dyn SerialServices {
    try_instance().expect("SerialServices not installed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_instance_is_none_before_kernel_install() {
        assert!(try_instance().is_none());
    }
}
