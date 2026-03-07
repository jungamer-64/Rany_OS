// ============================================================================
// kernel_api/src/netdev.rs - Network device provider traits
// ============================================================================

extern crate alloc;

use crate::service::kernel;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MacAddress(pub [u8; 6]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetDeviceInfo {
    pub device_id: u64,
    pub mtu: u32,
    pub mac: MacAddress,
    pub flags: u32,
}

pub trait NetDeviceServices: Send + Sync {
    fn devices(&self) -> Vec<NetDeviceInfo>;

    fn primary_device(&self) -> Option<NetDeviceInfo> {
        self.devices().into_iter().next()
    }
}

#[inline]
pub fn try_instance() -> Option<&'static dyn NetDeviceServices> {
    if !kernel::is_installed() {
        return None;
    }

    kernel::instance().netdev()
}

#[inline]
pub fn instance() -> &'static dyn NetDeviceServices {
    try_instance().expect("NetDeviceServices not installed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_instance_is_none_before_kernel_install() {
        assert!(try_instance().is_none());
    }
}
