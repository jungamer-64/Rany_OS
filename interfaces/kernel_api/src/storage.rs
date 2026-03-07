// ============================================================================
// kernel_api/src/storage.rs - Storage provider traits and discovery helpers
// ============================================================================

extern crate alloc;

use crate::service::kernel;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageTransport {
    Nvme,
    Ahci,
    VirtioBlock,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageDeviceInfo {
    pub device_id: u64,
    pub namespace_id: u32,
    pub block_size: u32,
    pub max_transfer_blocks: u32,
    pub transport: StorageTransport,
    pub flags: u32,
}

pub trait StorageServices: Send + Sync {
    fn devices(&self) -> Vec<StorageDeviceInfo>;

    fn lookup(&self, device_id: u64) -> Option<StorageDeviceInfo> {
        self.devices()
            .into_iter()
            .find(|device| device.device_id == device_id)
    }
}

#[inline]
pub fn try_instance() -> Option<&'static dyn StorageServices> {
    if !kernel::is_installed() {
        return None;
    }

    kernel::instance().storage()
}

#[inline]
pub fn instance() -> &'static dyn StorageServices {
    try_instance().expect("StorageServices not installed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_instance_is_none_before_kernel_install() {
        assert!(try_instance().is_none());
    }
}
