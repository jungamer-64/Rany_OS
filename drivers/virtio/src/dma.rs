// ============================================================================
// drivers/virtio/src/dma.rs - Device-scoped DMA helpers
// ============================================================================

use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::dma::{CpuOwned, DmaSlice};
use kernel_api::service::kernel;

pub type VirtioDmaBuffer = DmaSlice<CpuOwned>;

#[inline]
pub fn alloc_dma_buffer(size: usize, device_id: PackedPciLocation) -> Option<VirtioDmaBuffer> {
    if device_id == PackedPciLocation::NULL {
        return None;
    }

    kernel::instance().alloc_dma_for_device(size, device_id).ok()
}
