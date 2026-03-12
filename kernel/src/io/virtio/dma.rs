use crate::io::dma::{CoherentDmaBuffer, DmaMemoryAttributes};
use crate::io::iommu::types::DeviceId as IommuDeviceId;

/// Shared helper to allocate a VirtIO DMA buffer, optionally mapping it via IOMMU
pub fn alloc_virtio_dma_buffer(
    size: usize,
    attrs: DmaMemoryAttributes,
    iommu_device_id: &IommuDeviceId,
) -> Option<CoherentDmaBuffer> {
    CoherentDmaBuffer::new_for_device(size, attrs, iommu_device_id)
}
