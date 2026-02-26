use crate::io::dma::{CoherentDmaBuffer, DmaMemoryAttributes};
use crate::io::iommu::types::DeviceId as IommuDeviceId;

/// Shared helper to allocate a VirtIO DMA buffer, optionally mapping it via IOMMU
pub fn alloc_virtio_dma_buffer(
    size: usize,
    attrs: DmaMemoryAttributes,
    iommu_device_id: Option<&IommuDeviceId>,
) -> Option<CoherentDmaBuffer> {
    match iommu_device_id {
        Some(dev_id) => CoherentDmaBuffer::new_for_device(size, attrs, dev_id),
        None => CoherentDmaBuffer::new(size, attrs),
    }
}
