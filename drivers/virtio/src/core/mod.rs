// ============================================================================
// drivers/virtio/src/core/mod.rs - VirtIO Core Components
// ============================================================================

pub mod virtqueue;

pub use virtqueue::{VirtQueue, VIRTIO_F_VERSION_1, VIRTIO_F_IOMMU_PLATFORM};

/// Standard feature bits that may be used across multiple devices
pub mod features {
    pub use super::virtqueue::{VIRTIO_F_VERSION_1, VIRTIO_F_IOMMU_PLATFORM};
    pub const VIRTIO_F_RING_PACKED: u64 = 1 << 34;
}
