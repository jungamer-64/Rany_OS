// ============================================================================
// drivers/virtio/src/core/mod.rs - VirtIO Core Components
// ============================================================================

pub mod virtqueue;

pub use virtqueue::{VIRTIO_F_IOMMU_PLATFORM, VIRTIO_F_VERSION_1, VirtQueue};

/// Standard feature bits that may be used across multiple devices
pub mod features {
    pub use super::virtqueue::{VIRTIO_F_IOMMU_PLATFORM, VIRTIO_F_VERSION_1};
    pub const VIRTIO_F_RING_PACKED: u64 = 1 << 34;
}
