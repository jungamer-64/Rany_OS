//! The split queue owns RAM, descriptors and accepted command metadata together.

mod queue;
pub use queue::*;

pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
pub const VIRTIO_F_IOMMU_PLATFORM: u64 = 1 << 33;

pub mod features {
    pub use super::{VIRTIO_F_IOMMU_PLATFORM, VIRTIO_F_VERSION_1};
    pub const VIRTIO_F_RING_PACKED: u64 = 1 << 34;
}
