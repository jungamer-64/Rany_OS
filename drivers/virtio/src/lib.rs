// ============================================================================
// drivers/virtio/src/lib.rs - VirtIO Driver
// ============================================================================

#![no_std]
#![allow(dead_code)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::type_complexity)]

extern crate alloc;

#[cfg(feature = "standalone")]
kernel_api::register_cell_runtime!();

pub mod balloon;
pub mod blk;
pub mod console;
pub mod core;
pub mod defs;
pub mod input;
pub mod net;
pub mod gpu;
pub mod transport;

// Re-export core types
pub use crate::core::virtqueue::VirtQueue;

// Re-export transport types
pub use transport::{
    TransportError, TransportResult, TransportType, VirtioDeviceInit, VirtioMmioTransport,
    VirtioPciTransport, VirtioTransport,
};

// Re-export commonly used types from defs
pub use defs::{
    avail_flags,
    common_features,
    mmio_regs,
    status,
    used_flags,
    vring_flags,
    VirtioDeviceStatus,
    VirtioDeviceType,
    VirtioPciCap,
    VirtioPciCapType,
    VringAvailHeader,
    VringDesc,
    VringUsedElem,
    VringUsedHeader,
    VIRTIO_F_INDIRECT_DESC,
    VIRTIO_MMIO_MAGIC,
    VIRTQUEUE_DEFAULT_SIZE,
    VIRTQUEUE_MAX_SIZE,
};

pub use crate::core::{VIRTIO_F_VERSION_1, VIRTIO_F_IOMMU_PLATFORM};
