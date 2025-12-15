// ============================================================================
// drivers/virtio/src/lib.rs - VirtIO Driver
// ============================================================================
//!
//! # VirtIO Driver
//!
//! VirtIO device support (block, network, etc.)
//!
//! ## Architecture
//! - Common VirtQueue definitions
//! - Transport abstraction (PCI/MMIO)
//! - Device-specific drivers
//!
//! Note: Some implementations remain in kernel due to deep dependencies.
//! This crate provides type definitions and core abstractions.

#![no_std]
#![allow(dead_code)]

extern crate alloc;

pub mod core;
pub mod defs;
pub mod transport;

// Re-export core types
pub use crate::core::*;

// Re-export transport types
pub use transport::{
    TransportError, TransportResult, TransportType, VirtioDeviceInit, VirtioMmioTransport,
    VirtioPciTransport, VirtioTransport,
};

// Re-export commonly used types from defs
pub use defs::{
    // Status
    VirtioDeviceStatus,
    status,
    // Queue constants
    VIRTQUEUE_DEFAULT_SIZE,
    VIRTQUEUE_MAX_SIZE,
    // Descriptor types
    VringDesc,
    VringAvailHeader,
    VringUsedElem,
    VringUsedHeader,
    vring_flags,
    avail_flags,
    used_flags,
    // Fixed-size rings
    VringAvail256,
    VringUsed256,
    // Transport types
    // VirtioTransport is defined in `defs` and re-exported below to avoid duplicate definitions.
    VirtioDeviceType,
    // MMIO
    mmio_regs,
    VIRTIO_MMIO_MAGIC,
    // PCI
    VirtioPciCapType,
    VirtioPciCap,
    // Features
    common_features,
};
