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
    VIRTIO_MMIO_MAGIC,
    // Queue constants
    VIRTQUEUE_DEFAULT_SIZE,
    VIRTQUEUE_MAX_SIZE,
    // Status
    VirtioDeviceStatus,
    // Transport types
    // VirtioTransport is defined in `defs` and re-exported below to avoid duplicate definitions.
    VirtioDeviceType,
    VirtioPciCap,
    // PCI
    VirtioPciCapType,
    // Fixed-size rings
    VringAvail256,
    VringAvailHeader,
    // Descriptor types
    VringDesc,
    VringUsed256,
    VringUsedElem,
    VringUsedHeader,
    avail_flags,
    // Features
    common_features,
    // MMIO
    mmio_regs,
    status,
    used_flags,
    vring_flags,
};
