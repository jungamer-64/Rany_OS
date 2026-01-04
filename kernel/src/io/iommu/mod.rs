// ============================================================================
// kernel/src/io/iommu/mod.rs
// ============================================================================
//!
//! IOMMU Support (Intel VT-d / AMD-Vi)
//!

#![allow(dead_code)]

use core::sync::atomic::AtomicBool;

// Public API surface
pub mod api;
pub mod backend;
pub mod cmdqueue;
pub mod dma_handle;
pub mod types;

pub use self::backend::IommuBackend;
pub use self::types::{DeviceId, IommuError};

// Internal modules (crate-visible)
pub(crate) mod cache;
pub(crate) mod common;
pub(crate) mod config;
pub(crate) mod domain;
pub(crate) mod fault_log;
pub(crate) mod flush;
pub(crate) mod groups;
pub(crate) mod interface;
pub(crate) mod iova_bitmap;  // High-performance bitmap-based IOVA allocator with per-CPU magazine
pub(crate) mod mapping_slab;
pub(crate) mod zombie_queue;  // Lock-free zombie DMA handle queue
pub(crate) mod page_table_pool;
pub(crate) mod panic;
pub(crate) mod quarantine;
pub(crate) mod registry;
pub(crate) mod security;
pub(crate) mod tables;

// Re-export fast allocator types for internal use
pub(crate) use iova_bitmap::{IovaAllocatorFast, IovaGranularity, PAGE_SIZE_4K};

// Architectures (crate-local)
pub(crate) mod amd;
pub(crate) mod intel;

#[cfg(not(test))]
pub(crate) mod pci;

// ============================================================================
// Configuration
// ============================================================================

/// IOMMU Check Required
pub(crate) static IOMMU_REQUIRED: AtomicBool = AtomicBool::new(false);

// End of file
