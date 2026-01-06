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

// Re-export specific modules used by api but also useful directly
pub mod irq; 
pub mod stats;

pub use self::backend::IommuBackend;
pub use self::types::{DeviceId, IommuError};

// Benchmark exports (only available with "bench" feature)
#[cfg(feature = "bench")]
// pub use iova_bitmap::{IovaBitmap, IovaBitmapV2, IovaAllocatorSimple};

// Internal modules (crate-visible)
pub(crate) mod cache;
pub(crate) mod common;
pub(crate) mod config;
pub(crate) mod domain;
pub(crate) mod fault_log;
pub(crate) mod flush;
pub(crate) mod groups;
pub(crate) mod interface;

// pub(crate) mod iova_bitmap; // Keep module implementation for now (contains constants)
// pub(crate) use iova_bitmap::PAGE_SIZE_4K;
pub(crate) use crate::mm::PAGE_SIZE_4K;

pub(crate) mod iova_allocator; // New FastBitmapAllocator-based IOVA allocator (Phase 4)
pub(crate) use iova_allocator::{IovaAllocator as IovaAllocatorFast, IovaGranularity};
pub(crate) mod mapping_slab;
pub(crate) mod zombie_queue;  // Lock-free zombie DMA handle queue
pub(crate) mod page_table_pool;
pub(crate) mod panic;
pub(crate) mod quarantine;
pub(crate) mod registry;
pub(crate) mod security;
pub(crate) mod tables;

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
