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
pub mod types {
    pub use super::core::types::*;
}

// Public re-exports
pub use self::backend::IommuBackend;
pub use self::types::{DeviceId, IommuError};

// Layered module namespaces
pub(crate) mod backends;
pub(crate) mod core;
pub(crate) mod runtime;
pub(crate) mod tests;

// Root module aliases (preserve intra-subsystem imports while files live in layered dirs)
#[path = "runtime/backend.rs"]
pub(crate) mod backend;
#[path = "runtime/command/queue.rs"]
pub(crate) mod cmdqueue;
#[path = "core/dma/handle.rs"]
pub(crate) mod dma_handle;
#[path = "runtime/irq.rs"]
pub(crate) mod irq;
#[path = "runtime/stats.rs"]
pub(crate) mod stats;

#[path = "core/dma/cache.rs"]
pub(crate) mod cache;
#[path = "runtime/config.rs"]
pub(crate) mod config;
#[path = "core/domain/mod.rs"]
pub(crate) mod domain;
#[path = "runtime/fault_log.rs"]
pub(crate) mod fault_log;
#[path = "core/dma/flush.rs"]
pub(crate) mod flush;
#[path = "runtime/groups.rs"]
pub(crate) mod groups;
#[path = "core/interface.rs"]
pub(crate) mod interface;

pub(crate) use crate::mm::types::PAGE_SIZE_4K;

#[path = "core/dma/iova_allocator.rs"]
pub(crate) mod iova_allocator;
pub(crate) use iova_allocator::{IovaAllocator as IovaAllocatorFast, IovaGranularity};
#[path = "core/dma/mapping_slab.rs"]
pub(crate) mod mapping_slab;
#[path = "runtime/zombie/mod.rs"]
pub(crate) mod zombie_queue;
#[path = "core/dma/page_table_pool.rs"]
pub(crate) mod page_table_pool;
#[path = "runtime/panic.rs"]
pub(crate) mod panic;
#[path = "runtime/quarantine/mod.rs"]
pub(crate) mod quarantine;
#[path = "runtime/registry.rs"]
pub(crate) mod registry;
#[path = "runtime/security/mod.rs"]
pub(crate) mod security;
#[path = "core/tables.rs"]
pub(crate) mod tables;

#[path = "backends/amd/mod.rs"]
pub(crate) mod amd;
#[path = "backends/intel/mod.rs"]
pub(crate) mod intel;
#[path = "backends/common/mod.rs"]
pub(crate) mod common;

#[cfg(not(test))]
#[path = "runtime/pci.rs"]
pub(crate) mod pci;

#[cfg(feature = "qemu-test-export")]
pub(crate) mod qemu_tests {
    pub use super::tests::qemu::*;
}

// ============================================================================
// Configuration
// ============================================================================

/// IOMMU Check Required
pub(crate) static IOMMU_REQUIRED: AtomicBool = AtomicBool::new(false);

// End of file
