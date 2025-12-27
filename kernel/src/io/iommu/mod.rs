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
pub mod dma_handle;
pub mod types;

pub use self::interface::IommuDriver;
pub use self::types::{DeviceId, IommuError};

// Internal modules (crate-visible)
pub(crate) mod tables;
pub(crate) mod interface;
pub(crate) mod domain;
pub(crate) mod iova_allocator;
pub(crate) mod fault_log;
pub(crate) mod groups;
pub(crate) mod quarantine;
pub(crate) mod page_table_pool;
pub(crate) mod panic;
pub(crate) mod security;
pub(crate) mod registry;
pub(crate) mod cache;
pub(crate) mod config;
pub(crate) mod common;

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
