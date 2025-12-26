// ============================================================================
// kernel/src/io/iommu/mod.rs
// ============================================================================
//!
//! IOMMU Support (Intel VT-d / AMD-Vi)
//!

#![allow(dead_code)]

use core::sync::atomic::AtomicBool;

// Generic modules
pub mod tables;
pub use self::tables::*;

pub mod interface;
pub use self::interface::IommuDriver;

pub mod types;
pub use self::types::*;

pub mod domain;
pub use self::domain::*;

pub mod iova_allocator;
pub use self::iova_allocator::*;

pub mod fault_log;
pub use self::fault_log::*;

pub mod groups;
pub use self::groups::*;

pub mod dma_handle;
pub use self::dma_handle::*;

pub mod quarantine;
pub use self::quarantine::*;

pub mod page_table_pool;
pub use self::page_table_pool::{PageTablePool, PoolStats, PooledPt};

pub mod security;
pub use self::security::*;

pub mod api;
pub use self::api::*;

pub mod registry;
pub use self::registry::{
    get_iommu_driver, get_iommu_registry, init_driver, init_registry, is_iommu_enabled,
    IommuRegistry,
};

#[cfg(not(test))]
pub mod pci;
#[cfg(not(test))]
pub use self::pci::{setup_iommu_for_all_pci_devices, setup_iommu_for_pci_device};

// Architectures
pub mod amd;
pub mod intel;
pub use self::intel::controller;
pub use self::controller::IommuController;

// Mixed / To Be Refactored Modules (Currently Generic but contain Intel specifics)
// These should eventually move to intel/
pub mod qi;
pub use self::qi::*;

pub mod pasid;

pub mod registers;
pub use self::registers::*;

pub mod ats;
pub use self::ats::*;

pub mod cache;
pub use self::cache::*;

pub mod config;
pub use self::config::*;

// ============================================================================
// Configuration
// ============================================================================

/// IOMMU Check Required
pub static IOMMU_REQUIRED: AtomicBool = AtomicBool::new(false);

// End of file
