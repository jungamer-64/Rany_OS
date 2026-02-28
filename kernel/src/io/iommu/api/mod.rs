// ============================================================================
// kernel/src/io/iommu/api/mod.rs
// ============================================================================

//! IOMMU Public API
//!
//! Global API functions for IOMMU initialization, device protection,
//! and interrupt remapping.

pub mod dma;
pub mod dispatcher;
pub mod driver;
pub mod mgmt;
pub mod panic_dma;
pub mod pci;
pub mod security;

// Re-exports from submodules
pub use self::dma::*;
pub use self::dispatcher::*;
pub use self::driver::*;
pub use self::mgmt::*;
pub use self::panic_dma::*;
pub use self::pci::*;
pub use self::security::*;

// Re-exports from other internal modules (for API compatibility)
pub use crate::io::iommu::runtime::irq::{map_interrupt, get_remap_msi_message};
pub use crate::io::iommu::runtime::stats::{
    reset_map_unmap_counts, get_map_count, get_unmap_count,
};
pub use crate::io::iommu::runtime::registry::{
    is_iommu_enabled, 
    register_device_dma_mask, register_device_dma_width, clear_device_dma_mask, get_device_dma_mask
};
pub use crate::io::iommu::common::dma::handle::{
    DmaDirection, DmaHandle, MapError, MapErrorKind, UnmapError, UnmapErrorKind,
};

/// Diagnostics
pub fn dump_iommu_diagnostics() {
    log::info!("=== IOMMU Diagnostics ===");
    log::info!("Global map count: {}", crate::io::iommu::runtime::stats::get_map_count());
    log::info!("Global unmap count: {}", crate::io::iommu::runtime::stats::get_unmap_count());

    if let Some(driver) = crate::io::iommu::runtime::registry::get_iommu_driver() {
        driver.dump_diagnostics();
    } else {
        log::warn!("IOMMU driver not initialized");
    }
    log::info!("=========================");
}

// ========================================================================
// Internal Raw DMA Mapping Helpers (crate-local)
// ========================================================================

// Raw mapping helpers were deprecated and have been removed in favor of
// the safer DmaHandle APIs (e.g., `DmaHandle::map_rref`, `DmaHandle::new`).
// Keep the public `api` wrappers (`map_for_dma`, `map_for_device`, etc.) that
// forward to the DMA backend; callers should migrate to the DmaHandle type.
