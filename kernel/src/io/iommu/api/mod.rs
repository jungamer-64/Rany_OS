// ============================================================================
// kernel/src/io/iommu/api/mod.rs
// ============================================================================

//! IOMMU Public API
//!
//! Global API functions for IOMMU initialization, device protection,
//! and interrupt remapping.

pub mod dispatcher;
pub mod dma;
pub mod driver;
pub mod mgmt;
pub mod panic_dma;
pub mod pci;
pub mod security;

// Re-exports from submodules
pub use self::dispatcher::*;
pub use self::dma::*;
pub use self::driver::*;
pub use self::mgmt::*;
pub use self::panic_dma::*;
pub use self::pci::*;
pub use self::security::*;

// Re-exports from other internal modules (for API compatibility)
pub use crate::io::iommu::common::dma::handle::{
    DmaDirection, DmaHandle, MapError, MapErrorKind, UnmapError, UnmapErrorKind,
};
pub use crate::io::iommu::runtime::irq::{get_remap_msi_message, map_interrupt};
pub use crate::io::iommu::runtime::registry::{
    clear_device_dma_mask, get_device_dma_mask, is_iommu_enabled, register_device_dma_mask,
    register_device_dma_width,
};
pub use crate::io::iommu::runtime::stats::{
    get_identity_fallback_count, get_map_count, get_unmap_count, reset_map_unmap_counts,
};

/// Diagnostics
pub fn dump_iommu_diagnostics() {
    log::info!("=== IOMMU Diagnostics ===");
    log::info!(
        "Global map count: {}",
        crate::io::iommu::runtime::stats::get_map_count()
    );
    log::info!(
        "Global unmap count: {}",
        crate::io::iommu::runtime::stats::get_unmap_count()
    );
    log::info!(
        "Identity fallback count: {}",
        crate::io::iommu::runtime::stats::get_identity_fallback_count()
    );

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

// Raw global DMA mapping helpers were removed in favor of device-scoped
// `DmaHandle` / `DeviceDmaContext` APIs and explicit domain-managed mappings.
