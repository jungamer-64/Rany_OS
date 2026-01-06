// ============================================================================
// kernel/src/io/iommu/api/mod.rs
// ============================================================================
//! IOMMU Public API
//!
//! Global API functions for IOMMU initialization, device protection,
//! and interrupt remapping.

pub mod dma;
pub mod mgmt;

// Re-exports from submodules
pub use self::dma::*;
pub use self::mgmt::*;

// Re-exports from other internal modules (for API compatibility)
pub use super::irq::{map_interrupt, get_remap_msi_message};
pub use super::stats::{
    reset_map_unmap_counts, get_map_count, get_unmap_count,
};
pub use super::security::{
    FaultSummary, IsolationDecision, IsolationReason, SecurityEvent, SecurityNotifier,
    set_security_notifier, 
    // set_unsafe_identity_mapping_allowed,
    is_unsafe_identity_mapping_allowed,
    set_global_dma_mapping_allowed, is_global_dma_mapping_allowed,
};
pub use super::registry::{
    is_iommu_enabled, 
    register_device_dma_mask, register_device_dma_width, clear_device_dma_mask, get_device_dma_mask
};
pub use super::dma_handle::{
    DmaDirection, DmaHandle, MapError, MapErrorKind, UnmapError, UnmapErrorKind,
};

/// Diagnostics
pub fn dump_iommu_diagnostics() {
    log::info!("=== IOMMU Diagnostics ===");
    log::info!("Global map count: {}", super::stats::get_map_count());
    log::info!("Global unmap count: {}", super::stats::get_unmap_count());

    if let Some(driver) = super::registry::get_iommu_driver() {
        driver.dump_diagnostics();
    } else {
        log::warn!("IOMMU driver not initialized");
    }
    log::info!("=========================");
}

// ========================================================================
// Internal Raw DMA Mapping Helpers (crate-local)
// ========================================================================

/// Raw DMA mapping helpers for kernel-internal use only.
///
/// # Warning
///
/// **Do not use these functions directly in device drivers.**
/// Prefer safe APIs:
/// - `DmaHandle<T>::map_rref()` for type-safe DMA mapping
/// - `DmaHandle<T>::new()` for pre-allocated buffers
///
/// These raw functions exist only for:
/// - Legacy kernel components during migration
/// - Boot-time initialization before full IOMMU setup
/// - Panic/error paths where allocation may fail
pub(crate) mod raw {
    use crate::io::iommu::types::{DeviceId, IommuError};
    use x86_64::PhysAddr;

    /// Raw DMA mapping for caller-owned memory.
    ///
    /// # Safety
    /// Caller must guarantee ownership and DMA safety for the mapping duration.
    ///
    /// # Deprecation Notice
    /// Prefer `DmaHandle::map_rref()` for new code.
    #[deprecated(
        since = "0.4.0",
        note = "Use DmaHandle::map_rref() for type-safe DMA mapping"
    )]
    pub unsafe fn map_for_dma(phys_addr: PhysAddr, size: u64) -> Result<u64, IommuError> {
        unsafe { super::dma::map_for_dma(phys_addr, size) }
    }

    /// Raw DMA mapping for device-scoped domains.
    ///
    /// # Safety
    /// Caller must guarantee ownership and DMA safety for the mapping duration.
    ///
    /// # Deprecation Notice
    /// Prefer `DmaHandle::new()` with device context for new code.
    #[deprecated(
        since = "0.4.0",
        note = "Use DmaHandle::new() with device context"
    )]
    pub unsafe fn map_for_device(
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
    ) -> Result<u64, IommuError> {
        unsafe { super::dma::map_for_device(device, phys_addr, size) }
    }

    /// Async raw DMA mapping for device-scoped domains.
    ///
    /// # Safety
    /// Caller must guarantee ownership and DMA safety for the mapping duration.
    ///
    /// # Deprecation Notice
    /// Prefer async variants of DmaHandle for new code.
    #[deprecated(
        since = "0.4.0",
        note = "Use async DmaHandle methods"
    )]
    pub async unsafe fn map_for_device_async(
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
    ) -> Result<u64, IommuError> {
        unsafe { super::dma::map_for_device_async(device, phys_addr, size).await }
    }
}
