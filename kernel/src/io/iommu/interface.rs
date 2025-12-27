// ============================================================================
// kernel/src/io/iommu/interface.rs
// ============================================================================
//! IOMMU backend interfaces (driver/domain).

use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;

use x86_64::PhysAddr;

use super::types::{DeviceId, DmaMapping, IommuDomainType, IommuError};

/// Boxed future for IOMMU backend async operations.
pub type IommuFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// IOMMU driver interface (backend abstraction).
pub trait IommuDriver: Send + Sync {
    /// Whether the backend is initialized and usable.
    fn is_enabled(&self) -> bool;

    /// Enable IOMMU translation (all controllers).
    fn enable(&self) -> Result<(), IommuError>;

    /// Disable IOMMU translation (all controllers).
    fn disable(&self) -> Result<(), IommuError>;

    /// Handle pending fault events (ISR-safe entry point).
    fn handle_fault(&self);

    /// Wake any pending invalidation waiters (ISR-safe entry point).
    fn wake_invalidation_waiters(&self);

    /// Map an interrupt for a device using interrupt remapping.
    fn map_interrupt(
        &self,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        vector: u8,
        dest_id: u32,
        logical: bool,
    ) -> Result<u16, IommuError>;

    /// Generate MSI address/data for a remapped interrupt handle.
    fn get_remap_msi_message(&self, handle: u16) -> (u64, u32);

    /// Map a physical range for DMA (global domain).
    ///
    /// # Safety
    /// Caller must uphold DMA safety invariants for the backing memory.
    /// When translation is enabled, `phys_addr` and `size` must be 4K-aligned.
    unsafe fn map_for_dma(&self, phys_addr: PhysAddr, size: u64) -> Result<u64, IommuError>;

    /// Unmap a DMA range (global domain).
    fn unmap_dma(&self, iova: u64, size: u64) -> Result<(), IommuError>;

    /// Map a physical range for a specific device.
    ///
    /// # Safety
    /// Caller must uphold DMA safety invariants for the backing memory.
    /// When translation is enabled, `phys_addr` and `size` must be 4K-aligned.
    unsafe fn map_for_device(
        &self,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
    ) -> Result<u64, IommuError>;

    /// Async map for a device (CQ-backed when available).
    ///
    /// # Safety
    /// Caller must uphold DMA safety invariants for the backing memory.
    /// When translation is enabled, `phys_addr` and `size` must be 4K-aligned.
    unsafe fn map_for_device_async<'a>(
        &'a self,
        device: &'a DeviceId,
        phys_addr: PhysAddr,
        size: u64,
    ) -> IommuFuture<'a, Result<u64, IommuError>>;

    /// Unmap a device DMA range.
    fn unmap_for_device(&self, device: &DeviceId, iova: u64, size: u64) -> Result<(), IommuError>;

    /// Async unmap for a device (CQ-backed when available).
    fn unmap_for_device_async<'a>(
        &'a self,
        device: &'a DeviceId,
        iova: u64,
        size: u64,
    ) -> IommuFuture<'a, Result<(), IommuError>>;

    /// Create a new DMA domain.
    fn create_domain(
        &self,
        numa_node: Option<usize>,
        domain_type: IommuDomainType,
    ) -> Result<u16, IommuError>;

    /// Attach a device to an existing domain.
    fn attach_device(&self, device: DeviceId, domain_id: u16) -> Result<(), IommuError>;

    /// Detach a device from its domain.
    fn detach_device(&self, device: DeviceId) -> Result<(), IommuError>;

    /// Set NUMA hint for a domain.
    fn set_domain_numa(&self, domain_id: u16, numa_node: Option<usize>) -> Result<(), IommuError>;

    /// Get NUMA hint for a domain.
    fn get_domain_numa(&self, domain_id: u16) -> Result<Option<usize>, IommuError>;

    /// Emit backend diagnostics (best-effort, non-fatal).
    fn dump_diagnostics(&self) {}
}

/// IOMMU hardware context abstraction.
///
/// Domain logic uses this interface to allocate/free IOVA space without
/// depending on a concrete controller implementation.
pub trait IommuHardwareContext: Send + Sync {
    /// Allocate an IOVA range of the requested size.
    fn allocate_iova(&self, size: u64) -> Result<u64, IommuError>;

    /// Free a previously allocated IOVA range.
    fn free_iova(&self, iova: u64, size: u64) -> Result<(), IommuError>;
}

/// IOMMU domain interface (optional higher-level abstraction).
pub trait IommuDomain: Send + Sync {
    fn id(&self) -> Result<u16, IommuError>;
    fn domain_type(&self) -> Result<IommuDomainType, IommuError>;
    fn map(
        &self,
        iova: u64,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError>;
    fn unmap(&self, iova: u64) -> Result<DmaMapping, IommuError>;
    fn mapped_size(&self) -> Result<u64, IommuError>;
}
