// ============================================================================
// kernel/src/io/iommu/core/interface.rs
// ============================================================================

//! IOMMU backend interfaces (hardware context/domain).

use crate::io::iommu::core::types::{DmaMapping, IommuDomainType, IommuError};

/// Default IOVA allocation alignment (4KB).
pub const DEFAULT_IOVA_ALIGNMENT: u64 = 4096;

/// IOMMU hardware context abstraction.
///
/// Domain logic uses this interface to allocate/free IOVA space without
/// depending on a concrete controller implementation.
pub trait IommuHardwareContext: Send + Sync {
    /// Allocate an IOVA range of the requested size with default alignment (4KB).
    ///
    /// This is a convenience method that calls `allocate_iova_aligned` with
    /// the default alignment.
    fn allocate_iova(&self, size: u64) -> Result<u64, IommuError> {
        self.allocate_iova_aligned(size, DEFAULT_IOVA_ALIGNMENT)
    }

    /// Allocate an IOVA range with specific alignment.
    ///
    /// # Arguments
    /// * `size` - Size of the IOVA range to allocate (in bytes)
    /// * `alignment` - Required alignment (must be a power of 2, e.g., 4KB, 2MB, 1GB)
    ///
    /// # Returns
    /// * `Ok(iova)` - The allocated IOVA start address (aligned to `alignment`)
    /// * `Err(IommuError)` - Allocation failure
    ///
    /// # Use Cases
    /// - `4KB` alignment: Standard page mappings
    /// - `2MB` alignment: Large page mappings for better TLB efficiency
    /// - `1GB` alignment: Huge page mappings for very large buffers
    fn allocate_iova_aligned(&self, size: u64, alignment: u64) -> Result<u64, IommuError>;

    /// Allocate an IOVA range within a DMA address mask limit.
    ///
    /// # Arguments
    /// * `size` - Size of the IOVA range to allocate
    /// * `alignment` - Required alignment (power of 2)
    /// * `mask` - Inclusive DMA mask (e.g., `0xFFFF_FFFF` for 32-bit devices)
    ///
    /// # Returns
    /// An IOVA that satisfies: `iova + size <= mask + 1`
    fn allocate_iova_masked(
        &self,
        size: u64,
        alignment: u64,
        mask: u64,
    ) -> Result<u64, IommuError>;

    /// Free a previously allocated IOVA range.
    fn free_iova(&self, iova: u64, size: u64) -> Result<(), IommuError>;

    /// Free a previously allocated IOVA range immediately, bypassing software quarantine.
    ///
    /// # Safety
    /// The caller MUST ensure that all IOTLB entries for this IOVA range have been
    /// flushed from all relevant hardware units (IOMMUs and Device-TLBs) before
    /// calling this method.
    fn free_iova_immediate(&self, iova: u64, size: u64) -> Result<(), IommuError> {
        // Default implementation falls back to normal free (which may quarantine)
        self.free_iova(iova, size)
    }
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
