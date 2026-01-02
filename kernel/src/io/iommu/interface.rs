// ============================================================================
// kernel/src/io/iommu/interface.rs
// ============================================================================
//! IOMMU backend interfaces (hardware context/domain).

use super::types::{DmaMapping, IommuDomainType, IommuError};

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
