// ============================================================================
// kernel/src/io/iommu/common/domain/identity_mapping.rs
// ============================================================================

use super::*;

impl IommuDomain {
    /// Map a region with identity mapping (IOVA = Physical Address)
    ///
    /// # Security Warning
    ///
    /// Identity mapping bypasses IOMMU protection and should only be used
    /// for RMRR (Reserved Memory Region Reporting) regions or early boot.
    ///
    /// This function is only available when `debug_assertions` are enabled
    /// (debug builds).
    ///
    /// In production builds, use `map()` with explicit IOVA allocation instead.
    #[cfg(debug_assertions)]
    pub fn map_identity(
        &self,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        log::warn!(
            "[IOMMU][SECURITY] Identity mapping {:#x}+{:#x} - bypassing protection!",
            phys,
            size
        );
        self.map(phys, phys, size, read, write)
    }

    /// Map a region with identity mapping - DISABLED in production builds.
    ///
    /// This stub exists to provide a clear compile-time error when identity
    /// mapping is attempted in production builds without the bypass feature.
    #[cfg(not(debug_assertions))]
    #[allow(unused_variables)]
    pub fn map_identity(
        &self,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        log::error!("[IOMMU][SECURITY] Identity mapping rejected in non-debug build");
        Err(IommuError::NotSupported)
    }
}
