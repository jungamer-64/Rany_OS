// ============================================================================
// kernel/src/io/iommu/vendors/intel/controller/iova.rs
// ============================================================================

//! IOVA (I/O Virtual Address) Management Methods
//!
use super::IommuController;
use crate::io::iommu::common::dma::iova_allocator::IovaAllocator;
use crate::io::iommu::types::IommuError;
use alloc::sync::Arc;

impl IommuController {
    /// Initialize the controller's address space once; never replace a live bitmap.
    ///
    /// # Errors
    /// AlreadyInitialized retains the existing allocator and all outstanding flush owners.
    pub(in crate::io::iommu) fn init_iova(&self, base: u64, size: u64) -> Result<(), IommuError> {
        let mut guard = self
            .iova_allocator
            .lock_for_init("[IOMMU] iova_allocator init");
        if guard.is_some() {
            return Err(IommuError::AlreadyInitialized);
        }
        *guard = Some(Arc::new(IovaAllocator::new(base, size)?));
        Ok(())
    }
}
