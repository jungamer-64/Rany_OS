// ============================================================================
// kernel/src/io/iommu/common/domain/map_ops.rs
// ============================================================================

//! DMA handle mapping helpers
//!
//! Historically the `map_buffer` implementation lived in `unmap_ops.rs`, which
//! led to confusion because that file otherwise contained only unmapping logic.
//!
//! This module isolates the mapping side of the `DmaHandle` integration so that
//! the name of each source file matches its contents.  Unmap-related routines
//! remain in `unmap_ops.rs`.

use super::*;

impl IommuDomain {
    /// Map an RRef for DMA access
    ///
    /// This method:
    /// 1. Gets the physical address from the RRef
    /// 2. Allocates an IOVA from the hardware context
    /// 3. Creates page table mappings
    /// 4. Returns a DmaHandle that tracks ownership
    ///
    /// # Arguments
    /// * `rref` - The RRef to map (consumed)
    /// * `context` - The IOMMU context for IOVA allocation
    /// * `direction` - DMA transfer direction
    ///
    /// # Errors
    /// Returns `MapError<T>` containing the original RRef on failure.
    pub fn map_buffer<T>(
        &self,
        rref: crate::ipc::RRef<T>,
        context: &dyn IommuHardwareContext,
        direction: crate::io::iommu::common::dma::handle::DmaDirection,
    ) -> Result<crate::io::iommu::common::dma::handle::DmaHandle<T>, crate::io::iommu::common::dma::handle::MapError<T>> {
        use crate::io::iommu::common::dma::handle::{DmaHandle, MapError, MapErrorKind, MappingKind};
        use x86_64::VirtAddr;

        // Get physical address from RRef's virtual pointer
        let virt_ptr = &*rref as *const T as u64;
        let virt_addr = VirtAddr::new(virt_ptr);
        let phys_addr = crate::mm::virt::mapping::virt_to_phys(virt_addr);
        let phys = phys_addr.as_u64();

        let size = core::mem::size_of::<T>() as u64;

        // Page-align the size (round up)
        let aligned_size = (size + 4095) & !4095;
        if aligned_size == 0 {
            return Err(MapError::new(rref, MapErrorKind::InvalidAlignment));
        }

        // Allocate IOVA from domain's per-domain allocator (Phase 7)
        // This eliminates lock contention between domains for 100Gbps+ I/O
        let iova = match self.allocate_iova(aligned_size) {
            Ok(addr) => addr,
            Err(e) => return Err(MapError::new(rref, MapErrorKind::IommuError(e))),
        };
        let _ = context; // context kept for API compatibility but not used for IOVA

        // Determine permissions from direction
        let (read, write) = match direction {
            crate::io::iommu::common::dma::handle::DmaDirection::ToDevice => (true, false),
            crate::io::iommu::common::dma::handle::DmaDirection::FromDevice => (false, true),
            crate::io::iommu::common::dma::handle::DmaDirection::Bidirectional => (true, true),
        };

        // Create page table mappings
        if let Err(e) = self.map(iova, phys, aligned_size, read, write) {
            // Mapping failed - free IOVA back to domain allocator and return error with RRef
            let _ = self.free_iova(iova, aligned_size);
            return Err(MapError::new(rref, MapErrorKind::IommuError(e)));
        }

        // Success - create DmaHandle
        Ok(DmaHandle::new(
            rref,
            iova,
            phys,
            size,
            self.id,
            direction,
            MappingKind::Domain,
        ))
    }
}
