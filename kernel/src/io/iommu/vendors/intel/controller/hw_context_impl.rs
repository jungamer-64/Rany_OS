// ============================================================================
// kernel/src/io/iommu/vendors/intel/controller/hw_context_impl.rs
// ============================================================================

use super::*;

impl IommuHardwareContext for IommuController {
    fn allocate_iova_aligned(&self, size: u64, alignment: u64) -> Result<u64, IommuError> {
        // Fast path for 4KB-aligned allocations
        if alignment <= crate::mm::types::PAGE_SIZE_4K as u64 {
            if size == crate::mm::types::PAGE_SIZE_4K as u64 {
                return IovaManager::allocate_iova_fast(self, size);
            }
            return IovaManager::allocate_iova(self, size);
        }

        // Map alignment to granularity
        let granularity = if alignment >= 1024 * 1024 * 1024 {
            crate::io::iommu::common::dma::iova_allocator::PageGranularity::Page1G
        } else if alignment >= 2 * 1024 * 1024 {
            crate::io::iommu::common::dma::iova_allocator::PageGranularity::Page2M
        } else {
            crate::io::iommu::common::dma::iova_allocator::PageGranularity::Page4K
        };

        IovaManager::allocate_iova_aligned(self, size, granularity)
    }

    fn allocate_iova_masked(
        &self,
        size: u64,
        alignment: u64,
        mask: u64,
    ) -> Result<u64, IommuError> {
        // For masked allocation, alignment is handled via granularity
        let _ = alignment; // TODO: Support combined alignment + mask constraints
        IovaManager::allocate_iova_masked(self, size, mask)
    }

    fn free_iova(&self, iova: u64, size: u64) -> Result<(), IommuError> {
        if size == crate::mm::types::PAGE_SIZE_4K as u64 {
            IovaManager::free_iova_fast(self, iova, size)
        } else {
            IovaManager::free_iova(self, iova, size)
        }
    }

    fn free_iova_immediate(&self, iova: u64, size: u64) -> Result<(), IommuError> {
        // Bypass quarantine for already-flushed IOVAs
        let guard = self
            .iova_allocator
            .lock()
            .map_err(|_| IommuError::HardwareError)?;
        let alloc = guard.as_ref().ok_or(IommuError::NotPresent)?;
        alloc.free_immediate(iova, size)
    }
}

// ============================================================================
// Invalidation Waiter Future
// ============================================================================

pub struct InvalidationWaiter<'a> {
    pub(crate) controller: &'a IommuController,
    pub(crate) submit_result: Result<(), IommuError>,
    pub(crate) status_virt: usize,
    pub(crate) expected_data: u32,
}

impl<'a> Future for InvalidationWaiter<'a> {
    type Output = Result<(), IommuError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.submit_result {
            Err(e) => return Poll::Ready(Err(e)),
            Ok(()) => {
                // Security: Check for hardware faults during poll.
                let fsts = self
                    .controller
                    .read32(crate::io::iommu::vendors::intel::registers::regs::FSTS);
                if (fsts
                    & (crate::io::iommu::vendors::intel::registers::fsts_bits::FSTS_IQE
                        | crate::io::iommu::vendors::intel::registers::fsts_bits::FSTS_ICE
                        | crate::io::iommu::vendors::intel::registers::fsts_bits::FSTS_ITE))
                    != 0
                {
                    log::error!(
                        "[IOMMU][QI] Async wait failed: hardware fault detected in FSTS: {:#x}",
                        fsts
                    );
                    return Poll::Ready(Err(IommuError::HardwareError));
                }

                let status = unsafe { core::ptr::read_volatile(self.status_virt as *const u32) };
                if status.wrapping_sub(self.expected_data) < (1u32 << 31) {
                    return Poll::Ready(Ok(()));
                }
                self.controller.pending_waiters.register(cx.waker());
                // Double check after registration to avoid lost wakeups
                let status = unsafe { core::ptr::read_volatile(self.status_virt as *const u32) };
                if status.wrapping_sub(self.expected_data) < (1u32 << 31) {
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending
            }
        }
    }
}
