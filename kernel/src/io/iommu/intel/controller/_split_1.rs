use super::*;


impl IommuHardwareContext for IommuController {
    fn allocate_iova_aligned(&self, size: u64, alignment: u64) -> Result<u64, IommuError> {
        // Fast path for 4KB-aligned allocations
        if alignment <= crate::mm::PAGE_SIZE_4K as u64 {
            if size == crate::mm::PAGE_SIZE_4K as u64 {
                return IovaManager::allocate_iova_fast(self, size);
            }
            return IovaManager::allocate_iova(self, size);
        }

        // Map alignment to granularity
        let granularity = if alignment >= 1024 * 1024 * 1024 {
            crate::io::iommu::IovaGranularity::Page1G
        } else if alignment >= 2 * 1024 * 1024 {
            crate::io::iommu::IovaGranularity::Page2M
        } else {
            crate::io::iommu::IovaGranularity::Page4K
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
        if size == crate::mm::PAGE_SIZE_4K as u64 {
            IovaManager::free_iova_fast(self, iova, size)
        } else {
            IovaManager::free_iova(self, iova, size)
        }
    }
}

// ============================================================================
// Invalidation Waiter Future
// ============================================================================

pub struct InvalidationWaiter<'a> {
    controller: &'a IommuController,
    submit_result: Result<u64, IommuError>,
}

impl<'a> Future for InvalidationWaiter<'a> {
    type Output = Result<(), IommuError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.submit_result {
            Err(e) => return Poll::Ready(Err(e)),
            Ok(expected_tail) => {
                let head = self.controller.read64(IQH) >> 4;
                if head == expected_tail {
                    return Poll::Ready(Ok(()));
                }
                self.controller.pending_waiters.register(cx.waker());
                Poll::Pending
            }
        }
    }
}
