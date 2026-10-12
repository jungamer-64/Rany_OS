// Kernel-side Page-backed Block I/O Buffer
// DMA-capable buffer backed by contiguous kernel pages.

use core::ptr::NonNull;
use core::slice;

use crate::mm::phys::frame_allocator::{PhysicalAllocation, alloc_contiguous_frames};
use crate::mm::types::PAGE_SIZE_4K;
use kernel_api::block_io::{DmaInfo, ZeroCopyBuffer, ZeroCopyBufferMut};

/// Page-backed cluster buffer
pub struct PageClusterBuffer {
    phys_start: u64,
    len: usize,
    virt_ptr: NonNull<u8>,
    backing: Option<PhysicalAllocation>,
}

// SAFETY: moving this owner transfers its initialized RAM; an active CPU
// borrow prevents moving it. DMA must consume the buffer through device I/O.
unsafe impl Send for PageClusterBuffer {}
// SAFETY: shared methods only borrow initialized immutable bytes. Mutations
// require an exclusive buffer borrow and DMA metadata grants no device access.
unsafe impl Sync for PageClusterBuffer {}

impl PageClusterBuffer {
    /// Consume exclusive physical ownership and retain its exact return target.
    pub fn from_allocation(backing: PhysicalAllocation, len: usize) -> Option<Self> {
        if len == 0 || len > isize::MAX as usize || len as u64 > backing.size_bytes() {
            backing.release();
            return None;
        }
        let phys_start = backing.as_u64();
        let pointer = crate::mm::virt::mapping::physical_memory_offset()
            .checked_add(phys_start)
            .and_then(|base| {
                let last = base.checked_add(len as u64 - 1)?;
                x86_64::VirtAddr::try_new(base).ok()?;
                x86_64::VirtAddr::try_new(last).ok()?;
                NonNull::new(core::ptr::with_exposed_provenance_mut::<u8>(base as usize))
            });
        let Some(ptr) = pointer else {
            backing.release();
            return None;
        };
        // SAFETY: the exclusive allocation owns these direct-mapped RAM bytes.
        // Initialize the entire logical range before safe CPU borrows exist.
        unsafe { ptr.as_ptr().write_bytes(0u8, len) };
        Some(Self {
            phys_start,
            len,
            virt_ptr: ptr,
            backing: Some(backing),
        })
    }

    /// Allocate a new contiguous page-backed buffer.
    pub fn allocate(size: usize) -> Option<Self> {
        if size == 0 {
            return None;
        }

        let frames_needed = size.checked_add(PAGE_SIZE_4K - 1)? / PAGE_SIZE_4K;
        let start_phys = alloc_contiguous_frames(frames_needed).ok()?;
        Self::from_allocation(start_phys, size)
    }

    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: construction initialized this logical range and this owner
        // retains its direct-mapped allocation for the entire immutable borrow.
        unsafe { slice::from_raw_parts(self.virt_ptr.as_ptr(), self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: exclusive buffer borrowing excludes other CPU/device access
        // to its initialized logical range while the allocation remains retained.
        unsafe { slice::from_raw_parts_mut(self.virt_ptr.as_ptr(), self.len) }
    }
}

impl ZeroCopyBuffer for PageClusterBuffer {
    fn as_slice(&self) -> &[u8] {
        self.as_slice()
    }

    fn dma_info(&self) -> Option<DmaInfo> {
        Some(DmaInfo {
            phys_addr: self.phys_start,
            len: self.len,
        })
    }
}

impl ZeroCopyBufferMut for PageClusterBuffer {
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl Drop for PageClusterBuffer {
    fn drop(&mut self) {
        self.backing
            .take()
            .expect("buffer owns its physical allocation")
            .release();
    }
}

#[cfg(test)]
mod tests {
    use super::PageClusterBuffer;

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn invalid_buffer_geometry_is_rejected_before_ram_admission() {
        assert!(PageClusterBuffer::allocate(0).is_none());
        assert!(PageClusterBuffer::allocate(usize::MAX).is_none());
    }
}
