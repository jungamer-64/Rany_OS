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

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests {
    use super::{PAGE_SIZE_4K, PageClusterBuffer, alloc_contiguous_frames};
    use alloc::{boxed::Box, vec, vec::Vec};
    use kernel_api::block_io::{
        BlockDeviceInfo, BlockError, BlockResult, ZcFuture, ZeroCopyBlockDevice, ZeroCopyBuffer,
        ZeroCopyBufferMut,
    };

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    pub fn test_page_cluster_buffer_alloc_or_contig() {
        let buf = PageClusterBuffer::allocate(4096).expect("allocation failed");
        assert!(buf.as_slice().len() >= 4096);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    pub fn test_impl_zero_copy_traits() {
        // Compile-time trait bound test
        fn assert_traits<T: ZeroCopyBuffer + ZeroCopyBufferMut>() {}
        assert_traits::<PageClusterBuffer>();
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    pub fn test_page_cluster_buffer_dma_info() {
        let size = PAGE_SIZE_4K as usize;
        let backing = alloc_contiguous_frames(1).expect("physical buffer allocation");
        let phys = backing.as_u64();
        let buf =
            PageClusterBuffer::from_allocation(backing, size).expect("owned buffer construction");
        let info = buf.dma_info().expect("dma_info missing");
        assert_eq!(info.phys_addr, phys);
        assert_eq!(info.len, size);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    pub fn test_page_cluster_buffer_physical_alloc_and_write() {
        let backing = alloc_contiguous_frames(1).expect("owned test RAM");
        let mut buffer =
            PageClusterBuffer::from_allocation(backing, 512).expect("owned buffer construction");
        assert_eq!(buffer.as_slice(), &[0u8; 512]);
        // LOOP_PROOF: mode=bounded; reason=The initialized logical buffer fixes the independent byte-pattern vector length;
        for (index, byte) in buffer.as_mut_slice().iter_mut().enumerate() {
            *byte = (index & 0xff) as u8;
        }
        assert_eq!(&buffer.as_slice()[..4], &[0, 1, 2, 3]);
        assert_eq!(buffer.dma_info().unwrap().len, 512);
        assert!(PageClusterBuffer::allocate(0).is_none());
        assert!(
            PageClusterBuffer::from_allocation(
                alloc_contiguous_frames(1).unwrap(),
                PAGE_SIZE_4K + 1
            )
            .is_none()
        );
    }

    pub async fn test_page_cluster_buffer_zero_copy_roundtrip() {
        struct TestZcDevice {
            storage: crate::sync::Mutex<Vec<u8>>,
            block_size: u32,
            total_blocks: u64,
        }

        impl ZeroCopyBlockDevice for TestZcDevice {
            type Buffer = PageClusterBuffer;

            fn info(&self) -> BlockDeviceInfo {
                BlockDeviceInfo {
                    name: "testzc",
                    total_blocks: self.total_blocks,
                    block_size: self.block_size,
                    read_only: false,
                    max_sectors: 256,
                    num_queues: 1,
                }
            }

            fn flush(&self) -> BlockResult<()> {
                Ok(())
            }

            fn alloc_buffer(&self, size: usize) -> BlockResult<Self::Buffer> {
                PageClusterBuffer::allocate(size).ok_or(BlockError::NotReady)
            }

            fn read_async(
                &self,
                block: u64,
                count: u32,
            ) -> ZcFuture<'_, BlockResult<Self::Buffer>> {
                let block_size = self.block_size as usize;
                let len = count as usize * block_size;
                let storage_ref = &self.storage;
                Box::pin(async move {
                    let mut buf = PageClusterBuffer::allocate(len).ok_or(BlockError::NotReady)?;
                    let offset = block as usize * block_size;
                    let st = storage_ref.lock();
                    buf.as_mut_slice()[..len].copy_from_slice(&st[offset..offset + len]);
                    Ok(buf)
                })
            }

            fn write_async(
                &self,
                block: u64,
                buffer: Self::Buffer,
            ) -> ZcFuture<'_, BlockResult<Self::Buffer>> {
                let block_size = self.block_size as usize;
                let storage_ref = &self.storage;
                Box::pin(async move {
                    let data = buffer.as_slice();
                    let offset = block as usize * block_size;
                    let mut st = storage_ref.lock();
                    st[offset..offset + data.len()].copy_from_slice(data);
                    Ok(buffer)
                })
            }
        }

        let dev = TestZcDevice {
            storage: crate::sync::Mutex::new(vec![0u8; 2048 * 512]),
            block_size: 512,
            total_blocks: 2048,
        };

        let mut write_buf = PageClusterBuffer::allocate(512).expect("write buffer alloc failed");
        write_buf.as_mut_slice()[0..4].copy_from_slice(b"Rany");
        let _ = dev.write_async(0, write_buf).await.expect("write failed");

        let read_buf = dev.read_async(0, 1).await.expect("read failed");
        let info = read_buf.dma_info().expect("dma_info missing");
        assert_eq!(info.len, 512);
        assert_eq!(&read_buf.as_slice()[0..4], b"Rany");
    }
}
