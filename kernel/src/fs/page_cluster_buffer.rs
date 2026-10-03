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

// SAFETY: PageClusterBuffer holds a pointer into kernel-virtual memory (HHDM) and
// provides synchronous access to that memory. Accesses are not inherently racy and
// the buffer may be safely sent/shared across threads when used by callers that
// adhere to the DMA / buffer ownership invariants.
unsafe impl Send for PageClusterBuffer {}
unsafe impl Sync for PageClusterBuffer {}

impl PageClusterBuffer {
    /// Consume exclusive physical ownership and retain its exact return target.
    pub fn from_allocation(backing: PhysicalAllocation, len: usize) -> Option<Self> {
        if len == 0 || len as u64 > backing.size_bytes() {
            backing.release();
            return None;
        }
        let phys_start = backing.as_u64();
        let virt = (crate::mm::virt::mapping::physical_memory_offset() + phys_start) as *mut u8;
        let Some(ptr) = NonNull::new(virt) else {
            backing.release();
            return None;
        };
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
        let real_size = frames_needed * (PAGE_SIZE_4K as usize);
        Self::from_allocation(start_phys, real_size)
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.virt_ptr.as_ptr(), self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
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
    use crate::mm::virt::mapping::phys_to_virt;
    use alloc::{boxed::Box, vec, vec::Vec};
    use kernel_api::block_io::{
        BlockDeviceInfo, BlockError, BlockResult, ZcFuture, ZeroCopyBlockDevice, ZeroCopyBuffer,
        ZeroCopyBufferMut,
    };
    use x86_64::PhysAddr;

    #[cfg_attr(test, test_case)]
    pub fn test_page_cluster_buffer_alloc_or_contig() {
        let buf = PageClusterBuffer::allocate(4096).expect("allocation failed");
        assert!(buf.as_slice().len() >= 4096);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_impl_zero_copy_traits() {
        // Compile-time trait bound test
        fn assert_traits<T: ZeroCopyBuffer + ZeroCopyBufferMut>() {}
        assert_traits::<PageClusterBuffer>();
    }

    #[cfg_attr(test, test_case)]
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

    #[cfg_attr(test, test_case)]
    pub fn test_page_cluster_buffer_physical_alloc_and_write() {
        // Try to allocate contiguous frames for an end-to-end memory-backed buffer
        let frames_needed = 1usize;
        if let Ok(start_phys) = alloc_contiguous_frames(frames_needed) {
            let size = frames_needed * (PAGE_SIZE_4K as usize);
            let virt = phys_to_virt(PhysAddr::new(start_phys.as_u64()));
            unsafe {
                let slice = core::slice::from_raw_parts_mut(virt.as_u64() as *mut u8, size);
                for i in 0..size {
                    slice[i] = (i & 0xff) as u8;
                }
            }

            let buf = PageClusterBuffer::from_allocation(start_phys, size)
                .expect("owned buffer construction");
            // Now we can safely read via as_slice because the memory is valid
            let s = buf.as_slice();
            assert_eq!(s[0], 0u8);
            assert_eq!(s[1], 1u8);
            // Drop buf -> dealloc happens automatically
        } else {
            eprintln!("Skipping page-backed buffer test: alloc_contiguous_frames failed");
        }
    }

    #[cfg_attr(test, test_case)]
    pub fn test_page_cluster_buffer_zero_copy_roundtrip() {
        struct TestZcDevice {
            storage: spin::Mutex<Vec<u8>>,
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
            storage: spin::Mutex::new(vec![0u8; 2048 * 512]),
            block_size: 512,
            total_blocks: 2048,
        };

        let mut write_buf = PageClusterBuffer::allocate(512).expect("write buffer alloc failed");
        write_buf.as_mut_slice()[0..4].copy_from_slice(b"Rany");
        let _ = crate::task::block_on(dev.write_async(0, write_buf)).expect("write failed");

        let read_buf = crate::task::block_on(dev.read_async(0, 1)).expect("read failed");
        let info = read_buf.dma_info().expect("dma_info missing");
        assert_eq!(info.len, 512);
        assert_eq!(&read_buf.as_slice()[0..4], b"Rany");
    }
}
