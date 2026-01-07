// Kernel-side Page-backed Cluster Buffer
// Implements a Page-backed buffer that satisfies `fat32::ClusterBuffer` and
// `vfs::block::IoBufferMut` for DMA-capable I/O.

use alloc::boxed::Box;

use core::ptr::NonNull;
use core::slice;

use fat32::{ClusterBuffer, ClusterBufferAllocator};
use vfs::block::DmaInfo;
use x86_64::PhysAddr;

use crate::mm::{alloc_contiguous_frames, dealloc_contiguous_frames, PAGE_SIZE_4K};

/// Page-backed cluster buffer
pub struct PageClusterBuffer {
    phys_start: u64,
    len: usize,
    virt_ptr: NonNull<u8>,
    frames: usize,
}

// SAFETY: PageClusterBuffer holds a pointer into kernel-virtual memory (HHDM) and
// provides synchronous access to that memory. Accesses are not inherently racy and
// the buffer may be safely sent/shared across threads when used by callers that
// adhere to the DMA / buffer ownership invariants.
unsafe impl Send for PageClusterBuffer {}
unsafe impl Sync for PageClusterBuffer {}

impl PageClusterBuffer {
    /// Create a new PageClusterBuffer from a physical start address and length
    pub fn new_from_phys(phys_start: u64, len: usize) -> Option<Self> {
        if len == 0 {
            return None;
        }
        let virt = (crate::memory::physical_memory_offset() + phys_start) as *mut u8;
        let ptr = NonNull::new(virt)?;
        let frames = (len + (PAGE_SIZE_4K as usize - 1)) / (PAGE_SIZE_4K as usize);
        Some(Self {
            phys_start,
            len,
            virt_ptr: ptr,
            frames,
        })
    }
}

impl ClusterBuffer for PageClusterBuffer {
    fn len(&self) -> usize {
        self.len
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.virt_ptr.as_ptr(), self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.virt_ptr.as_ptr(), self.len) }
    }
}


/// Implement `ZeroCopyBuffer`/`ZeroCopyBufferMut` so PageClusterBuffer can be used as
/// an owned zero-copy buffer type by block devices (e.g., returned by `read_async`).
impl vfs::block::ZeroCopyBuffer for PageClusterBuffer {
    fn as_slice(&self) -> &[u8] {
        // Delegate to ClusterBuffer implementation
        ClusterBuffer::as_slice(&*self)
    }

    fn dma_info(&self) -> Option<DmaInfo> {
        Some(DmaInfo {
            phys_addr: self.phys_start,
            len: self.len,
        })
    }
}

impl vfs::block::ZeroCopyBufferMut for PageClusterBuffer {
    fn as_mut_slice(&mut self) -> &mut [u8] {
        ClusterBuffer::as_mut_slice(self)
    }
}

impl Drop for PageClusterBuffer {
    fn drop(&mut self) {
        // Best-effort deallocation
        let start = PhysAddr::new(self.phys_start);
        dealloc_contiguous_frames(start, self.frames);
    }
}

/// Kernel allocator that returns `Box<dyn ClusterBuffer>` for the FAT crate.
pub struct PageClusterBufferAllocator;

impl PageClusterBufferAllocator {
    pub fn new() -> Self {
        Self {}
    }
}

impl ClusterBufferAllocator for PageClusterBufferAllocator {
    fn alloc(&self, size: usize) -> Result<Box<dyn ClusterBuffer>, vfs::VfsError> {
        if size == 0 {
            return Err(vfs::VfsError::Other);
        }
        let frames_needed = (size + (PAGE_SIZE_4K as usize - 1)) / (PAGE_SIZE_4K as usize);

        if let Some(start_phys) = alloc_contiguous_frames(frames_needed) {
            // Use allocated contiguous region size = frames_needed * PAGE_SIZE_4K
            let real_size = frames_needed * (PAGE_SIZE_4K as usize);
            if let Some(buf) = PageClusterBuffer::new_from_phys(start_phys.as_u64(), real_size) {
                return Ok(Box::new(buf));
            } else {
                // Shouldn't happen, but if mapping failed, free and fall back
                dealloc_contiguous_frames(start_phys, frames_needed);
            }
        }

        // Fallback to heap-backed Vec buffer (compatibility)
        Ok(Box::new(alloc::vec![0u8; size]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vfs::block::{ZeroCopyBuffer, ZeroCopyBufferMut};
    use crate::mm::mapping::phys_to_virt;
    use x86_64::PhysAddr;

    #[test]
    fn test_page_cluster_buffer_alloc_fallback_or_contig() {
        let alloc = PageClusterBufferAllocator::new();
        // Try small allocation
        let b = alloc.alloc(4096).expect("alloc failed");
        assert!(b.len() >= 4096);
    }

    #[test]
    fn test_impl_zero_copy_traits() {
        // Compile-time trait bound test
        fn assert_traits<T: ZeroCopyBuffer + ZeroCopyBufferMut>() {}
        assert_traits::<PageClusterBuffer>();
    }

    #[test]
    fn test_page_cluster_buffer_dma_info() {
        let phys = 0x1000_0000u64;
        let size = PAGE_SIZE_4K as usize;
        if let Some(buf) = PageClusterBuffer::new_from_phys(phys, size) {
            let info = buf.dma_info().expect("dma_info missing");
            assert_eq!(info.phys_addr, phys);
            assert_eq!(info.len, size);
        } else {
            panic!("new_from_phys returned None for valid inputs");
        }
    }

    #[test]
    fn test_page_cluster_buffer_physical_alloc_and_write() {
        // Try to allocate contiguous frames for an end-to-end memory-backed buffer
        let frames_needed = 1usize;
        if let Some(start_phys) = alloc_contiguous_frames(frames_needed) {
            let size = frames_needed * (PAGE_SIZE_4K as usize);
            let virt = phys_to_virt(PhysAddr::new(start_phys.as_u64()));
            unsafe {
                let slice = core::slice::from_raw_parts_mut(virt.as_u64() as *mut u8, size);
                for i in 0..size {
                    slice[i] = (i & 0xff) as u8;
                }
            }

            let buf = PageClusterBuffer::new_from_phys(start_phys.as_u64(), size).expect("new_from_phys failed");
            // Now we can safely read via as_slice because the memory is valid
            let s = ClusterBuffer::as_slice(&buf);
            assert_eq!(s[0], 0u8);
            assert_eq!(s[1], 1u8);
            // Drop buf -> dealloc happens automatically
        } else {
            eprintln!("Skipping page-backed buffer test: alloc_contiguous_frames failed");
        }
    }

    // Integration test: mount FAT using PageClusterBuffer-backed zero-copy device
    #[test]
    fn test_fat_mount_with_page_allocator_zero_copy() {
        use alloc::sync::Arc;
        use vfs::block::{ZeroCopyBlockDevice, BlockDeviceInfo, BlockError, BlockResult};
        use fat32::Cluster;
        use crate::task::block_on;
        use crate::mm::mapping::phys_to_virt;
        use core::slice;

        // If the test environment cannot allocate contiguous frames, skip.
        if alloc_contiguous_frames(1).is_none() {
            eprintln!("Skipping FAT zero-copy integration test: contiguous frames not available");
            return;
        }

        struct TestZcDevice {
            storage: spin::Mutex<Vec<u8>>,
            block_size: u32,
            total_blocks: u64,
        }

        impl TestZcDevice {
            fn new(total_blocks: u64, block_size: u32) -> Self {
                Self {
                    storage: spin::Mutex::new(vec![0u8; (total_blocks as usize) * (block_size as usize)]),
                    block_size,
                    total_blocks,
                }
            }

            fn write_block(&self, block: u64, data: &[u8]) {
                let mut st = self.storage.lock();
                let start = (block as usize) * (self.block_size as usize);
                let end = start + data.len();
                st[start..end].copy_from_slice(data);
            }
        }

        impl ZeroCopyBlockDevice for TestZcDevice {
            type Buffer = PageClusterBuffer;

            fn info(&self) -> fat32::VfsBlockDeviceInfo {
                fat32::VfsBlockDeviceInfo {
                    name: "testzc",
                    total_blocks: self.total_blocks,
                    block_size: self.block_size,
                    read_only: false,
                    max_sectors: 256,
                    num_queues: 1,
                }
            }

            fn flush(&self) -> Result<(), BlockError> {
                Ok(())
            }

            fn alloc_buffer(&self, size: usize) -> BlockResult<Self::Buffer> {
                let frames_needed = (size + (PAGE_SIZE_4K as usize - 1)) / (PAGE_SIZE_4K as usize);
                if let Some(start_phys) = alloc_contiguous_frames(frames_needed) {
                    let real_size = frames_needed * (PAGE_SIZE_4K as usize);
                    if let Some(buf) = PageClusterBuffer::new_from_phys(start_phys.as_u64(), real_size) {
                        return Ok(buf);
                    } else {
                        dealloc_contiguous_frames(start_phys, frames_needed);
                    }
                }
                Err(BlockError::NotReady)
            }

            fn read_async(
                &self,
                block: u64,
                count: u32,
            ) -> fat32::ZcFuture<'_, BlockResult<Self::Buffer>> {
                let start_block = block as usize;
                let len = (count as usize) * (self.block_size as usize);
                let storage_ref = &self.storage;
                Box::pin(async move {
                    let frames_needed = (len + (PAGE_SIZE_4K as usize - 1)) / (PAGE_SIZE_4K as usize);
                    let start_phys = match alloc_contiguous_frames(frames_needed) {
                        Some(a) => a,
                        None => return Err(BlockError::NotReady),
                    };
                    let real_size = frames_needed * (PAGE_SIZE_4K as usize);
                    // Fill physical memory with contents from storage
                    let virt = phys_to_virt(PhysAddr::new(start_phys.as_u64()));
                    unsafe {
                        let dest = slice::from_raw_parts_mut(virt.as_u64() as *mut u8, real_size);
                        let st = storage_ref.lock();
                        let offset = start_block * (self.block_size as usize);
                        dest[..len].copy_from_slice(&st[offset..offset + len]);
                    }
                    let buf = PageClusterBuffer::new_from_phys(start_phys.as_u64(), real_size)
                        .ok_or(BlockError::IoError)?;
                    Ok(buf)
                })
            }

            fn write_async(
                &self,
                block: u64,
                buffer: Self::Buffer,
            ) -> fat32::ZcFuture<'_, BlockResult<Self::Buffer>> {
                let start_block = block as usize;
                let storage_ref = &self.storage;
                Box::pin(async move {
                    let data = ZeroCopyBuffer::as_slice(&buffer);
                    let mut st = storage_ref.lock();
                    let offset = start_block * (self.block_size as usize);
                    st[offset..offset + data.len()].copy_from_slice(&data[..]);
                    Ok(buffer)
                })
            }
        }

        // Initialize device and write a minimal boot sector
        let dev = Arc::new(TestZcDevice::new(2048, 512));
        let mut bs = [0u8; 512];
        bs[11..13].copy_from_slice(&512u16.to_le_bytes()); // bytes per sector
        bs[13] = 1; // sectors per cluster
        bs[14..16].copy_from_slice(&32u16.to_le_bytes()); // reserved sectors
        bs[16] = 2; // number of FATs
        bs[32..36].copy_from_slice(&4096u32.to_le_bytes()); // total sectors
        bs[36..40].copy_from_slice(&1u32.to_le_bytes()); // FAT size 32
        bs[44..48].copy_from_slice(&2u32.to_le_bytes()); // root cluster
        bs[82..90].copy_from_slice(b"FAT32   "); // fs type field
        bs[510] = 0x55;
        bs[511] = 0xAA;

        dev.write_block(0, &bs);

        // Direct read_async -> should return page-backed buffer with DMA info
        let read_buf = block_on(dev.read_async(0, 1)).expect("read_async failed");
        let info = read_buf.dma_info().expect("dma_info missing");
        assert_eq!(info.len, 512);
        assert_eq!(ZeroCopyBuffer::as_slice(&read_buf)[11..13], 512u16.to_le_bytes());

        // Mount FAT using the PageClusterBuffer allocator
        let alloc = Arc::new(PageClusterBufferAllocator::new());
        let fs_res = block_on(fat32::Fat32FileSystem::<PageClusterBuffer>::mount_zero_copy_with_allocator(
            Arc::clone(&dev) as Arc<dyn ZeroCopyBlockDevice<Buffer = PageClusterBuffer>>,
            alloc,
        ));

        let fs = fs_res.expect("mount_zero_copy_with_allocator failed");
        assert_eq!((&*fs).root_cluster, Cluster(2));
    }
}

