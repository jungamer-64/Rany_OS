use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::io::dma::CoherentDmaBuffer;

/// Virtqueue descriptor flags
pub mod vring_flags {
    pub const VRING_DESC_F_NEXT: u16 = 1;
    pub const VRING_DESC_F_WRITE: u16 = 2;
    pub const VRING_DESC_F_INDIRECT: u16 = 4;
}

/// Virtqueue descriptor
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VringDesc {
    /// Guest physical address
    pub addr: u64,
    /// Length in bytes
    pub len: u32,
    /// Flags
    pub flags: u16,
    /// Next descriptor index
    pub next: u16,
}

/// Virtqueue available ring
#[repr(C)]
pub struct VringAvail {
    pub flags: u16,
    pub idx: u16,
    // ring: [u16; queue_size] follows
}

/// Used element
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VringUsedElem {
    pub id: u32,
    pub len: u32,
}

/// Virtqueue used ring
#[repr(C)]
pub struct VringUsed {
    pub flags: u16,
    pub idx: u16,
    // ring: [VringUsedElem; queue_size] follows
}

/// Maximum queue size
pub const VIRTQUEUE_MAX_SIZE: u16 = 256;

/// VirtQueue management structure
pub struct VirtQueue {
    /// Queue size (must be power of 2)
    pub queue_size: u16,
    /// Descriptor table base address
    pub desc_table: *mut VringDesc,
    /// Available ring base address
    pub avail_ring: *mut VringAvail,
    /// Used ring base address
    pub used_ring: *mut VringUsed,
    /// Free descriptor bitmap
    free_bitmap: AtomicU64,
    /// Last seen used index
    last_used_idx: AtomicU32,
    /// DMA Buffer to keep memory alive (and properly manage ownership)
    dma_buffer: Option<CoherentDmaBuffer>,
    /// Queue index
    pub index: u16,
    
    // Kept here for compatibility during Phase 3 transition
    notify_addr: Option<u64>,
    notify_is_32bit: bool,
}

unsafe impl Send for VirtQueue {}
unsafe impl Sync for VirtQueue {}

impl VirtQueue {
    /// Initialize a VirtQueue with pre-allocated memory regions
    ///
    /// # Safety
    /// Caller must ensure:
    /// - Memory regions are valid and properly aligned
    /// - Queue size is power of 2 and <= VIRTQUEUE_MAX_SIZE
    pub unsafe fn new(
        queue_size: u16,
        desc_table: *mut VringDesc,
        avail_ring: *mut VringAvail,
        used_ring: *mut VringUsed,
        dma_buffer: Option<CoherentDmaBuffer>,
        index: u16,
        notify_addr: Option<u64>,
        notify_is_32bit: bool,
    ) -> Self {
        for i in 0..queue_size {
            unsafe {
                (*desc_table.add(i as usize)) = VringDesc::default();
            }
        }

        unsafe {
            (*avail_ring).flags = 0;
            (*avail_ring).idx = 0;
        }

        unsafe {
            (*used_ring).flags = 0;
            (*used_ring).idx = 0;
        }

        Self {
            queue_size,
            desc_table,
            avail_ring,
            used_ring,
            free_bitmap: AtomicU64::new(if queue_size >= 64 {
                u64::MAX
            } else {
                (1u64 << queue_size) - 1
            }),
            last_used_idx: AtomicU32::new(0),
            dma_buffer,
            index,
            notify_addr,
            notify_is_32bit,
        }
    }

    /// Safely get the current available index
    fn get_avail_idx(&self) -> u16 {
        unsafe { (*self.avail_ring).idx }
    }

    /// Safely set a new available index
    fn set_avail_idx(&self, idx: u16) {
        unsafe {
            (*self.avail_ring).idx = idx;
        }
    }

    /// Safely set an entry in the available ring
    fn set_avail_ring_entry(&self, ring_index: u16, head: u16) {
        let ring_ptr = unsafe { (self.avail_ring as *mut u16).add(2) };
        unsafe {
            *ring_ptr.add(ring_index as usize) = head;
        }
    }

    /// Safely get the current used index
    fn get_used_idx(&self) -> u16 {
        unsafe { (*self.used_ring).idx }
    }

    /// Safely get an element from the used ring
    fn get_used_elem(&self, ring_index: u16) -> VringUsedElem {
        let ring_ptr = unsafe { (self.used_ring as *const u8).add(4) as *const VringUsedElem };
        unsafe { ring_ptr.add(ring_index as usize).read_unaligned() }
    }

    /// Allocate a descriptor from the free list
    pub fn alloc_desc(&self) -> Option<u16> {
        loop {
            let bitmap = self.free_bitmap.load(Ordering::Acquire);
            if bitmap == 0 {
                return None;
            }

            let idx = bitmap.trailing_zeros() as u16;
            let new_bitmap = bitmap & !(1u64 << idx);

            if self
                .free_bitmap
                .compare_exchange(bitmap, new_bitmap, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(idx);
            }
        }
    }

    /// Free a descriptor back to the free list
    pub fn free_desc(&self, idx: u16) {
        loop {
            let bitmap = self.free_bitmap.load(Ordering::Acquire);
            let new_bitmap = bitmap | (1u64 << idx);

            if self
                .free_bitmap
                .compare_exchange(bitmap, new_bitmap, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    /// Add a buffer chain to the available ring
    ///
    /// # Safety
    /// Caller must ensure descriptors are properly set up
    pub unsafe fn submit(&self, head: u16) -> u16 {
        core::sync::atomic::fence(Ordering::Release);

        let avail_idx = self.get_avail_idx();
        self.set_avail_ring_entry(avail_idx % self.queue_size, head);

        core::sync::atomic::fence(Ordering::Release);

        self.set_avail_idx(avail_idx.wrapping_add(1));

        self.index
    }

    /// Notify the device that new buffers are available.
    #[allow(deprecated)]
    pub fn notify(&self) {
        let Some(addr) = self.notify_addr else {
            return;
        };

        if self.notify_is_32bit {
            crate::io::mmio::mmio_write_u32(addr as usize, self.index as u32);
        } else {
            crate::io::mmio::mmio_write_u16(addr as usize, self.index);
        }
    }

    /// Poll for completed requests
    pub fn poll_completions(&self) -> Option<(u16, u32)> {
        let last_used = self.last_used_idx.load(Ordering::Acquire);
        core::sync::atomic::fence(Ordering::Acquire);

        let used_idx = self.get_used_idx() as u32;
        if last_used == used_idx {
            return None;
        }

        let elem = self.get_used_elem((last_used % self.queue_size as u32) as u16);
        self.last_used_idx
            .store(last_used.wrapping_add(1), Ordering::Release);

        Some((elem.id as u16, elem.len))
    }
}
