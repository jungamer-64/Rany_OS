use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::io::dma::CoherentDmaBuffer;
pub use virtio_driver::defs::{VringDesc, VringUsedElem, VIRTQUEUE_MAX_SIZE, vring_flags};

/// Virtqueue available ring
#[repr(C)]
pub struct VringAvail {
    pub flags: u16,
    pub idx: u16,
    // ring: [u16; queue_size] follows
}

/// Virtqueue used ring
#[repr(C)]
pub struct VringUsed {
    pub flags: u16,
    pub idx: u16,
    // ring: [VringUsedElem; queue_size] follows
}

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
    pub free_bitmap: AtomicU64,
    /// Last seen used index
    pub last_used_idx: AtomicU32,
    /// DMA Buffer to keep memory alive (and properly manage ownership)
    dma_buffer: Option<CoherentDmaBuffer>,
    /// Queue index
    pub index: u16,
}

unsafe impl Send for VirtQueue {}
// SAFETY: Methods that mutate the queue state (avail_ring, used_ring, etc.) require `&mut self`.
// In ExoRust, `VirtQueue` is typically wrapped in `Arc<PoisonLock<VirtQueue>>` or `Mutex`,
// which ensures exclusive access for mutable operations. Raw pointers are only 
// accessed via volatile operations to synchronize with the hardware.
unsafe impl Sync for VirtQueue {}

impl VirtQueue {
    /// Initialize a VirtQueue with pre-allocated memory regions
    ///
    /// # Safety
    /// Caller must ensure:
    /// - Memory regions are valid and properly aligned
    pub unsafe fn new(
        queue_size: u16,
        desc_table: *mut VringDesc,
        avail_ring: *mut VringAvail,
        used_ring: *mut VringUsed,
        dma_buffer: Option<CoherentDmaBuffer>,
        index: u16,
    ) -> Self {
        for i in 0..queue_size {
            let desc_ptr = desc_table.add(i as usize);
            core::ptr::write_volatile(desc_ptr, VringDesc::default());
        }

        unsafe {
            core::ptr::write_volatile(&mut (*avail_ring).flags, 0);
            core::ptr::write_volatile(&mut (*avail_ring).idx, 0);
        }

        unsafe {
            core::ptr::write_volatile(&mut (*used_ring).flags, 0);
            core::ptr::write_volatile(&mut (*used_ring).idx, 0);
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
        }
    }

    /// Safely get the current available index
    fn get_avail_idx(&self) -> u16 {
        // SAFETY: The pointer `avail_ring` is guaranteed to be valid and points to the DMA ring.
        unsafe { core::ptr::read_volatile(&(*self.avail_ring).idx) }
    }

    /// Safely set a new available index
    fn set_avail_idx(&mut self, idx: u16) {
        // SAFETY: `&mut self` ensures exclusive access. `avail_ring` is valid.
        unsafe {
            core::ptr::write_volatile(&mut (*self.avail_ring).idx, idx);
        }
    }

    /// Safely set an entry in the available ring
    fn set_avail_ring_entry(&mut self, ring_index: u16, head: u16) {
        // SAFETY: The pointer arithmetic is within the bounds of the pre-allocated DMA ring.
        // `&mut self` enforces exclusive access, avoiding data races.
        let ring_ptr = unsafe { (self.avail_ring as *mut u16).add(2) };
        unsafe {
            core::ptr::write_volatile(ring_ptr.add(ring_index as usize), head);
        }
    }

    /// Safely get the current used index
    fn get_used_idx(&self) -> u16 {
        // SAFETY: Read-only access to the device-updated used ring memory.
        unsafe { core::ptr::read_volatile(&(*self.used_ring).idx) }
    }

    /// Safely get an element from the used ring
    fn get_used_elem(&self, ring_index: u16) -> VringUsedElem {
        // SAFETY: Pointer arithmetic and reads are within bounds of the used ring array.
        let ring_ptr = unsafe { (self.used_ring as *const u8).add(4) as *const VringUsedElem };
        unsafe { core::ptr::read_volatile(ring_ptr.add(ring_index as usize)) }
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
    pub unsafe fn submit(&mut self, head: u16) -> u16 {
        core::sync::atomic::fence(Ordering::Release);

        let avail_idx = self.get_avail_idx();
        self.set_avail_ring_entry(avail_idx % self.queue_size, head);

        core::sync::atomic::fence(Ordering::Release);

        self.set_avail_idx(avail_idx.wrapping_add(1));

        self.index
    }

    /// Notify the device that new buffers are available.
    pub fn notify(&self, transport: &dyn crate::io::virtio::transport::VirtioTransport) {
        transport.notify_queue(self.index);
    }

    /// Poll for a single completed request
    pub fn poll_completion(&mut self) -> Option<(u16, u32)> {
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

    /// Poll for all completed requests in bulk
    pub fn poll_completions<F>(&mut self, mut on_complete: F) -> usize
    where
        F: FnMut(u16, u32),
    {
        let last_used = self.last_used_idx.load(Ordering::Acquire);
        core::sync::atomic::fence(Ordering::Acquire);

        let used_idx = self.get_used_idx() as u32;
        if last_used == used_idx {
            return 0;
        }

        let mut count = 0;
        let mut idx = last_used;
        while idx != used_idx {
            let elem = self.get_used_elem((idx % self.queue_size as u32) as u16);
            on_complete(elem.id as u16, elem.len);
            idx = idx.wrapping_add(1);
            count += 1;
        }

        self.last_used_idx.store(idx, Ordering::Release);
        count
    }
}
