use core::sync::atomic::{AtomicU32, Ordering};
use core::ptr::NonNull;
use crate::sync::IrqPoisonLock;
use alloc::vec::Vec;
use crate::io::dma::CoherentDmaBuffer;
use crate::io::iommu::types::DmaAddr;
pub use virtio_driver::defs::{VringUsedElem, VIRTQUEUE_MAX_SIZE};

/// Virtqueue descriptor
#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
pub struct VringDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

impl VringDesc {
    pub const F_NEXT: u16 = 0x1;
    pub const F_WRITE: u16 = 0x2;
    pub const F_INDIRECT: u16 = 0x4;
}

pub mod vring_flags {
    pub const VRING_DESC_F_NEXT: u16 = 0x1;
    pub const VRING_DESC_F_WRITE: u16 = 0x2;
    pub const VRING_DESC_F_INDIRECT: u16 = 0x4;
}

pub const VIRTIO_F_INDIRECT_DESC: u64 = 1 << 28;

/// Virtqueue available ring
#[repr(C)]
pub struct VringAvail {
    pub flags: u16,
    pub idx: u16,
    pub ring: [u16; 32], // Alignment helper, use pointers for real access
}

/// Virtqueue used ring
#[repr(C)]
pub struct VringUsed {
    pub flags: u16,
    pub idx: u16,
    pub ring: [VringUsedElem; 32], // Alignment helper
}

#[derive(Debug)]
pub struct VirtQueue {
    /// Queue size (must be power of 2)
    pub queue_size: u16,
    /// Descriptor table base address
    pub desc_table: NonNull<VringDesc>,
    /// Available ring base address
    pub avail_ring: NonNull<VringAvail>,
    /// Used ring base address
    pub used_ring: NonNull<VringUsed>,
    /// Free descriptor list
    pub free_list: IrqPoisonLock<Vec<u16>>,
    /// Last seen used index
    pub last_used_idx: AtomicU32,
    /// DMA Buffer to keep memory alive (and properly manage ownership)
    dma_buffer: Option<CoherentDmaBuffer>,
    /// Queue index
    pub index: u16,
    /// Features negotiated with the device
    features: u64,
}

unsafe impl Send for VirtQueue {}
// SAFETY: Methods that mutate the queue state (avail_ring, used_ring, etc.) require `&mut self`.
// In ExoRust, `VirtQueue` is typically wrapped in `Arc<PoisonLock<VirtQueue>>` or `Mutex`,
// which ensures exclusive access for mutable operations. Raw pointers are only 
// accessed via volatile operations to synchronize with the hardware.
// SAFETY: VirtQueue management is now sound because:
// 1. All methods that modify internal state (submission, cleanup) either:
//    a) Require `&mut self`, ensuring exclusive access via device-level Mutex.
//    b) Use internal synchronization (e.g., `free_list` is protected by a Mutex,
//       `last_used_idx` uses atomic operations).
// 2. Raw pointers (`desc_table`, `avail_ring`, `used_ring`) are safely encapsulated
//    and accessed via volatile operations or proper memory barriers (fences).
// 3. The `used_ring` and `last_used_idx` logic correctly handles the single-writer
//    (device) and single-reader (driver) pattern common in VirtIO.
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
        features: u64,
    ) -> Self {
        let desc_table_ptr = NonNull::new(desc_table).expect("desc_table is null");
        let avail_ring_ptr = NonNull::new(avail_ring).expect("avail_ring is null");
        let used_ring_ptr = NonNull::new(used_ring).expect("used_ring is null");

        for i in 0..queue_size {
            let desc_ptr = desc_table.add(i as usize);
            core::ptr::write_volatile(desc_ptr, VringDesc::default());
        }

        let mut free_list = Vec::with_capacity(queue_size as usize);
        for i in (0..queue_size).rev() {
            free_list.push(i);
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
            desc_table: desc_table_ptr,
            avail_ring: avail_ring_ptr,
            used_ring: used_ring_ptr,
            free_list: IrqPoisonLock::new(free_list),
            last_used_idx: AtomicU32::new(0),
            dma_buffer,
            index,
            features,
        }
    }

    /// Safely get the current available index
    fn get_avail_idx(&self) -> u16 {
        // SAFETY: The pointer `avail_ring` is guaranteed to be valid and points to the DMA ring.
        // We use addr_of! to avoid creating an intermediate reference to a field in shared memory.
        let ptr = self.avail_ring.as_ptr();
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*ptr).idx)) }
    }

    /// Safely set a new available index
    fn set_avail_idx(&mut self, idx: u16) {
        // SAFETY: `&mut self` ensures exclusive access. `avail_ring` is valid.
        let ptr = self.avail_ring.as_ptr();
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*ptr).idx), idx);
        }
    }

    /// Safely set an entry in the available ring
    fn set_avail_ring_entry(&mut self, ring_index: u16, head: u16) {
        // SAFETY: The pointer arithmetic is within the bounds of the pre-allocated DMA ring.
        // Available ring structure: [u16 flags, u16 idx, u16 ring[size], u16 used_event]
        let ptr = self.avail_ring.as_ptr();
        let ring_ptr = unsafe { (ptr as *mut u16).add(2) };
        unsafe {
            core::ptr::write_volatile(ring_ptr.add(ring_index as usize), head);
        }
    }

    /// Safely get the current used index
    fn get_used_idx(&self) -> u16 {
        // SAFETY: Read-only access to the device-updated used ring memory.
        let ptr = self.used_ring.as_ptr();
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*ptr).idx)) }
    }

    /// Safely get an element from the used ring
    fn get_used_elem(&self, ring_index: u16) -> VringUsedElem {
        // SAFETY: Pointer arithmetic and reads are within bounds of the used ring array.
        // Used ring structure: [u16 flags, u16 idx, VringUsedElem ring[size], u16 avail_event]
        // Offset 4 bytes (flags and idx)
        let ptr = self.used_ring.as_ptr();
        let ring_ptr = unsafe { (ptr as *const u8).add(4) as *const VringUsedElem };
        unsafe { core::ptr::read_volatile(ring_ptr.add(ring_index as usize)) }
    }

    /// Allocate a descriptor from the free list
    pub fn alloc_desc(&self) -> Option<u16> {
        self.free_list.lock().ok().and_then(|mut list| list.pop())
    }

    /// Free a descriptor back to the free list
    pub fn free_desc(&self, idx: u16) {
        if let Ok(mut list) = self.free_list.lock() {
            list.push(idx);
        }
    }

    /// Add a buffer chain to the available ring
    ///
    /// # Safety
    /// Caller must ensure descriptors are properly set up
    pub unsafe fn submit(&mut self, head: u16) -> u16 {
        // 1. Ensure descriptor table updates are visible before updating available ring
        core::sync::atomic::fence(Ordering::Release);

        let avail_idx = self.get_avail_idx();
        self.set_avail_ring_entry(avail_idx % self.queue_size, head);

        // 2. Ensure available ring entry update is visible before updating avail.idx
        core::sync::atomic::fence(Ordering::Release);

        self.set_avail_idx(avail_idx.wrapping_add(1));

        // 3. Ensure avail.idx update is visible before the device sees the notification (doorbell)
        core::sync::atomic::fence(Ordering::Release);

        self.index
    }

    /// Submit a chain of descriptors as an indirect descriptor.
    ///
    /// # Safety
    /// Caller must ensure:
    /// - `indirect_table` points to a valid sequence of `VringDesc`
    /// - `count` is the number of descriptors in the table
    /// - `indirect_table` memory remains valid until the device processes it
    pub unsafe fn submit_indirect(&mut self, indirect_table_dma: DmaAddr, count: u16) -> Option<u16> {
        if (self.features & VIRTIO_F_INDIRECT_DESC) == 0 {
            return None;
        }

        let head = self.alloc_desc()?;
        let desc_ptr = self.desc_table.as_ptr().add(head as usize);

        core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc_ptr).addr), indirect_table_dma.as_u64());
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc_ptr).len), (count as usize * core::mem::size_of::<VringDesc>()) as u32);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc_ptr).flags), VringDesc::F_INDIRECT);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc_ptr).next), 0);

        self.submit(head);
        Some(head)
    }

    pub fn index(&self) -> u16 {
        self.index
    }

    pub fn size(&self) -> u16 {
        self.queue_size
    }

    pub fn notify(&self, transport: &dyn crate::io::virtio::transport::VirtioTransport) {
        transport.notify_queue(self.index);
    }

    /// Check if the device has produced any used elements that haven't been processed yet
    pub fn has_pending(&self) -> bool {
        self.last_used_idx.load(Ordering::Acquire) != self.get_used_idx() as u32
    }

    /// Poll for a single completed request
    pub fn poll_completion(&mut self) -> Option<(u16, u32)> {
        let last_used = self.last_used_idx.load(Ordering::Acquire);
        // REDUNDANT: load(Ordering::Acquire) already provides required barrier
        // core::sync::atomic::fence(Ordering::Acquire);

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
        // REDUNDANT: load(Ordering::Acquire) already provides required barrier
        // core::sync::atomic::fence(Ordering::Acquire);

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
