use crate::io::dma::CoherentDmaBuffer;
use crate::io::iommu::types::DmaAddr;
use crate::sync::IrqPoisonLock;
use alloc::vec::Vec;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU16, Ordering};

pub use virtio_driver::defs::{
    VIRTIO_F_INDIRECT_DESC, VIRTQUEUE_MAX_SIZE, VRING_AVAIL_ALIGN, VRING_DESC_ALIGN,
    VRING_USED_ALIGN, VringAvailHeader as VringAvail, VringDesc, VringUsedElem,
    VringUsedHeader as VringUsed, vring_flags,
};

/// Virtqueue implementation
#[derive(Debug)]
pub struct VirtQueue {
    /// Queue size (must be power of 2)
    pub(crate) queue_size: u16,
    /// Descriptor table base address
    pub(crate) desc_table: NonNull<VringDesc>,
    /// Available ring base address
    pub(crate) avail_ring: NonNull<VringAvail>,
    /// Used ring base address
    pub(crate) used_ring: NonNull<VringUsed>,
    /// Free descriptor list (using a lock for now, consider lock-free in future)
    pub(crate) free_list: IrqPoisonLock<Vec<u16>>,
    /// Last seen used index
    last_used_idx: AtomicU16,
    /// DMA Buffer to keep memory alive
    dma_buffer: Option<CoherentDmaBuffer>,
    /// Queue index
    index: u16,
    /// Features negotiated with the device
    features: u64,
}

// SAFETY: VirtQueue is thread-safe because:
// 1. Mutable state (free_list) is protected by a lock.
// 2. Shared memory (rings) is accessed via volatile operations on shared DMA memory.
// 3. Atomical updates for last_used_idx.
unsafe impl Send for VirtQueue {}
unsafe impl Sync for VirtQueue {}

impl VirtQueue {
    /// Calculate required memory size for a virtqueue
    pub fn calculate_layout(queue_size: u16) -> (usize, usize, usize, usize) {
        let queue_size = queue_size as usize;
        let desc_table_size = core::mem::size_of::<VringDesc>() * queue_size;

        // Avail: flags(2) + idx(2) + ring[queue_size](2*qs) + used_event(2)
        let avail_ring_size = 2 + 2 + 2 * queue_size + 2;

        // Used: flags(2) + idx(2) + ring[queue_size](8*qs) + avail_event(2)
        let used_ring_size = 2 + 2 + core::mem::size_of::<VringUsedElem>() * queue_size + 2;

        let used_offset =
            (desc_table_size + avail_ring_size + VRING_USED_ALIGN - 1) & !(VRING_USED_ALIGN - 1);
        let total_size = used_offset + used_ring_size;

        (desc_table_size, avail_ring_size, used_offset, total_size)
    }

    /// Initialize a VirtQueue with pre-allocated memory regions
    ///
    /// # Safety
    /// Caller must ensure:
    /// - Memory regions are valid and properly aligned
    /// - `dma_buffer` ownership is correctly handled
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

        // Initialize descriptor table
        for i in 0..queue_size {
            core::ptr::write_volatile(desc_table.add(i as usize), VringDesc::default());
        }

        // Initialize free list
        let mut free_list = Vec::with_capacity(queue_size as usize);
        for i in (0..queue_size).rev() {
            free_list.push(i);
        }

        // Initialize Available ring
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*avail_ring).flags), 0);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*avail_ring).idx), 0);

        // Initialize Used ring
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*used_ring).flags), 0);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*used_ring).idx), 0);

        Self {
            queue_size,
            desc_table: desc_table_ptr,
            avail_ring: avail_ring_ptr,
            used_ring: used_ring_ptr,
            free_list: IrqPoisonLock::new(free_list),
            last_used_idx: AtomicU16::new(0),
            dma_buffer,
            index,
            features,
        }
    }

    /// Returns the descriptor table pointer
    pub fn desc_table_ptr(&self) -> *mut VringDesc {
        self.desc_table.as_ptr()
    }

    /// Returns the queue size
    pub fn size(&self) -> u16 {
        self.queue_size
    }

    /// Returns the queue index
    pub fn index(&self) -> u16 {
        self.index
    }

    /// Returns the current used_idx from the device (volatile read)
    pub fn get_used_idx_public(&self) -> u16 {
        self.get_used_idx()
    }

    /// Returns the last used_idx tracked by the driver
    pub fn get_last_used_idx(&self) -> u16 {
        self.last_used_idx
            .load(core::sync::atomic::Ordering::Acquire)
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

    /// Safely get the current available index
    fn get_avail_idx(&self) -> u16 {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(self.avail_ring.as_ref().idx)) }
    }

    /// Safely set a new available index
    fn set_avail_idx(&mut self, idx: u16) {
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*self.avail_ring.as_ptr()).idx),
                idx,
            );
        }
    }

    /// Safely set an entry in the available ring
    fn set_avail_ring_entry(&mut self, ring_index: u16, head: u16) {
        let ring_ptr = unsafe { (self.avail_ring.as_ptr() as *mut u16).add(2) };
        unsafe {
            core::ptr::write_volatile(ring_ptr.add(ring_index as usize), head);
        }
    }

    /// Safely get the current used index
    fn get_used_idx(&self) -> u16 {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(self.used_ring.as_ref().idx)) }
    }

    /// Safely get an element from the used ring
    fn get_used_elem(&self, ring_index: u16) -> VringUsedElem {
        let ring_ptr =
            unsafe { (self.used_ring.as_ptr() as *const u8).add(4) as *const VringUsedElem };
        unsafe { core::ptr::read_volatile(ring_ptr.add(ring_index as usize)) }
    }

    /// Submit a head descriptor to the available ring
    ///
    /// # Safety
    /// Caller must ensure the descriptor chain starting at `head` is valid.
    pub unsafe fn submit(&mut self, head: u16) -> u16 {
        // Step 1: Write available ring entry.
        // We use Ordering::Release fence to ensure descriptor table writes are visible.
        core::sync::atomic::fence(Ordering::Release);

        let avail_idx = self.get_avail_idx();
        self.set_avail_ring_entry(avail_idx % self.queue_size, head);

        // Step 2: Update avail.idx.
        // We need another Release fence to ensure the ring entry update is visible before idx update.
        core::sync::atomic::fence(Ordering::Release);

        self.set_avail_idx(avail_idx.wrapping_add(1));

        // Note: The caller is responsible for notifying the device (doorbell).
        self.index
    }

    /// Submit a chain of descriptors as an indirect descriptor.
    ///
    /// # Safety
    /// Caller must ensure the indirect table is valid and DMA-accessible.
    pub unsafe fn submit_indirect(
        &mut self,
        indirect_table_dma: DmaAddr,
        count: u16,
    ) -> Option<u16> {
        if (self.features & VIRTIO_F_INDIRECT_DESC) == 0 {
            return None;
        }

        let head = self.alloc_desc()?;
        let desc_ptr = self.desc_table.as_ptr().add(head as usize);

        core::ptr::write_volatile(
            core::ptr::addr_of_mut!((*desc_ptr).addr),
            indirect_table_dma.as_u64(),
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!((*desc_ptr).len),
            (count as u32) * (core::mem::size_of::<VringDesc>() as u32),
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!((*desc_ptr).flags),
            VringDesc::F_INDIRECT,
        );
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc_ptr).next), 0);

        self.submit(head);
        Some(head)
    }

    /// Notify the device that new buffers are available
    pub fn notify(&self, transport: &dyn crate::io::virtio::transport::VirtioTransport) {
        transport.notify_queue(self.index);
    }

    /// Check if the device has produced any used elements
    pub fn has_pending(&self) -> bool {
        self.last_used_idx.load(Ordering::Acquire) != self.get_used_idx()
    }

    /// Poll for a single completed request
    pub fn poll_completion(&mut self) -> Option<(u16, u32)> {
        let last_used = self.last_used_idx.load(Ordering::Acquire);
        let used_idx = self.get_used_idx();

        if last_used == used_idx {
            return None;
        }

        let elem = self.get_used_elem(last_used % self.queue_size);
        self.last_used_idx
            .store(last_used.wrapping_add(1), Ordering::Release);

        Some((elem.id as u16, elem.len))
    }

    /// Poll for all completed requests in bulk
    pub fn poll_completions<F>(&mut self, mut on_complete: F) -> usize
    where
        F: FnMut(u16, u32),
    {
        let mut count = 0;
        while let Some((id, len)) = self.poll_completion() {
            on_complete(id, len);
            count += 1;
        }
        count
    }
}
