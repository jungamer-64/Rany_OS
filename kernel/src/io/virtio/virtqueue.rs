use crate::io::dma::CoherentDmaBuffer;
use crate::io::iommu::types::DmaAddr;

use virtio_driver::core::VirtQueue as InnerVirtQueue;
pub use virtio_driver::defs::{
    VIRTIO_F_INDIRECT_DESC, VIRTQUEUE_MAX_SIZE, VRING_AVAIL_ALIGN, VRING_DESC_ALIGN,
    VRING_USED_ALIGN, VringAvailHeader as VringAvail, VringDesc, VringUsedElem,
    VringUsedHeader as VringUsed, vring_flags,
};

/// Virtqueue implementation (Kernel Wrapper)
#[derive(Debug)]
pub struct VirtQueue {
    /// Inner implementation from virtio_driver crate
    inner: InnerVirtQueue,
    /// DMA Buffer to keep memory alive
    dma_buffer: Option<CoherentDmaBuffer>,
}

// SAFETY: VirtQueue is thread-safe because the inner implementation is Sync.
unsafe impl Send for VirtQueue {}
unsafe impl Sync for VirtQueue {}

impl VirtQueue {
    /// Calculate required memory size for a virtqueue
    pub fn calculate_layout(queue_size: u16) -> (usize, usize, usize, usize) {
        virtio_driver::core::VirtQueue::calculate_layout(queue_size)
    }

    /// Initialize a VirtQueue with pre-allocated memory regions
    pub unsafe fn new(
        queue_size: u16,
        desc_table: *mut VringDesc,
        avail_ring: *mut VringAvail,
        used_ring: *mut VringUsed,
        dma_buffer: Option<CoherentDmaBuffer>,
        index: u16,
        features: u64,
    ) -> Self {
        let inner = InnerVirtQueue::new(
            index,
            queue_size,
            desc_table,
            avail_ring as *mut virtio_driver::defs::VringAvailHeader,
            used_ring as *mut virtio_driver::defs::VringUsedHeader,
            features,
        )
        .expect("Failed to initialize VirtQueue inner");

        Self { inner, dma_buffer }
    }

    pub fn index(&self) -> u16 {
        self.inner.queue_index()
    }
    pub fn size(&self) -> u16 {
        self.inner.queue_size()
    }
    pub fn features(&self) -> u64 {
        self.inner.features()
    }

    pub fn alloc_desc(&self) -> Option<u16> {
        self.inner.alloc_desc()
    }
    pub fn free_desc(&self, idx: u16) {
        self.inner.free_desc(idx)
    }
    pub fn free_desc_chain(&self, head: u16) {
        self.inner.free_desc_chain(head)
    }

    pub unsafe fn submit(&mut self, head: u16) -> u16 {
        unsafe {
            self.inner.submit_avail(head);
        }
        self.inner.queue_index()
    }

    pub unsafe fn submit_indirect(&mut self, table_phys: DmaAddr, count: u16) -> Option<u16> {
        self.inner.submit_indirect(table_phys.as_u64(), count)
    }

    pub fn notify(&self, transport: &dyn crate::io::virtio::transport::VirtioTransport) {
        self.inner.notify(transport)
    }

    pub fn poll_complete(&mut self) -> Option<(u16, u32)> {
        self.inner.poll_complete()
    }

    pub fn poll_completions<F>(&mut self, mut on_complete: F) -> usize
    where
        F: FnMut(u16, u32),
    {
        let mut count = 0;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while let Some((id, len)) = self.inner.poll_complete() {
            on_complete(id, len);
            count += 1;
        }
        count
    }

    pub fn has_pending(&self) -> bool {
        self.inner.has_pending()
    }

    pub fn available_descriptors(&self) -> usize {
        self.inner.free_count() as usize
    }

    pub fn desc_table_ptr(&self) -> *mut VringDesc {
        unsafe { self.inner.desc_table_ptr() as *mut VringDesc }
    }

    pub fn inner(&self) -> &InnerVirtQueue {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut InnerVirtQueue {
        &mut self.inner
    }
}
