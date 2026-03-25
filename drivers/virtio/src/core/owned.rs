// ============================================================================
// drivers/virtio/src/core/owned.rs - Keepalive-backed VirtQueue wrapper
// ============================================================================

use crate::defs::{VringAvailHeader as VringAvail, VringDesc, VringUsedHeader as VringUsed};
use crate::transport::VirtioTransport;

/// VirtQueue wrapper that keeps the queue backing allocation alive.
#[derive(Debug)]
pub struct OwnedVirtQueue<K> {
    inner: super::virtqueue::VirtQueue,
    keepalive: Option<K>,
}

unsafe impl<K: Send> Send for OwnedVirtQueue<K> {}
unsafe impl<K: Sync> Sync for OwnedVirtQueue<K> {}

impl<K> OwnedVirtQueue<K> {
    pub fn calculate_layout(queue_size: u16) -> (usize, usize, usize, usize) {
        super::virtqueue::VirtQueue::calculate_layout(queue_size)
    }

    pub unsafe fn new(
        queue_index: u16,
        queue_size: u16,
        desc_table: *mut VringDesc,
        avail_ring: *mut VringAvail,
        used_ring: *mut VringUsed,
        keepalive: Option<K>,
        features: u64,
    ) -> Result<Self, &'static str> {
        let inner = unsafe {
            super::virtqueue::VirtQueue::new(
                queue_index,
                queue_size,
                desc_table,
                avail_ring,
                used_ring,
                features,
            )?
        };

        Ok(Self { inner, keepalive })
    }

    pub fn queue_index(&self) -> u16 {
        self.inner.queue_index()
    }

    pub fn queue_size(&self) -> u16 {
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

    pub fn submit(&self, head: u16) -> u16 {
        self.inner.submit(head)
    }

    pub unsafe fn submit_indirect(&self, indirect_table_phys: u64, count: u16) -> Option<u16> {
        unsafe { self.inner.submit_indirect(indirect_table_phys, count) }
    }

    pub fn notify(&self, transport: &dyn VirtioTransport) {
        self.inner.notify(transport)
    }

    pub fn poll_complete(&self) -> Option<(u16, u32)> {
        self.inner.poll_complete()
    }

    pub fn poll_completions<F>(&self, mut on_complete: F) -> usize
    where
        F: FnMut(u16, u32),
    {
        let mut count = 0;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.
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

    pub unsafe fn desc_table_ptr(&self) -> *mut VringDesc {
        unsafe { self.inner.desc_table_ptr() }
    }

    pub fn inner(&self) -> &super::virtqueue::VirtQueue {
        &self.inner
    }

    pub fn keepalive(&self) -> Option<&K> {
        self.keepalive.as_ref()
    }
}
