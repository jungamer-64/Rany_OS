// ============================================================================
// drivers/virtio/src/core/tracked.rs - Tracked VirtQueue
// ============================================================================

use super::virtqueue::VirtQueue;
use crate::transport::VirtioTransport;
use alloc::collections::VecDeque;
use spin::Mutex;

/// A VirtQueue that tracks buffer ownership during in-flight operations.
pub struct TrackedVirtQueue<T> {
    inner: VirtQueue,
    /// Pending buffers indexed by descriptor head index.
    pending: Mutex<VecDeque<Option<T>>>,
}

impl<T> TrackedVirtQueue<T> {
    pub fn new(inner: VirtQueue) -> Self {
        let queue_size = inner.queue_size() as usize;
        let mut pending = VecDeque::with_capacity(queue_size);
        for _ in 0..queue_size {
            pending.push_back(None);
        }
        Self {
            inner,
            pending: Mutex::new(pending),
        }
    }

    pub fn inner(&self) -> &VirtQueue {
        &self.inner
    }

    /// Add a buffer and track its ownership.
    ///
    /// # Safety
    /// Same safety requirements as `VirtQueue`.
    pub unsafe fn add_buffer_tracked(
        &self,
        addr: u64,
        len: u32,
        writable: bool,
        buffer: T,
    ) -> Result<u16, &'static str> {
        let idx = self.inner.alloc_desc().ok_or("No free descriptors")?;

        let desc = self.inner.get_desc_mut(idx);
        desc.addr = addr;
        desc.len = len;
        desc.flags = if writable {
            crate::defs::vring_flags::VRING_DESC_F_WRITE
        } else {
            0
        };
        desc.next = 0;

        {
            let mut pending = self.pending.lock();
            pending[idx as usize] = Some(buffer);
        }

        unsafe {
            self.inner.submit_avail(idx);
        }
        Ok(idx)
    }

    /// Poll for a completed request and recover the tracked buffer.
    pub fn poll_complete_tracked(&self) -> Option<(u16, T, u32)> {
        let (idx, len) = self.inner.poll_complete()?;

        let buffer = {
            let mut pending = self.pending.lock();
            pending[idx as usize]
                .take()
                .expect("Tracked buffer missing for completed index")
        };

        self.inner.free_desc(idx);
        Some((idx, buffer, len))
    }

    pub fn notify(&self, transport: &dyn VirtioTransport) {
        self.inner.notify(transport);
    }
}
