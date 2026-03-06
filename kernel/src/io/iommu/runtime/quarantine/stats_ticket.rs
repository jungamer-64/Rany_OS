// ============================================================================
// kernel/src/io/iommu/runtime/quarantine/stats_ticket.rs
// ============================================================================

use super::*;

// ============================================================================
// QuarantineStats - Statistics for monitoring
// ============================================================================

/// Statistics about the quarantine queue
#[derive(Debug, Clone, Copy)]
pub struct QuarantineStats {
    /// Number of active entries
    pub active_count: u32,
    /// Number of pending invalidations
    pub pending_invalidations: usize,
    /// Current batch ID
    pub current_batch: u64,
    /// Completed batch ID
    pub completed_batch: u64,
    /// Whether the queue is poisoned
    pub poisoned: bool,
}

// ============================================================================
// QuarantineTicket - Ticket for retrieving quarantined buffer
// ============================================================================

/// Ticket for retrieving a quarantined DMA buffer
///
/// The ticket is just a key - it does not own the RRef.
/// The Queue owns the RRef until poll_complete() succeeds.
///
/// If the ticket is dropped without polling, the entry is marked
/// as abandoned and will be cleaned up during the next flush.
pub struct QuarantineTicket<T> {
    /// Reference to the queue (Arc for lifetime guarantee)
    queue: Arc<QuarantineQueue>,
    /// Slot index
    slot: u32,
    /// Slot generation (for ABA prevention)
    slot_gen: u32,
    /// Batch ID
    batch_id: u64,
    /// PhantomData for T
    _marker: PhantomData<T>,
}

impl<T: 'static> QuarantineTicket<T> {
    /// Create a new ticket
    pub(crate) fn new(
        queue: Arc<QuarantineQueue>,
        slot: u32,
        slot_gen: u32,
        batch_id: u64,
    ) -> Self {
        Self {
            queue,
            slot,
            slot_gen,
            batch_id,
            _marker: PhantomData,
        }
    }

    /// Poll for completion
    ///
    /// Returns Ready(Ok(rref)) when the IOTLB invalidation is complete
    /// and the RRef can be safely returned.
    pub fn poll_complete(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<RRef<T>, QuarantineError>> {
        self.queue
            .poll_entry::<T>(self.slot, self.slot_gen, self.batch_id, cx)
    }

    /// Check if the batch is complete (non-blocking)
    pub fn is_complete(&self) -> bool {
        self.queue.completed_batch.load(Ordering::Acquire) >= self.batch_id
    }

    /// Get the batch ID
    pub fn batch_id(&self) -> u64 {
        self.batch_id
    }
}

impl<T> Drop for QuarantineTicket<T> {
    fn drop(&mut self) {
        // Mark the entry as abandoned
        // If batch is already complete, mark_abandoned will immediately reclaim (Must-fix 2B)
        // Otherwise, the queue will clean it up during the next reap_completed()
        self.queue
            .mark_abandoned(self.slot, self.slot_gen, self.batch_id);
    }
}

// SAFETY: QuarantineTicket is Send+Sync because it only holds keys
// and an Arc to a Send+Sync queue
unsafe impl<T: Send> Send for QuarantineTicket<T> {}
unsafe impl<T: Sync> Sync for QuarantineTicket<T> {}
