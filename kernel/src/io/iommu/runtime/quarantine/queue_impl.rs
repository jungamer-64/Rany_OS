// ============================================================================
// kernel/src/io/iommu/runtime/quarantine/queue_impl.rs
// ============================================================================

use super::*;

impl QuarantineQueue {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(IrqMutex::new(QuarantineQueueInner::new())),
            completed_batch: Arc::new(AtomicU64::new(0)),
            poisoned: Arc::new(AtomicBool::new(false)),
        })
    }

    /// PRIVATE: Poison the queue and wake all waiters to prevent hangs.
    /// Used when a critical invariant is violated.
    pub(super) fn poison_system(&self) {
        // Only do this once
        if self.poisoned.swap(true, Ordering::AcqRel) {
            return;
        }

        // Collect wakers to wake OUTSIDE the lock (Round 14)
        // Waking inside lock is dangerous (potential deadlocks/re-entrancy)
        let mut to_wake = alloc::vec::Vec::new();
        {
            let mut inner = self.inner.lock();
            for entry in inner.entries.iter_mut() {
                if let Some(waker) = entry.waker.take() {
                    to_wake.push(waker);
                }
            }
        } // Drop lock

        for waker in to_wake {
            waker.wake();
        }
    }

    /// Reserve a slot in the queue (Raw version)
    pub(crate) fn reserve_slot(&self) -> Result<(u32, u32, u64), QuarantineError> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(QuarantineError::Poisoned);
        }
        let mut inner = self.inner.lock();
        // Round 14: Double-check poison after lock to be strict
        if self.poisoned.load(Ordering::Acquire) {
            return Err(QuarantineError::Poisoned);
        }

        if inner.active_count >= QUARANTINE_CAPACITY as u32 {
            return Err(QuarantineError::QueueFull);
        }

        if let Some(slot) = inner.find_free_slot() {
            // Split borrow: Calculate and update generation first
            let idx = slot as usize;

            // Update generation (does not require borrowing entries)
            inner.slot_generations[idx] = inner.slot_generations[idx].wrapping_add(1);
            let slot_gen = inner.slot_generations[idx];

            // Get batch ID
            let batch_id = inner.current_batch;

            // NOW borrow entry mutably
            let entry = &mut inner.entries[idx];

            // Round 9 Must-fix: valid reset ensures no stale state
            entry.reset();

            entry.batch_id = batch_id; // Mark as used (non-zero)
            entry.in_use = true; // Mark as in use
            // entry.raw = None; // Covered by reset()
            // entry.committed = false; // Covered by reset()

            inner.active_count += 1;
            inner.next_slot = (slot + 1) % (QUARANTINE_CAPACITY as u32);

            Ok((slot, slot_gen, batch_id))
        } else {
            Err(QuarantineError::QueueFull)
        }
    }

    /// Reserve a slot in the queue (Guarded version)
    /// Round 9: Returns RAII guard
    pub fn reserve_slot_guarded(&self) -> Result<QuarantineSlotGuard, QuarantineError> {
        let (slot_idx, slot_gen, batch_id) = self.reserve_slot()?;
        Ok(QuarantineSlotGuard {
            queue: self.clone(),
            slot_idx,
            slot_gen,
            batch_id,
            committed: false,
            pte_cleared: false,
        })
    }

    /// Check if the queue has capacity for new entries.
    ///
    /// This is a non-blocking check that can be used before attempting
    /// to reserve a slot, enabling backpressure in async contexts.
    #[inline]
    pub fn has_capacity(&self) -> bool {
        if self.poisoned.load(Ordering::Acquire) {
            return false;
        }
        let inner = self.inner.lock();
        inner.active_count < QUARANTINE_CAPACITY as u32
    }

    /// Get current utilization (active_count / capacity).
    ///
    /// Returns a value between 0.0 and 1.0.
    #[inline]
    pub fn utilization(&self) -> f32 {
        let inner = self.inner.lock();
        inner.active_count as f32 / QUARANTINE_CAPACITY as f32
    }

    /// Register a waker to be notified when capacity becomes available.
    ///
    /// This enables async backpressure: instead of synchronously flushing
    /// when the queue is full, callers can await capacity.
    ///
    /// The waker is stored in a dedicated slot and will be woken when
    /// any entry is released (during reap_completed).
    pub fn register_capacity_waker(&self, waker: &Waker) {
        let mut inner = self.inner.lock();
        inner.capacity_waker = Some(waker.clone());
    }

    /// Poll for available capacity (backpressure pattern).
    ///
    /// Returns `Poll::Ready(())` if there is capacity for at least one entry.
    /// Returns `Poll::Pending` if the queue is full, registering the waker.
    ///
    /// This enables async code to wait for capacity without blocking:
    /// ```ignore
    /// // Instead of:
    /// if queue.reserve_slot().is_err() {
    ///     domain.flush(invalidator, context)?; // Blocking!
    /// }
    ///
    /// // Use:
    /// poll_fn(|cx| queue.poll_capacity(cx)).await;
    /// let slot = queue.reserve_slot_guarded()?;
    /// ```
    pub fn poll_capacity(&self, cx: &mut Context<'_>) -> Poll<()> {
        if self.poisoned.load(Ordering::Acquire) {
            // Queue is poisoned, return Ready to propagate error on next operation
            return Poll::Ready(());
        }

        let mut inner = self.inner.lock();
        if inner.active_count < QUARANTINE_CAPACITY as u32 {
            Poll::Ready(())
        } else {
            // Queue is full, register waker and return Pending
            inner.capacity_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    /// Reserve space for an invalidation request
    ///
    /// Call this after reserve_slot() but before PTE clear.
    /// If this fails, call rollback_slot().
    ///
    /// Round 7+8: Reserve invalidation slot (before PTE clear)
    ///
    /// Returns (inv_slot_idx, inv_gen) which must be passed to commit_invalidation() after PTE clear.
    /// Round 8: Added gen token for ABA prevention.
    /// This ensures the invalidation cannot be drained until PTE is actually cleared.
    pub(crate) fn reserve_invalidation_slot(
        &self,
        expected_batch: u64,
    ) -> Result<(usize, u32), QuarantineError> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(QuarantineError::Poisoned);
        }
        let mut inner = self.inner.lock();

        // Check batch hasn't advanced (flush raced)
        if inner.current_batch != expected_batch {
            return Err(QuarantineError::BatchAdvanced);
        }

        if inner.pending_count >= INVALIDATION_CAPACITY {
            return Err(QuarantineError::InvalidationRingFull);
        }

        // Find empty slot in pending array
        // Use index loop to avoid borrow checker issues with split borrows
        for idx in 0..INVALIDATION_CAPACITY {
            if matches!(inner.pending_invalidations[idx], InvSlot::Empty) {
                // Round 8: Increment generation and use it
                inner.inv_generations[idx] = inner.inv_generations[idx].wrapping_add(1);
                let inv_gen_token = inner.inv_generations[idx];

                inner.pending_invalidations[idx] = InvSlot::Reserved { expected_batch };
                inner.pending_count += 1;
                return Ok((idx, inv_gen_token));
            }
        }

        Err(QuarantineError::InvalidationRingFull)
    }

    /// Reserve invalidation slot (Guarded version)
    /// Round 9: Returns RAII guard
    pub fn reserve_invalidation_slot_guarded(
        &self,
        expected_batch: u64,
    ) -> Result<InvSlotGuard, QuarantineError> {
        let (idx, gen_token) = self.reserve_invalidation_slot(expected_batch)?;
        Ok(InvSlotGuard {
            queue: self.clone(),
            idx,
            gen_token,
            committed: false,
            pte_cleared: false,
        })
    }

    /// Drain pending invalidations
    ///
    /// Round 9: Returns DrainResult to force caller to handle "NotReady" case.
    /// - NoWork: No invalidations pending.
    /// - NotReady: Pending invalidations exist but some are Reserved (PTE clear in progress).
    ///             Caller MUST NOT issue invalidations or advance batch.
    /// - Drained: All pending invalidations are Ready. Returns requests to issue.
    ///
    /// The caller is responsible for issuing the invalidations and then calling `reap_completed`.
    ///
    /// `requests` is cleared and populated with drained invalidations.
    /// The buffer must have been pre-allocated with sufficient capacity.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if the buffer capacity is insufficient.
    /// In release builds, excess requests are dropped with an error log.
    /// Pass 1: Verify no Reserved slots exist in pending invalidations.
    /// Returns Some(batch) if corruption is detected, None if all clear.
    pub(super) fn verify_no_reserved_slots(&self, inner: &QuarantineQueueInner) -> Option<u64> {
        for slot in inner.pending_invalidations.iter() {
            if let InvSlot::Reserved { .. } = slot {
                debug_assert!(
                    false,
                    "drain saw Reserved despite counts - state corruption"
                );
                return Some(inner.current_batch);
            }
        }
        None
    }

    pub fn drain_pending_invalidations(
        &self,
        requests: &mut alloc::vec::Vec<InvalidateRequest>,
    ) -> DrainResult {
        requests.clear();

        // ISR-Safety: No dynamic allocation in critical path.
        // If capacity is insufficient, log error but don't allocate.
        // The caller should have pre-allocated with INVALIDATION_CAPACITY.
        debug_assert!(
            requests.capacity() >= INVALIDATION_CAPACITY,
            "flush_requests buffer must be pre-allocated with INVALIDATION_CAPACITY"
        );

        let mut inner = self.inner.lock();

        if self.poisoned.load(Ordering::Acquire) {
            return DrainResult::Poisoned {
                batch: inner.current_batch,
            };
        }

        if inner.pending_count == 0 {
            return DrainResult::NoWork {
                batch: inner.current_batch,
            };
        }

        if inner.ready_count != inner.pending_count {
            return DrainResult::NotReady {
                batch: inner.current_batch,
            };
        }

        // Round 12: 2-Pass Drain for Safety
        // Pass 1: Verify NO Reserved slots exist
        if let Some(batch) = self.verify_no_reserved_slots(&inner) {
            drop(inner);
            self.poison_system();
            return DrainResult::Poisoned { batch };
        }

        let drained_batch = inner.current_batch;

        // Pass 2: Drain (Mutation)
        for slot in inner.pending_invalidations.iter_mut() {
            match core::mem::replace(slot, InvSlot::Empty) {
                InvSlot::Ready(req) => requests.push(req),
                InvSlot::Empty => {}
                InvSlot::Reserved { .. } => {
                    debug_assert!(false, "Unreachable: Reserved found in pass 2");
                }
            }
        }

        inner.pending_count = 0;
        inner.ready_count = 0;

        inner.current_batch = inner.current_batch.wrapping_add(1);
        if inner.current_batch == 0 {
            inner.current_batch = 1;
        }

        DrainResult::Drained {
            batch: drained_batch,
        }
    }

    /// Round 7+8: Commit invalidation (after PTE clear)
    ///
    /// Marks the reserved slot as Ready so it can be drained.
    /// Round 8: Added gen check for ABA prevention.
    /// This is called AFTER PTE has been cleared to ensure correct ordering.
    pub fn commit_invalidation(
        &self,
        inv_slot_idx: usize,
        inv_gen: u32,
        req: InvalidateRequest,
    ) -> Result<(), QuarantineError> {
        let mut inner = self.inner.lock();

        if inv_slot_idx >= INVALIDATION_CAPACITY {
            return Err(QuarantineError::SlotGenerationMismatch);
        }

        // Round 8: Check generation matches
        if inner.inv_generations[inv_slot_idx] != inv_gen {
            return Err(QuarantineError::SlotGenerationMismatch);
        }

        // Capture current batch before mutable borrow of slot
        let current_batch = inner.current_batch;

        let slot = &mut inner.pending_invalidations[inv_slot_idx];
        match slot {
            InvSlot::Reserved { expected_batch } => {
                // Round 8 bonus: Verify batch hasn't advanced beyond what we reserved
                if current_batch != *expected_batch {
                    drop(inner);
                    self.poison_system();
                    log::error!(
                        "CRITICAL: Quarantine batch advanced before commit_invalidation. Queue POISONED."
                    );
                    crate::io::iommu::runtime::security::notify_security_listener(
                        crate::io::iommu::runtime::security::SecurityEvent::QuarantinePoisoned {
                            domain_id: 0,
                        },
                    );
                    return Err(QuarantineError::Poisoned);
                }
                *slot = InvSlot::Ready(req);
                inner.ready_count += 1;
                Ok(())
            }
            _ => Err(QuarantineError::SlotGenerationMismatch),
        }
    }

    /// Round 7+8: Rollback invalidation slot (if PTE clear fails)
    /// Round 8: Added gen check for ABA prevention.
    pub fn rollback_invalidation_slot(&self, inv_slot_idx: usize, inv_gen: u32) {
        let mut inner = self.inner.lock();

        if inv_slot_idx >= INVALIDATION_CAPACITY {
            return;
        }

        // Round 8: Check generation matches
        if inner.inv_generations[inv_slot_idx] != inv_gen {
            return;
        }

        let slot = &mut inner.pending_invalidations[inv_slot_idx];
        if let InvSlot::Reserved { .. } = slot {
            *slot = InvSlot::Empty;
            inner.pending_count = inner.pending_count.saturating_sub(1);
        }
    }

    /// Rollback a reserved slot (if subsequent operations fail before commit)
    pub fn rollback_slot(&self, slot: u32, slot_gen: u32) {
        let mut inner = self.inner.lock();

        if slot as usize >= QUARANTINE_CAPACITY {
            return;
        }

        // Read slot_gen first to avoid borrow conflict
        let current_slot_gen = inner.slot_generations[slot as usize];
        let entry = &mut inner.entries[slot as usize];
        if entry.in_use && current_slot_gen == slot_gen {
            entry.reset();
            inner.active_count = inner.active_count.saturating_sub(1);
        }
    }

    pub(super) fn handle_late_commit(
        late_free: Option<(u64, u64)>,
        late_wake: Option<core::task::Waker>,
        context: &dyn IommuHardwareContext,
    ) {
        if let Some((iova_to_free, size)) = late_free {
            let _ = context.free_iova(iova_to_free, size);
        }
        if let Some(waker) = late_wake {
            waker.wake();
        }
    }

    /// Commit an entry after PTE clear and RRef decomposition
    ///
    /// Must be called after reserve_slot() and reserve_invalidation() succeed,
    /// and after PTE has been cleared.
    ///
    /// Round 6: Handles late commit IOVA leak - if reap already ran, free IOVA here.
    pub fn commit_entry(
        &self,
        slot: u32,
        slot_gen: u32,
        batch_id: u64,
        raw: RRefRawParts,
        iova: u64,
        iova_size: u64,
        context: &dyn IommuHardwareContext, // Round 6: Added for late commit IOVA free
    ) -> Result<(), QuarantineError> {
        let mut late_free: Option<(u64, u64)> = None;
        let mut late_wake: Option<core::task::Waker> = None;

        {
            let mut inner = self.inner.lock();

            if slot as usize >= QUARANTINE_CAPACITY {
                // Drop raw parts if slot is out of bounds
                unsafe { raw.drop_erased() };
                return Err(QuarantineError::SlotMismatch);
            }

            // Read slot_gen first to avoid borrow conflict
            let current_slot_gen = inner.slot_generations[slot as usize];

            let entry = &mut inner.entries[slot as usize];
            if !entry.in_use || current_slot_gen != slot_gen {
                // Slot was already rolled back or reused - drop the raw parts
                unsafe { raw.drop_erased() };
                return Err(QuarantineError::SlotMismatch);
            }

            // Round 10: Verify batch consistency before taking ownership of raw
            debug_assert_eq!(entry.batch_id, batch_id, "Commit batch_id mismatch");
            if entry.batch_id != batch_id {
                // Clean up and return error if mismatched
                unsafe { raw.drop_erased() };
                return Err(QuarantineError::SlotMismatch);
            }

            entry.raw = Some(raw);
            // entry.batch_id = batch_id; // already checked matches
            entry.iova = iova;
            entry.iova_size = iova_size;
            entry.abandoned = false;
            entry.committed = true;

            // Round 6: Check if this is a late commit (reap already ran)
            let completed = self.completed_batch.load(Ordering::Acquire);
            if completed >= batch_id {
                // Late commit: reap already ran and skipped this entry because
                // it was uncommitted. We must free IOVA here to prevent leak.
                if entry.iova != 0 && entry.iova_size != 0 {
                    late_free = Some((entry.iova, entry.iova_size));
                    entry.iova = 0;
                    entry.iova_size = 0;
                }
                late_wake = entry.waker.take();
            }
        } // unlock

        Self::handle_late_commit(late_free, late_wake, context);

        Ok(())
    }

    /// Get the current batch ID
    pub fn current_batch(&self) -> u64 {
        self.inner.lock().current_batch
    }

    /// Poll for entry completion
    ///
    /// Returns Ready if batch is complete and entry is available.
    /// Registers waker if pending.
    ///
    /// Uses double-check pattern to avoid lost wake (Must-fix 1).
    pub fn poll_entry<T: 'static>(
        &self,
        slot: u32,
        slot_gen: u32,
        batch_id: u64,
        cx: &mut Context<'_>,
    ) -> Poll<Result<RRef<T>, QuarantineError>> {
        // Round 14: Fail-fast if poisoned
        if self.poisoned.load(Ordering::Acquire) {
            return Poll::Ready(Err(QuarantineError::Poisoned));
        }

        if !self.wait_for_batch(slot, slot_gen, batch_id, cx) {
            return Poll::Pending;
        }

        self.take_completed_entry(slot, slot_gen, cx)
    }

    /// Spin until the batch is complete, registering a waker if still pending.
    /// Returns `true` if the batch has completed, `false` if still pending.
    pub(super) fn wait_for_batch(
        &self,
        slot: u32,
        slot_gen: u32,
        batch_id: u64,
        cx: &mut Context<'_>,
    ) -> bool {
        loop {
            let completed = self.completed_batch.load(Ordering::Acquire);
            if completed >= batch_id {
                return true;
            }
            self.poll_register_waker(slot, slot_gen, cx);
            // Double-check: if batch completed while we were registering, retry
            if self.completed_batch.load(Ordering::Acquire) >= batch_id {
                continue;
            }
            return false;
        }
    }

    /// Register the waker for a pending entry under lock.
    pub(super) fn poll_register_waker(&self, slot: u32, slot_gen: u32, cx: &mut Context<'_>) {
        let mut inner = self.inner.lock();
        if (slot as usize) < QUARANTINE_CAPACITY {
            let current_slot_gen = inner.slot_generations[slot as usize];
            let entry = &mut inner.entries[slot as usize];
            if entry.in_use && current_slot_gen == slot_gen {
                let w = cx.waker();
                let should_replace = entry.waker.as_ref().map_or(true, |old| !old.will_wake(w));
                if should_replace {
                    entry.waker = Some(w.clone());
                }
            }
        }
    }

    /// Take raw parts of a completed entry under lock, then reconstruct `RRef<T>`.
    pub(super) fn take_completed_entry<T: 'static>(
        &self,
        slot: u32,
        slot_gen: u32,
        cx: &mut Context<'_>,
    ) -> Poll<Result<RRef<T>, QuarantineError>> {
        let raw = {
            let mut inner = self.inner.lock();

            if slot as usize >= QUARANTINE_CAPACITY {
                return Poll::Ready(Err(QuarantineError::SlotGenerationMismatch));
            }

            let current_slot_gen = inner.slot_generations[slot as usize];
            if current_slot_gen != slot_gen {
                return Poll::Ready(Err(QuarantineError::SlotGenerationMismatch));
            }

            let entry = &mut inner.entries[slot as usize];

            if !entry.in_use {
                return Poll::Ready(Err(QuarantineError::SlotGenerationMismatch));
            }

            if !entry.committed {
                let w = cx.waker();
                let should_replace = entry.waker.as_ref().map_or(true, |old| !old.will_wake(w));
                if should_replace {
                    entry.waker = Some(w.clone());
                }
                return Poll::Pending;
            }

            if entry.abandoned {
                return Poll::Ready(Err(QuarantineError::EntryAbandoned));
            }

            let raw = entry.raw.take();
            entry.reset();
            inner.active_count = inner.active_count.saturating_sub(1);
            raw
        };

        let raw = raw.ok_or(QuarantineError::TypeMismatch)?;
        let rref = unsafe { raw.into_rref::<T>()? };
        Poll::Ready(Ok(rref))
    }

    /// Mark an entry as abandoned (called when Ticket is dropped without polling)
    ///
    /// Round 3: Read completed INSIDE lock for proper double-check.
    /// If batch is already complete, immediately reclaim the entry.
    pub fn mark_abandoned(&self, slot: u32, slot_gen: u32, batch_id: u64) {
        let mut inner = self.inner.lock();

        if slot as usize >= QUARANTINE_CAPACITY {
            return;
        }

        // Read slot_gen first to avoid borrow conflict
        let current_slot_gen = inner.slot_generations[slot as usize];
        let entry = &mut inner.entries[slot as usize];

        if !entry.in_use || current_slot_gen != slot_gen {
            return;
        }

        // Round 3: If not committed yet (early reserve rollback), just reset
        if !entry.committed {
            entry.reset();
            inner.active_count = inner.active_count.saturating_sub(1);
            return;
        }

        // Round 3: Read completed INSIDE lock for proper double-check
        let completed = self.completed_batch.load(Ordering::Acquire);

        if completed >= batch_id {
            // Batch is complete - IOVA was already freed by reap_completed
            // We just need to drop raw parts and reset slot
            if let Some(raw) = entry.raw.take() {
                // SAFETY: drop_fn was set correctly when RRefRawParts was created
                unsafe { raw.drop_erased() };
            }
            entry.reset();
            inner.active_count = inner.active_count.saturating_sub(1);
        } else {
            // Batch not complete - just mark abandoned for reap_completed to handle
            entry.abandoned = true;
        }
    }

    /// Drain pending invalidations for flush
    ///
    /// Round 7: Only drains Ready slots (not Reserved).
    /// Round 8: Does NOT advance batch if Reserved slots remain.
    ///
    /// Requests are written into a caller-provided buffer to avoid per-flush allocations.

    /// Reap completed entries after flush
    ///
    /// # Context
    ///
    /// Must be called from thread/executor context. This method allocates and
    /// drops RRef raw parts, so it is not ISR-safe.
    ///
    /// Round 5 fix:
    /// - scan → publish → unlock order (prevents poll_entry race on IOVA)
    /// - Compute scan_threshold = max(old, completed_batch) inside lock
    /// - Zero IOVA on collect (idempotent, prevents double free)
    /// - Heavy operations (free_iova, drop_erased) OUTSIDE lock
    pub fn reap_completed(
        &self,
        completed_batch: u64,
        fctx: &mut FlushContext,
        context: &dyn IommuHardwareContext,
    ) {
        let mut capacity_waker: Option<Waker> = None;
        let mut freed_slots = false;

        {
            let mut inner = self.inner.lock();

            let old = self.completed_batch.load(Ordering::Relaxed);
            let scan_threshold = if completed_batch > old {
                completed_batch
            } else {
                old
            };

            for slot_idx in 0..QUARANTINE_CAPACITY {
                if scan_entry_for_reap(
                    &mut inner.entries[slot_idx],
                    scan_threshold,
                    &mut fctx.to_free_iova,
                    &mut fctx.to_wake,
                    &mut fctx.to_drop,
                ) {
                    inner.active_count = inner.active_count.saturating_sub(1);
                    freed_slots = true;
                }
            }

            if scan_threshold > old {
                self.completed_batch
                    .store(scan_threshold, Ordering::Release);
            }

            if freed_slots {
                capacity_waker = inner.capacity_waker.take();
            }
        }

        flush_reaped_resources(
            &mut fctx.to_free_iova,
            &mut fctx.to_drop,
            &mut fctx.to_wake,
            capacity_waker,
            context,
        );
    }

    /// Check if any part of the given IOVA range is currently in the quarantine.
    pub fn is_range_quarantined(&self, iova: u64, size: u64) -> bool {
        if size == 0 {
            return false;
        }
        let end = iova.saturating_add(size);
        let inner = self.inner.lock();

        for entry in inner.entries.iter() {
            if entry.in_use && entry.iova != 0 {
                let entry_end = entry.iova.saturating_add(entry.iova_size);
                // Check for overlap: [iova, end) and [entry.iova, entry_end)
                if iova < entry_end && entry.iova < end {
                    return true;
                }
            }
        }
        false
    }

    /// Get statistics
    pub fn stats(&self) -> QuarantineStats {
        let inner = self.inner.lock();
        QuarantineStats {
            active_count: inner.active_count,
            pending_invalidations: inner.pending_count,
            current_batch: inner.current_batch,
            completed_batch: self.completed_batch.load(Ordering::Relaxed),
            poisoned: self.poisoned.load(Ordering::Acquire),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_commit_invalidation_batch_advance_poisoned() {
        let queue = QuarantineQueue::new();
        let expected_batch = {
            let inner = queue.inner.lock();
            inner.current_batch
        };
        let (inv_slot_idx, inv_gen) = queue
            .reserve_invalidation_slot(expected_batch)
            .expect("reserve invalidation slot");

        {
            let mut inner = queue.inner.lock();
            inner.current_batch = inner.current_batch.wrapping_add(1);
        }

        let err = queue
            .commit_invalidation(inv_slot_idx, inv_gen, InvalidateRequest::domain(1))
            .expect_err("batch advance should poison queue");

        assert_eq!(err, QuarantineError::Poisoned);
        assert!(queue.poisoned.load(Ordering::Acquire));
        assert!(
            matches!(
                queue.inner.lock().pending_invalidations[inv_slot_idx],
                InvSlot::Reserved { .. }
            ),
            "reserved invalidation slot must not be rolled back after PTE clear"
        );
        assert_eq!(
            queue
                .reserve_slot()
                .expect_err("poisoned queue must reject new work"),
            QuarantineError::Poisoned
        );
    }
}

impl Default for QuarantineQueue {
    fn default() -> Self {
        Self {
            inner: Arc::new(IrqMutex::new(QuarantineQueueInner::new())),
            completed_batch: Arc::new(AtomicU64::new(0)),
            poisoned: Arc::new(AtomicBool::new(false)),
        }
    }
}
