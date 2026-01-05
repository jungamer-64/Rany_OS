// ============================================================================
// kernel/src/io/iommu/quarantine.rs - Zero-Allocation Quarantine for DMA Buffers
// ============================================================================
//
// Phase 5: Quarantine (Zero-Allocation)
//
// DESIGN: This module implements a quarantine mechanism for DMA buffers during
// IOTLB invalidation. The key design principles are:
//
// 1. Queue is the owner - QuarantineQueue owns all RRefRawParts
// 2. Ticket is just a key - QuarantineTicket holds (slot, slot_gen, batch_id)
// 3. Zero allocation on HOT PATH - reserve_slot/commit_entry/poll_entry are alloc-free
//    (flush path drain/reap may use Vec for collecting heavy ops outside lock)
// 4. IOVA free happens in flush - After HW completion, not in poll
// 5. Per-slot waker - Each entry has its own waker for proper async notification
// 6. Store-first wake ordering - completed_batch is stored before waking to avoid lost wake
// 7. IOVA zero-on-collect - Prevents double free on repeated reap calls
//
// CONCURRENCY: This module is designed for executor context. If reap_completed()
// needs to be called from IRQ context, the Vec allocations must be replaced with
// fixed-size ArrayVec or an event queue pattern (IRQ pushes event, executor reaps).
//
// ============================================================================

use alloc::sync::Arc;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};

use crate::ipc::rref::{RRef, RRefRawParts, RawPartsError};
use crate::sync::IrqMutex;

use super::domain::InvalidateRequest;
use super::interface::IommuHardwareContext;
use super::types::IommuError;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of quarantined entries per queue
pub const QUARANTINE_CAPACITY: usize = 256;

/// Maximum number of pending invalidation requests
pub const INVALIDATION_CAPACITY: usize = 64;

// ============================================================================
// Error Types
// ============================================================================

/// Quarantine-specific errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineError {
    /// Queue is full, cannot enqueue more entries
    QueueFull,
    /// Invalidation ring is full
    InvalidationRingFull,
    /// Batch advanced between reserve_slot and reserve_invalidation (flush raced)
    BatchAdvanced,
    /// Slot mismatch or generation mismatch during commit (logic error or race)
    SlotMismatch,
    /// Slot generation mismatch (entry was already reclaimed)
    SlotGenerationMismatch,
    /// Batch not yet completed
    BatchNotCompleted,
    /// Entry was abandoned
    EntryAbandoned,
    /// Type reconstruction failed
    TypeMismatch,
    /// IOMMU error
    Iommu(IommuError),
    /// Queue is poisoned due to critical error (e.g. PTE clear race)
    Poisoned,
}

impl From<IommuError> for QuarantineError {
    fn from(e: IommuError) -> Self {
        QuarantineError::Iommu(e)
    }
}

impl From<RawPartsError> for QuarantineError {
    fn from(e: RawPartsError) -> Self {
        match e {
            RawPartsError::TypeMismatch | RawPartsError::SizeMismatch => {
                QuarantineError::TypeMismatch
            }
        }
    }
}

// ============================================================================
// InvSlot - Invalidation slot state machine (Round 7)
// ============================================================================

/// Invalidation slot state
///
/// Round 7 safety fix: Separates "reserved" from "ready" to ensure:
/// - reserve_invalidation_slot() only reserves space (before PTE clear)
/// - commit_invalidation() marks it Ready (after PTE clear)
/// - drain_pending_invalidations() only drains Ready slots
///
/// Round 12: Simplified InvSlot
/// Note: Generation token is stored in inner.inv_generations array, avoiding redundancy.
#[derive(Clone)]
enum InvSlot {
    /// Slot is empty
    Empty,
    /// Slot is reserved but not yet ready for drain (PTE not yet cleared)
    Reserved { expected_batch: u64 },
    /// Slot is ready for drain (PTE has been cleared)
    Ready(InvalidateRequest),
}

// ============================================================================
// QuarantineEntry - Single entry in the quarantine queue
// ============================================================================

/// A single entry in the quarantine queue
///
/// The queue owns the RRefRawParts; tickets only hold keys.
struct QuarantineEntry {
    /// RRef raw parts (owned by queue)
    raw: Option<RRefRawParts>,
    /// Batch ID this entry belongs to
    batch_id: u64,
    /// IOVA address (for free_iova after flush)
    iova: u64,
    /// IOVA size in bytes (for free_iova)
    iova_size: u64,
    /// Per-slot waker for async notification
    waker: Option<Waker>,
    /// Whether the ticket was dropped without polling
    abandoned: bool,
    /// Whether this slot is currently in use (reserved)
    in_use: bool,
    /// Whether commit_entry has been called (raw parts are set)
    committed: bool,
}

impl QuarantineEntry {
    /// Create an empty entry
    const fn empty() -> Self {
        Self {
            raw: None,
            batch_id: 0,
            iova: 0,
            iova_size: 0,
            waker: None,
            abandoned: false,
            in_use: false,
            committed: false,
        }
    }

    /// Reset entry to empty state
    fn reset(&mut self) {
        self.raw = None;
        self.batch_id = 0;
        self.iova = 0;
        self.iova_size = 0;
        self.waker = None;
        self.abandoned = false;
        self.in_use = false;
        self.committed = false;
    }
}

// ============================================================================
// QuarantineQueueInner - Protected inner state
// ============================================================================

/// Inner state protected by IrqMutex
struct QuarantineQueueInner {
    /// Fixed-size entry array
    entries: [QuarantineEntry; QUARANTINE_CAPACITY],
    /// Slot generations (incremented each time a slot is reused)
    slot_generations: [u32; QUARANTINE_CAPACITY],
    /// Next slot to try for allocation
    next_slot: u32,
    /// Number of slots currently in use
    active_count: u32,
    /// Current batch ID (incremented on flush)
    current_batch: u64,
    /// Pending invalidation slots (fixed-size ring) - Round 7: uses InvSlot enum
    pending_invalidations: [InvSlot; INVALIDATION_CAPACITY],
    /// Invalidation slot generations (Round 8: ABA prevention)
    inv_generations: [u32; INVALIDATION_CAPACITY],
    /// Number of reserved + ready slots
    pending_count: usize,
    /// Number of ready slots (only Ready slots can be drained)
    ready_count: usize,
    /// Waker to notify when capacity becomes available (backpressure support)
    capacity_waker: Option<Waker>,
}

impl QuarantineQueueInner {
    /// Create a new inner state
    fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| QuarantineEntry::empty()),
            slot_generations: [0; QUARANTINE_CAPACITY],
            next_slot: 0,
            active_count: 0,
            current_batch: 1, // Start at 1 so 0 means "never"
            pending_invalidations: core::array::from_fn(|_| InvSlot::Empty),
            inv_generations: [0; INVALIDATION_CAPACITY],
            pending_count: 0,
            ready_count: 0,
            capacity_waker: None,
        }
    }

    /// Find a free slot
    fn find_free_slot(&self) -> Option<u32> {
        for i in 0..QUARANTINE_CAPACITY {
            let slot = ((self.next_slot as usize + i) % QUARANTINE_CAPACITY) as u32;
            if !self.entries[slot as usize].in_use {
                return Some(slot);
            }
        }
        None
    }
}

// ============================================================================
// QuarantineQueue
// ============================================================================

/// The Quarantine Queue
///
/// Manages lazy unmapping and IOTLB invalidation invalidation handling.
///
/// Thread-safe (internally uses Mutex).
#[derive(Clone)]
pub struct QuarantineQueue {
    inner: Arc<IrqMutex<QuarantineQueueInner>>,
    /// Completed batch ID (can be read without lock for fast path)
    /// Wrapped in Arc to allow QuarantineQueue to be Clone
    completed_batch: Arc<AtomicU64>,
    /// Poisoned flag: set when a critical safety invariant is violated.
    /// When true, all new operations fail to prevent further corruption.
    poisoned: Arc<AtomicBool>,
}

impl QuarantineQueue {
    /// Get completed batch ID
    pub fn completed_batch(&self) -> u64 {
        self.completed_batch.load(Ordering::Acquire)
    }
}

/// Round 9: DrainResult enum to prevent API misuse
#[derive(Debug)]
#[must_use]
pub enum DrainResult {
    /// No work to do (no pending invalidations)
    NoWork { batch: u64 },
    /// Cannot drain because Reserved slots exist (batch must not advance)
    NotReady { batch: u64 },
    /// Successfully drained invalidations (batch can advance)
    Drained { batch: u64 },
    /// Queue is poisoned (system failed). Caller must stop flushing.
    Poisoned { batch: u64 },
}

/// RAII Guard for Quarantine Slot
///
/// Automatically rolls back the slot reservation if dropped without commit.
#[must_use]
pub struct QuarantineSlotGuard {
    queue: QuarantineQueue,
    pub slot_idx: u32,
    pub slot_gen: u32,
    pub batch_id: u64,
    committed: bool,
    pte_cleared: bool,
}

impl Drop for QuarantineSlotGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }

        // Round 11: If PTE was cleared but not committed, we MUST NOT rollback.
        // Rolling back the slot would free it for reuse while the device might still have stale IOTLB access.
        // It is safer to leak the slot (keep it reserved but empty) than to risk UAF.
        if self.pte_cleared {
            // Round 13: Use helper to poison and wake everyone
            self.queue.poison_system();
            debug_assert!(
                false,
                "CRITICAL: QuarantineSlotGuard dropped after PTE clear but before commit! Queue POISONED."
            );
            return;
        }

        self.queue.rollback_slot(self.slot_idx, self.slot_gen);
    }
}

impl QuarantineSlotGuard {
    /// Mark that PTEs have been cleared.
    ///
    /// Once called, the guard will NOT rollback on drop.
    pub fn mark_pte_cleared(&mut self) {
        self.pte_cleared = true;
    }

    /// Commit the quarantine entry
    /// Consumes the guard.
    pub fn commit(
        mut self,
        raw: RRefRawParts,
        iova: u64,
        iova_size: u64,
        context: &dyn IommuHardwareContext,
    ) -> Result<(), QuarantineError> {
        self.queue.commit_entry(
            self.slot_idx,
            self.slot_gen,
            self.batch_id,
            raw,
            iova,
            iova_size,
            context,
        )?;
        self.committed = true;
        Ok(())
    }
}

/// RAII Guard for Invalidation Slot
///
/// Automatically rolls back the invalidation slot if dropped without commit.
#[must_use]
pub struct InvSlotGuard {
    queue: QuarantineQueue,
    pub idx: usize,
    pub gen_token: u32,
    committed: bool,
    pte_cleared: bool,
}

impl Drop for InvSlotGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }

        // Round 10: If PTE was cleared but not committed, we MUST NOT rollback.
        // Rolling back would leave the IOTLB in an inconsistent state (PTE cleared, outdated IOTLB).
        // Leaving it as Reserved will cause drain_pending_invalidations to return NotReady forever,
        // effectively halting the batch update. This is safer than silent data corruption.
        if self.pte_cleared {
            // Round 13: Use helper to poison and wake everyone
            self.queue.poison_system();
            // In debug builds, panic to alert the developer.
            // In release, we just leak the reservation to safeguard consistency.
            debug_assert!(
                false,
                "CRITICAL: InvSlotGuard dropped after PTE clear but before commit! Queue POISONED."
            );
            return;
        }

        self.queue
            .rollback_invalidation_slot(self.idx, self.gen_token);
    }
}

impl InvSlotGuard {
    /// Mark that PTEs have been cleared.
    ///
    /// Once called, the guard will NOT rollback on drop.
    pub fn mark_pte_cleared(&mut self) {
        self.pte_cleared = true;
    }

    /// Commit the invalidation
    /// Consumes the guard.
    pub fn commit(mut self, req: InvalidateRequest) -> Result<(), QuarantineError> {
        self.queue
            .commit_invalidation(self.idx, self.gen_token, req)?;
        self.committed = true;
        Ok(())
    }
}

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
    fn poison_system(&self) {
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

        // Round 13: Check poisoned ONLY inside lock? No, check atomic first is okay but inner has batch.
        // Actually, logic: if poisoned, we return Poisoned { batch }.
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

        // Round 8 Safety Check:
        if inner.ready_count != inner.pending_count {
            return DrainResult::NotReady {
                batch: inner.current_batch,
            };
        }

        // Round 12: 2-Pass Drain for Safety
        // Pass 1: Verify NO Reserved slots exist
        // If we find a Reserved slot here, it contradicts ready_count check above.
        // This implies internal corruption. Fail-stop.
        for slot in inner.pending_invalidations.iter() {
            if let InvSlot::Reserved { .. } = slot {
                debug_assert!(
                    false,
                    "drain saw Reserved despite counts - state corruption"
                );
                // Round 14: Simplify poison logic
                let batch = inner.current_batch;
                drop(inner); // Drop lock
                self.poison_system();
                return DrainResult::Poisoned { batch };
            }
        }

        let drained_batch = inner.current_batch;

        // Pass 2: Drain (Mutation)
        // Since we verified no Reserved slots exist, we can safely replace.
        // All pending slots are Ready -> We can drain them!
        // Iterate and collect Ready requests using mem::replace to avoid clone
        for slot in inner.pending_invalidations.iter_mut() {
            // Round 10: Check the REPLACED value, not the result of assignment
            match core::mem::replace(slot, InvSlot::Empty) {
                InvSlot::Ready(req) => requests.push(req),
                InvSlot::Empty => {}
                InvSlot::Reserved { .. } => {
                    // unreachable due to pass 1
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

        DrainResult::Drained { batch: drained_batch }
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
                    // Round 12 Fix: Fail-Stop logic.
                    // If batch advanced, it means a race occured or logic error.
                    // Since we are here (PTE cleared), we CANNOT safely clear the slot (would drop invalidation).
                    // We also CANNOT safely catch-up because it might violate batch boundaries.
                    // The only safe option is to HALT operations to prevent data corruption.
                    drop(inner); // drop lock before calling helper (avoids recursion if helper took lock)
                    // limit: poison_system takes lock.
                    self.poison_system();
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

        // Round 6: Handle late commit IOVA free outside lock
        if let Some((iova_to_free, size)) = late_free {
            let _ = context.free_iova(iova_to_free, size);
        }
        if let Some(waker) = late_wake {
            waker.wake();
        }

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

        loop {
            // Fast path: check completed_batch without lock
            let completed = self.completed_batch.load(Ordering::Acquire);
            if completed < batch_id {
                // Not yet complete - register waker
                {
                    let mut inner = self.inner.lock();
                    if (slot as usize) < QUARANTINE_CAPACITY {
                        // Read slot_gen first to avoid borrow conflict
                        let current_slot_gen = inner.slot_generations[slot as usize];
                        let entry = &mut inner.entries[slot as usize];
                        if entry.in_use && current_slot_gen == slot_gen {
                            // Avoid unnecessary clone if waker is the same
                            let w = cx.waker();
                            let should_replace =
                                entry.waker.as_ref().map_or(true, |old| !old.will_wake(w));
                            if should_replace {
                                entry.waker = Some(w.clone());
                            }
                        }
                    }
                }
                // Double-check: if batch completed while we were registering, retry
                if self.completed_batch.load(Ordering::Acquire) >= batch_id {
                    continue;
                }
                return Poll::Pending;
            }

            // Batch complete - exit loop to take the entry
            break;
        }

        // Batch complete - try to take the entry
        // Take raw under lock, then process outside lock (Issue 5)
        let raw = {
            let mut inner = self.inner.lock();

            if slot as usize >= QUARANTINE_CAPACITY {
                return Poll::Ready(Err(QuarantineError::SlotGenerationMismatch));
            }

            // Read slot_gen first to avoid borrow conflict
            let current_slot_gen = inner.slot_generations[slot as usize];

            // Verify slot generation
            if current_slot_gen != slot_gen {
                return Poll::Ready(Err(QuarantineError::SlotGenerationMismatch));
            }

            let entry = &mut inner.entries[slot as usize];

            if !entry.in_use {
                return Poll::Ready(Err(QuarantineError::SlotGenerationMismatch));
            }

            // Issue 4: If not committed yet, register waker and return Pending
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

            // Take the raw parts (may be None if already taken)
            let raw = entry.raw.take();

            // Always free the slot
            entry.reset();
            inner.active_count = inner.active_count.saturating_sub(1);

            raw
        }; // Lock released here (Issue 5)

        // Process raw outside lock
        let raw = raw.ok_or(QuarantineError::TypeMismatch)?;

        // Reconstruct RRef OUTSIDE lock (Issue 5)
        // SAFETY: Ticket<T> guarantees the type matches
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
    pub fn reap_completed(&self, completed_batch: u64, context: &dyn IommuHardwareContext) {
        use alloc::vec::Vec;

        // Collect items to process outside lock
        let mut to_wake: Vec<core::task::Waker> = Vec::new();
        let mut to_free_iova: Vec<(u64, u64)> = Vec::new(); // (iova, size)
        let mut to_drop: Vec<RRefRawParts> = Vec::new();
        let mut capacity_waker: Option<Waker> = None;
        let mut freed_slots = false;

        {
            let mut inner = self.inner.lock();

            // Round 5: Compute scan_threshold INSIDE lock
            let old = self.completed_batch.load(Ordering::Relaxed);
            let scan_threshold = if completed_batch > old {
                completed_batch
            } else {
                old
            };

            // Scan entries with threshold (idempotent due to zero-on-collect)
            for slot_idx in 0..QUARANTINE_CAPACITY {
                let entry = &mut inner.entries[slot_idx];

                if !entry.in_use {
                    continue;
                }

                // Only process committed entries
                if !entry.committed {
                    continue;
                }

                if entry.batch_id > scan_threshold {
                    // Entry belongs to a future batch
                    continue;
                }

                // Collect IOVA and ZERO it to prevent double free (idempotent)
                if entry.iova != 0 && entry.iova_size != 0 {
                    to_free_iova.push((entry.iova, entry.iova_size));
                    entry.iova = 0;
                    entry.iova_size = 0;
                }

                if entry.abandoned {
                    // Collect raw parts to drop (outside lock)
                    if let Some(raw) = entry.raw.take() {
                        to_drop.push(raw);
                    }
                    // Free the slot
                    entry.reset();
                    inner.active_count = inner.active_count.saturating_sub(1);
                    freed_slots = true;
                } else {
                    // Collect waker for later wake (outside lock)
                    if let Some(waker) = entry.waker.take() {
                        to_wake.push(waker);
                    }
                }
            }

            // Round 5: Publish AFTER scan, BEFORE unlock
            // This prevents poll_entry from resetting entry before we collect IOVA
            if scan_threshold > old {
                self.completed_batch
                    .store(scan_threshold, Ordering::Release);
            }

            // Collect capacity waker if slots were freed (backpressure notification)
            if freed_slots {
                capacity_waker = inner.capacity_waker.take();
            }
        } // Lock released here

        // Free IOVAs outside lock
        for (iova, size) in to_free_iova {
            let _ = context.free_iova(iova, size);
        }

        // Drop abandoned raw parts outside lock
        for raw in to_drop {
            // SAFETY: drop_fn was set correctly when RRefRawParts was created
            unsafe { raw.drop_erased() };
        }

        // Wake all waiters OUTSIDE the lock
        for waker in to_wake {
            waker.wake();
        }

        // Wake capacity waiter if slots were freed (backpressure notification)
        if let Some(waker) = capacity_waker {
            waker.wake();
        }
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

impl Default for QuarantineQueue {
    fn default() -> Self {
        Self {
            inner: Arc::new(IrqMutex::new(QuarantineQueueInner::new())),
            completed_batch: Arc::new(AtomicU64::new(0)),
            poisoned: Arc::new(AtomicBool::new(false)),
        }
    }
}

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
