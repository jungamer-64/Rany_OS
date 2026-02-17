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
mod _split_1;
use _split_1::*;
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

// ---------------------------------------------------------------------------
// Reap helpers (free functions to keep QuarantineQueue methods lean)
// ---------------------------------------------------------------------------

/// Check if the entry should be skipped during reap.
#[inline]
fn should_skip_for_reap(entry: &QuarantineEntry, scan_threshold: u64) -> bool {
    !entry.in_use || !entry.committed || entry.batch_id > scan_threshold
}

/// Collect IOVA information from an entry and clear its IOVA fields.
#[inline]
fn collect_entry_iova(
    entry: &mut QuarantineEntry,
    to_free_iova: &mut alloc::vec::Vec<(u64, u64)>,
) {
    if entry.iova != 0 && entry.iova_size != 0 {
        to_free_iova.push((entry.iova, entry.iova_size));
        entry.iova = 0;
        entry.iova_size = 0;
    }
}

/// Inspect a single quarantine entry during reap. Returns true if the slot was freed.
fn scan_entry_for_reap(
    entry: &mut QuarantineEntry,
    scan_threshold: u64,
    to_free_iova: &mut alloc::vec::Vec<(u64, u64)>,
    to_wake: &mut alloc::vec::Vec<core::task::Waker>,
    to_drop: &mut alloc::vec::Vec<RRefRawParts>,
) -> bool {
    if should_skip_for_reap(entry, scan_threshold) {
        return false;
    }
    collect_entry_iova(entry, to_free_iova);
    if entry.abandoned {
        if let Some(raw) = entry.raw.take() {
            to_drop.push(raw);
        }
        entry.reset();
        return true;
    }
    if let Some(waker) = entry.waker.take() {
        to_wake.push(waker);
    }
    false
}

/// Process collected reap results outside the lock.
fn flush_reaped_resources(
    to_free_iova: alloc::vec::Vec<(u64, u64)>,
    to_drop: alloc::vec::Vec<RRefRawParts>,
    to_wake: alloc::vec::Vec<core::task::Waker>,
    capacity_waker: Option<Waker>,
    context: &dyn IommuHardwareContext,
) {
    for (iova, size) in to_free_iova {
        let _ = context.free_iova(iova, size);
    }
    for raw in to_drop {
        unsafe { raw.drop_erased() };
    }
    for waker in to_wake {
        waker.wake();
    }
    if let Some(waker) = capacity_waker {
        waker.wake();
    }
}
