// ============================================================================
// src/sync/lockfree/index_stack.rs - Lock-Free Index Stack (runtime-capacity free-list)
// ============================================================================

use alloc::{boxed::Box, vec::Vec};
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use super::CacheLinePadded;
use super::backoff::Backoff;

/// Push error for [`LockFreeIndexStack`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockFreeIndexStackPushError {
    /// `idx` was outside the stack's capacity (`idx >= capacity`).
    OutOfRange,
    /// `idx` was already present in the stack (duplicate push).
    AlreadyPresent,
}

/// Lock-free stack specialized for `u32` indices.
///
/// This is intended for free-list style ownership transfer where each index is
/// stored in exactly one place at a time. It uses an ABA-resistant tagged head
/// pointer (32-bit tag + 32-bit index).
///
/// # Contract
/// - `idx < capacity`
/// - Pushing the same index twice concurrently (or without an intervening pop)
///   returns [`LockFreeIndexStackPushError::AlreadyPresent`]
/// - Internal invariants may still be violated by memory corruption or misuse
///   outside this API's contract
pub struct LockFreeIndexStack {
    head: CacheLinePadded<AtomicU64>,
    next: Box<[AtomicU32]>,
    present: Box<[AtomicU8]>,
    len: AtomicUsize,
}

impl LockFreeIndexStack {
    /// Sentinel value representing an empty head.
    pub const EMPTY_INDEX: u32 = u32::MAX;

    #[inline]
    const fn pack_head(tag: u32, idx: u32) -> u64 {
        ((tag as u64) << 32) | (idx as u64)
    }

    #[inline]
    const fn unpack_head(head: u64) -> (u32, u32) {
        ((head >> 32) as u32, head as u32)
    }

    fn make_next_array(capacity: usize) -> Box<[AtomicU32]> {
        let mut next = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            next.push(AtomicU32::new(Self::EMPTY_INDEX));
        }
        next.into_boxed_slice()
    }

    fn make_present_array(capacity: usize) -> Box<[AtomicU8]> {
        let mut present = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            present.push(AtomicU8::new(0));
        }
        present.into_boxed_slice()
    }

    /// Create an empty stack that can store indices in range `[0, capacity)`.
    pub fn new_empty(capacity: usize) -> Self {
        assert!(
            capacity <= u32::MAX as usize,
            "LockFreeIndexStack capacity exceeds u32::MAX"
        );
        Self {
            head: CacheLinePadded::new(AtomicU64::new(Self::pack_head(0, Self::EMPTY_INDEX))),
            next: Self::make_next_array(capacity),
            present: Self::make_present_array(capacity),
            len: AtomicUsize::new(0),
        }
    }

    /// Create a stack pre-filled with all indices in `[0, capacity)`.
    ///
    /// Elements are pushed in ascending order, so the first pop returns
    /// `capacity - 1` (LIFO).
    pub fn new_filled(capacity: usize) -> Self {
        let stack = Self::new_empty(capacity);
        for idx in 0..capacity {
            let result = stack.push(idx as u32);
            debug_assert!(result.is_ok(), "new_filled push failed at idx={idx}");
        }
        stack
    }

    /// Push an index onto the stack.
    ///
    /// Returns:
    /// - [`LockFreeIndexStackPushError::OutOfRange`] if `idx >= capacity`
    /// - [`LockFreeIndexStackPushError::AlreadyPresent`] if `idx` is already in
    ///   the stack (duplicate push)
    pub fn push(&self, idx: u32) -> Result<(), LockFreeIndexStackPushError> {
        let idx_usize = idx as usize;
        if idx_usize >= self.next.len() {
            return Err(LockFreeIndexStackPushError::OutOfRange);
        }
        if self.present[idx_usize]
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(LockFreeIndexStackPushError::AlreadyPresent);
        }

        let mut backoff = Backoff::new();
        loop {
            let head = self.head.load(Ordering::Acquire);
            let (tag, head_idx) = Self::unpack_head(head);

            // Safe to write before the CAS; if CAS fails we will overwrite `next[idx]`
            // with the new observed head and retry.
            self.next[idx_usize].store(head_idx, Ordering::Relaxed);

            let new_head = Self::pack_head(tag.wrapping_add(1), idx);
            match self.head.compare_exchange_weak(
                head,
                new_head,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.len.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                Err(_) => backoff.snooze(),
            }
        }
    }

    /// Pop an index from the stack.
    pub fn pop(&self) -> Option<u32> {
        let mut backoff = Backoff::new();
        loop {
            let head = self.head.load(Ordering::Acquire);
            let (tag, head_idx) = Self::unpack_head(head);
            if head_idx == Self::EMPTY_INDEX {
                return None;
            }

            let next_idx = self.next[head_idx as usize].load(Ordering::Acquire);
            let new_head = Self::pack_head(tag.wrapping_add(1), next_idx);

            match self.head.compare_exchange_weak(
                head,
                new_head,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    let was_present = self.present[head_idx as usize].swap(0, Ordering::AcqRel);
                    if was_present == 0 {
                        log::error!(
                            "[sync::lockfree] LockFreeIndexStack pop saw missing present bit for idx {}",
                            head_idx
                        );
                        debug_assert!(
                            was_present != 0,
                            "LockFreeIndexStack present bit missing on pop idx={head_idx}"
                        );
                    }
                    let prev = self.len.fetch_sub(1, Ordering::Relaxed);
                    debug_assert!(prev > 0, "LockFreeIndexStack len underflow");
                    return Some(head_idx);
                }
                Err(_) => backoff.snooze(),
            }
        }
    }

    /// Approximate length under concurrency, exact when quiescent.
    #[inline]
    pub fn len(&self) -> usize {
        self.len.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.next.len()
    }
}
