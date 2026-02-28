// ============================================================================
// kernel/src/sync/atomic_waker.rs
// ============================================================================
//! Atomic Waker implementations for ISR-safe task notification.
//!
//! This module provides:
//! - `AtomicWaker`: Lock-free implementation using atomic state machine (ISR-safe)
//! - `WakerQueue`: Multi-waker queue for multiple concurrent waiters
//!
//! ## Lock-Free Design
//!
//! The `AtomicWaker` uses a state machine with atomic transitions:
//! - IDLE: No waker registered, no wake pending
//! - REGISTERING: A task is in the process of registering a waker
//! - WAITING: A waker is registered and waiting for notification
//! - WAKING: A wake has been requested
//!
//! This design eliminates Mutex contention in ISR contexts entirely.
#![allow(dead_code)]
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use core::task::Waker;
use spin::Mutex;

// ============================================================================
// Lock-Free AtomicWaker (State Machine Based)
// ============================================================================

/// State constants for lock-free atomic waker
mod state {
    pub const IDLE: u8 = 0;
    pub const REGISTERING: u8 = 1;
    pub const WAITING: u8 = 2;
    pub const WAKING: u8 = 3;
}

/// Lock-free Waker storage using atomic state machine.
///
/// This implementation provides completely lock-free operation, making it safe 
/// to use from ISR contexts without any risk of deadlock or priority inversion.
///
/// # Thread Safety
///
/// - `register()`: Must be called from a single task context (not concurrent)
/// - `wake()` / `wake_from_isr()`: Can be called from any context including ISR
///
/// # Memory Ordering
///
/// The implementation uses careful memory ordering to ensure:
/// - Waker writes are visible before state transitions
/// - Wake notifications are not lost due to race conditions
#[repr(C)]
pub struct AtomicWaker {
    /// Current state (IDLE, REGISTERING, WAITING, WAKING)
    state: AtomicU8,
    /// Waker storage (only accessed when state allows)
    waker: UnsafeCell<Option<Waker>>,
}

// SAFETY: The state machine ensures exclusive access to waker storage
unsafe impl Send for AtomicWaker {}
unsafe impl Sync for AtomicWaker {}

impl AtomicWaker {
    /// Create a new lock-free atomic waker
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(state::IDLE),
            waker: UnsafeCell::new(None),
        }
    }

    /// Register a waker to be notified.
    ///
    /// If `wake()` was called before this registration, the waker will be
    /// immediately invoked.
    ///
    /// # Panics
    ///
    /// This method should not be called concurrently from multiple threads.
    /// Doing so may result in undefined behavior.
    /// Try to acquire the REGISTERING state, handling IDLE, WAITING,
    /// REGISTERING (spin), and WAKING states. Returns `true` if
    /// REGISTERING was acquired; `false` if a WAKING was consumed
    /// (caller should return early after calling `waker.wake_by_ref()`).
    fn try_acquire_registering(&self, waker: &Waker) -> bool {
        let mut current = self.state.load(Ordering::Acquire);
        loop {
            match current {
                state::IDLE | state::WAITING => {
                    match self.state.compare_exchange_weak(
                        current,
                        state::REGISTERING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => return true,
                        Err(actual) => {
                            current = actual;
                            continue;
                        }
                    }
                }
                state::REGISTERING => {
                    core::hint::spin_loop();
                    current = self.state.load(Ordering::Acquire);
                }
                state::WAKING => {
                    if self
                        .state
                        .compare_exchange(
                            state::WAKING,
                            state::IDLE,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        waker.wake_by_ref();
                        return false;
                    }
                    current = self.state.load(Ordering::Acquire);
                }
                _ => {
                    self.state.store(state::IDLE, Ordering::Release);
                    current = state::IDLE;
                }
            }
        }
    }

    pub fn register(&self, waker: &Waker) {
        // Try to transition from IDLE or WAITING to REGISTERING
        if !self.try_acquire_registering(waker) {
            return;
        }

        // We are now in REGISTERING state, safe to modify waker
        // SAFETY: We have exclusive access due to REGISTERING state
        let waker_slot = unsafe { &mut *self.waker.get() };

        // Check if we need to update the waker
        let should_update = match waker_slot {
            Some(existing) => !existing.will_wake(waker),
            None => true,
        };

        if should_update {
            *waker_slot = Some(waker.clone());
        }

        // Transition to WAITING
        // Use compare_exchange to handle race with wake()
        match self.state.compare_exchange(
            state::REGISTERING,
            state::WAITING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                // Successfully transitioned to WAITING
            }
            Err(actual) => {
                // State was changed (likely to WAKING by concurrent wake())
                if actual == state::WAKING {
                    // Take the waker and invoke it
                    let waker_to_wake = waker_slot.take();
                    self.state.store(state::IDLE, Ordering::Release);
                    if let Some(w) = waker_to_wake {
                        w.wake();
                    }
                } else {
                    // Unexpected state, reset
                    self.state.store(state::IDLE, Ordering::Release);
                }
            }
        }
    }

    /// Wake the registered waker (if any).
    ///
    /// This method is safe to call from any context, including ISR.
    pub fn wake(&self) {
        self.wake_impl(false);
    }

    /// Wake from ISR context.
    ///
    /// ISRでは直接 `wake()` を実行せず、deferred queue に積む。
    #[inline]
    pub fn wake_from_isr(&self) {
        let ptr = self as *const Self as usize;
        let _ = DEFERRED_ATOMIC_WAKER_QUEUE.push_once(ptr);
    }

    /// Internal wake implementation
    fn wake_impl(&self, from_isr: bool) {
        let mut current = self.state.load(Ordering::Acquire);

        loop {
            match current {
                state::IDLE => {
                    // No waker registered, nothing to do
                    return;
                }
                state::WAITING => {
                    // Try to transition to WAKING and take the waker
                    match self.state.compare_exchange_weak(
                        state::WAITING,
                        state::IDLE, // Go directly to IDLE after taking waker
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => {
                            // SAFETY: We successfully transitioned from WAITING,
                            // so we have exclusive access to take the waker
                            let waker = unsafe { (*self.waker.get()).take() };
                            if let Some(w) = waker {
                                if from_isr {
                                    // In ISR, we might want to defer, but since we're
                                    // lock-free, we can just call wake() directly
                                    w.wake();
                                } else {
                                    w.wake();
                                }
                            }
                            return;
                        }
                        Err(actual) => {
                            current = actual;
                            continue;
                        }
                    }
                }
                state::REGISTERING => {
                    // A register is in progress, set WAKING to signal it
                    match self.state.compare_exchange_weak(
                        state::REGISTERING,
                        state::WAKING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => {
                            // The registering thread will handle the wake
                            return;
                        }
                        Err(actual) => {
                            current = actual;
                            continue;
                        }
                    }
                }
                state::WAKING => {
                    // Already waking, nothing more to do
                    return;
                }
                _ => {
                    // Unknown state
                    return;
                }
            }
        }
    }

    /// Check if a waker is registered
    #[inline]
    pub fn has_waker(&self) -> bool {
        matches!(
            self.state.load(Ordering::Acquire),
            state::WAITING | state::REGISTERING
        )
    }

    /// Check if a wake is pending
    #[inline]
    pub fn is_wake_pending(&self) -> bool {
        self.state.load(Ordering::Acquire) == state::WAKING
    }

    /// Clear any registered waker
    pub fn clear(&self) {
        loop {
            let current = self.state.load(Ordering::Acquire);
            match current {
                state::IDLE | state::WAKING => {
                    self.state.store(state::IDLE, Ordering::Release);
                    return;
                }
                state::WAITING => {
                    if self
                        .state
                        .compare_exchange_weak(
                            state::WAITING,
                            state::IDLE,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        // SAFETY: Exclusive access due to successful transition
                        unsafe {
                            (*self.waker.get()).take();
                        }
                        return;
                    }
                }
                state::REGISTERING => {
                    // Wait for registration to complete
                    core::hint::spin_loop();
                }
                _ => return,
            }
        }
    }

    /// Get current state (for debugging)
    #[inline]
    pub fn state(&self) -> u8 {
        self.state.load(Ordering::Acquire)
    }
}

impl Default for AtomicWaker {
    fn default() -> Self {
        Self::new()
    }
}

/// Legacy type alias for backwards compatibility
pub type LockFreeAtomicWaker = AtomicWaker;

/// Process all deferred `AtomicWaker` wakes in non-ISR context.
///
/// ISR側で蓄積した AtomicWaker 通知を non-ISR コンテキストで処理する。
#[inline]
pub fn process_deferred_wakes() {
    while let Some(ptr) = DEFERRED_ATOMIC_WAKER_QUEUE.pop() {
        if ptr == 0 {
            continue;
        }
        // SAFETY: pointer must refer to a long-lived AtomicWaker.
        let aw = unsafe { &*(ptr as *const AtomicWaker) };
        aw.wake();
    }
}


// ============================================================================
// Multi-Waker Queue (supports multiple concurrent waiters)
// ============================================================================

/// ISR-safe Waker queue that supports multiple concurrent waiters
///
/// Unlike `AtomicWaker` which only stores a single waker, `WakerQueue` can
/// store multiple wakers and wake all of them when `wake_all()` is called.
/// This is essential for scenarios where multiple tasks may await the same
/// condition (e.g., multiple invalidation requests waiting for hardware).
///
/// # Thread Safety
///
/// - `register()`: Safe to call from async task context
/// - `wake_all()`: Safe to call from any context (including ISR via deferred)
/// - `wake_all_from_isr()`: Safe to call from ISR context (uses deferred queue)
pub struct WakerQueue {
    /// Registered wakers
    wakers: Mutex<Vec<Waker>>,
    /// Wake-all requested flag (set from ISR if lock fails)
    wake_requested: AtomicBool,
}

impl WakerQueue {
    /// Create a new empty waker queue
    pub const fn new() -> Self {
        Self {
            wakers: Mutex::new(Vec::new()),
            wake_requested: AtomicBool::new(false),
        }
    }

    /// Register a waker to be notified
    ///
    /// If a pending wake was requested while no wakers were registered,
    /// the waker is immediately woken.
    pub fn register(&self, waker: &Waker) {
        let mut guard = self.wakers.lock();

        // Check if this waker is already registered (avoid duplicates)
        let already_registered = guard.iter().any(|w| w.will_wake(waker));

        if !already_registered {
            guard.push(waker.clone());
        }

        // If an ISR requested wake-all, process it now
        if self.wake_requested.swap(false, Ordering::AcqRel) {
            let wakers: Vec<Waker> = guard.drain(..).collect();
            drop(guard);
            for w in wakers {
                w.wake();
            }
        }
    }

    /// Wake all registered wakers (non-ISR context)
    pub fn wake_all(&self) {
        self.wake_requested.store(false, Ordering::Release);

        let mut guard = self.wakers.lock();
        let wakers: Vec<Waker> = guard.drain(..).collect();
        drop(guard);

        for w in wakers {
            w.wake();
        }
    }

    /// ISR-safe wake-all: enqueue for deferred processing
    ///
    /// Direct wakeは行わず、必ずdeferred処理へ委譲する。
    pub fn wake_all_from_isr(&self) {
        self.wake_requested.store(true, Ordering::Release);
        let ptr = self as *const Self as usize;
        let _ = DEFERRED_WAKER_QUEUE_QUEUE.push_once(ptr);
    }

    /// Check if wake-all is pending
    pub fn is_wake_pending(&self) -> bool {
        self.wake_requested.load(Ordering::Acquire)
    }

    /// Get the number of registered wakers
    pub fn waker_count(&self) -> usize {
        self.wakers.lock().len()
    }

    /// Clear all wakers without waking them
    pub fn clear(&self) {
        self.wakers.lock().clear();
        self.wake_requested.store(false, Ordering::Release);
    }
}

impl Default for WakerQueue {
    fn default() -> Self {
        Self::new()
    }
}

// Separate deferred queue for WakerQueue (to distinguish from AtomicWaker)
static DEFERRED_WAKER_QUEUE_QUEUE: DeferredWakerQueue = DeferredWakerQueue::new();
static DEFERRED_ATOMIC_WAKER_QUEUE: DeferredWakerQueue = DeferredWakerQueue::new();

/// Process all deferred WakerQueue wakes; call from non-ISR context
pub fn process_deferred_waker_queue_wakes() {
    while let Some(ptr) = DEFERRED_WAKER_QUEUE_QUEUE.pop() {
        if ptr == 0 {
            continue;
        }
        // SAFETY: pointer must be to a long-lived WakerQueue instance
        let wq = unsafe { &*(ptr as *const WakerQueue) };
        wq.wake_all();
    }
}

// ============================================================================
// Deferred Waker Queue (ISR-safe producer, non-ISR consumer)
// ============================================================================

const DEFERRED_WAKE_QUEUE_SIZE: usize = 256; // power-of-two
const DEFERRED_WAKE_QUEUE_MASK: usize = DEFERRED_WAKE_QUEUE_SIZE - 1;

#[repr(C, align(64))]
struct DeferredWakerQueue {
    head: AtomicUsize,
    tail: AtomicUsize,
    buffer: [AtomicUsize; DEFERRED_WAKE_QUEUE_SIZE],
}

impl DeferredWakerQueue {
    const fn new() -> Self {
        const ZERO: AtomicUsize = AtomicUsize::new(0);
        Self {
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            buffer: [ZERO; DEFERRED_WAKE_QUEUE_SIZE],
        }
    }

    /// Try to push once from ISR context. If contention occurs or queue is full
    /// returns false (no spin/wait in ISR).
    #[inline]
    fn push_once(&self, value: usize) -> bool {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);

        // Full
        if head.wrapping_sub(tail) >= DEFERRED_WAKE_QUEUE_SIZE {
            return false;
        }

        let idx = head & DEFERRED_WAKE_QUEUE_MASK;

        // Try to claim slot (single attempt - ISR must avoid spinning)
        if self
            .head
            .compare_exchange_weak(
                head,
                head.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            self.buffer[idx].store(value, Ordering::Release);
            true
        } else {
            false
        }
    }

    /// Pop (called from non-ISR context)
    #[inline]
    fn pop(&self) -> Option<usize> {
        loop {
            let tail = self.tail.load(Ordering::Relaxed);
            let head = self.head.load(Ordering::Acquire);

            if tail == head {
                return None;
            }

            let idx = tail & DEFERRED_WAKE_QUEUE_MASK;

            if self
                .tail
                .compare_exchange_weak(
                    tail,
                    tail.wrapping_add(1),
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                let value = self.buffer[idx].load(Ordering::Acquire);
                // Clear slot for hygiene
                self.buffer[idx].store(0, Ordering::Release);
                return Some(value);
            }

            core::hint::spin_loop();
        }
    }
}



// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicBool;
    use core::task::{RawWaker, RawWakerVTable, Waker};

    fn dummy_waker() -> Waker {
        const VTABLE: RawWakerVTable = RawWakerVTable::new(
            |_| RawWaker::new(core::ptr::null(), &VTABLE),
            |_| {},
            |_| {},
            |_| {},
        );

        unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) }
    }

    fn make_flag_waker(flag: &AtomicBool) -> Waker {
        unsafe fn raw_clone(data: *const ()) -> RawWaker {
            RawWaker::new(data, &VTABLE)
        }
        unsafe fn raw_wake(data: *const ()) {
            let flag = unsafe { &*(data as *const AtomicBool) };
            flag.store(true, Ordering::Release);
        }
        unsafe fn raw_wake_by_ref(data: *const ()) {
            let flag = unsafe { &*(data as *const AtomicBool) };
            flag.store(true, Ordering::Release);
        }
        unsafe fn raw_drop(_data: *const ()) {}

        static VTABLE: RawWakerVTable =
            RawWakerVTable::new(raw_clone, raw_wake, raw_wake_by_ref, raw_drop);

        unsafe {
            Waker::from_raw(RawWaker::new(
                flag as *const AtomicBool as *const (),
                &VTABLE,
            ))
        }
    }

    #[test_case]
    fn test_atomic_waker() {
        let atomic_waker = AtomicWaker::new();
        let waker = dummy_waker();

        assert!(!atomic_waker.has_waker());

        atomic_waker.register(&waker);
        assert!(atomic_waker.has_waker());

        atomic_waker.wake();
        assert!(!atomic_waker.has_waker());
    }

    #[test_case]
    fn test_atomic_waker_isr_notify() {
        let atomic_waker = AtomicWaker::new();
        let flag = AtomicBool::new(false);
        let waker = make_flag_waker(&flag);

        // Register and then notify from ISR
        atomic_waker.register(&waker);
        assert!(atomic_waker.has_waker());

        // Lock-free implementation wakes directly from ISR context
        atomic_waker.wake_from_isr();

        // With lock-free implementation, wake should be immediate
        assert!(flag.load(Ordering::Acquire), "expected immediate wake");
        assert!(!atomic_waker.has_waker());
    }
}
