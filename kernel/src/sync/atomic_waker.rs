// ============================================================================
// kernel/src/sync/atomic_waker.rs
// ============================================================================
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::task::Waker;
use spin::Mutex;

/// ISR-safe Waker storage
///
/// Note: For ISR notification (`wake_from_isr`) the `AtomicWaker` instance
/// MUST be long-lived (e.g., a static or part of a heap-allocated device/controller)
/// since we enqueue a raw pointer to it into a global deferred queue.
pub struct AtomicWaker {
    /// Waker is set
    has_waker: AtomicBool,
    /// Waker (protected by Mutex)
    waker: Mutex<Option<Waker>>,
    /// Wake requested flag (set from ISR if lock fails or queued)
    wake_requested: AtomicBool,
}

impl AtomicWaker {
    /// Create new AtomicWaker
    pub const fn new() -> Self {
        Self {
            has_waker: AtomicBool::new(false),
            waker: Mutex::new(None),
            wake_requested: AtomicBool::new(false),
        }
    }

    /// Register Waker
    pub fn register(&self, waker: &Waker) {
        // Compare with existing waker
        let mut guard = self.waker.lock();
        let should_update = match &*guard {
            Some(existing) => !existing.will_wake(waker),
            None => true,
        };

        if should_update {
            *guard = Some(waker.clone());
            self.has_waker.store(true, Ordering::Release);
        }

        // If an ISR already requested a wake, process it immediately
        if self.wake_requested.swap(false, Ordering::AcqRel) {
            if let Some(w) = guard.take() {
                self.has_waker.store(false, Ordering::Release);
                drop(guard);
                w.wake();
            }
        }
    }

    /// Non-ISR wake: called from non-ISR context to perform the actual wake
    /// This takes the lock and invokes the stored waker if present.
    pub fn wake(&self) {
        // Clear any pending flag since we're processing it now
        self.wake_requested.store(false, Ordering::Release);

        let mut guard = self.waker.lock();
        if let Some(waker) = guard.take() {
            self.has_waker.store(false, Ordering::Release);
            drop(guard);
            waker.wake();
        }
    }

    /// ISR-safe notification: enqueue this AtomicWaker for deferred processing.
    ///
    /// Tries a fast path first (non-blocking `try_lock`) so tests and non-ISR callers
    /// still get immediate wake behavior when there's no contention. If the fast
    /// path fails, we fall back to setting the pending flag and attempting to
    /// enqueue for deferred processing by the Executor.
    pub fn wake_from_isr(&self) {
        // Fast path: if we can obtain the lock immediately, perform the wake now.
        if let Some(mut guard) = self.waker.try_lock() {
            if let Some(w) = guard.take() {
                self.has_waker.store(false, Ordering::Release);
                drop(guard);
                w.wake();
                // Clear pending flag if any
                self.wake_requested.store(false, Ordering::Release);
                return;
            }
        }

        // Fallback: mark pending and try to enqueue for deferred processing
        self.wake_requested.store(true, Ordering::Release);
        let ptr = self as *const Self as usize;
        let _ = DEFERRED_WAKE_QUEUE.push_once(ptr);
    }

    /// Has waker?
    pub fn has_waker(&self) -> bool {
        self.has_waker.load(Ordering::Acquire)
    }

    /// Is wake pending?
    pub fn is_wake_pending(&self) -> bool {
        self.wake_requested.load(Ordering::Acquire)
    }

    /// Clear waker
    pub fn clear(&self) {
        *self.waker.lock() = None;
        self.has_waker.store(false, Ordering::Release);
        self.wake_requested.store(false, Ordering::Release);
    }
}

impl Default for AtomicWaker {
    fn default() -> Self {
        Self::new()
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

static DEFERRED_WAKE_QUEUE: DeferredWakerQueue = DeferredWakerQueue::new();

/// Process all deferred wakes; must be called from non-ISR context (e.g. Executor loop)
pub fn process_deferred_wakes() {
    while let Some(ptr) = DEFERRED_WAKE_QUEUE.pop() {
        if ptr == 0 {
            continue;
        }

        // SAFETY: The pointer must point to a long-lived AtomicWaker instance
        // (e.g., static or part of an owned controller). This is a kernel-level
        // invariant for ISR notifications.
        let aw = unsafe { &*(ptr as *const AtomicWaker) };
        aw.wake();
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use core::task::{RawWaker, RawWakerVTable, Waker};
    use core::sync::atomic::AtomicBool;

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

        static VTABLE: RawWakerVTable = RawWakerVTable::new(
            raw_clone,
            raw_wake,
            raw_wake_by_ref,
            raw_drop,
        );

        unsafe { Waker::from_raw(RawWaker::new(flag as *const AtomicBool as *const (), &VTABLE)) }
    }

    #[test]
    fn test_atomic_waker() {
        let atomic_waker = AtomicWaker::new();
        let waker = dummy_waker();

        assert!(!atomic_waker.has_waker());

        atomic_waker.register(&waker);
        assert!(atomic_waker.has_waker());

        atomic_waker.wake();
        assert!(!atomic_waker.has_waker());
    }

    #[test]
    fn test_atomic_waker_isr_notify() {
        let atomic_waker = AtomicWaker::new();
        let flag = AtomicBool::new(false);
        let waker = make_flag_waker(&flag);

        // Register and then notify from ISR
        atomic_waker.register(&waker);
        assert!(atomic_waker.has_waker());

        atomic_waker.wake_from_isr();

        // Either the fast path delivered the wake immediately (flag=true)
        // or the notification is pending in the deferred queue (pending=true).
        let fast_path_woke = flag.load(Ordering::Acquire);
        let pending = atomic_waker.is_wake_pending();
        assert!(fast_path_woke || pending, "expected either immediate wake or pending flag");

        // Process deferred wakes (simulates Executor loop) to ensure eventual delivery
        process_deferred_wakes();

        assert!(flag.load(Ordering::Acquire));
        assert!(!atomic_waker.has_waker());
        assert!(!atomic_waker.is_wake_pending());
    }
}
