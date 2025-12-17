use core::sync::atomic::{AtomicBool, Ordering};
use core::task::Waker;
use spin::Mutex;

/// ISR-safe Waker storage
///
/// Can be safely operated from interrupt handlers.
pub struct AtomicWaker {
    /// Waker is set
    has_waker: AtomicBool,
    /// Waker (protected by Mutex)
    waker: Mutex<Option<Waker>>,
    /// Wake requested flag (set from ISR if lock fails)
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

        // Process pending wake request
        if self.wake_requested.swap(false, Ordering::AcqRel) {
            if let Some(w) = guard.take() {
                self.has_waker.store(false, Ordering::Release);
                drop(guard);
                w.wake();
            }
        }
    }

    /// Wake (called from ISR)
    ///
    /// # Safety
    /// calling from ISR is safe because we use try_lock.
    pub fn wake(&self) {
        // try_lock
        if let Some(mut guard) = self.waker.try_lock() {
            if let Some(waker) = guard.take() {
                self.has_waker.store(false, Ordering::Release);
                drop(guard);
                waker.wake();
                return;
            }
        }

        // Failed to lock, set flag
        if self.has_waker.load(Ordering::Acquire) {
            self.wake_requested.store(true, Ordering::Release);
        }
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
