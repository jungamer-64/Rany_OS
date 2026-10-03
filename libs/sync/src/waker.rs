//! Exclusive waker registration with coalesced notification state.
//!
//! CPU scheduling and interrupt deferral belong to the caller. This slot
//! serializes shared registration, clear, and wake operations and releases
//! ownership before executing any RawWaker clone, drop, or wake callback.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};
use core::task::Waker;
use hal::preemption::PreemptionGuard;

mod state {
    pub const IDLE: u8 = 0;
    pub const REGISTERING: u8 = 1;
    pub const WAITING: u8 = 2;
    pub const WAKING: u8 = 3;
    pub const REGISTERING_NOTIFIED: u8 = 4;
    pub const PENDING: u8 = 5;
}

/// A notification before registration remains pending. Racing registrations
/// notify the losing caller to retry. The registered Waker is consumed once
/// per delivery, and callbacks may reenter this slot after ownership release.
#[repr(C)]
pub struct WakerSlot {
    state: AtomicU8,
    waker: UnsafeCell<Option<Waker>>,
}

// SAFETY: REGISTERING and WAKING grant exclusive slot access until release.
// Every callback runs after that ownership has been relinquished.
unsafe impl Send for WakerSlot {}
// SAFETY: the same atomic slot-ownership protocol serializes shared access.
unsafe impl Sync for WakerSlot {}

impl core::fmt::Debug for WakerSlot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WakerSlot")
            .field("state", &self.state.load(Ordering::Relaxed))
            .finish()
    }
}

impl WakerSlot {
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(state::IDLE),
            waker: UnsafeCell::new(None),
        }
    }

    /// REGISTERING and WAKING own the UnsafeCell until its last access. A
    /// notification racing registration changes only REGISTERING_NOTIFIED,
    /// and an early notification persists as PENDING until registration.
    fn try_acquire_registering(&self) -> Option<bool> {
        let mut current = self.state.load(Ordering::Acquire);
        // LOOP_PROOF: mode=event; reason=Each CAS either acquires exclusive registration or observes an owner that makes the caller retry by notification.;
        loop {
            match current {
                state::IDLE | state::WAITING | state::PENDING => {
                    match self.state.compare_exchange_weak(
                        current,
                        state::REGISTERING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => return Some(current == state::PENDING),
                        Err(actual) => {
                            current = actual;
                            continue;
                        }
                    }
                }
                state::REGISTERING | state::REGISTERING_NOTIFIED | state::WAKING => return None,
                _ => panic!("invalid atomic waker state"),
            }
        }
    }

    /// Replaces registration after cloning the caller's waker outside ownership.
    /// A concurrent owner wakes the caller to retry its registration.
    ///
    /// # Panics
    /// Panics if memory corruption breaks the private slot state invariant.
    /// RawWaker callbacks retain their own panic policy.
    pub fn register(&self, waker: &Waker) {
        // RawWaker clone/drop callbacks are arbitrary code. Invoke them
        // outside slot ownership so a callback can register, clear, or wake
        // this slot without waiting on the operation that called it.
        let replacement = waker.clone();
        let preemption = PreemptionGuard::enter();
        let Some(already_notified) = self.try_acquire_registering() else {
            drop(preemption);
            // Another CPU owns the slot. Waking the registering task makes
            // its next poll retry without waiting on that CPU's callback.
            waker.wake_by_ref();
            return;
        };
        // SAFETY: REGISTERING is exclusive. A wake can mark it notified but
        // cannot touch the slot, and clear waits for its owner to publish.
        let waker_slot = unsafe { &mut *self.waker.get() };
        let retired = waker_slot.replace(replacement);
        let notification = if already_notified {
            let notification = waker_slot.take();
            self.state.store(state::IDLE, Ordering::Release);
            notification
        } else {
            match self.state.compare_exchange(
                state::REGISTERING,
                state::WAITING,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => None,
                Err(actual) => {
                    assert_eq!(actual, state::REGISTERING_NOTIFIED);
                    let notification = waker_slot.take();
                    self.state.store(state::IDLE, Ordering::Release);
                    notification
                }
            }
        };
        drop(preemption);
        drop(retired);
        if let Some(notification) = notification {
            notification.wake();
        }
    }

    pub fn wake(&self) {
        let preemption = PreemptionGuard::enter();
        let notification = self.take_notification();
        drop(preemption);
        if let Some(notification) = notification {
            notification.wake();
        }
    }

    fn take_notification(&self) -> Option<Waker> {
        let mut current = self.state.load(Ordering::Acquire);
        // LOOP_PROOF: mode=event; reason=A successful CAS publishes a pending notification or acquires the registered slot, and an existing notification coalesces with this wake.;
        loop {
            match current {
                state::IDLE | state::WAITING | state::REGISTERING => {
                    let next = match current {
                        state::IDLE => state::PENDING,
                        state::WAITING => state::WAKING,
                        state::REGISTERING => state::REGISTERING_NOTIFIED,
                        _ => unreachable!(),
                    };
                    match self.state.compare_exchange_weak(
                        current,
                        next,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => {
                            if next != state::WAKING {
                                return None;
                            }
                            // SAFETY: only WAITING -> WAKING grants slot
                            // ownership. Register and clear cannot enter it
                            // until this owner finishes taking the value.
                            let notification = unsafe { (*self.waker.get()).take() };
                            self.state.store(state::IDLE, Ordering::Release);
                            return notification;
                        }
                        Err(actual) => {
                            current = actual;
                            continue;
                        }
                    }
                }
                state::WAKING | state::REGISTERING_NOTIFIED | state::PENDING => return None,
                _ => panic!("invalid atomic waker state"),
            }
        }
    }

    #[inline]
    pub fn has_waker(&self) -> bool {
        matches!(
            self.state.load(Ordering::Acquire),
            state::WAITING | state::REGISTERING | state::REGISTERING_NOTIFIED
        )
    }

    #[inline]
    pub fn is_wake_pending(&self) -> bool {
        matches!(
            self.state.load(Ordering::Acquire),
            state::PENDING | state::REGISTERING_NOTIFIED
        )
    }

    /// Retires registration and any pending notification. A racing delivery
    /// that already took the waker may still finish its callback.
    ///
    /// # Panics
    /// Panics if memory corruption introduces an invalid private state value.
    /// The retired RawWaker's destructor retains its own panic policy.
    pub fn clear(&self) {
        let preemption = PreemptionGuard::enter();
        // LOOP_PROOF: mode=event; reason=Clear waits for a remote slot owner to publish, then acquires the slot or atomically removes an empty pending notification.;
        loop {
            let current = self.state.load(Ordering::Acquire);
            match current {
                state::IDLE | state::WAITING | state::PENDING => {
                    if self
                        .state
                        .compare_exchange_weak(
                            current,
                            state::REGISTERING,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        // SAFETY: the CAS owns the slot, including when
                        // replacing WAITING. Destruction happens after release.
                        let retired = unsafe { (*self.waker.get()).take() };
                        self.state.store(state::IDLE, Ordering::Release);
                        drop(preemption);
                        drop(retired);
                        return;
                    }
                }
                state::REGISTERING | state::REGISTERING_NOTIFIED | state::WAKING => {
                    core::hint::spin_loop();
                }
                _ => panic!("invalid atomic waker state"),
            }
        }
    }
}

impl Default for WakerSlot {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::sync::Arc;
    use alloc::task::Wake;
    use core::sync::atomic::AtomicUsize;
    use std::sync::Barrier;

    struct CountWake(AtomicUsize);

    impl Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[test]
    fn early_notifications_merge_and_clear_cancels_registration() {
        let slot = WakerSlot::new();
        let observer = Arc::new(CountWake(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&observer));
        slot.wake();
        slot.wake();
        assert!(slot.is_wake_pending());
        slot.register(&waker);
        assert_eq!(observer.0.load(Ordering::Acquire), 1);
        assert!(!slot.is_wake_pending());
        slot.register(&waker);
        assert!(slot.has_waker());
        slot.clear();
        slot.wake();
        assert_eq!(observer.0.load(Ordering::Acquire), 1);
        slot.clear();
        slot.register(&waker);
        slot.wake();
        assert_eq!(observer.0.load(Ordering::Acquire), 2);
    }

    struct ClearOnDrop(Arc<WakerSlot>);

    #[expect(
        clippy::manual_noop_waker,
        reason = "this waker's destructor reenters the slot and Waker::noop cannot carry that destructor"
    )]
    impl Wake for ClearOnDrop {
        fn wake(self: Arc<Self>) {}
    }
    impl Drop for ClearOnDrop {
        fn drop(&mut self) {
            self.0.clear();
        }
    }

    #[test]
    fn retiring_a_waker_can_reenter_without_stealing_slot_ownership() {
        let slot = Arc::new(WakerSlot::new());
        let reentrant = Waker::from(Arc::new(ClearOnDrop(Arc::clone(&slot))));
        slot.register(&reentrant);
        drop(reentrant);
        slot.register(Waker::noop());
        assert!(!slot.has_waker());
        slot.register(Waker::noop());
        slot.wake();
        assert!(!slot.has_waker());
    }

    #[test]
    fn racing_registration_and_wake_deliver_every_round() {
        let slot = WakerSlot::new();
        let observer = Arc::new(CountWake(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&observer));
        let barrier = Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for _ in 0..10_000 {
                    barrier.wait();
                    slot.wake();
                    barrier.wait();
                }
            });
            for round in 1..=10_000 {
                barrier.wait();
                slot.register(&waker);
                barrier.wait();
                assert_eq!(observer.0.load(Ordering::Acquire), round);
                assert!(!slot.has_waker());
                assert!(!slot.is_wake_pending());
            }
        });
    }
}
