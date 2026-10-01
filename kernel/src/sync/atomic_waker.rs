// ============================================================================
// kernel/src/sync/atomic_waker.rs
// ============================================================================
//! Atomic Waker implementations for ISR-safe task notification.
//!
//! This module provides:
//! - `AtomicWaker`: Lock-free implementation using atomic state machine (ISR-safe)
//! - `WakerQueue`: Multi-waker queue for multiple concurrent waiters
use crate::sync::IrqPoisonLock;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use core::task::Waker;
use hal::preemption::PreemptionGuard;

// ============================================================================
// Lock-Free AtomicWaker (State Machine Based)
// ============================================================================

mod state {
    pub const IDLE: u8 = 0;
    pub const REGISTERING: u8 = 1;
    pub const WAITING: u8 = 2;
    pub const WAKING: u8 = 3;
    pub const REGISTERING_NOTIFIED: u8 = 4;
    pub const PENDING: u8 = 5;
}

#[repr(C)]
pub struct AtomicWaker {
    state: AtomicU8,
    waker: UnsafeCell<Option<Waker>>,
}

unsafe impl Send for AtomicWaker {}
unsafe impl Sync for AtomicWaker {}

impl core::fmt::Debug for AtomicWaker {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AtomicWaker")
            .field("state", &self.state.load(Ordering::Relaxed))
            .finish()
    }
}

impl AtomicWaker {
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

impl Default for AtomicWaker {
    fn default() -> Self {
        Self::new()
    }
}

#[inline]
pub fn process_deferred_wakes() {
    let Some(current) = crate::cpu::CurrentCpu::acquire() else {
        return;
    };
    // LOOP_PROOF: mode=condition; reason=Each take_atomic_wake consumes one deferred CPU-local notification and the bounded queue ends the drain when empty.;
    while let Some(ptr) = current.take_atomic_wake() {
        if ptr == 0 {
            continue;
        }
        let aw = unsafe { &*(ptr as *const AtomicWaker) };
        aw.wake();
    }
}

// ============================================================================
// Multi-Waker Queue (supports multiple concurrent waiters)
// ============================================================================

#[derive(Debug)]
pub struct WakerQueue {
    wakers: IrqPoisonLock<Vec<Waker>>,
    wake_requested: AtomicBool,
}

impl WakerQueue {
    pub const fn new() -> Self {
        Self {
            wakers: IrqPoisonLock::new(Vec::new()),
            wake_requested: AtomicBool::new(false),
        }
    }

    pub fn register(&self, waker: &Waker) {
        let mut guard = self.wakers.lock().unwrap_or_else(|e| e.into_inner());
        let already_registered = guard.iter().any(|w| w.will_wake(waker));
        if !already_registered {
            guard.push(waker.clone());
        }
        if self.wake_requested.swap(false, Ordering::AcqRel) {
            let wakers: Vec<Waker> = guard.drain(..).collect();
            drop(guard);
            for w in wakers {
                w.wake();
            }
        }
    }

    pub fn wake_all(&self) {
        self.wake_requested.store(false, Ordering::Release);
        let mut guard = self.wakers.lock().unwrap_or_else(|e| e.into_inner());
        let wakers: Vec<Waker> = guard.drain(..).collect();
        drop(guard);
        for w in wakers {
            w.wake();
        }
    }

    pub fn is_wake_pending(&self) -> bool {
        self.wake_requested.load(Ordering::Acquire)
    }

    pub fn waker_count(&self) -> usize {
        self.wakers.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn clear(&self) {
        self.wakers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.wake_requested.store(false, Ordering::Release);
    }
}

impl Default for WakerQueue {
    fn default() -> Self {
        Self::new()
    }
}

pub fn process_deferred_waker_queue_wakes() {
    let Some(current) = crate::cpu::CurrentCpu::acquire() else {
        return;
    };
    // LOOP_PROOF: mode=condition; reason=Each take_queue_wake consumes one deferred CPU-local notification and the bounded queue ends the drain when empty.;
    while let Some(ptr) = current.take_queue_wake() {
        if ptr == 0 {
            continue;
        }
        let wq = unsafe { &*(ptr as *const WakerQueue) };
        wq.wake_all();
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

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_atomic_waker() {
        let atomic_waker = AtomicWaker::new();
        let waker = dummy_waker();
        assert!(!atomic_waker.has_waker());
        atomic_waker.register(&waker);
        assert!(atomic_waker.has_waker());
        atomic_waker.wake();
        assert!(!atomic_waker.has_waker());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn wake_before_registration_is_delivered_once() {
        let atomic_waker = AtomicWaker::new();
        let flag = AtomicBool::new(false);
        let waker = make_flag_waker(&flag);
        atomic_waker.wake();
        atomic_waker.wake();
        assert!(atomic_waker.is_wake_pending());
        atomic_waker.register(&waker);
        assert!(flag.swap(false, Ordering::AcqRel));
        assert!(!atomic_waker.is_wake_pending());
        atomic_waker.register(&waker);
        assert!(!flag.load(Ordering::Acquire));
        assert!(atomic_waker.has_waker());
        atomic_waker.clear();
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn clear_discards_a_retired_registration_and_its_notification() {
        let atomic_waker = AtomicWaker::new();
        let flag = AtomicBool::new(false);
        let waker = make_flag_waker(&flag);
        atomic_waker.register(&waker);
        atomic_waker.clear();
        atomic_waker.wake();
        atomic_waker.clear();
        atomic_waker.register(&waker);
        assert!(!flag.load(Ordering::Acquire));
        atomic_waker.wake();
        assert!(flag.load(Ordering::Acquire));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn replaced_waker_can_reenter_clear_from_its_destructor() {
        unsafe fn clone(data: *const ()) -> RawWaker {
            RawWaker::new(data, &VTABLE)
        }
        unsafe fn clear(data: *const ()) {
            // SAFETY: this test retains the slot until both callback owners
            // are dropped, and clear does not retain the pointer.
            unsafe { &*(data as *const AtomicWaker) }.clear();
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, |_| {}, |_| {}, clear);
        let atomic_waker = AtomicWaker::new();
        // SAFETY: all raw-waker clones are destroyed below before the slot.
        let reentrant = unsafe {
            Waker::from_raw(RawWaker::new(
                &atomic_waker as *const AtomicWaker as *const (),
                &VTABLE,
            ))
        };
        atomic_waker.register(&reentrant);
        atomic_waker.register(&dummy_waker());
        assert!(!atomic_waker.has_waker());
        drop(reentrant);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_atomic_waker_isr_notify() {
        let atomic_waker = AtomicWaker::new();
        let flag = AtomicBool::new(false);
        let waker = make_flag_waker(&flag);
        atomic_waker.register(&waker);
        assert!(atomic_waker.has_waker());
        atomic_waker.wake_from_isr();
        process_deferred_wakes();
        assert!(flag.load(Ordering::Acquire), "expected immediate wake");
        assert!(!atomic_waker.has_waker());
    }
}
