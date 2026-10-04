// ============================================================================
// kernel/src/sync/atomic_waker.rs
// ============================================================================
//! Atomic Waker implementations for ISR-safe task notification.
//!
//! This module provides:
//! - `AtomicWaker`: retained state with allocation-free ISR publication
//! - `WakerQueue`: Multi-waker queue for multiple concurrent waiters
use crate::sync::InitOnce;
use crate::sync::IrqPoisonLock;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::Waker;
use exorust_sync::{DeferredNotification, WakerSlot};

// ============================================================================
// Lock-Free AtomicWaker (State Machine Based)
// ============================================================================

/// Registration and notification state is retained by deferred CPU work.
/// Dropping this handle does not invalidate a notification already published.
pub struct AtomicWaker {
    inner: InitOnce<Arc<DeferredNotification<WakerSlot>>>,
    early_notification: AtomicBool,
}

impl AtomicWaker {
    pub const fn new() -> Self {
        Self {
            inner: InitOnce::new(),
            early_notification: AtomicBool::new(false),
        }
    }

    pub fn register(&self, waker: &Waker) {
        // Initialization and allocation precede ISR publication. The once
        // guard prevents a local task from interrupting this initializer.
        let inner = self
            .inner
            .call_once(|| Arc::new(DeferredNotification::new(WakerSlot::new())));
        if self.early_notification.swap(false, Ordering::AcqRel) {
            inner.value().wake();
        }
        inner.value().register(waker);
    }

    pub fn wake(&self) {
        if let Some(inner) = self.inner.get() {
            inner.value().wake();
            return;
        }
        self.early_notification.store(true, Ordering::Release);
        // Publication may race the first observation. Either the registering
        // task consumes the early request or this second observation does.
        if let Some(inner) = self.inner.get() {
            if self.early_notification.swap(false, Ordering::AcqRel) {
                inner.value().wake();
            }
        }
    }

    pub fn wake_from_isr(&self) {
        if let Some(inner) = self.inner.get() {
            self.defer(inner);
            return;
        }
        self.early_notification.store(true, Ordering::Release);
        if let Some(inner) = self.inner.get() {
            if self.early_notification.swap(false, Ordering::AcqRel) {
                self.defer(inner);
            }
        }
    }

    fn defer(&self, inner: &Arc<DeferredNotification<WakerSlot>>) {
        if let Some(current) = crate::cpu::CurrentCpu::acquire() {
            current.atomic_notifications().publish(inner);
        } else {
            // An event before CPU binding is retained for the first normal
            // registration, without allocating or calling a waker in the ISR.
            self.early_notification.store(true, Ordering::Release);
        }
    }

    pub fn has_waker(&self) -> bool {
        self.inner
            .get()
            .is_some_and(|inner| inner.value().has_waker())
    }
    pub fn is_wake_pending(&self) -> bool {
        self.early_notification.load(Ordering::Acquire)
            || self
                .inner
                .get()
                .is_some_and(|inner| inner.is_pending() || inner.value().is_wake_pending())
    }
    pub fn clear(&self) {
        self.early_notification.store(false, Ordering::Release);
        if let Some(inner) = self.inner.get() {
            inner.value().clear();
        }
    }
}

impl Default for AtomicWaker {
    fn default() -> Self {
        Self::new()
    }
}
impl core::fmt::Debug for AtomicWaker {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AtomicWaker")
            .field("registered", &self.has_waker())
            .field("pending", &self.is_wake_pending())
            .finish()
    }
}

#[inline]
pub fn process_deferred_wakes() {
    if let Some(current) = crate::cpu::CurrentCpu::acquire() {
        current.atomic_notifications().drain(WakerSlot::wake);
    }
}

// ============================================================================
// Multi-Waker Queue (supports multiple concurrent waiters)
// ============================================================================

pub struct WakerQueue {
    inner: InitOnce<Arc<DeferredNotification<WakerQueueState>>>,
    early_notification: AtomicBool,
}

impl WakerQueue {
    pub const fn new() -> Self {
        Self {
            inner: InitOnce::new(),
            early_notification: AtomicBool::new(false),
        }
    }
    pub fn register(&self, waker: &Waker) {
        let inner = self
            .inner
            .call_once(|| Arc::new(DeferredNotification::new(WakerQueueState::new())));
        if self.early_notification.swap(false, Ordering::AcqRel) {
            inner.value().wake_requested.store(true, Ordering::Release);
        }
        inner.value().register(waker);
    }
    pub fn wake_all(&self) {
        if let Some(inner) = self.inner.get() {
            inner.value().wake_all();
            return;
        }
        self.early_notification.store(true, Ordering::Release);
        if let Some(inner) = self.inner.get() {
            if self.early_notification.swap(false, Ordering::AcqRel) {
                inner.value().wake_all();
            }
        }
    }
    pub fn wake_all_from_isr(&self) {
        if let Some(inner) = self.inner.get() {
            self.defer(inner);
            return;
        }
        self.early_notification.store(true, Ordering::Release);
        if let Some(inner) = self.inner.get() {
            if self.early_notification.swap(false, Ordering::AcqRel) {
                self.defer(inner);
            }
        }
    }
    fn defer(&self, inner: &Arc<DeferredNotification<WakerQueueState>>) {
        inner.value().wake_requested.store(true, Ordering::Release);
        if let Some(current) = crate::cpu::CurrentCpu::acquire() {
            current.queue_notifications().publish(inner);
        }
    }
    pub fn is_wake_pending(&self) -> bool {
        self.early_notification.load(Ordering::Acquire)
            || self
                .inner
                .get()
                .is_some_and(|inner| inner.value().is_wake_pending())
    }
    pub fn waker_count(&self) -> usize {
        self.inner
            .get()
            .map_or(0, |inner| inner.value().waker_count())
    }
    pub fn clear(&self) {
        self.early_notification.store(false, Ordering::Release);
        if let Some(inner) = self.inner.get() {
            inner.value().clear();
        }
    }
}

#[derive(Debug)]
pub(crate) struct WakerQueueState {
    wakers: IrqPoisonLock<Vec<Waker>>,
    wake_requested: AtomicBool,
}

impl WakerQueueState {
    pub(crate) const fn new() -> Self {
        Self {
            wakers: IrqPoisonLock::new(Vec::new()),
            wake_requested: AtomicBool::new(false),
        }
    }

    pub fn register(&self, waker: &Waker) {
        let replacement = waker.clone();
        let mut guard = self.wakers.lock().unwrap_or_else(|e| e.into_inner());
        let already_registered = guard.iter().any(|w| w.will_wake(waker));
        if !already_registered {
            guard.push(replacement);
        }
        if self.wake_requested.swap(false, Ordering::AcqRel) {
            let wakers = core::mem::take(&mut *guard);
            drop(guard);
            for w in wakers {
                w.wake();
            }
        }
    }

    pub(crate) fn wake_all(&self) {
        self.wake_requested.store(true, Ordering::Release);
        self.deliver_pending();
    }

    pub(crate) fn deliver_pending(&self) {
        let mut guard = self
            .wakers
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if guard.is_empty() || !self.wake_requested.swap(false, Ordering::AcqRel) {
            return;
        }
        let wakers = core::mem::take(&mut *guard);
        drop(guard);
        for waker in wakers {
            waker.wake();
        }
    }

    pub fn is_wake_pending(&self) -> bool {
        self.wake_requested.load(Ordering::Acquire)
    }

    pub fn waker_count(&self) -> usize {
        self.wakers.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn clear(&self) {
        let mut guard = self
            .wakers
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let retired = core::mem::take(&mut *guard);
        self.wake_requested.store(false, Ordering::Release);
        drop(guard);
        drop(retired);
    }
}

impl core::fmt::Debug for WakerQueue {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("WakerQueue")
            .field("registered", &self.waker_count())
            .field("pending", &self.is_wake_pending())
            .finish()
    }
}

impl Default for WakerQueue {
    fn default() -> Self {
        Self::new()
    }
}

pub fn process_deferred_waker_queue_wakes() {
    if let Some(current) = crate::cpu::CurrentCpu::acquire() {
        current
            .queue_notifications()
            .drain(WakerQueueState::deliver_pending);
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
    fn interrupt_before_initialization_is_retained_without_a_callback() {
        let atomic_waker = AtomicWaker::new();
        let flag = AtomicBool::new(false);
        let waker = make_flag_waker(&flag);
        atomic_waker.wake_from_isr();
        assert!(!flag.load(Ordering::Acquire));
        assert!(atomic_waker.is_wake_pending());
        atomic_waker.register(&waker);
        assert!(flag.load(Ordering::Acquire));
        assert!(!atomic_waker.has_waker());
    }
}
