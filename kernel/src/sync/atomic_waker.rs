// ============================================================================
// kernel/src/sync/atomic_waker.rs
// ============================================================================
//! Atomic Waker implementations for ISR-safe task notification.
//!
//! This module provides:
//! - `AtomicWaker`: Lock-free implementation using atomic state machine (ISR-safe)
//! - `WakerQueue`: Multi-waker queue for multiple concurrent waiters

#![allow(dead_code)]
use crate::sync::IrqPoisonLock;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use core::task::Waker;

use super::lockfree::MpscRingBuffer;

// ============================================================================
// Lock-Free AtomicWaker (State Machine Based)
// ============================================================================

mod state {
    pub const IDLE: u8 = 0;
    pub const REGISTERING: u8 = 1;
    pub const WAITING: u8 = 2;
    pub const WAKING: u8 = 3;
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
        if !self.try_acquire_registering(waker) {
            return;
        }
        let waker_slot = unsafe { &mut *self.waker.get() };
        let should_update = match waker_slot {
            Some(existing) => !existing.will_wake(waker),
            None => true,
        };
        if should_update {
            *waker_slot = Some(waker.clone());
        }
        match self.state.compare_exchange(
            state::REGISTERING,
            state::WAITING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(actual) => {
                if actual == state::WAKING {
                    let waker_to_wake = waker_slot.take();
                    self.state.store(state::IDLE, Ordering::Release);
                    if let Some(w) = waker_to_wake {
                        w.wake();
                    }
                } else {
                    self.state.store(state::IDLE, Ordering::Release);
                }
            }
        }
    }

    pub fn wake(&self) {
        self.wake_impl(false);
    }

    #[inline]
    pub fn wake_from_isr(&self) {
        let ptr = self as *const Self as usize;
        let _ = DEFERRED_ATOMIC_WAKER_QUEUE.push_once(ptr);
    }

    fn wake_impl(&self, _from_isr: bool) {
        let mut current = self.state.load(Ordering::Acquire);
        loop {
            match current {
                state::IDLE => return,
                state::WAITING => {
                    match self.state.compare_exchange_weak(
                        state::WAITING,
                        state::IDLE,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => {
                            let waker = unsafe { (*self.waker.get()).take() };
                            if let Some(w) = waker {
                                w.wake();
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
                    match self.state.compare_exchange_weak(
                        state::REGISTERING,
                        state::WAKING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => return,
                        Err(actual) => {
                            current = actual;
                            continue;
                        }
                    }
                }
                state::WAKING => return,
                _ => return,
            }
        }
    }

    #[inline]
    pub fn has_waker(&self) -> bool {
        matches!(
            self.state.load(Ordering::Acquire),
            state::WAITING | state::REGISTERING
        )
    }

    #[inline]
    pub fn is_wake_pending(&self) -> bool {
        self.state.load(Ordering::Acquire) == state::WAKING
    }

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
                        unsafe {
                            (*self.waker.get()).take();
                        }
                        return;
                    }
                }
                state::REGISTERING => {
                    core::hint::spin_loop();
                }
                _ => return,
            }
        }
    }

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

pub type LockFreeAtomicWaker = AtomicWaker;

#[inline]
pub fn process_deferred_wakes() {
    while let Some(ptr) = DEFERRED_ATOMIC_WAKER_QUEUE.pop() {
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

    pub fn wake_all_from_isr(&self) {
        self.wake_requested.store(true, Ordering::Release);
        let ptr = self as *const Self as usize;
        let _ = DEFERRED_WAKER_QUEUE_QUEUE.push_once(ptr);
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

static DEFERRED_WAKER_QUEUE_QUEUE: DeferredWakerQueue = DeferredWakerQueue::new();
static DEFERRED_ATOMIC_WAKER_QUEUE: DeferredWakerQueue = DeferredWakerQueue::new();

pub fn process_deferred_waker_queue_wakes() {
    while let Some(ptr) = DEFERRED_WAKER_QUEUE_QUEUE.pop() {
        if ptr == 0 {
            continue;
        }
        let wq = unsafe { &*(ptr as *const WakerQueue) };
        wq.wake_all();
    }
}

// ============================================================================
// Deferred Waker Queue (ISR-safe producer, non-ISR consumer)
// ============================================================================

const DEFERRED_WAKE_QUEUE_SIZE: usize = 256;
const DEFERRED_WAKE_QUEUE_BACKING_SIZE: usize = DEFERRED_WAKE_QUEUE_SIZE + 1;

#[repr(C, align(64))]
struct DeferredWakerQueue {
    buffer: MpscRingBuffer<usize, DEFERRED_WAKE_QUEUE_BACKING_SIZE>,
}

impl DeferredWakerQueue {
    const fn new() -> Self {
        Self {
            buffer: MpscRingBuffer::new(),
        }
    }

    #[inline]
    fn push_once(&self, value: usize) -> bool {
        self.buffer.try_push(value).is_ok()
    }

    #[inline]
    fn pop(&self) -> Option<usize> {
        self.buffer.pop()
    }

    #[inline]
    fn len(&self) -> usize {
        self.buffer.len()
    }

    #[inline]
    fn capacity(&self) -> usize {
        DEFERRED_WAKE_QUEUE_SIZE
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.buffer.is_empty()
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

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn deferred_waker_queue_preserves_full_capacity() {
        let queue = DeferredWakerQueue::new();
        assert!(queue.is_empty());

        for i in 0..DEFERRED_WAKE_QUEUE_SIZE {
            assert!(queue.push_once(i + 1), "failed at {}", i);
        }
        assert!(!queue.push_once(usize::MAX));
        assert_eq!(queue.len(), DEFERRED_WAKE_QUEUE_SIZE);
        assert_eq!(queue.capacity(), DEFERRED_WAKE_QUEUE_SIZE);
        assert!(!queue.is_empty());

        for i in 0..DEFERRED_WAKE_QUEUE_SIZE {
            assert_eq!(queue.pop(), Some(i + 1));
        }
        assert_eq!(queue.pop(), None);
        assert!(queue.is_empty());
    }
}
