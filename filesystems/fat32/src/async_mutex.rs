// Minimal async-aware mutex for no_std + alloc environments.
// Designed for FAT32 crate internal use as a safe, Waker-based mutex
// that supports:
// - blocking acquisition for synchronous contexts (spin-based, short critical sections)
// - async acquisition (suspends task, does not spin CPU)
//
// Notes:
// - The internal waiters queue uses `PoisonLock` to protect short critical sections
//   when registering/unregistering wakers.
// - Guards are deliberately made !Send (PhantomData<Rc<()>>) to avoid accidental
//   cross-thread movement which could lead to surprising deadlocks in some
//   executor/interrupt setups.

#![allow(dead_code)]

use alloc::collections::VecDeque;
use core::cell::UnsafeCell;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};
use core::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
};
use exorust_sync::PoisonLock;

pub struct AsyncMutex<T: ?Sized> {
    locked: AtomicBool,
    waiters: PoisonLock<VecDeque<Waker>>,
    data: UnsafeCell<T>,
}

unsafe impl<T: ?Sized + Send> Send for AsyncMutex<T> {}
unsafe impl<T: ?Sized + Send> Sync for AsyncMutex<T> {}

impl<T> AsyncMutex<T> {
    pub const fn new(data: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            waiters: PoisonLock::new(VecDeque::new()),
            data: UnsafeCell::new(data),
        }
    }

    /// Try to acquire the lock immediately, returning a blocking guard if successful.
    pub fn try_lock(&self) -> Option<BlockingGuard<'_, T>> {
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(BlockingGuard {
                lock: self,
                nosend: PhantomData,
            })
        } else {
            None
        }
    }

    /// Blocking acquisition (spin-waits). Intended for short critical sections only.
    pub fn blocking_lock(&self) -> BlockingGuard<'_, T> {
        while self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        BlockingGuard {
            lock: self,
            nosend: PhantomData,
        }
    }

    /// Acquire the lock asynchronously (suspends the task if the lock isn't available).
    pub fn lock_async(&self) -> LockFuture<'_, T> {
        LockFuture { lock: self }
    }

    /// Alias for `blocking_lock()` for compatibility with std Mutex API.
    ///
    /// Prefer using `blocking_lock()` explicitly for clarity in async code,
    /// or `lock_async()` for async contexts.
    #[inline]
    pub fn lock(&self) -> BlockingGuard<'_, T> {
        self.blocking_lock()
    }
}

// Methods that work with T: ?Sized (for guards that may hold unsized types)
impl<T: ?Sized> AsyncMutex<T> {
    /// Internal unlock used by guards: clear locked flag and wake one waiter if present.
    fn unlock(&self) {
        // Clear the locked flag first so the woken task can acquire it immediately.
        self.locked.store(false, Ordering::Release);

        // Wake one registered waiter, if any.
        if let Some(waiters_result) = self.waiters.try_lock() {
            let mut waiters = match waiters_result {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Some(w) = waiters.pop_front() {
                w.wake();
            }
        }
    }
}

/// Blocking guard returned by `blocking_lock()` or `try_lock()`.
pub struct BlockingGuard<'a, T: ?Sized> {
    lock: &'a AsyncMutex<T>,
    nosend: PhantomData<alloc::rc::Rc<()>>,
}

impl<T: ?Sized> Deref for BlockingGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}
impl<T: ?Sized> DerefMut for BlockingGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for BlockingGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.unlock();
    }
}

/// Future returned by `lock_async()`.
pub struct LockFuture<'a, T: ?Sized> {
    lock: &'a AsyncMutex<T>,
}

impl<'a, T: ?Sized> Future for LockFuture<'a, T> {
    type Output = AsyncGuard<'a, T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Fast path: try to acquire immediately
        if self
            .lock
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return Poll::Ready(AsyncGuard {
                lock: self.lock,
                nosend: PhantomData,
            });
        }

        // Otherwise, register waker and go pending
        let mut waiters = match self.lock.waiters.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        // Replace identical waker if present to avoid duplicates; otherwise push
        // (We keep the logic simple: push if will_wake doesn't match any existing waker)
        let mut replace_idx: Option<usize> = None;
        for (i, w) in waiters.iter().enumerate() {
            if w.will_wake(cx.waker()) {
                replace_idx = Some(i);
                break;
            }
        }
        if let Some(i) = replace_idx {
            waiters[i] = cx.waker().clone();
        } else {
            waiters.push_back(cx.waker().clone());
        }

        Poll::Pending
    }
}

/// Guard returned by `lock_async().await`.
pub struct AsyncGuard<'a, T: ?Sized> {
    lock: &'a AsyncMutex<T>,
    nosend: PhantomData<alloc::rc::Rc<()>>,
}

impl<T: ?Sized> Deref for AsyncGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}
impl<T: ?Sized> DerefMut for AsyncGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for AsyncGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.unlock();
    }
}

// ========================= QEMU Test Exports =========================
#[cfg(test)]
pub(crate) mod qemu_tests {
    // explicit imports reduce wildcard usage
    use super::AsyncMutex;
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    pub fn blocking_lock_basic_smoke() -> bool {
        let m = AsyncMutex::new(0usize);
        {
            let mut g = m.blocking_lock();
            *g += 1;
        }
        match m.try_lock() {
            Some(g) => *g == 1usize,
            None => false,
        }
    }

    pub fn async_lock_wait_then_acquire_smoke() -> bool {
        let m = AsyncMutex::new(0usize);
        let held = m.blocking_lock();

        let mut fut = m.lock_async();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        if !matches!(Pin::new(&mut fut).poll(&mut cx), Poll::Pending) {
            return false;
        }

        drop(held);

        let mut guard = match Pin::new(&mut fut).poll(&mut cx) {
            Poll::Ready(g) => g,
            Poll::Pending => return false,
        };
        *guard += 1;
        drop(guard);

        match m.try_lock() {
            Some(g) => *g == 1usize,
            None => false,
        }
    }

    fn noop_waker() -> Waker {
        unsafe fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(core::ptr::null(), &VTABLE)
        }
        unsafe fn wake(_: *const ()) {}
        unsafe fn wake_by_ref(_: *const ()) {}
        unsafe fn drop(_: *const ()) {}
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
        let raw = RawWaker::new(core::ptr::null(), &VTABLE);
        unsafe { Waker::from_raw(raw) }
    }
}
