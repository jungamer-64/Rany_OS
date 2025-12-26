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

use crate::poison_lock::PoisonLock;
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
        if let Some(w) = self.waiters.try_lock().and_then(|mut q| q.pop_front()) {
            w.wake();
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
        let mut waiters = self.lock.waiters.lock();

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

// ========================= Tests =========================
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};

    // Basic blocking behavior
    #[test]
    fn blocking_lock_basic() {
        let m = Arc::new(AsyncMutex::new(0usize));
        {
            let mut g = m.blocking_lock();
            *g += 1;
        }
        let g = m.try_lock().expect("should lock");
        assert_eq!(*g, 1usize);
    }

    // Simple async lock test using std executor
    #[test]
    fn async_lock_order() {
        use futures::executor::LocalPool;
        use futures::task::LocalSpawnExt;

        let pool = &mut LocalPool::new();
        let spawner = pool.spawner();

        let m = Arc::new(AsyncMutex::new(0usize));
        let cnt = Arc::new(AtomicUsize::new(0));

        // Task A acquires lock and holds it for one wake cycle
        {
            let m = m.clone();
            let cnt = cnt.clone();
            spawner
                .spawn_local(async move {
                    let mut g = m.lock_async().await;
                    *g += 1;
                    // simulate some async yield
                    cnt.fetch_add(1, Ordering::SeqCst);
                })
                .unwrap();
        }

        // Task B will wait for the lock
        {
            let m = m.clone();
            let cnt = cnt.clone();
            spawner
                .spawn_local(async move {
                    let mut g = m.lock_async().await;
                    // by the time we get the lock, A should have run
                    assert!(cnt.load(Ordering::SeqCst) >= 1);
                    *g += 10;
                })
                .unwrap();
        }

        pool.run();

        // final value should be 11
        let g = m.try_lock().expect("lock freed");
        assert_eq!(*g, 11usize);
    }
}
