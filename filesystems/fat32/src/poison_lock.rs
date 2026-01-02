// ============================================================================
// filesystems/fat32/src/poison_lock.rs - Minimal poison-aware spinlock for FAT32
// ============================================================================

#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

/// Minimal poison-aware lock (spin-based).
///
/// This is a local, no_std-compatible lock used to avoid `spin::RwLock` in FS code.
pub struct PoisonLock<T: ?Sized> {
    locked: AtomicBool,
    poisoned: AtomicBool,
    data: UnsafeCell<T>,
}

unsafe impl<T: ?Sized + Send> Sync for PoisonLock<T> {}
unsafe impl<T: ?Sized + Send> Send for PoisonLock<T> {}

impl<T> PoisonLock<T> {
    pub const fn new(data: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            poisoned: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }
}

impl<T: ?Sized> PoisonLock<T> {
    /// Acquire the lock (spins until available).
    pub fn lock(&self) -> PoisonLockGuard<'_, T> {
        while self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }

        if self.poisoned.load(Ordering::Acquire) {
            log::error!("[fat32] PoisonLock is poisoned; continuing with best-effort access");
        }

        PoisonLockGuard { lock: self, nosend: core::marker::PhantomData }
    }

    /// Try to acquire the lock without blocking.
    pub fn try_lock(&self) -> Option<PoisonLockGuard<'_, T>> {
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(PoisonLockGuard { lock: self, nosend: core::marker::PhantomData })
        } else {
            None
        }
    }

    /// Check if the lock was poisoned by a panic.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
    }

    /// Clear the poisoned state (manual recovery).
    pub fn clear_poison(&self) {
        self.poisoned.store(false, Ordering::Release);
    }
}

/// Guard for `PoisonLock`.
///
/// Keep the guard scope short and never hold it across `.await`.
pub struct PoisonLockGuard<'a, T: ?Sized> {
    lock: &'a PoisonLock<T>,
    /// Prevent the guard from being `Send` across threads or being held across `.await` points
    /// (holding a spin-based lock across an `.await` is unsafe — use an async-aware mutex instead).
    nosend: core::marker::PhantomData<alloc::rc::Rc<()>>,
}

impl<T: ?Sized> Deref for PoisonLockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for PoisonLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for PoisonLockGuard<'_, T> {
    fn drop(&mut self) {
        #[cfg(test)]
        if std::thread::panicking() {
            self.lock.poisoned.store(true, Ordering::Release);
        }
        self.lock.locked.store(false, Ordering::Release);
    }
}
