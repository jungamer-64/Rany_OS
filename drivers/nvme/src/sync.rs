// ============================================================================
// src/io/nvme/sync.rs - ISR-safe Mutex
// ============================================================================
// Copied/Adapted from kernel/src/sync/irq_mutex.rs to make it available to the driver
// which cannot depend on the kernel crate.

use core::cell::UnsafeCell;
use core::fmt;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

/// A Mutex that disables interrupts while locked.
///
/// This is necessary for data structures shared between thread context and ISR context.
/// If a regular spinlock is used, an interrupt could occur while the lock is held,
/// and if the ISR tries to acquire the same lock, a deadlock occurs.
pub struct IrqMutex<T: ?Sized> {
    lock: AtomicBool,
    data: UnsafeCell<T>,
}

unsafe impl<T: ?Sized + Send> Sync for IrqMutex<T> {}
unsafe impl<T: ?Sized + Send> Send for IrqMutex<T> {}

/// A guard that restores the interrupt state when dropped.
pub struct IrqMutexGuard<'a, T: ?Sized + 'a> {
    lock: &'a AtomicBool,
    data: &'a mut T,
    saved_int_state: bool,
}

impl<T> IrqMutex<T> {
    /// Creates a new IrqMutex.
    pub const fn new(data: T) -> Self {
        Self {
            lock: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }
}

impl<T: ?Sized> IrqMutex<T> {
    /// Locks the mutex and disables interrupts.
    ///
    /// Returns a guard that will restore the previous interrupt state when dropped.
    pub fn lock(&self) -> IrqMutexGuard<'_, T> {
        // 1. Disable interrupts and save state
        let saved_int_state = x86_64::instructions::interrupts::are_enabled();
        x86_64::instructions::interrupts::disable();

        // 2. Acquire lock (spin)
        while self
            .lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Spin wait
            core::hint::spin_loop();
        }

        // 3. Return guard
        IrqMutexGuard {
            lock: &self.lock,
            data: unsafe { &mut *self.data.get() },
            saved_int_state,
        }
    }

    /// Try to lock the mutex.
    ///
    /// If successful, returns the guard. Interrupts are disabled if successful.
    /// If failed, returns None and interrupt state is unchanged (or restored).
    pub fn try_lock(&self) -> Option<IrqMutexGuard<'_, T>> {
        let saved_int_state = x86_64::instructions::interrupts::are_enabled();
        x86_64::instructions::interrupts::disable();

        if self
            .lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(IrqMutexGuard {
                lock: &self.lock,
                data: unsafe { &mut *self.data.get() },
                saved_int_state,
            })
        } else {
            // Restore interrupts if we didn't get the lock
            if saved_int_state {
                x86_64::instructions::interrupts::enable();
            }
            None
        }
    }
}

impl<'a, T: ?Sized> Deref for IrqMutexGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.data
    }
}

impl<'a, T: ?Sized> DerefMut for IrqMutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.data
    }
}

impl<'a, T: ?Sized> Drop for IrqMutexGuard<'a, T> {
    fn drop(&mut self) {
        self.lock.store(false, Ordering::Release);

        // Restore interrupts if they were enabled before locking
        if self.saved_int_state {
            x86_64::instructions::interrupts::enable();
        }
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for IrqMutex<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Note: attempting to lock to check value might be dangerous in Debug
        write!(f, "IrqMutex {{ <locked> }}")
    }
}
