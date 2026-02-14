// ============================================================================
// filesystems/fat32/src/irq_lock.rs - IRQ-safe PoisonLock for FAT32
// ============================================================================

#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(not(any(test, feature = "qemu-test-export")))]
use core::arch::asm;

#[cfg(any(test, feature = "qemu-test-export"))]
static TEST_INTERRUPTS_ENABLED: AtomicBool = AtomicBool::new(true);

/// Save and disable interrupts, returning whether interrupts were enabled before.
#[cfg(not(any(test, feature = "qemu-test-export")))]
#[inline]
fn save_and_disable_interrupts() -> bool {
    let rflags: u64;

    unsafe {
        // Read RFLAGS
        asm!(
            "pushfq",
            "pop {0}",
            out(reg) rflags,
            options(nomem, preserves_flags)
        );

        // Disable interrupts
        asm!("cli", options(nomem, nostack));
    }

    // IF bit (bit 9)
    (rflags & (1 << 9)) != 0
}

#[cfg(any(test, feature = "qemu-test-export"))]
#[inline]
fn save_and_disable_interrupts() -> bool {
    TEST_INTERRUPTS_ENABLED.swap(false, Ordering::SeqCst)
}

/// Restore interrupts to the previous state.
#[cfg(not(any(test, feature = "qemu-test-export")))]
#[inline]
fn restore_interrupts(was_enabled: bool) {
    if was_enabled {
        unsafe {
            asm!("sti", options(nomem, nostack));
        }
    }
}

#[cfg(any(test, feature = "qemu-test-export"))]
#[inline]
fn restore_interrupts(was_enabled: bool) {
    if was_enabled {
        TEST_INTERRUPTS_ENABLED.store(true, Ordering::SeqCst);
    }
}

/// IRQ-safe PoisonLock: disables interrupts while holding the lock and supports poisoning on panic.
pub struct IrqPoisonLock<T: ?Sized> {
    locked: AtomicBool,
    poisoned: AtomicBool,
    data: UnsafeCell<T>,
}

unsafe impl<T: ?Sized + Send> Sync for IrqPoisonLock<T> {}
unsafe impl<T: ?Sized + Send> Send for IrqPoisonLock<T> {}

impl<T> IrqPoisonLock<T> {
    pub const fn new(data: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            poisoned: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }
}

impl<T: ?Sized> IrqPoisonLock<T> {
    /// Acquire the lock with interrupts disabled. This blocks (spins) until acquired.
    pub fn lock(&self) -> IrqPoisonLockGuard<'_, T> {
        // 1. disable interrupts and save previous state
        let irq_was_enabled = save_and_disable_interrupts();

        // 2. spin to acquire lock
        while self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }

        // 3. warn if poisoned (best-effort)
        if self.poisoned.load(Ordering::Acquire) {
            log::error!("[fat32::IrqPoisonLock] lock is poisoned; continuing with best-effort access");
        }

        IrqPoisonLockGuard { lock: self, irq_was_enabled, nosend: core::marker::PhantomData }
    }

    /// Try to acquire the lock without blocking. If acquired, interrupts are disabled until guard is dropped.
    pub fn try_lock(&self) -> Option<IrqPoisonLockGuard<'_, T>> {
        // disable interrupts first
        let irq_was_enabled = save_and_disable_interrupts();
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            if self.poisoned.load(Ordering::Acquire) {
                log::error!("[fat32::IrqPoisonLock] try_lock acquired but lock is poisoned");
            }
            Some(IrqPoisonLockGuard { lock: self, irq_was_enabled, nosend: core::marker::PhantomData })
        } else {
            // failed to acquire -> restore interrupts
            restore_interrupts(irq_was_enabled);
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

/// Guard for `IrqPoisonLock`.
pub struct IrqPoisonLockGuard<'a, T: ?Sized> {
    lock: &'a IrqPoisonLock<T>,
    irq_was_enabled: bool,
    /// Prevent being `Send` (avoid accidentally moving across threads / await points)
    nosend: core::marker::PhantomData<alloc::rc::Rc<()>>,
}

impl<T: ?Sized> Deref for IrqPoisonLockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for IrqPoisonLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for IrqPoisonLockGuard<'_, T> {
    fn drop(&mut self) {
        // If we are panicking in test environment, mark poisoned
        #[cfg(test)]
        if std::thread::panicking() {
            self.lock.poisoned.store(true, Ordering::Release);
            log::error!("[fat32::IrqPoisonLock] lock poisoned due to panic");
        }

        // release lock
        self.lock.locked.store(false, Ordering::Release);

        // restore interrupts
        restore_interrupts(self.irq_was_enabled);
    }
}

// ============================================================================
// QEMU Test Exports
// ============================================================================

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::*;

    pub fn basic_locking_smoke() -> bool {
        let lock = IrqPoisonLock::new(5usize);
        {
            let mut guard = lock.lock();
            if *guard != 5 {
                return false;
            }
            *guard = 7;
        }
        {
            let guard = lock.lock();
            if *guard != 7 {
                return false;
            }
        }
        !lock.is_poisoned()
    }

    pub fn try_lock_contention_smoke() -> bool {
        let lock = IrqPoisonLock::new(1usize);
        let guard = lock.lock();
        if lock.try_lock().is_some() {
            return false;
        }
        drop(guard);
        lock.try_lock().is_some()
    }

    pub fn irq_restore_smoke() -> bool {
        TEST_INTERRUPTS_ENABLED.store(true, Ordering::SeqCst);
        if !TEST_INTERRUPTS_ENABLED.load(Ordering::SeqCst) {
            return false;
        }

        let saved = save_and_disable_interrupts();
        if !saved {
            return false;
        }
        if TEST_INTERRUPTS_ENABLED.load(Ordering::SeqCst) {
            return false;
        }

        restore_interrupts(saved);
        TEST_INTERRUPTS_ENABLED.load(Ordering::SeqCst)
    }
}
