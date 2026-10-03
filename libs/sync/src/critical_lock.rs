//! Non-poisoning locks whose ownership excludes local task preemption.
//!
//! Interrupt handlers must still use an IRQ-safe lock for data they share with
//! tasks. Preemption exclusion does not mask interrupts or prevent ISR reentry.

use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};
use hal::preemption::PreemptionGuard;

#[derive(Debug)]
pub struct Mutex<T: ?Sized>(spin::Mutex<T>);

impl<T> Mutex<T> {
    pub const fn new(value: T) -> Self {
        Self(spin::Mutex::new(value))
    }

    pub fn into_inner(self) -> T {
        self.0.into_inner()
    }
}

impl<T: ?Sized> Mutex<T> {
    /// Exclusion begins before spinning so a local owner cannot be suspended.
    pub fn lock(&self) -> MutexGuard<'_, T> {
        let preemption = PreemptionGuard::enter();
        MutexGuard {
            inner: ManuallyDrop::new(self.0.lock()),
            _preemption: preemption,
        }
    }

    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        let preemption = PreemptionGuard::enter();
        self.0.try_lock().map(|inner| MutexGuard {
            inner: ManuallyDrop::new(inner),
            _preemption: preemption,
        })
    }

    pub fn get_mut(&mut self) -> &mut T {
        self.0.get_mut()
    }
}

impl<T: Default> Default for Mutex<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

pub struct MutexGuard<'a, T: ?Sized> {
    inner: ManuallyDrop<spin::MutexGuard<'a, T>>,
    _preemption: PreemptionGuard,
}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        // SAFETY: this guard owns the inner guard and drops it exactly once,
        // before the CPU-local exclusion field is automatically released.
        unsafe { ManuallyDrop::drop(&mut self.inner) };
    }
}

#[derive(Debug)]
pub struct RwLock<T: ?Sized>(spin::RwLock<T>);

impl<T> RwLock<T> {
    pub const fn new(value: T) -> Self {
        Self(spin::RwLock::new(value))
    }
    pub fn into_inner(self) -> T {
        self.0.into_inner()
    }
}

impl<T: ?Sized> RwLock<T> {
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        let preemption = PreemptionGuard::enter();
        RwLockReadGuard {
            inner: ManuallyDrop::new(self.0.read()),
            _preemption: preemption,
        }
    }
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        let preemption = PreemptionGuard::enter();
        RwLockWriteGuard {
            inner: ManuallyDrop::new(self.0.write()),
            _preemption: preemption,
        }
    }
    pub fn try_read(&self) -> Option<RwLockReadGuard<'_, T>> {
        let preemption = PreemptionGuard::enter();
        self.0.try_read().map(|inner| RwLockReadGuard {
            inner: ManuallyDrop::new(inner),
            _preemption: preemption,
        })
    }
    pub fn try_write(&self) -> Option<RwLockWriteGuard<'_, T>> {
        let preemption = PreemptionGuard::enter();
        self.0.try_write().map(|inner| RwLockWriteGuard {
            inner: ManuallyDrop::new(inner),
            _preemption: preemption,
        })
    }
    pub fn get_mut(&mut self) -> &mut T {
        self.0.get_mut()
    }
}

impl<T: Default> Default for RwLock<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

pub struct RwLockReadGuard<'a, T: ?Sized> {
    inner: ManuallyDrop<spin::RwLockReadGuard<'a, T>>,
    _preemption: PreemptionGuard,
}

impl<T: ?Sized> Deref for RwLockReadGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T: ?Sized> Drop for RwLockReadGuard<'_, T> {
    fn drop(&mut self) {
        // SAFETY: exclusive ownership of the guard guarantees exactly one
        // unlock, before releasing local preemption exclusion.
        unsafe { ManuallyDrop::drop(&mut self.inner) };
    }
}

pub struct RwLockWriteGuard<'a, T: ?Sized> {
    inner: ManuallyDrop<spin::RwLockWriteGuard<'a, T>>,
    _preemption: PreemptionGuard,
}

impl<T: ?Sized> Deref for RwLockWriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T: ?Sized> DerefMut for RwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: ?Sized> Drop for RwLockWriteGuard<'_, T> {
    fn drop(&mut self) {
        // SAFETY: exclusive ownership of the guard guarantees exactly one
        // unlock, before releasing local preemption exclusion.
        unsafe { ManuallyDrop::drop(&mut self.inner) };
    }
}
