// ============================================================================
// libs/sync/src/poison_lock.rs - パニック時自動毒入れロック
// ============================================================================
//!
//! `ExoRust`設計書 8.4: Poisoning戦略：共有リソースの安全な回収
//!
//! ドメインが`Mutex`を保持したままパニックすると、そのロックを待機している
//! 他のドメインがデッドロックに陥る問題を解決する。
//!
//! `PoisonLock<T>`は、ロックを保持中にパニックが発生すると自動的に
//! "poisoned"（毒入れされた）状態としてマークされる。
use core::cell::UnsafeCell;
use core::fmt;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::Backoff;

// ============================================================================
// PoisonError - ロックが毒入れされた場合のエラー
// ============================================================================

#[derive(Debug)]
pub struct PoisonError<T> {
    guard: T,
}

impl<T> PoisonError<T> {
    pub(crate) const fn new(guard: T) -> Self {
        Self { guard }
    }
    pub fn into_inner(self) -> T {
        self.guard
    }
    pub const fn get_ref(&self) -> &T {
        &self.guard
    }
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

impl<T> fmt::Display for PoisonError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "lock was poisoned (holder panicked)")
    }
}

pub type LockResult<Guard> = Result<Guard, PoisonError<Guard>>;

// ============================================================================
// PoisonRwLock
// ============================================================================

pub struct PoisonRwLock<T> {
    inner: spin::RwLock<T>,
    poisoned: AtomicBool,
}

unsafe impl<T: Send + Sync> Sync for PoisonRwLock<T> {}
unsafe impl<T: Send> Send for PoisonRwLock<T> {}

impl<T> PoisonRwLock<T> {
    pub const fn new(data: T) -> Self {
        Self {
            inner: spin::RwLock::new(data),
            poisoned: AtomicBool::new(false),
        }
    }

    /// # Errors
    ///
    /// Returns a poison error containing the acquired guard if a writer
    /// previously panicked while holding the lock.
    pub fn read(&self) -> LockResult<PoisonRwLockReadGuard<'_, T>> {
        let guard = self.inner.read();
        let p_guard = PoisonRwLockReadGuard { guard };
        if self.poisoned.load(Ordering::Acquire) {
            Err(PoisonError::new(p_guard))
        } else {
            Ok(p_guard)
        }
    }

    /// # Errors
    ///
    /// Returns a poison error containing the acquired guard if a writer
    /// previously panicked while holding the lock.
    pub fn write(&self) -> LockResult<PoisonRwLockWriteGuard<'_, T>> {
        let guard = self.inner.write();
        let p_guard = PoisonRwLockWriteGuard { lock: self, guard };
        if self.poisoned.load(Ordering::Acquire) {
            Err(PoisonError::new(p_guard))
        } else {
            Ok(p_guard)
        }
    }

    pub fn try_read(&self) -> Option<LockResult<PoisonRwLockReadGuard<'_, T>>> {
        self.inner.try_read().map(|guard| {
            let p_guard = PoisonRwLockReadGuard { guard };
            if self.poisoned.load(Ordering::Acquire) {
                Err(PoisonError::new(p_guard))
            } else {
                Ok(p_guard)
            }
        })
    }

    pub fn try_write(&self) -> Option<LockResult<PoisonRwLockWriteGuard<'_, T>>> {
        self.inner.try_write().map(|guard| {
            let p_guard = PoisonRwLockWriteGuard { lock: self, guard };
            if self.poisoned.load(Ordering::Acquire) {
                Err(PoisonError::new(p_guard))
            } else {
                Ok(p_guard)
            }
        })
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Relaxed)
    }
    pub fn clear_poison(&self) {
        self.poisoned.store(false, Ordering::Release);
    }
}

pub struct PoisonRwLockReadGuard<'a, T> {
    guard: spin::RwLockReadGuard<'a, T>,
}

impl<T> Deref for PoisonRwLockReadGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &*self.guard
    }
}

pub struct PoisonRwLockWriteGuard<'a, T> {
    lock: &'a PoisonRwLock<T>,
    guard: spin::RwLockWriteGuard<'a, T>,
}

impl<T> Deref for PoisonRwLockWriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &*self.guard
    }
}

impl<T> DerefMut for PoisonRwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut *self.guard
    }
}

impl<T> Drop for PoisonRwLockWriteGuard<'_, T> {
    fn drop(&mut self) {
        if is_panicking() {
            self.lock.poisoned.store(true, Ordering::Release);
        }
    }
}

// ============================================================================
// PoisonLock
// ============================================================================

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

    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the operation fails.
    pub fn lock(&self) -> LockResult<PoisonLockGuard<'_, T>> {
        let mut backoff = Backoff::new();
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            backoff.spin();
        }
        let guard = PoisonLockGuard {
            lock: self,
            _nosend: core::marker::PhantomData,
        };
        if self.poisoned.load(Ordering::Acquire) {
            Err(PoisonError::new(guard))
        } else {
            Ok(guard)
        }
    }

    pub fn try_lock(&self) -> Option<LockResult<PoisonLockGuard<'_, T>>> {
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            let guard = PoisonLockGuard {
                lock: self,
                _nosend: core::marker::PhantomData,
            };
            if self.poisoned.load(Ordering::Acquire) {
                Some(Err(PoisonError::new(guard)))
            } else {
                Some(Ok(guard))
            }
        } else {
            None
        }
    }

    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Relaxed)
    }
    pub fn clear_poison(&self) {
        self.poisoned.store(false, Ordering::Release);
    }
}

pub struct PoisonLockGuard<'a, T: ?Sized> {
    lock: &'a PoisonLock<T>,
    _nosend: core::marker::PhantomData<*const ()>,
}

impl<T: ?Sized> Deref for PoisonLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for PoisonLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for PoisonLockGuard<'_, T> {
    fn drop(&mut self) {
        if is_panicking() {
            self.lock.poisoned.store(true, Ordering::Release);
        }
        self.lock.locked.store(false, Ordering::Release);
    }
}

// ============================================================================
// IrqPoisonLock (x86_64 only)
// ============================================================================

#[cfg(target_arch = "x86_64")]
pub struct IrqPoisonLock<T: ?Sized> {
    inner: PoisonLock<T>,
}

#[cfg(target_arch = "x86_64")]
impl<T> IrqPoisonLock<T> {
    pub const fn new(data: T) -> Self {
        Self {
            inner: PoisonLock::new(data),
        }
    }

    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the operation fails.
    pub fn lock(&self) -> LockResult<IrqPoisonLockGuard<'_, T>> {
        let mut flags: usize = 0;
        unsafe {
            core::arch::asm!("pushfq; pop {}", out(reg) flags, options(nomem, nostack));
            core::arch::asm!("cli", options(nomem, nostack));
        }
        match self.inner.lock() {
            Ok(guard) => Ok(IrqPoisonLockGuard {
                guard,
                rflags: flags,
            }),
            Err(e) => Err(PoisonError::new(IrqPoisonLockGuard {
                guard: e.into_inner(),
                rflags: flags,
            })),
        }
    }

    pub fn try_lock(&self) -> Option<LockResult<IrqPoisonLockGuard<'_, T>>> {
        let mut flags: usize = 0;
        unsafe {
            core::arch::asm!("pushfq; pop {}", out(reg) flags, options(nomem, nostack));
            core::arch::asm!("cli", options(nomem, nostack));
        }
        match self.inner.try_lock() {
            Some(Ok(guard)) => Some(Ok(IrqPoisonLockGuard {
                guard,
                rflags: flags,
            })),
            Some(Err(e)) => Some(Err(PoisonError::new(IrqPoisonLockGuard {
                guard: e.into_inner(),
                rflags: flags,
            }))),
            None => {
                if (flags & (1 << 9)) != 0 {
                    unsafe {
                        core::arch::asm!("sti", options(nomem, nostack));
                    }
                }
                None
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
pub struct IrqPoisonLockGuard<'a, T: ?Sized> {
    guard: PoisonLockGuard<'a, T>,
    rflags: usize,
}

#[cfg(target_arch = "x86_64")]
impl<T: ?Sized> Deref for IrqPoisonLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &*self.guard
    }
}

#[cfg(target_arch = "x86_64")]
impl<T: ?Sized> DerefMut for IrqPoisonLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut *self.guard
    }
}

#[cfg(target_arch = "x86_64")]
impl<T: ?Sized> Drop for IrqPoisonLockGuard<'_, T> {
    fn drop(&mut self) {
        let restore_irq = (self.rflags & (1 << 9)) != 0;
        if restore_irq {
            unsafe {
                core::arch::asm!("sti", options(nomem, nostack));
            }
        }
    }
}

// ============================================================================
// パニック検出ヘルパー
// ============================================================================

static PANICKING_CORES: AtomicU64 = AtomicU64::new(0);

fn is_panicking() -> bool {
    #[cfg(feature = "std")]
    {
        std::thread::panicking()
    }
    #[cfg(not(feature = "std"))]
    {
        let core_id = get_current_core_id();
        if core_id >= 64 {
            return false;
        }
        let mask = PANICKING_CORES.load(Ordering::Acquire);
        (mask & (1u64 << core_id)) != 0
    }
}

pub fn set_panicking(panicking: bool) {
    let core_id = get_current_core_id();
    if core_id >= 64 {
        return;
    }
    let bit = 1u64 << core_id;
    if panicking {
        PANICKING_CORES.fetch_or(bit, Ordering::Release);
    } else {
        PANICKING_CORES.fetch_and(!bit, Ordering::Release);
    }
}

#[inline]
fn get_current_core_id() -> u32 {
    #[cfg(test)]
    {
        return 0;
    }
    #[cfg(not(test))]
    {
        #[cfg(target_arch = "x86_64")]
        {
            let aux: u32;
            unsafe {
                core::arch::asm!("rdtscp", out("ecx") aux, out("eax") _, out("edx") _, options(nomem, nostack));
            }
            aux
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            0
        }
    }
}
