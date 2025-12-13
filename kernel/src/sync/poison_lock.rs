// ============================================================================
// src/sync/poison_lock.rs - パニック時自動毒入れロック
// 設計書 8.4: Poisoning戦略：共有リソースの安全な回収
//
// ドメインがMutexを保持したままパニックすると、そのロックを待機している
// 他のドメインがデッドロックに陥る問題を解決する。
//
// PoisonLock<T>は、ロックを保持中にパニックが発生すると自動的に
// "poisoned"（毒入れされた）状態としてマークされる。
// ============================================================================
#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::fmt;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

use super::lockfree::Backoff;

// ============================================================================
// PoisonError - ロックが毒入れされた場合のエラー
// ============================================================================

/// ロックが毒入れされた場合のエラー
///
/// 設計書 8.4: 次にそのMutexをロックしようとしたドメインには、
/// `Result::Err(PoisonError)` が返される。
#[derive(Debug)]
pub struct PoisonError<T> {
    /// 毒入れされたガード（回復用）
    guard: T,
}

impl<T> PoisonError<T> {
    /// 新しいPoisonErrorを作成
    fn new(guard: T) -> Self {
        Self { guard }
    }

    /// 毒入れされたデータへのアクセスを取得
    ///
    /// # 注意
    /// このメソッドを使用すると、不整合な状態のデータにアクセスする可能性があります。
    /// 呼び出し側は、データの整合性を確認・修復する責任があります。
    pub fn into_inner(self) -> T {
        self.guard
    }

    /// 毒入れされたデータへの参照を取得
    pub fn get_ref(&self) -> &T {
        &self.guard
    }

    /// 毒入れされたデータへの可変参照を取得
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

impl<T> fmt::Display for PoisonError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "lock was poisoned (holder panicked)")
    }
}

/// PoisonLock::lock()の戻り値型
pub type LockResult<Guard> = Result<Guard, PoisonError<Guard>>;

// ============================================================================
// PoisonLock - パニック時自動毒入れMutex
// ============================================================================

/// パニック時自動毒入れMutex
///
/// 設計書 8.4: 共有リソースへのアクセスには、標準的な `Mutex<T>` の代わりに
/// 「Poisoning対応ラッパー」（`PoisonLock<T>`）の使用を必須とする。
///
/// # 特徴
/// - ロック保持中にパニックが発生すると自動的にpoisoned状態になる
/// - poisoned状態のロックにアクセスするとエラーが返される
/// - 呼び出し側はエラー処理（リトライ、代替リソースの使用、縮退運転等）が可能
///
/// # 使用例
/// ```ignore
/// let lock = PoisonLock::new(MyData::new());
///
/// match lock.lock() {
///     Ok(guard) => {
///         // 正常にロックを取得
///         guard.do_something();
///     }
///     Err(poisoned) => {
///         // ロックが毒入れされている
///         // 回復処理またはエラー伝播
///         let guard = poisoned.into_inner();
///         // データの整合性を確認・修復...
///     }
/// }
/// ```
pub struct PoisonLock<T: ?Sized> {
    /// スピンロック本体
    locked: AtomicBool,
    /// 毒入れフラグ
    poisoned: AtomicBool,
    /// 保護されるデータ
    data: UnsafeCell<T>,
}

// SAFETY: PoisonLock は排他的アクセスを保証する
unsafe impl<T: ?Sized + Send> Sync for PoisonLock<T> {}
unsafe impl<T: ?Sized + Send> Send for PoisonLock<T> {}

impl<T> PoisonLock<T> {
    /// 新しいPoisonLockを作成
    pub const fn new(data: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            poisoned: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    /// ロックを取得
    ///
    /// ロックが毒入れされている場合は`Err(PoisonError)`を返す。
    /// 呼び出し側は`into_inner()`で回復を試みることができる。
    pub fn lock(&self) -> LockResult<PoisonLockGuard<'_, T>> {
        // 1. スピンロックを取得（指数バックオフ付き）
        let mut backoff = Backoff::new();
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            backoff.spin();
        }

        let guard = PoisonLockGuard {
            lock: self,
            panicking: false,
        };

        // 2. 毒入れ状態をチェック
        if self.poisoned.load(Ordering::Acquire) {
            Err(PoisonError::new(guard))
        } else {
            Ok(guard)
        }
    }

    /// ロックを試行（失敗したら即座に返る）
    pub fn try_lock(&self) -> Option<LockResult<PoisonLockGuard<'_, T>>> {
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            let guard = PoisonLockGuard {
                lock: self,
                panicking: false,
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

    /// ロック状態を確認（デバッグ用）
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }

    /// 毒入れ状態を確認
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Relaxed)
    }

    /// 毒入れ状態をクリア（回復後）
    ///
    /// # Safety
    /// 呼び出し側は、データの整合性が回復されたことを保証する必要がある
    pub fn clear_poison(&self) {
        self.poisoned.store(false, Ordering::Release);
    }

    /// 内部データへの参照を取得（ロックなし、unsafeのみ）
    ///
    /// # Safety
    /// 呼び出し側は、排他的アクセスを保証する必要がある
    pub unsafe fn get_unchecked(&self) -> &T {
        unsafe { &*self.data.get() }
    }

    /// 内部データへの可変参照を取得（ロックなし、unsafeのみ）
    ///
    /// # Safety
    /// 呼び出し側は、排他的アクセスを保証する必要がある
    pub unsafe fn get_unchecked_mut(&self) -> &mut T {
        unsafe { &mut *self.data.get() }
    }
}

impl<T: Default> Default for PoisonLock<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: fmt::Debug> fmt::Debug for PoisonLock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let poisoned = self.poisoned.load(Ordering::Relaxed);
        let locked = self.locked.load(Ordering::Relaxed);

        f.debug_struct("PoisonLock")
            .field("poisoned", &poisoned)
            .field("locked", &locked)
            .finish_non_exhaustive()
    }
}

// ============================================================================
// PoisonLockGuard - PoisonLockのガード
// ============================================================================

/// PoisonLockのガード
///
/// ドロップ時にロックを解放する。
/// パニック中にドロップされると、ロックが毒入れされる。
pub struct PoisonLockGuard<'a, T: ?Sized> {
    lock: &'a PoisonLock<T>,
    /// パニック中かどうかのフラグ（最適化用）
    panicking: bool,
}

impl<T: ?Sized> Deref for PoisonLockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: ロックを保持しているので安全にアクセス可能
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for PoisonLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: ロックを保持しているので安全にアクセス可能
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for PoisonLockGuard<'_, T> {
    fn drop(&mut self) {
        // パニック中かどうかをチェック
        // std::thread::panicking()の代わりにカスタム実装を使用
        let panicking = is_panicking();

        if panicking {
            // 設計書 8.4: パニック時のPoisoning
            // ドメインがMutexを保持したままパニックすると、
            // そのMutexは「poisoned」状態としてマークされる
            self.lock.poisoned.store(true, Ordering::Release);
            crate::serial_println!("[PoisonLock] Lock poisoned due to panic");
        }

        // スピンロックを解放
        self.lock.locked.store(false, Ordering::Release);
    }
}

impl<T: fmt::Debug + ?Sized> fmt::Debug for PoisonLockGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl<T: fmt::Display + ?Sized> fmt::Display for PoisonLockGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

// ============================================================================
// パニック検出ヘルパー
// ============================================================================

use core::sync::atomic::AtomicU32;

/// 現在パニック中のCPUコアのビットマスク（最大32コア対応）
static PANICKING_CORES: AtomicU32 = AtomicU32::new(0);

/// 現在のCPUコアがパニック中かどうかをチェック
fn is_panicking() -> bool {
    let core_id = get_current_core_id();
    if core_id >= 32 {
        return false;
    }

    let mask = PANICKING_CORES.load(Ordering::Acquire);
    (mask & (1 << core_id)) != 0
}

/// 現在のCPUコアのパニック状態を設定
pub fn set_panicking(panicking: bool) {
    let core_id = get_current_core_id();
    if core_id >= 32 {
        return;
    }

    let bit = 1u32 << core_id;
    if panicking {
        PANICKING_CORES.fetch_or(bit, Ordering::Release);
    } else {
        PANICKING_CORES.fetch_and(!bit, Ordering::Release);
    }
}

/// 現在のCPUコアIDを取得
#[inline]
fn get_current_core_id() -> u32 {
    // LAPIC IDから取得する場合（APICが利用可能な場合）
    // ここでは簡易実装としてRDTSCPのAUX値を使用
    #[cfg(target_arch = "x86_64")]
    {
        let aux: u32;
        unsafe {
            core::arch::asm!(
                "rdtscp",
                out("ecx") aux,
                out("eax") _,
                out("edx") _,
                options(nomem, nostack),
            );
        }
        aux
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

// ============================================================================
// IrqPoisonLock - 割り込み禁止 + パニック時毒入れ
// ============================================================================

/// 割り込み禁止 + パニック時毒入れMutex
///
/// IrqMutexとPoisonLockを組み合わせた実装。
/// ISRからのアクセスが必要かつ、パニック耐性も必要な場合に使用。
pub struct IrqPoisonLock<T: ?Sized> {
    /// スピンロック本体
    locked: AtomicBool,
    /// 毒入れフラグ
    poisoned: AtomicBool,
    /// 保護されるデータ
    data: UnsafeCell<T>,
}

unsafe impl<T: ?Sized + Send> Sync for IrqPoisonLock<T> {}
unsafe impl<T: ?Sized + Send> Send for IrqPoisonLock<T> {}

impl<T> IrqPoisonLock<T> {
    /// 新しいIrqPoisonLockを作成
    pub const fn new(data: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            poisoned: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    /// ロックを取得（割り込み禁止付き）
    pub fn lock(&self) -> LockResult<IrqPoisonLockGuard<'_, T>> {
        // 1. 割り込みを禁止
        let irq_was_enabled = super::irq_mutex::save_and_disable_interrupts();

        // 2. スピンロックを取得
        let mut backoff = Backoff::new();
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            backoff.spin();
        }

        let guard = IrqPoisonLockGuard {
            lock: self,
            irq_was_enabled,
        };

        // 3. 毒入れ状態をチェック
        if self.poisoned.load(Ordering::Acquire) {
            Err(PoisonError::new(guard))
        } else {
            Ok(guard)
        }
    }

    /// 毒入れ状態を確認
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Relaxed)
    }

    /// 毒入れ状態をクリア
    pub fn clear_poison(&self) {
        self.poisoned.store(false, Ordering::Release);
    }
}

/// IrqPoisonLockのガード
pub struct IrqPoisonLockGuard<'a, T: ?Sized> {
    lock: &'a IrqPoisonLock<T>,
    irq_was_enabled: bool,
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
        // パニック検出と毒入れ
        if is_panicking() {
            self.lock.poisoned.store(true, Ordering::Release);
            crate::serial_println!("[IrqPoisonLock] Lock poisoned due to panic");
        }

        // スピンロックを解放
        self.lock.locked.store(false, Ordering::Release);

        // 割り込み状態を復元
        super::irq_mutex::restore_interrupts(self.irq_was_enabled);
    }
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_lock() {
        let lock = PoisonLock::new(42);

        let guard = lock.lock().unwrap();
        assert_eq!(*guard, 42);
        drop(guard);

        assert!(!lock.is_locked());
        assert!(!lock.is_poisoned());
    }

    #[test]
    fn test_poisoned_after_simulated_panic() {
        let lock = PoisonLock::new(42);

        // パニックをシミュレート
        {
            let _guard = lock.lock().unwrap();
            set_panicking(true);
        } // ドロップ時に毒入れされる
        set_panicking(false);

        assert!(lock.is_poisoned());

        // 毒入れ後のアクセス
        match lock.lock() {
            Ok(_) => panic!("Expected PoisonError"),
            Err(err) => {
                // 回復可能
                let guard = err.into_inner();
                assert_eq!(*guard, 42);
            }
        }
    }
}
