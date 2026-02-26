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
//!
//! # 実装の関係
//!
//! - **正規版**: `kernel/src/sync/poison_lock.rs` (IrqPoisonLock, メトリクス含む)
//! - **本ファイル**: 外部クレート向けスタンドアロン版 (filesystems/fat32, pure-tests等)
//!
//! API契約は正規版に準拠。カーネル固有機能（IrqPoisonLock, ロックメトリクス）は
//! 本ファイルには含まれない。

#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::fmt;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::Backoff;

// ============================================================================
// PoisonError - ロックが毒入れされた場合のエラー
// ============================================================================

/// ロックが毒入れされた場合のエラー
///
/// 設計書 8.4: 次にその`Mutex`をロックしようとしたドメインには、
/// `Result::Err(PoisonError)` が返される。
#[derive(Debug)]
pub struct PoisonError<T> {
    /// 毒入れされたガード（回復用）
    guard: T,
}

impl<T> PoisonError<T> {
    /// 新しい`PoisonError`を作成
    pub(crate) const fn new(guard: T) -> Self {
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
    pub const fn get_ref(&self) -> &T {
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

/// `PoisonLock::lock()`の戻り値型
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
    /// 新しい`PoisonLock`を作成
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
    ///
    /// # Errors
    ///
    /// ロックが毒入れされている場合、`PoisonError`を含む`Err`を返す。
    pub fn lock(&self) -> LockResult<PoisonLockGuard<'_, T>> {
        #[cfg(feature = "metrics")]
        let _start_spin_count: u64;
        #[cfg(feature = "metrics")]
        {
            _start_spin_count = 0;
        }

        let mut spin_count: u64 = 0;
        let mut backoff = Backoff::new();

        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            backoff.spin();
            spin_count = spin_count.wrapping_add(1);
        }

        // メトリクス更新
        #[cfg(feature = "metrics")]
        {
            LOCK_ACQUIRE_COUNT.fetch_add(1, Ordering::Relaxed);
            if spin_count > 0 {
                LOCK_CONTENTION_EVENTS.fetch_add(1, Ordering::Relaxed);
            }
        }

        let guard = PoisonLockGuard {
            lock: self,
            _nosend: core::marker::PhantomData,
        };

        // 毒入れ状態をチェック
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
            #[cfg(feature = "metrics")]
            LOCK_ACQUIRE_COUNT.fetch_add(1, Ordering::Relaxed);

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

    /// 初期化時のベストエフォート回復用ロック
    ///
    /// ロックが毒入れされている場合でも警告ログを出力して
    /// 内部ガードを返す。これは初期化時や例外的な回復パスでのみ使用する。
    /// ランタイム/ホットパスでは明示的なエラー処理を推奨。
    pub fn lock_for_init(&self, context: &str) -> PoisonLockGuard<'_, T> {
        match self.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                #[cfg(feature = "log")]
                log::warn!(
                    "[POISON] {} - lock poisoned during init; proceeding with best-effort",
                    context
                );
                let _ = context; // suppress unused warning when log is disabled
                poisoned.into_inner()
            }
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
    #[allow(clippy::mut_from_ref)]
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

/// `PoisonLock`のガード
///
/// ドロップ時にロックを解放する。
/// パニック中にドロップされると、ロックが毒入れされる。
pub struct PoisonLockGuard<'a, T: ?Sized> {
    lock: &'a PoisonLock<T>,
    /// `.await`をまたいでガードを保持することを防ぐ（スピンロックはasync非対応）
    _nosend: core::marker::PhantomData<*const ()>,
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
        if is_panicking() {
            self.lock.poisoned.store(true, Ordering::Release);
            #[cfg(feature = "log")]
            log::info!("[PoisonLock] Lock poisoned due to panic");
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

/// 現在パニック中のCPUコアのビットマスク（最大64コア対応）
static PANICKING_CORES: AtomicU64 = AtomicU64::new(0);

/// 現在のCPUコアがパニック中かどうかをチェック
fn is_panicking() -> bool {
    // std環境ではstd::thread::panickingを使用
    #[cfg(feature = "std")]
    {
        std::thread::panicking()
    }

    // no_std環境ではコアIDベースのフラグをチェック
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

/// 現在のCPUコアのパニック状態を設定（no_std環境用）
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

/// 現在のCPUコアIDを取得
#[inline]
fn get_current_core_id() -> u32 {
    // テスト環境ではコア0を返す
    #[cfg(test)]
    {
        return 0;
    }

    #[cfg(not(test))]
    {
        // x86_64ではRDTSCPのAUX値を使用
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
}

// ============================================================================
// Lock acquisition metrics (軽量計測用)
// ============================================================================

#[cfg(feature = "metrics")]
static LOCK_ACQUIRE_COUNT: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "metrics")]
static LOCK_CONTENTION_EVENTS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "metrics")]
static LOCK_TOTAL_ACQUIRE_TICKS: AtomicU64 = AtomicU64::new(0);

/// ロック計測値を取得する構造体
#[cfg(feature = "metrics")]
pub struct LockMetrics {
    pub acquire_count: u64,
    pub contention_events: u64,
    pub total_acquire_ticks: u64,
    pub average_acquire_ticks: u64,
}

/// 計測値を返す
#[cfg(feature = "metrics")]
pub fn get_lock_metrics() -> LockMetrics {
    let acq = LOCK_ACQUIRE_COUNT.load(Ordering::Relaxed);
    let cont = LOCK_CONTENTION_EVENTS.load(Ordering::Relaxed);
    let total = LOCK_TOTAL_ACQUIRE_TICKS.load(Ordering::Relaxed);
    let avg = total.checked_div(acq).unwrap_or(0);
    LockMetrics {
        acquire_count: acq,
        contention_events: cont,
        total_acquire_ticks: total,
        average_acquire_ticks: avg,
    }
}

/// 計測値をリセット（テスト用）
#[cfg(feature = "metrics")]
pub fn reset_lock_metrics() {
    LOCK_ACQUIRE_COUNT.store(0, Ordering::Relaxed);
    LOCK_CONTENTION_EVENTS.store(0, Ordering::Relaxed);
    LOCK_TOTAL_ACQUIRE_TICKS.store(0, Ordering::Relaxed);
}

#[cfg(test)]
#[allow(clippy::must_use_candidate)]
mod qemu_tests {
    use super::PoisonLock;
    use core::sync::atomic::Ordering;

    pub fn basic_lock_smoke() -> bool {
        let lock = PoisonLock::new(42);

        let Ok(guard) = lock.lock() else {
            return false;
        };
        let ok = *guard == 42;
        drop(guard);

        ok && !lock.is_locked() && !lock.is_poisoned()
    }

    pub fn try_lock_smoke() -> bool {
        let lock = PoisonLock::new(42);

        let Some(Ok(guard)) = lock.try_lock() else {
            return false;
        };
        let value_ok = *guard == 42;
        let contention_ok = lock.try_lock().is_none();
        drop(guard);

        value_ok && contention_ok && lock.try_lock().is_some()
    }

    pub fn initial_poison_state_smoke() -> bool {
        let lock = PoisonLock::new(0u32);
        !lock.is_poisoned()
    }

    pub fn clear_poison_smoke() -> bool {
        let lock = PoisonLock::new(42);

        lock.poisoned.store(true, Ordering::Release);
        if !lock.is_poisoned() {
            return false;
        }
        lock.clear_poison();
        !lock.is_poisoned()
    }

    pub fn default_lock_smoke() -> bool {
        let lock: PoisonLock<i32> = PoisonLock::default();
        lock.lock().map_or(false, |guard| *guard == 0)
    }
}

#[cfg(test)]
mod qemu_smoke_tests {
    use super::qemu_tests;

    #[test]
    fn basic_lock_smoke() {
        assert!(qemu_tests::basic_lock_smoke());
    }

    #[test]
    fn try_lock_smoke() {
        assert!(qemu_tests::try_lock_smoke());
    }

    #[test]
    fn initial_poison_state_smoke() {
        assert!(qemu_tests::initial_poison_state_smoke());
    }

    #[test]
    fn clear_poison_smoke() {
        assert!(qemu_tests::clear_poison_smoke());
    }

    #[test]
    fn default_lock_smoke() {
        assert!(qemu_tests::default_lock_smoke());
    }
}

