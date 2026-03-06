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
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use super::lockfree::Backoff;
// use serial_driver::serial_println;

// ============================================================================
// PoisonError - ロックが毒入れされた場合のエラー
// ============================================================================

/// ロックが毒入れされた場合のエラー
///
/// 設計書 8.4: 次にそのMutexをロックしようとしたドメインには、
/// `Result::Err(PoisonError)` が返される。
mod tests;
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
        // 計測: ロック獲得に要した時間とコンテンション有無を記録
        #[cfg(all(test, feature = "std"))]
        let start = std::time::Instant::now();
        #[cfg(any(not(test), not(feature = "std")))]
        let start = crate::task::timer::current_tick();

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

        // 計測値を更新
        #[cfg(all(test, feature = "std"))]
        let acquire_time = std::time::Instant::now().duration_since(start).as_micros() as u64;
        #[cfg(any(not(test), not(feature = "std")))]
        let acquire_time = crate::task::timer::current_tick().saturating_sub(start);

        LOCK_ACQUIRE_COUNT.fetch_add(1, Ordering::Relaxed);
        LOCK_TOTAL_ACQUIRE_TICKS.fetch_add(acquire_time, Ordering::Relaxed);
        if spin_count > 0 {
            LOCK_CONTENTION_EVENTS.fetch_add(1, Ordering::Relaxed);
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
        // try_lock は即時取得成功時のみ計測する
        #[cfg(all(test, feature = "std"))]
        let start = std::time::Instant::now();
        #[cfg(any(not(test), not(feature = "std")))]
        let start = crate::task::timer::current_tick();

        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            #[cfg(all(test, feature = "std"))]
            let acquire_time = std::time::Instant::now().duration_since(start).as_micros() as u64;
            #[cfg(any(not(test), not(feature = "std")))]
            let acquire_time = crate::task::timer::current_tick().saturating_sub(start);

            LOCK_ACQUIRE_COUNT.fetch_add(1, Ordering::Relaxed);
            LOCK_TOTAL_ACQUIRE_TICKS.fetch_add(acquire_time, Ordering::Relaxed);

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

    /// Lock used for initialization-time best-effort recovery.
    ///
    /// If the lock is poisoned, log a warning with the provided `context` and return the
    /// inner guard for best-effort recovery. This helper is intended for use during
    /// initialization or exceptional recovery paths only — prefer explicit error
    /// handling for runtime/hot-paths.
    pub fn lock_for_init(&self, context: &str) -> PoisonLockGuard<'_, T> {
        match self.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                log::warn!(
                    "[POISON] {} - lock poisoned during init; proceeding with best-effort",
                    context
                );
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
            // テスト環境ではシリアルへのI/Oは特権命令になり得るため、出力を抑止
            #[cfg(not(test))]
            {
                log::info!("[PoisonLock] Lock poisoned due to panic");

                // Debug: capture a lightweight backtrace at the point of panic to help
                // locate the originating code that caused the poisoning. This uses the
                // frame-pointer-based capture which does not perform heap allocations.
                #[cfg(debug_assertions)]
                {
                    crate::io::log::early_print("[PoisonLock] Capturing backtrace...\n");
                    let bt = crate::unwind::Backtrace::capture();
                    for entry in bt.iter() {
                        crate::io::log::early_print("[PoisonLock][BT] IP=");
                        crate::io::log::early_print_hex(entry.frame.instruction_pointer as u64);
                        crate::io::log::early_print("\n");
                    }
                }
            }
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

pub fn is_panicking_for_debug() -> bool {
    is_panicking()
}

// ============================================================================
// Lock acquisition metrics (軽量計測用)
// - acquire_count: ロック取得呼び出し回数
// - contention_events: スピンが発生した回数（コンテンション検知）
// - total_acquire_ticks: ロック取得に費やした合計ティック数
// ============================================================================
static LOCK_ACQUIRE_COUNT: AtomicU64 = AtomicU64::new(0);
static LOCK_CONTENTION_EVENTS: AtomicU64 = AtomicU64::new(0);
static LOCK_TOTAL_ACQUIRE_TICKS: AtomicU64 = AtomicU64::new(0);

/// ロック計測値を取得する構造体
pub struct LockMetrics {
    pub acquire_count: u64,
    pub contention_events: u64,
    pub total_acquire_ticks: u64,
    pub average_acquire_ticks: u64,
}

/// 計測値を返す
pub fn get_lock_metrics() -> LockMetrics {
    let acq = LOCK_ACQUIRE_COUNT.load(Ordering::Relaxed);
    let cont = LOCK_CONTENTION_EVENTS.load(Ordering::Relaxed);
    let total = LOCK_TOTAL_ACQUIRE_TICKS.load(Ordering::Relaxed);
    let avg = if acq > 0 { total / acq } else { 0 };
    LockMetrics {
        acquire_count: acq,
        contention_events: cont,
        total_acquire_ticks: total,
        average_acquire_ticks: avg,
    }
}

/// 計測値をリセット（テスト用）
pub fn reset_lock_metrics() {
    LOCK_ACQUIRE_COUNT.store(0, Ordering::Relaxed);
    LOCK_CONTENTION_EVENTS.store(0, Ordering::Relaxed);
    LOCK_TOTAL_ACQUIRE_TICKS.store(0, Ordering::Relaxed);
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

pub fn get_current_core_id_for_debug() -> u32 {
    get_current_core_id()
}

/// 現在のCPUコアIDを取得
#[inline]
fn get_current_core_id() -> u32 {
    // Tests should run deterministically on the host; use core 0 in test builds.
    if cfg!(test) {
        return 0;
    }

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
}

impl<T: ?Sized> IrqPoisonLock<T> {
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

    /// 初期化時用のロック（毒入れされていても無視して取得し、初期化後に毒をクリアする）
    pub fn lock_for_init(&self, context: &str) -> IrqPoisonLockGuard<'_, T> {
        if self.is_poisoned() {
            log::warn!(
                "[IrqPoisonLock] Recovering poisoned lock during init: {}",
                context
            );
            self.clear_poison();
        }
        match self.lock() {
            Ok(guard) => guard,
            Err(err) => {
                // 既にクリアしたはずだが、レースコンディション等で再度発生した場合は
                // into_inner() で強制的に取得
                err.into_inner()
            }
        }
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
            log::info!("[IrqPoisonLock] Lock poisoned due to panic");
        }

        // スピンロックを解放
        self.lock.locked.store(false, Ordering::Release);

        // 割り込み状態を復元
        super::irq_mutex::restore_interrupts(self.irq_was_enabled);
    }
}
impl<T: fmt::Debug + ?Sized> fmt::Debug for IrqPoisonLockGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl<T: fmt::Display + ?Sized> fmt::Display for IrqPoisonLockGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}
impl<T: fmt::Debug + ?Sized> fmt::Debug for IrqPoisonLock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("IrqPoisonLock");
        d.field("poisoned", &self.is_poisoned());
        // We use load to check if it's locked to avoid deadlocks in Debug
        if self.locked.load(Ordering::Relaxed) {
            d.field("data", &"<locked>");
        } else if let Ok(guard) = self.lock() {
            d.field("data", &&*guard);
        } else {
            d.field("data", &"<locked or poisoned>");
        }
        d.finish()
    }
}
