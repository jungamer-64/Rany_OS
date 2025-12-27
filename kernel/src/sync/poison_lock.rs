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
        #[cfg(test)]
        let start = std::time::Instant::now();
        #[cfg(not(test))]
        let start = crate::task::current_tick();

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
        #[cfg(test)]
        let acquire_time = std::time::Instant::now().duration_since(start).as_micros() as u64;
        #[cfg(not(test))]
        let acquire_time = crate::task::current_tick().saturating_sub(start);

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
        #[cfg(test)]
        let start = std::time::Instant::now();
        #[cfg(not(test))]
        let start = crate::task::current_tick();

        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            #[cfg(test)]
            let acquire_time = std::time::Instant::now().duration_since(start).as_micros() as u64;
            #[cfg(not(test))]
            let acquire_time = crate::task::current_tick().saturating_sub(start);

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
            log::info!("[IrqPoisonLock] Lock poisoned due to panic");
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

    #[test]
    fn test_lock_for_init_recovers_on_poison() {
        use crate::sync::set_panicking;

        let lock = PoisonLock::new(0usize);

        // Poison the lock by simulating a panic while holding the guard
        set_panicking(true);
        {
            let _guard = lock.lock().unwrap();
            // dropping _guard while panicking will mark the lock as poisoned
        }
        set_panicking(false);

        // Recover via lock_for_init and mutate value
        {
            let mut g = lock.lock_for_init("test_lock_for_init");
            *g = 123usize;
        }

        // Subsequent lock should reflect the updated value, either via Ok or Err with inner reference
        match lock.lock() {
            Ok(g) => assert_eq!(*g, 123usize),
            Err(poisoned) => {
                let guard = poisoned.into_inner();
                assert_eq!(*guard, 123usize);
            }
        }
    }

    #[test]
    fn test_lock_contention_metrics() {
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        reset_lock_metrics();

        let lock = Arc::new(PoisonLock::new(0usize));
        let l2 = Arc::clone(&lock);

        // Hold the lock in a background thread to force contention
        let th = thread::spawn(move || {
            let _g = l2.lock().unwrap();
            thread::sleep(Duration::from_millis(100));
        });

        // Give the other thread a moment to acquire the lock
        thread::sleep(Duration::from_millis(10));

        // This acquisition should experience contention
        let _guard = lock.lock().unwrap();

        th.join().unwrap();

        let m = get_lock_metrics();
        assert!(
            m.acquire_count >= 1,
            "expected at least one lock acquisition"
        );
        assert!(
            m.contention_events >= 1,
            "expected at least one contention event"
        );
    }

    /// Sharded-style stress test that simulates a sharded registry by creating
    /// multiple `PoisonLock` instances and having many threads randomly lock
    /// them repeatedly. This approximates contention patterns seen in
    /// sharded registries without depending on the full `sas` module.
    #[test]
    fn test_sharded_poisonlock_stress() {
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        reset_lock_metrics();

        let shard_count = 32usize;
        let mut vec = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            vec.push(Arc::new(PoisonLock::new(0usize)));
        }
        let shards = Arc::new(vec);

        let num_threads = 16usize;
        let ops = 300usize;
        let mut handles = Vec::new();

        for t in 0..num_threads {
            let shards = Arc::clone(&shards);
            let handle = thread::spawn(move || {
                for i in 0..ops {
                    let idx = (i + t) % shard_count;
                    let _g = shards[idx].lock().unwrap();
                    // occasional short hold to increase contention likelihood
                    if i % 2 == 0 {
                        thread::sleep(Duration::from_micros(50));
                    }
                }
            });
            handles.push(handle);
        }

        for h in handles {
            h.join().unwrap();
        }

        let m = get_lock_metrics();
        assert!(m.acquire_count > 0, "expected some lock acquisitions");
        assert!(m.contention_events > 0, "expected some contention events");
    }

    /// Higher contention scenario: fewer shards, more threads and longer holds.
    #[test]
    fn test_sharded_poisonlock_high_contention() {
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        reset_lock_metrics();

        let shard_count = 4usize;
        let mut vec = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            vec.push(Arc::new(PoisonLock::new(0usize)));
        }
        let shards = Arc::new(vec);

        let num_threads = 32usize;
        let ops = 200usize;
        let mut handles = Vec::new();

        for t in 0..num_threads {
            let shards = Arc::clone(&shards);
            let handle = thread::spawn(move || {
                for i in 0..ops {
                    let idx = (i + t) % shard_count;
                    let _g = shards[idx].lock().unwrap();
                    // hold slightly longer to force spins on other threads
                    thread::sleep(Duration::from_micros(200));
                }
            });
            handles.push(handle);
        }

        for h in handles {
            h.join().unwrap();
        }

        let m = get_lock_metrics();
        assert!(m.acquire_count > 0, "expected some lock acquisitions");
        assert!(m.contention_events > 0, "expected some contention events");
    }

    /// Measurement helper: sweep a few shard/thread configurations and print
    /// CSV-style measurements so we can pick shard counts and judge contention.
    /// This test is intended to run on the host (cfg(test)) only and prints
    /// results to stdout for quick inspection.
    #[test]
    fn test_lock_metrics_sweep() {
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let configs = [
            (32usize, 8usize, 200usize, 50u64),
            (16usize, 16usize, 300usize, 100u64),
            (8usize, 32usize, 300usize, 200u64),
            (4usize, 64usize, 150usize, 500u64),
        ];

        println!("shards,threads,ops,hold_us,acq_count,contention,avg_acq_ticks");

        for (shard_count, num_threads, ops, hold_us) in configs.iter().cloned() {
            reset_lock_metrics();

            let mut vec = Vec::with_capacity(shard_count);
            for _ in 0..shard_count {
                vec.push(Arc::new(PoisonLock::new(0usize)));
            }
            let shards = Arc::new(vec);

            let mut handles = Vec::new();
            for t in 0..num_threads {
                let shards = Arc::clone(&shards);
                let handle = thread::spawn(move || {
                    for i in 0..ops {
                        let idx = (i + t) % shard_count;
                        let _g = shards[idx].lock().unwrap();
                        if hold_us > 0 {
                            thread::sleep(Duration::from_micros(hold_us));
                        }
                    }
                });
                handles.push(handle);
            }

            for h in handles {
                h.join().unwrap();
            }

            let m = get_lock_metrics();
            println!(
                "{},{},{},{},{},{},{}",
                shard_count,
                num_threads,
                ops,
                hold_us,
                m.acquire_count,
                m.contention_events,
                m.average_acquire_ticks
            );
        }
    }
}
