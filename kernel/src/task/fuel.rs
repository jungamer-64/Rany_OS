// ============================================================================
// kernel/src/task/fuel.rs - Fuel-Based Execution for Starvation Prevention
// ============================================================================
//!
//! # Fuel-Based Execution for Starvation Prevention
//!
//! This module implements a "fuel" mechanism to limit the execution time of
//! cooperative tasks (futures). This prevents a single task from monopolizing
//! the CPU by forcing it to yield after consuming its budget.
//!
//! ## Concept
//! - **Fuel**: A unit of execution budget (arbitrary scale, e.g., 1 fuel ~ 100-1000 cycles).
//! - **Injector**: The executor injects fuel into the task context before polling.
//! - **Consumption**: The task consumes fuel during loops or heavy operations.
//! - **Yielding**: When fuel is exhausted, the task yields (returns `Poll::Pending`).

use core::sync::atomic::{AtomicU64, Ordering};

/// Maximum number of CPUs supported
const MAX_CPUS: usize = 64;

/// Global fuel configuration
pub struct FuelConfig {
    /// Default fuel per task slice
    pub default_fuel: u64,
}

impl FuelConfig {
    pub const DEFAULT: Self = Self {
        default_fuel: 10_000,
    };
}

/// Per-CPU fuel storage
/// Uses atomic operations for safe access from any context.
/// Index by current CPU ID.
static CURRENT_FUEL: [AtomicU64; MAX_CPUS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_CPUS]
};

/// Get current CPU index safely (clamped to valid range)
#[inline]
fn cpu_index() -> usize {
    let cpu_id = crate::smp::current_cpu() as usize;
    if cpu_id < MAX_CPUS {
        cpu_id
    } else {
        0 // Fallback to CPU 0 if out of range
    }
}

/// Fuel manager
pub struct Fuel;

impl Fuel {
    /// Refill the current task's fuel
    #[inline]
    pub fn refill(amount: u64) {
        CURRENT_FUEL[cpu_index()].store(amount, Ordering::Relaxed);
    }

    /// Consume fuel. Returns false if exhausted (should yield).
    #[inline]
    pub fn consume(amount: u64) -> bool {
        let idx = cpu_index();
        let current = CURRENT_FUEL[idx].load(Ordering::Relaxed);
        if let Some(remaining) = current.checked_sub(amount) {
            CURRENT_FUEL[idx].store(remaining, Ordering::Relaxed);
            true
        } else {
            CURRENT_FUEL[idx].store(0, Ordering::Relaxed);
            false
        }
    }

    /// Check remaining fuel
    #[inline]
    pub fn remaining() -> u64 {
        CURRENT_FUEL[cpu_index()].load(Ordering::Relaxed)
    }

    /// Check if fuel management is active (fuel has been set)
    #[inline]
    pub fn is_active() -> bool {
        CURRENT_FUEL[cpu_index()].load(Ordering::Relaxed) > 0
    }

    /// Force exhaustion (e.g. on yield)
    #[inline]
    pub fn exhaust() {
        CURRENT_FUEL[cpu_index()].store(0, Ordering::Relaxed);
    }
}

/// Helper macro to check fuel in loops
#[macro_export]
macro_rules! check_fuel {
    ($cost:expr) => {
        if !$crate::task::fuel::Fuel::consume($cost) {
            $crate::task::yield_now().await;
        }
    };
}

// ============================================================================
// FFI Call Macro - 設計書 4.4.3: 外部クレート呼び出しの燃料チェック
// ============================================================================
//
// 外部クレート（gimli, hashbrown等）は燃料チェックを行わないため、
// 呼び出し前に燃料を消費し、必要に応じてyieldする。
//
// ## 使用例
// ```
// // 同期コンテキストでの使用
// let result = ffi_call_sync!(1000, gimli::parse_dwarf(&data));
//
// // 非同期コンテキストでの使用
// let result = ffi_call!(1000, expensive_external_call()).await;
// ```

/// 外部FFI呼び出し用の燃料コスト定数
pub mod ffi_cost {
    /// gimli DWARFパース（中程度の複雑さ）
    pub const GIMLI_PARSE: u64 = 2000;
    /// hashbrown HashMap操作
    pub const HASHBROWN_OP: u64 = 100;
    /// ed25519署名検証
    pub const ED25519_VERIFY: u64 = 5000;
    /// SHA256ハッシュ計算（1KB）
    pub const SHA256_1KB: u64 = 500;
    /// メモリ割り当て（一般）
    pub const ALLOC_GENERAL: u64 = 50;
    /// 複雑なイテレータ操作
    pub const COMPLEX_ITERATOR: u64 = 200;
    /// デフォルトFFIコスト
    pub const DEFAULT: u64 = 500;
}

/// FFI呼び出し用マクロ（非同期版）
/// 
/// 【設計書 4.4.3】外部クレートの呼び出しには必ずこのマクロを使用すること。
/// 
/// 外部クレート（gimli, hashbrown, ed25519-compact等）は内部で燃料チェックを
/// 行わないため、呼び出し前に燃料を消費する。燃料が不足している場合は
/// yieldしてから呼び出しを実行する。
/// 
/// # 引数
/// - `$cost`: この呼び出しで消費する燃料量（ffi_cost定数を推奨）
/// - `$call`: 実際のFFI呼び出し式
/// 
/// # 例
/// ```
/// // gimliでDWARFをパース
/// let eh_frame = ffi_call!(ffi_cost::GIMLI_PARSE, gimli::EhFrame::new(&data)).await;
/// 
/// // hashmapへの挿入
/// ffi_call!(ffi_cost::HASHBROWN_OP, map.insert(key, value)).await;
/// ```
#[macro_export]
macro_rules! ffi_call {
    ($cost:expr, $call:expr) => {{
        // 燃料が不足していれば先にyield
        if !$crate::task::fuel::Fuel::consume($cost) {
            $crate::task::yield_now().await;
            // yield後に燃料を再充填（executorがrefillを行う想定だが念のため）
        }
        // FFI呼び出しを実行
        $call
    }};
}

/// FFI呼び出し用マクロ（同期版）
/// 
/// 非同期コンテキスト外（割り込みハンドラ等）での使用向け。
/// 燃料が不足していても呼び出しは実行するが、燃料を消費して
/// 後続の処理でyieldが発生するようにする。
/// 
/// # 引数
/// - `$cost`: この呼び出しで消費する燃料量
/// - `$call`: 実際のFFI呼び出し式
#[macro_export]
macro_rules! ffi_call_sync {
    ($cost:expr, $call:expr) => {{
        // 燃料を消費（同期版なのでyieldはしない）
        let _ = $crate::task::fuel::Fuel::consume($cost);
        // FFI呼び出しを実行
        $call
    }};
}

/// FFI呼び出しをラップする関数（戻り値がResult型の場合）
/// 
/// エラー時にも燃料を消費したことを記録する。
#[inline]
pub fn ffi_call_result<T, E, F>(cost: u64, f: F) -> Result<T, E>
where
    F: FnOnce() -> Result<T, E>,
{
    Fuel::consume(cost);
    f()
}

/// 重い操作の前に燃料をチェックし、不足時はResult::Errを返す
/// 
/// yieldできない同期コンテキストでの使用向け。
/// 燃料不足時にはエラーを返し、呼び出し元でリトライを判断させる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuelExhausted;

impl core::fmt::Display for FuelExhausted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Fuel exhausted, operation deferred")
    }
}

/// 燃料が十分にあるかチェックし、不足時はエラーを返す
#[inline]
pub fn require_fuel(cost: u64) -> Result<(), FuelExhausted> {
    if Fuel::remaining() >= cost {
        Fuel::consume(cost);
        Ok(())
    } else {
        Err(FuelExhausted)
    }
}

/// 重いループ内での燃料チェック用ヘルパー
/// 
/// 指定回数ごとに燃料をチェックし、不足時はtrueを返す（yieldすべき）
#[inline]
pub fn should_yield_every(iteration: usize, check_interval: usize, cost_per_check: u64) -> bool {
    if iteration % check_interval == 0 {
        !Fuel::consume(cost_per_check)
    } else {
        false
    }
}
