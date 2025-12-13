// ============================================================================
// kernel/src/task/fuel.rs - Fuel-Based Execution for Starvation Prevention
// ============================================================================
//!
//! # Fuel-Based Execution (燃料ベース実行)
//!
//! 設計書 Section 4.4.1 に基づく実装
//!
//! 協調的マルチタスクにおけるスターベーション対策として、
//! 各タスクに「燃料」を割り当て、計算量に応じて消費させます。
//! 燃料が切れたタスクは強制的にyieldされます。
//!
//! ## 燃料消費ポイント
//!
//! - ループのバックエッジ（各反復で消費）
//! - 関数呼び出し（呼び出し深度に応じて消費）
//! - 長時間計算が予想される操作
//!
//! ## 燃料クォータ設定
//!
//! | タスクタイプ | 燃料クォータ |
//! |-------------|-------------|
//! | デフォルト | 10,000 単位 |
//! | リアルタイム | 無制限 |
//! | 低優先度 | 1,000 単位 |
//!
//! ## 使用例
//!
//! ```rust
//! let mut fuel = FuelCounter::default();
//!
//! // 計算ループ内で燃料を消費
//! for item in items {
//!     if fuel.consume(1).should_yield() {
//!         // 燃料切れ - タスクをyield
//!         yield_now().await;
//!         fuel.refill();
//!     }
//!     process(item);
//! }
//! ```

use core::sync::atomic::{AtomicU64, Ordering};

/// デフォルトの燃料クォータ
pub const DEFAULT_FUEL_QUOTA: u64 = 10_000;

/// リアルタイムタスク用の無制限燃料
pub const REALTIME_FUEL_QUOTA: u64 = u64::MAX;

/// 低優先度タスク用の燃料クォータ
pub const LOW_PRIORITY_FUEL_QUOTA: u64 = 1_000;

/// 燃料消費結果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuelResult {
    /// まだ燃料が残っている
    Continue,
    /// 燃料切れ - yieldすべき
    ShouldYield,
}

impl FuelResult {
    /// yieldすべきかどうか
    #[inline]
    pub fn should_yield(self) -> bool {
        matches!(self, FuelResult::ShouldYield)
    }

    /// 継続可能かどうか
    #[inline]
    pub fn can_continue(self) -> bool {
        matches!(self, FuelResult::Continue)
    }
}

/// 燃料カウンター
///
/// タスクごとに割り当てられ、計算量を追跡する
#[derive(Debug)]
pub struct FuelCounter {
    /// 現在の燃料残量
    remaining: u64,
    /// 最大燃料クォータ（refill時に復元される値）
    quota: u64,
    /// 累計消費量（統計用）
    total_consumed: u64,
}

impl Default for FuelCounter {
    fn default() -> Self {
        Self::with_quota(DEFAULT_FUEL_QUOTA)
    }
}

impl FuelCounter {
    /// 指定したクォータで燃料カウンターを作成
    pub const fn with_quota(quota: u64) -> Self {
        Self {
            remaining: quota,
            quota,
            total_consumed: 0,
        }
    }

    /// リアルタイムタスク用（無制限燃料）
    pub const fn realtime() -> Self {
        Self::with_quota(REALTIME_FUEL_QUOTA)
    }

    /// 低優先度タスク用
    pub const fn low_priority() -> Self {
        Self::with_quota(LOW_PRIORITY_FUEL_QUOTA)
    }

    /// 燃料を消費
    ///
    /// # Arguments
    /// * `amount` - 消費する燃料量
    ///
    /// # Returns
    /// * `FuelResult::Continue` - まだ燃料が残っている
    /// * `FuelResult::ShouldYield` - 燃料切れ
    #[inline]
    pub fn consume(&mut self, amount: u64) -> FuelResult {
        // 無制限燃料の場合は常に継続
        if self.quota == REALTIME_FUEL_QUOTA {
            return FuelResult::Continue;
        }

        self.total_consumed = self.total_consumed.saturating_add(amount);

        if self.remaining >= amount {
            self.remaining -= amount;
            FuelResult::Continue
        } else {
            self.remaining = 0;
            FuelResult::ShouldYield
        }
    }

    /// ループ反復での燃料消費（1単位）
    #[inline]
    pub fn consume_loop_iteration(&mut self) -> FuelResult {
        self.consume(1)
    }

    /// 関数呼び出しでの燃料消費
    #[inline]
    pub fn consume_function_call(&mut self) -> FuelResult {
        self.consume(5) // 関数呼び出しは5単位
    }

    /// 重い操作での燃料消費
    #[inline]
    pub fn consume_heavy_operation(&mut self) -> FuelResult {
        self.consume(100) // 重い操作は100単位
    }

    /// 燃料を補充（スケジュール時に呼び出される）
    pub fn refill(&mut self) {
        self.remaining = self.quota;
    }

    /// 現在の燃料残量を取得
    pub fn remaining(&self) -> u64 {
        self.remaining
    }

    /// クォータを取得
    pub fn quota(&self) -> u64 {
        self.quota
    }

    /// 累計消費量を取得（統計用）
    pub fn total_consumed(&self) -> u64 {
        self.total_consumed
    }

    /// 燃料が残っているかどうか
    pub fn has_fuel(&self) -> bool {
        self.remaining > 0 || self.quota == REALTIME_FUEL_QUOTA
    }

    /// 燃料が空かどうか
    pub fn is_empty(&self) -> bool {
        self.remaining == 0 && self.quota != REALTIME_FUEL_QUOTA
    }

    /// クォータを変更
    pub fn set_quota(&mut self, new_quota: u64) {
        self.quota = new_quota;
        // 現在の残量が新しいクォータを超えている場合は調整
        if self.remaining > new_quota {
            self.remaining = new_quota;
        }
    }
}

/// グローバル燃料統計
pub struct FuelStats {
    /// 総燃料消費量
    total_consumed: AtomicU64,
    /// yield回数
    yield_count: AtomicU64,
}

/// グローバル燃料統計インスタンス
static FUEL_STATS: FuelStats = FuelStats {
    total_consumed: AtomicU64::new(0),
    yield_count: AtomicU64::new(0),
};

impl FuelStats {
    /// 燃料消費を記録
    pub fn record_consumption(amount: u64) {
        FUEL_STATS.total_consumed.fetch_add(amount, Ordering::Relaxed);
    }

    /// yieldを記録
    pub fn record_yield() {
        FUEL_STATS.yield_count.fetch_add(1, Ordering::Relaxed);
    }

    /// 総消費量を取得
    pub fn total_consumed() -> u64 {
        FUEL_STATS.total_consumed.load(Ordering::Relaxed)
    }

    /// yield回数を取得
    pub fn yield_count() -> u64 {
        FUEL_STATS.yield_count.load(Ordering::Relaxed)
    }
}

/// 燃料チェックマクロ
///
/// ループ内で簡単に燃料チェックを行うためのヘルパーマクロ
#[macro_export]
macro_rules! check_fuel {
    ($fuel:expr) => {
        if $fuel.consume_loop_iteration().should_yield() {
            $crate::task::yield_now().await;
            $fuel.refill();
            $crate::task::fuel::FuelStats::record_yield();
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_quota() {
        let fuel = FuelCounter::default();
        assert_eq!(fuel.quota(), DEFAULT_FUEL_QUOTA);
        assert_eq!(fuel.remaining(), DEFAULT_FUEL_QUOTA);
    }

    #[test]
    fn test_consume() {
        let mut fuel = FuelCounter::with_quota(100);

        assert_eq!(fuel.consume(50), FuelResult::Continue);
        assert_eq!(fuel.remaining(), 50);

        assert_eq!(fuel.consume(50), FuelResult::Continue);
        assert_eq!(fuel.remaining(), 0);

        assert_eq!(fuel.consume(1), FuelResult::ShouldYield);
        assert_eq!(fuel.remaining(), 0);
    }

    #[test]
    fn test_refill() {
        let mut fuel = FuelCounter::with_quota(100);
        fuel.consume(100);
        assert!(fuel.is_empty());

        fuel.refill();
        assert_eq!(fuel.remaining(), 100);
        assert!(fuel.has_fuel());
    }

    #[test]
    fn test_realtime_unlimited() {
        let mut fuel = FuelCounter::realtime();

        // リアルタイムタスクは常に継続
        for _ in 0..1000 {
            assert_eq!(fuel.consume(1000), FuelResult::Continue);
        }
        assert!(fuel.has_fuel());
    }

    #[test]
    fn test_total_consumed() {
        let mut fuel = FuelCounter::with_quota(1000);

        fuel.consume(100);
        fuel.consume(200);
        fuel.consume(300);

        assert_eq!(fuel.total_consumed(), 600);
    }
}
