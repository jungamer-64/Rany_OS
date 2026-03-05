// ============================================================================
// drivers/mlx5/src/health.rs - Health Monitoring & Error Recovery
// ============================================================================
//!
//! ConnectX-4 Lx FW 健全性モニタリングとエラーリカバリ。
//!
//! ## 機能
//!
//! - FW 健全性バッファの定期チェック
//! - 連続障害検出とリカバリ判定
//! - ティアダウン → 再初期化リカバリパイプライン
//!
//! ## ExoRust 設計原則
//!
//! - `Result::Err` でエラーを伝播（パニックではなくエラー型で障害通知）
//! - ウォッチドッグタイマーでハング検出

use crate::error::Mlx5Result;
use crate::fw;

/// 健全性チェックの結果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// デバイスは健全
    Healthy,
    /// 軽微な問題を検出（連続空ポーリング等）
    Degraded,
    /// FW エラー検出 — リカバリが必要
    Critical,
    /// デバイス未初期化
    Unknown,
}

/// 健全性モニタリング状態
pub struct HealthMonitor {
    /// 連続 FW エラー検出数
    consecutive_errors: u32,
    /// リカバリが必要と判定されるエラー閾値
    error_threshold: u32,
    /// 合計チェック回数
    total_checks: u64,
    /// 合計エラー検出数
    total_errors: u64,
    /// 最後のリカバリからのチェック数
    checks_since_recovery: u64,
    /// リカバリ実行回数
    recovery_count: u32,
    /// 最大リカバリ試行回数（上限超過時はデバイス無効化）
    max_recoveries: u32,
}

impl HealthMonitor {
    /// 新しい HealthMonitor を作成
    pub fn new() -> Self {
        Self {
            consecutive_errors: 0,
            error_threshold: 3,
            total_checks: 0,
            total_errors: 0,
            checks_since_recovery: 0,
            recovery_count: 0,
            max_recoveries: 5,
        }
    }

    /// カスタム閾値で作成
    pub fn with_threshold(error_threshold: u32, max_recoveries: u32) -> Self {
        Self {
            error_threshold,
            max_recoveries,
            ..Self::new()
        }
    }

    /// FW 健全性をチェック
    ///
    /// # Safety
    /// - `bar0_base` が有効な MMIO マッピングであること
    pub unsafe fn check(&mut self, bar0_base: u64) -> HealthStatus {
        self.total_checks += 1;
        self.checks_since_recovery += 1;

        let healthy = fw::check_health(bar0_base);

        if healthy {
            self.consecutive_errors = 0;
            HealthStatus::Healthy
        } else {
            self.consecutive_errors += 1;
            self.total_errors += 1;

            log::warn!(
                target: "mlx5::health",
                "FW health check failed ({}/{} consecutive, total={})",
                self.consecutive_errors,
                self.error_threshold,
                self.total_errors,
            );

            if self.consecutive_errors >= self.error_threshold {
                HealthStatus::Critical
            } else {
                HealthStatus::Degraded
            }
        }
    }

    /// リカバリが必要か判定
    pub fn needs_reset(&self) -> bool {
        self.consecutive_errors >= self.error_threshold
    }

    /// リカバリを試行可能か判定（上限チェック）
    pub fn can_recover(&self) -> bool {
        self.recovery_count < self.max_recoveries
    }

    /// リカバリ完了を通知
    pub fn record_recovery(&mut self) {
        self.recovery_count += 1;
        self.consecutive_errors = 0;
        self.checks_since_recovery = 0;

        log::info!(
            target: "mlx5::health",
            "Recovery #{} completed",
            self.recovery_count,
        );
    }

    /// 統計情報を取得
    pub fn stats(&self) -> HealthStats {
        HealthStats {
            total_checks: self.total_checks,
            total_errors: self.total_errors,
            consecutive_errors: self.consecutive_errors,
            recovery_count: self.recovery_count,
            checks_since_recovery: self.checks_since_recovery,
        }
    }
}

impl Default for HealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// 健全性統計
#[derive(Debug, Clone)]
pub struct HealthStats {
    /// 合計チェック回数
    pub total_checks: u64,
    /// 合計エラー検出数
    pub total_errors: u64,
    /// 連続エラー数
    pub consecutive_errors: u32,
    /// リカバリ実行回数
    pub recovery_count: u32,
    /// 最後のリカバリからのチェック数
    pub checks_since_recovery: u64,
}
