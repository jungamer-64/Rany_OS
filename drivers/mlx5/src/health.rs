// ============================================================================
// drivers/mlx5/src/health.rs - Health Monitoring & Error Recovery
// ============================================================================
//!
//! ConnectX ファミリ FW 健全性モニタリングとエラーリカバリ。
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

#![forbid(unsafe_code)]

use crate::regs::fw_state;

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
    /// 前回の健全性カウンタ値
    last_health_counter: u32,
    /// カウンタが停止している連続回数
    counter_stuck_count: u32,
}

impl HealthMonitor {
    pub fn new() -> Self {
        Self {
            consecutive_errors: 0,
            error_threshold: 3,
            total_checks: 0,
            total_errors: 0,
            checks_since_recovery: 0,
            recovery_count: 0,
            last_health_counter: 0,
            counter_stuck_count: 0,
        }
    }

    pub fn record_recovery(&mut self) {
        self.recovery_count += 1;
        self.consecutive_errors = 0;
        self.checks_since_recovery = 0;
        self.counter_stuck_count = 0;
    }

    /// Observes one counter sample, avoiding inconsistent double reads of the
    /// hardware register. The result is advisory, never a DMA-revocation proof.
    pub(crate) fn observe(&mut self, counter: u32, full_reset_required: bool) -> HealthStatus {
        self.total_checks = self.total_checks.saturating_add(1);
        self.checks_since_recovery = self.checks_since_recovery.saturating_add(1);
        if counter != 0 && counter == self.last_health_counter {
            self.counter_stuck_count = self.counter_stuck_count.saturating_add(1);
        } else {
            self.counter_stuck_count = 0;
            self.last_health_counter = counter;
        }
        let stuck = self.counter_stuck_count >= 10;
        if counter != fw_state::HEALTH_FATAL && !stuck && !full_reset_required {
            self.consecutive_errors = 0;
            return HealthStatus::Healthy;
        }
        self.consecutive_errors = self.consecutive_errors.saturating_add(1);
        self.total_errors = self.total_errors.saturating_add(1);
        if self.consecutive_errors >= self.error_threshold || stuck || full_reset_required {
            HealthStatus::Critical
        } else {
            HealthStatus::Degraded
        }
    }

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

#[derive(Debug, Clone)]
pub struct HealthStats {
    pub total_checks: u64,
    pub total_errors: u64,
    pub consecutive_errors: u32,
    pub recovery_count: u32,
    pub checks_since_recovery: u64,
}

impl Default for HealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stuck_counter_requires_ten_repeated_nonzero_samples() {
        let mut monitor = HealthMonitor::new();
        for _ in 0..10 {
            assert_eq!(monitor.observe(7, false), HealthStatus::Healthy);
        }
        assert_eq!(monitor.observe(7, false), HealthStatus::Critical);
        assert_eq!(monitor.observe(8, false), HealthStatus::Healthy);
        for _ in 0..12 {
            assert_eq!(monitor.observe(0, false), HealthStatus::Healthy);
        }
    }

    #[test]
    fn fatal_errors_escalate_and_success_clears_consecutive_errors() {
        let mut monitor = HealthMonitor::new();
        assert_eq!(
            monitor.observe(fw_state::HEALTH_FATAL, false),
            HealthStatus::Degraded
        );
        assert_eq!(
            monitor.observe(fw_state::HEALTH_FATAL, false),
            HealthStatus::Degraded
        );
        assert_eq!(
            monitor.observe(fw_state::HEALTH_FATAL, false),
            HealthStatus::Critical
        );
        assert_eq!(monitor.observe(1, false), HealthStatus::Healthy);
        assert_eq!(monitor.stats().consecutive_errors, 0);
        assert_eq!(monitor.observe(2, true), HealthStatus::Critical);
    }
}
