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

use crate::fw;
use crate::regs::init_seg;
use crate::structs::health::HealthLayout;

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
            max_recoveries: 5,
            last_health_counter: 0,
            counter_stuck_count: 0,
        }
    }

    /// FW 健全性を詳細にチェック
    pub unsafe fn check(&mut self, bar0_base: u64) -> HealthStatus {
        self.total_checks += 1;
        self.checks_since_recovery += 1;

        // 1. 健全性カウンタのチェック
        let health_counter = crate::mmio_read_be32(bar0_base as usize + init_seg::HEALTH_COUNTER);
        if health_counter == self.last_health_counter && health_counter != 0 {
            self.counter_stuck_count += 1;
        } else {
            self.counter_stuck_count = 0;
            self.last_health_counter = health_counter;
        }

        // 2. 致命的エラー状態のチェック
        let healthy = fw::check_health(bar0_base);
        let stuck = self.counter_stuck_count >= 10; // 10回連続でカウンタ停止ならハングとみなす

        if healthy && !stuck {
            self.consecutive_errors = 0;
            HealthStatus::Healthy
        } else {
            self.consecutive_errors += 1;
            self.total_errors += 1;

            let h_buf = self.read_health_buffer(bar0_base);
            let layout = HealthLayout::new(&h_buf);

            log::warn!(
                target: "mlx5::health",
                "FW health error: syndrome={:#x}, ext_syndrome={:#x}, full_reset={}, stuck={}",
                layout.syndrome(),
                layout.ext_syndrome(),
                layout.full_reset_required(),
                stuck
            );

            if self.consecutive_errors >= self.error_threshold
                || layout.full_reset_required()
                || stuck
            {
                HealthStatus::Critical
            } else {
                HealthStatus::Degraded
            }
        }
    }

    unsafe fn read_health_buffer(&self, bar0_base: u64) -> [u8; 64] {
        let mut buf = [0u8; 64];
        let base = bar0_base as usize + init_seg::HEALTH_BUFFER;
        for i in 0..16 {
            let val = crate::mmio_read_be32(base + i * 4);
            buf[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
        }
        buf
    }

    pub fn record_recovery(&mut self) {
        self.recovery_count += 1;
        self.consecutive_errors = 0;
        self.checks_since_recovery = 0;
        self.counter_stuck_count = 0;
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
