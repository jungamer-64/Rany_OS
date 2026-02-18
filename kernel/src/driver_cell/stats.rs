// ============================================================================
// kernel/src/driver_cell/stats.rs - DriverCell 統計情報
// ============================================================================
//! # ドライバセル統計トラッキング
//!
//! DriverCellのパフォーマンスとヘルス状態を追跡する統計情報。
//! 構造化ログと組み合わせて、システム可観測性を向上させる。
//!
//! 設計書 9: デバッグとトレーシング - 構造化ログ

#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// Statistics
// ============================================================================

/// DriverCellの統計情報
#[derive(Debug, Clone)]
pub struct DriverCellStats {
    /// ロードにかかった時間（TSCティック）
    pub load_duration_ticks: u64,
    /// ロード時刻（TSCティック）
    pub load_timestamp: u64,
    /// 最後のstart時刻
    pub last_start_timestamp: u64,
    /// 最後のstop時刻
    pub last_stop_timestamp: u64,
    /// 累計起動回数
    pub start_count: u64,
    /// 累計停止回数
    pub stop_count: u64,
    /// 累計障害回数
    pub fault_count: u64,
    /// 累計再起動回数
    pub restart_count: u64,
    /// 累計ホットスワップ回数
    pub hot_swap_count: u64,
    /// 累計稼働時間（TSCティック）
    pub total_uptime_ticks: u64,
    /// 最長連続稼働時間（TSCティック）
    pub max_uptime_ticks: u64,
    /// 現在の連続稼働開始時刻（0=停止中）
    current_uptime_start: u64,
}

impl DriverCellStats {
    /// 新しい統計情報を作成
    pub fn new() -> Self {
        Self {
            load_duration_ticks: 0,
            load_timestamp: 0,
            last_start_timestamp: 0,
            last_stop_timestamp: 0,
            start_count: 0,
            stop_count: 0,
            fault_count: 0,
            restart_count: 0,
            hot_swap_count: 0,
            total_uptime_ticks: 0,
            max_uptime_ticks: 0,
            current_uptime_start: 0,
        }
    }

    /// ロード完了を記録
    pub fn record_load(&mut self) {
        let now = crate::task::timer::current_tick();
        self.load_timestamp = now;
    }

    /// ロード時間を記録
    pub fn record_load_duration(&mut self, start_tick: u64) {
        let now = crate::task::timer::current_tick();
        self.load_duration_ticks = now.saturating_sub(start_tick);
    }

    /// 開始を記録
    pub fn record_start(&mut self) {
        let now = crate::task::timer::current_tick();
        self.last_start_timestamp = now;
        self.current_uptime_start = now;
        self.start_count += 1;
    }

    /// 停止を記録
    pub fn record_stop(&mut self) {
        let now = crate::task::timer::current_tick();
        self.last_stop_timestamp = now;
        self.stop_count += 1;

        // 稼働時間を計算
        if self.current_uptime_start > 0 {
            let uptime = now.saturating_sub(self.current_uptime_start);
            self.total_uptime_ticks += uptime;
            if uptime > self.max_uptime_ticks {
                self.max_uptime_ticks = uptime;
            }
            self.current_uptime_start = 0;
        }
    }

    /// 障害を記録
    pub fn record_fault(&mut self) {
        self.fault_count += 1;

        // 稼働時間を更新
        let now = crate::task::timer::current_tick();
        if self.current_uptime_start > 0 {
            let uptime = now.saturating_sub(self.current_uptime_start);
            self.total_uptime_ticks += uptime;
            if uptime > self.max_uptime_ticks {
                self.max_uptime_ticks = uptime;
            }
            self.current_uptime_start = 0;
        }
    }

    /// 再起動を記録
    pub fn record_restart(&mut self) {
        self.restart_count += 1;
        let now = crate::task::timer::current_tick();
        self.current_uptime_start = now;
        self.last_start_timestamp = now;
    }

    /// ホットスワップを記録
    pub fn record_hot_swap(&mut self) {
        self.hot_swap_count += 1;
    }

    /// 現在の稼働時間を取得（TSCティック、0=停止中）
    pub fn current_uptime(&self) -> u64 {
        if self.current_uptime_start > 0 {
            crate::task::timer::current_tick().saturating_sub(self.current_uptime_start)
        } else {
            0
        }
    }

    /// 可用性（%）を計算
    ///
    /// 作成時刻からの経過時間に対する稼働時間の割合
    pub fn availability_percent(&self, created_at: u64) -> f64 {
        let now = crate::task::timer::current_tick();
        let total_time = now.saturating_sub(created_at);
        if total_time == 0 {
            return 100.0;
        }
        let uptime = self.total_uptime_ticks + self.current_uptime();
        (uptime as f64 / total_time as f64) * 100.0
    }

    /// MTBF（平均故障間隔）を取得（TSCティック）
    ///
    /// 障害回数が0の場合はNoneを返す
    pub fn mean_time_between_failures(&self) -> Option<u64> {
        if self.fault_count == 0 {
            return None;
        }
        let total_uptime = self.total_uptime_ticks + self.current_uptime();
        Some(total_uptime / self.fault_count)
    }

    /// MTTR（平均復旧時間）を推定
    ///
    /// ダウンタイム / 障害回数
    pub fn mean_time_to_repair(&self, created_at: u64) -> Option<u64> {
        if self.fault_count == 0 {
            return None;
        }
        let now = crate::task::timer::current_tick();
        let total_time = now.saturating_sub(created_at);
        let uptime = self.total_uptime_ticks + self.current_uptime();
        let downtime = total_time.saturating_sub(uptime);
        Some(downtime / self.fault_count)
    }
}

impl Default for DriverCellStats {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global Statistics
// ============================================================================

/// グローバルDriverCell統計（アトミック）
pub struct GlobalDriverCellStats {
    /// 累計作成数
    pub total_created: AtomicU64,
    /// 累計アンロード数
    pub total_unloaded: AtomicU64,
    /// 累計障害数
    pub total_faults: AtomicU64,
    /// 累計ホットスワップ数
    pub total_hot_swaps: AtomicU64,
    /// 累計再起動成功数
    pub total_restarts_succeeded: AtomicU64,
    /// 累計再起動失敗数
    pub total_restarts_failed: AtomicU64,
}

impl GlobalDriverCellStats {
    /// 新しいグローバル統計を作成
    pub const fn new() -> Self {
        Self {
            total_created: AtomicU64::new(0),
            total_unloaded: AtomicU64::new(0),
            total_faults: AtomicU64::new(0),
            total_hot_swaps: AtomicU64::new(0),
            total_restarts_succeeded: AtomicU64::new(0),
            total_restarts_failed: AtomicU64::new(0),
        }
    }

    /// 作成を記録
    pub fn on_created(&self) {
        self.total_created.fetch_add(1, Ordering::Relaxed);
    }

    /// アンロードを記録
    pub fn on_unloaded(&self) {
        self.total_unloaded.fetch_add(1, Ordering::Relaxed);
    }

    /// 障害を記録
    pub fn on_fault(&self) {
        self.total_faults.fetch_add(1, Ordering::Relaxed);
    }

    /// ホットスワップを記録
    pub fn on_hot_swap(&self) {
        self.total_hot_swaps.fetch_add(1, Ordering::Relaxed);
    }

    /// 再起動成功を記録
    pub fn on_restart_succeeded(&self) {
        self.total_restarts_succeeded.fetch_add(1, Ordering::Relaxed);
    }

    /// 再起動失敗を記録
    pub fn on_restart_failed(&self) {
        self.total_restarts_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// サマリーを取得
    pub fn summary(&self) -> GlobalStatsSummary {
        GlobalStatsSummary {
            total_created: self.total_created.load(Ordering::Relaxed),
            total_unloaded: self.total_unloaded.load(Ordering::Relaxed),
            total_faults: self.total_faults.load(Ordering::Relaxed),
            total_hot_swaps: self.total_hot_swaps.load(Ordering::Relaxed),
            total_restarts_succeeded: self.total_restarts_succeeded.load(Ordering::Relaxed),
            total_restarts_failed: self.total_restarts_failed.load(Ordering::Relaxed),
        }
    }
}

/// グローバル統計のスナップショット
#[derive(Debug, Clone)]
pub struct GlobalStatsSummary {
    pub total_created: u64,
    pub total_unloaded: u64,
    pub total_faults: u64,
    pub total_hot_swaps: u64,
    pub total_restarts_succeeded: u64,
    pub total_restarts_failed: u64,
}

/// グローバル統計インスタンス
static GLOBAL_STATS: GlobalDriverCellStats = GlobalDriverCellStats::new();

/// グローバル統計にアクセス
pub fn global_stats() -> &'static GlobalDriverCellStats {
    &GLOBAL_STATS
}
