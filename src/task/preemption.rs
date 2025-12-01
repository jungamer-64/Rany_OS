// ============================================================================
// src/task/preemption.rs - Cooperative + Preemptive Hybrid Scheduler
// 設計書 4.4: スターベーション対策
// ============================================================================
#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};

/// タスク実行時間の制限（ティック数）
/// 設計書: APICタイマー割り込みを利用し、一定時間以上Executorに制御が戻らない場合は
/// 強制的に現在のタスクを中断
const DEFAULT_TIME_SLICE: u64 = 10; // 10ms (1 tick = 1ms)

/// 最小タイムスライス
const MIN_TIME_SLICE: u64 = 1;

/// 最大タイムスライス
const MAX_TIME_SLICE: u64 = 100;

/// プリエンプションコントローラ
/// 協調的マルチタスクとプリエンプティブの「ハイブリッド」アプローチを実装
pub struct PreemptionController {
    /// 現在のタイムスライス設定
    time_slice: AtomicU64,
    /// 現在のタスクが開始したティック
    task_start_tick: AtomicU64,
    /// プリエンプションが必要かどうか
    preemption_pending: AtomicBool,
    /// プリエンプションが有効かどうか
    enabled: AtomicBool,
    /// 強制プリエンプション回数（統計用）
    forced_preemptions: AtomicU64,
    /// 自発的yield回数（統計用）
    voluntary_yields: AtomicU64,
}

impl PreemptionController {
    pub const fn new() -> Self {
        Self {
            time_slice: AtomicU64::new(DEFAULT_TIME_SLICE),
            task_start_tick: AtomicU64::new(0),
            preemption_pending: AtomicBool::new(false),
            enabled: AtomicBool::new(true),
            forced_preemptions: AtomicU64::new(0),
            voluntary_yields: AtomicU64::new(0),
        }
    }
    
    /// タイムスライスを設定
    pub fn set_time_slice(&self, ticks: u64) {
        let clamped = ticks.clamp(MIN_TIME_SLICE, MAX_TIME_SLICE);
        self.time_slice.store(clamped, Ordering::Relaxed);
    }
    
    /// プリエンプションを有効/無効化
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Release);
    }
    
    /// タスク実行開始を記録
    pub fn task_started(&self, current_tick: u64) {
        self.task_start_tick.store(current_tick, Ordering::Release);
        self.preemption_pending.store(false, Ordering::Release);
    }
    
    /// タイマー割り込みから呼ばれる
    /// タイムスライスを超過した場合はプリエンプションフラグを立てる
    pub fn check_time_slice(&self, current_tick: u64) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        
        let start = self.task_start_tick.load(Ordering::Acquire);
        let elapsed = current_tick.saturating_sub(start);
        let slice = self.time_slice.load(Ordering::Relaxed);
        
        if elapsed >= slice {
            self.preemption_pending.store(true, Ordering::Release);
            self.forced_preemptions.fetch_add(1, Ordering::Relaxed);
        }
    }
    
    /// プリエンプションが必要かチェック
    pub fn should_preempt(&self) -> bool {
        self.preemption_pending.load(Ordering::Acquire)
    }
    
    /// プリエンプションフラグをクリア
    pub fn clear_preemption(&self) {
        self.preemption_pending.store(false, Ordering::Release);
    }
    
    /// 自発的yieldを記録
    pub fn record_voluntary_yield(&self) {
        self.voluntary_yields.fetch_add(1, Ordering::Relaxed);
    }
    
    /// 統計を取得
    pub fn stats(&self) -> PreemptionStats {
        PreemptionStats {
            forced_preemptions: self.forced_preemptions.load(Ordering::Relaxed),
            voluntary_yields: self.voluntary_yields.load(Ordering::Relaxed),
            current_time_slice: self.time_slice.load(Ordering::Relaxed),
            enabled: self.enabled.load(Ordering::Relaxed),
        }
    }
}

/// プリエンプション統計
#[derive(Debug, Clone)]
pub struct PreemptionStats {
    /// 強制プリエンプション回数
    pub forced_preemptions: u64,
    /// 自発的yield回数
    pub voluntary_yields: u64,
    /// 現在のタイムスライス
    pub current_time_slice: u64,
    /// プリエンプションが有効かどうか
    pub enabled: bool,
}

/// グローバルプリエンプションコントローラ
static PREEMPTION_CONTROLLER: PreemptionController = PreemptionController::new();

/// プリエンプション要求フラグ（割り込みハンドラ外で処理するため）
static YIELD_REQUESTED: AtomicBool = AtomicBool::new(false);

/// プリエンプションコントローラを取得
pub fn preemption_controller() -> &'static PreemptionController {
    &PREEMPTION_CONTROLLER
}

/// タイマー割り込みハンドラから呼ばれる
/// タスクの時間スライスをチェックし、必要に応じてプリエンプションをスケジュール
pub fn handle_timer_tick(current_tick: u64) {
    PREEMPTION_CONTROLLER.check_time_slice(current_tick);
}

/// プリエンプションが必要かどうか（割り込みハンドラから呼ばれる）
pub fn should_preempt() -> bool {
    PREEMPTION_CONTROLLER.should_preempt()
}

/// Yield要求をセット（割り込みハンドラから呼ばれる）
/// 割り込みハンドラ内では実際のyieldを行わず、フラグを立てるだけ
pub fn request_yield() {
    YIELD_REQUESTED.store(true, Ordering::Release);
}

/// Yield要求をチェックしてクリア
/// ExecutorのメインループやYieldポイントで呼ばれる
pub fn check_and_clear_yield_request() -> bool {
    YIELD_REQUESTED.swap(false, Ordering::AcqRel)
}

/// タスク開始を通知（Executorから呼ばれる）
pub fn notify_task_started(current_tick: u64) {
    PREEMPTION_CONTROLLER.task_started(current_tick);
}

/// Yieldポイント
/// 設計書 4.4: ループのバックエッジや長い関数呼び出しの合間に自動的に挿入
#[inline]
pub fn yield_point() {
    if PREEMPTION_CONTROLLER.should_preempt() {
        PREEMPTION_CONTROLLER.clear_preemption();
        // Executorに制御を返す
        // 実際にはWakerを通じてスケジュールし直す
        core::hint::spin_loop();
    }
}

/// 自発的にyield
pub fn voluntary_yield() {
    PREEMPTION_CONTROLLER.record_voluntary_yield();
    // Poll::Pendingを返すことでExecutorに制御を返す
}

// ============================================================================
// Yield Future - 非同期コンテキストでのyield
// ============================================================================

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

/// Yieldを行うFuture
pub struct YieldNow {
    yielded: bool,
}

impl YieldNow {
    pub fn new() -> Self {
        Self { yielded: false }
    }
}

impl Default for YieldNow {
    fn default() -> Self {
        Self::new()
    }
}

impl Future for YieldNow {
    type Output = ();
    
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            PREEMPTION_CONTROLLER.record_voluntary_yield();
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// Executorに制御を返す（非同期版）
pub async fn yield_now() {
    YieldNow::new().await
}

// ============================================================================
// CPU時間追跡
// ============================================================================

/// タスクごとのCPU時間追跡
#[derive(Debug, Clone, Default)]
pub struct CpuTimeTracker {
    /// 累積実行時間（ティック）
    pub total_ticks: u64,
    /// 最後の実行開始ティック
    pub last_start: u64,
    /// 実行回数
    pub run_count: u64,
}

impl CpuTimeTracker {
    pub const fn new() -> Self {
        Self {
            total_ticks: 0,
            last_start: 0,
            run_count: 0,
        }
    }
    
    /// 実行開始を記録
    pub fn start(&mut self, current_tick: u64) {
        self.last_start = current_tick;
        self.run_count += 1;
    }
    
    /// 実行終了を記録
    pub fn stop(&mut self, current_tick: u64) {
        let elapsed = current_tick.saturating_sub(self.last_start);
        self.total_ticks += elapsed;
    }
    
    /// 平均実行時間を取得
    pub fn average_run_time(&self) -> u64 {
        if self.run_count > 0 {
            self.total_ticks / self.run_count
        } else {
            0
        }
    }
}

// ============================================================================
// 適応的タイムスライス
// ============================================================================

/// 適応的タイムスライスコントローラ
/// タスクの振る舞いに基づいてタイムスライスを動的に調整
pub struct AdaptiveTimeSlice {
    /// 基本タイムスライス
    base_slice: AtomicU64,
    /// 現在の調整係数（パーセント）
    adjustment: AtomicU64,
}

impl AdaptiveTimeSlice {
    pub const fn new() -> Self {
        Self {
            base_slice: AtomicU64::new(DEFAULT_TIME_SLICE),
            adjustment: AtomicU64::new(100), // 100% = 調整なし
        }
    }
    
    /// 実行時間に基づいてタイムスライスを調整
    /// 短いタスクには短いスライス、長いタスクには長いスライスを与える
    pub fn adjust(&self, average_run_time: u64) {
        let adjustment = if average_run_time < 1 {
            50  // 非常に短いタスク -> スライスを半分に
        } else if average_run_time < 5 {
            75  // 短いタスク -> スライスを75%に
        } else if average_run_time > 20 {
            150 // 長いタスク -> スライスを150%に
        } else {
            100 // 通常
        };
        
        self.adjustment.store(adjustment, Ordering::Relaxed);
    }
    
    /// 調整後のタイムスライスを取得
    pub fn get_time_slice(&self) -> u64 {
        let base = self.base_slice.load(Ordering::Relaxed);
        let adj = self.adjustment.load(Ordering::Relaxed);
        (base * adj / 100).clamp(MIN_TIME_SLICE, MAX_TIME_SLICE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_preemption_controller() {
        let controller = PreemptionController::new();
        
        // タスク開始
        controller.task_started(0);
        assert!(!controller.should_preempt());
        
        // タイムスライス内
        controller.check_time_slice(5);
        assert!(!controller.should_preempt());
        
        // タイムスライス超過
        controller.check_time_slice(DEFAULT_TIME_SLICE + 1);
        assert!(controller.should_preempt());
        
        // クリア
        controller.clear_preemption();
        assert!(!controller.should_preempt());
    }
    
    #[test]
    fn test_cpu_time_tracker() {
        let mut tracker = CpuTimeTracker::new();
        
        tracker.start(0);
        tracker.stop(10);
        assert_eq!(tracker.total_ticks, 10);
        
        tracker.start(10);
        tracker.stop(30);
        assert_eq!(tracker.total_ticks, 30);
        assert_eq!(tracker.average_run_time(), 15);
    }
}
