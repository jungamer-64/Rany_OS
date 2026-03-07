// ============================================================================
// kernel_api/src/time.rs - Time Service Interface for ExoRust OS
// ============================================================================
//!
//! # Time Service Interface
//!
//! Defines the `TimeService` trait representing the high-level time management
//! cell interface. The kernel framework provides low-level hardware primitives
//! (PIT, TSC, APIC timer), while the time management driver (Cell) implements
//! user-facing timer functionality through this trait.
//!
//! ## Framework vs Cell 分離
//!
//! - **Framework (kernel)**: PIT/TSC/APIC 制御、割り込みソース、Fuel
//! - **Cell (time_driver)**: スリープ管理、タイマー登録、CPU時間統計、NTP

extern crate alloc;

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

/// タイマーハンドル（登録されたタイマーを識別）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimerHandle(pub u64);

/// タイマーモード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerMode {
    /// ワンショット: 1回だけ発火
    OneShot,
    /// 周期的: 指定間隔で繰り返し発火
    Periodic,
}

/// CPU時間統計
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuTimeStats {
    /// タスクが実際にCPUを使用した時間 (ナノ秒)
    pub cpu_time_ns: u64,
    /// タスクが最後にスケジュールされた時刻 (ティック)
    pub last_scheduled_tick: u64,
    /// タスクがスケジュールされた回数
    pub schedule_count: u64,
}

/// タイマーサービス統計
#[derive(Debug, Clone, Copy, Default)]
pub struct TimerServiceStats {
    /// 現在登録されているタイマー数
    pub active_timers: usize,
    /// 処理済みタイマー発火回数
    pub total_fired: u64,
    /// Wakerキューのエンキュー成功回数
    pub waker_enqueued: usize,
    /// Wakerキューのドロップ回数（キュー満杯）
    pub waker_dropped: usize,
    /// 現在のペンディングWaker数
    pub pending_wakers: usize,
}

/// 時間管理サービスのトレイト
///
/// time_driver (Cell) がこのトレイトを実装し、KernelServices経由で提供する。
/// ISRから呼ばれるメソッド (`on_timer_interrupt`, `process_pending_wakers`)
/// はロックフリーまたはtry_lockで安全に動作する。
pub trait TimeService: Send + Sync {
    // ========================================================================
    // Sleep / Timer
    // ========================================================================

    /// 指定ミリ秒のスリープティックを返す (現在ティック + duration_ms)
    ///
    /// 返された wake_tick は SleepFuture の登録に使用する。
    fn compute_wake_tick(&self, duration_ms: u64) -> u64;

    /// タイマーを登録（ワンショットまたは周期）
    ///
    /// `interval_ms` 後に `waker` を起床させる。
    /// 返された `TimerHandle` でキャンセル可能。
    fn register_timer(
        &self,
        interval_ms: u64,
        mode: TimerMode,
        waker: core::task::Waker,
    ) -> TimerHandle;

    /// 登録されたタイマーをキャンセル
    fn cancel_timer(&self, handle: TimerHandle) -> bool;

    // ========================================================================
    // Time Queries
    // ========================================================================

    /// 現在のティック数（ミリ秒単位、起動からの経過）
    fn current_tick_ms(&self) -> u64;

    /// 起動からの経過時間（ナノ秒）
    fn uptime_ns(&self) -> u64;

    /// Unix タイムスタンプ (秒)
    fn unix_timestamp(&self) -> u64;

    /// Unix タイムスタンプ (ミリ秒)
    fn unix_timestamp_ms(&self) -> u64;

    // ========================================================================
    // Statistics
    // ========================================================================

    /// タイマーサービス統計を取得
    fn stats(&self) -> TimerServiceStats;

    /// タスクのCPU時間統計を取得
    fn task_cpu_stats(&self, task_id: u64) -> Option<CpuTimeStats>;

    /// タスクのCPU実行開始を記録
    fn record_task_start(&self, task_id: u64);

    /// タスクのCPU実行終了を記録
    fn record_task_stop(&self, task_id: u64);

    // ========================================================================
    // ISR Bridge (2段階Wake方式)
    // ========================================================================

    /// タイマー割り込みハンドラから呼ばれる
    ///
    /// 【設計書 4.2】ISRコンテキスト: ティックをインクリメントし、
    /// 期限切れWakerをロックフリーキューにエンキューする。
    /// 直接 wake() は呼ばない。
    fn on_timer_interrupt(&self);

    /// 保留中のWakerを処理（Executorから呼び出し）
    ///
    /// 【設計書 4.2】非ISRコンテキスト: キューからWakerをドレインし、
    /// 安全にwake()を呼び出す。
    fn process_pending_wakers(&self);

    // ========================================================================
    // Wall Clock Adjustment
    // ========================================================================

    /// ウォールクロックの調整（NTP等からの補正用）
    fn adjust_wall_clock(&self, delta_ns: i64);

    // ========================================================================
    // Sleep Registry (SleepFuture support)
    // ========================================================================

    /// スリープレジストリにWakerを登録
    fn register_sleep(&self, wake_tick: u64, waker: core::task::Waker);

    /// スリープレジストリからWakerを削除
    fn unregister_sleep(&self, wake_tick: u64);
}

/// Access the registered time service if the kernel installed one.
#[inline]
pub fn try_instance() -> Option<&'static dyn TimeService> {
    if !crate::service::kernel::is_installed() {
        return None;
    }

    crate::service::kernel::instance().time_service()
}

/// Access the registered time service.
///
/// # Panics
/// Panics when the kernel runtime has not installed a time service yet.
#[inline]
pub fn instance() -> &'static dyn TimeService {
    try_instance().expect("TimeService not installed")
}

/// Generic sleep future backed by the installed [`TimeService`].
pub struct SleepFuture {
    wake_tick: u64,
    registered: bool,
}

impl SleepFuture {
    pub fn new(duration_ms: u64) -> Self {
        Self {
            wake_tick: instance().compute_wake_tick(duration_ms),
            registered: false,
        }
    }
}

impl Future for SleepFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let service = instance();

        if service.current_tick_ms() >= self.wake_tick {
            return Poll::Ready(());
        }

        if !self.registered {
            service.register_sleep(self.wake_tick, cx.waker().clone());
            self.registered = true;
        }

        Poll::Pending
    }
}

impl Drop for SleepFuture {
    fn drop(&mut self) {
        if self.registered {
            instance().unregister_sleep(self.wake_tick);
        }
    }
}

#[inline]
pub fn sleep_ms(duration_ms: u64) -> SleepFuture {
    SleepFuture::new(duration_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_instance_is_none_before_kernel_install() {
        assert!(try_instance().is_none());
    }
}
