// ============================================================================
// drivers/time/src/lib.rs - Time Management Driver (Cell)
// ============================================================================
//!
//! # Time Management Driver
//!
//! ExoRust アーキテクチャにおける時間管理セル（ドライバ）。
//! 高レベルのタイマーサービスを提供する。

#![no_std]
#![allow(clippy::cast_possible_truncation)]

extern crate alloc;

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use core::task::Waker;
use exorust_sync::PoisonLock;
use kernel_api::service::time::{
    CpuTimeStats, TimeService, TimerHandle, TimerMode, TimerServiceStats,
};

// ============================================================================
// Constants
// ============================================================================

const NANOS_PER_MILLI: u64 = 1_000_000;
const NANOS_PER_SEC: u64 = 1_000_000_000;

// ============================================================================
// TimeManagement
// ============================================================================



pub struct TimeManagement {
    ticks: AtomicU64,
    wall_clock_offset_ns: AtomicI64,
    total_fired: AtomicU64,
    waker_dispatches: AtomicU64,
}

unsafe impl Send for TimeManagement {}
unsafe impl Sync for TimeManagement {}

impl TimeManagement {
    pub const fn new() -> Self {
        Self {
            ticks: AtomicU64::new(0),
            wall_clock_offset_ns: AtomicI64::new(0),
            total_fired: AtomicU64::new(0),
            waker_dispatches: AtomicU64::new(0),
        }
    }

    pub fn pending_waker_count(&self) -> usize {
        let current_tick = self.current_tick_ms();
        let pending_sleeps = self.sleep_registry.expired_len(current_tick);
        let pending_timers = self
            .timers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .expired_len(current_tick);
        pending_sleeps + pending_timers
    }

    pub fn pending_waker_stats(&self) -> (usize, usize) {
        (self.pending_waker_count(), 0)
    }

    fn uptime_ns_from_ticks(&self) -> u64 {
        self.current_tick_ms().saturating_mul(NANOS_PER_MILLI)
    }

    fn wall_clock_ns(&self) -> u64 {
        let uptime_ns = self.uptime_ns_from_ticks() as i128;
        let offset_ns = self.wall_clock_offset_ns.load(Ordering::Relaxed) as i128;
        clamp_i128_to_u64(uptime_ns + offset_ns)
    }






}

impl TimeService for TimeManagement {
    fn compute_wake_tick(&self, duration_ms: u64) -> u64 {
        self.ticks
            .load(Ordering::SeqCst)
            .saturating_add(duration_ms)
    }





    fn current_tick_ms(&self) -> u64 {
        self.ticks.load(Ordering::SeqCst)
    }

    fn uptime_ns(&self) -> u64 {
        self.uptime_ns_from_ticks()
    }

    fn unix_timestamp(&self) -> u64 {
        self.wall_clock_ns() / NANOS_PER_SEC
    }

    fn unix_timestamp_ms(&self) -> u64 {
        self.wall_clock_ns() / NANOS_PER_MILLI
    }

    fn stats(&self) -> TimerServiceStats {
        let active_timers = self
            .timers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .active_len();

        TimerServiceStats {
            active_timers,
            total_fired: self.total_fired.load(Ordering::Relaxed),
            waker_enqueued: self.waker_dispatches.load(Ordering::Relaxed) as usize,
            waker_dropped: 0,
            pending_wakers: self.pending_waker_count(),
        }
    }







    fn on_timer_interrupt(&self) {
        self.ticks.fetch_add(1, Ordering::SeqCst);
    }

    fn process_pending_wakers(&self) {
        let current_tick = self.ticks.load(Ordering::SeqCst);
        // LOOP_PROOF: mode=event; reason=Pending-waker drain loop exits once no expired wake source remains for the current tick.;
        loop {
            match self.next_expired_kind(current_tick) {
                Some(ExpiredKind::Sleep) => {
                    if !self.process_expired_sleep(current_tick) {
                        break;
                    }
                }
                Some(ExpiredKind::Timer) => {
                    if !self.process_expired_timer(current_tick) {
                        break;
                    }
                }
                None => break,
            }
        }
    }

    fn adjust_wall_clock(&self, delta_ns: i64) {
        let _ =
            self.wall_clock_offset_ns
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                    Some(current.saturating_add(delta_ns))
                });
    }




}

pub static TIME_MANAGER: TimeManagement = TimeManagement::new();

pub fn time_service() -> &'static dyn TimeService {
    &TIME_MANAGER
}

pub fn handle_timer_interrupt() {
    TIME_MANAGER.on_timer_interrupt();
}

pub fn process_pending_timer_wakers() {
    TIME_MANAGER.process_pending_wakers();
}

pub fn pending_timer_waker_count() -> usize {
    TIME_MANAGER.pending_waker_count()
}

pub fn pending_waker_stats() -> (usize, usize) {
    TIME_MANAGER.pending_waker_stats()
}

pub fn current_tick() -> u64 {
    TIME_MANAGER.current_tick_ms()
}

fn clamp_i128_to_u64(value: i128) -> u64 {
    if value <= 0 {
        0
    } else if value >= u64::MAX as i128 {
        u64::MAX
    } else {
        value as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use alloc::task::Wake;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use exorust_sync::Mutex;

    struct CountingWaker {
        count: AtomicUsize,
    }

    impl CountingWaker {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                count: AtomicUsize::new(0),
            })
        }

        fn observed(&self) -> usize {
            self.count.load(Ordering::SeqCst)
        }
    }

    impl Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct OrderedWaker {
        id: u64,
        order: Arc<Mutex<Vec<u64>>>,
    }

    impl OrderedWaker {
        fn new(id: u64, order: Arc<Mutex<Vec<u64>>>) -> Arc<Self> {
            Arc::new(Self { id, order })
        }
    }

    impl Wake for OrderedWaker {
        fn wake(self: Arc<Self>) {
            self.order.lock().push(self.id);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.order.lock().push(self.id);
        }
    }

    fn set_wall_clock_ms(tm: &TimeManagement, target_ms: u64) {
        let current_ms = tm.unix_timestamp_ms();
        let delta_ms = target_ms as i128 - current_ms as i128;
        let delta_ns = delta_ms.saturating_mul(NANOS_PER_MILLI as i128);
        tm.adjust_wall_clock(delta_ns.clamp(i64::MIN as i128, i64::MAX as i128) as i64);
    }

    impl TimeManagement {
        fn record_stop_for_test(&self, task_id: u64, current_tick: u64) {
            self.cpu_tracker.record_stop(task_id, current_tick);
        }
    }

    #[test]
    fn tick_increment_smoke() {
        let tm = TimeManagement::new();
        assert_eq!(tm.current_tick_ms(), 0);
        tm.on_timer_interrupt();
        assert_eq!(tm.current_tick_ms(), 1);
        tm.on_timer_interrupt();
        assert_eq!(tm.current_tick_ms(), 2);
    }

    #[test]
    fn wall_clock_seed_uses_single_offset_model() {
        let tm = TimeManagement::new();
        set_wall_clock_ms(&tm, 1_000_000);
        assert_eq!(tm.unix_timestamp_ms(), 1_000_000);
        tm.on_timer_interrupt();
        assert_eq!(tm.unix_timestamp_ms(), 1_000_001);
    }

    #[test]
    fn wall_clock_reset_recomputes_offset() {
        let tm = TimeManagement::new();
        set_wall_clock_ms(&tm, 10_000);
        tm.on_timer_interrupt();
        tm.on_timer_interrupt();
        tm.on_timer_interrupt();
        assert_eq!(tm.unix_timestamp_ms(), 10_003);

        set_wall_clock_ms(&tm, 42_000);
        assert_eq!(tm.unix_timestamp_ms(), 42_000);
    }

    #[test]
    fn timer_registration_smoke() {
        let tm = TimeManagement::new();
        let counter = CountingWaker::new();
        let handle = tm.register_timer(100, TimerMode::OneShot, counter.clone().into());
        assert!(tm.cancel_timer(handle));
        assert!(!tm.cancel_timer(handle));
        assert_eq!(counter.observed(), 0);
    }

    #[test]
    fn one_shot_timer_fires_when_pending_wakers_are_processed() {
        let tm = TimeManagement::new();
        let counter = CountingWaker::new();
        tm.register_timer(2, TimerMode::OneShot, counter.clone().into());

        tm.on_timer_interrupt();
        assert_eq!(counter.observed(), 0);
        tm.process_pending_wakers();
        assert_eq!(counter.observed(), 0);

        tm.on_timer_interrupt();
        assert_eq!(counter.observed(), 0);
        tm.process_pending_wakers();
        assert_eq!(counter.observed(), 1);
    }

    #[test]
    fn periodic_timer_reschedules_until_cancelled() {
        let tm = TimeManagement::new();
        let counter = CountingWaker::new();
        let handle = tm.register_timer(2, TimerMode::Periodic, counter.clone().into());

        tm.on_timer_interrupt();
        tm.on_timer_interrupt();
        tm.process_pending_wakers();
        assert_eq!(counter.observed(), 1);

        tm.on_timer_interrupt();
        tm.on_timer_interrupt();
        tm.process_pending_wakers();
        assert_eq!(counter.observed(), 2);

        assert!(tm.cancel_timer(handle));
        tm.on_timer_interrupt();
        tm.on_timer_interrupt();
        tm.process_pending_wakers();
        assert_eq!(counter.observed(), 2);
    }

    #[test]
    fn multiple_expired_entries_drain_in_deadline_order() {
        let tm = TimeManagement::new();
        let order = Arc::new(Mutex::new(Vec::new()));

        tm.register_sleep(2, OrderedWaker::new(20, order.clone()).into());
        tm.register_timer(
            3,
            TimerMode::OneShot,
            OrderedWaker::new(30, order.clone()).into(),
        );
        tm.register_timer(
            1,
            TimerMode::OneShot,
            OrderedWaker::new(10, order.clone()).into(),
        );

        tm.on_timer_interrupt();
        tm.on_timer_interrupt();
        tm.on_timer_interrupt();
        tm.process_pending_wakers();

        assert_eq!(*order.lock(), alloc::vec![10, 20, 30]);
    }

    #[test]
    fn cpu_tracker_smoke() {
        let tm = TimeManagement::new();
        tm.on_timer_interrupt(); // tick=1
        tm.record_task_start(42);
        tm.on_timer_interrupt(); // tick=2
        tm.on_timer_interrupt(); // tick=3
        tm.record_stop_for_test(42, 3);
        let stats = tm.task_cpu_stats(42).expect("task stats should exist");
        assert_eq!(stats.schedule_count, 1);
        assert!(stats.cpu_time_ns > 0);
    }

    #[test]
    fn uptime_ns_smoke() {
        let tm = TimeManagement::new();
        tm.on_timer_interrupt();
        assert_eq!(tm.uptime_ns(), NANOS_PER_MILLI);
    }
}
