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
// Ordered Sleep Registry
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SleepKey {
    wake_tick: u64,
    registration_id: u64,
}

struct OrderedSleepRegistry {
    next_registration_id: AtomicU64,
    entries: PoisonLock<BTreeMap<SleepKey, Waker>>,
}

impl OrderedSleepRegistry {
    const fn new() -> Self {
        Self {
            next_registration_id: AtomicU64::new(1),
            entries: PoisonLock::new(BTreeMap::new()),
        }
    }

    fn insert(&self, wake_tick: u64, waker: Waker) {
        let registration_id = self.next_registration_id.fetch_add(1, Ordering::Relaxed);
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                SleepKey {
                    wake_tick,
                    registration_id,
                },
                waker,
            );
    }

    fn remove_one(&self, wake_tick: u64) -> bool {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let start = SleepKey {
            wake_tick,
            registration_id: 0,
        };
        let end = SleepKey {
            wake_tick,
            registration_id: u64::MAX,
        };
        let key = entries.range(start..=end).next().map(|(key, _)| *key);
        if let Some(key) = key {
            entries.remove(&key);
            true
        } else {
            false
        }
    }

    fn next_deadline(&self) -> Option<u64> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .first_key_value()
            .map(|(key, _)| key.wake_tick)
    }

    fn pop_expired(&self, current_tick: u64) -> Option<Waker> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let key = match entries.first_key_value() {
            Some((key, _)) if key.wake_tick <= current_tick => *key,
            _ => return None,
        };
        entries.remove(&key)
    }

    fn expired_len(&self, current_tick: u64) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .range(
                ..=SleepKey {
                    wake_tick: current_tick,
                    registration_id: u64::MAX,
                },
            )
            .count()
    }
}

// ============================================================================
// Timer Registry
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct TimerKey {
    fire_tick: u64,
    handle_id: u64,
}

struct TimerEntry {
    interval_ms: u64,
    mode: TimerMode,
    waker: Waker,
}

struct TimerRegistry {
    by_deadline: BTreeMap<TimerKey, TimerEntry>,
    by_id: BTreeMap<u64, u64>,
}

impl TimerRegistry {
    const fn new() -> Self {
        Self {
            by_deadline: BTreeMap::new(),
            by_id: BTreeMap::new(),
        }
    }

    fn insert(&mut self, handle_id: u64, fire_tick: u64, entry: TimerEntry) {
        self.by_deadline.insert(
            TimerKey {
                fire_tick,
                handle_id,
            },
            entry,
        );
        self.by_id.insert(handle_id, fire_tick);
    }

    fn cancel(&mut self, handle_id: u64) -> bool {
        let Some(fire_tick) = self.by_id.remove(&handle_id) else {
            return false;
        };
        self.by_deadline
            .remove(&TimerKey {
                fire_tick,
                handle_id,
            })
            .is_some()
    }

    fn next_deadline(&self) -> Option<u64> {
        self.by_deadline
            .first_key_value()
            .map(|(key, _)| key.fire_tick)
    }

    fn pop_expired(&mut self, current_tick: u64) -> Option<(TimerKey, TimerEntry)> {
        let key = match self.by_deadline.first_key_value() {
            Some((key, _)) if key.fire_tick <= current_tick => *key,
            _ => return None,
        };
        let entry = self.by_deadline.remove(&key)?;
        self.by_id.remove(&key.handle_id);
        Some((key, entry))
    }

    fn reschedule(&mut self, handle_id: u64, current_tick: u64, entry: TimerEntry) {
        let fire_tick = current_tick.saturating_add(entry.interval_ms);
        self.insert(handle_id, fire_tick, entry);
    }

    fn active_len(&self) -> usize {
        self.by_id.len()
    }

    fn expired_len(&self, current_tick: u64) -> usize {
        self.by_deadline
            .range(
                ..=TimerKey {
                    fire_tick: current_tick,
                    handle_id: u64::MAX,
                },
            )
            .count()
    }
}

// ============================================================================
// CPU Time Tracker
// ============================================================================

struct CpuTimeEntry {
    cpu_time_ns: u64,
    start_tick: u64,
    last_scheduled_tick: u64,
    schedule_count: u64,
}

struct TaskCpuTracker {
    entries: PoisonLock<BTreeMap<u64, CpuTimeEntry>>,
}

impl TaskCpuTracker {
    const fn new() -> Self {
        Self {
            entries: PoisonLock::new(BTreeMap::new()),
        }
    }

    fn record_start(&self, task_id: u64, current_tick: u64) {
        let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let entry = map.entry(task_id).or_insert(CpuTimeEntry {
            cpu_time_ns: 0,
            start_tick: 0,
            last_scheduled_tick: 0,
            schedule_count: 0,
        });
        entry.start_tick = current_tick;
        entry.last_scheduled_tick = current_tick;
        entry.schedule_count += 1;
    }

    fn record_stop(&self, task_id: u64, current_tick: u64) {
        let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = map.get_mut(&task_id) {
            if entry.start_tick > 0 {
                let elapsed_ticks = current_tick.saturating_sub(entry.start_tick);
                entry.cpu_time_ns += elapsed_ticks * NANOS_PER_MILLI;
                entry.start_tick = 0;
            }
        }
    }

    fn get_stats(&self, task_id: u64) -> Option<CpuTimeStats> {
        let map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        map.get(&task_id).map(|entry| CpuTimeStats {
            cpu_time_ns: entry.cpu_time_ns,
            last_scheduled_tick: entry.last_scheduled_tick,
            schedule_count: entry.schedule_count,
        })
    }
}

// ============================================================================
// TimeManagement
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpiredKind {
    Sleep,
    Timer,
}

pub struct TimeManagement {
    ticks: AtomicU64,
    wall_clock_offset_ns: AtomicI64,
    sleep_registry: OrderedSleepRegistry,
    timers: PoisonLock<TimerRegistry>,
    next_timer_id: AtomicU64,
    total_fired: AtomicU64,
    waker_dispatches: AtomicU64,
    cpu_tracker: TaskCpuTracker,
}

unsafe impl Send for TimeManagement {}
unsafe impl Sync for TimeManagement {}

impl TimeManagement {
    pub const fn new() -> Self {
        Self {
            ticks: AtomicU64::new(0),
            wall_clock_offset_ns: AtomicI64::new(0),
            sleep_registry: OrderedSleepRegistry::new(),
            timers: PoisonLock::new(TimerRegistry::new()),
            next_timer_id: AtomicU64::new(1),
            total_fired: AtomicU64::new(0),
            waker_dispatches: AtomicU64::new(0),
            cpu_tracker: TaskCpuTracker::new(),
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

    fn next_expired_kind(&self, current_tick: u64) -> Option<ExpiredKind> {
        let next_sleep = self
            .sleep_registry
            .next_deadline()
            .filter(|tick| *tick <= current_tick);
        let next_timer = self
            .timers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .next_deadline()
            .filter(|tick| *tick <= current_tick);

        match (next_sleep, next_timer) {
            (Some(sleep_tick), Some(timer_tick)) => {
                if sleep_tick <= timer_tick {
                    Some(ExpiredKind::Sleep)
                } else {
                    Some(ExpiredKind::Timer)
                }
            }
            (Some(_), None) => Some(ExpiredKind::Sleep),
            (None, Some(_)) => Some(ExpiredKind::Timer),
            (None, None) => None,
        }
    }

    fn process_expired_sleep(&self, current_tick: u64) -> bool {
        let Some(waker) = self.sleep_registry.pop_expired(current_tick) else {
            return false;
        };
        self.waker_dispatches.fetch_add(1, Ordering::Relaxed);
        waker.wake();
        true
    }

    fn process_expired_timer(&self, current_tick: u64) -> bool {
        let Some((key, entry)) = self
            .timers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop_expired(current_tick)
        else {
            return false;
        };

        let TimerEntry {
            interval_ms,
            mode,
            waker,
        } = entry;

        if mode == TimerMode::Periodic {
            self.timers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .reschedule(
                    key.handle_id,
                    current_tick,
                    TimerEntry {
                        interval_ms,
                        mode,
                        waker: waker.clone(),
                    },
                );
        }

        self.total_fired.fetch_add(1, Ordering::Relaxed);
        self.waker_dispatches.fetch_add(1, Ordering::Relaxed);
        waker.wake();
        true
    }
}

impl TimeService for TimeManagement {
    fn compute_wake_tick(&self, duration_ms: u64) -> u64 {
        self.ticks
            .load(Ordering::SeqCst)
            .saturating_add(duration_ms)
    }

    fn register_timer(&self, interval_ms: u64, mode: TimerMode, waker: Waker) -> TimerHandle {
        let handle_id = self.next_timer_id.fetch_add(1, Ordering::Relaxed);
        let current_tick = self.ticks.load(Ordering::SeqCst);
        let normalized_interval = match mode {
            TimerMode::OneShot => interval_ms,
            TimerMode::Periodic => interval_ms.max(1),
        };

        self.timers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                handle_id,
                current_tick.saturating_add(normalized_interval),
                TimerEntry {
                    interval_ms: normalized_interval,
                    mode,
                    waker,
                },
            );

        TimerHandle(handle_id)
    }

    fn cancel_timer(&self, handle: TimerHandle) -> bool {
        self.timers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .cancel(handle.0)
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

    fn task_cpu_stats(&self, task_id: u64) -> Option<CpuTimeStats> {
        self.cpu_tracker.get_stats(task_id)
    }

    fn record_task_start(&self, task_id: u64) {
        self.cpu_tracker
            .record_start(task_id, self.ticks.load(Ordering::SeqCst));
    }

    fn record_task_stop(&self, task_id: u64) {
        self.cpu_tracker
            .record_stop(task_id, self.ticks.load(Ordering::SeqCst));
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
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                    Some(current.saturating_add(delta_ns))
                });
    }

    fn register_sleep(&self, wake_tick: u64, waker: Waker) {
        self.sleep_registry.insert(wake_tick, waker);
    }

    fn unregister_sleep(&self, wake_tick: u64) {
        if self.current_tick_ms() >= wake_tick {
            return;
        }
        let _ = self.sleep_registry.remove_one(wake_tick);
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
    use spin::Mutex;

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
