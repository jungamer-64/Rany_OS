// ============================================================================
// drivers/time/src/lib.rs - Time Management Driver (Cell)
// ============================================================================
//!
//! # Time Management Driver
//!
//! ExoRust アーキテクチャにおける時間管理セル（ドライバ）。
//! 高レベルのタイマーサービスを提供する。

#![no_std]
#![allow(dead_code)]
#![allow(clippy::cast_possible_truncation)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};
use exorust_sync::PoisonLock;
use kernel_api::service::time::{
    CpuTimeStats, TimeService, TimerHandle, TimerMode, TimerServiceStats,
};

// ============================================================================
// Constants
// ============================================================================

const NANOS_PER_MILLI: u64 = 1_000_000;
const NANOS_PER_SEC: u64 = 1_000_000_000;
const SHARD_COUNT: usize = 16;
const SHARD_MASK: usize = SHARD_COUNT - 1;
const PENDING_QUEUE_SIZE: usize = 512;
const PENDING_QUEUE_MASK: usize = PENDING_QUEUE_SIZE - 1;

// ============================================================================
// Sharded Sleep Registry
// ============================================================================

struct ShardedSleepRegistry {
    shards: [PoisonLock<BTreeMap<u64, Vec<Waker>>>; SHARD_COUNT],
}

impl ShardedSleepRegistry {
    const fn new() -> Self {
        const EMPTY_SHARD: PoisonLock<BTreeMap<u64, Vec<Waker>>> = PoisonLock::new(BTreeMap::new());
        Self {
            shards: [EMPTY_SHARD; SHARD_COUNT],
        }
    }

    #[inline]
    fn shard_index(tick: u64) -> usize {
        (tick as usize) & SHARD_MASK
    }

    fn insert(&self, tick: u64, waker: Waker) {
        let idx = Self::shard_index(tick);
        self.shards[idx]
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(tick)
            .or_insert_with(Vec::new)
            .push(waker);
    }

    fn remove(&self, tick: u64) -> Option<Waker> {
        let idx = Self::shard_index(tick);
        let mut guard = self.shards[idx].lock().unwrap_or_else(|e| e.into_inner());
        if let Some(wakers) = guard.get_mut(&tick) {
            let w = wakers.pop();
            if wakers.is_empty() {
                guard.remove(&tick);
            }
            w
        } else {
            None
        }
    }

    fn drain_expired(&self, current_tick: u64, out: &mut Vec<Waker>) {
        for shard in &self.shards {
            if let Ok(mut guard) = shard.try_lock() {
                let expired_keys: Vec<u64> =
                    guard.range(..=current_tick).map(|(k, _)| *k).collect();

                for key in expired_keys {
                    if let Some(wakers) = guard.remove(&key) {
                        out.extend(wakers);
                    }
                }
            } else if let Some(e) = shard.try_lock().err() {
                if let exorust_sync::PoisonError::Poisoned(mut guard) = e {
                    let expired_keys: Vec<u64> =
                        guard.range(..=current_tick).map(|(k, _)| *k).collect();
                    for key in expired_keys {
                        if let Some(wakers) = guard.remove(&key) {
                            out.extend(wakers);
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// Lock-Free Pending Wakers Queue
// ============================================================================

#[repr(C, align(64))]
struct LockFreePendingWakers {
    head: AtomicUsize,
    tail: AtomicUsize,
    buffer: [AtomicUsize; PENDING_QUEUE_SIZE],
    enqueued: AtomicUsize,
    dropped: AtomicUsize,
}

impl LockFreePendingWakers {
    const fn new() -> Self {
        const ZERO: AtomicUsize = AtomicUsize::new(0);
        Self {
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            buffer: [ZERO; PENDING_QUEUE_SIZE],
            enqueued: AtomicUsize::new(0),
            dropped: AtomicUsize::new(0),
        }
    }

    fn enqueue(&self, waker: Waker) -> bool {
        let boxed = Box::new(waker);
        let ptr = Box::into_raw(boxed) as usize;

        loop {
            let head = self.head.load(Ordering::Acquire);
            let tail = self.tail.load(Ordering::Acquire);

            if head.wrapping_sub(tail) >= PENDING_QUEUE_SIZE {
                unsafe {
                    let _ = Box::from_raw(ptr as *mut Waker);
                }
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return false;
            }

            let idx = head & PENDING_QUEUE_MASK;

            match self.head.compare_exchange_weak(
                head,
                head.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.buffer[idx].store(ptr, Ordering::Release);
                    self.enqueued.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
                Err(_) => {
                    core::hint::spin_loop();
                }
            }
        }
    }

    fn drain(&self) -> Vec<Waker> {
        let mut wakers = Vec::new();

        loop {
            let tail = self.tail.load(Ordering::Acquire);
            let head = self.head.load(Ordering::Acquire);

            if tail == head {
                break;
            }

            let idx = tail & PENDING_QUEUE_MASK;

            match self.tail.compare_exchange_weak(
                tail,
                tail.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    let ptr = self.buffer[idx].swap(0, Ordering::Acquire);
                    if ptr != 0 {
                        let waker = unsafe { *Box::from_raw(ptr as *mut Waker) };
                        wakers.push(waker);
                    }
                }
                Err(_) => {
                    core::hint::spin_loop();
                }
            }
        }

        wakers
    }

    fn stats(&self) -> (usize, usize) {
        (
            self.enqueued.load(Ordering::Relaxed),
            self.dropped.load(Ordering::Relaxed),
        )
    }

    fn len(&self) -> usize {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        head.wrapping_sub(tail)
    }
}

// ============================================================================
// Timer Entry
// ============================================================================

struct TimerEntry {
    fire_tick: u64,
    interval_ms: u64,
    mode: TimerMode,
    waker: Waker,
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
        map.get(&task_id).map(|e| CpuTimeStats {
            cpu_time_ns: e.cpu_time_ns,
            last_scheduled_tick: e.last_scheduled_tick,
            schedule_count: e.schedule_count,
        })
    }
}

// ============================================================================
// TimeManagement
// ============================================================================

pub struct TimeManagement {
    ticks: AtomicU64,
    boot_unix_timestamp_ms: AtomicU64,
    wall_clock_adjustment_ns: AtomicI64,
    sleep_registry: ShardedSleepRegistry,
    pending_wakers: LockFreePendingWakers,
    timers: PoisonLock<BTreeMap<u64, TimerEntry>>,
    next_timer_id: AtomicU64,
    total_fired: AtomicU64,
    cpu_tracker: TaskCpuTracker,
}

unsafe impl Send for TimeManagement {}
unsafe impl Sync for TimeManagement {}

impl TimeManagement {
    pub const fn new() -> Self {
        Self {
            ticks: AtomicU64::new(0),
            boot_unix_timestamp_ms: AtomicU64::new(0),
            wall_clock_adjustment_ns: AtomicI64::new(0),
            sleep_registry: ShardedSleepRegistry::new(),
            pending_wakers: LockFreePendingWakers::new(),
            timers: PoisonLock::new(BTreeMap::new()),
            next_timer_id: AtomicU64::new(1),
            total_fired: AtomicU64::new(0),
            cpu_tracker: TaskCpuTracker::new(),
        }
    }

    pub fn set_boot_timestamp_ms(&self, timestamp_ms: u64) {
        self.boot_unix_timestamp_ms
            .store(timestamp_ms, Ordering::SeqCst);
    }

    pub fn pending_waker_count(&self) -> usize {
        self.pending_wakers.len()
    }

    pub fn pending_waker_stats(&self) -> (usize, usize) {
        self.pending_wakers.stats()
    }

    fn process_expired_timers(&self, current_tick: u64) {
        if let Ok(mut timers) = self.timers.try_lock() {
            self.do_process_expired_timers(&mut timers, current_tick);
        } else if let Some(e) = self.timers.try_lock().err() {
            if let exorust_sync::PoisonError::Poisoned(mut timers) = e {
                self.do_process_expired_timers(&mut timers, current_tick);
            }
        }
    }

    fn do_process_expired_timers(&self, timers: &mut BTreeMap<u64, TimerEntry>, current_tick: u64) {
        let mut to_fire: Vec<u64> = Vec::new();
        let mut to_reschedule: Vec<(u64, TimerEntry)> = Vec::new();

        for (&id, entry) in timers.iter() {
            if entry.fire_tick <= current_tick {
                to_fire.push(id);
            }
        }

        for id in &to_fire {
            if let Some(entry) = timers.remove(id) {
                let _ = self.pending_wakers.enqueue(entry.waker.clone());
                self.total_fired.fetch_add(1, Ordering::Relaxed);

                if entry.mode == TimerMode::Periodic {
                    to_reschedule.push((
                        *id,
                        TimerEntry {
                            fire_tick: current_tick + entry.interval_ms,
                            interval_ms: entry.interval_ms,
                            mode: entry.mode,
                            waker: entry.waker,
                        },
                    ));
                }
            }
        }

        for (id, entry) in to_reschedule {
            timers.insert(id, entry);
        }
    }
}

impl TimeService for TimeManagement {
    fn compute_wake_tick(&self, duration_ms: u64) -> u64 {
        self.ticks.load(Ordering::SeqCst) + duration_ms
    }

    fn register_timer(&self, interval_ms: u64, mode: TimerMode, waker: Waker) -> TimerHandle {
        let id = self.next_timer_id.fetch_add(1, Ordering::Relaxed);
        let current = self.ticks.load(Ordering::SeqCst);

        let entry = TimerEntry {
            fire_tick: current + interval_ms,
            interval_ms,
            mode,
            waker,
        };

        self.timers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, entry);
        TimerHandle(id)
    }

    fn cancel_timer(&self, handle: TimerHandle) -> bool {
        self.timers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&handle.0)
            .is_some()
    }

    fn current_tick_ms(&self) -> u64 {
        self.ticks.load(Ordering::SeqCst)
    }

    fn uptime_ns(&self) -> u64 {
        self.ticks.load(Ordering::SeqCst) * NANOS_PER_MILLI
    }

    fn unix_timestamp(&self) -> u64 {
        let boot_ms = self.boot_unix_timestamp_ms.load(Ordering::Relaxed);
        let uptime_ms = self.ticks.load(Ordering::SeqCst);
        let adj_ns = self.wall_clock_adjustment_ns.load(Ordering::Relaxed);
        let total_ms = boot_ms + uptime_ms;
        let adj_ms = adj_ns / (NANOS_PER_MILLI as i64);
        (total_ms as i64 + adj_ms) as u64 / 1000
    }

    fn unix_timestamp_ms(&self) -> u64 {
        let boot_ms = self.boot_unix_timestamp_ms.load(Ordering::Relaxed);
        let uptime_ms = self.ticks.load(Ordering::SeqCst);
        let adj_ns = self.wall_clock_adjustment_ns.load(Ordering::Relaxed);
        let adj_ms = adj_ns / (NANOS_PER_MILLI as i64);
        (boot_ms as i64 + uptime_ms as i64 + adj_ms) as u64
    }

    fn stats(&self) -> TimerServiceStats {
        let (enq, drop) = self.pending_wakers.stats();
        let active = self
            .timers
            .try_lock()
            .map_or_else(|e| e.into_inner().len(), |t| t.len());

        TimerServiceStats {
            active_timers: active,
            total_fired: self.total_fired.load(Ordering::Relaxed),
            waker_enqueued: enq,
            waker_dropped: drop,
            pending_wakers: self.pending_wakers.len(),
        }
    }

    fn task_cpu_stats(&self, task_id: u64) -> Option<CpuTimeStats> {
        self.cpu_tracker.get_stats(task_id)
    }

    fn record_task_start(&self, task_id: u64) {
        let tick = self.ticks.load(Ordering::SeqCst);
        self.cpu_tracker.record_start(task_id, tick);
    }

    fn record_task_stop(&self, task_id: u64) {
        let tick = self.ticks.load(Ordering::SeqCst);
        self.cpu_tracker.record_stop(task_id, tick);
    }

    fn on_timer_interrupt(&self) {
        let current_tick = self.ticks.fetch_add(1, Ordering::SeqCst) + 1;
        let mut expired = Vec::new();
        self.sleep_registry
            .drain_expired(current_tick, &mut expired);
        for waker in expired {
            let _ok = self.pending_wakers.enqueue(waker);
        }
        self.process_expired_timers(current_tick);
    }

    fn process_pending_wakers(&self) {
        let wakers = self.pending_wakers.drain();
        for waker in wakers {
            waker.wake();
        }
    }

    fn adjust_wall_clock(&self, delta_ns: i64) {
        self.wall_clock_adjustment_ns
            .fetch_add(delta_ns, Ordering::Relaxed);
    }

    fn register_sleep(&self, wake_tick: u64, waker: Waker) {
        self.sleep_registry.insert(wake_tick, waker);
    }

    fn unregister_sleep(&self, wake_tick: u64) {
        let _ = self.sleep_registry.remove(wake_tick);
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

pub async fn sleep_ms(duration_ms: u64) {
    SleepFuture::new(duration_ms).await;
}

pub struct SleepFuture {
    wake_tick: u64,
    registered: bool,
}

impl SleepFuture {
    pub fn new(duration_ms: u64) -> Self {
        let wake_tick = TIME_MANAGER.compute_wake_tick(duration_ms);
        Self {
            wake_tick,
            registered: false,
        }
    }
}

impl Future for SleepFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let current = TIME_MANAGER.current_tick_ms();
        if current >= self.wake_tick {
            return Poll::Ready(());
        }
        if !self.registered {
            TIME_MANAGER.register_sleep(self.wake_tick, cx.waker().clone());
            self.registered = true;
        }
        Poll::Pending
    }
}

impl Drop for SleepFuture {
    fn drop(&mut self) {
        if self.registered {
            TIME_MANAGER.unregister_sleep(self.wake_tick);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn timer_registration_smoke() {
        let tm = TimeManagement::new();
        let waker = core::task::Waker::noop();
        let handle = tm.register_timer(100, TimerMode::OneShot, waker.clone());
        assert!(tm.cancel_timer(handle));
        assert!(!tm.cancel_timer(handle));
    }

    #[test]
    fn cpu_tracker_smoke() {
        let tm = TimeManagement::new();
        tm.on_timer_interrupt(); // tick=1
        tm.record_task_start(42);
        tm.on_timer_interrupt(); // tick=2
        tm.on_timer_interrupt(); // tick=3
        tm.record_stop(42, 3);
        let stats = tm.task_cpu_stats(42).expect("task stats should exist");
        assert_eq!(stats.schedule_count, 1);
        assert!(stats.cpu_time_ns > 0);
    }

    impl TimeManagement {
        fn record_stop(&self, task_id: u64, current_tick: u64) {
            self.cpu_tracker.record_stop(task_id, current_tick);
        }
    }

    #[test]
    fn shard_index_smoke() {
        assert_eq!(ShardedSleepRegistry::shard_index(0), 0);
        assert_eq!(ShardedSleepRegistry::shard_index(16), 0);
        assert_eq!(ShardedSleepRegistry::shard_index(1), 1);
        assert_eq!(ShardedSleepRegistry::shard_index(15), 15);
    }

    #[test]
    fn uptime_ns_smoke() {
        let tm = TimeManagement::new();
        tm.on_timer_interrupt();
        assert_eq!(tm.uptime_ns(), NANOS_PER_MILLI);
    }

    #[test]
    fn wall_clock_adjustment_smoke() {
        let tm = TimeManagement::new();
        tm.set_boot_timestamp_ms(1_000_000);
        tm.adjust_wall_clock(500_000_000); // +500ms
        assert_eq!(tm.unix_timestamp_ms(), 1_000_500);
    }
}
