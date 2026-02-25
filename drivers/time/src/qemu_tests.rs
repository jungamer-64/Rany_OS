#![allow(clippy::wildcard_imports)]
use super::*;

pub fn tick_increment_smoke() -> bool {
    let tm = TimeManagement::new();
    if tm.current_tick_ms() != 0 {
        return false;
    }
    tm.on_timer_interrupt();
    if tm.current_tick_ms() != 1 {
        return false;
    }
    tm.on_timer_interrupt();
    tm.current_tick_ms() == 2
}

pub fn timer_registration_smoke() -> bool {
    let tm = TimeManagement::new();
    let waker = core::task::Waker::noop();
    let handle = tm.register_timer(100, TimerMode::OneShot, waker.clone());
    tm.cancel_timer(handle) && !tm.cancel_timer(handle)
}

pub fn cpu_tracker_smoke() -> bool {
    let tm = TimeManagement::new();
    tm.on_timer_interrupt(); // tick=1
    tm.record_task_start(42);
    tm.on_timer_interrupt(); // tick=2
    tm.on_timer_interrupt(); // tick=3
    tm.record_task_stop(42);

    match tm.task_cpu_stats(42) {
        Some(stats) => stats.schedule_count == 1 && stats.cpu_time_ns > 0,
        None => false,
    }
}

pub fn shard_index_smoke() -> bool {
    ShardedSleepRegistry::shard_index(0) == 0
        && ShardedSleepRegistry::shard_index(16) == 0
        && ShardedSleepRegistry::shard_index(1) == 1
        && ShardedSleepRegistry::shard_index(15) == 15
}

pub fn uptime_ns_smoke() -> bool {
    let tm = TimeManagement::new();
    tm.on_timer_interrupt();
    tm.uptime_ns() == NANOS_PER_MILLI
}

pub fn wall_clock_adjustment_smoke() -> bool {
    let tm = TimeManagement::new();
    tm.set_boot_timestamp_ms(1_000_000);
    tm.adjust_wall_clock(500_000_000); // +500ms
    tm.unix_timestamp_ms() == 1_000_500
}
