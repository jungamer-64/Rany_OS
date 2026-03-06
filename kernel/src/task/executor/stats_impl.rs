use super::*;

impl ExecutorStats {
    pub(super) const fn new() -> Self {
        Self {
            tasks_spawned: AtomicU64::new(0),
            tasks_completed: AtomicU64::new(0),
            wakeups: AtomicU64::new(0),
            poll_cycles: AtomicU64::new(0),
            global_fetches: AtomicU64::new(0),
            idle_cycles: AtomicU64::new(0),
            steals: AtomicU64::new(0),
        }
    }

    /// スナップショットを取得
    pub fn snapshot(&self) -> ExecutorStatsSnapshot {
        ExecutorStatsSnapshot {
            tasks_spawned: self.tasks_spawned.load(Ordering::Relaxed),
            tasks_completed: self.tasks_completed.load(Ordering::Relaxed),
            wakeups: self.wakeups.load(Ordering::Relaxed),
            poll_cycles: self.poll_cycles.load(Ordering::Relaxed),
            global_fetches: self.global_fetches.load(Ordering::Relaxed),
            idle_cycles: self.idle_cycles.load(Ordering::Relaxed),
            steals: self.steals.load(Ordering::Relaxed),
        }
    }
}

/// 統計のスナップショット
#[derive(Debug, Clone, Copy)]
pub struct ExecutorStatsSnapshot {
    pub tasks_spawned: u64,
    pub tasks_completed: u64,
    pub wakeups: u64,
    pub poll_cycles: u64,
    pub global_fetches: u64,
    pub idle_cycles: u64,
    pub steals: u64,
}

/// Executor統計を取得
pub fn get_executor_stats() -> ExecutorStatsSnapshot {
    EXECUTOR_STATS.snapshot()
}
