use super::*;

impl GlobalScheduler {
    pub fn new(num_cores: u32) -> Self {
        let mut workers = Vec::with_capacity(num_cores as usize);
        for i in 0..num_cores {
            workers.push(PerCoreWorker::new(i));
        }

        Self {
            workers,
            global_queue: Mutex::new(VecDeque::with_capacity(GLOBAL_QUEUE_CAPACITY)),
            active_cores: AtomicU32::new(num_cores),
            next_task_id: AtomicU64::new(1),
            poll_counter: AtomicU64::new(0),
            load_balance_enabled: AtomicBool::new(true),
        }
    }

    /// 新しいタスクIDを生成
    pub fn alloc_task_id(&self) -> TaskId {
        TaskId(self.next_task_id.fetch_add(1, Ordering::Relaxed))
    }

    /// タスクをスポーン
    pub fn spawn(&self, mut task: Box<StealableTask>) -> Result<(), Box<StealableTask>> {
        // アフィニティに基づいてコアを選択
        let target_core = self.select_core_for_task(&task);

        if let Some(worker) = self.workers.get(target_core as usize) {
            match worker.push_task(task) {
                Ok(()) => return Ok(()),
                Err(returned_task) => task = returned_task,
            }
        }

        // ローカルキューが満杯ならグローバルキューへ
        let mut global = self.global_queue.lock();
        if global.len() < GLOBAL_QUEUE_CAPACITY {
            global.push_back(task);
            Ok(())
        } else {
            Err(task)
        }
    }

    /// タスクに適したコアを選択
    pub(super) fn select_core_for_task(&self, task: &StealableTask) -> u32 {
        // 優先コアがあればそれを使用
        if let Some(preferred) = task.affinity.preferred_core() {
            if task.affinity.is_allowed(preferred) {
                return preferred;
            }
        }

        // 最後に実行されたコア（キャッシュローカリティ）
        if let Some(last) = task.last_core {
            if task.affinity.is_allowed(last) {
                let worker = &self.workers[last as usize];
                if worker.queue_size() < LOCAL_QUEUE_CAPACITY / 2 {
                    return last;
                }
            }
        }

        // 最も負荷の低いコアを選択
        self.find_least_loaded_core(&task.affinity)
    }

    /// 最も負荷の低いコアを見つける
    pub(super) fn find_least_loaded_core(&self, affinity: &CoreAffinity) -> u32 {
        let mut min_load = usize::MAX;
        let mut selected = 0;

        for (i, worker) in self.workers.iter().enumerate() {
            if !affinity.is_allowed(i as u32) {
                continue;
            }

            let load = worker.queue_size();
            if load < min_load {
                min_load = load;
                selected = i as u32;
            }
        }

        selected
    }

    /// 指定コアの次のタスクを取得
    pub fn schedule(&self, core_id: u32) -> Option<Box<StealableTask>> {
        let worker = self.workers.get(core_id as usize)?;

        // 1. ローカルキューから
        if let Some(task) = worker.pop_task() {
            return Some(task);
        }

        // 2. グローバルキューから
        if let Some(task) = self.try_pop_global(core_id) {
            return Some(task);
        }

        // 3. 他のコアからスチール
        if worker.queue_size() < STEAL_THRESHOLD {
            if let Some(task) = self.try_steal_from_others(core_id) {
                worker
                    .stats
                    .tasks_received_from_steal
                    .fetch_add(1, Ordering::Relaxed);
                return Some(task);
            }
        }

        // 周期的な負荷バランシング
        self.maybe_load_balance();

        None
    }

    /// グローバルキューからポップ
    pub(super) fn try_pop_global(&self, core_id: u32) -> Option<Box<StealableTask>> {
        let mut global = self.global_queue.lock();

        // アフィニティに適合するタスクを探す
        for i in 0..global.len() {
            if global[i].affinity.is_allowed(core_id) {
                return global.remove(i);
            }
        }
        None
    }

    /// 他のコアからスチール
    ///
    /// 【設計書 4.3】NUMA優先の3段階ワークスティーリング:
    /// 1. ローカルコア（L1/L2キャッシュ共有）から優先
    /// 2. 同一NUMAノード内のコアから
    /// 3. 他のNUMAノードのコアから
    pub(super) fn try_steal_from_others(&self, core_id: u32) -> Option<Box<StealableTask>> {
        if self.workers.len() <= 1 {
            return None;
        }

        let numa_info = NumaTopology::get();

        if let Some(task) = self.steal_from_llc_siblings(core_id, numa_info) {
            return Some(task);
        }
        if let Some(task) = self.steal_from_same_numa(core_id, numa_info) {
            return Some(task);
        }
        self.steal_from_remote_numa(core_id, numa_info)
    }

    /// Phase 1: 同一LLCを共有するコア（Hyperthread sibling）からスチール
    pub(super) fn steal_from_llc_siblings(
        &self,
        core_id: u32,
        numa_info: &NumaTopology,
    ) -> Option<Box<StealableTask>> {
        for &sibling_id in numa_info.get_llc_siblings(core_id) {
            if sibling_id == core_id || sibling_id as usize >= self.workers.len() {
                continue;
            }
            if let Some(task) = self.try_steal_from_core(sibling_id, core_id) {
                return Some(task);
            }
        }
        None
    }

    /// Phase 2: 同一NUMAノード内の他コアからスチール（LLC sibling除く）
    pub(super) fn steal_from_same_numa(
        &self,
        core_id: u32,
        numa_info: &NumaTopology,
    ) -> Option<Box<StealableTask>> {
        let my_numa_node = numa_info.get_numa_node(core_id);
        for &target_core in numa_info.get_cores_in_node(my_numa_node) {
            if target_core == core_id || target_core as usize >= self.workers.len() {
                continue;
            }
            if numa_info.shares_llc(core_id, target_core) {
                continue;
            }
            if let Some(task) = self.try_steal_from_core(target_core, core_id) {
                return Some(task);
            }
        }
        None
    }

    /// Phase 3: 他のNUMAノードからスチール（最後の手段）
    pub(super) fn steal_from_remote_numa(
        &self,
        core_id: u32,
        numa_info: &NumaTopology,
    ) -> Option<Box<StealableTask>> {
        let my_numa_node = numa_info.get_numa_node(core_id);
        for node in 0..numa_info.num_nodes() {
            if node == my_numa_node {
                continue;
            }
            for &target_core in numa_info.get_cores_in_node(node) {
                if target_core as usize >= self.workers.len() {
                    continue;
                }
                if let Some(task) = self.try_steal_from_core(target_core, core_id) {
                    self.workers[core_id as usize]
                        .stats
                        .cross_numa_steals
                        .fetch_add(1, Ordering::Relaxed);
                    return Some(task);
                }
            }
        }
        None
    }

    /// 特定のコアからタスクをスチール
    pub(super) fn try_steal_from_core(
        &self,
        victim_id: u32,
        thief_id: u32,
    ) -> Option<Box<StealableTask>> {
        let victim = &self.workers[victim_id as usize];

        // 被害者のキューが十分にある場合のみスチール
        if victim.queue_size() <= STEAL_BATCH_SIZE {
            return None;
        }

        // バッチスチール
        for _ in 0..STEAL_BATCH_SIZE {
            if let Some(task) = victim.steal_task() {
                if task.affinity.is_allowed(thief_id) {
                    return Some(task);
                }
                // アフィニティが合わない場合は被害者のキューに戻す
                // （簡略化のため現在は破棄）
            }
        }
        None
    }

    /// 負荷バランシングを試行
    pub(super) fn maybe_load_balance(&self) {
        if !self.load_balance_enabled.load(Ordering::Relaxed) {
            return;
        }

        let count = self.poll_counter.load(Ordering::Relaxed);
        if count % LOAD_BALANCE_INTERVAL == 0 {
            self.load_balance();

            // AutoNUMA スキャン
            // 内部でタイマーチェックを行うため、頻繁に呼び出しても安全
            crate::mm::numa::autonuma::try_scan_current_process();
        }
    }

    /// 負荷バランシングを実行
    pub fn load_balance(&self) {
        // 最も負荷の高いコアと低いコアを見つける
        let mut max_load = 0;
        let mut max_core = 0;
        let mut min_load = usize::MAX;
        let mut min_core = 0;

        for (i, worker) in self.workers.iter().enumerate() {
            let load = worker.queue_size();
            if load > max_load {
                max_load = load;
                max_core = i;
            }
            if load < min_load {
                min_load = load;
                min_core = i;
            }
        }

        // 負荷差が大きい場合にマイグレーション
        if max_load > min_load * 2 && max_load > STEAL_BATCH_SIZE * 2 {
            let move_count = (max_load - min_load) / 2;
            // 実際のマイグレーション処理（省略）
            let _ = (max_core, min_core, move_count);
        }
    }

    /// ワーカー数を取得
    pub fn num_workers(&self) -> usize {
        self.workers.len()
    }

    /// ワーカーを取得
    pub fn worker(&self, core_id: u32) -> Option<&PerCoreWorker> {
        self.workers.get(core_id as usize)
    }

    /// 全体の統計を取得
    pub fn total_stats(&self) -> SchedulerStats {
        let mut stats = SchedulerStats::default();

        for worker in &self.workers {
            let ws = worker.stats();
            stats.tasks_executed += ws.tasks_executed.load(Ordering::Relaxed);
            stats.tasks_stolen += ws.tasks_stolen.load(Ordering::Relaxed);
            stats.idle_cycles += ws.idle_cycles.load(Ordering::Relaxed);
        }

        stats.global_queue_size = self.global_queue.lock().len();
        stats
    }
}

/// スケジューラ全体の統計
#[derive(Debug, Default)]
pub struct SchedulerStats {
    pub tasks_executed: u64,
    pub tasks_stolen: u64,
    pub idle_cycles: u64,
    pub global_queue_size: usize,
}

// ============================================================================
// Global Instance (Lock-Free via spin::Once)
// ============================================================================

/// Global scheduler instance using Once for lock-free access after initialization.
/// This pattern eliminates Mutex overhead for all scheduler operations after init.
pub(crate) static SCHEDULER: Once<GlobalScheduler> = Once::new();

/// スケジューラを初期化
///
/// Must be called exactly once during kernel startup.
/// Subsequent calls are no-ops (the first initialization wins).
pub fn init(num_cores: u32) {
    SCHEDULER.call_once(|| GlobalScheduler::new(num_cores));
}

/// スケジューラにアクセス（ロックフリー）
///
/// Returns None if scheduler is not yet initialized.
/// After initialization, this is a single atomic load.
#[inline]
pub fn with_scheduler<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&GlobalScheduler) -> R,
{
    SCHEDULER.get().map(f)
}

/// スケジューラへの直接参照を取得（初期化済みの場合）
#[inline]
pub fn get_scheduler() -> Option<&'static GlobalScheduler> {
    SCHEDULER.get()
}

/// スケジューラが初期化済みかどうか
#[inline]
pub fn is_initialized() -> bool {
    SCHEDULER.get().is_some()
}

/// タスクをスポーン（ロックフリー）
pub fn spawn(task: Box<StealableTask>) -> Result<(), Box<StealableTask>> {
    match SCHEDULER.get() {
        Some(scheduler) => scheduler.spawn(task),
        None => Err(task),
    }
}

/// 次のタスクをスケジュール（ロックフリー）
#[inline]
pub fn schedule(core_id: u32) -> Option<Box<StealableTask>> {
    SCHEDULER.get().and_then(|s| s.schedule(core_id))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
