// ============================================================================
// src/task/executor.rs - Lock-Free Executor with Work Stealing
// 設計書 4.1: Async/await firstのスケジューリング
// 設計書 4.3: マルチコアスケーリング
// ============================================================================
//!
//! # ロックフリー Executor
//!
//! ## 設計方針
//! - ロックフリーキューでコンテンション削減
//! - Per-CPUローカルキャッシュによるキャッシュ効率向上
//! - Work Stealingによる負荷分散
//!
//! ## 実装
//! - AtomicベースのMPMC Queueを内部で実装（crossbeam相当）
//! - ローカルキュー → グローバルキュー → スティールの優先順位
//! - batch処理でスループット向上
//! - Per-coreタスクストアでロックコンテンション削減（設計書 4.3）
#![allow(dead_code)]

use super::{Task, TaskId, create_waker};
use crate::sync::PoisonLock;
use alloc::collections::{BTreeMap, VecDeque};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll};
#[cfg(not(feature = "qemu-test-export"))]
use x86_64::instructions::interrupts;

// ============================================================================
// ロックフリーキュー（簡易MPMC実装）
// ============================================================================

/// ロックフリーのタスクID キュー
///
/// 実際のタスクはTASK_STOREに保存し、
/// キューはTaskIdのみを管理してオーバーヘッド削減。
mod stats_impl;
pub struct LockFreeQueue {
    /// リングバッファ
    buffer: [AtomicU64; QUEUE_SIZE],
    /// 先頭インデックス
    head: AtomicUsize,
    /// 末尾インデックス
    tail: AtomicUsize,
}

const QUEUE_SIZE: usize = 1024;
const EMPTY_SLOT: u64 = u64::MAX;

impl LockFreeQueue {
    /// 新しいキューを作成
    pub const fn new() -> Self {
        const EMPTY: AtomicU64 = AtomicU64::new(EMPTY_SLOT);
        Self {
            buffer: [EMPTY; QUEUE_SIZE],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    /// タスクIDをプッシュ（try）
    pub fn push(&self, task_id: TaskId) -> bool {
        loop {
            let tail = self.tail.load(Ordering::Relaxed);
            let head = self.head.load(Ordering::Acquire);

            // キューが満杯
            if tail.wrapping_sub(head) >= QUEUE_SIZE {
                return false;
            }

            let idx = tail % QUEUE_SIZE;

            // CAS for tail
            if self
                .tail
                .compare_exchange_weak(
                    tail,
                    tail.wrapping_add(1),
                    Ordering::Release,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                self.buffer[idx].store(task_id.as_u64(), Ordering::Release);
                return true;
            }

            core::hint::spin_loop();
        }
    }

    /// タスクIDをポップ（try）
    pub fn pop(&self) -> Option<TaskId> {
        loop {
            let head = self.head.load(Ordering::Relaxed);
            let tail = self.tail.load(Ordering::Acquire);

            // キューが空
            if head == tail {
                return None;
            }

            let idx = head % QUEUE_SIZE;
            let task_id = self.buffer[idx].load(Ordering::Acquire);

            // まだ書き込まれていない
            if task_id == EMPTY_SLOT {
                core::hint::spin_loop();
                continue;
            }

            // CAS for head
            if self
                .head
                .compare_exchange_weak(
                    head,
                    head.wrapping_add(1),
                    Ordering::Release,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                self.buffer[idx].store(EMPTY_SLOT, Ordering::Release);
                return Some(TaskId(task_id));
            }

            core::hint::spin_loop();
        }
    }

    /// キューが空かどうか
    pub fn is_empty(&self) -> bool {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        head == tail
    }

    /// キュー内のアイテム数
    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        tail.wrapping_sub(head)
    }
}

// ============================================================================
// グローバルキュー
// ============================================================================

/// グローバルなロックフリータスクキュー
static GLOBAL_QUEUE: LockFreeQueue = LockFreeQueue::new();

/// 最大CPU数
const MAX_CPUS: usize = 64;

/// Per-coreタスクストア
/// 設計書 4.3: コアローカルなタスク管理でロックコンテンション削減
struct PerCoreTaskStore {
    /// タスク保存マップ（Per-core）
    tasks: PoisonLock<BTreeMap<TaskId, Task>>,
    /// このCPUが有効かどうか
    active: AtomicBool,
    /// 保存タスク数（統計用）
    task_count: AtomicUsize,
}

impl PerCoreTaskStore {
    const fn new() -> Self {
        Self {
            tasks: PoisonLock::new(BTreeMap::new()),
            active: AtomicBool::new(false),
            task_count: AtomicUsize::new(0),
        }
    }

    /// タスクを追加
    fn insert(&self, task_id: TaskId, task: Task) {
        match self.tasks.lock() {
            Ok(mut guard) => {
                guard.insert(task_id, task);
                self.task_count.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                log::error!(
                    "[EXECUTOR] Per-core tasks lock poisoned during insert; dropping task"
                );
                // Legacy global TASK_STORE is deprecated and not used here.
            }
        }
    }

    /// タスクを取り出し
    fn remove(&self, task_id: &TaskId) -> Option<Task> {
        match self.tasks.lock() {
            Ok(mut guard) => {
                let result = guard.remove(task_id);
                if result.is_some() {
                    self.task_count.fetch_sub(1, Ordering::Relaxed);
                }
                result
            }
            Err(_) => {
                log::error!(
                    "[EXECUTOR] Per-core tasks lock poisoned during remove; cannot remove task"
                );
                None
            }
        }
    }

    /// タスク数を取得
    fn len(&self) -> usize {
        self.task_count.load(Ordering::Relaxed)
    }

    /// Work Stealing: タスクを1つ盗む
    fn steal_one(&self) -> Option<(TaskId, Task)> {
        match self.tasks.lock() {
            Ok(mut guard) => {
                if let Some((&task_id, _)) = guard.iter().next() {
                    if let Some(task) = guard.remove(&task_id) {
                        self.task_count.fetch_sub(1, Ordering::Relaxed);
                        return Some((task_id, task));
                    }
                }
                None
            }
            Err(_) => {
                log::error!("[EXECUTOR] Per-core tasks lock poisoned during steal - cannot steal");
                None
            }
        }
    }
}

/// Per-coreタスクストア配列
static PER_CORE_STORES: [PerCoreTaskStore; MAX_CPUS] = {
    const INIT: PerCoreTaskStore = PerCoreTaskStore::new();
    [INIT; MAX_CPUS]
};

// Legacy global task store removed — migrate to `PER_CORE_STORES` instead.

/// Wake queue（ISR-safe ロックフリー）
static WAKE_QUEUE: LockFreeQueue = LockFreeQueue::new();

/// 統計情報
static EXECUTOR_STATS: ExecutorStats = ExecutorStats::new();

/// アクティブCPU数
static ACTIVE_CPU_COUNT: AtomicUsize = AtomicUsize::new(1);

/// CPUをアクティブとして登録
pub fn register_cpu(cpu_id: usize) {
    if cpu_id < MAX_CPUS {
        PER_CORE_STORES[cpu_id]
            .active
            .store(true, Ordering::Release);
        ACTIVE_CPU_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

/// アクティブCPU数を取得
pub fn active_cpu_count() -> usize {
    ACTIVE_CPU_COUNT.load(Ordering::Relaxed)
}

/// タスクをwake queueに追加（Wakerから呼ばれる）
pub fn wake_task(task_id: TaskId) {
    WAKE_QUEUE.push(task_id);
    EXECUTOR_STATS.wakeups.fetch_add(1, Ordering::Relaxed);
}

// ============================================================================
// Executor本体
// ============================================================================

/// ロックフリー Executor
pub struct Executor {
    /// ローカルキュー（Per-CPU）
    local_queue: VecDeque<Task>,
    /// ローカルキャッシュ（高速アクセス用）
    local_cache: VecDeque<TaskId>,
    /// CPUインデックス（Work Stealing用）
    cpu_id: usize,
    /// バッチサイズ
    batch_size: usize,
}

impl Executor {
    /// 新しいExecutorを作成
    pub fn new() -> Self {
        Self::with_cpu_id(0)
    }

    /// CPU IDを指定してExecutorを作成
    pub fn with_cpu_id(cpu_id: usize) -> Self {
        Self {
            local_queue: VecDeque::with_capacity(256),
            local_cache: VecDeque::with_capacity(64),
            cpu_id,
            batch_size: 32,
        }
    }

    /// タスクをローカルキューにスケジュール
    pub fn spawn(&mut self, task: Task) {
        self.local_queue.push_back(task);
        EXECUTOR_STATS.tasks_spawned.fetch_add(1, Ordering::Relaxed);
    }

    /// グローバルキューにタスクを追加
    pub fn spawn_global(task: Task) {
        let task_id = task.id;
        // CPU 0のper-coreストアに追加（デフォルト）
        PER_CORE_STORES[0].insert(task_id, task);
        GLOBAL_QUEUE.push(task_id);
        EXECUTOR_STATS.tasks_spawned.fetch_add(1, Ordering::Relaxed);
    }

    /// 指定CPUにタスクをスポーン
    pub fn spawn_on_cpu(task: Task, cpu_id: usize) {
        let task_id = task.id;
        let target_cpu = if cpu_id < MAX_CPUS { cpu_id } else { 0 };
        crate::task::fuel::Fuel::refill(crate::task::fuel::FuelConfig::DEFAULT.default_fuel);
        PER_CORE_STORES[target_cpu].insert(task_id, task);
        GLOBAL_QUEUE.push(task_id);
        EXECUTOR_STATS.tasks_spawned.fetch_add(1, Ordering::Relaxed);
    }

    /// メインループ
    pub fn run(&mut self) -> ! {
        loop {
            // 0. Process pending interrupt events and deferred waker notifications (non-ISR)
            crate::interrupts::poll_timer_events();
            crate::io::hid::keyboard::process_pending_wakes();
            crate::task::timer::process_pending_timer_wakers();
            crate::task::interrupt_waker::process_interrupt_events();
            crate::io::io_scheduler::process_deferred_completions();
            crate::sync::process_deferred_wakes();
            crate::io::io_scheduler::hybrid_coordinator().tick(|| {
                crate::task::interrupt_waker::process_interrupt_events();
            });
            // IOMMU command queue processing
            crate::io::iommu::api::process_pending_command_queues();

            // 1. Refill fuel for this executor slice and process local tasks
            crate::task::fuel::Fuel::refill(crate::task::fuel::FuelConfig::DEFAULT.default_fuel);
            self.run_ready_tasks();

            // 2. Wake queueを処理
            self.process_wake_queue();

            // 3. グローバルキューからバッチ取得
            self.fetch_from_global();

            // 4. Work Stealing（他のCPUから盗む）
            if self.local_queue.is_empty() && self.local_cache.is_empty() {
                self.try_steal();
            }

            // 4.5. Quiescent Point (設計書 3.5.3: Epoch-based Reclamation)
            // ライブアップデートのために「安全な状態」を通知
            crate::loader::live_update::enter_quiescent_state();
            crate::loader::live_update::poll_pending_updates();
            crate::driver_cell::hot_swap::poll_validation_windows();

            // 5. アイドル状態
            if self.local_queue.is_empty() && self.local_cache.is_empty() {
                EXECUTOR_STATS.idle_cycles.fetch_add(1, Ordering::Relaxed);

                // Aggregate per-core logs and kick serial TX while idle (non-ISR context).
                // This does bounded work (AGGREGATE_MAX_PER_CALL) and avoids creating
                // extra background tasks by leveraging the executor idle path.
                crate::io::log::kick_serial_tx();

                #[cfg(feature = "qemu-test-export")]
                {
                    core::hint::spin_loop();
                    continue;
                }
                #[cfg(not(feature = "qemu-test-export"))]
                interrupts::enable_and_hlt();
            }
        }
    }

    /// ローカルキューのタスクを実行
    fn run_ready_tasks(&mut self) {
        // バッチ処理
        let mut processed = 0;

        while let Some(mut task) = self.local_queue.pop_front() {
            let waker = create_waker(task.id);
            let mut context = Context::from_waker(&waker);

            match task.poll(&mut context) {
                Poll::Ready(()) => {
                    // タスク完了
                    EXECUTOR_STATS
                        .tasks_completed
                        .fetch_add(1, Ordering::Relaxed);
                }
                Poll::Pending => {
                    // ペンディング状態のタスクをper-coreストアに保存
                    PER_CORE_STORES[self.cpu_id].insert(task.id, task);
                }
            }

            processed += 1;

            // Preemption integration: if a timer-triggered preemption is pending, force fuel exhaustion
            // so long-running tasks hit `check_fuel!()` and yield soon. Also clear the preemption flag.
            if crate::task::preemption::is_preemption_pending() {
                crate::task::fuel::Fuel::exhaust();
                crate::task::preemption::clear_preemption_pending();
                break;
            }

            // Check for explicit yield request (set by ISR / preemption handler)
            if crate::task::preemption::check_and_clear_yield_request() {
                break;
            }

            // バッチ上限で一旦中断（他の処理を許可）
            if processed >= self.batch_size {
                break;
            }
        }

        if processed > 0 {
            EXECUTOR_STATS
                .poll_cycles
                .fetch_add(processed as u64, Ordering::Relaxed);
        }
    }

    /// Wake queueを処理
    /// Search PER_CORE_STORES for a task: own core first, then others.
    /// When `check_active` is true, skip stores that are not marked active.
    fn find_task_in_stores(&self, task_id: TaskId, check_active: bool) -> Option<Task> {
        if let Some(task) = PER_CORE_STORES[self.cpu_id].remove(&task_id) {
            return Some(task);
        }
        for (cpu_id, store) in PER_CORE_STORES.iter().enumerate() {
            if cpu_id == self.cpu_id { continue; }
            if check_active && !store.active.load(Ordering::Acquire) { continue; }
            if let Some(task) = store.remove(&task_id) {
                return Some(task);
            }
        }
        None
    }

    fn process_wake_queue(&mut self) {
        // ロックフリーでWake queueを処理
        let mut woken = 0;
        while let Some(task_id) = WAKE_QUEUE.pop() {
            if let Some(task) = self.find_task_in_stores(task_id, true) {
                self.local_queue.push_back(task);
                woken += 1;
            } else {
                self.local_cache.push_back(task_id);
            }

            // バッチ上限
            if woken >= self.batch_size {
                break;
            }
        }
    }

    /// グローバルキューからタスクを取得
    fn fetch_from_global(&mut self) {
        let mut fetched = 0;
        while fetched < self.batch_size {
            if let Some(task_id) = GLOBAL_QUEUE.pop() {
                if let Some(task) = self.find_task_in_stores(task_id, false) {
                    self.local_queue.push_back(task);
                    fetched += 1;
                } else {
                    // Legacy TASK_STORE is deprecated; cache the task id for later processing.
                    self.local_cache.push_back(task_id);
                }
            } else {
                break;
            }
        }

        if fetched > 0 {
            EXECUTOR_STATS
                .global_fetches
                .fetch_add(fetched as u64, Ordering::Relaxed);
        }
    }

    /// Work Stealing: 他のCPUからタスクを盗む
    /// 【設計書 4.3】NUMA優先の3段階ワークスティーリング:
    /// 1. 同一LLC/Hyperthread siblingから
    /// 2. 同一NUMAノード内のコアから
    /// 3. 他のNUMAノードのコアから
    fn try_steal(&mut self) {
        // アクティブCPUが1つしかない場合はスキップ
        if ACTIVE_CPU_COUNT.load(Ordering::Relaxed) <= 1 {
            return;
        }

        // NUMA トポロジ情報を取得
        let numa_info = super::work_stealing_advanced::NumaTopology::get();
        let core_id = self.cpu_id as u32;
        let mut stolen = 0;

        // Phase 1: 同一LLCを共有するコア（Hyperthread sibling）からスチール
        if self.steal_from_llc_siblings(numa_info, core_id, &mut stolen) {
            return;
        }

        // Phase 2: 同一NUMAノード内の他コアからスチール
        let my_numa_node = numa_info.get_numa_node(core_id);
        if self.steal_from_numa_node_cores(numa_info, core_id, my_numa_node, true, &mut stolen) {
            return;
        }

        // Phase 3: 他のNUMAノードからスチール（最後の手段）
        for node in 0..numa_info.num_nodes() {
            if node == my_numa_node {
                continue;
            }
            if self.steal_from_numa_node_cores(numa_info, core_id, node, false, &mut stolen) {
                return;
            }
        }
    }

    /// 指定コアのストアから1タスクをスチールしてローカルキューにpush。
    /// バッチサイズ半分に達したらtrueを返す。
    fn try_steal_from_store(&mut self, target_core: u32, stolen: &mut usize) -> bool {
        if target_core as usize >= MAX_CPUS {
            return false;
        }
        let store = &PER_CORE_STORES[target_core as usize];
        if !store.active.load(Ordering::Acquire) {
            return false;
        }
        if store.len() <= 1 {
            return false;
        }
        if let Some((_, task)) = store.steal_one() {
            self.local_queue.push_back(task);
            *stolen += 1;
            EXECUTOR_STATS.steals.fetch_add(1, Ordering::Relaxed);
            return *stolen >= self.batch_size / 2;
        }
        false
    }

    /// Phase 1: LLCを共有するsiblingコアからスチール
    fn steal_from_llc_siblings(
        &mut self,
        numa_info: &super::work_stealing_advanced::NumaTopology,
        core_id: u32,
        stolen: &mut usize,
    ) -> bool {
        for &sibling_id in numa_info.get_llc_siblings(core_id) {
            if sibling_id == core_id {
                continue;
            }
            if self.try_steal_from_store(sibling_id, stolen) {
                return true;
            }
        }
        false
    }

    /// 指定NUMAノード内のコアからスチール。skip_llc=trueならLLC共有コアはスキップ。
    fn steal_from_numa_node_cores(
        &mut self,
        numa_info: &super::work_stealing_advanced::NumaTopology,
        core_id: u32,
        node: usize,
        skip_llc: bool,
        stolen: &mut usize,
    ) -> bool {
        for &target_core in numa_info.get_cores_in_node(node) {
            if target_core == core_id {
                continue;
            }
            if skip_llc && numa_info.shares_llc(core_id, target_core) {
                continue;
            }
            if self.try_steal_from_store(target_core, stolen) {
                return true;
            }
        }
        false
    }
}

impl Default for Executor {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// 統計情報
// ============================================================================

/// Executor統計
pub struct ExecutorStats {
    /// スポーンされたタスク数
    pub tasks_spawned: AtomicU64,
    /// 完了したタスク数
    pub tasks_completed: AtomicU64,
    /// Wakeup回数
    pub wakeups: AtomicU64,
    /// Pollサイクル数
    pub poll_cycles: AtomicU64,
    /// グローバルからのフェッチ数
    pub global_fetches: AtomicU64,
    /// アイドルサイクル数
    pub idle_cycles: AtomicU64,
    /// Work Stealingで盗んだタスク数
    pub steals: AtomicU64,
}
