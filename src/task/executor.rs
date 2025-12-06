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
use alloc::collections::{BTreeMap, VecDeque};
use core::sync::atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering};
use core::task::{Context, Poll};
use spin::Mutex;
use x86_64::instructions::interrupts;

// ============================================================================
// ロックフリーキュー（簡易MPMC実装）
// ============================================================================

/// ロックフリーのタスクID キュー
///
/// 実際のタスクはTASK_STOREに保存し、
/// キューはTaskIdのみを管理してオーバーヘッド削減。
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
    tasks: Mutex<BTreeMap<TaskId, Task>>,
    /// このCPUが有効かどうか
    active: AtomicBool,
    /// 保存タスク数（統計用）
    task_count: AtomicUsize,
}

impl PerCoreTaskStore {
    const fn new() -> Self {
        Self {
            tasks: Mutex::new(BTreeMap::new()),
            active: AtomicBool::new(false),
            task_count: AtomicUsize::new(0),
        }
    }

    /// タスクを追加
    fn insert(&self, task_id: TaskId, task: Task) {
        self.tasks.lock().insert(task_id, task);
        self.task_count.fetch_add(1, Ordering::Relaxed);
    }

    /// タスクを取り出し
    fn remove(&self, task_id: &TaskId) -> Option<Task> {
        let result = self.tasks.lock().remove(task_id);
        if result.is_some() {
            self.task_count.fetch_sub(1, Ordering::Relaxed);
        }
        result
    }

    /// タスク数を取得
    fn len(&self) -> usize {
        self.task_count.load(Ordering::Relaxed)
    }

    /// Work Stealing: タスクを1つ盗む
    fn steal_one(&self) -> Option<(TaskId, Task)> {
        let mut guard = self.tasks.lock();
        if let Some((&task_id, _)) = guard.iter().next() {
            if let Some(task) = guard.remove(&task_id) {
                self.task_count.fetch_sub(1, Ordering::Relaxed);
                return Some((task_id, task));
            }
        }
        None
    }
}

/// Per-coreタスクストア配列
static PER_CORE_STORES: [PerCoreTaskStore; MAX_CPUS] = {
    const INIT: PerCoreTaskStore = PerCoreTaskStore::new();
    [INIT; MAX_CPUS]
};

/// レガシー用グローバルタスクストア（後方互換性）
/// 新規コードはper-coreストアを使用すべき
static TASK_STORE: Mutex<BTreeMap<TaskId, Task>> = Mutex::new(BTreeMap::new());

/// Wake queue（ISR-safe ロックフリー）
static WAKE_QUEUE: LockFreeQueue = LockFreeQueue::new();

/// 統計情報
static EXECUTOR_STATS: ExecutorStats = ExecutorStats::new();

/// アクティブCPU数
static ACTIVE_CPU_COUNT: AtomicUsize = AtomicUsize::new(1);

/// CPUをアクティブとして登録
pub fn register_cpu(cpu_id: usize) {
    if cpu_id < MAX_CPUS {
        PER_CORE_STORES[cpu_id].active.store(true, Ordering::Release);
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
        PER_CORE_STORES[target_cpu].insert(task_id, task);
        GLOBAL_QUEUE.push(task_id);
        EXECUTOR_STATS.tasks_spawned.fetch_add(1, Ordering::Relaxed);
    }

    /// メインループ
    pub fn run(&mut self) -> ! {
        loop {
            // 1. ローカルキューのタスクを処理
            self.run_ready_tasks();

            // 2. Wake queueを処理
            self.process_wake_queue();

            // 3. グローバルキューからバッチ取得
            self.fetch_from_global();

            // 4. Work Stealing（他のCPUから盗む）
            if self.local_queue.is_empty() && self.local_cache.is_empty() {
                self.try_steal();
            }

            // 5. アイドル状態
            if self.local_queue.is_empty() && self.local_cache.is_empty() {
                EXECUTOR_STATS.idle_cycles.fetch_add(1, Ordering::Relaxed);
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
    fn process_wake_queue(&mut self) {
        // ロックフリーでWake queueを処理
        let mut woken = 0;
        while let Some(task_id) = WAKE_QUEUE.pop() {
            // まず自分のCPUのストアを探す
            if let Some(task) = PER_CORE_STORES[self.cpu_id].remove(&task_id) {
                self.local_queue.push_back(task);
                woken += 1;
            } else {
                // 他のCPUのストアを探す
                let mut found = false;
                for (cpu_id, store) in PER_CORE_STORES.iter().enumerate() {
                    if cpu_id != self.cpu_id && store.active.load(Ordering::Acquire) {
                        if let Some(task) = store.remove(&task_id) {
                            self.local_queue.push_back(task);
                            woken += 1;
                            found = true;
                            break;
                        }
                    }
                }
                // レガシーストアも探す（後方互換性）
                if !found {
                    if let Some(task) = TASK_STORE.lock().remove(&task_id) {
                        self.local_queue.push_back(task);
                        woken += 1;
                    } else {
                        // タスクが見つからない場合はローカルキャッシュに追加
                        self.local_cache.push_back(task_id);
                    }
                }
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
                // まず自分のCPUのストアを探す
                if let Some(task) = PER_CORE_STORES[self.cpu_id].remove(&task_id) {
                    self.local_queue.push_back(task);
                    fetched += 1;
                    continue;
                }
                // 他のCPUのストアを探す
                let mut found = false;
                for (cpu_id, store) in PER_CORE_STORES.iter().enumerate() {
                    if cpu_id != self.cpu_id {
                        if let Some(task) = store.remove(&task_id) {
                            self.local_queue.push_back(task);
                            fetched += 1;
                            found = true;
                            break;
                        }
                    }
                }
                // レガシーストアも探す
                if !found {
                    if let Some(task) = TASK_STORE.lock().remove(&task_id) {
                        self.local_queue.push_back(task);
                        fetched += 1;
                    }
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
    fn try_steal(&mut self) {
        // アクティブCPUが1つしかない場合はスキップ
        if ACTIVE_CPU_COUNT.load(Ordering::Relaxed) <= 1 {
            return;
        }

        // 他のCPUからタスクを盗む（ラウンドロビン）
        let start = (self.cpu_id + 1) % MAX_CPUS;
        let mut stolen = 0;

        for i in 0..MAX_CPUS {
            let target_cpu = (start + i) % MAX_CPUS;
            if target_cpu == self.cpu_id {
                continue;
            }

            let store = &PER_CORE_STORES[target_cpu];
            if !store.active.load(Ordering::Acquire) {
                continue;
            }

            // タスクが十分にある場合のみ盗む
            if store.len() > 1 {
                if let Some((_, task)) = store.steal_one() {
                    self.local_queue.push_back(task);
                    stolen += 1;
                    EXECUTOR_STATS.steals.fetch_add(1, Ordering::Relaxed);
                    
                    // バッチ上限
                    if stolen >= self.batch_size / 2 {
                        break;
                    }
                }
            }
        }
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

impl ExecutorStats {
    const fn new() -> Self {
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
