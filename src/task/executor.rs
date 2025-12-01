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
#![allow(dead_code)]

use super::{create_waker, Task, TaskId};
use alloc::collections::{BTreeMap, VecDeque};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
            if self.tail.compare_exchange_weak(
                tail,
                tail.wrapping_add(1),
                Ordering::Release,
                Ordering::Relaxed,
            ).is_ok() {
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
            if self.head.compare_exchange_weak(
                head,
                head.wrapping_add(1),
                Ordering::Release,
                Ordering::Relaxed,
            ).is_ok() {
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

/// ペンディング状態のタスクストア
static TASK_STORE: Mutex<BTreeMap<TaskId, Task>> = Mutex::new(BTreeMap::new());

/// Wake queue（ISR-safe ロックフリー）
static WAKE_QUEUE: LockFreeQueue = LockFreeQueue::new();

/// 統計情報
static EXECUTOR_STATS: ExecutorStats = ExecutorStats::new();

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
        TASK_STORE.lock().insert(task_id, task);
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
                    EXECUTOR_STATS.tasks_completed.fetch_add(1, Ordering::Relaxed);
                }
                Poll::Pending => {
                    // ペンディング状態のタスクをストアに保存
                    TASK_STORE.lock().insert(task.id, task);
                }
            }
            
            processed += 1;
            
            // バッチ上限で一旦中断（他の処理を許可）
            if processed >= self.batch_size {
                break;
            }
        }
        
        if processed > 0 {
            EXECUTOR_STATS.poll_cycles.fetch_add(processed as u64, Ordering::Relaxed);
        }
    }

    /// Wake queueを処理
    fn process_wake_queue(&mut self) {
        // ロックフリーでWake queueを処理
        let mut woken = 0;
        while let Some(task_id) = WAKE_QUEUE.pop() {
            if let Some(task) = TASK_STORE.lock().remove(&task_id) {
                self.local_queue.push_back(task);
                woken += 1;
            } else {
                // タスクが見つからない場合はローカルキャッシュに追加
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
                if let Some(task) = TASK_STORE.lock().remove(&task_id) {
                    self.local_queue.push_back(task);
                    fetched += 1;
                }
            } else {
                break;
            }
        }
        
        if fetched > 0 {
            EXECUTOR_STATS.global_fetches.fetch_add(fetched as u64, Ordering::Relaxed);
        }
    }

    /// Work Stealing: 他のCPUからタスクを盗む
    fn try_steal(&mut self) {
        // シングルコアの場合はスキップ
        // TODO: マルチコア対応時に拡張
        let _ = self.cpu_id;
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
}

/// Executor統計を取得
pub fn get_executor_stats() -> ExecutorStatsSnapshot {
    EXECUTOR_STATS.snapshot()
}
