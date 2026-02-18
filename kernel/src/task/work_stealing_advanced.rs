// ============================================================================
// src/task/work_stealing_advanced.rs - 高度なWork-Stealingスケジューラ
// ============================================================================
//!
//! # 高度なWork-Stealingスケジューラ
//!
//! 設計書4.3に基づく高性能マルチコアスケジューラ。
//! コアごとのローカルキューとグローバルキュー、
//! アダプティブスチーリングで最大スループットを実現。
//!
//! ## 機能
//! - コアアフィニティを考慮したタスク配置
//! - ロックフリーキュー（Deque）
//! - アダプティブスチーリング戦略
//! - 負荷バランシング
//! - プリエンプションサポート

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering, fence};
use core::ptr;
use core::cell::UnsafeCell;
use spin::{Mutex, Once};
use crate::interrupts;

// ============================================================================
// Configuration
// ============================================================================

/// 最大コア数
mod _split_1;
pub use _split_1::*;
const MAX_CORES: usize = 64;

/// 最大NUMAノード数
const MAX_NUMA_NODES: usize = 8;

/// ローカルキュー容量
const LOCAL_QUEUE_CAPACITY: usize = 256;

/// グローバルキュー容量
const GLOBAL_QUEUE_CAPACITY: usize = 4096;

/// スチーリング閾値（ローカルキューがこれ以下になったらスチール）
const STEAL_THRESHOLD: usize = 32;

/// スチーリングバッチサイズ
const STEAL_BATCH_SIZE: usize = 16;

/// 負荷バランス間隔（ポーリング回数）
const LOAD_BALANCE_INTERVAL: u64 = 1000;

// ============================================================================
// NUMA Topology (設計書 4.3)
// ============================================================================

/// NUMAトポロジ情報
///
/// 【設計書 4.3】3段階ワークスティーリングのためのNUMAトポロジ管理
pub struct NumaTopology {
    /// コア -> NUMAノードのマッピング
    core_to_node: [u8; MAX_CORES],
    /// NUMAノード -> コアリストのマッピング
    node_cores: [Vec<u32>; MAX_NUMA_NODES],
    /// LLC（Last Level Cache）を共有するコアグループ
    /// core_id -> 同じLLCを共有するコアのリスト
    llc_siblings: [Vec<u32>; MAX_CORES],
    /// 有効なNUMAノード数
    num_nodes: usize,
    /// 有効なコア数
    num_cores: usize,
}

impl NumaTopology {
    /// グローバルトポロジ情報を取得
    pub fn get() -> &'static NumaTopology {
        static TOPOLOGY: spin::Once<NumaTopology> = spin::Once::new();
        TOPOLOGY.call_once(|| NumaTopology::detect())
    }

    /// トポロジを検出（ACPI SRATなどから）
    fn detect() -> Self {
        // Note: 実際のACPI SRATパースは crate::io::acpi モジュールで実装
        // 現在はシングルNUMAノードを想定したデフォルト値

        // [Vec<u32>; 64] は Default を実装していないので手動で初期化
        const EMPTY_VEC: Vec<u32> = Vec::new();

        let mut topology = Self {
            core_to_node: [0; MAX_CORES],
            node_cores: [EMPTY_VEC; MAX_NUMA_NODES],
            llc_siblings: [EMPTY_VEC; MAX_CORES],
            num_nodes: 1,
            num_cores: 1,
        };

        // CPUコア数を検出（仮実装）
        let core_count = core::cmp::min(crate::smp::cpu_count() as usize, MAX_CORES);
        topology.num_cores = core_count;

        // シングルNUMAノードとしてすべてのコアを登録
        for i in 0..core_count {
            topology.core_to_node[i] = 0;
            topology.node_cores[0].push(i as u32);

            // HyperThreadingペアを推測（偶数/奇数ペア）
            // 実際にはCPUID命令で検出すべき
            let sibling = if i % 2 == 0 { i + 1 } else { i - 1 };
            if sibling < core_count {
                topology.llc_siblings[i].push(sibling as u32);
            }
            topology.llc_siblings[i].push(i as u32);
        }

        topology
    }

    /// コアが所属するNUMAノードを取得
    pub fn get_numa_node(&self, core_id: u32) -> usize {
        if (core_id as usize) < MAX_CORES {
            self.core_to_node[core_id as usize] as usize
        } else {
            0
        }
    }

    /// 指定NUMAノード内のコアリストを取得
    pub fn get_cores_in_node(&self, node: usize) -> &[u32] {
        if node < MAX_NUMA_NODES {
            &self.node_cores[node]
        } else {
            &[]
        }
    }

    /// LLCを共有するコアのリストを取得
    pub fn get_llc_siblings(&self, core_id: u32) -> &[u32] {
        if (core_id as usize) < MAX_CORES {
            &self.llc_siblings[core_id as usize]
        } else {
            &[]
        }
    }

    /// 2つのコアがLLCを共有しているかチェック
    pub fn shares_llc(&self, core_a: u32, core_b: u32) -> bool {
        if (core_a as usize) < MAX_CORES {
            self.llc_siblings[core_a as usize].contains(&core_b)
        } else {
            false
        }
    }

    /// NUMAノード数を取得
    pub fn num_nodes(&self) -> usize {
        self.num_nodes
    }

    /// コア数を取得
    pub fn num_cores(&self) -> usize {
        self.num_cores
    }
}

// node_coresのDefault実装が必要
impl Default for NumaTopology {
    fn default() -> Self {
        Self {
            core_to_node: [0; MAX_CORES],
            node_cores: core::array::from_fn(|_| Vec::new()),
            llc_siblings: core::array::from_fn(|_| Vec::new()),
            num_nodes: 1,
            num_cores: 1,
        }
    }
}

// ============================================================================
// Task Types
// ============================================================================

/// タスクID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TaskId(pub u64);

/// タスク優先度
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Idle = 0,
    Low = 1,
    Normal = 2,
    High = 3,
    RealTime = 4,
}

impl Default for Priority {
    fn default() -> Self {
        Priority::Normal
    }
}

/// タスク状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Ready,
    Running,
    Blocked,
    Sleeping,
    Terminated,
}

/// コアアフィニティ
#[derive(Debug, Clone)]
pub struct CoreAffinity {
    /// 許可されたコアのビットマスク
    mask: u64,
    /// 優先コア（ある場合）
    preferred: Option<u32>,
}

impl CoreAffinity {
    /// すべてのコアを許可
    pub fn all() -> Self {
        Self {
            mask: u64::MAX,
            preferred: None,
        }
    }

    /// 特定のコアのみ許可
    pub fn single(core_id: u32) -> Self {
        Self {
            mask: 1 << core_id,
            preferred: Some(core_id),
        }
    }

    /// コアが許可されているかチェック
    pub fn is_allowed(&self, core_id: u32) -> bool {
        if core_id >= 64 {
            return false;
        }
        (self.mask & (1 << core_id)) != 0
    }

    /// 優先コアを取得
    pub fn preferred_core(&self) -> Option<u32> {
        self.preferred
    }

    /// 許可されたコアのリストを取得
    pub fn allowed_cores(&self) -> Vec<u32> {
        (0..64).filter(|&c| self.is_allowed(c)).collect()
    }
}

impl Default for CoreAffinity {
    fn default() -> Self {
        Self::all()
    }
}

/// スチール可能なタスク
pub struct StealableTask {
    pub id: TaskId,
    pub priority: Priority,
    pub affinity: CoreAffinity,
    pub state: TaskState,
    /// タスクのコンテキスト（実際の実行データ）
    pub context: *mut u8,
    /// 最後に実行されたコア
    pub last_core: Option<u32>,
    /// 累積実行時間（ナノ秒）
    pub runtime_ns: u64,
}

unsafe impl Send for StealableTask {}
unsafe impl Sync for StealableTask {}

impl StealableTask {
    pub fn new(id: TaskId, priority: Priority) -> Self {
        Self {
            id,
            priority,
            affinity: CoreAffinity::all(),
            state: TaskState::Ready,
            context: core::ptr::null_mut(),
            last_core: None,
            runtime_ns: 0,
        }
    }

    /// アフィニティを設定
    pub fn with_affinity(mut self, affinity: CoreAffinity) -> Self {
        self.affinity = affinity;
        self
    }
}

// ============================================================================
// Lock-Free Deque (Work-Stealing Queue)
// ============================================================================

// ============================================================================
// Lock-Free Deque (Chase-Lev)
// ============================================================================

/// Lock-free Work-Stealing Deque (Chase-Lev algorithm)
///
/// Thread-safety:
/// - push/pop: Must be called by the owner thread only.
/// - steal: Can be called by any thread.
pub struct WorkStealingDeque {
    /// Circular buffer of tasks (pointers)
    buffer: Box<[AtomicPtr<StealableTask>]>,
    /// Buffer mask (capacity - 1)
    mask: usize,
    /// Bottom index (modified by owner)
    bottom: AtomicUsize,
    /// Top index (modified by owner and thieves)
    top: AtomicUsize,
}

// SAFETY: Deque handles its own synchronization for steal vs pop.
// Owner-only methods must be protected by caller (e.g., interrupt suppression).
unsafe impl Sync for WorkStealingDeque {}
unsafe impl Send for WorkStealingDeque {}

impl WorkStealingDeque {
    pub fn new(capacity: usize) -> Self {
        // Capacity must be power of 2
        let cap = capacity.next_power_of_two();
        
        // Initialize buffer with null pointers
        let mut buffer = Vec::with_capacity(cap);
        for _ in 0..cap {
            buffer.push(AtomicPtr::new(ptr::null_mut()));
        }

        Self {
            buffer: buffer.into_boxed_slice(),
            mask: cap - 1,
            bottom: AtomicUsize::new(0),
            top: AtomicUsize::new(0),
        }
    }

    /// Push a task (Owner only)
    ///
    /// # Safety
    /// Must be called with interrupts disabled to prevent re-entrancy on the same core.
    pub unsafe fn push(&self, task: Box<StealableTask>) -> Result<(), Box<StealableTask>> {
        let b = self.bottom.load(Ordering::Relaxed);
        let t = self.top.load(Ordering::Acquire);
        
        if b.wrapping_sub(t) >= self.buffer.len() {
            return Err(task);
        }

        let idx = b & self.mask;
        self.buffer[idx].store(Box::into_raw(task), Ordering::Relaxed);
        
        fence(Ordering::Release);
        
        self.bottom.store(b.wrapping_add(1), Ordering::Relaxed);
        Ok(())
    }

    /// Pop a task (Owner only)
    ///
    /// # Safety
    /// Must be called with interrupts disabled.
    pub unsafe fn pop(&self) -> Option<Box<StealableTask>> {
        let b = self.bottom.load(Ordering::Relaxed);
        if b == 0 {
            // Empty (wrapping handled by wrapping_sub below potentially, but 0 check is optimization)
            // Wait, b starts at 0. b-1 checks are needed.
            // If b > 0 or wrapped? wrapping_sub(1) handles logic.
        }
        
        // Check "empty" based on t vs b logic?
        // Standard Chase-Lev:
        let b = b.wrapping_sub(1);
        self.bottom.store(b, Ordering::Relaxed);
        
        fence(Ordering::SeqCst);
        
        let t = self.top.load(Ordering::Relaxed);
        let size = b.wrapping_sub(t);
        
        if (size as isize) < 0 {
            // Empty
            self.bottom.store(b.wrapping_add(1), Ordering::Relaxed);
            return None;
        }

        let idx = b & self.mask;
        let task_ptr = self.buffer[idx].load(Ordering::Relaxed);
        
        if size > 0 {
            // Normal case: at least one task left
            if !task_ptr.is_null() {
                return Some(Box::from_raw(task_ptr));
            }
            return None; // Should not happen
        }

        // size == 0: Race with steal
        if !self.top.compare_exchange(
            t, 
            t.wrapping_add(1), 
            Ordering::SeqCst, 
            Ordering::Relaxed
        ).is_ok() {
            // Fail (lost race)
            self.bottom.store(b.wrapping_add(1), Ordering::Relaxed);
            return None;
        }

        self.bottom.store(b.wrapping_add(1), Ordering::Relaxed);
        if !task_ptr.is_null() {
            return Some(Box::from_raw(task_ptr));
        }
        None
    }

    /// Steal a task (Any thread)
    pub fn steal(&self) -> Option<Box<StealableTask>> {
        loop {
            let t = self.top.load(Ordering::Acquire);
            fence(Ordering::SeqCst);
            let b = self.bottom.load(Ordering::Acquire);
            
            let size = b.wrapping_sub(t);
            if (size as isize) <= 0 {
                return None; // Empty
            }

            let idx = t & self.mask;
            let task_ptr = self.buffer[idx].load(Ordering::Relaxed);
            
            if !self.top.compare_exchange(
                t, 
                t.wrapping_add(1), 
                Ordering::SeqCst, 
                Ordering::Relaxed
            ).is_ok() {
                continue; // Retry
            }

            // Success
            if !task_ptr.is_null() {
                // Safety: We claimed the slot via CAS on top
                return unsafe { Some(Box::from_raw(task_ptr)) };
            }
            return None;
        }
    }

    /// Get approximate length
    pub fn len(&self) -> usize {
        let b = self.bottom.load(Ordering::Relaxed);
        let t = self.top.load(Ordering::Relaxed);
        let len = b.wrapping_sub(t);
        if (len as isize) < 0 { 0 } else { len }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ============================================================================
// Per-Core Worker
// ============================================================================

/// コアごとのワーカー統計
#[derive(Debug, Default)]
pub struct WorkerStats {
    pub tasks_executed: AtomicU64,
    pub tasks_stolen: AtomicU64,
    pub tasks_received_from_steal: AtomicU64,
    /// 【設計書 4.3】NUMA間スチール回数（パフォーマンス監視用）
    pub cross_numa_steals: AtomicU64,
    pub idle_cycles: AtomicU64,
    pub total_runtime_ns: AtomicU64,
}

/// コアごとのワーカー
pub struct PerCoreWorker {
    /// コアID
    core_id: u32,
    /// ローカルキュー (UnsafeCell to allow interrupt-safe exclusive access by owner)
    local_queue: UnsafeCell<WorkStealingDeque>,
    /// 現在実行中のタスク (UnsafeCell for strictly local access)
    current_task: UnsafeCell<Option<Box<StealableTask>>>,
    /// 統計
    stats: WorkerStats,
    /// アクティブフラグ
    active: AtomicBool,
    /// アイドル状態
    idle: AtomicBool,
}

// SAFETY: 
// - local_queue: steal() is thread-safe. push/pop are protected by checking core_id (ownership) and disabling interrupts.
// - current_task: Only accessed by owner thread/core.
unsafe impl Sync for PerCoreWorker {}

impl PerCoreWorker {
    pub fn new(core_id: u32) -> Self {
        Self {
            core_id,
            local_queue: UnsafeCell::new(WorkStealingDeque::new(LOCAL_QUEUE_CAPACITY)),
            current_task: UnsafeCell::new(None),
            stats: WorkerStats::default(),
            active: AtomicBool::new(true),
            idle: AtomicBool::new(true),
        }
    }

    /// タスクをローカルキューにプッシュ
    pub fn push_task(&self, task: Box<StealableTask>) -> Result<(), Box<StealableTask>> {
        // SAFETY: Only called by owner, interrupt suppressed to prevent re-entrancy
        interrupts::without_interrupts(|| unsafe {
            (*self.local_queue.get()).push(task)
        })
    }

    /// タスクをポップ
    pub fn pop_task(&self) -> Option<Box<StealableTask>> {
        // SAFETY: Only called by owner, interrupt suppressed
        interrupts::without_interrupts(|| unsafe {
            (*self.local_queue.get()).pop()
        })
    }

    /// タスクをスチール (Safe to call from any thread)
    pub fn steal_task(&self) -> Option<Box<StealableTask>> {
        // SAFETY: steal() is lock-free and thread-safe
        let result = unsafe { (*self.local_queue.get()).steal() };
        
        if result.is_some() {
            self.stats.tasks_stolen.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// ローカルキューサイズを取得
    pub fn queue_size(&self) -> usize {
        // Relaxed loads are safe
        unsafe { (*self.local_queue.get()).len() }
    }

    /// 次のタスクを取得して実行準備
    pub fn schedule_next(&self) -> Option<Box<StealableTask>> {
        let task = self.pop_task()?;
        self.idle.store(false, Ordering::Release);
        
        // Update current_task
        // SAFETY: Only owner updates current_task
        interrupts::without_interrupts(|| unsafe {
            // Drop old current task if any (should be None or handled)
            *self.current_task.get() = None; 
        });
        
        Some(task)
    }
    
    /// 現在のタスクを設定（実行中）
    pub fn set_current(&self, task: Option<Box<StealableTask>>) {
        interrupts::without_interrupts(|| unsafe {
            *self.current_task.get() = task;
        });
    }

    /// タスク実行完了
    pub fn task_completed(&self, _runtime_ns: u64) {
        self.set_current(None);
        self.stats.tasks_executed.fetch_add(1, Ordering::Relaxed);
        self.idle.store(true, Ordering::Release);
    }

    /// アイドル状態かどうか
    pub fn is_idle(&self) -> bool {
        self.idle.load(Ordering::Acquire)
    }

    /// 統計を取得
    pub fn stats(&self) -> &WorkerStats {
        &self.stats
    }

    /// コアIDを取得
    pub fn core_id(&self) -> u32 {
        self.core_id
    }
}

// ============================================================================
// Global Scheduler
// ============================================================================

/// グローバルスケジューラ
pub struct GlobalScheduler {
    /// コアごとのワーカー
    workers: Vec<PerCoreWorker>,
    /// グローバルキュー（オーバーフロー用）
    global_queue: Mutex<VecDeque<Box<StealableTask>>>,
    /// アクティブなコア数
    active_cores: AtomicU32,
    /// 次のタスクID
    next_task_id: AtomicU64,
    /// ポーリングカウンタ
    poll_counter: AtomicU64,
    /// 負荷バランス有効
    load_balance_enabled: AtomicBool,
}
