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

use crate::interrupts;
use crate::mm::types::NumaNodeId;
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use boot_proto::NumaInfo;
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::{
    AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering, fence,
};
use spin::{Mutex, Once};

// ============================================================================
// Configuration
// ============================================================================

/// 最大コア数
mod scheduler_impl;
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
    fn topology_once() -> &'static spin::Once<NumaTopology> {
        static TOPOLOGY: spin::Once<NumaTopology> = spin::Once::new();
        &TOPOLOGY
    }

    /// グローバルトポロジ情報を取得
    pub fn get() -> &'static NumaTopology {
        Self::topology_once().call_once(NumaTopology::detect)
    }

    /// トポロジを検出（ACPI SRATなどから）
    fn detect() -> Self {
        let mut topology = Self::default();
        let core_count = core::cmp::min(crate::smp::cpu_count() as usize, MAX_CORES);
        topology.num_cores = core_count;
        topology.num_nodes = 1;

        for i in 0..core_count {
            topology.core_to_node[i] = 0;
            topology.node_cores[0].push(i as u32);
            topology.llc_siblings[i].push(i as u32);
        }

        topology
    }

    fn from_boot_info(numa_info: &NumaInfo) -> Self {
        let core_count = core::cmp::min(crate::smp::cpu_count() as usize, MAX_CORES);
        Self::from_boot_info_with_core_count(numa_info, core_count)
    }

    fn from_boot_info_with_core_count(numa_info: &NumaInfo, core_count: usize) -> Self {
        let node_count = (numa_info.node_count as usize).min(MAX_NUMA_NODES);
        if node_count == 0 {
            return Self::detect();
        }

        let core_count = core::cmp::min(core_count, MAX_CORES);
        let mut topology = Self::default();
        let mut assigned = [false; MAX_CORES];
        topology.num_nodes = node_count.max(1);
        topology.num_cores = core_count.max(1);

        for node_idx in 0..node_count {
            let node = &numa_info.nodes[node_idx];

            for apic_id in 0..128u32 {
                let present = if apic_id < 64 {
                    (node.cpu_apic_mask_low & (1u64 << apic_id)) != 0
                } else {
                    (node.cpu_apic_mask_high & (1u64 << (apic_id - 64))) != 0
                };
                if !present {
                    continue;
                }

                let Some(cpu_id) = crate::smp::cpu_for_apic_id(apic_id) else {
                    continue;
                };
                if cpu_id >= core_count || cpu_id >= MAX_CORES || assigned[cpu_id] {
                    continue;
                }

                topology.core_to_node[cpu_id] = node_idx as u8;
                topology.node_cores[node_idx].push(cpu_id as u32);
                topology.llc_siblings[cpu_id].push(cpu_id as u32);
                assigned[cpu_id] = true;
            }
        }

        if topology
            .node_cores
            .iter()
            .take(node_count)
            .all(|cores| cores.is_empty())
        {
            return Self::detect();
        }

        for cpu_id in 0..core_count {
            if assigned[cpu_id] {
                continue;
            }
            topology.core_to_node[cpu_id] = 0;
            topology.node_cores[0].push(cpu_id as u32);
            topology.llc_siblings[cpu_id].push(cpu_id as u32);
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

    pub fn steal_candidates_for(&self, core_id: u32) -> Vec<u32> {
        let mut order = Vec::new();
        let my_node = self.get_numa_node(core_id);

        for &candidate in self.get_llc_siblings(core_id) {
            if candidate != core_id && !order.contains(&candidate) {
                order.push(candidate);
            }
        }

        for &candidate in self.get_cores_in_node(my_node) {
            if candidate == core_id
                || self.shares_llc(core_id, candidate)
                || order.contains(&candidate)
            {
                continue;
            }
            order.push(candidate);
        }

        for node in 0..self.num_nodes() {
            if node == my_node {
                continue;
            }
            for &candidate in self.get_cores_in_node(node) {
                if candidate != core_id && !order.contains(&candidate) {
                    order.push(candidate);
                }
            }
        }

        order
    }
}

pub fn configure_from_boot_info(numa_info: &NumaInfo) {
    let topology =
        NumaTopology::topology_once().call_once(|| NumaTopology::from_boot_info(numa_info));
    crate::mm::numa::topology::update_numa_node_count(topology.num_nodes());
    for cpu_id in 0..topology.num_cores().min(crate::per_cpu::MAX_CPUS) {
        crate::mm::numa::topology::set_cpu_to_node(
            cpu_id,
            topology.get_numa_node(cpu_id as u32) as u8,
        );
    }
}

pub fn configure_current_cpu_locality() {
    let Some(cpu_id) = crate::per_cpu::try_current_cpu_id() else {
        return;
    };

    let topology = NumaTopology::get();
    let local_node = NumaNodeId::new(topology.get_numa_node(cpu_id as u32) as u8);
    let mut sorted_nodes = [NumaNodeId::new(0); crate::mm::numa::topology::MAX_NUMA_NODES];
    let mut count = 0usize;

    sorted_nodes[count] = local_node;
    count += 1;

    for node_idx in 0..topology.num_nodes() {
        let node = NumaNodeId::new(node_idx as u8);
        if node == local_node {
            continue;
        }
        if count >= sorted_nodes.len() {
            break;
        }
        sorted_nodes[count] = node;
        count += 1;
    }

    unsafe {
        if let Some(hot) = crate::per_cpu::current_per_cpu_hot_mut() {
            let cold = hot.cold_mut();
            cold.setup_numa_zonelist(local_node, &sorted_nodes, count);
            cold.pt_magazine.set_preferred_node(local_node.as_u8());
        }

        if let Some(legacy) = crate::per_cpu::current_per_cpu_mut() {
            legacy.setup_numa_zonelist(local_node, &sorted_nodes, count);
            legacy.pt_magazine.set_preferred_node(local_node.as_u8());
        }
    }

    crate::mm::numa::topology::set_cpu_to_node(cpu_id, local_node.as_u8());
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test_case]
    fn boot_info_topology_uses_registered_apic_mappings() {
        crate::smp::reset_cpu_routing_for_tests();
        crate::smp::register_cpu_apic_mapping(0, 2);
        crate::smp::register_cpu_apic_mapping(1, 41);
        crate::smp::register_cpu_apic_mapping(2, 99);

        let mut info = NumaInfo {
            node_count: 2,
            ..Default::default()
        };
        info.nodes[0].cpu_apic_mask_low = (1u64 << 2) | (1u64 << 41);
        info.nodes[1].cpu_apic_mask_high = 1u64 << (99 - 64);

        let topology = NumaTopology::from_boot_info_with_core_count(&info, 3);

        assert_eq!(topology.num_nodes(), 2);
        assert_eq!(topology.num_cores(), 3);
        assert_eq!(topology.get_numa_node(0), 0);
        assert_eq!(topology.get_numa_node(1), 0);
        assert_eq!(topology.get_numa_node(2), 1);
        assert_eq!(topology.get_cores_in_node(0), &[0, 1]);
        assert_eq!(topology.get_cores_in_node(1), &[2]);
    }

    #[test_case]
    fn steal_candidates_prioritize_llc_then_local_then_remote() {
        let mut topology = NumaTopology::default();
        topology.num_nodes = 2;
        topology.num_cores = 4;
        topology.core_to_node[0] = 0;
        topology.core_to_node[1] = 0;
        topology.core_to_node[2] = 0;
        topology.core_to_node[3] = 1;
        topology.node_cores[0] = vec![0, 1, 2];
        topology.node_cores[1] = vec![3];
        topology.llc_siblings[0] = vec![0, 1];
        topology.llc_siblings[1] = vec![1, 0];
        topology.llc_siblings[2] = vec![2];
        topology.llc_siblings[3] = vec![3];

        assert_eq!(topology.steal_candidates_for(0), vec![1, 2, 3]);
        assert_eq!(topology.steal_candidates_for(3), vec![0, 1, 2]);
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
        if !self
            .top
            .compare_exchange(t, t.wrapping_add(1), Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
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

            if !self
                .top
                .compare_exchange(t, t.wrapping_add(1), Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
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
        interrupts::without_interrupts(|| unsafe { (*self.local_queue.get()).push(task) })
    }

    /// タスクをポップ
    pub fn pop_task(&self) -> Option<Box<StealableTask>> {
        // SAFETY: Only called by owner, interrupt suppressed
        interrupts::without_interrupts(|| unsafe { (*self.local_queue.get()).pop() })
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
