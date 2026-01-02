// ============================================================================
// src/task/work_stealing.rs - Lock-Free Work-Stealing Queue
// 設計書 4.3: マルチコアスケーリングとShare-Nothingアーキテクチャ
// ============================================================================
#![allow(dead_code)]

use super::Task;
use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use spin::Mutex;

/// ワーカーのメタデータ
/// NUMA優先スティーリングのためにCPUコアIDとNUMAノードIDを保持
#[derive(Clone, Copy, Debug)]
pub struct WorkerMetadata {
    /// このワーカーが属するCPUコアID
    pub core_id: u32,
    /// このワーカーが属するNUMAノードID
    pub numa_node: u32,
}

impl WorkerMetadata {
    pub fn new(core_id: u32, numa_node: u32) -> Self {
        Self { core_id, numa_node }
    }
}

impl Default for WorkerMetadata {
    fn default() -> Self {
        Self {
            core_id: 0,
            numa_node: 0,
        }
    }
}

/// ワークスティーリング対応のタスクキュー
/// 本来はcrossbeamのInjectorとWorkerを使用するが、no_std環境のため簡易実装
pub struct WorkStealingQueue {
    local: VecDeque<Task>,
    /// このキューのメタデータ（NUMAノード情報等）
    metadata: WorkerMetadata,
}

impl WorkStealingQueue {
    pub fn new() -> Self {
        Self {
            local: VecDeque::with_capacity(256),
            metadata: WorkerMetadata::default(),
        }
    }

    /// メタデータ付きで新しいキューを作成
    pub fn with_metadata(metadata: WorkerMetadata) -> Self {
        Self {
            local: VecDeque::with_capacity(256),
            metadata,
        }
    }

    /// ローカルキューにタスクをプッシュ
    pub fn push(&mut self, task: Task) {
        self.local.push_back(task);
    }

    /// ローカルキューからタスクをポップ（LIFO: キャッシュ効率優先）
    pub fn pop(&mut self) -> Option<Task> {
        self.local.pop_back()
    }

    /// FIFO方式でタスクを取得（他のコアからsteal用）
    pub fn steal(&mut self) -> Option<Task> {
        self.local.pop_front()
    }

    /// キューが空かどうか
    pub fn is_empty(&self) -> bool {
        self.local.is_empty()
    }

    /// キュー内のタスク数
    pub fn len(&self) -> usize {
        self.local.len()
    }

    /// メタデータを取得
    pub fn metadata(&self) -> &WorkerMetadata {
        &self.metadata
    }

    /// メタデータを設定
    pub fn set_metadata(&mut self, metadata: WorkerMetadata) {
        self.metadata = metadata;
    }
}

impl Default for WorkStealingQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// グローバルなインジェクタキュー（全コア共有）
static GLOBAL_INJECTOR: Mutex<VecDeque<Task>> = Mutex::new(VecDeque::new());

/// グローバルキューにタスクを注入
pub fn inject_global(task: Task) {
    GLOBAL_INJECTOR.lock().push_back(task);
}

/// グローバルキューからタスクを取得
pub fn steal_from_global() -> Option<Task> {
    GLOBAL_INJECTOR.lock().pop_front()
}

// ============================================================================
// 【設計書 4.3】Share-Nothingアーキテクチャに準拠したPer-Core Worker Queues
// ============================================================================
//
// 従来のArc<Mutex<Vec<Arc<Mutex<WorkStealingQueue>>>>>構造は
// Share-Nothing設計に反するため、Per-Core配列に変更。
//
// ## 設計
// - 各CPUコアは専用のWorkStealingQueueを持つ（AtomicPtrで参照）
// - スティーリングは他コアのキューからFIFOで取得
// - メタデータアクセスは読み取り専用のため、追加の同期は不要

/// 最大CPUコア数
const MAX_CORES: usize = 64;

/// Per-coreワーカーキュー（AtomicPtrで管理）
/// 
/// 【設計書 4.3】Share-Nothing準拠
/// - 各コアは自分のキューを直接操作（ロック不要）
/// - 他コアへのアクセスはスティーリング時のみ
static PER_CORE_QUEUES: [AtomicPtr<Mutex<WorkStealingQueue>>; MAX_CORES] = {
    const NULL_PTR: AtomicPtr<Mutex<WorkStealingQueue>> = AtomicPtr::new(core::ptr::null_mut());
    [NULL_PTR; MAX_CORES]
};

/// Per-coreメタデータ（読み取り専用、ロック不要）
static PER_CORE_METADATA: [spin::Once<WorkerMetadata>; MAX_CORES] = {
    const UNINIT: spin::Once<WorkerMetadata> = spin::Once::new();
    [UNINIT; MAX_CORES]
};

/// 登録済みコア数
static REGISTERED_CORE_COUNT: AtomicUsize = AtomicUsize::new(0);

/// 【新API】Per-coreワーカーキューを登録
/// 
/// 各CPUコアの初期化時に呼び出す。
pub fn register_per_core_worker(core_id: usize, queue: alloc::boxed::Box<Mutex<WorkStealingQueue>>) {
    if core_id >= MAX_CORES {
        log::warn!("[WorkStealing] Core ID {} exceeds MAX_CORES {}", core_id, MAX_CORES);
        return;
    }
    
    // キューをリークしてAtomicPtrに格納
    let queue_ptr = alloc::boxed::Box::into_raw(queue);
    PER_CORE_QUEUES[core_id].store(queue_ptr, Ordering::Release);
    
    // メタデータを設定
    let topology = super::work_stealing_advanced::NumaTopology::get();
    let numa_node = topology.get_numa_node(core_id as u32) as u32;
    PER_CORE_METADATA[core_id].call_once(|| WorkerMetadata::new(core_id as u32, numa_node));
    
    REGISTERED_CORE_COUNT.fetch_add(1, Ordering::AcqRel);
    
    log::debug!(
        "[WorkStealing] Registered per-core queue for core {} (NUMA node {})",
        core_id,
        numa_node
    );
}

/// 指定コアのキューを取得
fn get_per_core_queue(core_id: usize) -> Option<&'static Mutex<WorkStealingQueue>> {
    if core_id >= MAX_CORES {
        return None;
    }
    let ptr = PER_CORE_QUEUES[core_id].load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        // SAFETY: register_per_core_workerで有効なポインタが格納されている
        Some(unsafe { &*ptr })
    }
}

/// 指定コアのメタデータを取得
fn get_per_core_metadata(core_id: usize) -> Option<WorkerMetadata> {
    if core_id >= MAX_CORES {
        return None;
    }
    PER_CORE_METADATA[core_id].get().copied()
}



// ============================================================================
// 新API: Share-Nothing準拠のPer-Coreスティーリング
// ============================================================================

/// 【設計書 4.3】3段階NUMAアウェアなワークスティーリング（Per-Core版）
/// 
/// スティーリング優先順位:
/// 1. 同一LLCを共有するコアのキュー（キャッシュ効率最優先）
/// 2. 同一NUMAノード内のコアのキュー（メモリレイテンシ考慮）
/// 3. リモートNUMAノードのコアのキュー（最終手段）
/// 
/// # 引数
/// - `my_core_id`: 現在のCPUコアID
/// 
/// # 戻り値
/// スティールしたタスク、または None
pub fn steal_from_per_core_workers_numa_aware(my_core_id: u32) -> Option<Task> {
    let topology = super::work_stealing_advanced::NumaTopology::get();
    let my_numa_node = topology.get_numa_node(my_core_id);
    let registered_count = REGISTERED_CORE_COUNT.load(Ordering::Acquire);

    // フェーズ1: 同一LLCを共有するコアから優先的にスティール
    let llc_siblings = topology.get_llc_siblings(my_core_id);
    for &sibling_core in llc_siblings {
        if sibling_core == my_core_id {
            continue;
        }
        if let Some(queue) = get_per_core_queue(sibling_core as usize) {
            if let Some(task) = queue.lock().steal() {
                return Some(task);
            }
        }
    }

    // フェーズ2: 同一NUMAノード内のコアからスティール
    let same_node_cores = topology.get_cores_in_node(my_numa_node);
    for &core in same_node_cores {
        if core == my_core_id || llc_siblings.contains(&core) {
            continue;
        }
        if let Some(queue) = get_per_core_queue(core as usize) {
            if let Some(task) = queue.lock().steal() {
                return Some(task);
            }
        }
    }

    // フェーズ3: リモートNUMAノードからスティール（最終手段）
    for core_id in 0..registered_count.min(MAX_CORES) {
        let Some(metadata) = get_per_core_metadata(core_id) else {
            continue;
        };
        
        // 自分自身、同一NUMAノードはスキップ（既にチェック済み）
        if metadata.core_id == my_core_id || metadata.numa_node as usize == my_numa_node {
            continue;
        }
        
        if let Some(queue) = get_per_core_queue(core_id) {
            if let Some(task) = queue.lock().steal() {
                return Some(task);
            }
        }
    }

    None
}



/// 現在のコアIDに基づいてワーカーメタデータを生成
pub fn create_worker_metadata_for_current_core() -> WorkerMetadata {
    let core_id = crate::smp::current_cpu() as u32;
    let topology = super::work_stealing_advanced::NumaTopology::get();
    let numa_node = topology.get_numa_node(core_id) as u32;
    
    WorkerMetadata::new(core_id, numa_node)
}

/// スティーリング統計（デバッグ/チューニング用）
#[derive(Debug, Default, Clone, Copy)]
pub struct StealingStats {
    /// LLCシブリングからのスティール成功数
    pub llc_steals: u64,
    /// 同一NUMAノードからのスティール成功数
    pub same_numa_steals: u64,
    /// リモートNUMAノードからのスティール成功数
    pub remote_numa_steals: u64,
    /// スティール試行総数
    pub total_attempts: u64,
}

/// Per-Coreスティーリング統計（Share-Nothing準拠）
/// 各コアは自分のスロットのみアクセスするため、ロック不要
static PER_CORE_STEALING_STATS: [core::cell::UnsafeCell<StealingStats>; MAX_CORES] = {
    const INIT: core::cell::UnsafeCell<StealingStats> = core::cell::UnsafeCell::new(StealingStats {
        llc_steals: 0,
        same_numa_steals: 0,
        remote_numa_steals: 0,
        total_attempts: 0,
    });
    [INIT; MAX_CORES]
};

// SAFETY: 各コアは自分のスロットのみアクセスするため、データ競合は発生しない
unsafe impl Sync for StealingStatsWrapper {}
struct StealingStatsWrapper;

/// 現在のコアのスティーリング統計を取得
pub fn get_current_core_stealing_stats() -> StealingStats {
    let core_id = crate::smp::current_cpu();
    if core_id >= MAX_CORES {
        return StealingStats::default();
    }
    // SAFETY: 各コアは自分のスロットのみアクセス
    unsafe { *PER_CORE_STEALING_STATS[core_id].get() }
}

/// 現在のコアのスティーリング統計を更新
pub fn update_current_core_stealing_stats(updater: impl FnOnce(&mut StealingStats)) {
    let core_id = crate::smp::current_cpu();
    if core_id >= MAX_CORES {
        return;
    }
    // SAFETY: 各コアは自分のスロットのみアクセス
    unsafe {
        updater(&mut *PER_CORE_STEALING_STATS[core_id].get());
    }
}

/// 全コアのスティーリング統計を集計（デバッグ/チューニング用）
pub fn get_stealing_stats() -> StealingStats {
    let mut total = StealingStats::default();
    let count = REGISTERED_CORE_COUNT.load(Ordering::Acquire);
    for i in 0..count.min(MAX_CORES) {
        // SAFETY: 読み取り専用アクセス、集計用途
        let stats = unsafe { *PER_CORE_STEALING_STATS[i].get() };
        total.llc_steals += stats.llc_steals;
        total.same_numa_steals += stats.same_numa_steals;
        total.remote_numa_steals += stats.remote_numa_steals;
        total.total_attempts += stats.total_attempts;
    }
    total
}

/// 全コアのスティーリング統計をリセット
pub fn reset_stealing_stats() {
    let count = REGISTERED_CORE_COUNT.load(Ordering::Acquire);
    for i in 0..count.min(MAX_CORES) {
        // SAFETY: リセット操作、各コアが非アクティブ時に呼び出すことを想定
        unsafe {
            *PER_CORE_STEALING_STATS[i].get() = StealingStats::default();
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_work_stealing_queue() {
        let mut queue = WorkStealingQueue::new();

        // Push some tasks
        for _i in 0..5 {
            queue.push(Task::new(async move {
                // Test task
            }));
        }

        assert_eq!(queue.len(), 5);

        // Pop (LIFO)
        assert!(queue.pop().is_some());
        assert_eq!(queue.len(), 4);

        // Steal (FIFO)
        assert!(queue.steal().is_some());
        assert_eq!(queue.len(), 3);
    }

    #[test]
    fn test_worker_metadata() {
        let metadata = WorkerMetadata::new(2, 1);
        assert_eq!(metadata.core_id, 2);
        assert_eq!(metadata.numa_node, 1);

        let queue = WorkStealingQueue::with_metadata(metadata);
        assert_eq!(queue.metadata().core_id, 2);
        assert_eq!(queue.metadata().numa_node, 1);
    }
}
