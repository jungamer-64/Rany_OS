// ============================================================================
// src/task/work_stealing.rs - Lock-Free Work-Stealing Queue
// 設計書 4.3: マルチコアスケーリングとShare-Nothingアーキテクチャ
// ============================================================================
#![allow(dead_code)]

use super::Task;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
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

/// 他のワーカーのキューへの参照（マルチコア対応）
/// 注意: 本実装はシングルコアの簡易版。将来的にはper-core配列に拡張
static WORKER_QUEUES: Mutex<alloc::vec::Vec<Arc<Mutex<WorkStealingQueue>>>> =
    Mutex::new(alloc::vec::Vec::new());

/// ワーカーキューを登録
pub fn register_worker(queue: Arc<Mutex<WorkStealingQueue>>) {
    WORKER_QUEUES.lock().push(queue);
}

/// ワーカーキューをメタデータ付きで登録
pub fn register_worker_with_metadata(
    queue: Arc<Mutex<WorkStealingQueue>>,
    metadata: WorkerMetadata,
) {
    if let Some(mut q) = queue.try_lock() {
        q.set_metadata(metadata);
    }
    WORKER_QUEUES.lock().push(queue);
}

/// 他のワーカーからタスクを盗む（旧API: 互換性のため維持）
/// 
/// 注意: この関数はNUMAを考慮しない単純なラウンドロビン。
/// 新しいコードでは `steal_from_workers_numa_aware()` を使用してください。
pub fn steal_from_workers(my_index: usize) -> Option<Task> {
    let workers = WORKER_QUEUES.lock();

    // ラウンドロビンで他のワーカーを探索
    for (i, worker) in workers.iter().enumerate() {
        if i == my_index {
            continue; // 自分自身はスキップ
        }

        if let Some(task) = worker.lock().steal() {
            return Some(task);
        }
    }

    None
}

/// 【設計書 4.3】3段階NUMAアウェアなワークスティーリング
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
pub fn steal_from_workers_numa_aware(my_core_id: u32) -> Option<Task> {
    let topology = super::work_stealing_advanced::NumaTopology::get();
    let my_numa_node = topology.get_numa_node(my_core_id);
    let workers = WORKER_QUEUES.lock();

    // フェーズ1: 同一LLCを共有するコアから優先的にスティール
    let llc_siblings = topology.get_llc_siblings(my_core_id);
    for (i, worker) in workers.iter().enumerate() {
        let worker_guard = worker.lock();
        let worker_core = worker_guard.metadata().core_id;
        
        // 自分自身はスキップ
        if worker_core == my_core_id {
            continue;
        }
        
        // LLC共有コアをチェック
        if llc_siblings.contains(&worker_core) {
            drop(worker_guard);
            if let Some(task) = worker.lock().steal() {
                return Some(task);
            }
        }
    }

    // フェーズ2: 同一NUMAノード内のコアからスティール
    let same_node_cores = topology.get_cores_in_node(my_numa_node);
    for (i, worker) in workers.iter().enumerate() {
        let worker_guard = worker.lock();
        let worker_core = worker_guard.metadata().core_id;
        let worker_node = worker_guard.metadata().numa_node as usize;
        
        // 自分自身、既にチェックしたLLCシブリングはスキップ
        if worker_core == my_core_id || llc_siblings.contains(&worker_core) {
            continue;
        }
        
        // 同一NUMAノードをチェック
        if worker_node == my_numa_node {
            drop(worker_guard);
            if let Some(task) = worker.lock().steal() {
                return Some(task);
            }
        }
    }

    // フェーズ3: リモートNUMAノードからスティール（最終手段）
    for (i, worker) in workers.iter().enumerate() {
        let worker_guard = worker.lock();
        let worker_core = worker_guard.metadata().core_id;
        let worker_node = worker_guard.metadata().numa_node as usize;
        
        // 自分自身、同一NUMAノードはスキップ（既にチェック済み）
        if worker_core == my_core_id || worker_node == my_numa_node {
            continue;
        }
        
        drop(worker_guard);
        if let Some(task) = worker.lock().steal() {
            return Some(task);
        }
    }

    None
}

/// 現在のコアIDに基づいてワーカーメタデータを生成
pub fn create_worker_metadata_for_current_core() -> WorkerMetadata {
    let core_id = crate::smp::current_cpu_id() as u32;
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

/// Per-coreスティーリング統計
/// 注意: 実際の使用にはper-core配列が必要（現在は単一統計）
static STEALING_STATS: Mutex<StealingStats> = Mutex::new(StealingStats {
    llc_steals: 0,
    same_numa_steals: 0,
    remote_numa_steals: 0,
    total_attempts: 0,
});

/// スティーリング統計を取得
pub fn get_stealing_stats() -> StealingStats {
    *STEALING_STATS.lock()
}

/// スティーリング統計をリセット
pub fn reset_stealing_stats() {
    *STEALING_STATS.lock() = StealingStats::default();
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
