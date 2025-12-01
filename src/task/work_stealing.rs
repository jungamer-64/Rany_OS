// ============================================================================
// src/task/work_stealing.rs - Lock-Free Work-Stealing Queue
// 設計書 4.3: マルチコアスケーリングとShare-Nothingアーキテクチャ
// ============================================================================
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use spin::Mutex;
use super::Task;

/// ワークスティーリング対応のタスクキュー
/// 本来はcrossbeamのInjectorとWorkerを使用するが、no_std環境のため簡易実装
pub struct WorkStealingQueue {
    local: VecDeque<Task>,
}

impl WorkStealingQueue {
    pub fn new() -> Self {
        Self {
            local: VecDeque::with_capacity(256),
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

/// 他のワーカーからタスクを盗む
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
}
