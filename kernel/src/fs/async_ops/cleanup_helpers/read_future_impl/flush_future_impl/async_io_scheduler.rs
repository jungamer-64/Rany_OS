use super::*;

// ============================================================================
// I/Oスケジューラ統合
// ============================================================================

/// 非同期I/Oスケジューラ
pub struct AsyncIoScheduler {
    /// 保留中のリクエスト
    pending: Mutex<BTreeMap<u64, Arc<AsyncIoRequest>>>,
    /// 完了したリクエスト
    completed: Mutex<Vec<Arc<AsyncIoRequest>>>,
    /// 完了済みリクエストIDキュー
    completed_ids: Mutex<Vec<u64>>,
    /// 統計: 発行リクエスト数
    requests_issued: AtomicU64,
    /// 統計: 完了リクエスト数
    requests_completed: AtomicU64,
}

impl AsyncIoScheduler {
    /// 新しいスケジューラを作成
    pub const fn new() -> Self {
        Self {
            pending: Mutex::new(BTreeMap::new()),
            completed: Mutex::new(Vec::new()),
            completed_ids: Mutex::new(Vec::new()),
            requests_issued: AtomicU64::new(0),
            requests_completed: AtomicU64::new(0),
        }
    }

    /// リクエストを発行
    pub fn submit(&self, request: Arc<AsyncIoRequest>) {
        self.pending.lock().insert(request.id, request);
        self.requests_issued.fetch_add(1, Ordering::Relaxed);
    }

    /// 完了したリクエストを処理
    pub fn process_completions(&self) {
        let mut pending = self.pending.lock();
        let mut completed = self.completed.lock();
        let mut completed_ids = self.completed_ids.lock();

        for request_id in completed_ids.drain(..) {
            if let Some(req) = pending.remove(&request_id) {
                completed.push(req);
                self.requests_completed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// 完了したリクエストIDを登録
    pub fn mark_completed(&self, request_id: u64) {
        self.completed_ids.lock().push(request_id);
    }

    /// 統計を取得
    pub fn stats(&self) -> IoSchedulerStats {
        IoSchedulerStats {
            requests_issued: self.requests_issued.load(Ordering::Relaxed),
            requests_completed: self.requests_completed.load(Ordering::Relaxed),
            pending_count: self.pending.lock().len(),
        }
    }
}

/// I/Oスケジューラ統計
#[derive(Debug, Clone)]
pub struct IoSchedulerStats {
    pub requests_issued: u64,
    pub requests_completed: u64,
    pub pending_count: usize,
}

// ============================================================================
// ヘルパー関数
// ============================================================================

// ============================================================================
// グローバルインスタンス
// ============================================================================

/// グローバル非同期I/Oスケジューラ
pub(crate) static ASYNC_IO_SCHEDULER: AsyncIoScheduler = AsyncIoScheduler::new();

/// 非同期I/Oスケジューラを取得
pub fn async_io_scheduler() -> &'static AsyncIoScheduler {
    &ASYNC_IO_SCHEDULER
}

#[cfg(test)]
#[path = "../../../tests.rs"]
mod tests;
