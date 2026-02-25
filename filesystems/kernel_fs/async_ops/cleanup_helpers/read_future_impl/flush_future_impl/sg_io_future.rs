#![allow(clippy::wildcard_imports)]
use super::*;


/// Scatter-Gather I/O Future
pub struct SgIoFuture {
    request: Arc<SgIoRequest>,
}

impl SgIoFuture {
    pub(super) fn new(request: Arc<SgIoRequest>) -> Self {
        Self { request }
    }

    pub fn request_id(&self) -> u64 {
        self.request.id
    }
}

impl Future for SgIoFuture {
    type Output = FsResult<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.request.completed.load(Ordering::Acquire) {
            let result = self
                .request
                .result
                .lock()
                .take()
                .unwrap_or(Err(FsError::IoError));
            return Poll::Ready(result);
        }

        {
            let mut slot = self.request.waker.lock();
            let replace = match slot.as_ref() {
                Some(existing) => !existing.will_wake(cx.waker()),
                None => true,
            };
            if replace {
                *slot = Some(cx.waker().clone());
            }
        }

        if self.request.completed.load(Ordering::Acquire) {
            let result = self
                .request
                .result
                .lock()
                .take()
                .unwrap_or(Err(FsError::IoError));
            return Poll::Ready(result);
        }

        Poll::Pending
    }
}

pub(crate) fn sg_request_to_dma_list(request: &SgIoRequest) -> FsResult<TypedSgList<CpuOwned>> {
    let mut list = TypedSgList::new();

    for entry in &request.entries {
        if entry.len == 0 {
            return Err(FsError::InvalidArgument);
        }
        let idx = list.add_buffer(entry.len).ok_or(FsError::NoSpace)?;
        if !request.is_read {
            // Safety: caller provides valid source buffers in SgEntry.
            let src = unsafe { core::slice::from_raw_parts(entry.addr as *const u8, entry.len) };
            let dst = list
                .buffer_mut(idx)
                .ok_or(FsError::InvalidArgument)?;
            dst.as_mut_slice().copy_from_slice(src);
        }
    }

    Ok(list)
}

pub(crate) fn sg_request_copy_back(
    request: &SgIoRequest,
    list: &TypedSgList<CpuOwned>,
    bytes: usize,
) -> FsResult<()> {
    let mut remaining = bytes;

    for (idx, entry) in request.entries.iter().enumerate() {
        let src = list.buffer(idx).ok_or(FsError::InvalidArgument)?;
        let copy_len = entry.len.min(remaining);
        unsafe {
            // Safety: caller provides valid destination buffers in SgEntry.
            core::ptr::copy_nonoverlapping(
                src.as_slice().as_ptr(),
                entry.addr as *mut u8,
                copy_len,
            );
        }
        if copy_len < entry.len {
            unsafe {
                // Safety: caller provides valid destination buffers in SgEntry.
                core::ptr::write_bytes(
                    (entry.addr as *mut u8).add(copy_len),
                    0,
                    entry.len - copy_len,
                );
            }
        }
        remaining = remaining.saturating_sub(copy_len);
    }

    Ok(())
}

// ============================================================================
// I/Oスケジューラ統合
// ============================================================================

/// 非同期I/Oスケジューラ
pub struct AsyncIoScheduler {
    /// 保留中のリクエスト
    pending: Mutex<BTreeMap<u64, Arc<AsyncIoRequest>>>,
    /// 保留中のSGリクエスト
    pending_sg: Mutex<BTreeMap<u64, Arc<SgIoRequest>>>,
    /// 完了したリクエスト
    completed: Mutex<Vec<Arc<AsyncIoRequest>>>,
    /// 完了済みリクエストIDキュー
    completed_ids: Mutex<Vec<u64>>,
    /// 次のリクエストID
    next_id: AtomicU64,
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
            pending_sg: Mutex::new(BTreeMap::new()),
            completed: Mutex::new(Vec::new()),
            completed_ids: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(0),
            requests_issued: AtomicU64::new(0),
            requests_completed: AtomicU64::new(0),
        }
    }

    /// リクエストを発行
    pub fn submit(&self, request: Arc<AsyncIoRequest>) {
        self.pending.lock().insert(request.id, request);
        self.requests_issued.fetch_add(1, Ordering::Relaxed);
    }

    /// Scatter-Gatherリクエストを発行
    pub fn submit_sg_request(
        &self,
        handle: DirectBlockHandle,
        request: Arc<SgIoRequest>,
    ) -> SgIoFuture {
        let request_id = request.id;
        self.pending_sg.lock().insert(request_id, request.clone());
        self.requests_issued.fetch_add(1, Ordering::Relaxed);
        let future = SgIoFuture::new(request.clone());
        let task_request = request.clone();

        crate::task::spawn(async move {
            let result = handle.execute_sg_request(&task_request).await;
            task_request.complete(result);
            async_io_scheduler().complete_sg_request(request_id);
        });
        future
    }

    pub(super) fn complete_sg_request(&self, request_id: u64) {
        self.pending_sg.lock().remove(&request_id);
        self.requests_completed.fetch_add(1, Ordering::Relaxed);
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
            pending_count: self.pending.lock().len() + self.pending_sg.lock().len(),
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

/// リクエストIDを生成
pub(crate) fn generate_request_id() -> u64 {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

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

