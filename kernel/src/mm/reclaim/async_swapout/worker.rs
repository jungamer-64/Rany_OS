use super::{
    SwapError, SwapHandle, SwapKind, atomic_saturating_decrement, buffer_pool_get_4k,
    buffer_pool_put_4k, release_frame_and_untrack, try_zswap_store_and_dealloc_any,
};
use crate::mm::types::FrameIndex;

mod enqueue;
pub use enqueue::*;
mod kernel_worker;
use kernel_worker::*;

const ENQUEUE_OVERRIDE_NONE: usize = 0;
const ENQUEUE_OVERRIDE_ALREADY_PENDING: usize = 1;
const ENQUEUE_OVERRIDE_QUEUE_FULL: usize = 2;
const ENQUEUE_OVERRIDE_NOT_SUPPORTED: usize = 3;

#[cfg(test)]
static TEST_ENQUEUE_OVERRIDE: AtomicUsize = AtomicUsize::new(ENQUEUE_OVERRIDE_NONE);
#[cfg(feature = "qemu-test-export")]
static QEMU_TEST_ENQUEUE_OVERRIDE: AtomicUsize = AtomicUsize::new(ENQUEUE_OVERRIDE_NONE);

fn encode_test_enqueue_override(value: Option<SwapError>) -> usize {
    match value {
        None => ENQUEUE_OVERRIDE_NONE,
        Some(SwapError::AlreadyPending) => ENQUEUE_OVERRIDE_ALREADY_PENDING,
        Some(SwapError::QueueFull) => ENQUEUE_OVERRIDE_QUEUE_FULL,
        Some(SwapError::NotSupported) => ENQUEUE_OVERRIDE_NOT_SUPPORTED,
    }
}

fn decode_test_enqueue_override(value: usize) -> Option<SwapError> {
    match value {
        ENQUEUE_OVERRIDE_NONE => None,
        ENQUEUE_OVERRIDE_ALREADY_PENDING => Some(SwapError::AlreadyPending),
        ENQUEUE_OVERRIDE_QUEUE_FULL => Some(SwapError::QueueFull),
        ENQUEUE_OVERRIDE_NOT_SUPPORTED => Some(SwapError::NotSupported),
        _ => None,
    }
}
#[cfg(all(test, feature = "std"))]
mod test_impl {
    use super::*;
    use alloc::collections::BTreeSet;
    use alloc::sync::Arc;
    use spin::Once;
    use std::collections::VecDeque;
    use std::sync::{Condvar, Mutex as StdMutex};
    use std::thread;

    /// キュー容量／バッチサイズはテスト向けに控えめに設定可能
    pub(super) const QUEUE_CAPACITY: usize = 64;
    pub(super) const BATCH_SIZE: usize = 8;

    use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

    pub(super) static TEST_FILE_QUEUE_COUNT: AtomicUsize = AtomicUsize::new(0);
    pub(super) static TEST_PROCESSING_DELAY_MS: AtomicU64 = AtomicU64::new(0);
    pub(super) static TEST_WORKER_RUNNING: AtomicBool = AtomicBool::new(false);
    pub(super) static TEST_WORKER_SHUTDOWN: AtomicBool = AtomicBool::new(false);
    // Test diagnostics
    pub(super) static TEST_DEALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
    pub(super) static TEST_ZSWAP_FAILS: AtomicUsize = AtomicUsize::new(0);

    // Token-bucket backpressure (test)
    pub(super) const TEST_TOKEN_CAPACITY: usize = QUEUE_CAPACITY / 4; // burst capacity for anon entries
    pub(super) const TEST_REFILL_PER_BATCH: usize = BATCH_SIZE / 2; // tokens added per processed batch

    // Allow dynamic test-time override of token capacity and reserved slots
    pub(super) static TEST_TOKEN_CAPACITY_DYNAMIC: AtomicUsize =
        AtomicUsize::new(TEST_TOKEN_CAPACITY);
    pub(super) static TEST_TOKENS: AtomicUsize = AtomicUsize::new(TEST_TOKEN_CAPACITY);

    // Dynamic reserved file slots
    pub(super) const RESERVED_FILE_SLOTS_TEST: usize = QUEUE_CAPACITY / 8;
    pub(super) static TEST_RESERVED_FILE_SLOTS_DYNAMIC: AtomicUsize =
        AtomicUsize::new(RESERVED_FILE_SLOTS_TEST);

    pub(super) struct WorkerInner {
        queue: StdMutex<VecDeque<SwapEntry>>,
        pending: StdMutex<BTreeSet<usize>>,
        condvar: Condvar,
    }

    pub(super) static WORKER: Once<Arc<WorkerInner>> = Once::new();

    pub(super) fn process_file_swap_entry(entry: &SwapEntry, ino: u64, page_num: u64) {
        let written = crate::fs::page_cache().sync_page(ino, page_num, |offset, data| {
            match crate::fs::write_inode_by_number(ino, offset, data) {
                Ok(_) => Ok(()),
                Err(_) => Err(()),
            }
        });

        match written {
            Ok(true) => {
                release_frame_and_untrack(entry.frame);
                TEST_DEALLOC_COUNT.fetch_add(1, Ordering::AcqRel);
                crate::mm::reclaim::page_reclaim::notify_async_swapout_success(entry.frame);
            }
            _ => {
                process_file_swap_fallback(entry);
            }
        }
    }

    pub(super) fn process_file_swap_fallback(entry: &SwapEntry) {
        if crate::fs::page_cache()
            .sync_all(|ino, offset, data| {
                match crate::fs::write_inode_by_number(ino, offset, data) {
                    Ok(_) => Ok(()),
                    Err(_) => Err(()),
                }
            })
            .unwrap_or(0)
            > 0
        {
            release_frame_and_untrack(entry.frame);
            TEST_DEALLOC_COUNT.fetch_add(1, Ordering::AcqRel);
            crate::mm::reclaim::page_reclaim::notify_async_swapout_success(entry.frame);
        } else {
            crate::mm::reclaim::page_reclaim::PAGE_RECLAIM.account_writeback_skipped();
            crate::mm::reclaim::page_reclaim::notify_async_swapout_failure(entry.frame);
        }
    }

    pub(super) fn process_anon_swap_entry(
        entry: &SwapEntry,
        reuse_buf: &mut crate::mm::reclaim::async_swapout::Buffer4K,
    ) {
        if try_zswap_store_and_dealloc_any(entry.frame, reuse_buf) {
            TEST_DEALLOC_COUNT.fetch_add(1, Ordering::AcqRel);
            crate::mm::reclaim::page_reclaim::notify_async_swapout_success(entry.frame);
        } else {
            TEST_ZSWAP_FAILS.fetch_add(1, Ordering::AcqRel);
            crate::mm::reclaim::page_reclaim::notify_async_swapout_failure(entry.frame);
        }
    }

    pub(super) fn finalize_entry(thread_inner: &WorkerInner, entry: &SwapEntry) {
        // 完了通知
        let (lock, cvar) = &*entry.completion;
        let mut done = lock.lock().unwrap();
        *done = true;
        cvar.notify_all();

        // pending を解除
        thread_inner
            .pending
            .lock()
            .unwrap()
            .remove(&entry.frame.as_usize());

        // decrement file queue count when file processed (saturating)
        if let SwapKind::File { .. } = entry.kind {
            atomic_saturating_decrement(&TEST_FILE_QUEUE_COUNT);
        }

        // optional processing delay
        let d = TEST_PROCESSING_DELAY_MS.load(Ordering::Acquire);
        if d > 0 {
            std::thread::sleep(std::time::Duration::from_millis(d));
        }
    }

    pub(super) fn refill_token_bucket() {
        let add = TEST_REFILL_PER_BATCH;
        // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
        loop {
            let cur = TEST_TOKENS.load(Ordering::Acquire);
            let cap = TEST_TOKEN_CAPACITY_DYNAMIC.load(Ordering::Acquire);
            if cur >= cap {
                break;
            }
            let new = (cur + add).min(cap);
            match TEST_TOKENS.compare_exchange(cur, new, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
    }

    pub(super) fn drain_batch(
        q_guard: &mut std::sync::MutexGuard<'_, VecDeque<SwapEntry>>,
    ) -> Vec<SwapEntry> {
        let mut batch = Vec::new();
        for _ in 0..BATCH_SIZE {
            if let Some(entry) = q_guard.pop_front() {
                batch.push(entry);
            } else {
                break;
            }
        }
        batch
    }

    pub(super) fn worker_thread_body(thread_inner: Arc<WorkerInner>) {
        let mut reuse_buf = crate::mm::reclaim::async_swapout::buffer_pool_get_4k();
        loop {
            let mut q_guard = thread_inner.queue.lock().unwrap();
            while q_guard.is_empty() && !TEST_WORKER_SHUTDOWN.load(Ordering::Acquire) {
                q_guard = thread_inner.condvar.wait(q_guard).unwrap();
            }

            if q_guard.is_empty() && TEST_WORKER_SHUTDOWN.load(Ordering::Acquire) {
                break;
            }

            let batch = drain_batch(&mut q_guard);
            drop(q_guard);

            for entry in batch {
                match entry.kind {
                    SwapKind::File { ino, page_num } => {
                        process_file_swap_entry(&entry, ino, page_num);
                    }
                    SwapKind::Anon => {
                        process_anon_swap_entry(&entry, &mut reuse_buf);
                    }
                }
                finalize_entry(&thread_inner, &entry);
            }

            refill_token_bucket();
        }

        crate::mm::reclaim::async_swapout::buffer_pool_put_4k(reuse_buf);
        TEST_WORKER_RUNNING.store(false, Ordering::Release);
    }

    pub(super) fn init_worker() -> Arc<WorkerInner> {
        WORKER.call_once(|| {
            Arc::new(WorkerInner {
                queue: StdMutex::new(VecDeque::new()),
                pending: StdMutex::new(BTreeSet::new()),
                condvar: Condvar::new(),
            })
        });

        let worker = WORKER.get().as_ref().unwrap().clone(); // Arc clone

        // Spawn worker thread if not already running
        if TEST_WORKER_RUNNING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let thread_inner = worker.clone();
            std::thread::spawn(move || {
                worker_thread_body(thread_inner);
            });
        }

        worker.clone()
    }

    pub fn try_enqueue(frame: FrameIndex, kind: SwapKind) -> Result<super::SwapHandle, SwapError> {
        let worker = init_worker();

        // pending と容量チェック
        {
            let mut pending = worker.pending.lock().unwrap();
            if pending.contains(&frame.as_usize()) {
                return Err(SwapError::AlreadyPending);
            }

            let mut q = worker.queue.lock().unwrap();
            if q.len() >= QUEUE_CAPACITY {
                return Err(SwapError::QueueFull);
            }

            // Enforce reservation for file writes when queue nearly full
            if let SwapKind::Anon = kind {
                let total = q.len();
                let file_q = TEST_FILE_QUEUE_COUNT.load(Ordering::Acquire);
                let free_slots = QUEUE_CAPACITY.saturating_sub(total);
                let reserved = TEST_RESERVED_FILE_SLOTS_DYNAMIC.load(Ordering::Acquire);
                if free_slots <= reserved && file_q >= reserved {
                    return Err(SwapError::QueueFull);
                }
            }

            pending.insert(frame.as_usize());

            let completion = Arc::new((StdMutex::new(false), Condvar::new()));
            let entry = SwapEntry {
                frame,
                kind,
                completion: completion.clone(),
            };

            // Consume a token for anon entries
            if let SwapKind::Anon = entry.kind {
                try_consume_anon_token(&frame, &mut pending)?;
            }

            if let SwapKind::File { .. } = entry.kind {
                TEST_FILE_QUEUE_COUNT.fetch_add(1, Ordering::AcqRel);
            }

            q.push_back(entry);
            worker.condvar.notify_one();

            Ok(super::SwapHandle { done: completion })
        }
    }

    // Test inspection helpers
    #[cfg(test)]
    pub fn _queue_len() -> usize {
        let worker = init_worker();
        worker.queue.lock().unwrap().len()
    }

    #[cfg(test)]
    pub fn _pending_len() -> usize {
        let worker = init_worker();
        worker.pending.lock().unwrap().len()
    }

    #[cfg(test)]
    pub fn _is_pending(frame: FrameIndex) -> bool {
        let worker = init_worker();
        worker.pending.lock().unwrap().contains(&frame.as_usize())
    }

    // Additional test helpers
    #[cfg(test)]
    pub fn _file_queue_len() -> usize {
        TEST_FILE_QUEUE_COUNT.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub fn _queue_capacity() -> usize {
        QUEUE_CAPACITY
    }

    #[cfg(test)]
    pub fn _reserved_file_slots() -> usize {
        RESERVED_FILE_SLOTS_TEST
    }

    #[cfg(test)]
    pub fn set_processing_delay(ms: u64) {
        TEST_PROCESSING_DELAY_MS.store(ms, Ordering::Release);
    }

    #[cfg(test)]
    pub fn stop_worker() {
        TEST_WORKER_SHUTDOWN.store(true, Ordering::Release);
        if let Some(inner) = WORKER.get() {
            inner.condvar.notify_all();
        }
    }

    #[cfg(test)]
    pub fn start_worker() {
        TEST_WORKER_SHUTDOWN.store(false, Ordering::Release);
        init_worker();
    }

    #[cfg(test)]
    pub fn is_worker_running() -> bool {
        TEST_WORKER_RUNNING.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub fn _token_count() -> usize {
        TEST_TOKENS.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub fn set_tokens(n: usize) {
        let cap = TEST_TOKEN_CAPACITY_DYNAMIC.load(Ordering::Acquire);
        TEST_TOKENS.store(n.min(cap), Ordering::Release);
    }

    #[cfg(test)]
    pub fn _huge_2m_skip_count() -> usize {
        GLOBAL_HUGE_2M_SKIPPED.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub fn _reset_huge_2m_skip_count() {
        GLOBAL_HUGE_2M_SKIPPED.store(0, Ordering::Release);
    }

    #[cfg(test)]
    pub fn add_tokens(n: usize) {
        loop {
            let cur = TEST_TOKENS.load(Ordering::Acquire);
            let cap = TEST_TOKEN_CAPACITY_DYNAMIC.load(Ordering::Acquire);
            if cur >= cap {
                break;
            }
            let new = (cur + n).min(cap);
            match TEST_TOKENS.compare_exchange(cur, new, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
    }

    #[cfg(test)]
    pub fn token_capacity() -> usize {
        TEST_TOKEN_CAPACITY_DYNAMIC.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub fn set_token_capacity_for_test(n: usize) {
        let cap = n.min(QUEUE_CAPACITY);
        TEST_TOKEN_CAPACITY_DYNAMIC.store(cap, Ordering::Release);
        // Trim current tokens to new cap
        loop {
            let cur = TEST_TOKENS.load(Ordering::Acquire);
            let new = cur.min(cap);
            if cur == new {
                break;
            }
            match TEST_TOKENS.compare_exchange(cur, new, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
    }

    #[cfg(test)]
    pub fn set_reserved_file_slots_for_test(n: usize) {
        let v = n.min(QUEUE_CAPACITY);
        TEST_RESERVED_FILE_SLOTS_DYNAMIC.store(v, Ordering::Release);
    }

    #[cfg(test)]
    pub fn _dealloc_count() -> usize {
        TEST_DEALLOC_COUNT.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub fn _reset_dealloc_count() {
        TEST_DEALLOC_COUNT.store(0, Ordering::Release);
    }

    #[cfg(test)]
    pub fn _dec_file_queue_count_safe() {
        atomic_saturating_decrement(&TEST_FILE_QUEUE_COUNT);
    }

    #[cfg(test)]
    pub fn _zswap_fail_count() -> usize {
        TEST_ZSWAP_FAILS.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub fn _reset_zswap_fail_count() {
        TEST_ZSWAP_FAILS.store(0, Ordering::Release);
    }
}
