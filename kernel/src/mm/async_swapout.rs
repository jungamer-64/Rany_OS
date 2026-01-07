// ============================================================================
// kernel/src/mm/async_swapout.rs
// ============================================================================
//! 非同期スワップアウト / 書き戻し合流モジュール
//!
//! - テスト時は std スレッドを使ったワーカを起動し非同期処理をシミュレートする
//! - 非テスト（カーネル実装）ではフォールバックとして同期処理を行う
//!
#![allow(dead_code)]

use x86_64::structures::paging::PhysFrame;

use crate::mm::types::FrameIndex;
use crate::mm::frame_backing;
use crate::mm::buddy_allocator;

// ファイルシステム型（Inode）
use crate::fs::fs_abstraction::InodeNum;

/// スワップアウト種別
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapKind {
    File { ino: InodeNum, page_num: u64 },
    Anon,
}

/// エラー種別
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapError {
    QueueFull,
    AlreadyPending,
    NotSupported,
}

// Completion handle (テスト用に簡易実装)
#[cfg(test)]
use alloc::sync::Arc;

#[cfg(test)]
pub struct SwapHandle {
    done: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
}

#[cfg(not(test))]
pub struct SwapHandle;

#[cfg(test)]
impl SwapHandle {
    pub fn wait(&self) {
        let (lock, cvar) = &*self.done;
        let mut done = lock.lock().unwrap();
        while !*done {
            done = cvar.wait(done).unwrap();
        }
    }

    pub fn is_done(&self) -> bool {
        let (lock, _) = &*self.done;
        *lock.lock().unwrap()
    }
} 

// 内部エントリ（テスト用）
#[cfg(test)]
struct SwapEntry {
    frame: FrameIndex,
    kind: SwapKind,
    completion: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
} 

// テスト専用: 永続ワーカ実装（条件変数 + バウンドキュー）
#[cfg(test)]
mod test_impl {
    use super::*;
    use alloc::collections::BTreeSet;
    use alloc::sync::Arc;
    use std::collections::VecDeque;
    use std::sync::{Mutex as StdMutex, Condvar};
    use spin::Once;
    use std::thread;

    /// キュー容量／バッチサイズはテスト向けに控えめに設定可能
    const QUEUE_CAPACITY: usize = 64;
    const BATCH_SIZE: usize = 8;
    const RESERVED_FILE_SLOTS_TEST: usize = QUEUE_CAPACITY / 8;

    use core::sync::atomic::{AtomicBool, AtomicUsize, AtomicU64, Ordering};

    static TEST_FILE_QUEUE_COUNT: AtomicUsize = AtomicUsize::new(0);
    static TEST_PROCESSING_DELAY_MS: AtomicU64 = AtomicU64::new(0);
    static TEST_WORKER_RUNNING: AtomicBool = AtomicBool::new(false);
    static TEST_WORKER_SHUTDOWN: AtomicBool = AtomicBool::new(false);

    // Token-bucket backpressure (test)
    const TEST_TOKEN_CAPACITY: usize = QUEUE_CAPACITY / 4; // burst capacity for anon entries
    const TEST_REFILL_PER_BATCH: usize = BATCH_SIZE / 2; // tokens added per processed batch

    static TEST_TOKENS: AtomicUsize = AtomicUsize::new(TEST_TOKEN_CAPACITY);

    struct WorkerInner {
        queue: StdMutex<VecDeque<SwapEntry>>,
        pending: StdMutex<BTreeSet<usize>>,
        condvar: Condvar,
    }

    static WORKER: Once<Option<Arc<WorkerInner>>> = Once::new();

    fn init_worker() -> Arc<WorkerInner> {
        WORKER.call_once(|| {
            let inner = Arc::new(WorkerInner {
                queue: StdMutex::new(VecDeque::new()),
                pending: StdMutex::new(BTreeSet::new()),
                condvar: Condvar::new(),
            });

            Some(inner)
        });

        let worker = WORKER.get().as_ref().unwrap().clone();

        // Spawn worker thread if not already running
        if TEST_WORKER_RUNNING.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            let thread_inner = worker.clone();
            std::thread::spawn(move || {
                loop {
                    // Wait for work or shutdown
                    let mut q_guard = thread_inner.queue.lock().unwrap();
                    while q_guard.is_empty() && !TEST_WORKER_SHUTDOWN.load(Ordering::Acquire) {
                        q_guard = thread_inner.condvar.wait(q_guard).unwrap();
                    }

                    // if shutdown and queue empty, exit
                    if q_guard.is_empty() && TEST_WORKER_SHUTDOWN.load(Ordering::Acquire) {
                        break;
                    }

                    let mut batch = Vec::new();
                    for _ in 0..BATCH_SIZE {
                        if let Some(entry) = q_guard.pop_front() {
                            batch.push(entry);
                        } else {
                            break;
                        }
                    }
                    drop(q_guard);

                    // バッチ処理
                    for entry in batch {
                        match entry.kind {
                            SwapKind::File { ino, page_num } => {
                                let res = crate::fs::page_cache().sync_page(ino, page_num, |offset, data| {
                                    match crate::fs::write_inode_by_number(ino, offset, data) {
                                        Ok(_) => Ok(()),
                                        Err(_) => Err(()),
                                    }
                                });

                                if res.is_ok() {
                                    let _ = frame_backing::untrack_frame_backing(entry.frame);
                                    let phys = unsafe { PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(entry.frame.to_phys_addr())) };
                                    buddy_allocator::buddy_dealloc_frame(phys);
                                }
                            }
                            SwapKind::Anon => {
                                if crate::mm::zswap::zswap_is_enabled() {
                                    let phys = entry.frame.to_phys_addr();
                                    let vaddr = crate::mm::mapping::phys_to_virt(x86_64::PhysAddr::new(phys));
                                    let src = vaddr.as_u64() as *const u8;
                                    let mut buf = vec![0u8; crate::mm::PAGE_SIZE_4K];
                                    unsafe { core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), crate::mm::PAGE_SIZE_4K); }
                                    let _ = crate::mm::zswap::zswap_store(0, &buf);
                                    let physf = unsafe { PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(entry.frame.to_phys_addr())) };
                                    buddy_allocator::buddy_dealloc_frame(physf);
                                } else {
                                    let physf = unsafe { PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(entry.frame.to_phys_addr())) };
                                    buddy_allocator::buddy_dealloc_frame(physf);
                                }
                            }
                        }

                        // 完了通知
                        let (lock, cvar) = &*entry.completion;
                        let mut done = lock.lock().unwrap();
                        *done = true;
                        cvar.notify_all();

                        // pending を解除
                        thread_inner.pending.lock().unwrap().remove(&entry.frame.as_usize());

                        // decrement file queue count when file processed
                        if let SwapKind::File { .. } = entry.kind {
                            TEST_FILE_QUEUE_COUNT.fetch_sub(1, Ordering::AcqRel);
                        }

                        // optional processing delay
                        let d = TEST_PROCESSING_DELAY_MS.load(Ordering::Acquire);
                        if d > 0 {
                            std::thread::sleep(std::time::Duration::from_millis(d));
                        }
                    }

                    // Refill token bucket after processing batch
                    {
                        let add = TEST_REFILL_PER_BATCH;
                        loop {
                            let cur = TEST_TOKENS.load(Ordering::Acquire);
                            if cur >= TEST_TOKEN_CAPACITY { break; }
                            let new = (cur + add).min(TEST_TOKEN_CAPACITY);
                            match TEST_TOKENS.compare_exchange(cur, new, Ordering::AcqRel, Ordering::Acquire) {
                                Ok(_) => break,
                                Err(_) => continue,
                            }
                        }
                    }
                }

                TEST_WORKER_RUNNING.store(false, Ordering::Release);
            });
        }

        worker
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
                if free_slots <= RESERVED_FILE_SLOTS_TEST && file_q >= RESERVED_FILE_SLOTS_TEST {
                    return Err(SwapError::QueueFull);
                }
            }

            pending.insert(frame.as_usize());

            let completion = Arc::new((StdMutex::new(false), Condvar::new()));
            let entry = SwapEntry { frame, kind, completion: completion.clone() };

            // Consume a token for anon entries
            if let SwapKind::Anon = entry.kind {
                let mut cur = TEST_TOKENS.load(Ordering::Acquire);
                loop {
                    if cur == 0 {
                        // rollback pending and fail fast
                        worker.pending.lock().unwrap().remove(&frame.as_usize());
                        return Err(SwapError::QueueFull);
                    }
                    match TEST_TOKENS.compare_exchange(cur, cur - 1, Ordering::AcqRel, Ordering::Acquire) {
                        Ok(_) => break,
                        Err(c) => cur = c,
                    }
                }
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
        if let Some(inner) = WORKER.get().as_ref().and_then(|o| o.as_ref()) {
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
        TEST_TOKENS.store(n.min(TEST_TOKEN_CAPACITY), Ordering::Release);
    }

    #[cfg(test)]
    pub fn add_tokens(n: usize) {
        loop {
            let cur = TEST_TOKENS.load(Ordering::Acquire);
            if cur >= TEST_TOKEN_CAPACITY { break; }
            let new = (cur + n).min(TEST_TOKEN_CAPACITY);
            match TEST_TOKENS.compare_exchange(cur, new, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
    }

    #[cfg(test)]
    pub fn token_capacity() -> usize {
        TEST_TOKEN_CAPACITY
    }
} 

// カーネル向け実装: 永続ワーカ（non-test）
#[cfg(not(test))]
mod kernel_impl {
    use super::*;
    use alloc::vec::Vec;
    use spin::{Once, Mutex};
    use crate::sync::lockfree::{BoundedChannel, BoundedSender, BoundedReceiver};
    use crate::sync::AtomicWaker;
    use crate::task::Task;
    use crate::mm::page_flags::{self, PageFlags};

    // Channel capacity and batch size tunables
    const CHANNEL_SIZE: usize = 1024;
    const BATCH_SIZE: usize = 32;

    #[derive(Clone, Copy)]
    struct SwapEntryKernel {
        frame: FrameIndex,
        kind: SwapKind,
    }

    // Static channel (initialized once)
    static CHANNEL_ONCE: Once<Option<(BoundedSender<SwapEntryKernel, CHANNEL_SIZE>, BoundedReceiver<SwapEntryKernel, CHANNEL_SIZE>)>> = Once::new();

    // Pending set is replaced by GlobalPageFlags

    // Queue occupancy counters (for reservation of file slots)
    use core::sync::atomic::{AtomicUsize, Ordering};
    static QUEUE_COUNT: AtomicUsize = AtomicUsize::new(0);
    static FILE_QUEUE_COUNT: AtomicUsize = AtomicUsize::new(0);
    // Reserve some slots for file writes so heavy anon traffic cannot starve file writebacks
    const RESERVED_FILE_SLOTS: usize = CHANNEL_SIZE / 8; // reserve ~12.5% for file writes
    // Token-bucket backpressure (anonymous pages)
    // - TOKEN_BUCKET_CAPACITY: Burst capacity for anon enqueues. Larger value allows absorbing transient spikes
    //   but increases risk of anon traffic delaying file writebacks.
    // - TOKEN_REFILL_PER_BATCH: Amount of tokens restored per processed batch. Controls long-term sustained rate.
    const TOKEN_BUCKET_CAPACITY: usize = CHANNEL_SIZE / 4; // anonymous burst capacity
    const TOKEN_REFILL_PER_BATCH: usize = BATCH_SIZE / 2;

    // Runtime-adjustable parameters (Atomics allow tuning without recompilation)
    static RESERVED_FILE_SLOTS_ATOMIC: AtomicUsize = AtomicUsize::new(RESERVED_FILE_SLOTS);
    static TOKEN_BUCKET_CAPACITY_ATOMIC: AtomicUsize = AtomicUsize::new(TOKEN_BUCKET_CAPACITY);
    static TOKEN_REFILL_PER_BATCH_ATOMIC: AtomicUsize = AtomicUsize::new(TOKEN_REFILL_PER_BATCH);

    static TOKENS: AtomicUsize = AtomicUsize::new(TOKEN_BUCKET_CAPACITY);
    // Worker waker and running flags
    static WORKER_WAKER: AtomicWaker = AtomicWaker::new();
    static WORKER_RUNNING: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    static WORKER_SHUTDOWN: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

    fn ensure_channel_started() {
        CHANNEL_ONCE.call_once(|| {
            let (s, r) = BoundedChannel::<SwapEntryKernel, CHANNEL_SIZE>::new();
            Some((s, r))
        });

        // Try to spawn the worker if not already running
        if WORKER_RUNNING.compare_exchange(false, true, core::sync::atomic::Ordering::AcqRel, core::sync::atomic::Ordering::Acquire).is_ok() {
            WORKER_SHUTDOWN.store(false, core::sync::atomic::Ordering::Release);
            let task = Task::new(async move { worker_loop().await });
            crate::task::Executor::spawn_global(task);
        }
    }

    // Future that waits until there is work in the channel
    struct WaitForWork;
    impl core::future::Future for WaitForWork {
        type Output = ();
        fn poll(self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> core::task::Poll<()> {
            // Fast path: if receiver has elements, return ready
            if let Some(ch) = CHANNEL_ONCE.get().and_then(|opt| opt.as_ref()) {
                if !ch.1.is_empty() {
                    return core::task::Poll::Ready(());
                }
            }

            // Register waker
            WORKER_WAKER.register(cx.waker());

            // Re-check to avoid races
            if let Some(ch) = CHANNEL_ONCE.get().and_then(|opt| opt.as_ref()) {
                if !ch.1.is_empty() {
                    return core::task::Poll::Ready(());
                }
            }

            core::task::Poll::Pending
        }
    }

    async fn worker_loop() {
        loop {
            WaitForWork.await;

            // If shutdown requested and channel empty, stop
            if WORKER_SHUTDOWN.load(core::sync::atomic::Ordering::Acquire) {
                if let Some(ch) = CHANNEL_ONCE.get().and_then(|opt| opt.as_ref()) {
                    if ch.1.is_empty() {
                        WORKER_RUNNING.store(false, core::sync::atomic::Ordering::Release);
                        break;
                    }
                } else {
                    WORKER_RUNNING.store(false, core::sync::atomic::Ordering::Release);
                    break;
                }
            }

            // Drain up to BATCH_SIZE entries
            let mut batch: Vec<SwapEntryKernel> = Vec::new();
            if let Some(ch) = CHANNEL_ONCE.get().and_then(|opt| opt.as_ref()) {
                let rx = &ch.1;
                for _ in 0..BATCH_SIZE {
                    if let Some(entry) = rx.recv() {
                        batch.push(entry);
                    } else {
                        break;
                    }
                }
            }

            // Process batch
            for entry in batch {
                match entry.kind {
                    SwapKind::File { ino, page_num } => {
                        let written = crate::fs::page_cache().sync_page(ino, page_num, |offset, data| {
                            match crate::fs::write_inode_by_number(ino, offset, data) {
                                Ok(_) => Ok(()),
                                Err(_) => Err(()),
                            }
                        });

                        match written {
                            Ok(true) => {
                                let _ = frame_backing::untrack_frame_backing(entry.frame);
                                let physf = unsafe { PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(entry.frame.to_phys_addr())) };
                                buddy_allocator::buddy_dealloc_frame(physf);
                            }
                            _ => {
                                // Fall back to global sync
                                if crate::fs::page_cache().sync_all(|ino, offset, data| {
                                    match crate::fs::write_inode_by_number(ino, offset, data) {
                                        Ok(_) => Ok(()),
                                        Err(_) => Err(()),
                                    }
                                }).unwrap_or(0) > 0 {
                                    if let Some(info) = crate::mm::memcg::memcg_untrack_page(entry.frame) {
                                        let _ = crate::mm::memcg::memcg_uncharge(info.memcg_id, 1, info.charge_type);
                                    }
                                    let _ = frame_backing::untrack_frame_backing(entry.frame);
                                    let physf = unsafe { PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(entry.frame.to_phys_addr())) };
                                    buddy_allocator::buddy_dealloc_frame(physf);
                                } else {
                                    crate::mm::page_reclaim::PAGE_RECLAIM.account_writeback_skipped();
                                }
                            }
                        }

                        // Remove pending flag and update queue counters
                        page_flags::clear_flag(entry.frame, PageFlags::SwapPending);
                        QUEUE_COUNT.fetch_sub(1, Ordering::AcqRel);
                        FILE_QUEUE_COUNT.fetch_sub(1, Ordering::AcqRel); // safe to decrement even if zero due to caller correctness
                    }
                    SwapKind::Anon => {
                        if crate::mm::zswap::zswap_is_enabled() {
                            let phys = entry.frame.to_phys_addr();
                            let vaddr = crate::mm::mapping::phys_to_virt(x86_64::PhysAddr::new(phys));
                            let src = vaddr.as_u64() as *const u8;
                            let mut buf = alloc::vec![0u8; crate::mm::PAGE_SIZE_4K];
                            unsafe { core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), crate::mm::PAGE_SIZE_4K); }
                            let _ = crate::mm::zswap::zswap_store(0, &buf);
                            let physf = unsafe { PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(entry.frame.to_phys_addr())) };
                            buddy_allocator::buddy_dealloc_frame(physf);
                        } else {
                            let physf = unsafe { PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(entry.frame.to_phys_addr())) };
                            buddy_allocator::buddy_dealloc_frame(physf);
                        }

                        page_flags::clear_flag(entry.frame, PageFlags::SwapPending);
                        QUEUE_COUNT.fetch_sub(1, Ordering::AcqRel);
                    }
                }
            }


            // Refill token bucket after processing batch
            // Only refill if we actually processed something or if we just woke up to check
            // Use a simple strategy: constant refill rate per batch processing cycle
            add_tokens(TOKEN_REFILL_PER_BATCH_ATOMIC.load(Ordering::Acquire));

            // If shutdown requested and channel empty after processing, stop
            if WORKER_SHUTDOWN.load(core::sync::atomic::Ordering::Acquire) {
                if let Some(ch) = CHANNEL_ONCE.get().and_then(|opt| opt.as_ref()) {
                    if ch.1.is_empty() {
                        WORKER_RUNNING.store(false, core::sync::atomic::Ordering::Release);
                        break;
                    }
                } else {
                    WORKER_RUNNING.store(false, core::sync::atomic::Ordering::Release);
                    break;
                }
            }
        }
    }

    fn try_consume_token() -> bool {
        let mut cur = TOKENS.load(Ordering::Acquire);
        loop {
            if cur == 0 {
                return false;
            }
            match TOKENS.compare_exchange(cur, cur - 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return true,
                Err(c) => cur = c,
            }
        }
    }

    fn add_tokens(n: usize) {
        // Respect current dynamic capacity
        let cap = TOKEN_BUCKET_CAPACITY_ATOMIC.load(Ordering::Acquire);
        let mut cur = TOKENS.load(Ordering::Acquire);
        loop {
            if cur >= cap {
                return;
            }
            let new = (cur + n).min(cap);
            match TOKENS.compare_exchange(cur, new, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return,
                Err(c) => cur = c,
            }
        }
    }

    pub fn try_enqueue(frame: FrameIndex, kind: SwapKind) -> Result<super::SwapHandle, SwapError> {
        ensure_channel_started();

        // If worker has been stopped, not supported
        if !WORKER_RUNNING.load(core::sync::atomic::Ordering::Acquire) {
            return Err(SwapError::NotSupported);
        }

        // Fast-path: try to set pending flag (atomic)
        if page_flags::test_and_set_flag(frame, PageFlags::SwapPending) {
             // Already set
             return Err(SwapError::AlreadyPending);
        }

        // Check sender capacity
        if let Some(ch) = CHANNEL_ONCE.get().and_then(|opt| opt.as_ref()) {
            let sender = &ch.0;
            if sender.is_full() {
                page_flags::clear_flag(frame, PageFlags::SwapPending);
                return Err(SwapError::QueueFull);
            }

            // Enforce strict reservation for file writes: keep RESERVED_FILE_SLOTS free for file entries
            if let SwapKind::Anon = kind {
                let total = QUEUE_COUNT.load(Ordering::Acquire);
                let free_slots = CHANNEL_SIZE.saturating_sub(total);
                let reserved = RESERVED_FILE_SLOTS_ATOMIC.load(Ordering::Acquire);
                if free_slots <= reserved {
                    // reserve slots for file writes — anon enqueues fail fast
                    page_flags::clear_flag(frame, PageFlags::SwapPending);
                    return Err(SwapError::QueueFull);
                }
            }

            // Token-bucket consumption for anon entries
            let mut token_consumed = false;
            if let SwapKind::Anon = kind {
                if !try_consume_token() {
                    page_flags::clear_flag(frame, PageFlags::SwapPending);
                    return Err(SwapError::QueueFull);
                }
                token_consumed = true;
            }

            match sender.send(SwapEntryKernel { frame, kind }) {
                Ok(()) => {
                    // Update counters
                    QUEUE_COUNT.fetch_add(1, Ordering::AcqRel);
                    if let SwapKind::File { .. } = kind {
                        FILE_QUEUE_COUNT.fetch_add(1, Ordering::AcqRel);
                    }

                    // Wake the worker
                    WORKER_WAKER.wake();
                    Ok(super::SwapHandle {})
                }
                Err(_v) => {
                    if token_consumed {
                        add_tokens(1);
                    }
                    page_flags::clear_flag(frame, PageFlags::SwapPending);
                    Err(SwapError::QueueFull)
                }
            }
        } else {
            page_flags::clear_flag(frame, PageFlags::SwapPending);
            Err(SwapError::NotSupported)
        }
    }

    // Kernel control / introspection
    pub fn queued_counts() -> (usize, usize) {
        (QUEUE_COUNT.load(core::sync::atomic::Ordering::Acquire), FILE_QUEUE_COUNT.load(core::sync::atomic::Ordering::Acquire))
    }

    pub fn token_count() -> usize {
        TOKENS.load(core::sync::atomic::Ordering::Acquire)
    }

    /// Runtime tunables and inspection
    pub fn set_token_bucket_capacity(n: usize) {
        let n = n.min(CHANNEL_SIZE);
        TOKEN_BUCKET_CAPACITY_ATOMIC.store(n, Ordering::Release);
        // Trim current tokens if above new capacity
        loop {
            let cur = TOKENS.load(Ordering::Acquire);
            if cur <= n { break; }
            match TOKENS.compare_exchange(cur, n, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
    }

    pub fn token_bucket_capacity() -> usize {
        TOKEN_BUCKET_CAPACITY_ATOMIC.load(Ordering::Acquire)
    }

    pub fn set_token_refill_per_batch(n: usize) {
        TOKEN_REFILL_PER_BATCH_ATOMIC.store(n, Ordering::Release);
    }

    pub fn token_refill_per_batch() -> usize {
        TOKEN_REFILL_PER_BATCH_ATOMIC.load(Ordering::Acquire)
    }

    pub fn set_reserved_file_slots(n: usize) {
        RESERVED_FILE_SLOTS_ATOMIC.store(n.min(CHANNEL_SIZE), Ordering::Release);
    }

    pub fn reserved_file_slots() -> usize {
        RESERVED_FILE_SLOTS_ATOMIC.load(Ordering::Acquire)
    }

    pub fn set_token_count(n: usize) {
        let cap = TOKEN_BUCKET_CAPACITY_ATOMIC.load(Ordering::Acquire);
        TOKENS.store(n.min(cap), Ordering::Release);
    }

    pub fn add_tokens_public(n: usize) {
        add_tokens(n);
    }

    pub fn start_worker() {
        ensure_channel_started();
    }

    pub fn stop_worker() {
        WORKER_SHUTDOWN.store(true, core::sync::atomic::Ordering::Release);
        WORKER_WAKER.wake();
    }

    pub fn is_worker_running() -> bool {
        WORKER_RUNNING.load(core::sync::atomic::Ordering::Acquire)
    }
}



// 公開API: try_enqueue_swapout
pub fn try_enqueue_swapout(frame: FrameIndex, kind: SwapKind) -> Result<SwapHandle, SwapError> {
    #[cfg(test)]
    {
        test_impl::try_enqueue(frame, kind)
    }

    #[cfg(not(test))]
    {
        kernel_impl::try_enqueue(frame, kind)
    }
}

/// Start the async swapout worker (tests call test worker, kernel calls kernel worker)
pub fn start_worker() {
    #[cfg(test)]
    {
        test_impl::start_worker();
    }

    #[cfg(not(test))]
    {
        kernel_impl::start_worker();
    }
}

/// Stop the async swapout worker
pub fn stop_worker() {
    #[cfg(test)]
    {
        test_impl::stop_worker();
    }

    #[cfg(not(test))]
    {
        kernel_impl::stop_worker();
    }
}

/// Return whether the worker is running
pub fn is_worker_running() -> bool {
    #[cfg(test)]
    {
        test_impl::is_worker_running()
    }

    #[cfg(not(test))]
    {
        kernel_impl::is_worker_running()
    }
}

/// Return (queue_len, file_queue_len)
pub fn queued_counts() -> (usize, usize) {
    #[cfg(test)]
    {
        (test_impl::_queue_len(), test_impl::_file_queue_len())
    }

    #[cfg(not(test))]
    {
        kernel_impl::queued_counts()
    }
}

/// Return the current token count (anon token bucket)
pub fn token_count() -> usize {
    #[cfg(test)]
    {
        test_impl::_token_count()
    }

    #[cfg(not(test))]
    {
        kernel_impl::token_count()
    }
}

/// Runtime tunables (top-level wrappers)
pub fn set_token_bucket_capacity(n: usize) {
    #[cfg(not(test))]
    { kernel_impl::set_token_bucket_capacity(n); }
}

pub fn token_bucket_capacity() -> usize {
    #[cfg(not(test))]
    { kernel_impl::token_bucket_capacity() }
    #[cfg(test)]
    { 0 }
}

pub fn set_token_refill_per_batch(n: usize) {
    #[cfg(not(test))]
    { kernel_impl::set_token_refill_per_batch(n); }
}

pub fn token_refill_per_batch() -> usize {
    #[cfg(not(test))]
    { kernel_impl::token_refill_per_batch() }
    #[cfg(test)]
    { 0 }
}

pub fn set_reserved_file_slots(n: usize) {
    #[cfg(not(test))]
    { kernel_impl::set_reserved_file_slots(n); }
}

pub fn reserved_file_slots() -> usize {
    #[cfg(not(test))]
    { kernel_impl::reserved_file_slots() }
    #[cfg(test)]
    { 0 }
}

pub fn set_token_count(n: usize) {
    #[cfg(not(test))]
    { kernel_impl::set_token_count(n); }
    #[cfg(test)]
    { test_impl::set_tokens(n); }
}

pub fn add_tokens(n: usize) {
    #[cfg(not(test))]
    { kernel_impl::add_tokens_public(n); }
    #[cfg(test)]
    { test_impl::add_tokens(n); }
}

// テスト: キューイング API とワーカの動作を検証するユニットテストを追加
#[cfg(test)]
mod tests {
    use super::*;
    use crate::mm::{PAGE_SIZE_4K, frame_backing};

    #[test]
    fn test_async_swapout_file_backed() {
        // セットアップ: page cache にページを入れ、対応するフレームを確保して frame_backing を登録
        let cache = crate::fs::cache::PageCache::new(64 * 1024);
        let ino = 42u64;
        let page_num = 1u64;
        let data = alloc::vec![0xAAu8; PAGE_SIZE_4K];
        cache.insert(ino, page_num as usize, data, PAGE_SIZE_4K as u64);
        assert!(cache.mark_dirty(ino, page_num as usize));

        // allocate a frame to represent the physical page
        let frame = crate::mm::alloc_frame().expect("alloc frame");
        let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());

        // track the frame backing
        frame_backing::track_frame_backing(frame_idx, ino, page_num);

        // enqueue
        let handle = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::File { ino, page_num })
            .expect("enqueue ok");

        // wait for completion
        handle.wait();

        // backing must be gone
        assert!(frame_backing::get_frame_backing(frame_idx).is_none());

        // page should be clean
        let files = cache.files.read();
        if let Some(file_cache) = files.get(&ino) {
            if let Some(page) = file_cache.get_page(page_num as usize) {
                assert!(!page.is_dirty());
            } else { panic!("page not found"); }
        } else { panic!("file cache not found"); }
    }

    #[test]
    fn test_async_swapout_dedup() {
        // setup similar to file-backed test
        let cache = crate::fs::cache::PageCache::new(64 * 1024);
        let ino = 43u64;
        let page_num = 2u64;
        let data = alloc::vec![0xBBu8; PAGE_SIZE_4K];
        cache.insert(ino, page_num as usize, data, PAGE_SIZE_4K as u64);
        assert!(cache.mark_dirty(ino, page_num as usize));

        let frame = crate::mm::alloc_frame().expect("alloc frame");
        let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
        frame_backing::track_frame_backing(frame_idx, ino, page_num);

        // first enqueue should succeed
        let handle1 = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::File { ino, page_num }).expect("enqueue ok");

        // second enqueue for same frame should return AlreadyPending
        let err = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::File { ino, page_num }).expect_err("should be pending");
        assert_eq!(err, SwapError::AlreadyPending);

        // wait for first completion, then enqueue again
        handle1.wait();
        let handle2 = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::File { ino, page_num }).expect("enqueue ok");
        handle2.wait();

        // after completion backing must be removed
        assert!(frame_backing::get_frame_backing(frame_idx).is_none());
    }

    #[test]
    fn test_memcg_concurrent_swapout() {
        // Initialize memcg and global page cache
        crate::mm::memcg::init_memcg();
        let cg = crate::mm::memcg::memcg_create(String::from("concurrent"), crate::mm::memcg::memcg_root()).expect("create memcg");
        crate::fs::cache::init_page_cache(64 * 1024);
        let cache = crate::fs::page_cache();

        let n = 64usize;
        let mut join_handles = Vec::new();

        for i in 0..n {
            let cache = cache; // copy ref
            let cg = cg;
            let handle = std::thread::spawn(move || {
                // allocate a frame
                let frame = crate::mm::alloc_frame().expect("alloc frame");
                let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());

                if i % 2 == 0 {
                    // file-backed
                    assert!(crate::mm::memcg::memcg_charge(cg, 1, crate::mm::memcg::ChargeType::Cache).is_ok());
                    crate::mm::memcg::memcg_track_page(frame_idx, cg, crate::mm::memcg::ChargeType::Cache);

                    let ino = 1000u64;
                    let page_num = i as u64;
                    let data = alloc::vec![0u8; PAGE_SIZE_4K];
                    cache.insert(ino, page_num as usize, data, PAGE_SIZE_4K as u64);
                    assert!(cache.mark_dirty(ino, page_num as usize));
                    crate::mm::frame_backing::track_frame_backing(frame_idx, ino, page_num);

                    let h = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::File { ino, page_num }).expect("enqueue ok");
                    h.wait();
                } else {
                    // anon
                    assert!(crate::mm::memcg::memcg_charge(cg, 1, crate::mm::memcg::ChargeType::Anon).is_ok());
                    crate::mm::memcg::memcg_track_page(frame_idx, cg, crate::mm::memcg::ChargeType::Anon);

                    let h = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon).expect("enqueue ok");
                    h.wait();
                }

                // After completion, page info should be gone
                assert!(crate::mm::memcg::memcg_get_page_info(frame_idx).is_none());
            });

            join_handles.push(handle);
        }

        for h in join_handles {
            h.join().expect("thread join");
        }

        // All charges should be cleared
        let stats = crate::mm::memcg::memcg_stats(cg).expect("stats");
        assert_eq!(stats.cache_pages, 0);
        assert_eq!(stats.anon_pages, 0);
    }

    #[test]
    fn test_async_swapout_concurrent_dedup() {
        // Initialize global cache
        crate::fs::cache::init_page_cache(64 * 1024);
        let cache = crate::fs::page_cache();

        // Setup a single frame and track it
        let ino = 2000u64;
        let page_num = 1u64;
        let data = alloc::vec![0xEEu8; PAGE_SIZE_4K];
        cache.insert(ino, page_num as usize, data, PAGE_SIZE_4K as u64);
        assert!(cache.mark_dirty(ino, page_num as usize));

        let frame = crate::mm::alloc_frame().expect("alloc frame");
        let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
        crate::mm::frame_backing::track_frame_backing(frame_idx, ino, page_num);

        // Check queue/pending metrics before enqueue
        assert_eq!(test_impl::_queue_len(), 0);
        assert_eq!(test_impl::_pending_len(), 0);
        assert!(!test_impl::_is_pending(frame_idx));

        // Barrier to synchronize enqueuers
        let threads = 8usize;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(threads + 1));
        let results = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

        let mut joiners = Vec::new();
        for _ in 0..threads {
            let barrier = barrier.clone();
            let results = results.clone();
            let frame_idx = frame_idx;
            let t = std::thread::spawn(move || {
                barrier.wait();
                let res = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::File { ino, page_num });
                results.lock().unwrap().push(res);
            });
            joiners.push(t);
        }

        // Release all enqueuers
        barrier.wait();

        // Give a tiny moment for enqueues to be processed
        std::thread::sleep(std::time::Duration::from_millis(10));

        // After enqueuing, queue and pending should reflect the entry
        assert!(test_impl::_queue_len() >= 1);
        assert_eq!(test_impl::_pending_len(), 1);
        assert!(test_impl::_is_pending(frame_idx));

        for j in joiners {
            j.join().expect("join");
        }

        let resvec = results.lock().unwrap();
        // There should be at least one Ok and at least one AlreadyPending among the others
        let mut ok_count = 0usize;
        let mut pending_count = 0usize;
        for r in resvec.iter() {
            match r {
                Ok(_) => ok_count += 1,
                Err(SwapError::AlreadyPending) => pending_count += 1,
                Err(_) => (),
            }
        }

        assert!(ok_count >= 1, "expected at least one successful enqueue");
        assert!(pending_count >= 1, "expected at least one AlreadyPending");

        // Wait for any successful handles to complete
        for r in resvec.iter() {
            if let Ok(h) = r {
                h.wait();
            }
        }

        // After completion, queue must be drained and pending cleared
        assert_eq!(test_impl::_queue_len(), 0);
        assert_eq!(test_impl::_pending_len(), 0);
        assert!(!test_impl::_is_pending(frame_idx));

        assert!(crate::mm::frame_backing::get_frame_backing(frame_idx).is_none());
    }

    #[test]
    fn test_worker_restart() {
        // ensure worker lifecycle control works via top-level API
        start_worker();
        assert!(is_worker_running(), "worker should be running after start");

        stop_worker();
        // Wait for worker to stop
        for _ in 0..20 {
            if !is_worker_running() { break; }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(!is_worker_running(), "worker should have stopped");

        // Restart and ensure it runs
        start_worker();
        assert!(is_worker_running(), "worker should be running after restart");

        // Clean up
        stop_worker();
    }

    #[test]
    fn test_async_swapout_qos_reservation() {
        crate::fs::cache::init_page_cache(64 * 1024);
        let cache = crate::fs::page_cache();

        // Stop worker to allow deterministic queue fill
        test_impl::stop_worker();
        for _ in 0..20 {
            if !test_impl::is_worker_running() { break; }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let cap = test_impl::_queue_capacity();
        let reserved = test_impl::_reserved_file_slots();

        let fill_count = cap.saturating_sub(reserved) + 1;

        let mut handles = Vec::new();

        let ino = 3000u64;
        for i in 0..fill_count {
            let page_num = i as u64;
            let data = alloc::vec![0u8; PAGE_SIZE_4K];
            cache.insert(ino, page_num as usize, data, PAGE_SIZE_4K as u64);
            assert!(cache.mark_dirty(ino, page_num as usize));

            let frame = crate::mm::alloc_frame().expect("alloc frame");
            let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
            crate::mm::frame_backing::track_frame_backing(frame_idx, ino, page_num);

            let h = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::File { ino, page_num }).expect("enqueue ok");
            handles.push(h);
        }

        assert!(test_impl::_queue_len() >= fill_count);
        assert!(test_impl::_file_queue_len() >= reserved);

        let frame = crate::mm::alloc_frame().expect("alloc frame");
        let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
        let err = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon).expect_err("expected QueueFull due to reservation");
        assert_eq!(err, SwapError::QueueFull);

        // Start worker to process entries
        test_impl::start_worker();

        for h in handles {
            h.wait();
        }

        // After processing, queue should be empty
        assert_eq!(test_impl::_queue_len(), 0);
        assert_eq!(test_impl::_file_queue_len(), 0);

        // Now anon enqueue should succeed
        let frame = crate::mm::alloc_frame().expect("alloc frame");
        let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
        let h = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon).expect("enqueue ok");
        h.wait();

        // Ensure backing removed (if any)
        assert!(crate::mm::memcg::memcg_get_page_info(frame_idx).is_none());
    }

    #[test]
    fn test_token_bucket_exhaustion_and_refill() {
        // Ensure worker controlled
        stop_worker();
        for _ in 0..20 { if !is_worker_running() { break; } std::thread::sleep(std::time::Duration::from_millis(10)); }

        // Set tokens to zero to simulate exhaustion
        test_impl::set_tokens(0);

        // allocate a frame
        let frame = crate::mm::alloc_frame().expect("alloc frame");
        let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());

        // Ensure anon enqueue fails
        let err = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon).expect_err("should be QueueFull due to tokens");
        assert_eq!(err, SwapError::QueueFull);

        // Add one token and try again
        test_impl::add_tokens(1);

        // Start worker to allow processing
        start_worker();

        let h = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon).expect("enqueue ok");
        h.wait();

        // cleanup: restore tokens to capacity
        test_impl::set_tokens(test_impl::token_capacity());

        // stop worker
        stop_worker();
    }

    #[test]
    fn test_token_refill_on_processing() {
        // Stop worker to control processing
        stop_worker();
        for _ in 0..20 { if !is_worker_running() { break; } std::thread::sleep(std::time::Duration::from_millis(10)); }

        // Set tokens to zero
        test_impl::set_tokens(0);

        // Enqueue a file-backed entry to trigger processing and refill
        crate::fs::cache::init_page_cache(64 * 1024);
        let cache = crate::fs::page_cache();
        let ino = 4000u64;
        let page_num = 1u64;
        let data = alloc::vec![0u8; PAGE_SIZE_4K];
        cache.insert(ino, page_num as usize, data, PAGE_SIZE_4K as u64);
        assert!(cache.mark_dirty(ino, page_num as usize));

        let frame = crate::mm::alloc_frame().expect("alloc frame");
        let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
        crate::mm::frame_backing::track_frame_backing(frame_idx, ino, page_num);

        // Enqueue file entry
        let h = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::File { ino, page_num }).expect("enqueue ok");

        // Start worker to process and refill tokens
        start_worker();

        h.wait();

        // After processing, tokens should have been refilled
        assert!(test_impl::_token_count() > 0);

        // Clean up
        stop_worker();
    }

    #[test]
    fn test_async_swapout_stress_concurrency() {
        crate::mm::memcg::init_memcg();
        let cg = crate::mm::memcg::memcg_create(String::from("stress"), crate::mm::memcg::memcg_root()).expect("create memcg");
        crate::fs::cache::init_page_cache(64 * 1024);
        let cache = crate::fs::page_cache();

        // Slow down processing to build pressure and exercise tokens
        test_impl::set_processing_delay(2);
        test_impl::set_tokens(test_impl::token_capacity());

        start_worker();

        let threads = 32usize;
        let iters = 80usize;
        let mut joiners = Vec::new();

        for t in 0..threads {
            let cache = cache;
            let cg = cg;
            let j = std::thread::spawn(move || {
                for i in 0..iters {
                    let frame = crate::mm::alloc_frame().expect("alloc frame");
                    let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());

                    if ((i + t) % 2) == 0 {
                        // file-backed
                        assert!(crate::mm::memcg::memcg_charge(cg, 1, crate::mm::memcg::ChargeType::Cache).is_ok());
                        crate::mm::memcg::memcg_track_page(frame_idx, cg, crate::mm::memcg::ChargeType::Cache);

                        let ino = 6000u64 + (i % 256) as u64;
                        let page_num = i as u64;
                        let data = alloc::vec![0u8; PAGE_SIZE_4K];
                        cache.insert(ino, page_num as usize, data, PAGE_SIZE_4K as u64);
                        assert!(cache.mark_dirty(ino, page_num as usize));
                        crate::mm::frame_backing::track_frame_backing(frame_idx, ino, page_num);

                        match crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::File { ino, page_num }) {
                            Ok(h) => { h.wait(); }
                            Err(SwapError::QueueFull) => {
                                // fallback sync writeback
                                let _ = crate::fs::page_cache().sync_page(ino, page_num, |_offset, _data| Ok(()));
                                let physf = unsafe { PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(frame_idx.to_phys_addr())) };
                                buddy_allocator::buddy_dealloc_frame(physf);
                            }
                            Err(e) => panic!("unexpected enqueue error: {:?}", e),
                        }
                    } else {
                        // anon
                        assert!(crate::mm::memcg::memcg_charge(cg, 1, crate::mm::memcg::ChargeType::Anon).is_ok());
                        crate::mm::memcg::memcg_track_page(frame_idx, cg, crate::mm::memcg::ChargeType::Anon);

                        match crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon) {
                            Ok(h) => { h.wait(); }
                            Err(SwapError::QueueFull) => {
                                let physf = unsafe { PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(frame_idx.to_phys_addr())) };
                                buddy_allocator::buddy_dealloc_frame(physf);
                            }
                            Err(e) => panic!("unexpected enqueue error: {:?}", e),
                        }
                    }
                }
            });

            joiners.push(j);
        }

        for j in joiners {
            j.join().expect("join");
        }

        stop_worker();
        for _ in 0..200 {
            if !is_worker_running() { break; }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        let stats = crate::mm::memcg::memcg_stats(cg).expect("stats");
        assert_eq!(stats.cache_pages, 0);
        assert_eq!(stats.anon_pages, 0);
    }

    #[test]
    #[ignore]
    fn test_async_swapout_heavy_stress() {
        crate::mm::memcg::init_memcg();
        let cg = crate::mm::memcg::memcg_create(String::from("heavy"), crate::mm::memcg::memcg_root()).expect("create memcg");
        crate::fs::cache::init_page_cache(64 * 1024);
        let cache = crate::fs::page_cache();

        test_impl::set_processing_delay(5);
        test_impl::set_tokens(test_impl::token_capacity());

        start_worker();

        let threads = 64usize;
        let iters = 200usize;
        let mut joiners = Vec::new();

        for t in 0..threads {
            let cache = cache;
            let cg = cg;
            let j = std::thread::spawn(move || {
                for i in 0..iters {
                    let frame = crate::mm::alloc_frame().expect("alloc frame");
                    let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
                    if ((i + t) % 2) == 0 {
                        assert!(crate::mm::memcg::memcg_charge(cg, 1, crate::mm::memcg::ChargeType::Cache).is_ok());
                        crate::mm::memcg::memcg_track_page(frame_idx, cg, crate::mm::memcg::ChargeType::Cache);
                        let ino = 7000u64 + (i % 512) as u64;
                        let page_num = i as u64;
                        let data = alloc::vec![0u8; PAGE_SIZE_4K];
                        cache.insert(ino, page_num as usize, data, PAGE_SIZE_4K as u64);
                        assert!(cache.mark_dirty(ino, page_num as usize));
                        crate::mm::frame_backing::track_frame_backing(frame_idx, ino, page_num);
                        match crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::File { ino, page_num }) {
                            Ok(h) => { h.wait(); }
                            Err(SwapError::QueueFull) => {
                                let _ = crate::fs::page_cache().sync_page(ino, page_num, |_o, _d| Ok(()));
                                let physf = unsafe { PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(frame_idx.to_phys_addr())) };
                                buddy_allocator::buddy_dealloc_frame(physf);
                            }
                            Err(e) => panic!("unexpected enqueue error: {:?}", e),
                        }
                    } else {
                        assert!(crate::mm::memcg::memcg_charge(cg, 1, crate::mm::memcg::ChargeType::Anon).is_ok());
                        crate::mm::memcg::memcg_track_page(frame_idx, cg, crate::mm::memcg::ChargeType::Anon);
                        match crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon) {
                            Ok(h) => { h.wait(); }
                            Err(SwapError::QueueFull) => {
                                let physf = unsafe { PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(frame_idx.to_phys_addr())) };
                                buddy_allocator::buddy_dealloc_frame(physf);
                            }
                            Err(e) => panic!("unexpected enqueue error: {:?}", e),
                        }
                    }
                }
            });
            joiners.push(j);
        }

        for j in joiners { j.join().expect("join"); }

        stop_worker();
        for _ in 0..500 { if !is_worker_running() { break; } std::thread::sleep(std::time::Duration::from_millis(10)); }

        let stats = crate::mm::memcg::memcg_stats(cg).expect("stats");
        assert_eq!(stats.cache_pages, 0);
        assert_eq!(stats.anon_pages, 0);
    }

    #[test]
    #[ignore]
    fn bench_enqueue_throughput() {
        crate::fs::cache::init_page_cache(64 * 1024);

        test_impl::set_processing_delay(1);
        test_impl::set_tokens(test_impl::token_capacity());

        start_worker();

        let count = 2000usize;
        let start = std::time::Instant::now();
        for _ in 0..count {
            let frame = crate::mm::alloc_frame().expect("alloc frame");
            let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
            let h = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon).expect("enqueue ok");
            h.wait();
        }
        let dur = start.elapsed();
        println!("Enqueued+processed {} anon entries in {:?}", count, dur);

        stop_worker();
    }
}


