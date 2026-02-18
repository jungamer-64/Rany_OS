use super::*;



// カーネル向け実装: 永続ワーカ（non-test）
#[cfg(any(not(test), feature = "full_mm_tests"))]
pub(crate) mod kernel_impl {
    use super::*;
    use alloc::vec::Vec;
    use spin::Once;
    use crate::sync::lockfree::{BoundedChannel, BoundedSender, BoundedReceiver};
    use crate::sync::AtomicWaker;
    use crate::task::Task;
    use crate::mm::meta::page_flags::{self, PageMetaFlags};

    // Channel capacity and batch size tunables
    pub(super) const CHANNEL_SIZE: usize = 1024;
    pub(super) const BATCH_SIZE: usize = 32;

    #[derive(Clone, Copy)]
    pub(super) struct SwapEntryKernel {
        frame: FrameIndex,
        kind: SwapKind,
    }

    // Static channel (initialized once)
    pub(super) static CHANNEL_ONCE: Once<Option<(BoundedSender<SwapEntryKernel, CHANNEL_SIZE>, BoundedReceiver<SwapEntryKernel, CHANNEL_SIZE>)>> = Once::new();

    // Pending set is replaced by GlobalPageFlags

    // Queue occupancy counters (for reservation of file slots)
    use core::sync::atomic::{AtomicUsize, Ordering};
    pub(super) static QUEUE_COUNT: AtomicUsize = AtomicUsize::new(0);
    pub(super) static FILE_QUEUE_COUNT: AtomicUsize = AtomicUsize::new(0);
    // Reserve some slots for file writes so heavy anon traffic cannot starve file writebacks
    pub(super) const RESERVED_FILE_SLOTS: usize = CHANNEL_SIZE / 8; // reserve ~12.5% for file writes
    // Token-bucket backpressure (anonymous pages)
    // - TOKEN_BUCKET_CAPACITY: Burst capacity for anon enqueues. Larger value allows absorbing transient spikes
    //   but increases risk of anon traffic delaying file writebacks.
    // - TOKEN_REFILL_PER_BATCH: Amount of tokens restored per processed batch. Controls long-term sustained rate.
    pub(super) const TOKEN_BUCKET_CAPACITY: usize = CHANNEL_SIZE / 4; // anonymous burst capacity
    pub(super) const TOKEN_REFILL_PER_BATCH: usize = BATCH_SIZE / 2;

    // Runtime-adjustable parameters (Atomics allow tuning without recompilation)
    pub(super) static RESERVED_FILE_SLOTS_ATOMIC: AtomicUsize = AtomicUsize::new(RESERVED_FILE_SLOTS);
    pub(super) static TOKEN_BUCKET_CAPACITY_ATOMIC: AtomicUsize = AtomicUsize::new(TOKEN_BUCKET_CAPACITY);
    pub(super) static TOKEN_REFILL_PER_BATCH_ATOMIC: AtomicUsize = AtomicUsize::new(TOKEN_REFILL_PER_BATCH);

    pub(super) static TOKENS: AtomicUsize = AtomicUsize::new(TOKEN_BUCKET_CAPACITY);
    // Worker waker and running flags
    pub(super) static WORKER_WAKER: AtomicWaker = AtomicWaker::new();
    pub(super) static WORKER_RUNNING: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    pub(super) static WORKER_SHUTDOWN: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

    pub(super) fn ensure_channel_started() {
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
    pub(super) struct WaitForWork;
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

    pub(super) async fn worker_loop() {
        // reuse buffer to avoid per-page allocations
        let mut reuse_buf = buffer_pool_get_4k();
        loop {
            WaitForWork.await;

            if should_shutdown() {
                break;
            }

            let batch = drain_batch();

            // Process batch
            for entry in batch {
                process_swap_entry(entry, &mut reuse_buf);
            }

            // Refill token bucket after processing batch
            add_tokens(TOKEN_REFILL_PER_BATCH_ATOMIC.load(Ordering::Acquire));

            if should_shutdown() {
                break;
            }
        }
    }

    /// Check if the worker should shut down (shutdown requested and channel empty).
    pub(super) fn should_shutdown() -> bool {
        if !WORKER_SHUTDOWN.load(core::sync::atomic::Ordering::Acquire) {
            return false;
        }
        let channel_empty = CHANNEL_ONCE
            .get()
            .and_then(|opt| opt.as_ref())
            .map_or(true, |ch| ch.1.is_empty());
        if channel_empty {
            WORKER_RUNNING.store(false, core::sync::atomic::Ordering::Release);
        }
        channel_empty
    }

    /// Drain up to BATCH_SIZE entries from the channel.
    pub(super) fn drain_batch() -> Vec<SwapEntryKernel> {
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
        batch
    }

    /// Process a single swap entry (file or anon).
    pub(super) fn process_swap_entry(entry: SwapEntryKernel, reuse_buf: &mut Vec<u8>) {
        match entry.kind {
            SwapKind::File { ino, page_num } => {
                process_file_swap(entry.frame, ino, page_num);
                page_flags::clear_flag(entry.frame, PageMetaFlags::SwapPending);
                atomic_saturating_decrement(&QUEUE_COUNT);
                atomic_saturating_decrement(&FILE_QUEUE_COUNT);
            }
            SwapKind::Anon => {
                if try_zswap_store_and_dealloc_any(entry.frame, reuse_buf) {
                    crate::mm::reclaim::page_reclaim::notify_async_swapout_success(entry.frame);
                } else {
                    log::warn!("zswap store failed during anon swapout for frame {:?}", entry.frame);
                    crate::mm::reclaim::page_reclaim::notify_async_swapout_failure(entry.frame);
                }
                page_flags::clear_flag(entry.frame, PageMetaFlags::SwapPending);
                atomic_saturating_decrement(&QUEUE_COUNT);
            }
        }
    }

    /// Process a file swapout entry.
    pub(super) fn process_file_swap(frame: FrameIndex, ino: u64, page_num: u64) {
        let written = crate::fs::page_cache().sync_page(ino, page_num, |offset, data| {
            match crate::fs::write_inode_by_number(ino, offset, data) {
                Ok(_) => Ok(()),
                Err(_) => Err(()),
            }
        });

        match written {
            Ok(true) => {
                release_frame_and_untrack(frame);
                crate::mm::reclaim::page_reclaim::notify_async_swapout_success(frame);
            }
            _ => {
                if crate::fs::page_cache().sync_all(|ino, offset, data| {
                    match crate::fs::write_inode_by_number(ino, offset, data) {
                        Ok(_) => Ok(()),
                        Err(_) => Err(()),
                    }
                }).unwrap_or(0) > 0 {
                    release_frame_and_untrack(frame);
                    crate::mm::reclaim::page_reclaim::notify_async_swapout_success(frame);
                } else {
                    crate::mm::reclaim::page_reclaim::PAGE_RECLAIM.account_writeback_skipped();
                    crate::mm::reclaim::page_reclaim::notify_async_swapout_failure(frame);
                }
            }
        }
    }

    pub(super) fn try_consume_token() -> bool {
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

    pub(super) fn add_tokens(n: usize) {
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



    /// Check channel capacity and anon-specific reservation/token constraints.
    /// Returns `true` if the anon token was consumed (must be restored on send failure).
    pub(super) fn check_anon_constraints(
        sender: &BoundedSender<SwapEntryKernel, CHANNEL_SIZE>,
        frame: FrameIndex,
        kind: &SwapKind,
    ) -> Result<bool, SwapError> {
        if sender.is_full() {
            page_flags::clear_flag(frame, PageMetaFlags::SwapPending);
            return Err(SwapError::QueueFull);
        }

        if let SwapKind::Anon = kind {
            let total = QUEUE_COUNT.load(Ordering::Acquire);
            let free_slots = CHANNEL_SIZE.saturating_sub(total);
            let reserved = RESERVED_FILE_SLOTS_ATOMIC.load(Ordering::Acquire);
            if free_slots <= reserved {
                page_flags::clear_flag(frame, PageMetaFlags::SwapPending);
                return Err(SwapError::QueueFull);
            }
            if !try_consume_token() {
                page_flags::clear_flag(frame, PageMetaFlags::SwapPending);
                return Err(SwapError::QueueFull);
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn try_enqueue(frame: FrameIndex, kind: SwapKind) -> Result<super::SwapHandle, SwapError> {
        ensure_channel_started();

        // If worker has been stopped, not supported
        if !WORKER_RUNNING.load(core::sync::atomic::Ordering::Acquire) {
            return Err(SwapError::NotSupported);
        }

        // Fast-path: try to set pending flag (atomic)
        if page_flags::test_and_set_flag(frame, PageMetaFlags::SwapPending) {
             // Already set
             return Err(SwapError::AlreadyPending);
        }

        // Check sender capacity
        if let Some(ch) = CHANNEL_ONCE.get().and_then(|opt| opt.as_ref()) {
            let sender = &ch.0;
            let token_consumed = check_anon_constraints(sender, frame, &kind)?;

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
                    page_flags::clear_flag(frame, PageMetaFlags::SwapPending);
                    Err(SwapError::QueueFull)
                }
            }
        } else {
            page_flags::clear_flag(frame, PageMetaFlags::SwapPending);
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
