// ============================================================================
// src/io/nvme/io_queue.rs - Shared NVMe Queue Management
// ============================================================================
//!
//! # 共有可能な `NVMe` I/O キュー管理
//!
//! キャッシュライン整列された hardware queue と統計を管理する。
//!
//! ## 特徴
//! - 64バイトキャッシュライン整列（偽共有防止）
//! - 初期化時に一度だけ設定される queue pair
//! - ドアベルバッチ処理
//! - 詳細な統計収集

// QueuePair is installed once before publication and remains immutable thereafter.
#![allow(clippy::mut_from_ref)]
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use super::commands::{NvmeCommand, NvmeCompletion};
use super::defs::{DOORBELL_BATCH_THRESHOLD, SECTOR_SIZE, SglDescriptor};
use super::queue::QueuePair;
use super::requests::PendingRequests;
use crate::sync::IrqMutex;
use alloc::sync::Arc;
use core::task::Waker;

// ============================================================================
// Queue Statistics
// ============================================================================

/// キュー統計（キャッシュライン整列）
#[repr(C, align(64))]
#[derive(Debug, Default)]
pub struct NvmeQueueStats {
    pub commands_submitted: AtomicU64,
    pub commands_completed: AtomicU64,
    pub read_bytes: AtomicU64,
    pub write_bytes: AtomicU64,
    pub errors: AtomicU64,
    pub poll_cycles: AtomicU64,
    pub doorbell_writes: AtomicU64,
    pub batched_commands: AtomicU64,
    _padding: [u8; 0], // 64バイト境界にパディング
}

// ============================================================================
// Deferred Completion Storage
// ============================================================================

const MAX_ISR_COMPLETIONS_PER_PASS: usize = 64;
const DEFERRED_COMPLETION_QUEUE_SIZE: usize = 256;

#[derive(Clone, Copy)]
struct DeferredCompletion {
    cid: u16,
    cqe: NvmeCompletion,
}

struct DeferredCompletionQueue {
    entries: [Option<DeferredCompletion>; DEFERRED_COMPLETION_QUEUE_SIZE],
    head: usize,
    tail: usize,
    len: usize,
}

impl DeferredCompletionQueue {
    const fn new() -> Self {
        const NONE: Option<DeferredCompletion> = None;
        Self {
            entries: [NONE; DEFERRED_COMPLETION_QUEUE_SIZE],
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    fn push(&mut self, entry: DeferredCompletion) -> bool {
        if self.len >= DEFERRED_COMPLETION_QUEUE_SIZE {
            return false;
        }

        self.entries[self.tail] = Some(entry);
        self.tail = (self.tail + 1) % DEFERRED_COMPLETION_QUEUE_SIZE;
        self.len += 1;
        true
    }

    fn pop(&mut self) -> Option<DeferredCompletion> {
        if self.len == 0 {
            return None;
        }

        let entry = self.entries[self.head].take();
        self.head = (self.head + 1) % DEFERRED_COMPLETION_QUEUE_SIZE;
        self.len -= 1;
        entry
    }

    fn is_full(&self) -> bool {
        self.len >= DEFERRED_COMPLETION_QUEUE_SIZE
    }
}

// ============================================================================
// Hardware I/O Queue
// ============================================================================

/// NVMe hardware I/O queue（キャッシュライン整列）
///
/// 64バイトアラインメントにより、異なる CPU 間での
/// 偽共有（false sharing）を防止し、キャッシュ効率を最大化。
///
/// QueuePair is installed before publication. SQ/CQ mutation is serialized in
/// the queue implementation so this object can be reassigned as CPUs change.
#[repr(C, align(64))]
pub struct NvmeIoQueue {
    /// キューペア（UnsafeCellでロックフリーアクセス）
    inner: UnsafeCell<Option<QueuePair>>,
    /// Zero-based index in the controller's I/O queue collection.
    queue_index: u32,
    /// 初期化完了フラグ
    initialized: AtomicBool,
    /// ドアベルバッチカウンタ（保留中のコマンド数）
    pending_commands: AtomicU32,
    /// 統計（別キャッシュライン）
    stats: NvmeQueueStats,
    /// Pending Requests for Async I/O (ISR-safe)
    pending_requests: Arc<IrqMutex<PendingRequests>>,
    /// Serializes CID allocation, SQ publication, and pending registration.
    submission_lock: IrqMutex<()>,
    /// IRQで拾った完了を通常文脈へ渡す固定長キュー
    deferred_completions: IrqMutex<DeferredCompletionQueue>,
}

// SAFETY: QueuePair is written only during initialization and published by
// `initialized`; subsequent SQ/CQ mutation is internally synchronized.
unsafe impl Sync for NvmeIoQueue {}
unsafe impl Send for NvmeIoQueue {}

impl NvmeIoQueue {
    /// 新しい hardware I/O queue を作成する。
    pub fn new(queue_index: u32) -> Self {
        Self {
            inner: UnsafeCell::new(None),
            queue_index,
            initialized: AtomicBool::new(false),
            pending_commands: AtomicU32::new(0),
            stats: NvmeQueueStats {
                commands_submitted: AtomicU64::new(0),
                commands_completed: AtomicU64::new(0),
                read_bytes: AtomicU64::new(0),
                write_bytes: AtomicU64::new(0),
                errors: AtomicU64::new(0),
                poll_cycles: AtomicU64::new(0),
                doorbell_writes: AtomicU64::new(0),
                batched_commands: AtomicU64::new(0),
                _padding: [],
            },
            pending_requests: Arc::new(IrqMutex::new(PendingRequests::new())),
            submission_lock: IrqMutex::new(()),
            deferred_completions: IrqMutex::new(DeferredCompletionQueue::new()),
        }
    }

    /// キューペアを設定（初期化時のみ呼び出し）
    ///
    /// # Safety
    /// 初期化中にのみ呼び出すこと。他のスレッドから同時アクセスがないことを保証。
    pub unsafe fn set_queue_pair(&self, qp: QueuePair) {
        let ptr = self.inner.get();
        unsafe { (*ptr) = Some(qp) };
        self.initialized.store(true, Ordering::Release);
    }

    /// キューが初期化済みかチェック
    #[inline]
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }

    /// Returns the queue pair after initialization publication.
    ///
    /// # Safety
    /// `set_queue_pair` must have completed before this method is called.
    #[inline]
    pub(crate) unsafe fn get_queue_pair(&self) -> Option<&QueuePair> {
        unsafe { (*self.inner.get()).as_ref() }
    }

    /// 読み取り操作を発行（ドアベルバッチ対応）
    ///
    /// # Safety
    /// PRP が controller からアクセス可能で、command completion まで有効であること。
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the required device state cannot be read.
    pub unsafe fn read(
        &self,
        nsid: u32,
        lba: u64,
        blocks: u16,
        prp1: u64,
        prp2: u64,
    ) -> Result<u16, &'static str> {
        let _submission = self.submission_lock.lock();
        let qp = unsafe { self.get_queue_pair() }.ok_or("Queue not initialized")?;

        // CIDはSQのtailから取得
        let cid = qp.sq().tail();
        let cmd = NvmeCommand::read(cid, nsid, lba, blocks, prp1, prp2);
        let _tail = qp.submit_no_doorbell(&cmd)?;

        // Register pending request BEFORE doorbell to avoid missing completions
        {
            let mut pending = self.pending_requests.lock();
            let _ = pending.register(cid, qp.sq().qid());
        }

        self.stats
            .commands_submitted
            .fetch_add(1, Ordering::Relaxed);
        self.stats
            .read_bytes
            .fetch_add((blocks as u64) * (SECTOR_SIZE as u64), Ordering::Relaxed);

        // バッチカウンタをインクリメント
        let pending = self.pending_commands.fetch_add(1, Ordering::Relaxed) + 1;

        // 閾値を超えたらドアベルをフラッシュ
        if pending >= DOORBELL_BATCH_THRESHOLD as u32 {
            self.flush_doorbell_locked();
        }

        Ok(cid)
    }

    /// 読み取り操作を発行（SGL）
    ///
    /// # Safety
    /// SGL が controller からアクセス可能な valid descriptor であること。
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the required device state cannot be read.
    pub unsafe fn read_sgl(
        &self,
        nsid: u32,
        lba: u64,
        blocks: u16,
        sgl: SglDescriptor,
    ) -> Result<u16, &'static str> {
        let _submission = self.submission_lock.lock();
        let qp = unsafe { self.get_queue_pair() }.ok_or("Queue not initialized")?;

        let cid = qp.sq().tail();
        let cmd = NvmeCommand::read_sgl(cid, nsid, lba, blocks, sgl);
        let _tail = qp.submit_no_doorbell(&cmd)?;

        {
            let mut pending = self.pending_requests.lock();
            let _ = pending.register(cid, qp.sq().qid());
        }

        self.stats
            .commands_submitted
            .fetch_add(1, Ordering::Relaxed);
        self.stats
            .read_bytes
            .fetch_add((blocks as u64) * (SECTOR_SIZE as u64), Ordering::Relaxed);

        let pending = self.pending_commands.fetch_add(1, Ordering::Relaxed) + 1;
        if pending >= DOORBELL_BATCH_THRESHOLD as u32 {
            self.flush_doorbell_locked();
        }

        Ok(cid)
    }

    /// 読み取り操作を即時発行（ドアベルを即座に書き込み）
    ///
    /// # Safety
    /// PRP が controller からアクセス可能で、command completion まで有効であること。
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the required device state cannot be read.
    pub unsafe fn read_immediate(
        &self,
        nsid: u32,
        lba: u64,
        blocks: u16,
        prp1: u64,
        prp2: u64,
    ) -> Result<u16, &'static str> {
        let _submission = self.submission_lock.lock();
        let qp = unsafe { self.get_queue_pair() }.ok_or("Queue not initialized")?;

        // CIDはSQのtailから取得
        let cid = qp.sq().tail();
        let cmd = NvmeCommand::read(cid, nsid, lba, blocks, prp1, prp2);
        let _tail = qp.submit_no_doorbell(&cmd)?;
        qp.sq().ring_doorbell();

        self.stats
            .commands_submitted
            .fetch_add(1, Ordering::Relaxed);
        self.stats
            .read_bytes
            .fetch_add((blocks as u64) * (SECTOR_SIZE as u64), Ordering::Relaxed);
        self.stats.doorbell_writes.fetch_add(1, Ordering::Relaxed);

        Ok(cid)
    }

    /// 書き込み操作を発行（ドアベルバッチ対応）
    ///
    /// # Safety
    /// PRP が controller からアクセス可能で、command completion まで有効であること。
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the device cannot accept the operation.
    pub unsafe fn write(
        &self,
        nsid: u32,
        lba: u64,
        blocks: u16,
        prp1: u64,
        prp2: u64,
    ) -> Result<u16, &'static str> {
        let _submission = self.submission_lock.lock();
        let qp = unsafe { self.get_queue_pair() }.ok_or("Queue not initialized")?;

        // CIDはSQのtailから取得
        let cid = qp.sq().tail();
        let cmd = NvmeCommand::write(cid, nsid, lba, blocks, prp1, prp2);
        let _tail = qp.submit_no_doorbell(&cmd)?;

        // Register pending request BEFORE doorbell
        {
            let mut pending = self.pending_requests.lock();
            let _ = pending.register(cid, qp.sq().qid());
        }

        self.stats
            .commands_submitted
            .fetch_add(1, Ordering::Relaxed);
        self.stats
            .write_bytes
            .fetch_add((blocks as u64) * (SECTOR_SIZE as u64), Ordering::Relaxed);

        // バッチカウンタをインクリメント
        let pending = self.pending_commands.fetch_add(1, Ordering::Relaxed) + 1;

        // 閾値を超えたらドアベルをフラッシュ
        if pending >= DOORBELL_BATCH_THRESHOLD as u32 {
            self.flush_doorbell_locked();
        }

        Ok(cid)
    }

    /// 書き込み操作を発行（SGL）
    ///
    /// # Safety
    /// SGL が controller からアクセス可能な valid descriptor であること。
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the device cannot accept the operation.
    pub unsafe fn write_sgl(
        &self,
        nsid: u32,
        lba: u64,
        blocks: u16,
        sgl: SglDescriptor,
    ) -> Result<u16, &'static str> {
        let _submission = self.submission_lock.lock();
        let qp = unsafe { self.get_queue_pair() }.ok_or("Queue not initialized")?;

        let cid = qp.sq().tail();
        let cmd = NvmeCommand::write_sgl(cid, nsid, lba, blocks, sgl);
        let _tail = qp.submit_no_doorbell(&cmd)?;

        {
            let mut pending = self.pending_requests.lock();
            let _ = pending.register(cid, qp.sq().qid());
        }

        self.stats
            .commands_submitted
            .fetch_add(1, Ordering::Relaxed);
        self.stats
            .write_bytes
            .fetch_add((blocks as u64) * (SECTOR_SIZE as u64), Ordering::Relaxed);

        let pending = self.pending_commands.fetch_add(1, Ordering::Relaxed) + 1;
        if pending >= DOORBELL_BATCH_THRESHOLD as u32 {
            self.flush_doorbell_locked();
        }

        Ok(cid)
    }

    /// フラッシュコマンドを発行
    ///
    /// # Safety
    /// Queue pair initialization must remain valid for the operation.
    /// # Errors
    ///
    /// Returns an error if the device is not ready, times out, or reports a failed completion.
    pub unsafe fn flush(&self, nsid: u32) -> Result<u16, &'static str> {
        let _submission = self.submission_lock.lock();
        let qp = unsafe { self.get_queue_pair() }.ok_or("Queue not initialized")?;

        let cid = qp.sq().tail();
        let cmd = NvmeCommand::flush(cid, nsid);
        let _tail = qp.submit_no_doorbell(&cmd)?;

        {
            let mut pending = self.pending_requests.lock();
            let _ = pending.register(cid, qp.sq().qid());
        }

        self.stats
            .commands_submitted
            .fetch_add(1, Ordering::Relaxed);

        let pending = self.pending_commands.fetch_add(1, Ordering::Relaxed) + 1;
        if pending >= DOORBELL_BATCH_THRESHOLD as u32 {
            self.flush_doorbell_locked();
        }

        Ok(cid)
    }

    /// Dataset Management (TRIM) コマンドを発行
    ///
    /// # Safety
    /// `prp1` が controller からアクセス可能で、command completion まで有効であること。
    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the device operation fails.
    pub unsafe fn dataset_management(
        &self,
        nsid: u32,
        nr: u8,
        prp1: u64,
    ) -> Result<u16, &'static str> {
        let _submission = self.submission_lock.lock();
        let qp = unsafe { self.get_queue_pair() }.ok_or("Queue not initialized")?;

        let cid = qp.sq().tail();
        let cmd = NvmeCommand::dataset_management(cid, nsid, nr, prp1);
        let _tail = qp.submit_no_doorbell(&cmd)?;

        {
            let mut pending = self.pending_requests.lock();
            let _ = pending.register(cid, qp.sq().qid());
        }

        self.stats
            .commands_submitted
            .fetch_add(1, Ordering::Relaxed);

        let pending = self.pending_commands.fetch_add(1, Ordering::Relaxed) + 1;
        if pending >= DOORBELL_BATCH_THRESHOLD as u32 {
            self.flush_doorbell_locked();
        }

        Ok(cid)
    }

    /// 書き込み操作を即時発行（ドアベルを即座に書き込み）
    ///
    /// # Safety
    /// PRP が controller からアクセス可能で、command completion まで有効であること。
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the device cannot accept the operation.
    pub unsafe fn write_immediate(
        &self,
        nsid: u32,
        lba: u64,
        blocks: u16,
        prp1: u64,
        prp2: u64,
    ) -> Result<u16, &'static str> {
        let _submission = self.submission_lock.lock();
        let qp = unsafe { self.get_queue_pair() }.ok_or("Queue not initialized")?;

        // CIDはSQのtailから取得
        let cid = qp.sq().tail();
        let cmd = NvmeCommand::write(cid, nsid, lba, blocks, prp1, prp2);
        let _tail = qp.submit_no_doorbell(&cmd)?;
        qp.sq().ring_doorbell();

        self.stats
            .commands_submitted
            .fetch_add(1, Ordering::Relaxed);
        self.stats
            .write_bytes
            .fetch_add((blocks as u64) * (SECTOR_SIZE as u64), Ordering::Relaxed);
        self.stats.doorbell_writes.fetch_add(1, Ordering::Relaxed);

        Ok(cid)
    }

    /// 保留中のコマンドをフラッシュ（ドアベル書き込み）
    ///
    /// # Safety
    /// Queue pair initialization must remain valid for the operation.
    pub unsafe fn flush_doorbell(&self) {
        let _submission = self.submission_lock.lock();
        self.flush_doorbell_locked();
    }

    fn flush_doorbell_locked(&self) {
        if let Some(qp) = unsafe { self.get_queue_pair() } {
            let pending = self.pending_commands.swap(0, Ordering::Relaxed);
            if pending > 0 {
                qp.sq().ring_doorbell();
                self.stats.doorbell_writes.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .batched_commands
                    .fetch_add(pending as u64, Ordering::Relaxed);
            }
        }
    }

    /// 完了をポーリング
    ///
    /// # Safety
    /// Queue pair initialization must remain valid for the operation.
    pub unsafe fn poll(&self) -> Option<NvmeCompletion> {
        let qp = unsafe { self.get_queue_pair() }?;

        self.stats.poll_cycles.fetch_add(1, Ordering::Relaxed);

        if let Some(cqe) = qp.poll_completion() {
            self.stats
                .commands_completed
                .fetch_add(1, Ordering::Relaxed);
            if !cqe.is_success() {
                self.stats.errors.fetch_add(1, Ordering::Relaxed);
            }
            Some(cqe)
        } else {
            None
        }
    }

    /// バッチポーリング（複数の完了を一度に処理）
    ///
    /// # Safety
    /// Queue pair initialization must remain valid for the operation.
    pub unsafe fn poll_batch(&self, max_completions: usize) -> Vec<NvmeCompletion> {
        let mut completions = Vec::with_capacity(max_completions);

        for _ in 0..max_completions {
            if let Some(cqe) = unsafe { self.poll() } {
                completions.push(cqe);
            } else {
                break;
            }
        }

        completions
    }

    /// 高性能ポーリングループ（PAUSE命令による効率化）
    ///
    /// # Safety
    /// Queue pair initialization must remain valid for the operation.
    pub unsafe fn poll_spin(&self, max_spins: u32) -> Option<NvmeCompletion> {
        for _ in 0..max_spins {
            if let Some(cqe) = unsafe { self.poll() } {
                return Some(cqe);
            }
            // PAUSE命令でCPUリソースを節約
            // Use target_feature guard for SSE intrinsics on soft-float targets
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            core::arch::x86_64::_mm_pause();
            #[cfg(not(all(target_arch = "x86_64", target_feature = "sse2")))]
            core::hint::spin_loop();
        }
        None
    }

    /// 統計を取得
    pub fn stats(&self) -> &NvmeQueueStats {
        &self.stats
    }

    /// Zero-based hardware queue index.
    pub fn queue_index(&self) -> u32 {
        self.queue_index
    }

    /// 保留中のコマンド数を取得
    pub fn pending_commands(&self) -> u32 {
        self.pending_commands.load(Ordering::Relaxed)
    }

    /// Wakerを登録（非同期I/O用）
    pub fn register_waker(&self, cid: u16, waker: Waker) {
        let wake = {
            let mut pending = self.pending_requests.lock();
            pending.set_waker(cid, waker)
        };
        if let Some(waker) = wake {
            waker.wake();
        }
    }

    /// 完了を確認（ISRが処理済みのものを取得）
    pub fn check_completion(&self, cid: u16) -> Option<NvmeCompletion> {
        self.pending_requests.lock().check_completion(cid)
    }

    /// 完了を取得してペンディングから削除
    pub fn take_completion(&self, cid: u16) -> Option<NvmeCompletion> {
        let mut pending = self.pending_requests.lock();
        pending.take(cid).and_then(|req| req.result().cloned())
    }

    /// 保留中のリクエストマップを取得（ISR用）
    pub fn get_pending_requests(&self) -> Arc<IrqMutex<PendingRequests>> {
        self.pending_requests.clone()
    }

    /// 完了を処理（ISRコンテキスト対応）
    ///
    /// # Safety
    /// ISRから呼び出されることを想定。
    /// QueuePairのCQのみを操作するため、SQ操作中のメインスレッドと競合しない。
    pub unsafe fn process_completions(&self) -> usize {
        let qp_ptr = self.inner.get();
        // lock-free check: if None, can't poll
        let qp_opt = unsafe { &*qp_ptr };

        let mut count = 0;

        if let Some(qp) = qp_opt {
            let mut deferred = self.deferred_completions.lock();
            // LOOP_PROOF: mode=condition; reason=ISR completion loop is capped per pass and exits on empty CQ or MAX_ISR_COMPLETIONS_PER_PASS.;
            while count < MAX_ISR_COMPLETIONS_PER_PASS && !deferred.is_full() {
                let Some(cqe) = qp.poll_completion() else {
                    break;
                };
                self.stats
                    .commands_completed
                    .fetch_add(1, Ordering::Relaxed);
                if !cqe.is_success() {
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                }

                let cid = cqe.command_id();
                if !deferred.push(DeferredCompletion { cid, cqe }) {
                    break;
                }

                count += 1;
            }
        }
        count
    }

    pub fn process_deferred_completions(&self) -> usize {
        let mut count = 0usize;

        // LOOP_PROOF: mode=event; reason=Deferred completion drain exits when the queue becomes empty for this processing pass.;
        loop {
            let completion = {
                let mut deferred = self.deferred_completions.lock();
                deferred.pop()
            };

            let Some(DeferredCompletion { cid, cqe }) = completion else {
                break;
            };

            let mut pending = self.pending_requests.lock();
            let _ = pending.complete(cid, cqe);
            count += 1;
        }

        count
    }
}

/// NVMe Interrupt Handler (ISR context)
pub fn irq_handler() {
    // Kernel-owned interrupt routing dispatches deferred completions without a
    // driver-local CPU identity registry.
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::task::Wake;
    use core::sync::atomic::{AtomicUsize, Ordering};

    struct CountingWaker {
        wakes: AtomicUsize,
    }

    impl CountingWaker {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                wakes: AtomicUsize::new(0),
            })
        }

        fn observed(&self) -> usize {
            self.wakes.load(Ordering::Acquire)
        }
    }

    impl Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::AcqRel);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[test]
    fn deferred_completion_only_wakes_on_drain() {
        let queue = NvmeIoQueue::new(0);
        let waker = CountingWaker::new();
        let cid = 7u16;

        {
            let mut pending = queue.pending_requests.lock();
            pending.register(cid, 1).expect("register request");
            assert!(
                pending.set_waker(cid, Waker::from(waker.clone())).is_none(),
                "request should remain pending until deferred drain",
            );
        }

        {
            let mut deferred = queue.deferred_completions.lock();
            assert!(deferred.push(DeferredCompletion {
                cid,
                cqe: NvmeCompletion {
                    result: 0,
                    rsvd: 0,
                    sq_head: 0,
                    sq_id: 1,
                    cid,
                    status: 0,
                },
            }));
        }

        assert_eq!(waker.observed(), 0);
        assert!(queue.check_completion(cid).is_none());

        assert_eq!(queue.process_deferred_completions(), 1);
        assert_eq!(waker.observed(), 1);
        assert!(queue.check_completion(cid).is_some());
    }

    #[test]
    fn shared_queue_serializes_cid_allocation_and_publication() {
        const DEPTH: usize = 16;
        let mut submission_entries = Box::new([NvmeCommand::default(); DEPTH]);
        let mut completion_entries = Box::new([NvmeCompletion::default(); DEPTH]);
        let mut submission_doorbell = Box::new(0u32);
        let mut completion_doorbell = Box::new(0u32);

        let queue_pair = unsafe {
            QueuePair::new(
                submission_entries.as_mut_ptr(),
                completion_entries.as_mut_ptr(),
                DEPTH as u16,
                submission_doorbell.as_mut() as *mut u32,
                completion_doorbell.as_mut() as *mut u32,
                1,
            )
        };
        let queue = Arc::new(NvmeIoQueue::new(0));
        unsafe { queue.set_queue_pair(queue_pair) };

        let first_queue = queue.clone();
        let first = std::thread::spawn(move || unsafe { first_queue.flush(1) });
        let second_queue = queue.clone();
        let second = std::thread::spawn(move || unsafe { second_queue.flush(1) });

        let mut cids = [
            first.join().unwrap().unwrap(),
            second.join().unwrap().unwrap(),
        ];
        cids.sort_unstable();
        assert_eq!(cids, [0, 1]);
        assert_eq!(submission_entries[0].cid(), 0);
        assert_eq!(submission_entries[1].cid(), 1);
    }
}
