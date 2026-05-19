// ============================================================================
// src/io/nvme/per_core.rs - Per-Core NVMe Queue Management
// ============================================================================
//!
//! # コアごとの`NVMe`キュー管理
//!
//! キャッシュライン整列されたコアローカルキューと統計管理。
//! ロックフリーアクセスで最大スループットを実現。
//!
//! ## 特徴
//! - 64バイトキャッシュライン整列（偽共有防止）
//! - `UnsafeCell`によるロックフリーアクセス
//! - ドアベルバッチ処理
//! - 詳細な統計収集

// Allow mutable borrow from &self - intentional for per-core lock-free access.
// Each core exclusively owns its queue via core affinity (single-threaded access guarantee).
#![allow(clippy::mut_from_ref)]
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering};

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
// Global Registry for ISR Access
// ============================================================================

const MAX_CORES: usize = 256;
static QUEUES: [AtomicPtr<PerCoreNvmeQueue>; MAX_CORES] =
    [const { AtomicPtr::new(ptr::null_mut()) }; MAX_CORES];
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

/// ISR用にキューを登録
pub fn register_queue(core_id: u32, queue: &PerCoreNvmeQueue) {
    if (core_id as usize) < MAX_CORES {
        QUEUES[core_id as usize].store(queue as *const _ as *mut _, Ordering::Release);
    }
}

pub fn queue_for_core(core_id: u32) -> Option<&'static PerCoreNvmeQueue> {
    if (core_id as usize) >= MAX_CORES {
        return None;
    }
    let ptr = QUEUES[core_id as usize].load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &*ptr })
    }
}

// ============================================================================
// Per-Core Queue
// ============================================================================

/// コアごとのNVMeキュー（キャッシュライン整列、ロックフリー）
///
/// 64バイトアラインメントにより、異なるコア間での
/// 偽共有（false sharing）を防止し、キャッシュ効率を最大化。
///
/// UnsafeCellにより、各コアが自身のキューにロックフリーでアクセス可能。
/// （コアアフィニティによりレースコンディションは発生しない）
#[repr(C, align(64))]
pub struct PerCoreNvmeQueue {
    /// キューペア（UnsafeCellでロックフリーアクセス）
    inner: UnsafeCell<Option<QueuePair>>,
    /// コアID
    core_id: u32,
    /// 初期化完了フラグ
    initialized: AtomicBool,
    /// ドアベルバッチカウンタ（保留中のコマンド数）
    pending_commands: AtomicU32,
    /// 統計（別キャッシュライン）
    stats: NvmeQueueStats,
    /// Pending Requests for Async I/O (ISR-safe)
    pending_requests: Arc<IrqMutex<PendingRequests>>,
    /// IRQで拾った完了を通常文脈へ渡す固定長キュー
    deferred_completions: IrqMutex<DeferredCompletionQueue>,
}

// Safety: PerCoreNvmeQueueは各コア固有のキューとして使用され、
// コアアフィニティによりシングルスレッドアクセスが保証される。
// 初期化以外の操作は所有コアからのみ行われる。
unsafe impl Sync for PerCoreNvmeQueue {}
unsafe impl Send for PerCoreNvmeQueue {}

impl PerCoreNvmeQueue {
    /// 新しいコアキューを作成
    pub fn new(core_id: u32) -> Self {
        Self {
            inner: UnsafeCell::new(None),
            core_id,
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

    /// ロックフリーでキューペアにアクセス（所有コアのみ）
    ///
    /// # Safety
    /// 現在のコアがこのPerCoreNvmeQueueの所有者であることを呼び出し側が保証。
    #[inline]
    pub(crate) unsafe fn get_queue_pair(&self) -> Option<&QueuePair> {
        unsafe { (*self.inner.get()).as_ref() }
    }

    /// 読み取り操作を発行（ドアベルバッチ対応）
    ///
    /// # Safety
    /// 現在のコアがこのキューの所有者であることを呼び出し側が保証。
    pub unsafe fn read(
        &self,
        nsid: u32,
        lba: u64,
        blocks: u16,
        prp1: u64,
        prp2: u64,
    ) -> Result<u16, &'static str> {
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
            unsafe { self.flush_doorbell() };
        }

        Ok(cid)
    }

    /// 読み取り操作を発行（SGL）
    ///
    /// # Safety
    /// 現在のコアがこのキューの所有者であることを呼び出し側が保証。
    pub unsafe fn read_sgl(
        &self,
        nsid: u32,
        lba: u64,
        blocks: u16,
        sgl: SglDescriptor,
    ) -> Result<u16, &'static str> {
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
            unsafe { self.flush_doorbell() };
        }

        Ok(cid)
    }

    /// 読み取り操作を即時発行（ドアベルを即座に書き込み）
    ///
    /// # Safety
    /// 現在のコアがこのキューの所有者であることを呼び出し側が保証。
    pub unsafe fn read_immediate(
        &self,
        nsid: u32,
        lba: u64,
        blocks: u16,
        prp1: u64,
        prp2: u64,
    ) -> Result<u16, &'static str> {
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
    /// 現在のコアがこのキューの所有者であることを呼び出し側が保証。
    pub unsafe fn write(
        &self,
        nsid: u32,
        lba: u64,
        blocks: u16,
        prp1: u64,
        prp2: u64,
    ) -> Result<u16, &'static str> {
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
            unsafe { self.flush_doorbell() };
        }

        Ok(cid)
    }

    /// 書き込み操作を発行（SGL）
    ///
    /// # Safety
    /// 現在のコアがこのキューの所有者であることを呼び出し側が保証。
    pub unsafe fn write_sgl(
        &self,
        nsid: u32,
        lba: u64,
        blocks: u16,
        sgl: SglDescriptor,
    ) -> Result<u16, &'static str> {
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
            unsafe { self.flush_doorbell() };
        }

        Ok(cid)
    }

    /// フラッシュコマンドを発行
    ///
    /// # Safety
    /// 現在のコアがこのキューの所有者であることを呼び出し側が保証。
    pub unsafe fn flush(&self, nsid: u32) -> Result<u16, &'static str> {
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
            unsafe { self.flush_doorbell() };
        }

        Ok(cid)
    }

    /// Dataset Management (TRIM) コマンドを発行
    ///
    /// # Safety
    /// 現在のコアがこのキューの所有者であることを呼び出し側が保証。
    /// prp1は有効な物理アドレスである必要がある。
    pub unsafe fn dataset_management(
        &self,
        nsid: u32,
        nr: u8,
        prp1: u64,
    ) -> Result<u16, &'static str> {
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
            unsafe { self.flush_doorbell() };
        }

        Ok(cid)
    }

    /// 書き込み操作を即時発行（ドアベルを即座に書き込み）
    ///
    /// # Safety
    /// 現在のコアがこのキューの所有者であることを呼び出し側が保証。
    pub unsafe fn write_immediate(
        &self,
        nsid: u32,
        lba: u64,
        blocks: u16,
        prp1: u64,
        prp2: u64,
    ) -> Result<u16, &'static str> {
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
    /// 現在のコアがこのキューの所有者であることを呼び出し側が保証。
    pub unsafe fn flush_doorbell(&self) {
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
    /// 現在のコアがこのキューの所有者であることを呼び出し側が保証。
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
    /// 現在のコアがこのキューの所有者であることを呼び出し側が保証。
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
    /// 現在のコアがこのキューの所有者であることを呼び出し側が保証。
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

    /// コアIDを取得
    pub fn core_id(&self) -> u32 {
        self.core_id
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
    // Kernel-owned interrupt routing now dispatches deferred completions by
    // logical core ID from the executor side instead of maintaining a driver-
    // local APIC/core mirror in this crate.
}

pub fn process_deferred_completions_for_core(core_id: u32) -> usize {
    queue_for_core(core_id)
        .map(|queue| queue.process_deferred_completions())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let queue = PerCoreNvmeQueue::new(0);
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
}
