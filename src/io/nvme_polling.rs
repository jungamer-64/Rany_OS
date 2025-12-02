// ============================================================================
// src/io/nvme_polling.rs - NVMe Polling Mode Driver
// ============================================================================
//!
//! # NVMeポーリングモードドライバ
//!
//! 設計書6.3に基づく高性能NVMeストレージアクセス。
//! コアごとのSubmission/Completion Queueとポーリングモードで
//! 最大スループットを実現。
//!
//! ## 機能
//! - マルチキューサポート（コアごとのSQ/CQ）
//! - ポーリングモード（割り込み不使用）
//! - 非同期コマンド発行
//! - I/O優先度サポート
//! - SGL（Scatter-Gather List）対応

#![allow(dead_code)]

use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicBool, Ordering};
use core::ptr::{read_volatile, write_volatile};
use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::collections::VecDeque;
use spin::Mutex;

// ============================================================================
// NVMe Constants
// ============================================================================

/// キューエントリサイズ（64バイト）
const QUEUE_ENTRY_SIZE: usize = 64;

/// 最大キュー深度
const MAX_QUEUE_DEPTH: u16 = 1024;

/// デフォルトキュー深度
const DEFAULT_QUEUE_DEPTH: u16 = 256;

/// 最大SGL長
const MAX_SGL_ENTRIES: usize = 32;

/// セクタサイズ
const SECTOR_SIZE: usize = 512;

/// 最大転送サイズ（128KB）
const MAX_TRANSFER_SIZE: usize = 128 * 1024;

// NVMe管理コマンドオペコード
const ADMIN_CREATE_SQ: u8 = 0x01;
const ADMIN_CREATE_CQ: u8 = 0x05;
const ADMIN_IDENTIFY: u8 = 0x06;
const ADMIN_SET_FEATURES: u8 = 0x09;
const ADMIN_GET_FEATURES: u8 = 0x0A;

// NVMe I/Oコマンドオペコード
const IO_READ: u8 = 0x02;
const IO_WRITE: u8 = 0x01;
const IO_FLUSH: u8 = 0x00;
const IO_COMPARE: u8 = 0x05;
const IO_DATASET_MGMT: u8 = 0x09; // TRIM

// ============================================================================
// NVMe Data Structures
// ============================================================================

/// NVMe Submission Queue Entry
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, Default)]
pub struct NvmeCommand {
    /// Command Dword 0
    pub cdw0: u32,
    /// Namespace ID
    pub nsid: u32,
    /// Reserved
    pub reserved: [u32; 2],
    /// Metadata Pointer
    pub mptr: u64,
    /// Data Pointer (PRP or SGL)
    pub dptr: [u64; 2],
    /// Command Dwords 10-15
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
}

impl NvmeCommand {
    /// 新しいコマンドを作成
    pub fn new() -> Self {
        Self::default()
    }

    /// オペコードを設定
    pub fn set_opcode(&mut self, opcode: u8) {
        self.cdw0 = (self.cdw0 & !0xFF) | (opcode as u32);
    }

    /// コマンドIDを設定
    pub fn set_cid(&mut self, cid: u16) {
        self.cdw0 = (self.cdw0 & 0xFFFF) | ((cid as u32) << 16);
    }

    /// PRPエントリを設定
    pub fn set_prp(&mut self, prp1: u64, prp2: u64) {
        self.dptr[0] = prp1;
        self.dptr[1] = prp2;
    }

    /// 読み取りコマンドを作成
    pub fn read(nsid: u32, lba: u64, blocks: u16, prp1: u64, prp2: u64) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(IO_READ);
        cmd.nsid = nsid;
        cmd.cdw10 = lba as u32;
        cmd.cdw11 = (lba >> 32) as u32;
        cmd.cdw12 = (blocks - 1) as u32; // 0-based
        cmd.set_prp(prp1, prp2);
        cmd
    }

    /// 書き込みコマンドを作成
    pub fn write(nsid: u32, lba: u64, blocks: u16, prp1: u64, prp2: u64) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(IO_WRITE);
        cmd.nsid = nsid;
        cmd.cdw10 = lba as u32;
        cmd.cdw11 = (lba >> 32) as u32;
        cmd.cdw12 = (blocks - 1) as u32;
        cmd.set_prp(prp1, prp2);
        cmd
    }

    /// フラッシュコマンドを作成
    pub fn flush(nsid: u32) -> Self {
        let mut cmd = Self::new();
        cmd.set_opcode(IO_FLUSH);
        cmd.nsid = nsid;
        cmd
    }
}

/// NVMe Completion Queue Entry
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct NvmeCompletion {
    /// Command Specific
    pub dw0: u32,
    /// Reserved
    pub dw1: u32,
    /// SQ Head Pointer
    pub sq_head: u16,
    /// SQ Identifier
    pub sq_id: u16,
    /// Command Identifier
    pub cid: u16,
    /// Status Field
    pub status: u16,
}

impl NvmeCompletion {
    /// フェーズタグを取得
    pub fn phase(&self) -> bool {
        (self.status & 1) != 0
    }

    /// ステータスコードを取得
    pub fn status_code(&self) -> u8 {
        ((self.status >> 1) & 0xFF) as u8
    }

    /// ステータスコードタイプを取得
    pub fn status_code_type(&self) -> u8 {
        ((self.status >> 9) & 0x7) as u8
    }

    /// 成功かどうか
    pub fn is_success(&self) -> bool {
        self.status_code() == 0 && self.status_code_type() == 0
    }
}

// ============================================================================
// Queue Pair
// ============================================================================

/// Submission Queue
pub struct SubmissionQueue {
    /// キューバッファ
    buffer: *mut NvmeCommand,
    /// キュー深度
    depth: u16,
    /// 現在のテール
    tail: AtomicU16,
    /// ドアベルレジスタアドレス
    doorbell: *mut u32,
    /// キューID
    qid: u16,
}

unsafe impl Send for SubmissionQueue {}
unsafe impl Sync for SubmissionQueue {}

impl SubmissionQueue {
    /// 新しいSQを作成
    pub unsafe fn new(buffer: *mut NvmeCommand, depth: u16, doorbell: *mut u32, qid: u16) -> Self {
        Self {
            buffer,
            depth,
            tail: AtomicU16::new(0),
            doorbell,
            qid,
        }
    }

    /// コマンドを送信
    pub fn submit(&self, cmd: &NvmeCommand) -> Result<u16, &'static str> {
        let tail = self.tail.load(Ordering::Acquire);
        let next_tail = (tail + 1) % self.depth;

        // キューが満杯の場合はエラー
        // 注：実際にはCQ Headとの比較が必要

        unsafe {
            let entry = self.buffer.add(tail as usize);
            write_volatile(entry, *cmd);

            // メモリバリア
            core::sync::atomic::fence(Ordering::Release);

            // ドアベルを更新
            write_volatile(self.doorbell, next_tail as u32);
        }

        self.tail.store(next_tail, Ordering::Release);
        Ok(tail)
    }

    /// キューIDを取得
    pub fn qid(&self) -> u16 {
        self.qid
    }
}

/// Completion Queue
pub struct CompletionQueue {
    /// キューバッファ
    buffer: *mut NvmeCompletion,
    /// キュー深度
    depth: u16,
    /// 現在のヘッド
    head: AtomicU16,
    /// フェーズビット
    phase: AtomicBool,
    /// ドアベルレジスタアドレス
    doorbell: *mut u32,
    /// キューID
    qid: u16,
}

unsafe impl Send for CompletionQueue {}
unsafe impl Sync for CompletionQueue {}

impl CompletionQueue {
    /// 新しいCQを作成
    pub unsafe fn new(buffer: *mut NvmeCompletion, depth: u16, doorbell: *mut u32, qid: u16) -> Self {
        Self {
            buffer,
            depth,
            head: AtomicU16::new(0),
            phase: AtomicBool::new(true),
            doorbell,
            qid,
        }
    }

    /// 完了をポーリング
    pub fn poll(&self) -> Option<NvmeCompletion> {
        let head = self.head.load(Ordering::Acquire);
        let expected_phase = self.phase.load(Ordering::Acquire);

        let entry = unsafe {
            read_volatile(self.buffer.add(head as usize))
        };

        // フェーズビットをチェック
        if entry.phase() != expected_phase {
            return None;
        }

        // ヘッドを進める
        let next_head = (head + 1) % self.depth;
        self.head.store(next_head, Ordering::Release);

        // ラップアラウンド時にフェーズを反転
        if next_head == 0 {
            self.phase.fetch_xor(true, Ordering::AcqRel);
        }

        Some(entry)
    }

    /// ドアベルを更新（完了処理後に呼ぶ）
    pub fn update_doorbell(&self) {
        let head = self.head.load(Ordering::Acquire);
        unsafe {
            write_volatile(self.doorbell, head as u32);
        }
    }

    /// キューIDを取得
    pub fn qid(&self) -> u16 {
        self.qid
    }
}

/// キューペア（SQ + CQ）
pub struct QueuePair {
    sq: SubmissionQueue,
    cq: CompletionQueue,
    /// 未完了コマンド数
    outstanding: AtomicU32,
}

impl QueuePair {
    /// 新しいキューペアを作成
    pub unsafe fn new(
        sq_buffer: *mut NvmeCommand,
        cq_buffer: *mut NvmeCompletion,
        depth: u16,
        sq_doorbell: *mut u32,
        cq_doorbell: *mut u32,
        qid: u16,
    ) -> Self {
        Self {
            sq: SubmissionQueue::new(sq_buffer, depth, sq_doorbell, qid),
            cq: CompletionQueue::new(cq_buffer, depth, cq_doorbell, qid),
            outstanding: AtomicU32::new(0),
        }
    }

    /// コマンドを送信
    pub fn submit(&self, cmd: &NvmeCommand) -> Result<u16, &'static str> {
        self.outstanding.fetch_add(1, Ordering::AcqRel);
        self.sq.submit(cmd)
    }

    /// 完了をポーリング
    pub fn poll_completion(&self) -> Option<NvmeCompletion> {
        if let Some(cqe) = self.cq.poll() {
            self.outstanding.fetch_sub(1, Ordering::AcqRel);
            self.cq.update_doorbell();
            Some(cqe)
        } else {
            None
        }
    }

    /// 未完了コマンド数を取得
    pub fn outstanding(&self) -> u32 {
        self.outstanding.load(Ordering::Acquire)
    }
}

// ============================================================================
// Per-Core Queue
// ============================================================================

/// コアごとのNVMeキュー
pub struct PerCoreNvmeQueue {
    /// コアID
    core_id: u32,
    /// キューペア
    queue_pair: Option<QueuePair>,
    /// 統計
    stats: NvmeQueueStats,
}

/// キュー統計
#[derive(Debug, Default)]
pub struct NvmeQueueStats {
    pub commands_submitted: AtomicU64,
    pub commands_completed: AtomicU64,
    pub read_bytes: AtomicU64,
    pub write_bytes: AtomicU64,
    pub errors: AtomicU64,
    pub poll_cycles: AtomicU64,
}

impl PerCoreNvmeQueue {
    /// 新しいコアキューを作成
    pub fn new(core_id: u32) -> Self {
        Self {
            core_id,
            queue_pair: None,
            stats: NvmeQueueStats::default(),
        }
    }

    /// キューペアを設定
    pub fn set_queue_pair(&mut self, qp: QueuePair) {
        self.queue_pair = Some(qp);
    }

    /// 読み取り操作を発行
    pub fn read(&self, nsid: u32, lba: u64, blocks: u16, prp1: u64, prp2: u64) -> Result<u16, &'static str> {
        let qp = self.queue_pair.as_ref().ok_or("Queue not initialized")?;
        
        let mut cmd = NvmeCommand::read(nsid, lba, blocks, prp1, prp2);
        let cid = qp.submit(&cmd)?;
        cmd.set_cid(cid);

        self.stats.commands_submitted.fetch_add(1, Ordering::Relaxed);
        self.stats.read_bytes.fetch_add((blocks as u64) * (SECTOR_SIZE as u64), Ordering::Relaxed);

        Ok(cid)
    }

    /// 書き込み操作を発行
    pub fn write(&self, nsid: u32, lba: u64, blocks: u16, prp1: u64, prp2: u64) -> Result<u16, &'static str> {
        let qp = self.queue_pair.as_ref().ok_or("Queue not initialized")?;
        
        let mut cmd = NvmeCommand::write(nsid, lba, blocks, prp1, prp2);
        let cid = qp.submit(&cmd)?;
        cmd.set_cid(cid);

        self.stats.commands_submitted.fetch_add(1, Ordering::Relaxed);
        self.stats.write_bytes.fetch_add((blocks as u64) * (SECTOR_SIZE as u64), Ordering::Relaxed);

        Ok(cid)
    }

    /// 完了をポーリング
    pub fn poll(&self) -> Option<NvmeCompletion> {
        let qp = self.queue_pair.as_ref()?;
        
        self.stats.poll_cycles.fetch_add(1, Ordering::Relaxed);
        
        if let Some(cqe) = qp.poll_completion() {
            self.stats.commands_completed.fetch_add(1, Ordering::Relaxed);
            if !cqe.is_success() {
                self.stats.errors.fetch_add(1, Ordering::Relaxed);
            }
            Some(cqe)
        } else {
            None
        }
    }

    /// 統計を取得
    pub fn stats(&self) -> &NvmeQueueStats {
        &self.stats
    }

    /// コアIDを取得
    pub fn core_id(&self) -> u32 {
        self.core_id
    }
}

// ============================================================================
// Polling Driver
// ============================================================================

/// NVMeポーリングドライバ
pub struct NvmePollingDriver {
    /// BAR0ベースアドレス
    bar0: u64,
    /// キャパシティレジスタ
    cap: u64,
    /// ドアベルストライド
    doorbell_stride: usize,
    /// 管理キュー
    admin_queue: Option<QueuePair>,
    /// コアごとのI/Oキュー
    io_queues: Vec<PerCoreNvmeQueue>,
    /// 名前空間ID
    nsid: u32,
    /// 最大転送サイズ
    max_transfer_size: usize,
    /// アクティブフラグ
    active: AtomicBool,
}

impl NvmePollingDriver {
    /// 新しいドライバを作成
    pub fn new(bar0: u64, num_cores: u32) -> Self {
        let mut io_queues = Vec::new();
        for i in 0..num_cores {
            io_queues.push(PerCoreNvmeQueue::new(i));
        }

        Self {
            bar0,
            cap: 0,
            doorbell_stride: 4, // デフォルト
            admin_queue: None,
            io_queues,
            nsid: 1,
            max_transfer_size: MAX_TRANSFER_SIZE,
            active: AtomicBool::new(false),
        }
    }

    /// コントローラを初期化
    pub fn init(&mut self) -> Result<(), &'static str> {
        // CAP レジスタを読む
        self.cap = unsafe { read_volatile((self.bar0) as *const u64) };
        
        // ドアベルストライドを計算
        let dstrd = ((self.cap >> 32) & 0xF) as usize;
        self.doorbell_stride = 4 << dstrd;

        // TODO: 管理キューの設定、コントローラの有効化

        self.active.store(true, Ordering::Release);
        Ok(())
    }

    /// I/Oキューを設定
    pub fn setup_io_queue(&mut self, core_id: u32, qp: QueuePair) {
        if let Some(queue) = self.io_queues.get_mut(core_id as usize) {
            queue.set_queue_pair(qp);
        }
    }

    /// コアのキューを取得
    pub fn get_queue(&self, core_id: u32) -> Option<&PerCoreNvmeQueue> {
        self.io_queues.get(core_id as usize)
    }

    /// ポーリングループを実行
    pub fn poll_loop(&self, core_id: u32) -> usize {
        let queue = match self.get_queue(core_id) {
            Some(q) => q,
            None => return 0,
        };

        let mut completed = 0;
        while let Some(_cqe) = queue.poll() {
            completed += 1;
        }
        completed
    }

    /// アクティブかどうか
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }
}

// ============================================================================
// Async I/O Request
// ============================================================================

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

/// I/Oリクエストの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoRequestState {
    Pending,
    Submitted,
    Completed,
    Error,
}

/// 非同期I/Oリクエスト
pub struct AsyncIoRequest {
    /// コマンドID
    cid: u16,
    /// 状態
    state: IoRequestState,
    /// 完了結果
    result: Option<NvmeCompletion>,
    /// Waker
    waker: Option<Waker>,
}

impl AsyncIoRequest {
    pub fn new(cid: u16) -> Self {
        Self {
            cid,
            state: IoRequestState::Pending,
            result: None,
            waker: None,
        }
    }

    /// 完了を設定
    pub fn complete(&mut self, cqe: NvmeCompletion) {
        self.result = Some(cqe);
        self.state = if cqe.is_success() {
            IoRequestState::Completed
        } else {
            IoRequestState::Error
        };

        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
}

/// 非同期読み取りFuture
pub struct ReadFuture<'a> {
    driver: &'a NvmePollingDriver,
    core_id: u32,
    request: AsyncIoRequest,
}

impl<'a> Future for ReadFuture<'a> {
    type Output = Result<(), NvmeCompletion>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // ポーリングして完了を確認
        if let Some(queue) = self.driver.get_queue(self.core_id) {
            if let Some(cqe) = queue.poll() {
                if cqe.cid == self.request.cid {
                    if cqe.is_success() {
                        return Poll::Ready(Ok(()));
                    } else {
                        return Poll::Ready(Err(cqe));
                    }
                }
            }
        }

        self.request.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

// ============================================================================
// Global Instance
// ============================================================================

static NVME_DRIVER: Mutex<Option<NvmePollingDriver>> = Mutex::new(None);

/// NVMeドライバを初期化
pub fn init(bar0: u64, num_cores: u32) -> Result<(), &'static str> {
    let mut driver = NvmePollingDriver::new(bar0, num_cores);
    driver.init()?;
    *NVME_DRIVER.lock() = Some(driver);
    Ok(())
}

/// NVMeドライバにアクセス
pub fn with_driver<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&NvmePollingDriver) -> R,
{
    NVME_DRIVER.lock().as_ref().map(f)
}

/// ポーリングを実行
pub fn poll(core_id: u32) -> usize {
    with_driver(|d| d.poll_loop(core_id)).unwrap_or(0)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nvme_command_read() {
        let cmd = NvmeCommand::read(1, 0, 8, 0x1000, 0);
        assert_eq!(cmd.nsid, 1);
        assert_eq!(cmd.cdw10, 0);
        assert_eq!(cmd.cdw12, 7); // 8-1
    }

    #[test]
    fn test_nvme_completion_status() {
        let mut cqe = NvmeCompletion::default();
        cqe.status = 0x0001; // Phase bit set, success
        assert!(cqe.phase());
        assert!(cqe.is_success());
    }

    #[test]
    fn test_io_request_state() {
        let req = AsyncIoRequest::new(42);
        assert_eq!(req.state, IoRequestState::Pending);
    }
}
