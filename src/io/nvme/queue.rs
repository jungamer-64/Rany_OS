// ============================================================================
// src/io/nvme/queue.rs - NVMe Queue Structures for Driver
// ============================================================================
//!
//! # NVMeキュー構造体（ドライバ用）
//!
//! Submission Queue、Completion Queue、QueuePairの実装。
//! driver.rsから分離した低レベルキュー操作。

#![allow(dead_code)]

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};

use super::commands::{NvmeCommand, NvmeCompletion};

// ============================================================================
// Submission Queue
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
    ///
    /// # Safety
    /// バッファとドアベルアドレスが有効であることを呼び出し側が保証。
    pub unsafe fn new(buffer: *mut NvmeCommand, depth: u16, doorbell: *mut u32, qid: u16) -> Self {
        Self {
            buffer,
            depth,
            tail: AtomicU16::new(0),
            doorbell,
            qid,
        }
    }

    /// コマンドを送信（ドアベル書き込みあり）
    pub fn submit(&self, cmd: &NvmeCommand) -> Result<u16, &'static str> {
        let cid = self.submit_no_doorbell(cmd)?;
        self.ring_doorbell();
        Ok(cid)
    }

    /// コマンドを送信（ドアベル書き込みなし - バッチ処理用）
    ///
    /// 複数のコマンドをキューに投入してから一度だけドアベルを
    /// 書き込むことで、MMIOオーバーヘッドを削減。
    pub fn submit_no_doorbell(&self, cmd: &NvmeCommand) -> Result<u16, &'static str> {
        let tail = self.tail.load(Ordering::Acquire);
        let next_tail = (tail + 1) % self.depth;

        // キューが満杯の場合はエラー
        // 注：実際にはCQ Headとの比較が必要

        unsafe {
            let entry = self.buffer.add(tail as usize);
            write_volatile(entry, *cmd);

            // メモリバリア（コマンドの書き込みがドアベル前に完了することを保証）
            core::sync::atomic::fence(Ordering::Release);
        }

        self.tail.store(next_tail, Ordering::Release);
        Ok(tail)
    }

    /// ドアベルを鳴らす（コントローラにSQテール更新を通知）
    ///
    /// バッチ処理時は複数コマンド投入後にこれを1回呼ぶ。
    #[inline]
    pub fn ring_doorbell(&self) {
        let tail = self.tail.load(Ordering::Acquire);
        unsafe {
            // MMIO書き込み（高コスト）
            write_volatile(self.doorbell, tail as u32);
        }
    }

    /// キューIDを取得
    pub fn qid(&self) -> u16 {
        self.qid
    }

    /// 現在のテール位置を取得
    pub fn tail(&self) -> u16 {
        self.tail.load(Ordering::Acquire)
    }

    /// キュー深度を取得
    pub fn depth(&self) -> u16 {
        self.depth
    }
}

// ============================================================================
// Completion Queue
// ============================================================================

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
    ///
    /// # Safety
    /// バッファとドアベルアドレスが有効であることを呼び出し側が保証。
    pub unsafe fn new(
        buffer: *mut NvmeCompletion,
        depth: u16,
        doorbell: *mut u32,
        qid: u16,
    ) -> Self {
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

        let entry = unsafe { read_volatile(self.buffer.add(head as usize)) };

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

// ============================================================================
// Queue Pair
// ============================================================================

/// キューペア（SQ + CQ）
pub struct QueuePair {
    sq: SubmissionQueue,
    cq: CompletionQueue,
    /// 未完了コマンド数
    outstanding: AtomicU32,
}

impl QueuePair {
    /// 新しいキューペアを作成
    ///
    /// # Safety
    /// バッファとドアベルアドレスが有効であることを呼び出し側が保証。
    pub unsafe fn new(
        sq_buffer: *mut NvmeCommand,
        cq_buffer: *mut NvmeCompletion,
        depth: u16,
        sq_doorbell: *mut u32,
        cq_doorbell: *mut u32,
        qid: u16,
    ) -> Self {
        Self {
            sq: unsafe { SubmissionQueue::new(sq_buffer, depth, sq_doorbell, qid) },
            cq: unsafe { CompletionQueue::new(cq_buffer, depth, cq_doorbell, qid) },
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

    /// SQへの参照を取得
    pub fn sq(&self) -> &SubmissionQueue {
        &self.sq
    }

    /// CQへの参照を取得
    pub fn cq(&self) -> &CompletionQueue {
        &self.cq
    }
}
