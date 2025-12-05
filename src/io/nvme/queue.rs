// ============================================================================
// src/io/nvme/queue.rs - NVMe Queue Structures
// ============================================================================
//!
//! NVMeサブミッションキュー・コンプリーションキュー構造体
//!
//! NVMe Base Specification 2.0 Section 4に基づくキュー実装。

#![allow(dead_code)]

extern crate alloc;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicU16, Ordering};
use crate::io::nvme::commands::{NvmeCommand, NvmeCompletion};

// ============================================================================
// Constants
// ============================================================================

/// デフォルトキュー深度
pub const DEFAULT_QUEUE_DEPTH: u16 = 64;

/// 最大キュー深度（NVMe仕様上の最大値）
pub const MAX_QUEUE_DEPTH: u16 = 65535;

/// Submission Queueエントリサイズ（バイト）
pub const SQ_ENTRY_SIZE: usize = 64;

/// Completion Queueエントリサイズ（バイト）
pub const CQ_ENTRY_SIZE: usize = 16;

// ============================================================================
// Submission Queue
// ============================================================================

/// NVMe Submission Queue
pub struct NvmeSubmissionQueue {
    /// ベースアドレス（物理）
    base_phys: u64,
    /// ベースアドレス（仮想）
    base_virt: *mut NvmeCommand,
    /// キュー深度
    depth: u16,
    /// Queue ID
    qid: u16,
    /// Tailポインタ
    tail: AtomicU16,
    /// Headポインタ（ソフトウェア追跡用）
    head: AtomicU16,
    /// ドアベルレジスタアドレス
    doorbell: *mut u32,
}

// Safety: NvmeSubmissionQueue は内部でアトミック操作を使用し、
// 適切な同期を行う
unsafe impl Send for NvmeSubmissionQueue {}
unsafe impl Sync for NvmeSubmissionQueue {}

impl NvmeSubmissionQueue {
    /// 新しいSubmission Queueを作成
    ///
    /// # Safety
    /// - `base_virt`は有効なメモリを指している必要がある
    /// - `doorbell`は有効なMMIOアドレスを指している必要がある
    pub unsafe fn new(
        base_phys: u64,
        base_virt: *mut NvmeCommand,
        depth: u16,
        qid: u16,
        doorbell: *mut u32,
    ) -> Self {
        Self {
            base_phys,
            base_virt,
            depth,
            qid,
            tail: AtomicU16::new(0),
            head: AtomicU16::new(0),
            doorbell,
        }
    }

    /// Queue IDを取得
    pub fn qid(&self) -> u16 {
        self.qid
    }

    /// キュー深度を取得
    pub fn depth(&self) -> u16 {
        self.depth
    }

    /// 物理ベースアドレスを取得
    pub fn base_phys(&self) -> u64 {
        self.base_phys
    }

    /// 現在のtailポインタを取得
    pub fn tail(&self) -> u16 {
        self.tail.load(Ordering::Acquire)
    }

    /// 空きスロット数を取得
    pub fn available_slots(&self) -> u16 {
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        if tail >= head {
            self.depth - (tail - head) - 1
        } else {
            head - tail - 1
        }
    }

    /// キューがフルかどうか
    pub fn is_full(&self) -> bool {
        self.available_slots() == 0
    }

    /// コマンドを送信
    ///
    /// # Returns
    /// 成功時はコマンドIDを返す
    pub fn submit(&self, cmd: &NvmeCommand) -> Result<u16, NvmeQueueError> {
        if self.is_full() {
            return Err(NvmeQueueError::QueueFull);
        }

        let tail = self.tail.load(Ordering::Acquire);
        let cmd_id = tail;

        // コマンドをキューにコピー
        unsafe {
            let slot = self.base_virt.add(tail as usize);
            ptr::write_volatile(slot, *cmd);
        }

        // Tailを更新
        let new_tail = (tail + 1) % self.depth;
        self.tail.store(new_tail, Ordering::Release);

        // ドアベルを鳴らす
        self.ring_doorbell();

        Ok(cmd_id)
    }

    /// 複数のコマンドを一括送信
    pub fn submit_batch(&self, cmds: &[NvmeCommand]) -> Result<Vec<u16>, NvmeQueueError> {
        if cmds.len() > self.available_slots() as usize {
            return Err(NvmeQueueError::QueueFull);
        }

        let mut cmd_ids = Vec::new();
        let mut tail = self.tail.load(Ordering::Acquire);

        for cmd in cmds {
            // コマンドをキューにコピー
            unsafe {
                let slot = self.base_virt.add(tail as usize);
                ptr::write_volatile(slot, *cmd);
            }
            cmd_ids.push(tail);
            tail = (tail + 1) % self.depth;
        }

        // Tailを一括更新
        self.tail.store(tail, Ordering::Release);

        // ドアベルを1回だけ鳴らす
        self.ring_doorbell();

        Ok(cmd_ids)
    }

    /// Headポインタを更新（CQ処理後に呼び出す）
    pub fn update_head(&self, new_head: u16) {
        self.head.store(new_head, Ordering::Release);
    }

    /// ドアベルを鳴らす
    fn ring_doorbell(&self) {
        let tail = self.tail.load(Ordering::Acquire);
        unsafe {
            ptr::write_volatile(self.doorbell, tail as u32);
        }
    }
}

// ============================================================================
// Completion Queue
// ============================================================================

/// NVMe Completion Queue
pub struct NvmeCompletionQueue {
    /// ベースアドレス（物理）
    base_phys: u64,
    /// ベースアドレス（仮想）
    base_virt: *mut NvmeCompletion,
    /// キュー深度
    depth: u16,
    /// Queue ID
    qid: u16,
    /// Headポインタ
    head: AtomicU16,
    /// 現在のフェーズビット
    phase: core::sync::atomic::AtomicBool,
    /// ドアベルレジスタアドレス
    doorbell: *mut u32,
}

// Safety: NvmeCompletionQueue は内部でアトミック操作を使用し、
// 適切な同期を行う
unsafe impl Send for NvmeCompletionQueue {}
unsafe impl Sync for NvmeCompletionQueue {}

impl NvmeCompletionQueue {
    /// 新しいCompletion Queueを作成
    ///
    /// # Safety
    /// - `base_virt`は有効なメモリを指している必要がある
    /// - `doorbell`は有効なMMIOアドレスを指している必要がある
    pub unsafe fn new(
        base_phys: u64,
        base_virt: *mut NvmeCompletion,
        depth: u16,
        qid: u16,
        doorbell: *mut u32,
    ) -> Self {
        Self {
            base_phys,
            base_virt,
            depth,
            qid,
            head: AtomicU16::new(0),
            phase: core::sync::atomic::AtomicBool::new(true),
            doorbell,
        }
    }

    /// Queue IDを取得
    pub fn qid(&self) -> u16 {
        self.qid
    }

    /// キュー深度を取得
    pub fn depth(&self) -> u16 {
        self.depth
    }

    /// 物理ベースアドレスを取得
    pub fn base_phys(&self) -> u64 {
        self.base_phys
    }

    /// 現在のheadポインタを取得
    pub fn head(&self) -> u16 {
        self.head.load(Ordering::Acquire)
    }

    /// 完了エントリをポーリング
    ///
    /// # Returns
    /// 完了エントリがあればSome、なければNone
    pub fn poll(&self) -> Option<NvmeCompletion> {
        let head = self.head.load(Ordering::Acquire);
        let expected_phase = self.phase.load(Ordering::Acquire);

        // 完了エントリを読み取り
        let entry = unsafe {
            let slot = self.base_virt.add(head as usize);
            ptr::read_volatile(slot)
        };

        // フェーズビットチェック
        if entry.phase() != expected_phase {
            return None;
        }

        Some(entry)
    }

    /// 完了エントリを消費してheadを進める
    pub fn consume(&self) -> Option<NvmeCompletion> {
        let entry = self.poll()?;

        let head = self.head.load(Ordering::Acquire);
        let new_head = (head + 1) % self.depth;

        // ラップアラウンド時にフェーズを反転
        if new_head == 0 {
            let current = self.phase.load(Ordering::Acquire);
            self.phase.store(!current, Ordering::Release);
        }

        self.head.store(new_head, Ordering::Release);
        Some(entry)
    }

    /// ドアベルを鳴らしてコントローラに通知
    pub fn ring_doorbell(&self) {
        let head = self.head.load(Ordering::Acquire);
        unsafe {
            ptr::write_volatile(self.doorbell, head as u32);
        }
    }

    /// 複数の完了エントリを一括処理
    pub fn process_completions<F>(&self, mut handler: F) -> usize
    where
        F: FnMut(NvmeCompletion),
    {
        let mut count = 0;
        while let Some(entry) = self.consume() {
            handler(entry);
            count += 1;
        }
        
        // 処理した分だけドアベルを更新
        if count > 0 {
            self.ring_doorbell();
        }
        
        count
    }
}

// ============================================================================
// Queue Pair
// ============================================================================

/// NVMe Queue Pair (SQ + CQ)
pub struct NvmeQueuePair {
    /// Submission Queue
    pub sq: NvmeSubmissionQueue,
    /// Completion Queue
    pub cq: NvmeCompletionQueue,
    /// ペアリングされたSQ ID（CQは複数のSQを持てる）
    sq_id: u16,
    /// 対応するCQ ID
    cq_id: u16,
}

impl NvmeQueuePair {
    /// 新しいQueue Pairを作成
    pub fn new(sq: NvmeSubmissionQueue, cq: NvmeCompletionQueue) -> Self {
        let sq_id = sq.qid();
        let cq_id = cq.qid();
        Self { sq, cq, sq_id, cq_id }
    }

    /// SQ IDを取得
    pub fn sq_id(&self) -> u16 {
        self.sq_id
    }

    /// CQ IDを取得
    pub fn cq_id(&self) -> u16 {
        self.cq_id
    }

    /// コマンドを送信して完了を待機（ブロッキング）
    pub fn submit_and_wait(&self, cmd: &NvmeCommand, timeout_us: u64) -> Result<NvmeCompletion, NvmeQueueError> {
        let cmd_id = self.sq.submit(cmd)?;

        // タイムアウト時間をナノ秒に変換
        let timeout_ns = timeout_us * 1000;
        let start = crate::time::system_clock().uptime_nanos();

        loop {
            if let Some(completion) = self.cq.consume() {
                if completion.command_id() == cmd_id {
                    self.cq.ring_doorbell();
                    return Ok(completion);
                }
            }

            // タイムアウトチェック
            let elapsed = crate::time::system_clock().uptime_nanos() - start;
            if elapsed > timeout_ns {
                return Err(NvmeQueueError::Timeout);
            }

            // CPUを少し休ませる
            core::hint::spin_loop();
        }
    }

    /// コマンドを非同期で送信（ポーリング用）
    pub fn submit_async(&self, cmd: &NvmeCommand) -> Result<u16, NvmeQueueError> {
        self.sq.submit(cmd)
    }

    /// 完了をポーリング
    pub fn poll_completion(&self) -> Option<NvmeCompletion> {
        self.cq.poll()
    }

    /// 完了を消費
    pub fn consume_completion(&self) -> Option<NvmeCompletion> {
        let completion = self.cq.consume()?;
        self.cq.ring_doorbell();
        Some(completion)
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// キューエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvmeQueueError {
    /// キューがフル
    QueueFull,
    /// タイムアウト
    Timeout,
    /// コントローラエラー
    ControllerError(u16),
    /// 無効なキューID
    InvalidQueueId,
    /// メモリ割り当て失敗
    AllocationFailed,
}

impl core::fmt::Display for NvmeQueueError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::QueueFull => write!(f, "Queue is full"),
            Self::Timeout => write!(f, "Operation timed out"),
            Self::ControllerError(status) => write!(f, "Controller error: 0x{:04x}", status),
            Self::InvalidQueueId => write!(f, "Invalid queue ID"),
            Self::AllocationFailed => write!(f, "Memory allocation failed"),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_queue_constants() {
        assert_eq!(SQ_ENTRY_SIZE, 64);
        assert_eq!(CQ_ENTRY_SIZE, 16);
        assert_eq!(DEFAULT_QUEUE_DEPTH, 64);
    }
}
