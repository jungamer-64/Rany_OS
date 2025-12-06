// ============================================================================
// src/io/nvme/async_io.rs - NVMe Async I/O Support
// ============================================================================
//!
//! # NVMe非同期I/Oサポート
//!
//! 非同期I/Oリクエストとフューチャー実装。
//! Rustのasync/awaitパターンでNVMe操作を実行。

#![allow(dead_code)]

use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU32, Ordering};
use core::task::{Context, Poll, Waker};

use super::commands::NvmeCompletion;
use super::defs::POLL_BATCH_SIZE;
use super::error::NvmeError;
use super::polling_driver::NvmePollingDriver;

// ============================================================================
// I/O Request State
// ============================================================================

/// I/Oリクエストの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoRequestState {
    Pending,
    Submitted,
    Completed,
    Error,
    Cancelled,
}

// ============================================================================
// Async I/O Request
// ============================================================================

/// 非同期I/Oリクエスト
pub struct AsyncIoRequest {
    /// コマンドID
    pub cid: u16,
    /// キューID
    pub qid: u16,
    /// 状態
    pub state: IoRequestState,
    /// 完了結果
    result: Option<NvmeCompletion>,
    /// Waker
    waker: Option<Waker>,
    /// 開始時刻（サイクルカウンタ）
    start_tsc: u64,
}

impl AsyncIoRequest {
    pub fn new(cid: u16, qid: u16) -> Self {
        Self {
            cid,
            qid,
            state: IoRequestState::Pending,
            result: None,
            waker: None,
            start_tsc: read_tsc(),
        }
    }

    /// 状態を取得
    pub fn state(&self) -> IoRequestState {
        self.state
    }

    /// 完了かどうか
    pub fn is_complete(&self) -> bool {
        matches!(
            self.state,
            IoRequestState::Completed | IoRequestState::Error
        )
    }

    /// 結果を取得
    pub fn result(&self) -> Option<&NvmeCompletion> {
        self.result.as_ref()
    }

    /// 経過時間（サイクル数）
    pub fn elapsed_cycles(&self) -> u64 {
        read_tsc().saturating_sub(self.start_tsc)
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

    /// キャンセル
    pub fn cancel(&mut self) {
        self.state = IoRequestState::Cancelled;
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
}

// ============================================================================
// Pending Requests Tracker
// ============================================================================

/// ペンディングリクエストトラッカー
pub struct PendingRequests {
    /// リクエストマップ（CID -> Request）
    requests: [Option<AsyncIoRequest>; 256],
    /// アクティブなリクエスト数
    active_count: AtomicU32,
}

impl PendingRequests {
    pub const fn new() -> Self {
        const NONE: Option<AsyncIoRequest> = None;
        Self {
            requests: [NONE; 256],
            active_count: AtomicU32::new(0),
        }
    }

    /// リクエストを登録
    pub fn register(&mut self, cid: u16, qid: u16) -> Result<(), &'static str> {
        let idx = (cid as usize) % 256;
        if self.requests[idx].is_some() {
            return Err("CID slot already in use");
        }
        self.requests[idx] = Some(AsyncIoRequest::new(cid, qid));
        self.active_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// リクエストを完了
    pub fn complete(&mut self, cid: u16, cqe: NvmeCompletion) -> bool {
        let idx = (cid as usize) % 256;
        if let Some(ref mut req) = self.requests[idx] {
            if req.cid == cid {
                req.complete(cqe);
                return true;
            }
        }
        false
    }

    /// リクエストを削除して取得
    pub fn take(&mut self, cid: u16) -> Option<AsyncIoRequest> {
        let idx = (cid as usize) % 256;
        if let Some(ref req) = self.requests[idx] {
            if req.cid == cid {
                self.active_count.fetch_sub(1, Ordering::Relaxed);
                return self.requests[idx].take();
            }
        }
        None
    }

    /// Wakerを設定
    pub fn set_waker(&mut self, cid: u16, waker: Waker) {
        let idx = (cid as usize) % 256;
        if let Some(ref mut req) = self.requests[idx] {
            if req.cid == cid {
                req.waker = Some(waker);
            }
        }
    }

    /// アクティブなリクエスト数
    pub fn active_count(&self) -> u32 {
        self.active_count.load(Ordering::Relaxed)
    }
}

// ============================================================================
// Read Future
// ============================================================================

/// 非同期読み取りFuture
pub struct ReadFuture<'a> {
    driver: &'a NvmePollingDriver,
    core_id: u32,
    cid: u16,
    #[allow(dead_code)]
    submitted: bool,
}

impl<'a> ReadFuture<'a> {
    pub fn new(driver: &'a NvmePollingDriver, core_id: u32, cid: u16) -> Self {
        Self {
            driver,
            core_id,
            cid,
            submitted: true,
        }
    }
}

impl<'a> Future for ReadFuture<'a> {
    type Output = Result<NvmeCompletion, NvmeError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // ポーリングして完了を確認
        if let Some(queue) = self.driver.get_queue(self.core_id) {
            // バッチでポーリング
            for _ in 0..POLL_BATCH_SIZE {
                // Safety: Futureは生成元のコアでのみpolledされると仮定
                if let Some(cqe) = unsafe { queue.poll() } {
                    if cqe.cid == self.cid {
                        if cqe.is_success() {
                            return Poll::Ready(Ok(cqe));
                        } else {
                            return Poll::Ready(Err(NvmeError::CommandError(cqe)));
                        }
                    }
                    // 他のCIDの完了 - 対応するwakerを起こす必要がある
                    // 実際の実装ではPendingRequestsと連携
                } else {
                    break;
                }
            }
        } else {
            return Poll::Ready(Err(NvmeError::QueueNotFound));
        }

        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

// ============================================================================
// Write Future
// ============================================================================

/// 非同期書き込みFuture
pub struct WriteFuture<'a> {
    driver: &'a NvmePollingDriver,
    core_id: u32,
    cid: u16,
}

impl<'a> WriteFuture<'a> {
    pub fn new(driver: &'a NvmePollingDriver, core_id: u32, cid: u16) -> Self {
        Self {
            driver,
            core_id,
            cid,
        }
    }
}

impl<'a> Future for WriteFuture<'a> {
    type Output = Result<NvmeCompletion, NvmeError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(queue) = self.driver.get_queue(self.core_id) {
            for _ in 0..POLL_BATCH_SIZE {
                // Safety: Futureは生成元のコアでのみpolledされると仮定
                if let Some(cqe) = unsafe { queue.poll() } {
                    if cqe.cid == self.cid {
                        if cqe.is_success() {
                            return Poll::Ready(Ok(cqe));
                        } else {
                            return Poll::Ready(Err(NvmeError::CommandError(cqe)));
                        }
                    }
                } else {
                    break;
                }
            }
        } else {
            return Poll::Ready(Err(NvmeError::QueueNotFound));
        }

        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

// ============================================================================
// High-Level Async API
// ============================================================================

/// 非同期読み取り
///
/// # Safety
/// 現在のコアIDが正しいことを呼び出し側が保証。
pub async unsafe fn async_read(
    driver: &NvmePollingDriver,
    core_id: u32,
    nsid: u32,
    lba: u64,
    blocks: u16,
    prp1: u64,
    prp2: u64,
) -> Result<NvmeCompletion, NvmeError> {
    let queue = driver.get_queue(core_id).ok_or(NvmeError::QueueNotFound)?;

    // Safety: 呼び出し元が正しいcore_idを保証
    let cid =
        unsafe { queue.read(nsid, lba, blocks, prp1, prp2) }.map_err(|_| NvmeError::QueueFull)?;

    ReadFuture::new(driver, core_id, cid).await
}

/// 非同期書き込み
///
/// # Safety
/// 現在のコアIDが正しいことを呼び出し側が保証。
pub async unsafe fn async_write(
    driver: &NvmePollingDriver,
    core_id: u32,
    nsid: u32,
    lba: u64,
    blocks: u16,
    prp1: u64,
    prp2: u64,
) -> Result<NvmeCompletion, NvmeError> {
    let queue = driver.get_queue(core_id).ok_or(NvmeError::QueueNotFound)?;

    // Safety: 呼び出し元が正しいcore_idを保証
    let cid =
        unsafe { queue.write(nsid, lba, blocks, prp1, prp2) }.map_err(|_| NvmeError::QueueFull)?;

    WriteFuture::new(driver, core_id, cid).await
}

// ============================================================================
// Helper Functions
// ============================================================================

/// TSCを読む（タイムスタンプカウンタ）
#[inline(always)]
fn read_tsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}
