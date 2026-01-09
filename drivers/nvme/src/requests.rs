// ============================================================================
// src/io/nvme/requests.rs - NVMe I/O Requests State
// ============================================================================
//!
//! # NVMe I/O Requests
//!
//! Defines state structures for tracking async I/O requests.
//! Separated from async_io.rs to break circular dependencies.
//!

use super::commands::NvmeCompletion;
use core::sync::atomic::{AtomicU32, Ordering};
use core::task::Waker;

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
    pub waker: Option<Waker>,
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
            if req.cid == cid && req.is_complete() {
                self.active_count.fetch_sub(1, Ordering::Relaxed);
                return self.requests[idx].take();
            }
        }
        None
    }

    /// Wakerを設定
    pub fn set_waker(&mut self, cid: u16, waker: Waker) -> Option<Waker> {
        let idx = (cid as usize) % 256;
        if let Some(ref mut req) = self.requests[idx] {
            if req.cid == cid {
                if req.is_complete() {
                    return Some(waker);
                }
                req.waker = Some(waker);
                return None;
            }
        }
        Some(waker)
    }

    /// 完了を確認（ステータスチェックのみ）
    pub fn check_completion(&self, cid: u16) -> Option<NvmeCompletion> {
        let idx = (cid as usize) % 256;
        if let Some(ref req) = self.requests[idx] {
            if req.cid == cid && req.is_complete() {
                return req.result().cloned();
            }
        }
        None
    }

    /// アクティブなリクエスト数
    pub fn active_count(&self) -> u32 {
        self.active_count.load(Ordering::Relaxed)
    }
}

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
