// ============================================================================
// src/io/nvme/async_io.rs - NVMe Async I/O Support
// ============================================================================
//!
//! # NVMe非同期I/Oサポート
//!
//! 非同期I/Oリクエストとフューチャー実装。
//! Rustのasync/awaitパターンでNVMe操作を実行。
use core::future::Future;
use core::pin::Pin;

use core::task::{Context, Poll};

use super::commands::NvmeCompletion;
use super::error::NvmeError;
use super::polling_driver::NvmePollingDriver;

// ============================================================================
// I/O Request State
// ============================================================================

// Moved to requests.rs

// ============================================================================
// Async I/O Request
// ============================================================================

// Moved to requests.rs

// ============================================================================
// Pending Requests Tracker
// ============================================================================

// Moved to requests.rs

// ============================================================================
// Read Future
// ============================================================================

/// 非同期読み取りFuture
pub struct ReadFuture<'a> {
    driver: &'a NvmePollingDriver,
    core_id: u32,
    cid: u16,
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
        // Check if already completed
        if let Some(queue) = self.driver.get_queue(self.core_id) {
            let pending_requests = queue.get_pending_requests();
            let mut pending = pending_requests.lock();

            // Check if completed
            if let Some(completion) = pending.check_completion(self.cid) {
                // Cleanup and return result
                let _ = pending.take(self.cid);
                if completion.is_success() {
                    return Poll::Ready(Ok(completion));
                } else {
                    return Poll::Ready(Err(NvmeError::CommandError(completion)));
                }
            }

            // Not completed, register waker
            let wake = pending.set_waker(self.cid, cx.waker().clone());

            // Check one more time to avoid race condition
            if let Some(completion) = pending.check_completion(self.cid) {
                // Cleanup and return result
                let _ = pending.take(self.cid);
                if completion.is_success() {
                    return Poll::Ready(Ok(completion));
                } else {
                    return Poll::Ready(Err(NvmeError::CommandError(completion)));
                }
            }
            drop(pending);
            if let Some(waker) = wake {
                waker.wake();
            }
        } else {
            return Poll::Ready(Err(NvmeError::QueueNotFound));
        }

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
            let pending_requests = queue.get_pending_requests();
            let mut pending = pending_requests.lock();

            // Check if completed
            if let Some(completion) = pending.check_completion(self.cid) {
                // Cleanup and return
                let _ = pending.take(self.cid);
                if completion.is_success() {
                    return Poll::Ready(Ok(completion));
                } else {
                    return Poll::Ready(Err(NvmeError::CommandError(completion)));
                }
            }

            // Not completed, register waker
            let wake = pending.set_waker(self.cid, cx.waker().clone());

            // Check one more time
            if let Some(completion) = pending.check_completion(self.cid) {
                // Cleanup and return
                let _ = pending.take(self.cid);
                if completion.is_success() {
                    return Poll::Ready(Ok(completion));
                } else {
                    return Poll::Ready(Err(NvmeError::CommandError(completion)));
                }
            }
            drop(pending);
            if let Some(waker) = wake {
                waker.wake();
            }
        } else {
            return Poll::Ready(Err(NvmeError::QueueNotFound));
        }

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
