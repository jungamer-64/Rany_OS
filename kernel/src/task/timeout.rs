// ============================================================================
// src/task/timeout.rs - タイムアウトユーティリティ
// ============================================================================
//!
//! # タイムアウト付きFuture
//!
//! 設計書 4.4: タイマーベースのyield
//!
//! ## 責務
//! - `TimeoutResult<T>`: タイムアウト結果型
//! - `TimeoutFuture<F>`: デッドライン付きFutureラッパー
//! - `with_timeout()`: タイムアウト付き実行
//!
//! ## 注意
//! `TimeoutFuture` is polled only as part of its owning scheduler task.
//! 実行基盤と配置判断は `task/scheduler.rs` が担当します。

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use kernel_api::service::time::{SleepFuture, TimerError};

// ============================================================================
// Timeout Support (設計書 4.4)
// ============================================================================

/// タイムアウト結果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutResult<T> {
    /// 正常完了
    Completed(T),
    /// タイムアウト
    TimedOut,
    /// The deadline could not be armed; this is not elapsed time.
    TimerFailed(TimerError),
}

impl<T> TimeoutResult<T> {
    /// 完了したか
    pub fn is_completed(&self) -> bool {
        matches!(self, TimeoutResult::Completed(_))
    }

    /// タイムアウトしたか
    pub fn is_timed_out(&self) -> bool {
        matches!(self, TimeoutResult::TimedOut)
    }

    /// 値を取得（タイムアウト時はNone）
    pub fn ok(self) -> Option<T> {
        match self {
            TimeoutResult::Completed(v) => Some(v),
            TimeoutResult::TimedOut | TimeoutResult::TimerFailed(_) => None,
        }
    }
}

/// タイムアウト付きFuture
///
/// 設計書 4.4: タイマーベースのyield
///
/// 内部Futureが `Pending` を返した場合でも、デッドライン到達時に
/// タイマーwaker経由でタスクを再pollし、タイムアウトを確実に発火させる。
pub struct TimeoutFuture<F: Future> {
    inner: F,
    timer: Option<SleepFuture>,
}

impl<F: Future> TimeoutFuture<F> {
    pub fn new(future: F, timeout_ms: u64) -> Self {
        Self {
            inner: future,
            timer: Some(SleepFuture::new(
                crate::drivers::time::service(),
                timeout_ms,
            )),
        }
    }
}

impl<F: Future> Future for TimeoutFuture<F> {
    type Output = TimeoutResult<F::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: inner is never moved by this implementation, including on
        // completion. Timer registrations are Unpin and have independent owners.
        let this = unsafe { self.get_unchecked_mut() };
        // SAFETY: projection preserves inner's pin for the entire parent lifetime.
        let inner = unsafe { Pin::new_unchecked(&mut this.inner) };
        if let Poll::Ready(result) = inner.poll(cx) {
            // Completion wins if both sides are ready in this poll. Cancellation
            // drops only this timeout's timer; other equal deadlines are untouched.
            this.timer.take();
            return Poll::Ready(TimeoutResult::Completed(result));
        }
        let timer = this
            .timer
            .as_mut()
            .expect("a pending timeout retains its timer");
        match Pin::new(timer).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                this.timer.take();
                Poll::Ready(TimeoutResult::TimedOut)
            }
            Poll::Ready(Err(cause)) => {
                this.timer.take();
                Poll::Ready(TimeoutResult::TimerFailed(cause))
            }
        }
    }
}

/// タイムアウト付きでFutureを実行
///
/// # 例
/// ```ignore
/// let result = with_timeout(some_async_operation(), 1000).await;
/// match result {
///     TimeoutResult::Completed(value) => println!("Got: {:?}", value),
///     TimeoutResult::TimedOut => println!("Operation timed out"),
///     TimeoutResult::TimerFailed(cause) => println!("Cannot arm deadline: {cause}"),
/// }
/// ```
pub fn with_timeout<F: Future>(future: F, timeout_ms: u64) -> TimeoutFuture<F> {
    TimeoutFuture::new(future, timeout_ms)
}
