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
//! - `spawn_with_timeout()`: タイムアウト付きタスクスポーン
//! - `block_on()`: テスト用同期実行ヘルパー
//!
//! ## 注意
//! コアなタスク型定義 (`TaskId`, `Task`) は `task/mod.rs` に残ります。
//! Executor は `task/executor.rs` が担当します。

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use super::timer::current_tick;
use super::{Executor, Task, TaskId};

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
            TimeoutResult::TimedOut => None,
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
    deadline: u64,
    timer_registered: bool,
}

impl<F: Future> TimeoutFuture<F> {
    /// 新しいタイムアウト付きFutureを作成
    pub fn new(future: F, timeout_ms: u64) -> Self {
        Self {
            inner: future,
            deadline: current_tick() + timeout_ms,
            timer_registered: false,
        }
    }
}

impl<F: Future> Future for TimeoutFuture<F> {
    type Output = TimeoutResult<F::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: inner futureをpinするためにunsafeが必要
        let this = unsafe { self.get_unchecked_mut() };

        let now = current_tick();
        let time_service = crate::drivers::time::service();

        // タイムアウトチェック
        if now >= this.deadline {
            // タイマー登録を解除
            if this.timer_registered {
                time_service.unregister_sleep(this.deadline);
                this.timer_registered = false;
            }
            return Poll::Ready(TimeoutResult::TimedOut);
        }

        // 内部Futureをpoll
        // SAFETY: selfがpinnedなので、innerもpinされている
        let inner_pin = unsafe { Pin::new_unchecked(&mut this.inner) };
        match inner_pin.poll(cx) {
            Poll::Ready(result) => {
                // 完了時にタイマー登録を解除
                if this.timer_registered {
                    time_service.unregister_sleep(this.deadline);
                    this.timer_registered = false;
                }
                Poll::Ready(TimeoutResult::Completed(result))
            }
            Poll::Pending => {
                // デッドライン到達時にタスクを起床させるためタイマーwaker登録
                if !this.timer_registered {
                    time_service.register_sleep(this.deadline, cx.waker().clone());
                    this.timer_registered = true;
                }
                Poll::Pending
            }
        }
    }
}

impl<F: Future> Drop for TimeoutFuture<F> {
    fn drop(&mut self) {
        if self.timer_registered {
            crate::drivers::time::service().unregister_sleep(self.deadline);
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
/// }
/// ```
pub fn with_timeout<F: Future>(future: F, timeout_ms: u64) -> TimeoutFuture<F> {
    TimeoutFuture::new(future, timeout_ms)
}

/// Simple helper to synchronously run a `Future` to completion in tests or
/// synchronous contexts. This creates a minimal local Waker that spins waiting
/// to be notified. Intended for tests and transitional use only.
pub fn block_on<F: Future>(future: F) -> F::Output {
    // Shared wake flag
    let flag = Arc::new(AtomicBool::new(false));

    unsafe fn clone_data(data: *const ()) -> RawWaker {
        // Convert back to Arc and increment refcount
        let arc = Arc::from_raw(data as *const AtomicBool);
        let cloned = arc.clone();
        // Re-leak the original Arc
        let _ = Arc::into_raw(arc);
        RawWaker::new(Arc::into_raw(cloned) as *const (), &VTABLE)
    }

    unsafe fn wake_data(data: *const ()) {
        let arc = Arc::from_raw(data as *const AtomicBool);
        arc.store(true, Ordering::SeqCst);
        // Drop original Arc reference obtained from from_raw
    }

    unsafe fn wake_by_ref_data(data: *const ()) {
        let arc = Arc::from_raw(data as *const AtomicBool);
        arc.store(true, Ordering::SeqCst);
        // Re-leak
        let _ = Arc::into_raw(arc);
    }

    unsafe fn drop_data(data: *const ()) {
        // Convert back to Arc and drop it so refcount decreases
        let _arc = Arc::from_raw(data as *const AtomicBool);
    }

    const VTABLE: RawWakerVTable =
        RawWakerVTable::new(clone_data, wake_data, wake_by_ref_data, drop_data);

    // Build initial RawWaker
    let raw = RawWaker::new(Arc::into_raw(flag.clone()) as *const (), &VTABLE);
    let waker = unsafe { Waker::from_raw(raw) };
    let mut cx = Context::from_waker(&waker);

    let mut fut = Box::pin(future);

    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => {
                // Wait until woken
                while !flag.load(Ordering::SeqCst) {
                    core::hint::spin_loop();
                }
                flag.store(false, Ordering::SeqCst);
            }
        }
    }
}

/// タイムアウト付きタスクをスポーン
///
/// 設計書 4.4対応: タイムアウト後は自動的にキャンセル
pub fn spawn_with_timeout<F>(future: F, timeout_ms: u64) -> TaskId
where
    F: Future<Output = ()> + Send + 'static,
{
    let task = Task::new(async move {
        let result = with_timeout(future, timeout_ms).await;
        if result.is_timed_out() {
            log::info!("[TASK] Task timed out after {}ms\n", timeout_ms);
        }
    });

    let task_id = task.id;
    Executor::spawn_global(task);
    task_id
}
