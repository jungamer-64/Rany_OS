// ============================================================================
// src/task/mod.rs - Task Definition and Per-Core Executor
// ============================================================================
//!
//! # Task / Per-Core Executor モジュール構成
//!
//! タスク実行に関連する複数のモジュールが存在する。それぞれの責務は以下の通り：
//!
//! ## `mod.rs`（本ファイル）
//! タスクの核となる型定義（`TaskId`, `Task`）と Waker VTable。
//! 他のサブモジュールはすべてここで `pub mod` 宣言され、
//! 主要な型が `pub use` で再エクスポートされる。
//!
//! ## `timeout` (タイムアウトユーティリティ)
//! `TimeoutFuture`, `with_timeout()`, `block_on()`, `spawn_with_timeout()`。
//! 設計書 4.4 対応のタイマーベースyield。
//!
//! ## `per_core_executor` (Per-Core Executor)
//! 通常 boot/runtime で使う正規の実行基盤。
//! `ExecutorManager` が全コアの executor を管理し、BSP/AP とも
//! `run_forever(cpu_id)` で同じ run loop に入る。
//! タスク本体は canonical な `Task` / `TaskId` を共有し、
//! per-core 側では内部 wrapper で優先度や統計を管理する。
//!
use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll};

pub mod environ;
pub mod fuel;
pub mod interrupt_waker;
pub mod io;
pub mod timeout;
mod waker;
pub use crate::drivers::time::{
    PendingTimerWakerStats, current_tick, handle_timer_interrupt, pending_timer_waker_count,
    pending_waker_stats, process_pending_timer_wakers, sleep_ms,
};
pub use environ::{
    EnvError, EnvKey, EnvValue, Environment, get_home, get_path, get_pwd, get_term, get_user,
    kernel_env, set_pwd,
};
pub use interrupt_waker::{
    AtomicWaker, InterruptFuture, InterruptSource, InterruptWakerRegistry, InterruptWakerStats,
    handle_timer_interrupt_waker, interrupt_waker_registry, register_interrupt_waker,
    wait_for_interrupt, wake_from_interrupt,
};
    // 新規追加: タイマー割り込み統合用
pub use waker::create_waker;

// Timeout/block_on utilities re-exported from timeout.rs
pub use timeout::{TimeoutFuture, TimeoutResult, block_on, spawn_with_timeout, with_timeout};

/// タスクID
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskId(u64);

impl TaskId {
    pub fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        TaskId(NEXT_ID.fetch_add(1, Ordering::Relaxed))
    }

    pub const fn from_raw(id: u64) -> Self {
        TaskId(id)
    }
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl Default for TaskId {
    fn default() -> Self {
        Self::new()
    }
}

/// 設計書 4.1: スタックレスコルーチンとしてのタスク
pub struct Task {
    pub id: TaskId,
    pub domain_id: crate::domain::DomainId,
    pub future: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl Task {
    pub fn new(future: impl Future<Output = ()> + Send + 'static) -> Task {
        Task {
            id: TaskId::new(),
            domain_id: crate::domain::current_domain(),
            future: Box::pin(future),
        }
    }

    pub fn poll(&mut self, context: &mut Context) -> Poll<()> {
        self.future.as_mut().poll(context)
    }
}

/// Waker実装用の構造体
mod raw;

/// Spawn a detached task onto the primary phase-2 executor path.
///
/// This is the canonical runtime spawn helper for normal boot and background
/// workers. Experimental per-core executors are intentionally excluded here.
pub fn spawn_detached(future: impl Future<Output = ()> + Send + 'static) -> TaskId {
    spawn_detached_in_domain(future, crate::domain::current_domain())
}

/// Spawn a detached task while explicitly preserving the owning domain.
pub fn spawn_detached_in_domain(
    future: impl Future<Output = ()> + Send + 'static,
    domain_id: crate::domain::DomainId,
) -> TaskId {
    let mut task = Task::new(future);
    task.domain_id = domain_id;
    spawn_task(task)
}
