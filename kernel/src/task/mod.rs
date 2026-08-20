// ============================================================================
// src/task/mod.rs - Task Definition and Per-Core Executor
// ============================================================================
//!
//! # Task scheduler
//!
//! タスク実行に関連する複数のモジュールが存在する。それぞれの責務は以下の通り：
//!
//! `TaskPlacement` is the sole placement contract. Scheduler queues are keyed
//! by sparse `CpuId` values and follow the CPU lifecycle state machine.
//!
use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};

pub mod environ;
mod execution;
pub mod fuel;
pub mod interrupt_waker;
pub mod io;
mod scheduler;
pub mod timeout;
mod waker;
mod yielding;
pub use crate::drivers::time::{
    PendingTimerWakerStats, current_tick, handle_timer_interrupt, pending_timer_waker_count,
    pending_waker_stats, process_pending_timer_wakers, sleep_ms,
};
pub use environ::{
    EnvError, EnvKey, EnvValue, Environment, get_home, get_path, get_pwd, get_term, get_user,
    kernel_env, set_pwd,
};
pub(crate) use execution::enter_domain;
pub use execution::{
    ExecutionContext, ExecutionContextUnavailable, Subject, current_execution_context,
    current_subject, current_task_id,
};
pub use interrupt_waker::{
    AtomicWaker, InterruptFuture, InterruptSource, InterruptWakerRegistry, InterruptWakerStats,
    handle_timer_interrupt_waker, interrupt_waker_registry, register_interrupt_waker,
    wait_for_interrupt, wake_from_interrupt,
};
pub use scheduler::{
    CpuRunQueueSnapshot, SchedulerSnapshot, SpawnError, TaskPlacement, initialize_scheduler,
    run_forever, scheduler_snapshot, spawn,
};
pub(crate) use scheduler::{
    abort_cpu_online, prepare_cpu_offline, prepare_cpu_online, publish_cpu_online,
    run_until_parked, spawn_task,
};
// 新規追加: タイマー割り込み統合用
pub use waker::create_waker;
pub use waker::{WakeQueueStats, wake_queue_stats};
pub use yielding::{YieldNow, yield_now, yield_point, yield_point_with_quota_check};

// Timeout/block_on utilities re-exported from timeout.rs
pub use timeout::{TimeoutFuture, TimeoutResult, block_on, with_timeout};

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
pub(crate) struct Task {
    pub(crate) id: TaskId,
    pub(crate) domain_id: crate::domain::DomainId,
    pub(crate) placement: TaskPlacement,
    future: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl Task {
    pub(crate) fn new(
        future: impl Future<Output = ()> + Send + 'static,
        placement: TaskPlacement,
    ) -> Task {
        Task {
            id: TaskId::new(),
            domain_id: crate::domain::current_domain(),
            placement,
            future: Box::pin(future),
        }
    }

    pub(crate) fn in_domain(
        future: impl Future<Output = ()> + Send + 'static,
        placement: TaskPlacement,
        domain_id: crate::domain::DomainId,
    ) -> Task {
        Task {
            id: TaskId::new(),
            domain_id,
            placement,
            future: Box::pin(future),
        }
    }
}

/// Waker実装用の構造体
mod raw;
