// ============================================================================
// src/task/mod.rs - Task Definition and Executor
// ============================================================================
//!
//! # Executor / Work-Stealing モジュール構成
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
//! ## `executor` (プライマリExecutor)
//! カーネル起動時に使用されるシンプルなExecutor。ロックフリーMPMCキューベースで、
//! `Executor::new()` → `executor.spawn()` → `executor.run()` の流れで使用。
//! `Executor::spawn_global()` でISRからのタスク投入も可能。
//! **kmain_innerで使用される唯一のExecutorループ。**
//!
//! ## `per_core_executor` (Per-Core Executor)
//! コアごとに独立したExecutorインスタンスを持つ、スケーラブルな実験アーキテクチャ。
//! `ExecutorManager` が全コアのExecutorを管理し、`spawn()` APIで自動コア選択。
//! `PoisonLock<VecDeque<T>>` ベースのWorkStealingQueue内包。
//! **通常ブートのフェーズ2ランタイムでは使用せず、フェーズ4以降の拡張用に維持する。**
//!
//! ## `work_stealing` (Global Injector Queue)
//! グローバルなタスク注入キュー。`inject_global()` / `steal_from_global()` 。
//! ※Per-Core用キューは `work_stealing_advanced` に移行済み。
//!
//! ## `work_stealing_advanced` (NUMA対応高性能スケジューラ)
//! NUMA対応の3段階スティーリング、`WorkStealingDeque`、`PerCoreWorker`、
//! `GlobalScheduler` を提供する Phase 4 の高度なスケジューラ実装。
//!
#![allow(dead_code)]
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

pub mod context;
pub mod environ;
mod executor;
pub mod fuel;
pub mod interrupt_waker;
pub mod io;
pub mod per_core_executor;
pub mod preemption;
pub mod timeout;
pub mod timer;
pub mod waker;
mod work_stealing;

// Phase 4: Advanced Work-Stealing
pub mod work_stealing_advanced;

#[allow(unused_imports)]
pub use context::{
    CpuContext, KernelStack, Subject, TaskControlBlock, TaskState, current_subject, current_task_id,
};
#[allow(unused_imports)]
pub use environ::{
    EnvError, EnvKey, EnvValue, Environment, get_home, get_path, get_pwd, get_term, get_user,
    kernel_env, set_pwd,
};
pub(crate) use executor::run_boxed_cold_start;
pub use executor::{
    Executor, active_cpu_count as executor_active_cpu_count, current_executor_phase,
    current_polled_task_context, register_cpu,
    set_active_cpu_count as set_executor_active_cpu_count,
};
#[allow(unused_imports)]
pub use interrupt_waker::{
    AtomicWaker, InterruptFuture, InterruptSource, InterruptWakerRegistry, InterruptWakerStats,
    handle_timer_interrupt_waker, interrupt_waker_registry, register_interrupt_waker,
    wait_for_interrupt, wake_from_interrupt,
};
#[allow(unused_imports)]
pub use per_core_executor::{
    ExecutorManager, ExecutorStats, PerCoreExecutor, Priority, Task as CoreTask,
    TaskId as CoreTaskId, TaskMetadata, TaskState as CoreTaskState, executor_manager,
    init_executors, spawn, spawn_with_priority,
};
#[allow(unused_imports)]
pub use preemption::{
    AdaptiveTimeSlice,
    CpuTimeTracker,
    PreemptionController,
    PreemptionStats,
    YieldNow,
    check_and_clear_yield_request,
    handle_timer_tick,
    notify_task_started,
    preemption_controller,
    request_yield,
    // 新規追加: タイマー割り込み統合用
    should_preempt,
    voluntary_yield,
    yield_now,
    yield_point,
};
pub use timer::{current_tick, sleep_ms};
#[allow(unused_imports)]
pub use waker::{
    WakeQueueStats, pop_woken_task, wake_queue_capacity, wake_queue_is_empty, wake_queue_len,
    wake_queue_stats,
};
#[allow(unused_imports)]
pub use work_stealing::{
    GlobalQueueStats, global_queue_len, global_queue_stats, inject_global, steal_from_global,
};

// Phase 4: Advanced Work-Stealing re-exports
#[allow(unused_imports)]
pub use work_stealing_advanced::{
    CoreAffinity, GlobalScheduler, PerCoreWorker, Priority as WsPriority, SchedulerStats,
    StealableTask, TaskId as WsTaskId, TaskState as WsTaskState, WorkStealingDeque, WorkerStats,
    init as init_work_stealing, schedule as ws_schedule, spawn as ws_spawn,
};

// Timeout/block_on utilities re-exported from timeout.rs
#[allow(unused_imports)]
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

    #[allow(dead_code)]
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
    pub domain_id: crate::domain_system::DomainId,
    pub future: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl Task {
    pub fn new(future: impl Future<Output = ()> + Send + 'static) -> Task {
        Task {
            id: TaskId::new(),
            domain_id: crate::domain_system::current_domain(),
            future: Box::pin(future),
        }
    }

    pub fn poll(&mut self, context: &mut Context) -> Poll<()> {
        self.future.as_mut().poll(context)
    }
}

/// Waker実装用の構造体
struct TaskWaker {
    task_id: TaskId,
}

impl TaskWaker {
    fn wake_task(&self) {
        // Wake queueにタスクIDを追加
        executor::wake_task(self.task_id);
    }
}

/// RawWaker用のVTable
/// これが最も複雑な部分 - 手動でWakerのVTableを構築
mod raw;

static WAKER_VTABLE: RawWakerVTable =
    RawWakerVTable::new(waker_clone, waker_wake, waker_wake_by_ref, waker_drop);

unsafe fn waker_clone(data: *const ()) -> RawWaker {
    // Arc::cloneと同等の処理
    // SAFETY: dataはArc::into_rawで変換されたポインタ
    unsafe {
        let arc = raw::arc_from_raw(data as *const TaskWaker);
        let cloned = arc.clone();
        core::mem::forget(arc); // from_rawで作ったArcはforgetする
        RawWaker::new(Arc::into_raw(cloned) as *const (), &WAKER_VTABLE)
    }
}

unsafe fn waker_wake(data: *const ()) {
    // 所有権を取得してwake
    // SAFETY: dataはArc::into_rawで変換されたポインタ
    unsafe {
        let arc = raw::arc_from_raw(data as *const TaskWaker);
        arc.wake_task();
        // Arcは自動的にdropされる
    }
}

unsafe fn waker_wake_by_ref(data: *const ()) {
    // 参照としてwake
    // SAFETY: dataはArc::into_rawで変換されたポインタ
    unsafe {
        let arc = raw::arc_from_raw(data as *const TaskWaker);
        arc.wake_task();
        core::mem::forget(arc); // from_rawで作ったArcはforgetする
    }
}

unsafe fn waker_drop(data: *const ()) {
    // Arc をdrop
    // SAFETY: dataはArc::into_rawで変換されたポインタ
    unsafe {
        drop(raw::arc_from_raw(data as *const TaskWaker));
    }
}

/// Wakerを作成する公開API
pub fn create_waker(task_id: TaskId) -> Waker {
    let task_waker = Arc::new(TaskWaker { task_id });
    let raw_waker = RawWaker::new(Arc::into_raw(task_waker) as *const (), &WAKER_VTABLE);
    unsafe { Waker::from_raw(raw_waker) }
}

/// Spawn a detached task onto the primary phase-2 executor path.
///
/// This is the canonical runtime spawn helper for normal boot and background
/// workers. Experimental per-core executors are intentionally excluded here.
pub fn spawn_detached(future: impl Future<Output = ()> + Send + 'static) -> TaskId {
    spawn_detached_in_domain(future, crate::domain_system::current_domain())
}

/// Spawn a detached task while explicitly preserving the owning domain.
pub fn spawn_detached_in_domain(
    future: impl Future<Output = ()> + Send + 'static,
    domain_id: crate::domain_system::DomainId,
) -> TaskId {
    let mut task = Task::new(future);
    task.domain_id = domain_id;
    let task_id = task.id;
    Executor::spawn_global(task);
    task_id
}
