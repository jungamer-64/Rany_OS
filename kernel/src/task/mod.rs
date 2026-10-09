// ============================================================================
// src/task/mod.rs - Task definition and topology-aware scheduler
// ============================================================================
//!
//! # Task scheduler
//!
//! タスク実行に関連する複数のモジュールが存在する。それぞれの責務は以下の通り：
//!
//! `TaskPlacement` is the sole placement contract. Scheduler queues are keyed
//! by sparse `CpuId` values and follow the CPU lifecycle state machine.
//!

pub(crate) mod config;
pub(crate) mod context;
pub mod environ;
pub(crate) mod execution;
pub mod fuel;
pub mod interrupt_waker;
mod scheduler;
mod stack;
pub mod timeout;
mod waker;
mod yielding;
pub use crate::drivers::time::{
    current_tick, handle_timer_interrupt, process_pending_timer_wakers, sleep_ms, timer_stats,
};
pub use environ::{
    EnvError, EnvKey, EnvValue, Environment, get_home, get_path, get_pwd, get_term, get_user,
    kernel_env, set_pwd,
};
pub use execution::{
    ExecutionAdmissionError, ExecutionContext, ExecutionContextUnavailable, Subject,
    current_subject, current_task_id,
};
pub(crate) use execution::{
    enter_cell_domain, enter_domain, enter_domain_teardown, enter_resource_callback,
};
pub use interrupt_waker::{
    AtomicWaker, InterruptFuture, InterruptSource, InterruptWakerRegistry, InterruptWakerStats,
    handle_timer_interrupt_waker, interrupt_waker_registry, wait_for_interrupt,
    wake_from_interrupt,
};
pub use scheduler::{
    CpuRunQueueSnapshot, PlacementError, SchedulerSnapshot, SpawnError, TaskOptions, TaskPlacement,
    TaskPriority, initialize_scheduler, run_forever, scheduler_snapshot, spawn,
};
pub(crate) use scheduler::{
    PollBudget, abort_cpu_online, domain_stop_boundary, domain_task_ids, idle_entries,
    prepare_cpu_offline, prepare_cpu_online, publish_cpu_online, quiesce_current_cpu_deferred_work,
    retire_domain_tasks, run_until_parked, spawn_in_domain,
};
pub use yielding::{YieldNow, yield_now, yield_point, yield_point_with_quota_check};

// Deadline composition remains inside the owning task.
pub use timeout::{TimeoutFuture, TimeoutResult, with_timeout};

pub use kernel_api::resource::task::TaskId;
