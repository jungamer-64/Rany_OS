// ============================================================================
// src/task/mod.rs - Task Definition and Executor
// ============================================================================
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use alloc::boxed::Box;
use alloc::sync::Arc;

mod executor;
pub mod timer;
mod work_stealing;
pub mod preemption;
pub mod context;
pub mod scheduler;
pub mod interrupt_waker;
pub mod per_core_executor;
pub mod signal;
pub mod process;
pub mod environ;

pub use executor::Executor;
pub use timer::{sleep_ms, current_tick};
#[allow(unused_imports)]
pub use work_stealing::{WorkStealingQueue, inject_global, steal_from_global};
#[allow(unused_imports)]
pub use preemption::{
    PreemptionController, preemption_controller,
    handle_timer_tick, yield_point, voluntary_yield,
    YieldNow, yield_now, CpuTimeTracker, AdaptiveTimeSlice, PreemptionStats,
    // 新規追加: タイマー割り込み統合用
    should_preempt, request_yield, check_and_clear_yield_request, notify_task_started,
};
#[allow(unused_imports)]
pub use context::{CpuContext, TaskControlBlock, TaskState, KernelStack};
#[allow(unused_imports)]
pub use scheduler::{PerCpuScheduler, init_scheduler};
#[allow(unused_imports)]
pub use interrupt_waker::{
    AtomicWaker, InterruptSource, InterruptWakerRegistry, InterruptWakerStats,
    interrupt_waker_registry, register_interrupt_waker, wake_from_interrupt,
    wait_for_interrupt, InterruptFuture, handle_timer_interrupt_waker,
};
#[allow(unused_imports)]
pub use per_core_executor::{
    PerCoreExecutor, ExecutorManager, ExecutorStats, Priority,
    executor_manager, init_executors, spawn, spawn_with_priority,
    Task as CoreTask, TaskId as CoreTaskId, TaskState as CoreTaskState, TaskMetadata,
};
#[allow(unused_imports)]
pub use signal::{
    Signal, SignalAction, SignalMask, SignalHandler, SignalQueue, SignalContext,
    SignalManager, signal_manager, kill, signal as set_signal, sigignore,
    SignalFuture,
};
#[allow(unused_imports)]
pub use process::{
    ProcessId, ThreadId, ProcessState, Credentials, ResourceLimits, ProcessInfo,
    ProcessManager, process_manager, spawn as spawn_process, exit as process_exit,
    waitpid, getpid, getppid, getuid, getgid, setpriority, getpriority,
};
#[allow(unused_imports)]
pub use environ::{
    EnvKey, EnvValue, EnvError, Environment, kernel_env,
    getenv, setenv, unsetenv, putenv, environ,
    get_path, get_home, get_user, get_pwd, set_pwd,
};

/// タスクID
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskId(u64);

impl TaskId {
    pub fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        TaskId(NEXT_ID.fetch_add(1, Ordering::Relaxed))
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
    pub future: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl Task {
    pub fn new(future: impl Future<Output = ()> + Send + 'static) -> Task {
        Task {
            id: TaskId::new(),
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
static WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    waker_clone,
    waker_wake,
    waker_wake_by_ref,
    waker_drop,
);

unsafe fn waker_clone(data: *const ()) -> RawWaker {
    // Arc::cloneと同等の処理
    // SAFETY: dataはArc::into_rawで変換されたポインタ
    unsafe {
        let arc = Arc::from_raw(data as *const TaskWaker);
        let cloned = arc.clone();
        core::mem::forget(arc); // from_rawで作ったArcはforgetする
        RawWaker::new(Arc::into_raw(cloned) as *const (), &WAKER_VTABLE)
    }
}

unsafe fn waker_wake(data: *const ()) {
    // 所有権を取得してwake
    // SAFETY: dataはArc::into_rawで変換されたポインタ
    unsafe {
        let arc = Arc::from_raw(data as *const TaskWaker);
        arc.wake_task();
        // Arcは自動的にdropされる
    }
}

unsafe fn waker_wake_by_ref(data: *const ()) {
    // 参照としてwake
    // SAFETY: dataはArc::into_rawで変換されたポインタ
    unsafe {
        let arc = Arc::from_raw(data as *const TaskWaker);
        arc.wake_task();
        core::mem::forget(arc); // from_rawで作ったArcはforgetする
    }
}

unsafe fn waker_drop(data: *const ()) {
    // Arc をdrop
    // SAFETY: dataはArc::into_rawで変換されたポインタ
    unsafe {
        drop(Arc::from_raw(data as *const TaskWaker));
    }
}

/// Wakerを作成する公開API
pub fn create_waker(task_id: TaskId) -> Waker {
    let task_waker = Arc::new(TaskWaker { task_id });
    let raw_waker = RawWaker::new(Arc::into_raw(task_waker) as *const (), &WAKER_VTABLE);
    unsafe { Waker::from_raw(raw_waker) }
}
