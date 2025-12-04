// ============================================================================
// src/task/mod.rs - Task Definition and Executor
// ============================================================================
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

pub mod context;
pub mod environ;
mod executor;
pub mod interrupt_waker;
pub mod per_core_executor;
pub mod preemption;
pub mod process;
pub mod scheduler;
pub mod signal;
pub mod timer;
mod work_stealing;

// Phase 4: Advanced Work-Stealing
pub mod work_stealing_advanced;

#[allow(unused_imports)]
pub use context::{CpuContext, KernelStack, TaskControlBlock, TaskState};
#[allow(unused_imports)]
pub use environ::{
    EnvError, EnvKey, EnvValue, Environment, environ, get_home, get_path, get_pwd, get_user,
    getenv, kernel_env, putenv, set_pwd, setenv, unsetenv,
};
pub use executor::Executor;
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
#[allow(unused_imports)]
pub use process::{
    Credentials, ProcessId, ProcessInfo, ProcessManager, ProcessState, ResourceLimits, ThreadId,
    exit as process_exit, getgid, getpid, getppid, getpriority, getuid, process_manager,
    setpriority, spawn as spawn_process, waitpid,
};
#[allow(unused_imports)]
pub use scheduler::{PerCpuScheduler, init_scheduler};
#[allow(unused_imports)]
pub use signal::{
    Signal, SignalAction, SignalContext, SignalFuture, SignalHandler, SignalManager, SignalMask,
    SignalQueue, kill, sigignore, signal as set_signal, signal_manager,
};
pub use timer::{current_tick, sleep_ms};
#[allow(unused_imports)]
pub use work_stealing::{WorkStealingQueue, inject_global, steal_from_global};

// Phase 4: Advanced Work-Stealing re-exports
#[allow(unused_imports)]
pub use work_stealing_advanced::{
    CoreAffinity, GlobalScheduler, PerCoreWorker, Priority as WsPriority, SchedulerStats,
    StealableTask, TaskId as WsTaskId, TaskState as WsTaskState, WorkStealingDeque, WorkerStats,
    init as init_work_stealing, schedule as ws_schedule, spawn as ws_spawn,
};

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
pub struct TimeoutFuture<F: Future> {
    inner: F,
    deadline: u64,
}

impl<F: Future> TimeoutFuture<F> {
    /// 新しいタイムアウト付きFutureを作成
    pub fn new(future: F, timeout_ms: u64) -> Self {
        Self {
            inner: future,
            deadline: current_tick() + timeout_ms,
        }
    }
}

impl<F: Future> Future for TimeoutFuture<F> {
    type Output = TimeoutResult<F::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: inner futureをpinするためにunsafeが必要
        let this = unsafe { self.get_unchecked_mut() };

        // タイムアウトチェック
        if current_tick() >= this.deadline {
            return Poll::Ready(TimeoutResult::TimedOut);
        }

        // 内部Futureをpoll
        // SAFETY: selfがpinnedなので、innerもpinされている
        let inner_pin = unsafe { Pin::new_unchecked(&mut this.inner) };
        match inner_pin.poll(cx) {
            Poll::Ready(result) => Poll::Ready(TimeoutResult::Completed(result)),
            Poll::Pending => Poll::Pending,
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
            crate::log!("[TASK] Task timed out after {}ms\n", timeout_ms);
        }
    });
    
    let task_id = task.id;
    Executor::spawn_global(task);
    task_id
}

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
static WAKER_VTABLE: RawWakerVTable =
    RawWakerVTable::new(waker_clone, waker_wake, waker_wake_by_ref, waker_drop);

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
