// ============================================================================
// src/task/per_core_executor.rs - Canonical per-core executor runtime
// 設計書 4.1/4.3: Async-first task runtime with per-core scheduling
// ============================================================================
use crate::sync::PoisonLock;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::task::Wake;
use alloc::vec::Vec;
use core::future::Future;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};
#[cfg(not(feature = "qemu-test-export"))]
use x86_64::instructions::interrupts;

const MAX_CPUS: usize = crate::per_cpu::MAX_CPUS;
const EXECUTOR_BATCH_SIZE: usize = 32;
const LOGICAL_WAKE_QUEUE_CAPACITY: usize = 1024;
const NO_POLLED_TASK_ID: u64 = u64::MAX;
const NO_POLLED_TASK_CPU: usize = usize::MAX;
const EXECUTOR_PHASE_IDLE: u8 = 0;
const EXECUTOR_PHASE_LOOP: u8 = 1;
const EXECUTOR_PHASE_SUSPENDED: u8 = 2;
const EXECUTOR_PHASE_RUN_READY: u8 = 3;
const EXECUTOR_PHASE_POLLING: u8 = 4;
const EXECUTOR_PHASE_WAKE_QUEUE: u8 = 5;
const EXECUTOR_PHASE_FETCH_GLOBAL: u8 = 6;
const EXECUTOR_PHASE_WORK_STEAL: u8 = 7;
const EXECUTOR_PHASE_QUIESCENT: u8 = 8;
const EXECUTOR_PHASE_WAITING: u8 = 9;
const EXECUTOR_RUN_MODE_BOOT: u8 = 0;
const EXECUTOR_RUN_MODE_RUNTIME: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExecutorRunMode {
    Boot = EXECUTOR_RUN_MODE_BOOT,
    Runtime = EXECUTOR_RUN_MODE_RUNTIME,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Priority {
    Realtime = 0,
    High = 1,
    Normal = 2,
    Low = 3,
    Idle = 4,
}

impl Default for Priority {
    fn default() -> Self {
        Self::Normal
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutorStats {
    pub core_id: u32,
    pub tasks_executed: u64,
    pub tasks_stolen: u64,
    pub tasks_stolen_from: u64,
    pub queue_length: usize,
    pub running_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WakeQueueStats {
    pub len: usize,
    pub capacity: usize,
    pub enqueued: usize,
    pub dropped: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlobalQueueStats {
    pub len: usize,
    pub capacity: usize,
    pub enqueued: usize,
    pub dequeued: usize,
    pub dropped: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolledTaskContext {
    pub cpu_id: usize,
    pub task_id: u64,
    pub domain_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum ScheduledTaskState {
    Ready = 0,
    Running = 1,
    Blocked = 2,
    Completed = 3,
}

pub struct WorkStealingQueue<T> {
    inner: PoisonLock<VecDeque<T>>,
}

impl<T> WorkStealingQueue<T> {
    pub fn new() -> Self {
        Self {
            inner: PoisonLock::new(VecDeque::with_capacity(256)),
        }
    }

    pub fn push(&self, item: T) {
        match self.inner.lock() {
            Ok(mut guard) => guard.push_back(item),
            Err(_) => log::error!("[EXECUTOR] queue poisoned during push"),
        }
    }

    pub fn pop(&self) -> Option<T> {
        match self.inner.lock() {
            Ok(mut guard) => guard.pop_back(),
            Err(_) => {
                log::error!("[EXECUTOR] queue poisoned during pop");
                None
            }
        }
    }

    pub fn steal(&self) -> Option<T> {
        match self.inner.lock() {
            Ok(mut guard) => guard.pop_front(),
            Err(_) => {
                log::error!("[EXECUTOR] queue poisoned during steal");
                None
            }
        }
    }

    pub fn steal_matching<F>(&self, mut predicate: F) -> Option<T>
    where
        F: FnMut(&T) -> bool,
    {
        match self.inner.lock() {
            Ok(mut guard) => {
                let idx = guard.iter().position(|item| predicate(item))?;
                guard.remove(idx)
            }
            Err(_) => {
                log::error!("[EXECUTOR] queue poisoned during steal_matching");
                None
            }
        }
    }

    pub fn len(&self) -> usize {
        match self.inner.lock() {
            Ok(guard) => guard.len(),
            Err(_) => 0,
        }
    }
}

impl<T> Default for WorkStealingQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

struct ScheduledTask {
    task: PoisonLock<super::Task>,
    priority: Priority,
    domain_id: crate::domain::DomainId,
    state: AtomicU8,
    queued: AtomicBool,
    affinity_mask: AtomicU64,
    preferred_cpu: AtomicUsize,
    preferred_numa_node: AtomicU8,
    suspended_until_ns: AtomicU64,
    last_run_at: AtomicU64,
    total_run_time: AtomicU64,
    schedule_count: AtomicU64,
}

impl ScheduledTask {
    fn new(
        task: super::Task,
        priority: Priority,
        affinity_mask: u64,
        preferred_cpu: usize,
        preferred_numa_node: Option<usize>,
    ) -> Arc<Self> {
        Arc::new(Self {
            domain_id: task.domain_id,
            task: PoisonLock::new(task),
            priority,
            state: AtomicU8::new(ScheduledTaskState::Ready as u8),
            queued: AtomicBool::new(false),
            affinity_mask: AtomicU64::new(affinity_mask),
            preferred_cpu: AtomicUsize::new(preferred_cpu),
            preferred_numa_node: AtomicU8::new(
                preferred_numa_node
                    .and_then(|node| u8::try_from(node).ok())
                    .unwrap_or(u8::MAX),
            ),
            suspended_until_ns: AtomicU64::new(0),
            last_run_at: AtomicU64::new(0),
            total_run_time: AtomicU64::new(0),
            schedule_count: AtomicU64::new(0),
        })
    }

    fn id(&self) -> super::TaskId {
        match self.task.lock() {
            Ok(guard) => guard.id,
            Err(poisoned) => poisoned.into_inner().id,
        }
    }

    fn begin_queueing(&self) -> bool {
        if self.is_completed() {
            return false;
        }
        !self.queued.swap(true, Ordering::AcqRel)
    }

    fn clear_queued(&self) {
        self.queued.store(false, Ordering::Release);
    }

    fn is_queued(&self) -> bool {
        self.queued.load(Ordering::Acquire)
    }

    fn is_completed(&self) -> bool {
        self.state.load(Ordering::Acquire) == ScheduledTaskState::Completed as u8
    }

    fn set_state(&self, state: ScheduledTaskState) {
        self.state.store(state as u8, Ordering::Release);
    }

    fn state(&self) -> ScheduledTaskState {
        match self.state.load(Ordering::Acquire) {
            x if x == ScheduledTaskState::Ready as u8 => ScheduledTaskState::Ready,
            x if x == ScheduledTaskState::Running as u8 => ScheduledTaskState::Running,
            x if x == ScheduledTaskState::Blocked as u8 => ScheduledTaskState::Blocked,
            _ => ScheduledTaskState::Completed,
        }
    }

    fn suspended_until_ns(&self) -> u64 {
        self.suspended_until_ns.load(Ordering::Acquire)
    }

    fn set_suspended_until_ns(&self, deadline: u64) {
        self.suspended_until_ns.store(deadline, Ordering::Release);
    }

    fn clear_suspended_until_ns(&self) {
        self.suspended_until_ns.store(0, Ordering::Release);
    }

    fn preferred_cpu(&self) -> usize {
        self.preferred_cpu.load(Ordering::Acquire)
    }

    fn set_preferred_cpu(&self, cpu_id: usize) {
        self.preferred_cpu.store(cpu_id, Ordering::Release);
    }

    fn preferred_numa_node(&self) -> Option<usize> {
        let raw = self.preferred_numa_node.load(Ordering::Acquire);
        (raw != u8::MAX).then_some(raw as usize)
    }

    fn set_preferred_numa_node(&self, node: Option<usize>) {
        self.preferred_numa_node.store(
            node.and_then(|value| u8::try_from(value).ok())
                .unwrap_or(u8::MAX),
            Ordering::Release,
        );
    }

    fn can_run_on(&self, cpu_id: usize) -> bool {
        if cpu_id >= 64 {
            return false;
        }
        (self.affinity_mask.load(Ordering::Acquire) & (1u64 << cpu_id)) != 0
    }

    fn poll(&self, context: &mut Context<'_>) -> Poll<()> {
        match self.task.lock() {
            Ok(mut guard) => guard.poll(context),
            Err(poisoned) => {
                log::error!("[EXECUTOR] task lock poisoned during poll");
                let mut guard = poisoned.into_inner();
                guard.poll(context)
            }
        }
    }
}

struct TaskWake {
    task: Arc<ScheduledTask>,
}

impl Wake for TaskWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        executor_manager().queue_wake(self.task.clone());
    }
}

pub struct PerCoreExecutor {
    core_id: u32,
    local_queue: WorkStealingQueue<Arc<ScheduledTask>>,
    high_priority_queue: PoisonLock<VecDeque<Arc<ScheduledTask>>>,
    pending_wakes: WorkStealingQueue<Arc<ScheduledTask>>,
    suspended_queue: PoisonLock<VecDeque<(u64, Arc<ScheduledTask>)>>,
    running_count: AtomicUsize,
    tasks_executed: AtomicU64,
    tasks_stolen: AtomicU64,
    tasks_stolen_from: AtomicU64,
    wake_enqueued: AtomicUsize,
    wake_dropped: AtomicUsize,
    shutdown: AtomicBool,
}

impl PerCoreExecutor {
    pub fn new(core_id: u32) -> Self {
        Self {
            core_id,
            local_queue: WorkStealingQueue::new(),
            high_priority_queue: PoisonLock::new(VecDeque::with_capacity(64)),
            pending_wakes: WorkStealingQueue::new(),
            suspended_queue: PoisonLock::new(VecDeque::with_capacity(64)),
            running_count: AtomicUsize::new(0),
            tasks_executed: AtomicU64::new(0),
            tasks_stolen: AtomicU64::new(0),
            tasks_stolen_from: AtomicU64::new(0),
            wake_enqueued: AtomicUsize::new(0),
            wake_dropped: AtomicUsize::new(0),
            shutdown: AtomicBool::new(false),
        }
    }

    pub fn core_id(&self) -> u32 {
        self.core_id
    }

    pub fn queue_length(&self) -> usize {
        let high = match self.high_priority_queue.lock() {
            Ok(guard) => guard.len(),
            Err(_) => 0,
        };
        self.local_queue.len() + self.pending_wakes.len() + high
    }

    pub fn stats(&self) -> ExecutorStats {
        ExecutorStats {
            core_id: self.core_id,
            tasks_executed: self.tasks_executed.load(Ordering::Relaxed),
            tasks_stolen: self.tasks_stolen.load(Ordering::Relaxed),
            tasks_stolen_from: self.tasks_stolen_from.load(Ordering::Relaxed),
            queue_length: self.queue_length(),
            running_count: self.running_count.load(Ordering::Relaxed),
        }
    }

    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }

    fn enqueue_spawned_task(&self, task: Arc<ScheduledTask>) -> bool {
        if !task.begin_queueing() {
            return false;
        }
        task.set_state(ScheduledTaskState::Ready);
        self.push_ready_already_queued(task)
    }

    fn enqueue_woken_task(&self, task: Arc<ScheduledTask>) -> bool {
        if task.is_completed() {
            return false;
        }

        let suspended_until = task.suspended_until_ns();
        if suspended_until != 0 && crate::time::precise_time_nanos() < suspended_until {
            return false;
        }

        if !task.begin_queueing() {
            return false;
        }

        self.wake_enqueued.fetch_add(1, Ordering::Relaxed);
        task.set_state(ScheduledTaskState::Ready);
        self.pending_wakes.push(task);
        true
    }

    fn push_ready_already_queued(&self, task: Arc<ScheduledTask>) -> bool {
        if task.priority <= Priority::High {
            match self.high_priority_queue.lock() {
                Ok(mut guard) => {
                    guard.push_back(task);
                    true
                }
                Err(_) => {
                    log::error!("[EXECUTOR] high priority queue poisoned");
                    task.clear_queued();
                    self.wake_dropped.fetch_add(1, Ordering::Relaxed);
                    false
                }
            }
        } else {
            self.local_queue.push(task);
            true
        }
    }

    fn next_task(&self) -> Option<Arc<ScheduledTask>> {
        match self.high_priority_queue.lock() {
            Ok(mut guard) => {
                if let Some(task) = guard.pop_front() {
                    task.clear_queued();
                    return Some(task);
                }
            }
            Err(_) => log::error!("[EXECUTOR] high priority queue poisoned"),
        }

        let task = self.local_queue.pop()?;
        task.clear_queued();
        Some(task)
    }

    fn runs_global_runtime_maintenance(&self) -> bool {
        self.core_id == 0
    }

    fn run_local_runtime_maintenance(&self, run_mode: ExecutorRunMode) {
        crate::task::interrupt_waker::process_interrupt_events();
        crate::sync::process_deferred_wakes();
        crate::sync::process_deferred_waker_queue_wakes();
        crate::task::process_pending_timer_wakers();

        if run_mode == ExecutorRunMode::Boot {
            return;
        }

        crate::interrupts::poll_timer_events();
        crate::drivers::hid::keyboard::process_pending_wakes();
        crate::drivers::nvme::per_core::process_deferred_completions_for_core(self.core_id);
        crate::io::io_scheduler::hybrid_coordinator().tick(|| {
            crate::task::interrupt_waker::process_interrupt_events();
        });
    }

    fn run_global_runtime_maintenance(&self, run_mode: ExecutorRunMode) {
        if run_mode == ExecutorRunMode::Boot || !self.runs_global_runtime_maintenance() {
            return;
        }

        crate::io::iommu::api::process_pending_command_queues();
    }

    fn complete_global_runtime_maintenance(&self, run_mode: ExecutorRunMode) {
        if run_mode == ExecutorRunMode::Runtime {
            crate::loader::live_update::enter_quiescent_state();
        }

        if self.runs_global_runtime_maintenance() {
            if run_mode == ExecutorRunMode::Runtime {
                crate::loader::live_update::poll_pending_updates();
                crate::driver_domain::hot_swap::poll_validation_windows();
            }
            crate::io::log::kick_serial_tx();
        }
    }

    fn process_suspended_tasks(&self) {
        let now_ns = crate::time::precise_time_nanos();
        let mut ready = VecDeque::new();

        match self.suspended_queue.lock() {
            Ok(mut queue) => {
                let mut pending = VecDeque::with_capacity(queue.len());
                while let Some((deadline, task)) = queue.pop_front() {
                    if now_ns >= deadline
                        && crate::domain::is_domain_runnable_now(task.domain_id, now_ns)
                    {
                        task.clear_suspended_until_ns();
                        ready.push_back(task);
                    } else {
                        pending.push_back((deadline, task));
                    }
                }
                *queue = pending;
            }
            Err(_) => log::error!("[EXECUTOR] suspended queue poisoned"),
        }

        while let Some(task) = ready.pop_front() {
            let _ = self.enqueue_spawned_task(task);
        }
    }

    fn push_suspended_task(&self, deadline: u64, task: Arc<ScheduledTask>) {
        task.set_suspended_until_ns(deadline);
        match self.suspended_queue.lock() {
            Ok(mut queue) => queue.push_back((deadline, task)),
            Err(_) => {
                log::error!("[EXECUTOR] suspended queue poisoned");
                task.clear_suspended_until_ns();
            }
        }
    }

    fn process_wake_queue(&self) -> usize {
        let mut drained = 0;

        while drained < EXECUTOR_BATCH_SIZE {
            let Some(task) = self.pending_wakes.pop() else {
                break;
            };

            if task.is_completed() {
                task.clear_queued();
                continue;
            }

            let suspended_until = task.suspended_until_ns();
            if suspended_until != 0 && crate::time::precise_time_nanos() < suspended_until {
                task.clear_queued();
                self.push_suspended_task(suspended_until, task);
                continue;
            }

            task.clear_suspended_until_ns();
            let _ = self.push_ready_already_queued(task);
            drained += 1;
        }

        drained
    }

    fn run_ready_tasks(&self) -> usize {
        let mut processed = 0;

        while processed < EXECUTOR_BATCH_SIZE {
            let Some(task) = self.next_task() else {
                break;
            };

            let now_ns = crate::time::precise_time_nanos();
            if !crate::domain::is_domain_runnable_now(task.domain_id, now_ns) {
                let deadline = crate::domain::quota_suspend_deadline_ns(task.domain_id)
                    .unwrap_or_else(|| {
                        now_ns.saturating_add(crate::domain::CPU_QUOTA_SUSPEND_WINDOW_NS)
                    });
                self.push_suspended_task(deadline, task);
                continue;
            }

            self.run_task(task);
            processed += 1;

            if crate::task::preemption::is_preemption_pending() {
                crate::task::fuel::Fuel::exhaust();
                crate::task::preemption::clear_preemption_pending();
                break;
            }

            if crate::task::preemption::check_and_clear_yield_request() {
                break;
            }
        }

        processed
    }

    fn run_task(&self, task: Arc<ScheduledTask>) {
        self.running_count.fetch_add(1, Ordering::Relaxed);
        task.set_state(ScheduledTaskState::Running);
        task.set_preferred_cpu(self.core_id as usize);
        task.set_preferred_numa_node(Some(crate::mm::numa::topology::node_for_cpu(
            self.core_id as usize,
        )));
        task.schedule_count.fetch_add(1, Ordering::Relaxed);

        let start_cycles = read_tsc();
        task.last_run_at.store(start_cycles, Ordering::Relaxed);
        let start_ns = crate::time::precise_time_nanos();

        crate::task::fuel::Fuel::refill(crate::task::fuel::FuelConfig::DEFAULT.default_fuel);
        crate::domain::set_current_domain(task.domain_id);
        crate::task::preemption::set_current_task_domain(task.domain_id.as_u64());
        crate::task::notify_task_started(crate::task::current_tick());
        mark_current_polled_task(self.core_id as usize, task.id(), task.domain_id);
        set_current_executor_phase(self.core_id as usize, EXECUTOR_PHASE_POLLING);

        let waker = Waker::from(Arc::new(TaskWake { task: task.clone() }));
        let mut context = Context::from_waker(&waker);
        let poll_result = task.poll(&mut context);

        clear_current_polled_task();
        crate::task::preemption::set_current_task_domain(0);
        crate::domain::set_current_domain(crate::domain::DomainId::KERNEL);

        let end_cycles = read_tsc();
        let end_ns = crate::time::precise_time_nanos();
        let elapsed_cycles = end_cycles.saturating_sub(start_cycles);
        let elapsed_ns = end_ns.saturating_sub(start_ns);
        task.total_run_time
            .fetch_add(elapsed_cycles, Ordering::Relaxed);

        let mut quota_action = crate::domain::CpuQuotaAction::None;
        if task.domain_id != crate::domain::DomainId::KERNEL {
            let exceeded = crate::domain::quota::quota_manager().consume_cpu_time(
                task.domain_id,
                elapsed_ns,
                end_ns,
            );
            if exceeded {
                quota_action = crate::domain::report_cpu_quota_exceeded(task.domain_id, end_ns);
            } else {
                crate::domain::report_cpu_quota_ok(task.domain_id);
            }
        }

        match poll_result {
            Poll::Ready(()) => {
                task.set_state(ScheduledTaskState::Completed);
                task.clear_suspended_until_ns();
            }
            Poll::Pending => match quota_action {
                crate::domain::CpuQuotaAction::Suspend { until_ns } => {
                    task.set_state(ScheduledTaskState::Blocked);
                    if !task.is_queued() {
                        self.push_suspended_task(until_ns, task.clone());
                    } else {
                        task.set_suspended_until_ns(until_ns);
                    }
                    crate::task::preemption::request_yield();
                }
                crate::domain::CpuQuotaAction::YieldDemote => {
                    task.set_state(ScheduledTaskState::Blocked);
                    crate::task::preemption::request_yield();
                }
                crate::domain::CpuQuotaAction::None => {
                    task.set_state(ScheduledTaskState::Blocked);
                }
            },
        }

        self.running_count.fetch_sub(1, Ordering::Relaxed);
        self.tasks_executed.fetch_add(1, Ordering::Relaxed);
        set_current_executor_phase(self.core_id as usize, EXECUTOR_PHASE_RUN_READY);
    }

    fn steal_from(&self, victim: &PerCoreExecutor) -> bool {
        if let Some(task) = victim
            .local_queue
            .steal_matching(|task| task.can_run_on(self.core_id as usize))
        {
            task.set_preferred_cpu(self.core_id as usize);
            task.set_preferred_numa_node(Some(crate::mm::numa::topology::node_for_cpu(
                self.core_id as usize,
            )));
            self.local_queue.push(task);
            self.tasks_stolen.fetch_add(1, Ordering::Relaxed);
            victim.tasks_stolen_from.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    fn try_steal(&self) -> bool {
        if executor_slot_count() <= 1 {
            return false;
        }

        for candidate in crate::mm::numa::topology::steal_candidates_for_cpu(self.core_id as usize)
        {
            if self.try_steal_from_cpu(candidate) {
                return true;
            }
        }

        false
    }

    fn try_steal_from_cpu(&self, cpu_id: usize) -> bool {
        let Some(victim) = executor_manager().get_executor(cpu_id as u32) else {
            return false;
        };
        if victim.core_id == self.core_id || victim.queue_length() <= 1 {
            return false;
        }
        self.steal_from(&victim)
    }

    fn run_single_iteration(&self, allow_idle_wait: bool) {
        let run_mode = current_run_mode();
        set_current_executor_phase(self.core_id as usize, EXECUTOR_PHASE_LOOP);
        self.run_local_runtime_maintenance(run_mode);
        self.run_global_runtime_maintenance(run_mode);

        set_current_executor_phase(self.core_id as usize, EXECUTOR_PHASE_SUSPENDED);
        self.process_suspended_tasks();

        crate::task::fuel::Fuel::refill(crate::task::fuel::FuelConfig::DEFAULT.default_fuel);
        set_current_executor_phase(self.core_id as usize, EXECUTOR_PHASE_RUN_READY);
        self.run_ready_tasks();

        set_current_executor_phase(self.core_id as usize, EXECUTOR_PHASE_WAKE_QUEUE);
        self.process_wake_queue();

        set_current_executor_phase(self.core_id as usize, EXECUTOR_PHASE_FETCH_GLOBAL);
        executor_manager().drain_bootstrap_queue_to(self.core_id as usize, EXECUTOR_BATCH_SIZE);

        if self.queue_length() == 0 {
            set_current_executor_phase(self.core_id as usize, EXECUTOR_PHASE_WORK_STEAL);
            let _ = self.try_steal();
        }

        set_current_executor_phase(self.core_id as usize, EXECUTOR_PHASE_QUIESCENT);
        self.complete_global_runtime_maintenance(run_mode);

        if allow_idle_wait && self.queue_length() == 0 {
            set_current_executor_phase(self.core_id as usize, EXECUTOR_PHASE_WAITING);

            #[cfg(feature = "qemu-test-export")]
            {
                core::hint::spin_loop();
                return;
            }

            #[cfg(not(feature = "qemu-test-export"))]
            if interrupts_allowed_for_executor() {
                interrupts::enable_and_hlt();
            } else {
                core::hint::spin_loop();
            }
        }
    }

    fn apply_run_mode(&self) {
        if current_run_mode() == ExecutorRunMode::Runtime {
            crate::interrupts::ensure_runtime_local_timer_started();
        }

        if interrupts_allowed_for_executor() {
            if !crate::interrupts::are_interrupts_enabled() {
                crate::interrupts::enable_interrupts();
            }
        } else if crate::interrupts::are_interrupts_enabled() {
            crate::interrupts::disable_interrupts();
        }
    }

    fn run_forever(&self) -> ! {
        loop {
            self.apply_run_mode();

            if self.shutdown.load(Ordering::Acquire) {
                set_current_executor_phase(self.core_id as usize, EXECUTOR_PHASE_IDLE);
                core::hint::spin_loop();
                continue;
            }

            self.run_single_iteration(true);
        }
    }
}

pub struct ExecutorManager {
    executors: PoisonLock<Vec<Arc<PerCoreExecutor>>>,
    bootstrap_queue: PoisonLock<VecDeque<Arc<ScheduledTask>>>,
    global_enqueued: AtomicUsize,
    global_dequeued: AtomicUsize,
    global_dropped: AtomicUsize,
}

impl ExecutorManager {
    pub const fn new() -> Self {
        Self {
            executors: PoisonLock::new(Vec::new()),
            bootstrap_queue: PoisonLock::new(VecDeque::new()),
            global_enqueued: AtomicUsize::new(0),
            global_dequeued: AtomicUsize::new(0),
            global_dropped: AtomicUsize::new(0),
        }
    }

    pub fn init(&self, core_count: usize) {
        let count = core_count.max(1).min(MAX_CPUS);
        let mut executors = self.executors.lock_for_init("[EXECUTOR] init");
        executors.clear();
        for cpu_id in 0..count {
            executors.push(Arc::new(PerCoreExecutor::new(cpu_id as u32)));
        }
        drop(executors);

        self.redistribute_bootstrap_queue();
    }

    fn provision(&self, core_count: usize) {
        let count = core_count.max(1).min(MAX_CPUS);
        let mut executors = self.executors.lock_for_init("[EXECUTOR] provision");
        let current = executors.len();
        if current >= count {
            return;
        }

        // Boot can provision the BSP executor before SMP discovery has settled;
        // later calls only append missing per-core slots so queued work survives.
        executors.reserve(count - current);
        for cpu_id in current..count {
            executors.push(Arc::new(PerCoreExecutor::new(cpu_id as u32)));
        }
        drop(executors);

        self.redistribute_bootstrap_queue();
    }

    pub fn active_cpu_count(&self) -> usize {
        match self.executors.lock() {
            Ok(executors) => executors.len().clamp(1, MAX_CPUS),
            Err(_) => 1,
        }
    }

    pub fn get_executor(&self, core_id: u32) -> Option<Arc<PerCoreExecutor>> {
        match self.executors.lock() {
            Ok(executors) => executors.get(core_id as usize).cloned(),
            Err(_) => None,
        }
    }

    pub fn current_executor(&self) -> Option<Arc<PerCoreExecutor>> {
        self.get_executor(current_core_id() as u32)
    }

    pub fn all_stats(&self) -> Vec<ExecutorStats> {
        match self.executors.lock() {
            Ok(executors) => executors.iter().map(|executor| executor.stats()).collect(),
            Err(_) => Vec::new(),
        }
    }

    pub fn shutdown_all(&self) {
        if let Ok(executors) = self.executors.lock() {
            for executor in executors.iter() {
                executor.shutdown();
            }
        }
    }

    pub fn spawn_task(&self, task: super::Task, priority: Priority) -> super::TaskId {
        let preferred_cpu = current_core_id().min(self.active_cpu_count().saturating_sub(1));
        let preferred_numa_node = crate::mm::numa::topology::node_for_cpu(preferred_cpu);
        self.spawn_task_with_policy(
            task,
            priority,
            self.default_affinity_mask(),
            preferred_cpu,
            Some(preferred_numa_node),
        )
    }

    fn spawn_task_with_policy(
        &self,
        task: super::Task,
        priority: Priority,
        affinity_mask: u64,
        preferred_cpu: usize,
        preferred_numa_node: Option<usize>,
    ) -> super::TaskId {
        let task_id = task.id;
        let scheduled = ScheduledTask::new(
            task,
            priority,
            affinity_mask,
            preferred_cpu,
            preferred_numa_node,
        );
        let target_cpu = self.pick_target_cpu_for_task(&scheduled);
        self.global_enqueued.fetch_add(1, Ordering::Relaxed);

        if let Some(executor) = self.get_executor(target_cpu as u32) {
            if executor.enqueue_spawned_task(scheduled) {
                self.global_dequeued.fetch_add(1, Ordering::Relaxed);
                self.notify_remote_cpu(target_cpu);
            } else {
                self.global_dropped.fetch_add(1, Ordering::Relaxed);
            }
        } else if let Ok(mut queue) = self.bootstrap_queue.lock() {
            queue.push_back(scheduled);
        } else {
            self.global_dropped.fetch_add(1, Ordering::Relaxed);
        }

        task_id
    }

    fn queue_wake(&self, task: Arc<ScheduledTask>) {
        let preferred_cpu = task
            .preferred_cpu()
            .min(self.active_cpu_count().saturating_sub(1));
        let target_cpu = if task.can_run_on(preferred_cpu) {
            preferred_cpu
        } else {
            self.pick_target_cpu_for_task(&task)
        };

        if let Some(executor) = self.get_executor(target_cpu as u32) {
            if executor.enqueue_woken_task(task) {
                self.notify_remote_cpu(target_cpu);
            }
            return;
        }

        if let Some(fallback) = self.get_executor(0) {
            if fallback.enqueue_woken_task(task) {
                self.notify_remote_cpu(0);
            }
        }
    }

    fn redistribute_bootstrap_queue(&self) {
        let mut pending = match self.bootstrap_queue.lock() {
            Ok(mut queue) => core::mem::take(&mut *queue),
            Err(_) => {
                self.global_dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };

        while let Some(task) = pending.pop_front() {
            let target_cpu = self.pick_target_cpu_for_task(&task);
            task.set_preferred_cpu(target_cpu);
            task.set_preferred_numa_node(Some(crate::mm::numa::topology::node_for_cpu(target_cpu)));
            if let Some(executor) = self.get_executor(target_cpu as u32) {
                if executor.enqueue_spawned_task(task) {
                    self.global_dequeued.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.global_dropped.fetch_add(1, Ordering::Relaxed);
                }
            } else {
                self.global_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn drain_bootstrap_queue_to(&self, cpu_id: usize, budget: usize) {
        if self.get_executor(cpu_id as u32).is_none() {
            return;
        }

        let mut drained = 0;
        while drained < budget {
            let task = match self.bootstrap_queue.lock() {
                Ok(mut queue) => queue.pop_front(),
                Err(_) => None,
            };

            let Some(task) = task else {
                break;
            };

            let target_cpu = if task.can_run_on(cpu_id) {
                cpu_id
            } else {
                self.pick_target_cpu_for_task(&task)
            };
            task.set_preferred_cpu(target_cpu);
            task.set_preferred_numa_node(Some(crate::mm::numa::topology::node_for_cpu(target_cpu)));
            let Some(target_executor) = self.get_executor(target_cpu as u32) else {
                self.global_dropped.fetch_add(1, Ordering::Relaxed);
                drained += 1;
                continue;
            };
            if target_executor.enqueue_spawned_task(task) {
                self.global_dequeued.fetch_add(1, Ordering::Relaxed);
                self.notify_remote_cpu(target_cpu);
            } else {
                self.global_dropped.fetch_add(1, Ordering::Relaxed);
            }
            drained += 1;
        }
    }

    fn default_affinity_mask(&self) -> u64 {
        let active = self.active_cpu_count().clamp(1, 64);
        if active >= 64 {
            u64::MAX
        } else {
            (1u64 << active) - 1
        }
    }

    fn pick_target_cpu_for_task(&self, task: &ScheduledTask) -> usize {
        let Ok(executors) = self.executors.lock() else {
            return 0;
        };
        let active_cpu_count = executors.len().clamp(1, MAX_CPUS);
        let preferred_cpu = task.preferred_cpu().min(active_cpu_count.saturating_sub(1));
        let preferred_node = task.preferred_numa_node();

        executors
            .iter()
            .take(active_cpu_count)
            .filter(|executor| task.can_run_on(executor.core_id as usize))
            .min_by_key(|executor| {
                let cpu_id = executor.core_id as usize;
                let node = crate::mm::numa::topology::node_for_cpu(cpu_id);
                let locality_rank = if cpu_id == preferred_cpu {
                    0usize
                } else if preferred_node == Some(node) {
                    1usize
                } else {
                    2usize
                };
                (locality_rank, executor.queue_length(), cpu_id)
            })
            .map(|executor| executor.core_id as usize)
            .unwrap_or_else(|| {
                (0..active_cpu_count)
                    .find(|&cpu_id| task.can_run_on(cpu_id))
                    .unwrap_or(preferred_cpu)
            })
    }

    fn notify_remote_cpu(&self, cpu_id: usize) {
        if self.active_cpu_count() <= 1 || !crate::cpu::workers_released() {
            return;
        }

        if current_core_id() == cpu_id {
            return;
        }

        send_executor_wake_to_cpu(cpu_id);
    }

    pub fn global_queue_stats(&self) -> GlobalQueueStats {
        let (len, capacity) = match self.bootstrap_queue.lock() {
            Ok(queue) => (queue.len(), queue.capacity()),
            Err(_) => (0, 0),
        };

        GlobalQueueStats {
            len,
            capacity,
            enqueued: self.global_enqueued.load(Ordering::Relaxed),
            dequeued: self.global_dequeued.load(Ordering::Relaxed),
            dropped: self.global_dropped.load(Ordering::Relaxed),
        }
    }

    pub fn wake_queue_stats(&self) -> WakeQueueStats {
        let mut len = 0usize;
        let mut enqueued = 0usize;
        let mut dropped = 0usize;
        let mut capacity = 0usize;

        if let Ok(executors) = self.executors.lock() {
            let active_cpu_count = executors.len().clamp(1, MAX_CPUS);
            for executor in executors.iter().take(active_cpu_count) {
                len = len.saturating_add(executor.pending_wakes.len());
                enqueued = enqueued.saturating_add(executor.wake_enqueued.load(Ordering::Relaxed));
                dropped = dropped.saturating_add(executor.wake_dropped.load(Ordering::Relaxed));
                capacity = capacity.saturating_add(LOGICAL_WAKE_QUEUE_CAPACITY);
            }
        }

        WakeQueueStats {
            len,
            capacity,
            enqueued,
            dropped,
        }
    }
}

static EXECUTOR_MANAGER: ExecutorManager = ExecutorManager::new();
static CURRENT_POLLED_TASK_ID: AtomicU64 = AtomicU64::new(NO_POLLED_TASK_ID);
static CURRENT_POLLED_TASK_DOMAIN: AtomicU64 = AtomicU64::new(0);
static CURRENT_POLLED_TASK_CPU: AtomicUsize = AtomicUsize::new(NO_POLLED_TASK_CPU);
static EXECUTOR_RUN_MODE: AtomicU8 = AtomicU8::new(EXECUTOR_RUN_MODE_RUNTIME);
static EXECUTOR_INTERRUPTS_ALLOWED: AtomicBool = AtomicBool::new(true);
static CURRENT_EXECUTOR_PHASE: [AtomicU8; MAX_CPUS] = {
    const INIT: AtomicU8 = AtomicU8::new(EXECUTOR_PHASE_IDLE);
    [INIT; MAX_CPUS]
};

#[cfg(test)]
static LAST_REMOTE_WAKE_APIC: AtomicU64 = AtomicU64::new(u64::MAX);
#[cfg(test)]
static REMOTE_WAKE_BROADCASTS: AtomicUsize = AtomicUsize::new(0);

pub fn executor_manager() -> &'static ExecutorManager {
    &EXECUTOR_MANAGER
}

pub fn init_executors(core_count: usize) {
    EXECUTOR_MANAGER.init(core_count);
}

pub fn provision_executors(core_count: usize) {
    EXECUTOR_MANAGER.provision(core_count);
}

pub fn executor_slot_count() -> usize {
    EXECUTOR_MANAGER.active_cpu_count()
}

pub fn current_polled_task_context() -> Option<PolledTaskContext> {
    let task_id = CURRENT_POLLED_TASK_ID.load(Ordering::Acquire);
    if task_id == NO_POLLED_TASK_ID {
        return None;
    }

    let cpu_id = CURRENT_POLLED_TASK_CPU.load(Ordering::Acquire);
    if cpu_id == NO_POLLED_TASK_CPU {
        return None;
    }

    Some(PolledTaskContext {
        cpu_id,
        task_id,
        domain_id: CURRENT_POLLED_TASK_DOMAIN.load(Ordering::Acquire),
    })
}

pub fn current_executor_phase(cpu_id: usize) -> Option<&'static str> {
    if cpu_id >= MAX_CPUS {
        return None;
    }

    match CURRENT_EXECUTOR_PHASE[cpu_id].load(Ordering::Acquire) {
        EXECUTOR_PHASE_IDLE => Some("idle"),
        EXECUTOR_PHASE_LOOP => Some("loop"),
        EXECUTOR_PHASE_SUSPENDED => Some("suspended"),
        EXECUTOR_PHASE_RUN_READY => Some("run_ready"),
        EXECUTOR_PHASE_POLLING => Some("polling"),
        EXECUTOR_PHASE_WAKE_QUEUE => Some("wake_queue"),
        EXECUTOR_PHASE_FETCH_GLOBAL => Some("fetch_global"),
        EXECUTOR_PHASE_WORK_STEAL => Some("work_steal"),
        EXECUTOR_PHASE_QUIESCENT => Some("quiescent"),
        EXECUTOR_PHASE_WAITING => Some("waiting"),
        _ => None,
    }
}

pub fn global_queue_stats() -> GlobalQueueStats {
    EXECUTOR_MANAGER.global_queue_stats()
}

pub fn wake_queue_stats() -> WakeQueueStats {
    EXECUTOR_MANAGER.wake_queue_stats()
}

pub fn current_run_mode() -> ExecutorRunMode {
    match EXECUTOR_RUN_MODE.load(Ordering::Acquire) {
        EXECUTOR_RUN_MODE_BOOT => ExecutorRunMode::Boot,
        _ => ExecutorRunMode::Runtime,
    }
}

pub fn configure_boot_run_mode(allow_interrupts: bool) {
    EXECUTOR_RUN_MODE.store(ExecutorRunMode::Boot as u8, Ordering::Release);
    EXECUTOR_INTERRUPTS_ALLOWED.store(allow_interrupts, Ordering::Release);
}

pub fn transition_to_runtime_run_mode() {
    EXECUTOR_RUN_MODE.store(ExecutorRunMode::Runtime as u8, Ordering::Release);
}

pub fn configure_runtime_interrupts(allow_interrupts: bool) {
    EXECUTOR_INTERRUPTS_ALLOWED.store(allow_interrupts, Ordering::Release);
}

pub fn spawn<F>(future: F) -> super::TaskId
where
    F: Future<Output = ()> + Send + 'static,
{
    let mut task = super::Task::new(future);
    task.domain_id = crate::domain::current_domain();
    EXECUTOR_MANAGER.spawn_task(task, Priority::Normal)
}

pub fn spawn_with_priority<F>(
    future: F,
    priority: Priority,
    domain_id: Option<u64>,
) -> super::TaskId
where
    F: Future<Output = ()> + Send + 'static,
{
    let mut task = super::Task::new(future);
    if let Some(domain) = domain_id {
        task.domain_id = crate::domain::DomainId::new(domain);
    }
    EXECUTOR_MANAGER.spawn_task(task, priority)
}

pub fn spawn_task(task: super::Task) -> super::TaskId {
    EXECUTOR_MANAGER.spawn_task(task, Priority::Normal)
}

pub(crate) fn spawn_on_cpu_with_priority<F>(
    cpu_id: usize,
    priority: Priority,
    future: F,
) -> super::TaskId
where
    F: Future<Output = ()> + Send + 'static,
{
    let mut task = super::Task::new(future);
    task.domain_id = crate::domain::current_domain();

    let max_cpu = EXECUTOR_MANAGER.active_cpu_count().saturating_sub(1);
    let target_cpu = cpu_id.min(max_cpu);
    let affinity_mask = if target_cpu < u64::BITS as usize {
        1u64 << target_cpu
    } else {
        u64::MAX
    };
    let preferred_numa_node = crate::mm::numa::topology::node_for_cpu(target_cpu);

    EXECUTOR_MANAGER.spawn_task_with_policy(
        task,
        priority,
        affinity_mask,
        target_cpu,
        Some(preferred_numa_node),
    )
}

#[cfg(any(test, feature = "qemu-test-export"))]
pub fn spawn_on_cpu_for_test<F>(cpu_id: usize, future: F) -> super::TaskId
where
    F: Future<Output = ()> + Send + 'static,
{
    spawn_on_cpu_with_priority(cpu_id, Priority::Normal, future)
}

pub fn run_forever(cpu_id: usize) -> ! {
    let executor = EXECUTOR_MANAGER
        .get_executor(cpu_id as u32)
        .unwrap_or_else(|| {
            provision_executors(cpu_id.saturating_add(1));
            EXECUTOR_MANAGER
                .get_executor(cpu_id as u32)
                .expect("executor must exist after provision")
        });

    executor.run_forever()
}

#[inline]
pub(crate) fn read_tsc() -> u64 {
    crate::time::rdtsc_unserialized()
}

#[inline]
pub(crate) fn current_core_id() -> usize {
    crate::cpu::current_id()
}

fn mark_current_polled_task(
    cpu_id: usize,
    task_id: super::TaskId,
    domain_id: crate::domain::DomainId,
) {
    CURRENT_POLLED_TASK_CPU.store(cpu_id, Ordering::Release);
    CURRENT_POLLED_TASK_DOMAIN.store(domain_id.as_u64(), Ordering::Release);
    CURRENT_POLLED_TASK_ID.store(task_id.as_u64(), Ordering::Release);
}

fn clear_current_polled_task() {
    CURRENT_POLLED_TASK_ID.store(NO_POLLED_TASK_ID, Ordering::Release);
    CURRENT_POLLED_TASK_DOMAIN.store(0, Ordering::Release);
    CURRENT_POLLED_TASK_CPU.store(NO_POLLED_TASK_CPU, Ordering::Release);
}

fn set_current_executor_phase(cpu_id: usize, phase: u8) {
    if cpu_id < MAX_CPUS {
        CURRENT_EXECUTOR_PHASE[cpu_id].store(phase, Ordering::Release);
    }
}

fn interrupts_allowed_for_executor() -> bool {
    EXECUTOR_INTERRUPTS_ALLOWED.load(Ordering::Acquire)
}

#[cfg(not(test))]
fn send_executor_wake_to_cpu(cpu_id: usize) {
    crate::cpu::send_ipi(cpu_id, crate::cpu::IpiKind::ExecutorWake);
}

#[cfg(test)]
fn send_executor_wake_to_cpu(cpu_id: usize) {
    if let Some(apic_id) = crate::cpu::apic_id(cpu_id) {
        LAST_REMOTE_WAKE_APIC.store(apic_id as u64, Ordering::Release);
    } else {
        REMOTE_WAKE_BROADCASTS.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(any(test, feature = "qemu-test-export"))]
pub struct TestExecutor {
    local_queue: VecDeque<TestScheduledTask>,
    suspended_queue: VecDeque<(u64, TestScheduledTask)>,
    wake_queue: Arc<TestWakeQueue>,
}

#[cfg(any(test, feature = "qemu-test-export"))]
type TestScheduledTask = Arc<PoisonLock<super::Task>>;

#[cfg(any(test, feature = "qemu-test-export"))]
struct TestWakeQueue {
    queue: PoisonLock<VecDeque<TestScheduledTask>>,
}

#[cfg(any(test, feature = "qemu-test-export"))]
impl TestWakeQueue {
    fn new() -> Self {
        Self {
            queue: PoisonLock::new(VecDeque::with_capacity(128)),
        }
    }

    fn push(&self, task: TestScheduledTask) {
        match self.queue.lock() {
            Ok(mut queue) => queue.push_back(task),
            Err(_) => log::error!("[EXECUTOR][TEST] wake queue poisoned"),
        }
    }

    fn pop(&self) -> Option<TestScheduledTask> {
        match self.queue.lock() {
            Ok(mut queue) => queue.pop_front(),
            Err(_) => None,
        }
    }
}

#[cfg(any(test, feature = "qemu-test-export"))]
struct TestTaskWake {
    task: TestScheduledTask,
    wake_queue: Arc<TestWakeQueue>,
}

#[cfg(any(test, feature = "qemu-test-export"))]
impl Wake for TestTaskWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wake_queue.push(self.task.clone());
    }
}

#[cfg(any(test, feature = "qemu-test-export"))]
impl TestExecutor {
    pub fn new() -> Self {
        Self {
            local_queue: VecDeque::with_capacity(128),
            suspended_queue: VecDeque::with_capacity(64),
            wake_queue: Arc::new(TestWakeQueue::new()),
        }
    }

    pub fn spawn(&mut self, task: super::Task) {
        self.local_queue.push_back(Arc::new(PoisonLock::new(task)));
    }

    pub fn drive_once_for_test(&mut self) {
        crate::interrupts::poll_timer_events();
        crate::drivers::hid::keyboard::process_pending_wakes();
        crate::task::process_pending_timer_wakers();
        crate::task::interrupt_waker::process_interrupt_events();
        crate::sync::process_deferred_wakes();
        crate::sync::process_deferred_waker_queue_wakes();
        crate::drivers::nvme::per_core::process_deferred_completions_for_core(0);
        crate::io::io_scheduler::hybrid_coordinator().tick(|| {
            crate::task::interrupt_waker::process_interrupt_events();
        });
        crate::io::iommu::api::process_pending_command_queues();

        self.process_suspended_tasks();
        crate::task::fuel::Fuel::refill(crate::task::fuel::FuelConfig::DEFAULT.default_fuel);
        self.run_ready_tasks();
        self.process_wake_queue();
        crate::loader::live_update::enter_quiescent_state();
        crate::loader::live_update::poll_pending_updates();
        crate::driver_domain::hot_swap::poll_validation_windows();
        crate::io::log::kick_serial_tx();
    }

    fn process_suspended_tasks(&mut self) {
        if self.suspended_queue.is_empty() {
            return;
        }

        let now_ns = crate::time::precise_time_nanos();
        let mut pending = VecDeque::with_capacity(self.suspended_queue.len());

        while let Some((deadline, task)) = self.suspended_queue.pop_front() {
            let domain_id = match task.lock() {
                Ok(guard) => guard.domain_id,
                Err(poisoned) => poisoned.into_inner().domain_id,
            };

            if now_ns >= deadline && crate::domain::is_domain_runnable_now(domain_id, now_ns) {
                self.local_queue.push_back(task);
            } else {
                pending.push_back((deadline, task));
            }
        }

        self.suspended_queue = pending;
    }

    fn run_ready_tasks(&mut self) {
        let mut processed = 0usize;

        while processed < EXECUTOR_BATCH_SIZE {
            let Some(task) = self.local_queue.pop_front() else {
                break;
            };

            let domain_id = match task.lock() {
                Ok(guard) => guard.domain_id,
                Err(poisoned) => poisoned.into_inner().domain_id,
            };
            let now_ns = crate::time::precise_time_nanos();
            if !crate::domain::is_domain_runnable_now(domain_id, now_ns) {
                let deadline =
                    crate::domain::quota_suspend_deadline_ns(domain_id).unwrap_or_else(|| {
                        now_ns.saturating_add(crate::domain::CPU_QUOTA_SUSPEND_WINDOW_NS)
                    });
                self.suspended_queue.push_back((deadline, task));
                continue;
            }

            let waker = Waker::from(Arc::new(TestTaskWake {
                task: task.clone(),
                wake_queue: self.wake_queue.clone(),
            }));
            let mut context = Context::from_waker(&waker);
            let start_ns = crate::time::precise_time_nanos();

            let poll_result = match task.lock() {
                Ok(mut guard) => {
                    crate::domain::set_current_domain(guard.domain_id);
                    crate::task::preemption::set_current_task_domain(guard.domain_id.as_u64());
                    guard.poll(&mut context)
                }
                Err(poisoned) => {
                    let mut guard = poisoned.into_inner();
                    crate::domain::set_current_domain(guard.domain_id);
                    crate::task::preemption::set_current_task_domain(guard.domain_id.as_u64());
                    guard.poll(&mut context)
                }
            };

            crate::task::preemption::set_current_task_domain(0);
            crate::domain::set_current_domain(crate::domain::DomainId::KERNEL);

            if let Poll::Pending = poll_result {
                let end_ns = crate::time::precise_time_nanos();
                let elapsed_ns = end_ns.saturating_sub(start_ns);
                if domain_id != crate::domain::DomainId::KERNEL {
                    let exceeded = crate::domain::quota::quota_manager()
                        .consume_cpu_time(domain_id, elapsed_ns, end_ns);
                    if exceeded {
                        if let crate::domain::CpuQuotaAction::Suspend { until_ns } =
                            crate::domain::report_cpu_quota_exceeded(domain_id, end_ns)
                        {
                            self.suspended_queue.push_back((until_ns, task));
                        }
                    } else {
                        crate::domain::report_cpu_quota_ok(domain_id);
                    }
                }
            }

            processed += 1;
            if crate::task::preemption::check_and_clear_yield_request() {
                break;
            }
        }
    }

    fn process_wake_queue(&mut self) {
        let mut drained = 0usize;
        while drained < EXECUTOR_BATCH_SIZE {
            let Some(task) = self.wake_queue.pop() else {
                break;
            };
            self.local_queue.push_back(task);
            drained += 1;
        }
    }
}

#[cfg(any(test, feature = "qemu-test-export"))]
impl Default for TestExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "per_core_executor/tests.rs"]
mod tests;
