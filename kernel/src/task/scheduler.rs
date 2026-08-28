use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll};

use spin::Once;

use crate::cpu::{CpuBlocker, CpuId, CpuSet, CurrentCpu};
use crate::sync::PoisonLock;

use super::{ExecutionContext, Task, TaskId, create_waker};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskPlacement {
    Any,
    Prefer(CpuId),
    Pinned(CpuId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnError {
    SchedulerUnavailable,
    NoOnlineCpu,
    CpuNotPresent(CpuId),
    CpuOffline(CpuId),
    DuplicateTaskId(TaskId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuRunQueueSnapshot {
    pub cpu: CpuId,
    pub ready_tasks: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulerSnapshot {
    pub task_count: usize,
    pub poll_count: u64,
    pub run_queues: Arc<[CpuRunQueueSnapshot]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PollWakeState {
    Quiet,
    Woken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TaskRunState {
    Ready { cpu: CpuId },
    Running { cpu: CpuId, wake: PollWakeState },
    Blocked { last_cpu: CpuId },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PollFinalization {
    Completed(crate::domain::DomainId),
    Requeued(CpuId),
}

struct TaskRecord {
    id: TaskId,
    domain: crate::domain::DomainId,
    placement: TaskPlacement,
    future: PoisonLock<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

struct TaskEntry {
    record: Arc<TaskRecord>,
    state: TaskRunState,
}

struct SchedulerState {
    present: CpuSet,
    online: CpuSet,
    queues: BTreeMap<CpuId, VecDeque<TaskId>>,
    tasks: BTreeMap<TaskId, TaskEntry>,
    next_any_member: usize,
}

impl SchedulerState {
    fn from_snapshot(snapshot: &crate::cpu::CpuSnapshot) -> Self {
        let present = snapshot.present().clone();
        let online = snapshot.online().clone();
        let queues = online.iter().map(|id| (id, VecDeque::new())).collect();
        Self {
            present,
            online,
            queues,
            tasks: BTreeMap::new(),
            next_any_member: 0,
        }
    }

    fn select_any(&mut self) -> Result<CpuId, SpawnError> {
        let member_count = self.online.len();
        if member_count == 0 {
            return Err(SpawnError::NoOnlineCpu);
        }
        let member_index = self.next_any_member % member_count;
        self.next_any_member = self.next_any_member.wrapping_add(1);
        self.online
            .member_at(member_index)
            .ok_or(SpawnError::NoOnlineCpu)
    }

    fn select_target(&mut self, placement: TaskPlacement) -> Result<CpuId, SpawnError> {
        match placement {
            TaskPlacement::Any => self.select_any(),
            TaskPlacement::Prefer(id) if self.online.contains(id) => Ok(id),
            TaskPlacement::Prefer(_) => self.select_any(),
            TaskPlacement::Pinned(id) if self.online.contains(id) => Ok(id),
            TaskPlacement::Pinned(id) => {
                if self.present.contains(id) {
                    Err(SpawnError::CpuOffline(id))
                } else {
                    Err(SpawnError::CpuNotPresent(id))
                }
            }
        }
    }

    fn enqueue(&mut self, id: TaskId, cpu: CpuId) -> Result<(), SpawnError> {
        let queue = self
            .queues
            .get_mut(&cpu)
            .ok_or(SpawnError::CpuOffline(cpu))?;
        queue.push_back(id);
        Ok(())
    }

    /// Returns the CPU to notify after publishing the ready state. A wake
    /// during poll is deferred to finish_poll so a future is never polled twice.
    fn apply_wake(&mut self, id: TaskId) -> Option<CpuId> {
        match self.tasks.get(&id)?.state {
            TaskRunState::Ready { .. } => None,
            TaskRunState::Running { cpu, .. } => {
                self.tasks.get_mut(&id)?.state = TaskRunState::Running {
                    cpu,
                    wake: PollWakeState::Woken,
                };
                None
            }
            TaskRunState::Blocked { .. } => {
                let placement = self.tasks.get(&id)?.record.placement;
                let cpu = self.select_target(placement).ok()?;
                self.enqueue(id, cpu)
                    .expect("selected wake target has an online run queue");
                self.tasks.get_mut(&id)?.state = TaskRunState::Ready { cpu };
                Some(cpu)
            }
        }
    }

    fn take_ready(&mut self, cpu: CpuId) -> Option<Arc<TaskRecord>> {
        let queue = self.queues.get_mut(&cpu)?;
        while let Some(id) = queue.pop_front() {
            let Some(entry) = self.tasks.get_mut(&id) else {
                continue;
            };
            if entry.state != (TaskRunState::Ready { cpu }) {
                continue;
            }
            entry.state = TaskRunState::Running {
                cpu,
                wake: PollWakeState::Quiet,
            };
            return Some(entry.record.clone());
        }
        None
    }

    fn finish_poll(&mut self, id: TaskId, cpu: CpuId, poll: Poll<()>) -> Option<PollFinalization> {
        let state = self.tasks.get(&id).map(|entry| entry.state)?;
        let TaskRunState::Running {
            cpu: running_cpu,
            wake,
        } = state
        else {
            return None;
        };
        if running_cpu != cpu {
            return None;
        }

        match poll {
            Poll::Ready(()) => self
                .tasks
                .remove(&id)
                .map(|entry| PollFinalization::Completed(entry.record.domain)),
            Poll::Pending => {
                if wake == PollWakeState::Woken {
                    let placement = self.tasks.get(&id)?.record.placement;
                    if let Ok(target) = self.select_target(placement) {
                        if let Some(entry) = self.tasks.get_mut(&id) {
                            entry.state = TaskRunState::Ready { cpu: target };
                        }
                        self.enqueue(id, target)
                            .expect("selected reschedule target has an online run queue");
                        return Some(PollFinalization::Requeued(target));
                    } else if let Some(entry) = self.tasks.get_mut(&id) {
                        entry.state = TaskRunState::Blocked { last_cpu: cpu };
                    }
                } else if let Some(entry) = self.tasks.get_mut(&id) {
                    entry.state = TaskRunState::Blocked { last_cpu: cpu };
                }
                None
            }
        }
    }

    fn defer_running(&mut self, id: TaskId, cpu: CpuId) {
        let Some(entry) = self.tasks.get_mut(&id) else {
            return;
        };
        if !matches!(entry.state, TaskRunState::Running { cpu: running, .. } if running == cpu) {
            return;
        }
        entry.state = TaskRunState::Ready { cpu };
        self.enqueue(id, cpu)
            .unwrap_or_else(|error| panic!("deferred task lost its CPU run queue: {error:?}"));
    }

    fn pinned_blockers(&self, cpu: CpuId) -> Arc<[CpuBlocker]> {
        self.tasks
            .values()
            .filter_map(|entry| match entry.record.placement {
                TaskPlacement::Pinned(pinned) if pinned == cpu => Some(CpuBlocker::PinnedTask {
                    task_id: entry.record.id.as_u64(),
                }),
                _ => None,
            })
            .collect::<alloc::vec::Vec<_>>()
            .into()
    }

    fn remove_online_cpu(&mut self, cpu: CpuId) -> Result<(), Arc<[CpuBlocker]>> {
        let blockers = self.pinned_blockers(cpu);
        if !blockers.is_empty() {
            return Err(blockers);
        }

        self.online.remove(cpu);
        let queued = self.queues.remove(&cpu).unwrap_or_default();
        for id in queued {
            let placement = match self.tasks.get(&id) {
                Some(entry) => entry.record.placement,
                None => continue,
            };
            let Ok(target) = self.select_target(placement) else {
                continue;
            };
            if let Some(entry) = self.tasks.get_mut(&id) {
                entry.state = TaskRunState::Ready { cpu: target };
            }
            let _ = self.enqueue(id, target);
        }
        Ok(())
    }

    fn add_online_cpu(&mut self, cpu: CpuId, snapshot: &crate::cpu::CpuSnapshot) {
        self.present = snapshot.present().clone();
        self.online = snapshot.online().clone();
        self.queues.entry(cpu).or_default();
    }

    fn prepare_online_cpu(&mut self, cpu: CpuId, snapshot: &crate::cpu::CpuSnapshot) {
        self.present = snapshot.present().clone();
        self.queues.entry(cpu).or_default();
    }

    fn abort_online_cpu(&mut self, cpu: CpuId) {
        self.online.remove(cpu);
        let queue = self.queues.remove(&cpu).unwrap_or_default();
        assert!(
            queue.is_empty(),
            "aborted CPU online preparation retained runnable tasks"
        );
    }
}

pub(crate) struct TaskRuntime {
    state: PoisonLock<SchedulerState>,
    poll_count: AtomicU64,
}

impl TaskRuntime {
    fn new(snapshot: &crate::cpu::CpuSnapshot) -> Self {
        Self {
            state: PoisonLock::new(SchedulerState::from_snapshot(snapshot)),
            poll_count: AtomicU64::new(0),
        }
    }

    fn spawn_task(&self, task: Task) -> Result<TaskId, SpawnError> {
        let id = task.id;
        let domain = task.domain_id;
        let placement = task.placement;
        let record = Arc::new(TaskRecord {
            id,
            domain,
            placement,
            future: PoisonLock::new(task.future),
        });
        let target = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if state.tasks.contains_key(&id) {
                return Err(SpawnError::DuplicateTaskId(id));
            }
            let target = state.select_target(placement)?;
            state.tasks.insert(
                id,
                TaskEntry {
                    record,
                    state: TaskRunState::Ready { cpu: target },
                },
            );
            state.enqueue(id, target)?;
            target
        };
        crate::domain::add_task_to_domain(domain, id.as_u64());
        notify_target(target);
        Ok(id)
    }

    fn poll_one(&self) -> bool {
        let Some(current) = CurrentCpu::acquire() else {
            return false;
        };
        let cpu = current.id();
        loop {
            let target = {
                let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
                // The state lock also serializes the MPSC queue's consumer.
                let Some(id) = super::waker::pop_woken_task() else {
                    break;
                };
                state.apply_wake(id)
            };
            if let Some(target) = target {
                notify_target(target);
            }
        }
        let record = {
            self.state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take_ready(cpu)
        };
        let Some(record) = record else {
            return false;
        };

        let admission_time = crate::time::best_effort_time_nanos();
        if !crate::domain::is_domain_runnable_now(record.domain, admission_time) {
            self.state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .defer_running(record.id, cpu);
            return false;
        }

        let execution = ExecutionContext::for_task(record.id, record.domain);
        let execution_guard = current.enter_execution(execution);
        let waker = create_waker(record.id);
        let mut context = Context::from_waker(&waker);
        let poll_started = crate::time::best_effort_time_nanos();
        let poll = record
            .future
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_mut()
            .poll(&mut context);
        let poll_finished = crate::time::best_effort_time_nanos();
        let elapsed = poll_finished.saturating_sub(poll_started);
        if crate::domain::quota_manager().consume_cpu_time(record.domain, elapsed, poll_finished) {
            let _ = crate::domain::report_cpu_quota_exceeded(record.domain, poll_finished);
        } else {
            crate::domain::report_cpu_quota_ok(record.domain);
        }
        self.poll_count.fetch_add(1, Ordering::Relaxed);
        drop(execution_guard);

        let finalization = self
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .finish_poll(record.id, cpu, poll);
        match finalization {
            Some(PollFinalization::Completed(domain)) => {
                crate::domain::remove_task_from_domain(domain, record.id.as_u64());
            }
            Some(PollFinalization::Requeued(target)) => notify_target(target),
            None => {}
        }
        true
    }

    fn snapshot(&self) -> SchedulerSnapshot {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let run_queues = state
            .queues
            .iter()
            .map(|(&cpu, queue)| CpuRunQueueSnapshot {
                cpu,
                ready_tasks: queue.len(),
            })
            .collect::<alloc::vec::Vec<_>>()
            .into();
        SchedulerSnapshot {
            task_count: state.tasks.len(),
            poll_count: self.poll_count.load(Ordering::Relaxed),
            run_queues,
        }
    }

    fn remove_online_cpu(&self, cpu: CpuId) -> Result<(), Arc<[CpuBlocker]>> {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove_online_cpu(cpu)
    }

    fn add_online_cpu(&self, cpu: CpuId, snapshot: &crate::cpu::CpuSnapshot) {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .add_online_cpu(cpu, snapshot);
    }

    fn prepare_online_cpu(&self, cpu: CpuId, snapshot: &crate::cpu::CpuSnapshot) {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .prepare_online_cpu(cpu, snapshot);
    }

    fn abort_online_cpu(&self, cpu: CpuId) {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .abort_online_cpu(cpu);
    }
}

static TASK_RUNTIME: Once<TaskRuntime> = Once::new();

pub fn initialize_scheduler() -> Result<(), SpawnError> {
    if TASK_RUNTIME.get().is_none() {
        let snapshot = crate::cpu::snapshot();
        TASK_RUNTIME.call_once(|| TaskRuntime::new(&snapshot));
    }
    Ok(())
}

fn runtime() -> Result<&'static TaskRuntime, SpawnError> {
    TASK_RUNTIME.get().ok_or(SpawnError::SchedulerUnavailable)
}

pub fn spawn(
    future: impl Future<Output = ()> + Send + 'static,
    placement: TaskPlacement,
) -> Result<TaskId, SpawnError> {
    spawn_task(Task::new(future, placement))
}

pub(crate) fn spawn_task(task: Task) -> Result<TaskId, SpawnError> {
    runtime()?.spawn_task(task)
}

pub fn scheduler_snapshot() -> Option<SchedulerSnapshot> {
    TASK_RUNTIME.get().map(TaskRuntime::snapshot)
}

pub(crate) fn prepare_cpu_offline(cpu: CpuId) -> Result<(), Arc<[CpuBlocker]>> {
    runtime()
        .unwrap_or_else(|error| {
            panic!("CPU offline requested without scheduler runtime: {error:?}")
        })
        .remove_online_cpu(cpu)
}

pub(crate) fn prepare_cpu_online(cpu: CpuId) {
    let snapshot = crate::cpu::snapshot();
    runtime()
        .unwrap_or_else(|error| panic!("CPU online requested without scheduler runtime: {error:?}"))
        .prepare_online_cpu(cpu, &snapshot);
}

pub(crate) fn abort_cpu_online(cpu: CpuId) {
    runtime()
        .unwrap_or_else(|error| panic!("CPU online abort lost scheduler runtime: {error:?}"))
        .abort_online_cpu(cpu);
}

pub(crate) fn publish_cpu_online(cpu: CpuId) {
    let snapshot = crate::cpu::snapshot();
    runtime()
        .unwrap_or_else(|error| panic!("CPU online commit lost scheduler runtime: {error:?}"))
        .add_online_cpu(cpu, &snapshot);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParkPolicy {
    Reject,
    Return,
}

fn run_scheduler_loop(park_policy: ParkPolicy) {
    let current = CurrentCpu::acquire()
        .unwrap_or_else(|| panic!("scheduler loop entered without CPU-local state"));
    let processes_rcu_callbacks = current.id() == CpuId::BOOTSTRAP;
    loop {
        let mut park_requested = false;
        while let Some(message) = current.take_control() {
            match message {
                crate::cpu::CpuControlMessage::WakeExecutor
                | crate::cpu::CpuControlMessage::Start => {}
                crate::cpu::CpuControlMessage::Park => match park_policy {
                    ParkPolicy::Reject => {
                        panic!("bootstrap scheduler received an illegal park request")
                    }
                    ParkPolicy::Return => park_requested = true,
                },
            }
        }
        crate::sync::process_deferred_wakes();
        crate::sync::process_deferred_waker_queue_wakes();
        crate::interrupts::poll_timer_events();
        super::interrupt_waker::process_interrupt_events();
        // Timer IRQs only advance the clock. Expired sleep/timeout wakers must
        // be delivered outside interrupt context before selecting ready work.
        super::process_pending_timer_wakers();
        if park_requested {
            crate::mm::sync::rcu::rcu_note_context_switch();
            return;
        }
        let made_progress = runtime().is_ok_and(TaskRuntime::poll_one);
        crate::mm::sync::rcu::rcu_note_context_switch();
        if processes_rcu_callbacks {
            crate::mm::sync::rcu::rcu_process_callbacks();
        }
        if !made_progress {
            idle_once();
        }
    }
}

pub(crate) fn run_until_parked() {
    let current = CurrentCpu::acquire()
        .unwrap_or_else(|| panic!("AP scheduler entered without CPU-local state"));
    assert_ne!(
        current.id(),
        CpuId::BOOTSTRAP,
        "bootstrap CPU cannot use the parkable scheduler loop"
    );
    run_scheduler_loop(ParkPolicy::Return);
}

pub(crate) fn quiesce_current_cpu_deferred_work() {
    assert!(
        !crate::interrupts::are_interrupts_enabled(),
        "CPU deferred work can only be retired with local interrupts disabled"
    );
    let current = CurrentCpu::acquire()
        .unwrap_or_else(|| panic!("deferred-work quiescence requires CPU-local state"));

    // These queues are produced only by local interrupt context. Once local
    // interrupts are disabled, each consumer drains its queue to exhaustion
    // and no producer can race the final emptiness check.
    crate::sync::process_deferred_wakes();
    crate::sync::process_deferred_waker_queue_wakes();
    super::interrupt_waker::process_interrupt_events();
    assert_eq!(
        current.pending_deferred_work(),
        0,
        "CPU {} retained deferred operations after local interrupt shutdown",
        current.id(),
    );
}

pub fn run_forever() -> ! {
    run_scheduler_loop(ParkPolicy::Reject);
    unreachable!("bootstrap scheduler loop returned")
}

fn notify_target(cpu: CpuId) {
    if let Some(local) = crate::cpu::runtime().cpu_local(cpu) {
        let remote = local.remote();
        let _ = remote.send(crate::cpu::CpuControlMessage::WakeExecutor);
        remote.request_wake();
        if CurrentCpu::acquire().is_some_and(|current| current.id() != cpu) {
            // No scheduler lock is held here: resolving the destination takes
            // the CPU lifecycle lock. A queue entry alone cannot wake HLT.
            if let Err(error) = crate::cpu::send_ipi(cpu, crate::cpu::IpiKind::ExecutorWake) {
                log::warn!("scheduler could not wake CPU {cpu}: {error:?}");
            }
        }
    }
}

fn idle_once() {
    #[cfg(any(test, feature = "std", target_os = "linux", target_os = "windows"))]
    core::hint::spin_loop();

    #[cfg(not(any(test, feature = "std", target_os = "linux", target_os = "windows")))]
    x86_64::instructions::hlt();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::{ApicId, CpuEjectCapability, FirmwareCpuIdentity, FirmwareCpuUid};

    fn sparse_runtime() -> crate::cpu::CpuRuntime {
        let runtime = crate::cpu::CpuRuntime::bootstrap(ApicId::new(0), None).unwrap();
        let cpu1 = runtime
            .discover_present(FirmwareCpuIdentity {
                uid: Some(FirmwareCpuUid::Integer(1)),
                apic_id: ApicId::new(1),
                proximity_domain: Some(0),
                eject: CpuEjectCapability::FirmwareEject,
            })
            .unwrap();
        let cpu2 = runtime
            .discover_present(FirmwareCpuIdentity {
                uid: Some(FirmwareCpuUid::Integer(2)),
                apic_id: ApicId::new(2),
                proximity_domain: Some(0),
                eject: CpuEjectCapability::FirmwareEject,
            })
            .unwrap();
        assert_ne!(cpu1, cpu2);
        runtime.begin_start(cpu2).unwrap();
        runtime.startup_ready(cpu2).unwrap();
        runtime
    }

    #[test]
    fn any_placement_selects_sparse_online_members() {
        let cpu_runtime = sparse_runtime();
        let mut scheduler = SchedulerState::from_snapshot(&cpu_runtime.snapshot());
        assert_eq!(
            scheduler.select_target(TaskPlacement::Any).unwrap(),
            CpuId::BOOTSTRAP
        );
        assert_eq!(
            scheduler
                .select_target(TaskPlacement::Any)
                .unwrap()
                .as_u16(),
            2
        );
    }

    #[test]
    fn pinned_offline_cpu_is_rejected() {
        let cpu_runtime = sparse_runtime();
        let mut scheduler = SchedulerState::from_snapshot(&cpu_runtime.snapshot());
        let offline = CpuId::try_from(1usize).unwrap();
        assert_eq!(
            scheduler.select_target(TaskPlacement::Pinned(offline)),
            Err(SpawnError::CpuOffline(offline))
        );
    }

    #[test]
    fn wake_reports_notification_only_after_a_task_becomes_ready() {
        let cpu_runtime = sparse_runtime();
        let mut scheduler = SchedulerState::from_snapshot(&cpu_runtime.snapshot());
        let cpu = CpuId::try_from(2usize).unwrap();
        let id = TaskId::new();
        scheduler.tasks.insert(
            id,
            TaskEntry {
                record: Arc::new(TaskRecord {
                    id,
                    domain: crate::domain::DomainId::KERNEL,
                    placement: TaskPlacement::Pinned(cpu),
                    future: PoisonLock::new(Box::pin(async {})),
                }),
                state: TaskRunState::Blocked { last_cpu: cpu },
            },
        );

        assert_eq!(scheduler.apply_wake(id), Some(cpu));
        assert_eq!(scheduler.apply_wake(id), None);
        assert_eq!(scheduler.take_ready(cpu).map(|task| task.id), Some(id));
        // A synchronous wake during poll cannot admit a second poll until
        // the first one has relinquished the future.
        assert_eq!(scheduler.apply_wake(id), None);
        assert!(scheduler.take_ready(cpu).is_none());
        assert_eq!(
            scheduler.finish_poll(id, cpu, Poll::Pending),
            Some(PollFinalization::Requeued(cpu))
        );
        assert_eq!(scheduler.take_ready(cpu).map(|task| task.id), Some(id));
        assert_eq!(
            scheduler.finish_poll(id, cpu, Poll::Ready(())),
            Some(PollFinalization::Completed(crate::domain::DomainId::KERNEL))
        );
        assert_eq!(scheduler.apply_wake(id), None);
    }

    #[test]
    fn deferred_domain_task_remains_ready_on_its_sparse_run_queue() {
        let cpu_runtime = sparse_runtime();
        let mut scheduler = SchedulerState::from_snapshot(&cpu_runtime.snapshot());
        let cpu = CpuId::try_from(2usize).unwrap();
        let id = TaskId::new();
        let record = Arc::new(TaskRecord {
            id,
            domain: crate::domain::DomainId::KERNEL,
            placement: TaskPlacement::Pinned(cpu),
            future: PoisonLock::new(Box::pin(async {}) as Pin<Box<dyn Future<Output = ()> + Send>>),
        });
        scheduler.tasks.insert(
            id,
            TaskEntry {
                record,
                state: TaskRunState::Ready { cpu },
            },
        );
        scheduler.enqueue(id, cpu).unwrap();

        assert_eq!(scheduler.take_ready(cpu).map(|task| task.id), Some(id));
        scheduler.defer_running(id, cpu);

        assert_eq!(scheduler.take_ready(cpu).map(|task| task.id), Some(id));
    }
}
