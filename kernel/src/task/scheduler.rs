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

    fn drain_wakes(&mut self) {
        while let Some(id) = super::waker::pop_woken_task() {
            let Some(state) = self.tasks.get(&id).map(|entry| entry.state) else {
                continue;
            };
            match state {
                TaskRunState::Ready { .. } => {}
                TaskRunState::Running { cpu, .. } => {
                    if let Some(entry) = self.tasks.get_mut(&id) {
                        entry.state = TaskRunState::Running {
                            cpu,
                            wake: PollWakeState::Woken,
                        };
                    }
                }
                TaskRunState::Blocked { .. } => {
                    let placement = match self.tasks.get(&id) {
                        Some(entry) => entry.record.placement,
                        None => continue,
                    };
                    let Ok(cpu) = self.select_target(placement) else {
                        continue;
                    };
                    if let Some(entry) = self.tasks.get_mut(&id) {
                        entry.state = TaskRunState::Ready { cpu };
                    }
                    let _ = self.enqueue(id, cpu);
                }
            }
        }
    }

    fn take_ready(&mut self, cpu: CpuId) -> Option<Arc<TaskRecord>> {
        self.drain_wakes();
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

    fn finish_poll(
        &mut self,
        id: TaskId,
        cpu: CpuId,
        poll: Poll<()>,
    ) -> Option<crate::domain::DomainId> {
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
            Poll::Ready(()) => self.tasks.remove(&id).map(|entry| entry.record.domain),
            Poll::Pending => {
                if wake == PollWakeState::Woken {
                    let placement = self.tasks.get(&id)?.record.placement;
                    if let Ok(target) = self.select_target(placement) {
                        if let Some(entry) = self.tasks.get_mut(&id) {
                            entry.state = TaskRunState::Ready { cpu: target };
                        }
                        let _ = self.enqueue(id, target);
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
        let record = {
            self.state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take_ready(cpu)
        };
        let Some(record) = record else {
            return false;
        };

        let execution = ExecutionContext::for_task(cpu, record.id, record.domain);
        let execution_guard = current.enter_execution(execution);
        let waker = create_waker(record.id);
        let mut context = Context::from_waker(&waker);
        let poll = record
            .future
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_mut()
            .poll(&mut context);
        self.poll_count.fetch_add(1, Ordering::Relaxed);
        drop(execution_guard);

        let completed_domain = self
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .finish_poll(record.id, cpu, poll);
        if let Some(domain) = completed_domain {
            crate::domain::remove_task_from_domain(domain, record.id.as_u64());
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
    match runtime() {
        Ok(runtime) => runtime.remove_online_cpu(cpu),
        Err(_) => Ok(()),
    }
}

pub(crate) fn prepare_cpu_online(cpu: CpuId) {
    if let Ok(runtime) = runtime() {
        let snapshot = crate::cpu::snapshot();
        runtime.prepare_online_cpu(cpu, &snapshot);
    }
}

pub(crate) fn publish_cpu_online(cpu: CpuId) {
    if let Ok(runtime) = runtime() {
        let snapshot = crate::cpu::snapshot();
        runtime.add_online_cpu(cpu, &snapshot);
    }
}

pub fn run_forever() -> ! {
    let processes_rcu_callbacks =
        CurrentCpu::acquire().is_some_and(|current| current.id() == CpuId::BOOTSTRAP);
    loop {
        crate::sync::process_deferred_wakes();
        crate::sync::process_deferred_waker_queue_wakes();
        super::interrupt_waker::process_interrupt_events();
        crate::io::io_scheduler::process_deferred_completions_local();
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

fn notify_target(cpu: CpuId) {
    if let Some(local) = crate::cpu::runtime().cpu_local(cpu) {
        let remote = local.remote();
        let _ = remote.send(crate::cpu::CpuControlMessage::WakeExecutor);
        remote.request_wake();
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
}
