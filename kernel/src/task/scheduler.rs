use alloc::boxed::Box;
use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll};

use crate::sync::InitOnce;

use crate::cpu::{CpuBlocker, CpuId, CpuSet, CurrentCpu};
#[cfg(test)]
use crate::mm::types::NumaNodeId;
use crate::mm::virt::higher_half::MapError;
use crate::sync::PoisonLock;

use super::context::TaskContext;
use super::stack::{StackError, TaskStack};
use super::waker::{WakeLease, wake_revision};
use super::{ExecutionContext, TaskId};

pub use kernel_api::resource::task::{
    PlacementError, SpawnError, TaskMappingError, TaskOptions, TaskPlacement, TaskPriority,
};

impl From<StackError> for SpawnError {
    fn from(error: StackError) -> Self {
        match error {
            StackError::SlotsExhausted => Self::TaskSlotsExhausted,
            StackError::PhysicalMemoryExhausted
            | StackError::Mapping(MapError::FrameAllocationFailed) => Self::PhysicalMemoryExhausted,
            StackError::Mapping(error) => Self::MappingFailed(match error {
                MapError::AlreadyMapped => TaskMappingError::AlreadyMapped,
                MapError::NotMapped => TaskMappingError::NotMapped,
                MapError::InvalidAddress => TaskMappingError::InvalidAddress,
                MapError::AlignmentError => TaskMappingError::Alignment,
                MapError::ParentEntryHugePage => TaskMappingError::ParentHugePage,
                MapError::ParentPermissionDenied => TaskMappingError::ParentPermissionDenied,
                MapError::HardwareError => TaskMappingError::Hardware,
                MapError::FrameAllocationFailed => unreachable!(),
            }),
        }
    }
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
    pub pending_wakes: usize,
    pub forced_switches: u64,
    pub runtime_ns: u64,
    pub quota_waiting: usize,
    pub interrupted_polls: usize,
    pub run_queues: Arc<[CpuRunQueueSnapshot]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PollWakeState {
    Quiet,
    Woken,
}

#[derive(Debug, Clone)]
enum TaskRunState {
    Ready {
        cpu: CpuId,
    },
    Running {
        cpu: CpuId,
        wake: PollWakeState,
    },
    EventWaiting {
        last_cpu: CpuId,
    },
    Interrupted {
        cpu: CpuId,
        wake: PollWakeState,
        continuation: PollContinuation,
    },
    QuotaWaiting {
        deadline_ns: u64,
        resume: QuotaResume,
    },
    Finished,
}

#[derive(Debug, Clone)]
struct PollContinuation {
    execution: ExecutionContext,
    fuel: u64,
}

#[derive(Debug, Clone)]
enum QuotaResume {
    Ready {
        last_cpu: CpuId,
    },
    Interrupted {
        cpu: CpuId,
        wake: PollWakeState,
        continuation: PollContinuation,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PollFinalization {
    Completed(crate::domain::DomainId),
    Requeued(CpuId),
}

struct TaskRecord {
    id: TaskId,
    domain: crate::domain::DomainId,
    options: TaskOptions,
    future: TaskFuture,
    wake: WakeLease,
    context: TaskContext,
    stack: TaskStack,
}

impl TaskRecord {
    fn can_begin_poll(&self) -> bool {
        if self.future.finalization.is_some() {
            crate::domain::registry::can_finalize(self.domain)
        } else {
            crate::domain::is_domain_runnable_now(self.domain, crate::time::precise_time_nanos())
        }
    }
}

/// Scheduler state grants one CPU exclusive poll authority. An interrupted
/// poll keeps its mutable borrow on that CPU's saved stack and is resumed,
/// never entered a second time. Wake paths may only mutate scheduler state.
struct TaskFuture {
    future: UnsafeCell<TaskFutureStorage>,
    // Field order keeps Drop code leased until the Future's destructor returns.
    code: crate::domain::DomainCodeLease,
    finalization: Option<super::execution::FinalizationAuthority>,
}

// SAFETY: the task state machine admits exactly one Running or Interrupted
// owner. The Future is accessed only by that owner's task stack, and the
// record cannot be destroyed until the stack has returned from poll.
unsafe impl Sync for TaskFuture {}

impl TaskFuture {
    fn new(
        future: Pin<Box<dyn Future<Output = ()> + Send>>,
        code: crate::domain::DomainCodeLease,
        finalization: Option<super::execution::FinalizationAuthority>,
    ) -> Self {
        Self {
            future: UnsafeCell::new(future),
            code,
            finalization,
        }
    }

    /// # Safety
    /// The caller must hold the scheduler's exclusive running-poll authority
    /// for this task. An interrupted poll retains that authority until resumed.
    unsafe fn poll(&self, context: &mut Context<'_>) -> Poll<()> {
        unsafe { (&mut *self.future.get()).as_mut().poll(context) }
    }
}

struct TaskEntry {
    record: Arc<TaskRecord>,
    state: TaskRunState,
    virtual_runtime: u128,
    runtime_ns: u64,
}

struct ScheduledTask {
    record: Arc<TaskRecord>,
    continuation: Option<PollContinuation>,
}

/// Initial preferences choose a new task's placement. A returned poll retains
/// its last CPU and node first; this hint never authorizes moving a saved poll.
enum PlacementOrigin {
    Spawn(Option<CpuId>),
    PollBoundary(CpuId),
}

/// Registration is indexed by the reserved arena slot, so publication and
/// every queue transition need no allocator after spawn preparation.
struct TaskTable([Option<TaskEntry>; super::config::SCHEDULER_CONFIG.max_tasks]);

impl TaskTable {
    fn new() -> Self {
        Self([const { None }; super::config::SCHEDULER_CONFIG.max_tasks])
    }

    fn values(&self) -> impl Iterator<Item = &TaskEntry> {
        self.0.iter().flatten()
    }

    fn iter(&self) -> impl Iterator<Item = (&TaskId, &TaskEntry)> {
        self.values().map(|entry| (&entry.record.id, entry))
    }

    fn len(&self) -> usize {
        self.values().count()
    }

    fn get(&self, id: &TaskId) -> Option<&TaskEntry> {
        self.values().find(|entry| entry.record.id == *id)
    }

    fn get_mut(&mut self, id: &TaskId) -> Option<&mut TaskEntry> {
        self.0
            .iter_mut()
            .flatten()
            .find(|entry| entry.record.id == *id)
    }

    fn contains_key(&self, id: &TaskId) -> bool {
        self.get(id).is_some()
    }

    fn insert(&mut self, id: TaskId, entry: TaskEntry) {
        let slot = entry.record.stack.slot();
        assert_eq!(entry.record.id, id);
        assert!(
            self.0[slot].is_none(),
            "reserved task slot already published"
        );
        self.0[slot] = Some(entry);
    }

    fn remove(&mut self, id: &TaskId) -> Option<TaskEntry> {
        let slot = self.get(id)?.record.stack.slot();
        self.0[slot].take()
    }
}

#[derive(Clone, Copy)]
struct RunQueue([u64; RUN_QUEUE_WORDS]);

const RUN_QUEUE_WORDS: usize = super::config::SCHEDULER_CONFIG
    .max_tasks
    .div_ceil(u64::BITS as usize);

impl RunQueue {
    const fn new() -> Self {
        Self([0; RUN_QUEUE_WORDS])
    }
    fn insert(&mut self, slot: usize) {
        assert!(!self.contains(slot), "task enqueued twice");
        self.0[slot / 64] |= 1 << (slot % 64);
    }
    fn remove(&mut self, slot: usize) {
        self.0[slot / 64] &= !(1 << (slot % 64));
    }
    fn contains(&self, slot: usize) -> bool {
        self.0[slot / 64] & (1 << (slot % 64)) != 0
    }
    fn len(&self) -> usize {
        self.0.iter().map(|word| word.count_ones() as usize).sum()
    }
    fn is_empty(&self) -> bool {
        self.0.iter().all(|&word| word == 0)
    }
}

struct SchedulerState {
    present: CpuSet,
    online: CpuSet,
    queues: [RunQueue; crate::cpu::MAX_POSSIBLE_CPUS],
    tasks: TaskTable,
    next_any_member: usize,
    min_virtual_runtime: u128,
}

impl SchedulerState {
    fn from_snapshot(snapshot: &crate::cpu::CpuSnapshot) -> Self {
        let present = snapshot.present().clone();
        let online = snapshot.online().clone();
        Self {
            present,
            online,
            queues: [RunQueue::new(); crate::cpu::MAX_POSSIBLE_CPUS],
            tasks: TaskTable::new(),
            next_any_member: 0,
            min_virtual_runtime: 0,
        }
    }

    fn select_any(&mut self, allowed: &CpuSet) -> Result<CpuId, SpawnError> {
        let member_count = self
            .online
            .iter()
            .filter(|id| allowed.contains(*id))
            .count();
        if member_count == 0 {
            return Err(if self.online.is_empty() {
                SpawnError::NoOnlineCpu
            } else {
                SpawnError::PlacementUnavailable
            });
        }
        let member_index = self.next_any_member % member_count;
        self.next_any_member = self.next_any_member.wrapping_add(1);
        self.online
            .iter()
            .filter(|id| allowed.contains(*id))
            .nth(member_index)
            .ok_or(SpawnError::NoOnlineCpu)
    }

    fn select_target(
        &mut self,
        placement: TaskPlacement,
        origin: PlacementOrigin,
    ) -> Result<CpuId, SpawnError> {
        if placement.allowed_cpus().len() == 1 {
            let cpu = placement
                .allowed_cpus()
                .iter()
                .next()
                .ok_or(SpawnError::PlacementUnavailable)?;
            if !self.present.contains(cpu) {
                return Err(SpawnError::CpuNotPresent(cpu));
            }
            if !self.online.contains(cpu) {
                return Err(SpawnError::CpuOffline(cpu));
            }
            return Ok(cpu);
        }
        let eligible =
            |cpu: CpuId| self.online.contains(cpu) && placement.allowed_cpus().contains(cpu);
        let in_node = |node: u8| {
            self.online
                .iter()
                .find(|&cpu| eligible(cpu) && cpu_node(cpu) == Some(node))
        };
        match origin {
            PlacementOrigin::Spawn(caller) => {
                if let Some(cpu) = placement.preferred_cpu().filter(|&cpu| eligible(cpu)) {
                    return Ok(cpu);
                }
                if let Some(cpu) = placement
                    .preferred_node()
                    .and_then(|node| in_node(node.as_u8()))
                {
                    return Ok(cpu);
                }
                if let Some(cpu) = caller.filter(|&cpu| eligible(cpu)) {
                    return Ok(cpu);
                }
                if let Some(cpu) = caller.and_then(cpu_node).and_then(in_node) {
                    return Ok(cpu);
                }
            }
            PlacementOrigin::PollBoundary(last_cpu) => {
                if eligible(last_cpu) {
                    return Ok(last_cpu);
                }
                if let Some(cpu) = cpu_node(last_cpu).and_then(in_node) {
                    return Ok(cpu);
                }
                if let Some(cpu) = placement.preferred_cpu().filter(|&cpu| eligible(cpu)) {
                    return Ok(cpu);
                }
                if let Some(cpu) = placement
                    .preferred_node()
                    .and_then(|node| in_node(node.as_u8()))
                {
                    return Ok(cpu);
                }
            }
        }
        self.select_any(&placement.allowed_cpus())
    }

    /// Selection and publication hold the same state lock. Offline/placement
    /// admission must finish before publication; updating this derived index
    /// is then infallible and cannot report spawn failure after admission.
    fn enqueue(&mut self, id: TaskId, cpu: CpuId) {
        assert!(self.online.contains(cpu), "queue target is offline");
        let entry = self
            .tasks
            .get(&id)
            .expect("queue index references unpublished task");
        assert!(matches!(entry.state,
            TaskRunState::Ready { cpu: owner } | TaskRunState::Interrupted { cpu: owner, .. }
            if owner == cpu));
        let slot = entry.record.stack.slot();
        self.queues[cpu.as_usize()].insert(slot);
    }

    fn account_fragment(&mut self, id: TaskId, cpu: CpuId, elapsed_ns: u64, weight: u64) -> bool {
        let Some(entry) = self.tasks.get_mut(&id) else {
            return false;
        };
        if !matches!(entry.state, TaskRunState::Running { cpu: owner, .. } if owner == cpu) {
            return false;
        }
        let scaled = u128::from(elapsed_ns).saturating_mul(64) / u128::from(weight);
        entry.virtual_runtime = entry.virtual_runtime.saturating_add(scaled);
        entry.runtime_ns = entry.runtime_ns.saturating_add(elapsed_ns);
        if let Some(minimum) = self
            .tasks
            .values()
            .filter(|entry| {
                matches!(
                    entry.state,
                    TaskRunState::Running { .. } | TaskRunState::Interrupted { .. }
                ) || (matches!(entry.state, TaskRunState::Ready { .. })
                    && entry.record.can_begin_poll())
            })
            .map(|entry| entry.virtual_runtime)
            .min()
        {
            self.min_virtual_runtime = self.min_virtual_runtime.max(minimum);
        }
        true
    }

    fn has_ready(&self, cpu: CpuId) -> bool {
        self.tasks.values().any(|entry| match entry.state.clone() {
            TaskRunState::Interrupted { cpu: owner, .. } => owner == cpu,
            TaskRunState::Ready { .. } => {
                entry.record.options.placement.allowed_cpus().contains(cpu)
                    && entry.record.can_begin_poll()
            }
            _ => false,
        })
    }

    fn has_pending_wake(&self) -> bool {
        self.tasks
            .values()
            .any(|entry| entry.record.wake.is_pending())
    }

    /// Returns the CPU to notify after publishing the ready state. A wake
    /// during poll is deferred to finish_poll so a future is never polled twice.
    fn apply_wake(&mut self, id: TaskId) -> Option<CpuId> {
        match self.tasks.get(&id)?.state.clone() {
            TaskRunState::Ready { .. } => None,
            TaskRunState::Running { cpu, .. } => {
                self.tasks.get_mut(&id)?.state = TaskRunState::Running {
                    cpu,
                    wake: PollWakeState::Woken,
                };
                None
            }
            TaskRunState::Interrupted {
                cpu, continuation, ..
            } => {
                self.tasks.get_mut(&id)?.state = TaskRunState::Interrupted {
                    cpu,
                    wake: PollWakeState::Woken,
                    continuation,
                };
                None
            }
            TaskRunState::EventWaiting { last_cpu } => {
                let placement = self.tasks.get(&id)?.record.options.placement;
                let cpu = self
                    .select_target(placement, PlacementOrigin::PollBoundary(last_cpu))
                    .ok()?;
                self.tasks.get_mut(&id)?.state = TaskRunState::Ready { cpu };
                self.enqueue(id, cpu);
                Some(cpu)
            }
            TaskRunState::QuotaWaiting {
                deadline_ns,
                resume,
            } => {
                if let QuotaResume::Interrupted {
                    cpu, continuation, ..
                } = resume
                {
                    self.tasks.get_mut(&id)?.state = TaskRunState::QuotaWaiting {
                        deadline_ns,
                        resume: QuotaResume::Interrupted {
                            cpu,
                            continuation,
                            wake: PollWakeState::Woken,
                        },
                    };
                }
                None
            }
            TaskRunState::Finished => None,
        }
    }

    fn apply_pending_wakes(&mut self) -> CpuSet {
        let mut pending = [None; super::config::SCHEDULER_CONFIG.max_tasks];
        let mut count = 0;
        for (&id, entry) in self.tasks.iter() {
            if entry.record.wake.take_pending() {
                pending[count] = Some(id);
                count += 1;
            }
        }
        let mut notified = CpuSet::empty_possible();
        for id in pending.into_iter().take(count).flatten() {
            if let Some(cpu) = self.apply_wake(id) {
                notified
                    .insert(cpu)
                    .unwrap_or_else(|_| panic!("wake target exceeds CPU capacity"));
            }
        }
        notified
    }

    fn take_ready(&mut self, cpu: CpuId) -> Option<ScheduledTask> {
        let entry = self
            .tasks
            .values()
            .filter(|entry| self.queues[cpu.as_usize()].contains(entry.record.stack.slot()))
            .filter(|entry| {
                matches!(entry.state, TaskRunState::Interrupted { .. })
                    || entry.record.can_begin_poll()
            })
            .min_by_key(|entry| (entry.virtual_runtime, entry.record.id))?;
        let id = entry.record.id;
        let slot = entry.record.stack.slot();
        self.queues[cpu.as_usize()].remove(slot);
        self.dispatch(id, cpu)
    }

    fn dispatch(&mut self, id: TaskId, cpu: CpuId) -> Option<ScheduledTask> {
        let entry = self.tasks.get_mut(&id)?;
        let (continuation, wake) = match entry.state.clone() {
            TaskRunState::Ready { .. } => (None, PollWakeState::Quiet),
            TaskRunState::Interrupted {
                cpu: owner,
                wake,
                continuation,
            } if owner == cpu => (Some(continuation), wake),
            _ => panic!("run queue index disagrees with authoritative task state"),
        };
        entry.state = TaskRunState::Running { cpu, wake };
        Some(ScheduledTask {
            record: entry.record.clone(),
            continuation,
        })
    }

    /// A CPU steals only a task whose previous poll has returned (Ready).
    /// Interrupted polls remain owned by their original CPU and never enter a
    /// remote run queue. Local-node donors take precedence over other nodes.
    fn take_ready_or_steal(&mut self, cpu: CpuId) -> Option<ScheduledTask> {
        if let Some(record) = self.take_ready(cpu) {
            return Some(record);
        }
        let node = cpu_node(cpu);
        let (id, donor) = self
            .tasks
            .iter()
            .filter_map(|(&id, entry)| {
                let TaskRunState::Ready { cpu: donor } = entry.state.clone() else {
                    return None;
                };
                if donor == cpu || !entry.record.options.placement.allowed_cpus().contains(cpu) {
                    return None;
                }
                if !entry.record.can_begin_poll() {
                    return None;
                }
                let remote_node = cpu_node(donor);
                let locality_rank = u8::from(node.is_none() || remote_node != node);
                Some(((locality_rank, entry.virtual_runtime, id), (id, donor)))
            })
            .min_by_key(|(key, _)| *key)
            .map(|(_, pair)| pair)?;
        let slot = self.tasks.get(&id)?.record.stack.slot();
        assert!(self.queues[donor.as_usize()].contains(slot));
        self.queues[donor.as_usize()].remove(slot);
        self.dispatch(id, cpu)
    }

    fn suspend_poll(&mut self, id: TaskId, cpu: CpuId, execution: ExecutionContext, fuel: u64) {
        let entry = self
            .tasks
            .get_mut(&id)
            .expect("suspended task was unpublished");
        let TaskRunState::Running { cpu: owner, wake } = entry.state.clone() else {
            panic!("timer suspended a task without running authority");
        };
        assert_eq!(owner, cpu);
        entry.state = TaskRunState::Interrupted {
            cpu,
            wake,
            continuation: PollContinuation { execution, fuel },
        };
        self.enqueue(id, cpu);
    }

    /// Quota waiting has no run-queue entry. Expired periods are reconsidered
    /// before selection so an exhausted domain cannot block later tasks.
    fn refresh_quota(&mut self, now_ns: u64) {
        for slot in 0..self.tasks.0.len() {
            let Some(entry) = self.tasks.0[slot].as_ref() else {
                continue;
            };
            let state = entry.state.clone();
            let domain = entry.record.domain;
            match &state {
                TaskRunState::QuotaWaiting { deadline_ns, .. } if now_ns < *deadline_ns => continue,
                TaskRunState::Ready { .. }
                | TaskRunState::Interrupted { .. }
                | TaskRunState::QuotaWaiting { .. } => {}
                _ => continue,
            }
            let deadline = crate::domain::quota_manager().cpu_wait_deadline(domain, now_ns);
            if let Some(deadline_ns) = deadline {
                let resume = match state {
                    TaskRunState::Ready { cpu } => {
                        self.queues[cpu.as_usize()].remove(slot);
                        QuotaResume::Ready { last_cpu: cpu }
                    }
                    TaskRunState::Interrupted {
                        cpu,
                        wake,
                        continuation,
                    } => {
                        self.queues[cpu.as_usize()].remove(slot);
                        QuotaResume::Interrupted {
                            cpu,
                            wake,
                            continuation,
                        }
                    }
                    TaskRunState::QuotaWaiting { resume, .. } => resume,
                    _ => unreachable!(),
                };
                self.tasks.0[slot]
                    .as_mut()
                    .expect("quota task vanished")
                    .state = TaskRunState::QuotaWaiting {
                    deadline_ns,
                    resume,
                };
            } else if let TaskRunState::QuotaWaiting { resume, .. } = state {
                let (cpu, resumed) = match resume {
                    QuotaResume::Ready { last_cpu } => {
                        let placement = self.tasks.0[slot]
                            .as_ref()
                            .expect("quota task vanished")
                            .record
                            .options
                            .placement;
                        let cpu = self
                            .select_target(placement, PlacementOrigin::PollBoundary(last_cpu))
                            .expect("admitted task lost all eligible CPUs");
                        (cpu, TaskRunState::Ready { cpu })
                    }
                    QuotaResume::Interrupted {
                        cpu,
                        wake,
                        continuation,
                    } => (
                        cpu,
                        TaskRunState::Interrupted {
                            cpu,
                            wake,
                            continuation,
                        },
                    ),
                };
                self.tasks.0[slot]
                    .as_mut()
                    .expect("quota task vanished")
                    .state = resumed;
                self.queues[cpu.as_usize()].insert(slot);
            }
        }
    }

    fn finish_poll(&mut self, id: TaskId, cpu: CpuId, poll: Poll<()>) -> Option<PollFinalization> {
        let state = self.tasks.get(&id).map(|entry| entry.state.clone())?;
        let TaskRunState::Running {
            cpu: running_cpu,
            mut wake,
        } = state
        else {
            return None;
        };
        if running_cpu != cpu {
            return None;
        }
        if self.tasks.get(&id)?.record.wake.take_pending() {
            wake = PollWakeState::Woken;
        }

        match poll {
            Poll::Ready(()) => {
                let entry = self.tasks.get_mut(&id)?;
                entry.state = TaskRunState::Finished;
                self.tasks
                    .remove(&id)
                    .map(|entry| PollFinalization::Completed(entry.record.domain))
            }
            Poll::Pending => {
                if wake == PollWakeState::Woken {
                    let placement = self.tasks.get(&id)?.record.options.placement;
                    if let Ok(target) =
                        self.select_target(placement, PlacementOrigin::PollBoundary(cpu))
                    {
                        if let Some(entry) = self.tasks.get_mut(&id) {
                            entry.state = TaskRunState::Ready { cpu: target };
                        }
                        self.enqueue(id, target);
                        return Some(PollFinalization::Requeued(target));
                    } else if let Some(entry) = self.tasks.get_mut(&id) {
                        entry.state = TaskRunState::EventWaiting { last_cpu: cpu };
                    }
                } else if let Some(entry) = self.tasks.get_mut(&id) {
                    entry.state = TaskRunState::EventWaiting { last_cpu: cpu };
                }
                None
            }
        }
    }

    fn pinned_blockers(&self, cpu: CpuId) -> Arc<[CpuBlocker]> {
        let mut blockers = alloc::vec::Vec::new();
        for entry in self.tasks.values() {
            let task_id = entry.record.id.as_u64();
            let allowed = entry.record.options.placement.allowed_cpus();
            if allowed.contains(cpu)
                && !self
                    .online
                    .iter()
                    .any(|other| other != cpu && allowed.contains(other))
            {
                blockers.push(CpuBlocker::PinnedTask { task_id });
            }
            match entry.state.clone() {
                TaskRunState::Running { cpu: owner, .. } if owner == cpu => {
                    blockers.push(CpuBlocker::ActivePoll { task_id });
                }
                TaskRunState::Interrupted { cpu: owner, .. } if owner == cpu => {
                    blockers.push(CpuBlocker::SuspendedPoll { task_id });
                }
                TaskRunState::QuotaWaiting {
                    resume: QuotaResume::Interrupted { cpu: owner, .. },
                    ..
                } if owner == cpu => {
                    blockers.push(CpuBlocker::SuspendedPoll { task_id });
                }
                _ => {}
            }
        }
        blockers.into()
    }

    fn remove_online_cpu(&mut self, cpu: CpuId) -> Result<(), Arc<[CpuBlocker]>> {
        let blockers = self.pinned_blockers(cpu);
        if !blockers.is_empty() {
            return Err(blockers);
        }

        self.online.remove(cpu);
        let queued = self.queues[cpu.as_usize()];
        self.queues[cpu.as_usize()] = RunQueue::new();
        let mut moved = [None; super::config::SCHEDULER_CONFIG.max_tasks];
        for (index, entry) in self
            .tasks
            .values()
            .filter(|entry| queued.contains(entry.record.stack.slot()))
            .enumerate()
        {
            moved[index] = Some(entry.record.id);
        }
        for id in moved.into_iter().flatten() {
            let placement = match self.tasks.get(&id) {
                Some(entry) => entry.record.options.placement,
                None => continue,
            };
            let Ok(target) = self.select_target(placement, PlacementOrigin::PollBoundary(cpu))
            else {
                continue;
            };
            if let Some(entry) = self.tasks.get_mut(&id) {
                entry.state = TaskRunState::Ready { cpu: target };
            }
            self.enqueue(id, target);
        }
        Ok(())
    }

    fn add_online_cpu(&mut self, cpu: CpuId, snapshot: &crate::cpu::CpuSnapshot) {
        self.present = snapshot.present().clone();
        self.online = snapshot.online().clone();
        assert!(self.queues[cpu.as_usize()].is_empty());
    }

    fn prepare_online_cpu(&mut self, cpu: CpuId, snapshot: &crate::cpu::CpuSnapshot) {
        self.present = snapshot.present().clone();
        assert!(self.queues[cpu.as_usize()].is_empty());
    }

    fn abort_online_cpu(&mut self, cpu: CpuId) {
        self.online.remove(cpu);
        let queue = self.queues[cpu.as_usize()];
        assert!(
            queue.is_empty(),
            "aborted CPU online preparation retained runnable tasks"
        );
    }
}

fn cpu_node(cpu: CpuId) -> Option<u8> {
    crate::cpu::try_runtime()?
        .cpu_local(cpu)?
        .remote()
        .numa_node()
}

pub(crate) struct PollBudget {
    remaining: u64,
}

impl PollBudget {
    pub(crate) const fn remaining(&self) -> u64 {
        self.remaining
    }
}

pub(crate) struct TaskRuntime {
    state: PoisonLock<SchedulerState>,
    poll_count: AtomicU64,
    forced_switches: AtomicU64,
    runtime_ns: AtomicU64,
}

impl TaskRuntime {
    fn new(snapshot: &crate::cpu::CpuSnapshot) -> Self {
        Self {
            state: PoisonLock::new(SchedulerState::from_snapshot(snapshot)),
            poll_count: AtomicU64::new(0),
            forced_switches: AtomicU64::new(0),
            runtime_ns: AtomicU64::new(0),
        }
    }

    fn poll_one(&self) -> bool {
        let current =
            CurrentCpu::acquire().unwrap_or_else(|| panic!("task dispatch requires a bound CPU"));
        let cpu = current.id();
        let Some(scheduled) = ({
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            state.refresh_quota(crate::time::precise_time_nanos());
            state.take_ready_or_steal(cpu)
        }) else {
            return false;
        };
        let record = &scheduled.record;
        // Policy is sampled once for this execution fragment. A priority
        // change affects subsequent fragments without resetting queue order.
        let weight = record.options.priority.weight()
            * crate::domain::quota_manager().scheduler_weight(record.domain);
        let resumed = scheduled.continuation.is_some();
        let continuation = scheduled.continuation.unwrap_or_else(|| PollContinuation {
            execution: {
                let execution = ExecutionContext::for_task(record.id, record.domain)
                    .with_cell(record.future.code.cell());
                match record.future.finalization.clone() {
                    Some(authority) => execution.with_finalization(authority),
                    None => execution,
                }
            },
            fuel: super::config::SCHEDULER_CONFIG.fuel_per_poll,
        });
        let _execution_scope = current.enter_execution(continuation.execution);
        let current = CurrentCpu::acquire().expect("task dispatch lost CPU binding");
        current.install_task_fuel(&PollBudget {
            remaining: continuation.fuel,
        });
        let preemption = current.preemption_state();
        assert!(
            !preemption.guarded(),
            "scheduler entered a task under a preemption guard"
        );
        let started_ns = crate::time::precise_time_nanos();
        let interrupts_enabled = crate::interrupts::are_interrupts_enabled();
        crate::interrupts::disable_interrupts();
        // SAFETY: the Arc retains context storage until the task stack has
        // returned to this CPU's scheduler stack.
        unsafe { preemption.enter_task(record.context.address()) };
        let outcome = unsafe {
            if resumed {
                super::context::resume(&record.context)
            } else {
                super::context::start(
                    &record.context,
                    record.stack.top(),
                    Arc::as_ptr(record) as *const (),
                    interrupts_enabled,
                )
            }
        };
        // Both the task exit and interrupt return with IF clear. No interrupt
        // can observe the active pointer after this ownership transition.
        preemption.leave_task(record.context.address());
        let stopped_ns = crate::time::precise_time_nanos();
        let elapsed_ns = stopped_ns.saturating_sub(started_ns);
        let suspended_execution = current.execution();
        let remaining_fuel = current.task_fuel();
        drop(_execution_scope);
        current.exhaust_task_fuel();
        if interrupts_enabled {
            x86_64::instructions::interrupts::enable();
        }

        crate::domain::quota_manager().consume_cpu_time(record.domain, elapsed_ns, stopped_ns);
        self.runtime_ns.fetch_add(elapsed_ns, Ordering::Relaxed);
        let finalization = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            assert!(state.account_fragment(record.id, cpu, elapsed_ns, weight));
            match outcome {
                0 => {
                    self.poll_count.fetch_add(1, Ordering::Relaxed);
                    state.finish_poll(record.id, cpu, Poll::Ready(()))
                }
                1 => {
                    self.forced_switches.fetch_add(1, Ordering::Relaxed);
                    state.suspend_poll(
                        record.id,
                        cpu,
                        suspended_execution.expect("interrupted poll lost execution context"),
                        remaining_fuel,
                    );
                    None
                }
                2 => {
                    self.poll_count.fetch_add(1, Ordering::Relaxed);
                    state.finish_poll(record.id, cpu, Poll::Pending)
                }
                _ => panic!("task stack returned an unknown outcome"),
            }
        };
        match finalization {
            Some(PollFinalization::Completed(_domain)) => {}
            Some(PollFinalization::Requeued(target)) => notify_target(target),
            None => {}
        }
        true
    }

    fn spawn_task(
        &self,
        future: Pin<Box<dyn Future<Output = ()> + Send>>,
        options: TaskOptions,
        domain: crate::domain::DomainId,
    ) -> Result<TaskId, SpawnError> {
        let finalization = crate::task::current_execution_context()
            .filter(|execution| execution.subject.domain == domain)
            .and_then(|execution| execution.finalization);
        let code_lease = match &finalization {
            Some(authority) => crate::domain::registry::acquire_finalization_future_lease(
                domain,
                authority.code.as_deref(),
            ),
            None => crate::domain::registry::acquire_future_code_lease(domain),
        }
        .ok_or(SpawnError::DomainUnavailable(domain))?;
        let future = TaskFuture::new(future, code_lease, finalization);
        let stack = TaskStack::allocate()?;
        let wake = WakeLease::activate(stack.slot());
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let raw_id = NEXT_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| SpawnError::TaskIdentityExhausted)?;
        let id = TaskId::from_raw(raw_id);
        let record = Arc::try_new(TaskRecord {
            id,
            domain,
            options,
            future,
            wake,
            context: TaskContext::new(&stack),
            stack,
        })
        .map_err(|_| SpawnError::PhysicalMemoryExhausted)?;
        let target = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            assert!(
                !state.tasks.contains_key(&id),
                "monotonic task identity reused"
            );
            let origin = CurrentCpu::acquire().map(|current| current.id());
            if !record.can_begin_poll() {
                return Err(SpawnError::DomainUnavailable(domain));
            }
            let target = state.select_target(options.placement, PlacementOrigin::Spawn(origin))?;
            let virtual_runtime = state.min_virtual_runtime;
            state.tasks.insert(
                id,
                TaskEntry {
                    record,
                    state: TaskRunState::Ready { cpu: target },
                    virtual_runtime,
                    runtime_ns: 0,
                },
            );
            state.enqueue(id, target);
            target
        };
        notify_target(target);
        Ok(id)
    }

    fn snapshot(&self) -> SchedulerSnapshot {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let run_queues = state
            .online
            .iter()
            .map(|cpu| CpuRunQueueSnapshot {
                cpu,
                ready_tasks: state.queues[cpu.as_usize()].len(),
            })
            .collect::<alloc::vec::Vec<_>>()
            .into();
        SchedulerSnapshot {
            task_count: state.tasks.len(),
            poll_count: self.poll_count.load(Ordering::Relaxed),
            forced_switches: self.forced_switches.load(Ordering::Relaxed),
            runtime_ns: self.runtime_ns.load(Ordering::Relaxed),
            quota_waiting: state
                .tasks
                .values()
                .filter(|entry| matches!(entry.state, TaskRunState::QuotaWaiting { .. }))
                .count(),
            interrupted_polls: state
                .tasks
                .values()
                .filter(|entry| {
                    matches!(
                        entry.state,
                        TaskRunState::Interrupted { .. }
                            | TaskRunState::QuotaWaiting {
                                resume: QuotaResume::Interrupted { .. },
                                ..
                            }
                    )
                })
                .count(),
            pending_wakes: state
                .tasks
                .values()
                .filter(|entry| entry.record.wake.is_pending())
                .count(),
            run_queues,
        }
    }

    fn process_pending_wakes(&self) {
        let targets = self
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .apply_pending_wakes();
        for cpu in targets.iter() {
            notify_target(cpu);
        }
    }

    fn idle_work(&self, cpu: CpuId) -> bool {
        match self.state.try_lock() {
            Ok(state) => state.has_ready(cpu) || state.has_pending_wake(),
            Err(crate::sync::poison_lock::TryLockError::WouldBlock) => true,
            Err(crate::sync::poison_lock::TryLockError::Poisoned(_)) => {
                panic!("scheduler state is poisoned during idle transition")
            }
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

/// Entered only on a newly admitted task stack. A timer suspension resumes
/// this same invocation through its saved interrupt frame; it never polls the
/// Future again until this invocation returns Pending or Ready.
pub(super) extern "sysv64" fn task_entry(task: *const ()) -> ! {
    let record = unsafe { &*(task as *const TaskRecord) };
    let waker = record.wake.waker();
    let result = {
        let mut context = Context::from_waker(&waker);
        unsafe { record.future.poll(&mut context) }
    };
    let code = match result {
        Poll::Ready(()) => 0,
        Poll::Pending => 2,
    };
    drop(waker);
    unsafe { super::context::exit(&record.context, code) }
}

static TASK_RUNTIME: InitOnce<TaskRuntime> = InitOnce::new();

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
    options: TaskOptions,
) -> Result<TaskId, SpawnError> {
    spawn_in_domain(future, options, crate::domain::current_domain())
}

pub(crate) fn spawn_in_domain(
    future: impl Future<Output = ()> + Send + 'static,
    options: TaskOptions,
    domain: crate::domain::DomainId,
) -> Result<TaskId, SpawnError> {
    let scheduler = runtime()?;
    let future = Box::try_new(future).map_err(|_| SpawnError::PhysicalMemoryExhausted)?;
    scheduler.spawn_task(Box::into_pin(future), options, domain)
}

pub fn scheduler_snapshot() -> Option<SchedulerSnapshot> {
    TASK_RUNTIME.get().map(TaskRuntime::snapshot)
}

pub(crate) fn domain_task_ids(domain: crate::domain::DomainId) -> alloc::vec::Vec<u64> {
    TASK_RUNTIME
        .get()
        .map_or_else(alloc::vec::Vec::new, |runtime| {
            let state = runtime
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state
                .tasks
                .values()
                .filter(|entry| entry.record.domain == domain)
                .map(|entry| entry.record.id.as_u64())
                .collect()
        })
}

/// Serializes a domain stop publication against selection and registration.
/// The callback only owns the domain lifecycle transition, not task storage.
pub(crate) fn domain_stop_boundary<T>(
    domain: crate::domain::DomainId,
    commit: impl FnOnce(crate::domain::DomainStopOutcome) -> T,
) -> T {
    let Some(runtime) = TASK_RUNTIME.get() else {
        return commit(crate::domain::DomainStopOutcome::Complete);
    };
    let state = runtime
        .state
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let mut active_polls = 0;
    let mut interrupted_polls = 0;
    for entry in state
        .tasks
        .values()
        .filter(|entry| entry.record.domain == domain)
    {
        match entry.state.clone() {
            TaskRunState::Running { .. } => active_polls += 1,
            TaskRunState::Interrupted { .. }
            | TaskRunState::QuotaWaiting {
                resume: QuotaResume::Interrupted { .. },
                ..
            } => interrupted_polls += 1,
            _ => {}
        }
    }
    let outcome = if active_polls + interrupted_polls == 0 {
        crate::domain::DomainStopOutcome::Complete
    } else {
        crate::domain::DomainStopOutcome::InProgress {
            active_polls,
            interrupted_polls,
        }
    };
    commit(outcome)
}

pub(crate) fn retire_domain_tasks(domain: crate::domain::DomainId) {
    let Some(runtime) = TASK_RUNTIME.get() else {
        return;
    };
    let mut retired = [const { None }; super::config::SCHEDULER_CONFIG.max_tasks];
    {
        let mut state = runtime
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        for slot in 0..state.tasks.0.len() {
            let Some(entry) = state.tasks.0[slot].as_ref() else {
                continue;
            };
            // Finalization tasks already own teardown authority. Cancelling a
            // waiting finalizer would lose the hardware completion it must report.
            if entry.record.domain != domain || entry.record.future.finalization.is_some() {
                continue;
            }
            assert!(
                !matches!(
                    entry.state,
                    TaskRunState::Running { .. }
                        | TaskRunState::Interrupted { .. }
                        | TaskRunState::QuotaWaiting {
                            resume: QuotaResume::Interrupted { .. },
                            ..
                        }
                ),
                "attempt to destroy an active poll stack"
            );
            for queue in &mut state.queues {
                queue.remove(slot);
            }
            retired[slot] = state.tasks.0[slot].take();
        }
    }
    // Future destructors may use locks or call domain services. Run them with
    // domain resources retained and without holding scheduler state.
    drop(retired);
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
    // LOOP_PROOF: mode=event; reason=The CPU scheduler dispatches runnable tasks and parks through idle_once when none remain, or returns after an accepted park message.;
    loop {
        let mut park_requested = false;
        // LOOP_PROOF: mode=condition; reason=Each take_control consumes one message from this CPU's bounded control mailbox and the drain ends when it is empty.;
        while let Some(message) = current.take_control() {
            match message {
                crate::cpu::CpuControlMessage::WakeExecutor
                | crate::cpu::CpuControlMessage::Start => {}
                crate::cpu::CpuControlMessage::ReclaimMemory => {
                    crate::heap::reclaim_local_caches();
                }
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
        if let Ok(scheduler) = runtime() {
            scheduler.process_pending_wakes();
        }
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
            idle_once(current.id(), wake_revision());
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

fn idle_once(cpu: CpuId, observed_wake_revision: u64) {
    #[cfg(any(test, feature = "std", target_os = "linux", target_os = "windows"))]
    {
        let _ = (cpu, observed_wake_revision);
        core::hint::spin_loop();
    }

    #[cfg(not(any(test, feature = "std", target_os = "linux", target_os = "windows")))]
    {
        if !crate::interrupts::are_interrupts_enabled() {
            core::hint::spin_loop();
            return;
        }
        // The final queue and wake check occurs with local interrupts masked.
        // STI's interrupt shadow keeps the following HLT adjacent, so a
        // pending IPI cannot be consumed before the CPU sleeps.
        unsafe { core::arch::asm!("cli", options(nomem, nostack)) };
        let work = runtime().is_ok_and(|scheduler| scheduler.idle_work(cpu));
        if work || wake_revision() != observed_wake_revision {
            unsafe { core::arch::asm!("sti", options(nomem, nostack)) };
            return;
        }
        unsafe { core::arch::asm!("sti; hlt", options(nomem, nostack)) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::{ApicId, CpuEjectCapability, FirmwareCpuIdentity, FirmwareCpuUid};

    fn sparse_runtime() -> crate::cpu::CpuRuntime {
        let runtime = crate::cpu::CpuRuntime::bootstrap(
            crate::cpu::LocatedCpu::resolve(
                crate::cpu::FirmwareCpuIdentity {
                    uid: None,
                    apic_id: crate::cpu::ApicId::new(0),
                    proximity_domain: None,
                    eject: crate::cpu::CpuEjectCapability::Fixed,
                },
                &crate::mm::numa::placement::NumaPlacement::try_new(&[], &[], |_, _| Some(10))
                    .unwrap(),
            )
            .unwrap(),
            None,
        )
        .unwrap();
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

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn any_placement_selects_sparse_online_members() {
        let cpu_runtime = sparse_runtime();
        let mut scheduler = SchedulerState::from_snapshot(&cpu_runtime.snapshot());
        assert_eq!(
            scheduler
                .select_target(TaskPlacement::any(), PlacementOrigin::Spawn(None))
                .unwrap(),
            CpuId::BOOTSTRAP
        );
        assert_eq!(
            scheduler
                .select_target(TaskPlacement::any(), PlacementOrigin::Spawn(None))
                .unwrap()
                .as_u16(),
            2
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn pinned_offline_cpu_is_rejected() {
        let cpu_runtime = sparse_runtime();
        let mut scheduler = SchedulerState::from_snapshot(&cpu_runtime.snapshot());
        let offline = CpuId::try_from(1usize).unwrap();
        assert_eq!(
            scheduler.select_target(TaskPlacement::pinned(offline), PlacementOrigin::Spawn(None)),
            Err(SpawnError::CpuOffline(offline))
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn initial_preference_does_not_move_a_returned_poll_off_its_last_cpu() {
        let cpu_runtime = sparse_runtime();
        let mut scheduler = SchedulerState::from_snapshot(&cpu_runtime.snapshot());
        let preferred = CpuId::try_from(2usize).unwrap();
        let placement = TaskPlacement::prefer_cpu(preferred);
        assert_eq!(
            scheduler.select_target(placement, PlacementOrigin::Spawn(Some(CpuId::BOOTSTRAP))),
            Ok(preferred)
        );
        assert_eq!(
            scheduler.select_target(placement, PlacementOrigin::PollBoundary(CpuId::BOOTSTRAP)),
            Ok(CpuId::BOOTSTRAP)
        );
        assert_eq!(
            scheduler.select_target(placement, PlacementOrigin::PollBoundary(preferred)),
            Ok(preferred)
        );
    }
}
