//! Scheduler ownership for one capability-owned NVMe controller.
//!
//! Each hardware queue has one lock covering both driver submission and the
//! scheduler completion route table. Consequently a completion parser cannot
//! observe a doorbell publication before its unique route is installed. DMA
//! ownership remains in the driver queue until that parser validates a CQE.

#![forbid(unsafe_code)]

use alloc::sync::Arc;
use alloc::vec::Vec;

use kernel_api::dma::{
    CompletedDmaLease, CpuDmaLease, DmaLeaseError, DmaTransitionError, PreparedDmaLease,
};
use nvme_driver::{
    CompletedCommand, CompletedOwnership, IoTransfer, NamespaceInfo, NvmeController, PollError,
    SubmitError, SubmitFailure, TransferDirection,
};

use crate::io::io_scheduler::{
    DeviceCompletion, DeviceId, DeviceOps, IoCommand, IoCompletion, IoCompletionRoute, IoError,
    IoOperationType, IoSubmission, IoSubmitOutcome, PollAffinity, PollHandler,
};
use crate::sync::PoisonLock;

#[derive(Clone, Copy, Debug)]
enum BlockCommandIdentity {
    Read { lba: u64, blocks: u16 },
    Write { lba: u64, blocks: u16 },
}

impl BlockCommandIdentity {
    const fn operation(self) -> IoOperationType {
        match self {
            Self::Read { .. } => IoOperationType::Read,
            Self::Write { .. } => IoOperationType::Write,
        }
    }

    fn rebuild(self, buffer: CpuDmaLease) -> IoCommand {
        match self {
            Self::Read { lba, blocks } => IoCommand::BlockRead {
                lba,
                blocks,
                buffer,
            },
            Self::Write { lba, blocks } => IoCommand::BlockWrite {
                lba,
                blocks,
                buffer,
            },
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum PendingKind {
    Transfer {
        identity: BlockCommandIdentity,
        bytes: usize,
    },
    Flush,
}

impl PendingKind {
    const fn operation(self) -> IoOperationType {
        match self {
            Self::Transfer { identity, .. } => identity.operation(),
            Self::Flush => IoOperationType::Flush,
        }
    }
}

#[derive(Debug)]
struct PendingRoute {
    route: IoCompletionRoute,
    kind: PendingKind,
}

#[derive(Debug)]
struct RuntimeQueueState {
    pending: Vec<Option<PendingRoute>>,
    phase: RuntimeQueuePhase,
}

#[derive(Debug)]
enum RuntimeQueuePhase {
    Running,
    Faulted(RuntimeQueueFault),
}

/// The first fault stops all further device polls and submissions on this
/// queue. Thus at most one owner can leave the driver without a valid route;
/// fault retention does not grow or allocate after device acceptance.
#[derive(Debug)]
enum RuntimeQueueFault {
    Driver(PollError),
    RouteCollision(Option<PendingRoute>),
    UnexpectedCompletion(CompletedCommand),
    Prepared {
        cause: SubmitFailure,
        failure: DmaTransitionError<PreparedDmaLease>,
    },
    OwnershipBlocked {
        cause: DmaLeaseError,
        completed: CompletedDmaLease,
    },
    Poisoned,
}

impl RuntimeQueueState {
    fn with_depth(depth: u16) -> Result<Self, ()> {
        let depth = usize::from(depth);
        let mut pending = Vec::new();
        pending.try_reserve_exact(depth).map_err(|_| ())?;
        pending.resize_with(depth, || None);
        Ok(Self {
            pending,
            phase: RuntimeQueuePhase::Running,
        })
    }

    fn take_faulted_route(&mut self) -> Option<PendingRoute> {
        if let RuntimeQueuePhase::Faulted(RuntimeQueueFault::RouteCollision(route)) =
            &mut self.phase
        {
            if let Some(route) = route.take() {
                return Some(route);
            }
        }
        self.pending.iter_mut().find_map(Option::take)
    }

    fn record_route(&mut self, command_id: u16, pending: PendingRoute) {
        match self.pending.get_mut(usize::from(command_id)) {
            Some(slot) if slot.is_none() => *slot = Some(pending),
            Some(_) | None => {
                self.phase =
                    RuntimeQueuePhase::Faulted(RuntimeQueueFault::RouteCollision(Some(pending)));
            }
        }
    }

    fn can_submit(&self) -> bool {
        matches!(self.phase, RuntimeQueuePhase::Running)
    }

    fn needs_poll(&self) -> bool {
        self.can_submit()
            || self.pending.iter().any(Option::is_some)
            || matches!(
                &self.phase,
                RuntimeQueuePhase::Faulted(RuntimeQueueFault::RouteCollision(Some(_)))
            )
    }

    fn fault_cause(&self) -> Option<IoError> {
        let RuntimeQueuePhase::Faulted(fault) = &self.phase else {
            return None;
        };
        Some(match fault {
            RuntimeQueueFault::Driver(cause) => map_poll_error(cause),
            RuntimeQueueFault::RouteCollision(route) => {
                let _retained_route = route.as_ref();
                IoError::DeviceError
            }
            RuntimeQueueFault::UnexpectedCompletion(completed) => {
                let _retained_command = completed_command_id(completed);
                IoError::DeviceError
            }
            RuntimeQueueFault::Prepared { cause, failure } => {
                let _retained_cause = failure.cause();
                map_submit_failure(*cause)
            }
            RuntimeQueueFault::OwnershipBlocked { cause, completed } => {
                let (_retained_cause, _retained_lease) = (*cause, completed.lease_id());
                IoError::DeviceError
            }
            RuntimeQueueFault::Poisoned => IoError::DeviceError,
        })
    }
}

#[derive(Debug)]
struct RuntimeQueue {
    queue_id: u16,
    state: PoisonLock<RuntimeQueueState>,
}

impl RuntimeQueue {
    fn lock(&self) -> crate::sync::PoisonLockGuard<'_, RuntimeQueueState> {
        match self.state.lock() {
            Ok(state) => state,
            Err(error) => {
                let mut state = error.into_inner();
                if state.can_submit() {
                    state.phase = RuntimeQueuePhase::Faulted(RuntimeQueueFault::Poisoned);
                }
                state
            }
        }
    }
}

/// Failure before a runtime can publish any scheduler or poller owner.
pub(crate) enum RuntimeCreateError {
    InvalidController {
        controller: NvmeController,
        namespace: NamespaceInfo,
    },
    MetadataAllocation {
        controller: NvmeController,
        namespace: NamespaceInfo,
    },
}

impl core::fmt::Debug for RuntimeCreateError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidController { namespace, .. } => formatter
                .debug_struct("InvalidController")
                .field("namespace", namespace)
                .finish_non_exhaustive(),
            Self::MetadataAllocation { namespace, .. } => formatter
                .debug_struct("MetadataAllocation")
                .field("namespace", namespace)
                .finish_non_exhaustive(),
        }
    }
}

/// One NVMe controller/namespace owner shared only by scheduler capabilities.
pub(crate) struct NvmeRuntime {
    controller: NvmeController,
    device: DeviceId,
    namespace: NamespaceInfo,
    queues: Vec<RuntimeQueue>,
}

impl NvmeRuntime {
    pub(crate) fn new(
        controller: NvmeController,
        controller_id: u8,
        namespace: NamespaceInfo,
    ) -> Result<Self, RuntimeCreateError> {
        let queue_count = controller.queue_count();
        if queue_count == 0
            || !controller.owns_namespace(namespace)
            || namespace.byte_capacity().is_none()
        {
            return Err(RuntimeCreateError::InvalidController {
                controller,
                namespace,
            });
        }
        let mut queues = Vec::new();
        if queues.try_reserve_exact(queue_count).is_err() {
            return Err(RuntimeCreateError::MetadataAllocation {
                controller,
                namespace,
            });
        }
        for index in 0..queue_count {
            let Some(queue_id) = index.checked_add(1).and_then(|id| u16::try_from(id).ok()) else {
                return Err(RuntimeCreateError::InvalidController {
                    controller,
                    namespace,
                });
            };
            let Some(depth) = controller.queue_depth(queue_id) else {
                return Err(RuntimeCreateError::InvalidController {
                    controller,
                    namespace,
                });
            };
            let state = match RuntimeQueueState::with_depth(depth) {
                Ok(state) => state,
                Err(()) => {
                    return Err(RuntimeCreateError::MetadataAllocation {
                        controller,
                        namespace,
                    });
                }
            };
            queues.push(RuntimeQueue {
                queue_id,
                state: PoisonLock::new(state),
            });
        }
        Ok(Self {
            controller,
            device: DeviceId::Nvme {
                controller: controller_id,
                namespace: namespace.namespace(),
            },
            namespace,
            queues,
        })
    }

    pub(crate) const fn device(&self) -> DeviceId {
        self.device
    }

    pub(crate) fn queue_count(&self) -> usize {
        self.queues.len()
    }

    fn submit(&self, submission: IoSubmission, cpu_id: crate::cpu::CpuId) -> IoSubmitOutcome {
        if submission.device() != self.device {
            return rejected(IoError::InvalidParameter, submission);
        }
        let plan = match self.plan(submission.command()) {
            Ok(plan) => plan,
            Err(cause) => return rejected(cause, submission),
        };
        let Some(queue) = queue_for_cpu(&self.queues, cpu_id) else {
            return rejected(IoError::NoResources, submission);
        };
        let mut state = queue.lock();
        if !state.can_submit() {
            return rejected(IoError::DeviceError, submission);
        }
        let (route, command) = submission.into_parts();
        match (plan, command) {
            (
                SubmissionPlan::Transfer { transfer, identity },
                IoCommand::BlockRead { buffer, .. } | IoCommand::BlockWrite { buffer, .. },
            ) => {
                let kind = PendingKind::Transfer {
                    identity,
                    bytes: transfer_bytes(transfer),
                };
                match self
                    .controller
                    .submit_transfer(queue.queue_id, transfer, buffer)
                {
                    Ok(submitted) => {
                        let pending = PendingRoute { route, kind };
                        state.record_route(submitted.command_id(), pending);
                        IoSubmitOutcome::Accepted
                    }
                    Err(error) => self.reject_transfer_error(route, identity, error, &mut state),
                }
            }
            (SubmissionPlan::Flush, IoCommand::Flush) => {
                match self
                    .controller
                    .submit_flush(queue.queue_id, self.namespace.namespace())
                {
                    Ok(submitted) => {
                        let pending = PendingRoute {
                            route,
                            kind: PendingKind::Flush,
                        };
                        state.record_route(submitted.command_id(), pending);
                        IoSubmitOutcome::Accepted
                    }
                    Err(cause) => route.reject(IoCommand::Flush, map_submit_failure(cause)),
                }
            }
            _ => unreachable!("submission plan was derived from the same owned command"),
        }
    }

    fn plan(&self, command: &IoCommand) -> Result<SubmissionPlan, IoError> {
        match command {
            IoCommand::BlockRead { lba, blocks, .. } => self.transfer_plan(
                TransferDirection::Read,
                BlockCommandIdentity::Read {
                    lba: *lba,
                    blocks: *blocks,
                },
            ),
            IoCommand::BlockWrite { lba, blocks, .. } => self.transfer_plan(
                TransferDirection::Write,
                BlockCommandIdentity::Write {
                    lba: *lba,
                    blocks: *blocks,
                },
            ),
            IoCommand::Flush => Ok(SubmissionPlan::Flush),
            IoCommand::Discard { .. } => Err(IoError::NotSupported),
        }
    }

    fn transfer_plan(
        &self,
        direction: TransferDirection,
        identity: BlockCommandIdentity,
    ) -> Result<SubmissionPlan, IoError> {
        let blocks = match identity {
            BlockCommandIdentity::Read { blocks, .. }
            | BlockCommandIdentity::Write { blocks, .. } => blocks,
        };
        let transfer = IoTransfer::for_namespace(
            self.namespace,
            direction,
            match identity {
                BlockCommandIdentity::Read { lba, .. }
                | BlockCommandIdentity::Write { lba, .. } => lba,
            },
            blocks,
        )
        .map_err(|_| IoError::InvalidParameter)?;
        Ok(SubmissionPlan::Transfer { transfer, identity })
    }

    fn reject_transfer_error(
        &self,
        route: IoCompletionRoute,
        identity: BlockCommandIdentity,
        error: SubmitError,
        state: &mut RuntimeQueueState,
    ) -> IoSubmitOutcome {
        match error {
            SubmitError::Cpu { cause, lease } => {
                route.reject(identity.rebuild(lease), map_submit_failure(cause))
            }
            SubmitError::Prepared { cause, lease } => match lease.abort() {
                Ok(lease) => route.reject(identity.rebuild(lease), map_submit_failure(cause)),
                Err(failure) => {
                    state.phase =
                        RuntimeQueuePhase::Faulted(RuntimeQueueFault::Prepared { cause, failure });
                    IoSubmitOutcome::Finished(route.finish(IoCompletion::authority_quarantined(
                        identity.operation(),
                        map_submit_failure(cause),
                    )))
                }
            },
        }
    }

    fn poll_queue(&self, queue_id: u16) -> Vec<DeviceCompletion> {
        let mut completions = Vec::new();
        let Some(queue_index) = queue_id.checked_sub(1).map(usize::from) else {
            return completions;
        };
        let Some(queue) = self
            .queues
            .get(queue_index)
            .filter(|queue| queue.queue_id == queue_id)
        else {
            return completions;
        };
        let mut state = queue.lock();
        if !state.can_submit() {
            finish_one_faulted_route(&mut state, &mut completions);
            return completions;
        }
        let completed = match self.controller.poll_completion(queue_id) {
            Ok(completed) => completed,
            Err(cause) => {
                state.phase = RuntimeQueuePhase::Faulted(RuntimeQueueFault::Driver(cause));
                finish_one_faulted_route(&mut state, &mut completions);
                return completions;
            }
        };
        let Some(completed) = completed else {
            return completions;
        };
        let command_id = completed_command_id(&completed);
        let pending = state
            .pending
            .get_mut(usize::from(command_id))
            .and_then(Option::take);
        let Some(pending) = pending else {
            state.phase =
                RuntimeQueuePhase::Faulted(RuntimeQueueFault::UnexpectedCompletion(completed));
            finish_one_faulted_route(&mut state, &mut completions);
            return completions;
        };
        completions.push(finish_completion(&mut state, pending, completed));
        completions
    }

    fn is_ready(&self) -> bool {
        self.queues.iter().any(|queue| queue.lock().can_submit())
    }
}

#[derive(Clone, Copy)]
enum SubmissionPlan {
    Transfer {
        transfer: IoTransfer,
        identity: BlockCommandIdentity,
    },
    Flush,
}

fn transfer_bytes(transfer: IoTransfer) -> usize {
    transfer.logical_byte_count().get()
}

fn queue_for_cpu(queues: &[RuntimeQueue], cpu_id: crate::cpu::CpuId) -> Option<&RuntimeQueue> {
    let queue_count = queues.len();
    if queue_count == 0 {
        return None;
    }
    let snapshot = crate::cpu::snapshot();
    let member = snapshot
        .online()
        .iter()
        .position(|online| online == cpu_id)?;
    queues.get(member % queue_count)
}

fn completed_command_id(completed: &CompletedCommand) -> u16 {
    match completed {
        CompletedCommand::Transfer { completion, .. } | CompletedCommand::Control(completion) => {
            completion.command_id()
        }
    }
}

fn finish_completion(
    state: &mut RuntimeQueueState,
    pending: PendingRoute,
    completed: CompletedCommand,
) -> DeviceCompletion {
    let PendingRoute { route, kind } = pending;
    match (kind, completed) {
        (
            PendingKind::Transfer { bytes, .. },
            CompletedCommand::Transfer {
                completion,
                ownership: CompletedOwnership::Cpu(buffer),
            },
        ) => {
            let result = if completion.status().is_success() {
                Ok(bytes)
            } else {
                Err(IoError::DeviceError)
            };
            route.finish(IoCompletion::transfer_returned(result, buffer))
        }
        (
            PendingKind::Transfer { identity, .. },
            CompletedCommand::Transfer {
                ownership: CompletedOwnership::Blocked { cause, completed },
                ..
            },
        ) => {
            state.phase = RuntimeQueuePhase::Faulted(RuntimeQueueFault::OwnershipBlocked {
                cause,
                completed,
            });
            route.finish(IoCompletion::authority_quarantined(
                identity.operation(),
                IoError::DeviceError,
            ))
        }
        (PendingKind::Flush, CompletedCommand::Control(completion)) => {
            let result = if completion.status().is_success() {
                Ok(0)
            } else {
                Err(IoError::DeviceError)
            };
            route.finish(IoCompletion::control(result))
        }
        (kind, completed) => {
            state.phase =
                RuntimeQueuePhase::Faulted(RuntimeQueueFault::UnexpectedCompletion(completed));
            route.finish(IoCompletion::outcome_unknown(
                kind.operation(),
                IoError::DeviceError,
            ))
        }
    }
}

fn finish_one_faulted_route(
    state: &mut RuntimeQueueState,
    completions: &mut Vec<DeviceCompletion>,
) {
    let cause = state.fault_cause().unwrap_or(IoError::DeviceError);
    if let Some(pending) = state.take_faulted_route() {
        completions.push(pending.route.finish(IoCompletion::outcome_unknown(
            pending.kind.operation(),
            cause,
        )));
    }
}

fn rejected(cause: IoError, submission: IoSubmission) -> IoSubmitOutcome {
    IoSubmitOutcome::Rejected { cause, submission }
}

const fn map_submit_failure(cause: SubmitFailure) -> IoError {
    match cause {
        SubmitFailure::QueueFull => IoError::Busy,
        SubmitFailure::InvalidQueue | SubmitFailure::InvalidTransfer => IoError::InvalidParameter,
        SubmitFailure::Register(_) | SubmitFailure::QueueFault | SubmitFailure::Dma(_) => {
            IoError::DeviceError
        }
    }
}

const fn map_poll_error(cause: &PollError) -> IoError {
    match cause {
        PollError::InvalidQueue => IoError::InvalidParameter,
        PollError::Register(_)
        | PollError::Shared(_)
        | PollError::InvalidCompletion(_)
        | PollError::Ownership(_)
        | PollError::QueueFault => IoError::DeviceError,
    }
}

pub(crate) struct NvmeDeviceOps(Arc<NvmeRuntime>);

impl NvmeDeviceOps {
    pub(crate) fn new(runtime: Arc<NvmeRuntime>) -> Self {
        Self(runtime)
    }
}

impl DeviceOps for NvmeDeviceOps {
    fn submit(&self, submission: IoSubmission, cpu_id: crate::cpu::CpuId) -> IoSubmitOutcome {
        self.0.submit(submission, cpu_id)
    }

    fn is_ready(&self) -> bool {
        self.0.is_ready()
    }
}

pub(crate) struct NvmeQueuePoller {
    runtime: Arc<NvmeRuntime>,
    queue_id: u16,
}

impl NvmeQueuePoller {
    pub(crate) fn new(runtime: Arc<NvmeRuntime>, queue_id: u16) -> Option<Self> {
        runtime
            .queues
            .get(usize::from(queue_id.checked_sub(1)?))
            .filter(|queue| queue.queue_id == queue_id)?;
        Some(Self { runtime, queue_id })
    }
}

impl PollHandler for NvmeQueuePoller {
    fn poll_completions(&self) -> Vec<DeviceCompletion> {
        self.runtime.poll_queue(self.queue_id)
    }

    fn is_ready(&self) -> bool {
        self.runtime
            .queues
            .get(usize::from(self.queue_id - 1))
            .is_some_and(|queue| queue.lock().needs_poll())
    }

    fn affinity(&self) -> PollAffinity {
        let snapshot = crate::cpu::snapshot();
        let online = snapshot.online();
        if online.is_empty() {
            return PollAffinity::Unavailable;
        }
        let Some(queue_index) = self.queue_id.checked_sub(1).map(usize::from) else {
            return PollAffinity::Unavailable;
        };
        online
            .member_at(queue_index % online.len())
            .map_or(PollAffinity::Unavailable, PollAffinity::Cpu)
    }
}

#[cfg(all(test, any(feature = "std", target_os = "linux")))]
mod tests {
    use super::*;

    #[test]
    fn a_fault_stops_submission_and_reports_its_machine_cause() {
        let mut state = RuntimeQueueState::with_depth(4).expect("small fixed table");
        assert!(state.can_submit());
        assert!(state.needs_poll());
        state.phase =
            RuntimeQueuePhase::Faulted(RuntimeQueueFault::Driver(PollError::InvalidQueue));
        assert!(!state.can_submit());
        assert!(!state.needs_poll());
        assert_eq!(state.fault_cause(), Some(IoError::InvalidParameter));
    }
}
