use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};

use spin::Once;

use crate::drivers::apic::LocalApicError;
use crate::sync::{AtomicWaker, PoisonLock};
use crate::task::{SpawnError, TaskPlacement};

use super::{
    CpuBlocker, CpuControlMessage, CpuDrainFailure, CpuFailurePhase, CpuFailureReason, CpuId,
    CpuIpiError, CpuRole, CpuSlotState, CpuTopologyIssue, CpuTransitionError, IpiKind,
};

const PARK_TIMEOUT_NS: u64 = 1_000_000_000;
const PARK_MAX_POLLS: usize = 10_000_000;
const SUBSYSTEM_DRAIN_TIMEOUT_NS: u64 = 1_000_000_000;
const SUBSYSTEM_DRAIN_MAX_POLLS: usize = 10_000_000;

struct TransitionCompletion<T> {
    result: PoisonLock<Option<T>>,
    waker: AtomicWaker,
}

impl<T> TransitionCompletion<T> {
    const fn new() -> Self {
        Self {
            result: PoisonLock::new(None),
            waker: AtomicWaker::new(),
        }
    }

    fn take_result(&self) -> Option<T> {
        self.result
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
    }

    fn complete(&self, result: T) {
        let previous = self
            .result
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .replace(result);
        assert!(
            previous.is_none(),
            "CPU transition completed more than once"
        );
        self.waker.wake();
    }
}

struct EjectPermit {
    id: CpuId,
}

/// Exclusive authority to execute the firmware portion of a physical CPU
/// eject after the lifecycle worker has removed the CPU from all runtime use.
///
/// The authority is consumed by exactly one outcome commit. Abandoning it is
/// reconciled by the same BSP-pinned lifecycle worker, so cancellation cannot
/// leave the slot indefinitely exposed as `Ejecting`.
pub(crate) struct CpuEjectAuthority {
    permit: Option<EjectPermit>,
}

impl CpuEjectAuthority {
    pub(crate) const fn cpu(&self) -> CpuId {
        self.permit
            .as_ref()
            .expect("consumed CPU eject authority was observed")
            .id
    }

    fn take_permit(&mut self) -> EjectPermit {
        self.permit
            .take()
            .expect("CPU eject authority was consumed more than once")
    }
}

impl Drop for CpuEjectAuthority {
    fn drop(&mut self) {
        let Some(permit) = self.permit.take() else {
            return;
        };
        let Some(queue) = TRANSITION_QUEUE.get() else {
            panic!("CPU eject authority outlived its lifecycle worker");
        };
        queue.enqueue(TransitionRequest::AbandonEject { permit });
    }
}

enum EjectOutcome {
    FirmwareAbsent,
    PresentOffline(super::FirmwareError),
}

enum TransitionRequest {
    Online {
        id: CpuId,
        completion: Arc<TransitionCompletion<Result<(), CpuTransitionError>>>,
    },
    Offline {
        id: CpuId,
        completion: Arc<TransitionCompletion<Result<(), CpuTransitionError>>>,
    },
    PrepareEject {
        id: CpuId,
        completion: Arc<TransitionCompletion<Result<CpuEjectAuthority, CpuTransitionError>>>,
    },
    FinishEject {
        permit: EjectPermit,
        outcome: EjectOutcome,
        completion: Arc<TransitionCompletion<Result<(), CpuTransitionError>>>,
    },
    AbandonEject {
        permit: EjectPermit,
    },
}

struct TransitionQueue {
    requests: PoisonLock<VecDeque<TransitionRequest>>,
    worker_waker: AtomicWaker,
    worker_started: AtomicBool,
}

impl TransitionQueue {
    const fn new() -> Self {
        Self {
            requests: PoisonLock::new(VecDeque::new()),
            worker_waker: AtomicWaker::new(),
            worker_started: AtomicBool::new(false),
        }
    }

    fn enqueue(&self, request: TransitionRequest) {
        self.requests
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push_back(request);
        self.worker_waker.wake();
    }

    fn pop(&self) -> Option<TransitionRequest> {
        self.requests
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .pop_front()
    }
}

static TRANSITION_QUEUE: Once<TransitionQueue> = Once::new();

pub(super) fn initialize() -> Result<(), SpawnError> {
    let queue = TRANSITION_QUEUE.call_once(TransitionQueue::new);
    if queue
        .worker_started
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Ok(());
    }
    match crate::task::spawn(transition_worker(), TaskPlacement::Pinned(CpuId::BOOTSTRAP)) {
        Ok(_) => Ok(()),
        Err(error) => {
            queue.worker_started.store(false, Ordering::Release);
            Err(error)
        }
    }
}

/// Starts or resumes an application CPU and publishes it for task placement.
///
/// Once submitted, cancellation of the returned future does not cancel the
/// lifecycle operation; the BSP-pinned worker remains its completion owner.
pub async fn online(id: CpuId) -> Result<(), CpuTransitionError> {
    let completion = Arc::new(TransitionCompletion::new());
    submit(
        TransitionRequest::Online {
            id,
            completion: completion.clone(),
        },
        completion,
    )
    .await
}

/// Removes an application CPU from task placement and parks it.
///
/// Once submitted, cancellation of the returned future does not cancel the
/// lifecycle operation; the BSP-pinned worker remains its completion owner.
pub async fn offline(id: CpuId) -> Result<(), CpuTransitionError> {
    let completion = Arc::new(TransitionCompletion::new());
    submit(
        TransitionRequest::Offline {
            id,
            completion: completion.clone(),
        },
        completion,
    )
    .await
}

/// Quiesces a CPU and grants exclusive authority for its firmware eject.
///
/// Once submitted, cancellation cannot cancel the drain. If the returned
/// authority is subsequently abandoned, the lifecycle worker records a typed
/// firmware failure and restores the slot to `PresentOffline`.
pub(crate) async fn prepare_eject(id: CpuId) -> Result<CpuEjectAuthority, CpuTransitionError> {
    let completion = Arc::new(TransitionCompletion::new());
    submit(
        TransitionRequest::PrepareEject {
            id,
            completion: completion.clone(),
        },
        completion,
    )
    .await
}

/// Commits firmware-confirmed absence and consumes the eject authority.
pub(crate) async fn commit_eject(
    mut authority: CpuEjectAuthority,
) -> Result<(), CpuTransitionError> {
    let permit = authority.take_permit();
    finish_eject(permit, EjectOutcome::FirmwareAbsent).await
}

/// Records a firmware eject failure and consumes the eject authority.
pub(crate) async fn fail_eject(
    mut authority: CpuEjectAuthority,
    error: super::FirmwareError,
) -> Result<(), CpuTransitionError> {
    let permit = authority.take_permit();
    finish_eject(permit, EjectOutcome::PresentOffline(error)).await
}

async fn finish_eject(
    permit: EjectPermit,
    outcome: EjectOutcome,
) -> Result<(), CpuTransitionError> {
    let completion = Arc::new(TransitionCompletion::new());
    submit(
        TransitionRequest::FinishEject {
            permit,
            outcome,
            completion: completion.clone(),
        },
        completion,
    )
    .await
}

async fn submit<T>(request: TransitionRequest, completion: Arc<TransitionCompletion<T>>) -> T {
    let queue = TRANSITION_QUEUE
        .get()
        .unwrap_or_else(|| panic!("CPU transition requested before CPU runtime initialization"));
    assert!(
        queue.worker_started.load(Ordering::Acquire),
        "CPU transition requested without its lifecycle worker"
    );
    queue.enqueue(request);
    CompletionFuture { completion }.await
}

struct CompletionFuture<T> {
    completion: Arc<TransitionCompletion<T>>,
}

impl<T> Future for CompletionFuture<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(result) = self.completion.take_result() {
            return Poll::Ready(result);
        }
        self.completion.waker.register(context.waker());
        match self.completion.take_result() {
            Some(result) => Poll::Ready(result),
            None => Poll::Pending,
        }
    }
}

struct NextRequestFuture {
    queue: &'static TransitionQueue,
}

impl Future for NextRequestFuture {
    type Output = TransitionRequest;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(request) = self.queue.pop() {
            return Poll::Ready(request);
        }
        self.queue.worker_waker.register(context.waker());
        match self.queue.pop() {
            Some(request) => Poll::Ready(request),
            None => Poll::Pending,
        }
    }
}

async fn transition_worker() {
    let queue = TRANSITION_QUEUE
        .get()
        .unwrap_or_else(|| panic!("CPU transition worker started without its request queue"));
    loop {
        let request = NextRequestFuture { queue }.await;
        match request {
            TransitionRequest::Online { id, completion } => {
                let result = perform_online(id);
                log_transition_failure(id, "online", &result);
                completion.complete(result);
            }
            TransitionRequest::Offline { id, completion } => match perform_offline(id).await {
                OfflineOutcome::Complete(result) => {
                    log_transition_failure(id, "offline", &result);
                    completion.complete(result);
                }
                OfflineOutcome::Reconcile(pending) => {
                    let result = Err(pending.error.clone());
                    log_transition_failure(id, "offline", &result);
                    completion.complete(result);
                    reconcile_timed_out_drain(pending).await;
                }
            },
            TransitionRequest::PrepareEject { id, completion } => {
                let result = perform_prepare_eject(id).await;
                if let Err(error) = &result {
                    log::warn!("CPU {id} prepare-eject transition failed: {error:?}");
                }
                completion.complete(result);
            }
            TransitionRequest::FinishEject {
                permit,
                outcome,
                completion,
            } => {
                let id = permit.id;
                let result = perform_finish_eject(permit, outcome);
                log_transition_failure(id, "finish-eject", &result);
                completion.complete(result);
            }
            TransitionRequest::AbandonEject { permit } => {
                let id = permit.id;
                let error = super::FirmwareError {
                    kind: super::FirmwareErrorKind::EventDelivery,
                    object: None,
                    detail: alloc::string::String::from(
                        "firmware eject authority was abandoned before outcome reconciliation",
                    ),
                };
                let result = perform_finish_eject(permit, EjectOutcome::PresentOffline(error));
                log_transition_failure(id, "abandon-eject", &result);
            }
        }
    }
}

fn log_transition_failure(
    id: CpuId,
    operation: &'static str,
    result: &Result<(), CpuTransitionError>,
) {
    if let Err(error) = result {
        log::warn!("CPU {} {} transition failed: {:?}", id, operation, error);
    }
}

async fn perform_prepare_eject(id: CpuId) -> Result<CpuEjectAuthority, CpuTransitionError> {
    let slot = super::snapshot()
        .slot(id)
        .cloned()
        .ok_or(CpuTransitionError::NotPresent)?;
    if slot.role == CpuRole::Bootstrap {
        return Err(CpuTransitionError::BootstrapCpu);
    }
    if slot.firmware.eject != super::CpuEjectCapability::FirmwareEject {
        return Err(CpuTransitionError::UnsupportedTopology(
            CpuTopologyIssue::PhysicalEjectUnsupported { id },
        ));
    }
    match slot.state {
        CpuSlotState::Online => match perform_offline(id).await {
            OfflineOutcome::Complete(result) => result?,
            OfflineOutcome::Reconcile(pending) => {
                let error = pending.error.clone();
                reconcile_timed_out_drain(pending).await;
                return Err(error);
            }
        },
        CpuSlotState::Parked | CpuSlotState::PresentOffline => {}
        CpuSlotState::FirmwareAbsent => return Err(CpuTransitionError::NotPresent),
        _ => {
            return Err(CpuTransitionError::UnsupportedTopology(
                CpuTopologyIssue::ConflictingFirmwareIdentity,
            ));
        }
    }
    super::runtime().begin_eject(id).map_err(runtime_error)?;
    Ok(CpuEjectAuthority {
        permit: Some(EjectPermit { id }),
    })
}

fn perform_finish_eject(
    permit: EjectPermit,
    outcome: EjectOutcome,
) -> Result<(), CpuTransitionError> {
    match outcome {
        EjectOutcome::FirmwareAbsent => super::runtime()
            .eject_complete(permit.id)
            .map_err(runtime_error),
        EjectOutcome::PresentOffline(error) => {
            super::runtime()
                .eject_failed(permit.id, CpuFailureReason::Firmware(error.clone()))
                .map_err(runtime_error)?;
            Err(CpuTransitionError::Firmware(error))
        }
    }
}

fn perform_online(id: CpuId) -> Result<(), CpuTransitionError> {
    let snapshot = super::snapshot();
    let slot = snapshot.slot(id).ok_or(CpuTransitionError::NotPresent)?;
    if slot.role == CpuRole::Bootstrap {
        return Err(CpuTransitionError::BootstrapCpu);
    }
    match slot.state {
        CpuSlotState::Online => return Ok(()),
        CpuSlotState::FirmwareAbsent => return Err(CpuTransitionError::NotPresent),
        CpuSlotState::PresentOffline | CpuSlotState::Parked => {}
        _ => {
            return Err(CpuTransitionError::UnsupportedTopology(
                CpuTopologyIssue::ConflictingFirmwareIdentity,
            ));
        }
    }
    super::startup::online_cpu(id).map_err(|reason| transition_error(id, reason))
}

struct PendingDrainReconciliation {
    id: CpuId,
    local: &'static super::CpuLocal,
    acknowledgement: u64,
    error: CpuTransitionError,
}

enum OfflineOutcome {
    Complete(Result<(), CpuTransitionError>),
    Reconcile(PendingDrainReconciliation),
}

async fn perform_offline(id: CpuId) -> OfflineOutcome {
    match try_perform_offline(id).await {
        Ok(None) => OfflineOutcome::Complete(Ok(())),
        Ok(Some(pending)) => OfflineOutcome::Reconcile(pending),
        Err(error) => OfflineOutcome::Complete(Err(error)),
    }
}

async fn try_perform_offline(
    id: CpuId,
) -> Result<Option<PendingDrainReconciliation>, CpuTransitionError> {
    let snapshot = super::snapshot();
    let slot = snapshot
        .slot(id)
        .cloned()
        .ok_or(CpuTransitionError::NotPresent)?;
    if slot.role == CpuRole::Bootstrap {
        return Err(CpuTransitionError::BootstrapCpu);
    }
    match slot.state {
        CpuSlotState::PresentOffline | CpuSlotState::Parked => return Ok(None),
        CpuSlotState::FirmwareAbsent => return Err(CpuTransitionError::NotPresent),
        CpuSlotState::Online => {}
        _ => {
            return Err(CpuTransitionError::UnsupportedTopology(
                CpuTopologyIssue::ConflictingFirmwareIdentity,
            ));
        }
    }

    let local = super::runtime().cpu_local(id).ok_or_else(|| {
        CpuTransitionError::UnsupportedTopology(CpuTopologyIssue::CpuStartupUnavailable {
            id,
            failure: super::CpuStartupFailure::CpuLocalBinding,
        })
    })?;
    crate::task::prepare_cpu_offline(id)
        .map_err(|blockers| CpuTransitionError::Busy { blockers })?;
    if let Err(error) = super::runtime().begin_drain(id) {
        crate::task::publish_cpu_online(id);
        return Err(runtime_error(error));
    }

    crate::net::runtime::context::begin_cpu_drain(id);
    let irq_blockers = crate::io::interrupt_manager::cpu_offline_blockers(slot.firmware.apic_id);
    if !irq_blockers.is_empty() {
        return Err(abort_blocked_drain(id, irq_blockers));
    }
    if let Err(blockers) = wait_for_subsystem_drain(id).await {
        return Err(abort_blocked_drain(id, blockers));
    }

    let acknowledgement = local.remote().park_acknowledgements();
    if local.remote().send(CpuControlMessage::Park).is_err() {
        let reason = CpuFailureReason::Drain(CpuDrainFailure::ControlQueueSaturated);
        rollback_drain(id, reason.clone());
        return Err(transition_error(id, reason));
    }
    let ipi_failure = super::send_ipi_to_apic(slot.firmware.apic_id, IpiKind::ExecutorWake)
        .err()
        .map(|error| map_drain_ipi_failure(slot.firmware.apic_id, error));
    if wait_for_park_acknowledgement(local, acknowledgement)
        .await
        .is_err()
    {
        let reason = ipi_failure.unwrap_or(CpuFailureReason::DrainTimedOut);
        let error = transition_error(id, reason.clone());
        super::runtime()
            .drain_failed(id, reason)
            .unwrap_or_else(|runtime_error| {
                panic!("CPU {id} drain failure could not be committed: {runtime_error:?}")
            });
        return Ok(Some(PendingDrainReconciliation {
            id,
            local,
            acknowledgement,
            error,
        }));
    }

    super::runtime().drain_complete(id).unwrap_or_else(|error| {
        panic!("CPU {id} park commit failed after AP acknowledgement: {error:?}")
    });
    Ok(None)
}

async fn wait_for_subsystem_drain(id: CpuId) -> Result<(), Arc<[CpuBlocker]>> {
    let start = crate::time::best_effort_time_nanos();
    for _ in 0..SUBSYSTEM_DRAIN_MAX_POLLS {
        let blockers = crate::net::runtime::context::cpu_drain_blockers(id);
        if blockers.is_empty() {
            return Ok(());
        }
        if crate::time::best_effort_time_nanos().saturating_sub(start) >= SUBSYSTEM_DRAIN_TIMEOUT_NS
        {
            return Err(blockers);
        }
        crate::task::yield_now().await;
    }
    Err(crate::net::runtime::context::cpu_drain_blockers(id))
}

fn abort_blocked_drain(id: CpuId, blockers: Arc<[CpuBlocker]>) -> CpuTransitionError {
    let reason = CpuFailureReason::Drain(CpuDrainFailure::Blocked { blockers });
    let error = transition_error(id, reason.clone());
    rollback_drain(id, reason);
    error
}

async fn reconcile_timed_out_drain(pending: PendingDrainReconciliation) {
    if wait_for_park_acknowledgement(pending.local, pending.acknowledgement)
        .await
        .is_err()
    {
        panic!(
            "CPU {} did not acknowledge a committed drain request; topology is no longer recoverable",
            pending.id
        );
    }
    super::runtime()
        .drain_complete(pending.id)
        .unwrap_or_else(|error| {
            panic!(
                "CPU {} late park acknowledgement could not be committed: {error:?}",
                pending.id
            )
        });
}

async fn wait_for_park_acknowledgement(
    local: &super::CpuLocal,
    acknowledgement: u64,
) -> Result<(), ()> {
    let start = crate::time::best_effort_time_nanos();
    for _ in 0..PARK_MAX_POLLS {
        if local.remote().park_acknowledgements() != acknowledgement {
            return Ok(());
        }
        if crate::time::best_effort_time_nanos().saturating_sub(start) >= PARK_TIMEOUT_NS {
            break;
        }
        crate::task::yield_now().await;
    }
    if local.remote().park_acknowledgements() != acknowledgement {
        return Ok(());
    }
    Err(())
}

fn rollback_drain(id: CpuId, reason: CpuFailureReason) {
    super::runtime()
        .drain_aborted(id, reason)
        .unwrap_or_else(|error| {
            panic!("CPU {id} drain rollback could not be committed: {error:?}")
        });
    crate::net::runtime::context::publish_cpu_online(id);
    crate::task::publish_cpu_online(id);
}

fn map_drain_ipi_failure(apic_id: super::ApicId, error: CpuIpiError) -> CpuFailureReason {
    match error {
        CpuIpiError::LocalApic(LocalApicError::DestinationNotAddressable { destination }) => {
            CpuFailureReason::Topology(CpuTopologyIssue::UnsupportedApicDestination {
                apic_id: super::ApicId::new(destination.as_u32()),
            })
        }
        CpuIpiError::LocalApic(LocalApicError::DeliveryTimedOut { .. }) => {
            CpuFailureReason::Drain(CpuDrainFailure::IpiDelivery)
        }
        CpuIpiError::LocalApic(_)
        | CpuIpiError::CpuNotPresent(_)
        | CpuIpiError::CpuStateIneligible { .. } => {
            CpuFailureReason::Topology(CpuTopologyIssue::InterruptDeliveryUnavailable { apic_id })
        }
    }
}

fn transition_error(id: CpuId, reason: CpuFailureReason) -> CpuTransitionError {
    match reason {
        CpuFailureReason::MissingRequiredFeature { feature } => {
            CpuTransitionError::UnsupportedTopology(CpuTopologyIssue::MissingRequiredFeature {
                feature,
            })
        }
        CpuFailureReason::Startup(failure) => {
            CpuTransitionError::UnsupportedTopology(CpuTopologyIssue::CpuStartupUnavailable {
                id,
                failure,
            })
        }
        CpuFailureReason::Drain(CpuDrainFailure::ControlQueueSaturated) => {
            CpuTransitionError::Busy {
                blockers: Arc::from([CpuBlocker::ControlQueue]),
            }
        }
        CpuFailureReason::Drain(CpuDrainFailure::IpiDelivery) => CpuTransitionError::TimedOut {
            phase: CpuFailurePhase::Drain,
        },
        CpuFailureReason::Drain(CpuDrainFailure::Blocked { blockers }) => {
            CpuTransitionError::Busy { blockers }
        }
        CpuFailureReason::TscInconsistent => {
            CpuTransitionError::UnsupportedTopology(CpuTopologyIssue::TscInconsistent)
        }
        CpuFailureReason::NumaInconsistent => {
            CpuTransitionError::UnsupportedTopology(CpuTopologyIssue::NumaInconsistent)
        }
        CpuFailureReason::StartupAcknowledgementTimedOut => CpuTransitionError::TimedOut {
            phase: CpuFailurePhase::Start,
        },
        CpuFailureReason::DrainTimedOut => CpuTransitionError::TimedOut {
            phase: CpuFailurePhase::Drain,
        },
        CpuFailureReason::Firmware(error) => CpuTransitionError::Firmware(error),
        CpuFailureReason::Topology(issue) => CpuTransitionError::UnsupportedTopology(issue),
    }
}

fn runtime_error(error: super::CpuRuntimeError) -> CpuTransitionError {
    match error {
        super::CpuRuntimeError::UnknownCpu(_) => CpuTransitionError::NotPresent,
        super::CpuRuntimeError::Topology(issue) => CpuTransitionError::UnsupportedTopology(issue),
        super::CpuRuntimeError::State(_) => {
            CpuTransitionError::UnsupportedTopology(CpuTopologyIssue::ConflictingFirmwareIdentity)
        }
    }
}
