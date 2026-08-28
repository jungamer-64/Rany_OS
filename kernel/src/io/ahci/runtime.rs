//! Scheduler composition for one capability-owned AHCI controller.
//!
//! The runtime serializes controller access, binds each non-NCQ port to one
//! scheduler request, and retains every non-CPU DMA state that cannot be
//! returned during admission or submission. Hardware completion is parsed by
//! `AhciPort::poll`; scheduler bookkeeping never fabricates completion facts.

#![forbid(unsafe_code)]

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::num::NonZeroUsize;

use ahci_driver::controller::{
    AhciController, ControllerPortCause, ControllerPortError, ControllerPortMemory,
};
use ahci_driver::port::{
    CommandPoll, InitializationMemory, PortFault, RejectedBuffer, SubmitCause,
};
use ahci_driver::{AtaCommand, PortNumber};
use kernel_api::dma::{
    CpuDmaLease, DmaLeaseError, DmaTransitionError, PreparedDmaLease, PreparedSharedDmaLease,
    UnmapFailedDmaLease,
};

use crate::io::io_scheduler::{
    DeviceCompletion, DeviceId, DeviceOps, IoCommand, IoCompletion, IoCompletionRoute, IoError,
    IoOperationType, IoSubmission, IoSubmitOutcome, PollAffinity, PollHandler,
};
use crate::sync::PoisonLock;

const PORT_COUNT: usize = 32;

#[derive(Debug)]
enum RetainedLease {
    PreparedTransfer(DmaTransitionError<PreparedDmaLease>),
    PreparedMetadata(DmaTransitionError<PreparedSharedDmaLease>),
    UnmapFailed(UnmapFailedDmaLease),
}

#[derive(Debug)]
enum RuntimePortState {
    Unavailable,
    Idle,
    Submitted {
        route: IoCompletionRoute,
        operation: IoOperationType,
    },
    AuthorityQuarantined {
        cause: IoError,
        lease: RetainedLease,
    },
    PortQuarantined {
        cause: IoError,
    },
}

#[derive(Debug)]
struct RuntimeState {
    controller: AhciController,
    ports: [RuntimePortState; PORT_COUNT],
    retained_initialization: Vec<RetainedLease>,
}

/// Result of attaching one implemented port and reclaiming any returned
/// metadata allocation.
#[derive(Debug)]
pub(crate) enum PortAdmission {
    Attached,
    Rejected {
        cause: ControllerPortCause,
        cleanup: AdmissionCleanup,
    },
    Quarantined {
        cause: ControllerPortCause,
        cleanup: AdmissionCleanup,
    },
}

/// Machine-readable disposition of metadata ownership after failed admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdmissionCleanup {
    ControllerRetained,
    Released,
    PreparedRetained(DmaLeaseError),
    UnmapFailedRetained(DmaLeaseError),
}

/// Exclusive runtime owner for one AHCI controller and its port requests.
#[derive(Debug)]
pub(crate) struct AhciRuntime {
    state: PoisonLock<RuntimeState>,
}

impl AhciRuntime {
    pub(crate) fn new(controller: AhciController) -> Self {
        Self {
            state: PoisonLock::new(RuntimeState {
                controller,
                ports: core::array::from_fn(|_| RuntimePortState::Unavailable),
                retained_initialization: Vec::new(),
            }),
        }
    }

    pub(crate) fn attach_port(
        &self,
        port: PortNumber,
        memory: CpuDmaLease,
        poll_budget: NonZeroUsize,
    ) -> PortAdmission {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        match state.controller.attach_port(port, memory, poll_budget) {
            Ok(()) => {
                if let Some(slot) = state.ports.get_mut(port.as_usize()) {
                    *slot = RuntimePortState::Idle;
                }
                PortAdmission::Attached
            }
            Err(ControllerPortError::Returned { cause, memory }) => {
                let cleanup = retain_or_release_initialization(&mut state, memory);
                PortAdmission::Rejected { cause, cleanup }
            }
            Err(ControllerPortError::Quarantined { cause, memory }) => {
                let cleanup = memory.map_or(AdmissionCleanup::ControllerRetained, |memory| {
                    retain_or_release_initialization(&mut state, memory)
                });
                if let Some(slot) = state.ports.get_mut(port.as_usize()) {
                    *slot = RuntimePortState::PortQuarantined {
                        cause: IoError::DeviceError,
                    };
                }
                PortAdmission::Quarantined { cause, cleanup }
            }
        }
    }

    pub(crate) fn attached_ports(&self) -> Vec<PortNumber> {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .ports
            .iter()
            .enumerate()
            .filter_map(|(index, state)| {
                matches!(state, RuntimePortState::Idle).then_some(PortNumber::new(index as u8))
            })
            .collect()
    }

    fn submit(&self, expected_port: PortNumber, submission: IoSubmission) -> IoSubmitOutcome {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if submission.device()
            != (DeviceId::Ahci {
                controller: state.controller.device(),
                port: expected_port.as_u8(),
            })
        {
            return rejected(IoError::InvalidParameter, submission);
        }
        let command = match submission.command() {
            IoCommand::BlockRead { lba, blocks, .. } => AtaCommand::read(*lba, u32::from(*blocks)),
            IoCommand::BlockWrite { lba, blocks, .. } => {
                AtaCommand::write(*lba, u32::from(*blocks))
            }
            IoCommand::Flush | IoCommand::Discard { .. } => {
                return rejected(IoError::NotSupported, submission);
            }
        };
        let command = match command {
            Ok(command) => command,
            Err(_) => return rejected(IoError::InvalidParameter, submission),
        };

        let index = expected_port.as_usize();
        let Some(runtime_port) = state.ports.get(index) else {
            return rejected(IoError::InvalidParameter, submission);
        };
        match runtime_port {
            RuntimePortState::Idle => {}
            RuntimePortState::Submitted { .. } => return rejected(IoError::Busy, submission),
            RuntimePortState::Unavailable => return rejected(IoError::NotSupported, submission),
            RuntimePortState::AuthorityQuarantined { .. }
            | RuntimePortState::PortQuarantined { .. } => {
                return rejected(IoError::DeviceError, submission);
            }
        }
        if state.controller.port_mut(expected_port).is_none() {
            return rejected(IoError::NotSupported, submission);
        }

        let (route, scheduler_command) = submission.into_parts();
        let (buffer, command_identity) = match scheduler_command {
            IoCommand::BlockRead {
                lba,
                blocks,
                buffer,
            } => (buffer, BlockCommandIdentity::Read { lba, blocks }),
            IoCommand::BlockWrite {
                lba,
                blocks,
                buffer,
            } => (buffer, BlockCommandIdentity::Write { lba, blocks }),
            IoCommand::Flush | IoCommand::Discard { .. } => {
                unreachable!("unsupported control commands were rejected before ownership transfer")
            }
        };

        // Retain the completion route before entering the driver's doorbell
        // boundary. An interrupted submit must not leave an accepted transfer
        // without a scheduler association in this owner.
        state.ports[index] = RuntimePortState::Submitted {
            route,
            operation: command_identity.operation(),
        };
        let result = state
            .controller
            .port_mut(expected_port)
            .expect("port presence was checked under the same controller lock")
            .submit(command, buffer);
        match result {
            Ok(()) => IoSubmitOutcome::Accepted,
            Err(error) => {
                let RuntimePortState::Submitted { route, .. } =
                    core::mem::replace(&mut state.ports[index], RuntimePortState::Idle)
                else {
                    unreachable!("submission route remains under the controller lock")
                };
                let cause = map_submit_cause(error.cause);
                match error.buffer {
                    RejectedBuffer::Cpu(buffer) => {
                        if matches!(
                            error.cause,
                            SubmitCause::Quarantined(_) | SubmitCause::Port(_)
                        ) {
                            *state
                                .ports
                                .get_mut(index)
                                .expect("validated AHCI port indexes the runtime table") =
                                RuntimePortState::PortQuarantined { cause };
                        }
                        route.reject(command_identity.rebuild(buffer), cause)
                    }
                    RejectedBuffer::AbortFailed(failure) => {
                        *state
                            .ports
                            .get_mut(index)
                            .expect("validated AHCI port indexes the runtime table") =
                            RuntimePortState::AuthorityQuarantined {
                                cause,
                                lease: RetainedLease::PreparedTransfer(failure),
                            };
                        IoSubmitOutcome::Finished(route.finish(
                            IoCompletion::authority_quarantined(
                                command_identity.operation(),
                                cause,
                            ),
                        ))
                    }
                }
            }
        }
    }

    fn is_ready(&self, port: PortNumber) -> bool {
        matches!(
            self.state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .ports
                .get(port.as_usize()),
            Some(RuntimePortState::Idle)
        )
    }

    fn poll(&self) -> Vec<DeviceCompletion> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        // At most one result per port. Reserve before consuming any hardware
        // completion so publishing the result cannot require another allocation.
        let mut completions = Vec::with_capacity(PORT_COUNT);
        for index in 0..PORT_COUNT {
            if !matches!(state.ports[index], RuntimePortState::Submitted { .. }) {
                continue;
            }
            let polled = state
                .controller
                .port_mut(PortNumber::new(index as u8))
                .expect("submitted runtime state requires an attached controller port")
                .poll();
            if matches!(polled, Ok(CommandPoll::Pending)) {
                continue;
            }
            let RuntimePortState::Submitted { route, operation } = core::mem::replace(
                &mut state.ports[index],
                RuntimePortState::PortQuarantined {
                    cause: IoError::DeviceError,
                },
            ) else {
                unreachable!("submitted state is held under the same controller lock")
            };
            let completion = match polled {
                Ok(CommandPoll::Completed(completion)) => {
                    state.ports[index] = RuntimePortState::Idle;
                    IoCompletion::transfer_returned(Ok(completion.transferred), completion.buffer)
                }
                Ok(CommandPoll::Idle) => {
                    IoCompletion::outcome_unknown(operation, IoError::DeviceError)
                }
                Err(fault) => {
                    let cause = map_port_fault(fault);
                    state.ports[index] = RuntimePortState::PortQuarantined { cause };
                    IoCompletion::outcome_unknown(operation, cause)
                }
                Ok(CommandPoll::Pending) => unreachable!("pending completion was not consumed"),
            };
            completions.push(route.finish(completion));
        }
        completions
    }
}

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

pub(crate) struct AhciPortOps {
    runtime: Arc<AhciRuntime>,
    port: PortNumber,
}

impl AhciPortOps {
    pub(crate) fn new(runtime: Arc<AhciRuntime>, port: PortNumber) -> Self {
        Self { runtime, port }
    }
}

impl DeviceOps for AhciPortOps {
    fn submit(&self, submission: IoSubmission, _cpu_id: crate::cpu::CpuId) -> IoSubmitOutcome {
        self.runtime.submit(self.port, submission)
    }

    fn is_ready(&self) -> bool {
        self.runtime.is_ready(self.port)
    }
}

pub(crate) struct AhciPoller(Arc<AhciRuntime>);

impl AhciPoller {
    pub(crate) fn new(runtime: Arc<AhciRuntime>) -> Self {
        Self(runtime)
    }
}

impl PollHandler for AhciPoller {
    fn poll_completions(&self) -> Vec<DeviceCompletion> {
        self.0.poll()
    }

    fn is_ready(&self) -> bool {
        true
    }

    fn affinity(&self) -> PollAffinity {
        PollAffinity::Any
    }
}

fn rejected(cause: IoError, submission: IoSubmission) -> IoSubmitOutcome {
    IoSubmitOutcome::Rejected { cause, submission }
}

fn retain_or_release_initialization(
    state: &mut RuntimeState,
    memory: ControllerPortMemory,
) -> AdmissionCleanup {
    match memory {
        ControllerPortMemory::Cpu(memory)
        | ControllerPortMemory::Initialization(InitializationMemory::Cpu(memory)) => {
            close_initialization_cpu(state, memory)
        }
        ControllerPortMemory::Initialization(InitializationMemory::Prepared(memory)) => {
            match memory.abort() {
                Ok(memory) => close_initialization_cpu(state, memory),
                Err(failure) => {
                    let cause = failure.cause();
                    state
                        .retained_initialization
                        .push(RetainedLease::PreparedMetadata(failure));
                    AdmissionCleanup::PreparedRetained(cause)
                }
            }
        }
    }
}

fn close_initialization_cpu(state: &mut RuntimeState, memory: CpuDmaLease) -> AdmissionCleanup {
    match memory.close() {
        Ok(()) => AdmissionCleanup::Released,
        Err(failure) => {
            let (cause, lease) = failure.into_parts();
            state
                .retained_initialization
                .push(RetainedLease::UnmapFailed(lease));
            AdmissionCleanup::UnmapFailedRetained(cause)
        }
    }
}

const fn map_submit_cause(cause: SubmitCause) -> IoError {
    match cause {
        SubmitCause::Busy => IoError::Busy,
        SubmitCause::Command(_) => IoError::InvalidParameter,
        SubmitCause::Dma(_) | SubmitCause::Port(_) | SubmitCause::Quarantined(_) => {
            IoError::DeviceError
        }
    }
}

const fn map_port_fault(fault: PortFault) -> IoError {
    match fault {
        PortFault::DeadlineExpired => IoError::Timeout,
        PortFault::DriverInterrupted
        | PortFault::EngineStopped
        | PortFault::LinkChanged
        | PortFault::UnexpectedActiveSlots
        | PortFault::Transport(_)
        | PortFault::TaskFile(_)
        | PortFault::ByteCount { .. }
        | PortFault::Dma(_) => IoError::DeviceError,
    }
}
