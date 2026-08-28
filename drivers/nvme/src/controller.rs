use alloc::boxed::Box;
use hal::MappedMmio;
use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::dma::DmaQueueIdentity;

use crate::{
    NvmeQueue, NvmeRegisterError, NvmeRegisters, PreparedQueuePair, QueueActivationError,
    QueueMemory, QueuePrepareError,
};

/// Failure while acquiring the mapped controller into a disable typestate.
pub enum ControllerAcquireError {
    /// Mandatory register geometry was invalid; the mapping is returned.
    Registers {
        cause: NvmeRegisterError,
        mapping: MappedMmio,
    },
    /// Device or queue generation cannot form a DMA queue identity.
    InvalidIdentity(NvmeRegisters),
    /// A register operation failed before ownership changed.
    Access {
        cause: NvmeRegisterError,
        registers: NvmeRegisters,
    },
}

impl core::fmt::Debug for ControllerAcquireError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Registers { cause, mapping } => formatter
                .debug_struct("Registers")
                .field("cause", cause)
                .field("mapping", mapping)
                .finish(),
            Self::InvalidIdentity(_) => formatter.write_str("InvalidIdentity(..)"),
            Self::Access { cause, .. } => formatter
                .debug_struct("Access")
                .field("cause", cause)
                .finish_non_exhaustive(),
        }
    }
}

/// Result of requesting the controller-disabled state.
pub enum ControllerAcquire {
    /// CSTS.RDY was already clear.
    Disabled(ControllerDisabled),
    /// CC.EN was cleared and RDY must still be polled.
    Disabling(ControllerDisabling),
}

/// Controller owner waiting for CSTS.RDY to clear.
pub struct ControllerDisabling {
    registers: NvmeRegisters,
    admin_identity: DmaQueueIdentity,
}

/// Controller owner that has observed CSTS.RDY clear.
pub struct ControllerDisabled {
    registers: NvmeRegisters,
    admin_identity: DmaQueueIdentity,
}

impl ControllerAcquire {
    /// Consume a mapped BAR and request the disabled state.
    ///
    /// # Errors
    /// Returns the complete mapping/register owner when geometry, identity, or
    /// the initial CC/CSTS access is invalid.
    pub fn begin(
        mapping: MappedMmio,
        device: PackedPciLocation,
        generation: u64,
    ) -> Result<Self, ControllerAcquireError> {
        let registers = match NvmeRegisters::new(mapping) {
            Ok(registers) => registers,
            Err((cause, mapping)) => {
                return Err(ControllerAcquireError::Registers { cause, mapping });
            }
        };
        let Some(admin_identity) = DmaQueueIdentity::new(device, 0, generation) else {
            return Err(ControllerAcquireError::InvalidIdentity(registers));
        };
        let status = match registers.status() {
            Ok(status) => status,
            Err(cause) => {
                return Err(ControllerAcquireError::Access { cause, registers });
            }
        };
        let enabled = match registers.enabled() {
            Ok(enabled) => enabled,
            Err(cause) => {
                return Err(ControllerAcquireError::Access { cause, registers });
            }
        };
        if !enabled && !status.ready() {
            return Ok(Self::Disabled(ControllerDisabled {
                registers,
                admin_identity,
            }));
        }
        if let Err(cause) = registers.request_disable() {
            return Err(ControllerAcquireError::Access { cause, registers });
        }
        Ok(Self::Disabling(ControllerDisabling {
            registers,
            admin_identity,
        }))
    }
}

impl ControllerDisabling {
    /// Observe one disable-progress step without spinning in the driver.
    ///
    /// # Errors
    /// Returns the unchanged owner if CSTS cannot be read.
    pub fn poll(self) -> Result<ControllerDisablePoll, ControllerDisableError> {
        let status = match self.registers.status() {
            Ok(status) => status,
            Err(cause) => {
                return Err(ControllerDisableError {
                    cause,
                    controller: self,
                });
            }
        };
        if status.ready() {
            Ok(ControllerDisablePoll::Waiting(self))
        } else {
            Ok(ControllerDisablePoll::Disabled(ControllerDisabled {
                registers: self.registers,
                admin_identity: self.admin_identity,
            }))
        }
    }
}

/// One disable poll observation.
pub enum ControllerDisablePoll {
    /// Controller is still ready; poll again under caller policy.
    Waiting(ControllerDisabling),
    /// Controller is now disabled.
    Disabled(ControllerDisabled),
}

/// Failed CSTS observation retaining the disabling owner.
pub struct ControllerDisableError {
    /// Register failure.
    pub cause: NvmeRegisterError,
    /// Owner that may be polled or shut down by policy.
    pub controller: ControllerDisabling,
}

impl core::fmt::Debug for ControllerDisableError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ControllerDisableError")
            .field("cause", &self.cause)
            .finish_non_exhaustive()
    }
}

/// Failure while installing the Admin queue, retaining controller and memory.
pub enum AdminQueueInstallError {
    /// Queue preparation failed before active sharing.
    Prepare {
        controller: ControllerDisabled,
        cause: QueuePrepareError,
    },
    /// Queue activation partially or completely failed.
    Activate {
        controller: ControllerDisabled,
        cause: QueueActivationError,
    },
    /// Queue memory is active but register programming did not complete.
    Program {
        controller: ControllerDisabled,
        cause: NvmeRegisterError,
        queue: Box<NvmeQueue>,
    },
}

impl core::fmt::Debug for AdminQueueInstallError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Prepare { cause, .. } => formatter.debug_tuple("Prepare").field(cause).finish(),
            Self::Activate { cause, .. } => formatter.debug_tuple("Activate").field(cause).finish(),
            Self::Program { cause, .. } => formatter
                .debug_struct("Program")
                .field("cause", cause)
                .finish_non_exhaustive(),
        }
    }
}

impl ControllerDisabled {
    /// Install active Admin queue RAM, program its properties, and request enable.
    ///
    /// # Errors
    /// Every failure retains the disabled controller and the queue-memory state.
    /// No success is reported until every property and CC.EN write completes.
    pub fn install_admin_queue(
        self,
        depth: u16,
        memory: QueueMemory,
    ) -> Result<ControllerEnabling, AdminQueueInstallError> {
        let prepared = match PreparedQueuePair::prepare(self.admin_identity, depth, memory) {
            Ok(prepared) => prepared,
            Err(cause) => {
                return Err(AdminQueueInstallError::Prepare {
                    controller: self,
                    cause,
                });
            }
        };
        let submission = prepared.submission_address();
        let completion = prepared.completion_address();
        let queue = match prepared.activate() {
            Ok(queue) => Box::new(queue),
            Err(cause) => {
                return Err(AdminQueueInstallError::Activate {
                    controller: self,
                    cause,
                });
            }
        };
        if let Err(cause) = self
            .registers
            .program_admin_queue(depth, submission, completion)
        {
            return Err(AdminQueueInstallError::Program {
                controller: self,
                cause,
                queue,
            });
        }
        if let Err(cause) = self.registers.enable_nvm() {
            return Err(AdminQueueInstallError::Program {
                controller: self,
                cause,
                queue,
            });
        }
        Ok(ControllerEnabling {
            registers: self.registers,
            admin_queue: queue,
        })
    }
}

/// Controller owner waiting for CSTS.RDY after Admin queue publication.
pub struct ControllerEnabling {
    registers: NvmeRegisters,
    admin_queue: Box<NvmeQueue>,
}

impl ControllerEnabling {
    /// Observe one enable-progress step without imposing a wait policy.
    ///
    /// # Errors
    /// Register failure or CSTS.CFS retains the complete controller and queue.
    pub fn poll(self) -> Result<ControllerEnablePoll, ControllerEnableError> {
        let status = match self.registers.status() {
            Ok(status) => status,
            Err(cause) => {
                return Err(ControllerEnableError {
                    cause: ControllerEnableFailure::Register(cause),
                    controller: self,
                });
            }
        };
        if status.fatal() {
            return Err(ControllerEnableError {
                cause: ControllerEnableFailure::FatalStatus,
                controller: self,
            });
        }
        if status.ready() {
            Ok(ControllerEnablePoll::Ready(NvmeAdminController {
                registers: self.registers,
                admin_queue: self.admin_queue,
            }))
        } else {
            Ok(ControllerEnablePoll::Waiting(self))
        }
    }
}

/// One enable poll observation.
pub enum ControllerEnablePoll {
    /// Controller has not asserted RDY yet.
    Waiting(ControllerEnabling),
    /// Admin command transport is ready.
    Ready(NvmeAdminController),
}

/// Machine-readable enable failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControllerEnableFailure {
    /// CSTS access failed.
    Register(NvmeRegisterError),
    /// Controller reported fatal status.
    FatalStatus,
}

/// Enable failure retaining controller and active Admin queue owners.
pub struct ControllerEnableError {
    /// Failure reason.
    pub cause: ControllerEnableFailure,
    /// One-way owner; queue memory is still device-shared.
    pub controller: ControllerEnabling,
}

impl core::fmt::Debug for ControllerEnableError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ControllerEnableError")
            .field("cause", &self.cause)
            .finish_non_exhaustive()
    }
}

/// Ready controller with one active Admin queue.
pub struct NvmeAdminController {
    pub(crate) registers: NvmeRegisters,
    pub(crate) admin_queue: Box<NvmeQueue>,
}
