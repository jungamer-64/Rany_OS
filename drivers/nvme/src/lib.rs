//! Capability-owned NVMe device core.
//!
//! Register access is derived from one retained MMIO mapping. Submission and
//! completion queues are registry-owned DMA leases in the device-shared state;
//! they are never reinterpreted as Rust references while hardware can access
//! them. Transfer ownership is recovered only from a validated completion.

#![no_std]
#![deny(unsafe_code)]
#![feature(allocator_ext)]

extern crate alloc;

mod controller;
mod identify;
mod protocol;
mod provision;
mod queue;
mod registers;
mod shutdown;
mod standalone;

pub use standalone::standalone_driver_vtable;

pub use controller::{
    AdminQueueInstallError, ControllerAcquire, ControllerAcquireError, ControllerDisableError,
    ControllerDisablePoll, ControllerDisabled, ControllerDisabling, ControllerEnableError,
    ControllerEnableFailure, ControllerEnablePoll, ControllerEnabling, NvmeAdminController,
};
pub use identify::{
    IdentifiedNamespace, IdentifyNamespaceError, IdentifyNamespacePoll, IdentifyNamespaceRequest,
    IdentifySubmitError, NamespaceIdentifyError, NamespaceInfo, NamespaceParseError,
};

pub use protocol::{
    CompletionStatus, IoOpcode, IoTransfer, NvmeCompletion, TransferDirection, TransferRangeError,
};
pub use provision::{
    ActiveQueueCreateCause, IoQueueCreatePoll, IoQueueCreation, IoQueueProvisioner, NvmeController,
    QueueBudgetCause, QueueBudgetError, QueueBudgetPoll, QueueBudgetRequest, QueueCreateError,
    QueueCreationStage, QueueInputError,
};
pub use queue::{
    CompletedCommand, CompletedOwnership, CompletionNotification, NvmeQueue, PollError,
    PreparedQueuePair, QueueActivationError, QueueMemory, QueuePrepareError, QueueSubmission,
    ReconciledResetCommand, SubmitError, SubmitFailure,
};
pub use registers::{ControllerCapabilities, ControllerStatus, NvmeRegisterError, NvmeRegisters};
pub use shutdown::{
    ControllerCloseError, ControllerDmaLocation, ControllerDmaPhase, ControllerDmaReconcileError,
    ControllerDmaReconciliation, ControllerDmaResetError, ControllerDmaRevoked, ControllerReset,
    ControllerResetPoll, ControllerResetPollError, ControllerResetStartError, ControllerResetting,
    IdleControllerCloseError, ReconciledIoCommand, ReconciledNvmeController,
};
