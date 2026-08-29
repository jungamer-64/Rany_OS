//! Capability-owned NVMe device core.
//!
//! Register access is derived from one retained MMIO mapping. Submission and
//! completion queues are registry-owned DMA leases in the device-shared state;
//! they are never reinterpreted as Rust references while hardware can access
//! them. Transfer ownership is recovered only from a validated completion.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

mod controller;
mod identify;
mod protocol;
mod provision;
mod queue;
mod registers;

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
    CompletedCommand, CompletedOwnership, NvmeQueue, PollError, PreparedQueuePair,
    QueueActivationError, QueueMemory, QueuePrepareError, QueueSubmission, SubmitError,
    SubmitFailure,
};
pub use registers::{ControllerCapabilities, ControllerStatus, NvmeRegisterError, NvmeRegisters};
