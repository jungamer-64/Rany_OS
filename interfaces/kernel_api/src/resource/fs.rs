pub use crate::types_impl::{FileHandle, OpenMode};

/// Phase retained when a journal operation cannot prove completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalStage {
    Opening,
    Recovering,
    ApplyingHome,
    DataWrite,
    DataFlush,
    RootWrite,
    RootFlush,
}

/// Device completion and DMA ownership remain separate outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalStorageError {
    InvalidRange,
    Allocation,
    Io(crate::service::storage::BlockTransferError),
    ShortTransfer { expected: usize, actual: usize },
    OutcomeUnknown(crate::service::storage::BlockTransferError),
    AuthorityRetained(crate::service::storage::BlockTransferError),
    Close(crate::dma::DmaLeaseError),
}

/// A failure after publication starts leaves admission closed and retains the
/// journal intent. A Retained result is not permission to replay the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalError {
    Busy,
    Retained {
        stage: WalStage,
        committed_records: usize,
        pending_records: usize,
        applied_operations: usize,
    },
    BackendUnavailable,
    InvalidConfig,
    Codec,
    Allocation,
    OutOfSpace,
    IdentityExhausted,
    Storage {
        stage: WalStage,
        cause: WalStorageError,
    },
}

/// Filesystem progress is observable independently of journal completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsMutationError {
    Filesystem(crate::KapiError),
    JournalUnavailable(WalError),
    MemoryCommitted(WalError),
    RecoveryRequired { intent_bytes: usize },
}

impl core::fmt::Display for FsMutationError {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Filesystem(cause) => write!(out, "filesystem: {cause}"),
            Self::JournalUnavailable(cause) => {
                write!(out, "journal admission failed before mutation: {cause:?}")
            }
            Self::RecoveryRequired { intent_bytes } => write!(
                out,
                "filesystem retains an unfinished mutation ({intent_bytes} journal bytes)"
            ),
            Self::MemoryCommitted(cause) => write!(
                out,
                "memory filesystem changed; journal completion unconfirmed: {cause:?}"
            ),
        }
    }
}
