//! Domain lifecycle outcomes retain whether execution and code reclamation are complete.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainId(u64);

impl DomainId {
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }

    pub const KERNEL: DomainId = DomainId(0);
}

impl core::fmt::Display for DomainId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Domain({})", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainState {
    Initializing,
    Running,
    Suspended,
    Stopping,
    Stopped,
    /// Admission is closed permanently; resources are retained until reclamation completes.
    Terminating,
    Terminated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainStopOutcome {
    Complete,
    InProgress {
        active_polls: usize,
        interrupted_polls: usize,
    },
}

/// Code stays mapped until its instances, references, and module finalizer
/// finish. Busy outcomes may be retried by the same reclamation owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeFinalizationError {
    Retained { leases: usize },
    DriverInstances { instances: usize },
    Busy,
    CellNotFound,
    OutOfMemory,
    ContextUnavailable,
    CallbackFailed(crate::abi::driver::AbiError),
}

impl CodeFinalizationError {
    /// The owner may retry after the retained invocation, instance, or lease ends.
    #[must_use]
    pub const fn is_pending(self) -> bool {
        matches!(
            self,
            Self::Retained { .. } | Self::DriverInstances { .. } | Self::Busy
        )
    }
}

impl core::fmt::Display for CodeFinalizationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Retained { leases } => write!(formatter, "code retained by {leases} leases"),
            Self::DriverInstances { instances } => {
                write!(formatter, "code retained by {instances} driver instances")
            }
            Self::Busy => formatter.write_str("module finalization remains in progress"),
            Self::CellNotFound => formatter.write_str("mapped cell not found"),
            Self::OutOfMemory => formatter.write_str("module finalization allocation failed"),
            Self::ContextUnavailable => {
                formatter.write_str("module finalization authority unavailable")
            }
            Self::CallbackFailed(cause) => {
                write!(formatter, "module finalization failed: {cause:?}")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaError {
    CpuPercentageOutOfRange {
        requested: u64,
    },
    CpuPeriodZero,
    CpuPeriodOverflow,
    /// A live account retains the time window of its existing charges.
    CpuPeriodChanged {
        current_ns: u64,
        requested_ns: u64,
    },
    /// CPU時間超過
    CpuTimeExceeded {
        domain_id: DomainId,
    },
    /// メモリ超過
    MemoryExceeded {
        requested: u64,
        available: u64,
        limit: u64,
    },
    /// I/O帯域超過
    IoBandwidthExceeded {
        requested: u64,
        available: u64,
    },
    /// 割り当て競合（再試行が必要）
    AllocationRace,
    /// No account exists for this non-kernel domain.
    Unregistered {
        domain_id: DomainId,
    },
    /// The account has stopped admitting execution and allocations.
    Retired {
        domain_id: DomainId,
    },
    /// Fallible allocation of registry storage or an account failed.
    MetadataAllocationFailed,
    /// The registry is poisoned and cannot safely publish policy.
    RegistryUnavailable,
    /// Byte totals or binding counts cannot be represented.
    AccountingOverflow,
    /// A charge must represent at least one byte.
    InvalidSize,
}

impl core::fmt::Display for QuotaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            QuotaError::CpuPercentageOutOfRange { requested } => {
                write!(f, "CPU quota percentage {requested} exceeds 100")
            }
            QuotaError::CpuPeriodZero => f.write_str("CPU quota period must be nonzero"),
            QuotaError::CpuPeriodOverflow => {
                f.write_str("CPU quota period cannot be represented in nanoseconds")
            }
            QuotaError::CpuPeriodChanged {
                current_ns,
                requested_ns,
            } => write!(
                f,
                "CPU quota period cannot change from {current_ns}ns to {requested_ns}ns while the account is live"
            ),
            QuotaError::CpuTimeExceeded { domain_id } => {
                write!(f, "CPU quota exceeded for domain {}", domain_id)
            }
            QuotaError::MemoryExceeded {
                requested,
                available,
                limit,
            } => {
                write!(
                    f,
                    "Memory quota exceeded: requested {} bytes, available {} of {} limit",
                    requested, available, limit
                )
            }
            QuotaError::IoBandwidthExceeded {
                requested,
                available,
            } => {
                write!(
                    f,
                    "I/O bandwidth exceeded: requested {} bytes, available {} tokens",
                    requested, available
                )
            }
            QuotaError::AllocationRace => write!(f, "Quota admission raced; retry required"),
            QuotaError::Unregistered { domain_id } => {
                write!(f, "Domain {domain_id} has no quota account")
            }
            QuotaError::Retired { domain_id } => {
                write!(f, "Domain {domain_id} quota account is retired")
            }
            QuotaError::MetadataAllocationFailed => write!(f, "Quota metadata allocation failed"),
            QuotaError::RegistryUnavailable => write!(f, "Quota registry unavailable"),
            QuotaError::AccountingOverflow => write!(f, "Quota accounting overflow"),
            QuotaError::InvalidSize => write!(f, "Quota charge must be nonzero"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainLifecycleError {
    NotFound,
    KernelDomain,
    RegistryPoisoned,
    PermissionDenied,
    Quota(QuotaError),
    InvalidState(DomainState),
    ReclamationInProgress,
    Busy(DomainStopOutcome),
    CodeBusy {
        leases: usize,
    },
    CodeFinalization {
        cell_id: u64,
        cause: CodeFinalizationError,
    },
    /// Closed handles stay closed on failure; retry finalizes the remaining
    /// owners. Domain memory and code remain retained throughout this result.
    ResourceCleanupIncomplete {
        completed_net_ports: usize,
        retained_net_ports: usize,
        completed_block_devices: usize,
        retained_block_devices: usize,
        completed_dma_leases: usize,
        retained_dma_leases: usize,
        retained_balloon_pages: usize,
        cause: crate::error::KapiError,
    },
}

impl core::fmt::Display for DomainLifecycleError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFound => formatter.write_str("domain not found"),
            Self::KernelDomain => formatter.write_str("kernel domain cannot be stopped"),
            Self::RegistryPoisoned => formatter.write_str("domain registry poisoned"),
            Self::PermissionDenied => formatter.write_str("owner or CAP_KILL required"),
            Self::Quota(cause) => write!(formatter, "domain quota admission failed: {cause}"),
            Self::InvalidState(state) => write!(
                formatter,
                "operation is unavailable in domain state {state:?}"
            ),
            Self::ReclamationInProgress => {
                formatter.write_str("domain reclamation is already in progress")
            }
            Self::Busy(outcome) => write!(formatter, "domain stop incomplete: {outcome:?}"),
            Self::CodeBusy { leases } => {
                write!(formatter, "domain code is retained by {leases} leases")
            }
            Self::CodeFinalization { cell_id, cause } => {
                write!(formatter, "cell {cell_id} finalization incomplete: {cause}")
            }
            Self::ResourceCleanupIncomplete {
                completed_net_ports,
                retained_net_ports,
                completed_block_devices,
                retained_block_devices,
                completed_dma_leases,
                retained_dma_leases,
                retained_balloon_pages,
                cause,
            } => write!(
                formatter,
                "domain cleanup incomplete: net ports {completed_net_ports} released/{retained_net_ports} retained; block devices {completed_block_devices} released/{retained_block_devices} retained; DMA leases {completed_dma_leases} released/{retained_dma_leases} retained; balloon pages {retained_balloon_pages} retained: {cause}"
            ),
        }
    }
}

impl DomainState {
    pub fn is_runnable(&self) -> bool {
        matches!(self, DomainState::Running | DomainState::Initializing)
    }

    pub fn is_active(&self) -> bool {
        !matches!(self, DomainState::Terminated)
    }
}
