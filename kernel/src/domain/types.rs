//! Canonical domain types and snapshots.

use super::quota::DomainPriority;
use crate::security::CapabilitySet;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Once;

pub const CPU_QUOTA_SUSPEND_STREAK: u8 = 3;
pub const CPU_QUOTA_SUSPEND_WINDOW_NS: u64 = 100_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuQuotaAction {
    None,
    YieldDemote,
    Suspend { until_ns: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainId(u64);

impl DomainId {
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    pub const fn as_u64(&self) -> u64 {
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
    Stopped,
    Terminated,
}

impl DomainState {
    pub fn is_runnable(&self) -> bool {
        matches!(self, DomainState::Running | DomainState::Initializing)
    }

    pub fn is_active(&self) -> bool {
        !matches!(self, DomainState::Terminated)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainCredentials {
    pub uid: u32,
    pub gid: u32,
}

impl DomainCredentials {
    pub const ROOT: Self = Self { uid: 0, gid: 0 };

    pub const fn new(uid: u32, gid: u32) -> Self {
        Self { uid, gid }
    }
}

#[derive(Debug, Clone)]
pub struct DomainSecurity {
    pub credentials: DomainCredentials,
    pub caps: CapabilitySet,
}

impl DomainSecurity {
    pub fn kernel() -> Self {
        Self {
            credentials: DomainCredentials::ROOT,
            caps: CapabilitySet::full(),
        }
    }
}

impl Default for DomainSecurity {
    fn default() -> Self {
        Self {
            credentials: DomainCredentials::ROOT,
            caps: CapabilitySet::empty(),
        }
    }
}

pub(crate) fn kernel_security_handle() -> Arc<DomainSecurity> {
    static KERNEL_SECURITY: Once<Arc<DomainSecurity>> = Once::new();
    KERNEL_SECURITY
        .call_once(|| Arc::new(DomainSecurity::kernel()))
        .clone()
}

#[derive(Debug, Clone, Copy)]
pub struct RequestedCap {
    pub cap: u64,
    pub expires: Option<u64>,
    pub delegatable: bool,
}

#[derive(Debug, Clone)]
pub struct DomainSnapshot {
    pub id: DomainId,
    pub name: alloc::string::String,
    pub state: DomainState,
    pub tasks: usize,
    pub task_ids: Vec<u64>,
    pub memory_bytes: u64,
    pub rrefs: u64,
    pub runtime_ticks: u64,
    pub context_switches: u64,
    pub created_at: u64,
    pub dependencies: Vec<DomainId>,
    pub dependents: Vec<DomainId>,
    pub numa_node: Option<usize>,
    pub priority: DomainPriority,
    pub cpu_limit_percent: u64,
    pub memory_limit_bytes: u64,
    pub io_bandwidth_limit: u64,
    pub panic_message: Option<alloc::string::String>,
    pub last_error: Option<alloc::string::String>,
}

#[derive(Debug, Clone, Default)]
pub struct DomainStats {
    pub total: usize,
    pub running: usize,
    pub stopped: usize,
    pub terminated: usize,
    pub memory_used: u64,
    pub total_rrefs: u64,
}
