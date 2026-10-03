//! Canonical domain types and snapshots.

#[path = "identity.rs"]
mod identity;
use super::quota::DomainPriority;
use crate::security::CapabilitySet;
use alloc::sync::Arc;
use alloc::vec::Vec;
pub use identity::DomainId;
use spin::Once;

pub const CPU_QUOTA_SUSPEND_STREAK: u8 = 3;
pub const CPU_QUOTA_SUSPEND_WINDOW_NS: u64 = 100_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuQuotaAction {
    None,
    YieldDemote,
    Suspend { until_ns: u64 },
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

/// Resource publication admission is independent of device authorization and
/// allocation funding. Its borrow is confined to the domain registry guard,
/// which prevents termination from committing before the publication finishes.
pub(crate) struct DomainResourceAdmission<'scope> {
    domain: &'scope DomainId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DomainResourceAdmissionError {
    UnknownOwner,
    RegistryUnavailable,
    OwnerTerminated,
}

impl<'scope> DomainResourceAdmission<'scope> {
    pub(super) fn checked(
        domain: &'scope DomainId,
        state: &'scope DomainState,
    ) -> Result<Self, DomainResourceAdmissionError> {
        if !state.is_active() {
            return Err(DomainResourceAdmissionError::OwnerTerminated);
        }
        Ok(Self { domain })
    }

    pub(crate) fn domain(&self) -> DomainId {
        *self.domain
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

/// Failure to observe a live domain's security snapshot. Lookup is independent
/// of quota admission and cannot synthesize credentials for an unknown owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainSecurityLookupError {
    UnknownDomain(DomainId),
    Terminated(DomainId),
    RegistryUnavailable,
}

impl core::fmt::Display for DomainSecurityLookupError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownDomain(domain) => write!(formatter, "domain {domain} not found"),
            Self::Terminated(domain) => write!(formatter, "domain {domain} has terminated"),
            Self::RegistryUnavailable => formatter.write_str("domain registry unavailable"),
        }
    }
}

#[cfg(all(test, any(feature = "std", target_os = "linux")))]
mod security_lookup_tests {
    use super::*;

    #[test]
    fn missing_and_terminated_security_owners_are_distinct_from_live_snapshots() {
        let missing = DomainId::new(u64::MAX);
        assert!(matches!(
            crate::domain::domain_security_handle(missing),
            Err(DomainSecurityLookupError::UnknownDomain(id)) if id == missing
        ));
        let owner =
            crate::domain::create_domain(alloc::string::String::from("security_lookup_owner"))
                .expect("fixture owner admission");
        let observed = crate::domain::domain_security_handle(owner).expect("live owner snapshot");
        assert_eq!(observed.caps, CapabilitySet::empty());
        crate::domain::terminate_domain(owner).expect("fixture owner retirement");
        assert!(matches!(
            crate::domain::domain_security_handle(owner),
            Err(DomainSecurityLookupError::Terminated(id)) if id == owner
        ));
        // An earlier immutable observation remains valid metadata, but does
        // not grant new execution or resource publication after retirement.
        assert_eq!(observed.caps, CapabilitySet::empty());
    }
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
    /// Most recent terminated dependency, recorded without allocating during recovery.
    pub terminated_dependency: Option<DomainId>,
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

#[cfg(all(test, any(feature = "std", target_os = "linux")))]
mod admission_tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    struct PreparedOwner {
        identity: usize,
        dropped: Arc<AtomicUsize>,
    }

    impl Drop for PreparedOwner {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn live_owner_publication_consumes_prepared_metadata_in_its_admission_scope() {
        let id = crate::domain::create_domain(alloc::string::String::from("resource_owner"))
            .expect("fixture domain admission");
        let published = crate::domain::with_resource_admission(id, 37, |admission, metadata| {
            (admission.domain(), metadata)
        });
        assert_eq!(published, Ok((id, 37)));
        crate::domain::terminate_domain(id).expect("fixture termination");
    }

    #[test]
    fn rejected_publication_returns_the_exact_owner_without_visiting_or_finalizing_it() {
        let id = crate::domain::create_domain(alloc::string::String::from("closed_resource_owner"))
            .expect("fixture domain admission");
        crate::domain::terminate_domain(id).expect("fixture termination");
        for (owner, expected) in [
            (id, DomainResourceAdmissionError::OwnerTerminated),
            (
                DomainId::new(u64::MAX),
                DomainResourceAdmissionError::UnknownOwner,
            ),
        ] {
            let dropped = Arc::new(AtomicUsize::new(0));
            let prepared = PreparedOwner {
                identity: 73,
                dropped: Arc::clone(&dropped),
            };
            let result = crate::domain::with_resource_admission(owner, prepared, |_, _| {
                panic!("a rejected owner cannot publish resource metadata")
            });
            let (cause, returned) = match result {
                Err(rejected) => rejected,
                Ok(_) => panic!("rejected publication was accepted"),
            };
            assert_eq!(cause, expected);
            assert_eq!(returned.identity, 73);
            assert_eq!(dropped.load(Ordering::Relaxed), 0);
            assert_eq!(
                crate::domain::get_domain_state(id),
                Some(DomainState::Terminated)
            );
            drop(returned);
            assert_eq!(dropped.load(Ordering::Relaxed), 1);
        }
    }
}
