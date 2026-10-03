use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

pub use crate::security::CapabilitySet;
#[path = "../domain/types.rs"]
pub mod types;
pub use types::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainErrorKind {
    OwnershipViolation,
    LifecycleError,
    RegistryPoisoned,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelError {
    Domain(DomainErrorKind),
}

#[path = "../domain/policy.rs"]
pub mod policy;
#[path = "../domain/quota.rs"]
pub mod quota;
pub use policy::{DomainPolicyError, DomainTerminationError};

pub use quota::{DomainPriority, DomainQuota, QuotaError, quota_manager};

#[derive(Debug, Clone)]
pub struct DomainRecord {
    pub id: DomainId,
    pub name: String,
    pub state: DomainState,
    pub priority: DomainPriority,
    pub cpu_limit_percent: u64,
    pub memory_limit_bytes: u64,
    pub io_bandwidth_limit: u64,
    pub numa_node: Option<usize>,
    pub security: Arc<DomainSecurity>,
    pub panic_message: Option<String>,
    /// Most recent terminated dependency, recorded without allocating during recovery.
    pub terminated_dependency: Option<DomainId>,
    pub tasks: Vec<u64>,
    pub dependencies: Vec<DomainId>,
    pub dependents: Vec<DomainId>,
}

static DOMAINS: Mutex<Vec<DomainRecord>> = Mutex::new(Vec::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn to_snapshot(domain: &DomainRecord) -> DomainSnapshot {
    DomainSnapshot {
        id: domain.id,
        name: domain.name.clone(),
        state: domain.state,
        tasks: domain.tasks.len(),
        task_ids: domain.tasks.clone(),
        memory_bytes: 0,
        rrefs: 0,
        runtime_ticks: 0,
        context_switches: 0,
        created_at: 0,
        dependencies: domain.dependencies.clone(),
        dependents: domain.dependents.clone(),
        numa_node: domain.numa_node,
        priority: domain.priority,
        cpu_limit_percent: domain.cpu_limit_percent,
        memory_limit_bytes: domain.memory_limit_bytes,
        io_bandwidth_limit: domain.io_bandwidth_limit,
        panic_message: domain.panic_message.clone(),
        terminated_dependency: domain.terminated_dependency,
    }
}

pub fn init() {
    let mut domains = DOMAINS.lock();
    if domains.iter().any(|domain| domain.id == DomainId::KERNEL) {
        return;
    }
    quota_manager()
        .register(DomainQuota::kernel())
        .expect("host kernel quota metadata");
    domains.push(DomainRecord {
        id: DomainId::KERNEL,
        name: String::from("kernel"),
        state: DomainState::Running,
        priority: DomainPriority::Critical,
        cpu_limit_percent: 100,
        memory_limit_bytes: u64::MAX,
        io_bandwidth_limit: 0,
        numa_node: None,
        security: kernel_security_handle(),
        panic_message: None,
        terminated_dependency: None,
        tasks: Vec::new(),
        dependencies: Vec::new(),
        dependents: Vec::new(),
    });
}

pub fn create_domain(name: String) -> Result<DomainId, KernelError> {
    init();
    let id = DomainId::new(NEXT_ID.fetch_add(1, Ordering::Relaxed));
    quota_manager()
        .register(DomainQuota::new(id, DomainPriority::Normal).with_memory_limit_bytes(u64::MAX))
        .map_err(|_| KernelError::Domain(DomainErrorKind::LifecycleError))?;
    DOMAINS.lock().push(DomainRecord {
        id,
        name,
        state: DomainState::Initializing,
        priority: DomainPriority::Normal,
        cpu_limit_percent: 100,
        memory_limit_bytes: u64::MAX,
        io_bandwidth_limit: 0,
        numa_node: None,
        security: Arc::new(DomainSecurity::default()),
        panic_message: None,
        terminated_dependency: None,
        tasks: Vec::new(),
        dependencies: Vec::new(),
        dependents: Vec::new(),
    });
    Ok(id)
}

pub fn spawn_domain_with_caps(
    name: String,
    _requested: &[RequestedCap],
) -> Result<(DomainId, Vec<u64>), KernelError> {
    let id = create_domain(name)?;
    set_domain_state(id, DomainState::Running)
        .map_err(|_| KernelError::Domain(DomainErrorKind::LifecycleError))?;
    Ok((id, Vec::new()))
}

pub fn with_domain<F, R>(id: DomainId, f: F) -> Option<R>
where
    F: FnOnce(&DomainRecord) -> R,
{
    DOMAINS.lock().iter().find(|domain| domain.id == id).map(f)
}

pub fn with_domain_mut<F, R>(id: DomainId, f: F) -> Option<R>
where
    F: FnOnce(&mut DomainRecord) -> R,
{
    DOMAINS
        .lock()
        .iter_mut()
        .find(|domain| domain.id == id)
        .map(f)
}

/// Host lookup observes the same live-owner contract as native security admission.
pub fn domain_security_handle(
    id: DomainId,
) -> Result<Arc<DomainSecurity>, DomainSecurityLookupError> {
    let domains = DOMAINS.lock();
    let domain = domains
        .iter()
        .find(|domain| domain.id == id)
        .ok_or(DomainSecurityLookupError::UnknownDomain(id))?;
    if !domain.state.is_active() {
        return Err(DomainSecurityLookupError::Terminated(id));
    }
    Ok(Arc::clone(&domain.security))
}

/// Only prepared, allocation-free resource publication may run in this scope.
/// Rejection returns the prepared owner unchanged after releasing the registry.
pub(crate) fn with_resource_admission<T, R>(
    owner: DomainId,
    prepared: T,
    publish: impl FnOnce(DomainResourceAdmission<'_>, T) -> R,
) -> Result<R, (DomainResourceAdmissionError, T)> {
    let domains = DOMAINS.lock();
    let admission = domains
        .iter()
        .find(|domain| domain.id == owner)
        .ok_or(DomainResourceAdmissionError::UnknownOwner)
        .and_then(|domain| DomainResourceAdmission::checked(&domain.id, &domain.state));
    match admission {
        Ok(admission) => Ok(publish(admission, prepared)),
        Err(cause) => {
            drop(domains);
            Err((cause, prepared))
        }
    }
}

pub fn get_domain_state(id: DomainId) -> Option<DomainState> {
    with_domain(id, |domain| domain.state)
}

pub fn list_domain_snapshots() -> Vec<DomainSnapshot> {
    DOMAINS.lock().iter().map(to_snapshot).collect()
}

pub fn get_domain_snapshot(id: DomainId) -> Option<DomainSnapshot> {
    with_domain(id, to_snapshot)
}

pub fn set_domain_state(id: DomainId, state: DomainState) -> Result<(), DomainPolicyError> {
    if state == DomainState::Terminated {
        return terminate_domain(id).map_err(DomainPolicyError::Termination);
    }
    with_domain_mut(id, |domain| {
        quota_manager()
            .update_policy(host_quota(
                domain,
                domain.priority,
                domain.cpu_limit_percent,
                domain.memory_limit_bytes,
                domain.io_bandwidth_limit,
            ))
            .map_err(DomainPolicyError::Quota)?;
        domain.state = state;
        Ok(())
    })
    .ok_or(DomainPolicyError::NotFound)?
}

pub fn start_domain(id: DomainId) -> Result<(), &'static str> {
    set_domain_state(id, DomainState::Running).map_err(|_| "Domain state admission failed")
}

pub fn stop_domain(id: DomainId) -> Result<(), &'static str> {
    set_domain_state(id, DomainState::Stopped).map_err(|_| "Domain state admission failed")
}

pub fn resume_domain(id: DomainId) -> Result<(), &'static str> {
    set_domain_state(id, DomainState::Running).map_err(|_| "Domain state admission failed")
}

pub fn terminate_domain(id: DomainId) -> Result<(), DomainTerminationError> {
    if id == DomainId::KERNEL {
        return Err(DomainTerminationError::KernelProtected);
    }
    let admission = {
        let mut domains = DOMAINS.lock();
        let index = domains
            .iter()
            .position(|domain| domain.id == id)
            .ok_or(DomainTerminationError::NotFound)?;
        let (before, rest) = domains.split_at_mut(index);
        let (domain, after) = rest.split_first_mut().expect("existing domain index");
        if domain.state == DomainState::Terminated {
            return Ok(());
        }
        let admission = quota_manager()
            .bind_memory(id)
            .map_err(DomainTerminationError::Quota)?;
        quota_manager().unregister(id);
        domain.state = DomainState::Terminated;
        if domain.dependents.contains(&id) {
            domain.terminated_dependency = Some(id);
        }
        for dependent in before.iter_mut().chain(after.iter_mut()) {
            if domain.dependents.contains(&dependent.id) {
                dependent.terminated_dependency = Some(id);
            }
        }
        admission
    };
    reclaim_domain_resources(id);
    drop(admission);
    Ok(())
}

pub fn handle_domain_panic(id: DomainId, message: String) {
    let _ = with_domain_mut(id, |domain| {
        domain.state = DomainState::Stopped;
        domain.panic_message = Some(message);
    });
}

pub fn set_domain_numa(id: DomainId, node: usize) {
    let _ = with_domain_mut(id, |domain| domain.numa_node = Some(node));
}

pub fn get_domain_numa(id: DomainId) -> Option<usize> {
    with_domain(id, |domain| domain.numa_node).flatten()
}

pub fn set_domain_capabilities(id: DomainId, caps: CapabilitySet) -> Result<(), DomainPolicyError> {
    let observed =
        with_domain(id, |domain| domain.security.clone()).ok_or(DomainPolicyError::NotFound)?;
    let replacement = Arc::try_new(DomainSecurity {
        credentials: observed.credentials,
        caps,
    })
    .map_err(|_| DomainPolicyError::MetadataAllocationFailed)?;
    let retired = {
        let mut domains = DOMAINS.lock();
        let domain = domains
            .iter_mut()
            .find(|domain| domain.id == id)
            .ok_or(DomainPolicyError::NotFound)?;
        if !Arc::ptr_eq(&domain.security, &observed) {
            return Err(DomainPolicyError::SecurityChanged);
        }
        core::mem::replace(&mut domain.security, replacement)
    };
    drop(retired);
    Ok(())
}

pub fn set_domain_priority(
    id: DomainId,
    priority: DomainPriority,
) -> Result<(), DomainPolicyError> {
    with_domain_mut(id, |domain| {
        let quota = host_quota(
            domain,
            priority,
            domain.cpu_limit_percent,
            domain.memory_limit_bytes,
            domain.io_bandwidth_limit,
        );
        quota_manager()
            .update_policy(quota)
            .map_err(DomainPolicyError::Quota)?;
        domain.priority = priority;
        Ok(())
    })
    .ok_or(DomainPolicyError::NotFound)?
}

fn host_quota(
    domain: &DomainRecord,
    priority: DomainPriority,
    cpu: u64,
    memory: u64,
    io: u64,
) -> DomainQuota {
    if domain.id == DomainId::KERNEL {
        return DomainQuota::kernel();
    }
    let mut quota = DomainQuota::new(domain.id, priority).with_cpu_limit(cpu.min(100), 100);
    quota.memory = quota::MemoryQuota::from_bytes(if memory == 0 { u64::MAX } else { memory });
    if io == 0 || io == u64::MAX {
        quota.network_io = quota::IoQuota::unlimited();
        quota.storage_io = quota::IoQuota::unlimited();
    } else {
        let rate = io.div_ceil(1024 * 1024);
        quota.network_io = quota::IoQuota::new(rate, rate);
        quota.storage_io = quota::IoQuota::new(rate, rate);
    }
    quota
}

pub fn set_domain_resource_limits(
    id: DomainId,
    cpu_limit_percent: u64,
    memory_limit_bytes: u64,
    io_bandwidth_limit: u64,
) -> Result<(), DomainPolicyError> {
    with_domain_mut(id, |domain| {
        let quota = host_quota(
            domain,
            domain.priority,
            cpu_limit_percent,
            memory_limit_bytes,
            io_bandwidth_limit,
        );
        quota_manager()
            .update_policy(quota)
            .map_err(DomainPolicyError::Quota)?;
        domain.cpu_limit_percent = cpu_limit_percent;
        domain.memory_limit_bytes = memory_limit_bytes;
        domain.io_bandwidth_limit = io_bandwidth_limit;
        Ok(())
    })
    .ok_or(DomainPolicyError::NotFound)?
}

pub fn report_cpu_quota_exceeded(_id: DomainId, _now_ns: u64) -> CpuQuotaAction {
    CpuQuotaAction::None
}

pub fn report_cpu_quota_ok(_id: DomainId) {}

pub fn quota_suspend_deadline_ns(_id: DomainId) -> Option<u64> {
    None
}

pub fn is_domain_runnable_now(id: DomainId, _now_ns: u64) -> bool {
    get_domain_state(id)
        .map(|state| state.is_runnable())
        .unwrap_or(false)
}

pub fn add_task_to_domain(domain_id: DomainId, task_id: u64) {
    let _ = with_domain_mut(domain_id, |domain| {
        if !domain.tasks.contains(&task_id) {
            domain.tasks.push(task_id);
        }
    });
}

pub fn remove_task_from_domain(domain_id: DomainId, task_id: u64) {
    let _ = with_domain_mut(domain_id, |domain| domain.tasks.retain(|id| *id != task_id));
}

pub fn register_heap_object(_ptr: usize, _layout: core::alloc::Layout, _owner: DomainId) {}
pub fn unregister_heap_object(_ptr: usize) {}
pub fn transfer_ownership(_ptr: usize, _new_owner: DomainId) -> bool {
    true
}
pub fn reclaim_domain_resources(_domain: DomainId) {}

pub fn get_domain_stats() -> DomainStats {
    let domains = DOMAINS.lock();
    let mut stats = DomainStats {
        total: domains.len(),
        ..DomainStats::default()
    };
    for domain in domains.iter() {
        match domain.state {
            DomainState::Initializing | DomainState::Running => stats.running += 1,
            DomainState::Suspended | DomainState::Stopped => stats.stopped += 1,
            DomainState::Terminated => stats.terminated += 1,
        }
    }
    stats
}

pub fn get_stats() -> DomainStats {
    get_domain_stats()
}

pub fn print_domain_list() {}
