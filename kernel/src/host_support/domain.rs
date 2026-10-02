use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Mutex, Once};

pub use crate::security::CapabilitySet;
#[path = "../domain/identity.rs"]
mod identity;
pub use identity::DomainId;

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
pub use policy::DomainPolicyError;

pub use quota::{DomainPriority, DomainQuota, QuotaError, quota_manager};

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
        matches!(self, DomainState::Initializing | DomainState::Running)
    }
}

impl Default for DomainState {
    fn default() -> Self {
        Self::Initializing
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainCredentials {
    pub uid: u32,
    pub gid: u32,
}

impl DomainCredentials {
    pub const ROOT: Self = Self { uid: 0, gid: 0 };
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

#[derive(Debug, Clone, Copy)]
pub struct RequestedCap {
    pub cap: u64,
    pub expires: Option<u64>,
    pub delegatable: bool,
}

#[derive(Debug, Clone)]
pub struct DomainSnapshot {
    pub id: DomainId,
    pub name: String,
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
    pub panic_message: Option<String>,
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
    pub tasks: Vec<u64>,
    pub dependencies: Vec<DomainId>,
    pub dependents: Vec<DomainId>,
}

static DOMAINS: Mutex<Vec<DomainRecord>> = Mutex::new(Vec::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn kernel_security_handle() -> Arc<DomainSecurity> {
    static SECURITY: Once<Arc<DomainSecurity>> = Once::new();
    SECURITY
        .call_once(|| Arc::new(DomainSecurity::kernel()))
        .clone()
}

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
        last_error: domain.last_error.clone(),
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
        last_error: None,
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
        last_error: None,
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

pub fn domain_security_handle(id: DomainId) -> Arc<DomainSecurity> {
    with_domain(id, |domain| domain.security.clone()).unwrap_or_else(kernel_security_handle)
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
    with_domain_mut(id, |domain| {
        if state == DomainState::Terminated {
            quota_manager().unregister(id);
        } else {
            quota_manager()
                .update_policy(host_quota(
                    domain,
                    domain.priority,
                    domain.cpu_limit_percent,
                    domain.memory_limit_bytes,
                    domain.io_bandwidth_limit,
                ))
                .map_err(DomainPolicyError::Quota)?;
        }
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
