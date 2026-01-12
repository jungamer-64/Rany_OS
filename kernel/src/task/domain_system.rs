// ============================================================================
// kernel/src/task/domain_system.rs
// ============================================================================
// Domain System (Task Grouping & Isolation)
// Provides unique identifiers and resource tracking for isolated domains.

use core::fmt;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

/// Unique identifier for a protection domain
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct DomainId(pub u64);

impl DomainId {
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    pub const KERNEL: DomainId = DomainId::new(0);
}

impl fmt::Display for DomainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DomainId({})", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainState {
    Initializing,
    Running,
    Stopped,
    Terminated,
}

pub struct Domain {
    pub state: DomainState,
    pub tasks: Vec<u64>,
    pub dependencies: Vec<DomainId>,
    pub dependents: Vec<DomainId>,
    pub panic_message: Option<String>,
    pub last_error: Option<String>,
    pub name: String,
}

impl Domain {
    pub fn new(name: String) -> Self {
        Self {
            state: DomainState::Initializing,
            tasks: Vec::new(),
            dependencies: Vec::new(),
            dependents: Vec::new(),
            panic_message: None,
            last_error: None,
            name,
        }
    }
    pub fn add_task(&mut self, id: u64) { self.tasks.push(id); }
    pub fn remove_task(&mut self, id: u64) { self.tasks.retain(|&x| x != id); }
    pub fn add_dependency(&mut self, id: DomainId) { if !self.dependencies.contains(&id) { self.dependencies.push(id); } }
    pub fn remove_dependency(&mut self, id: DomainId) { self.dependencies.retain(|&x| x != id); }
    pub fn add_dependent(&mut self, id: DomainId) { if !self.dependents.contains(&id) { self.dependents.push(id); } }
}

struct DomainRegistry {
    domains: BTreeMap<u64, Domain>,
    next_id: u64,
}

static REGISTRY: Mutex<DomainRegistry> = Mutex::new(DomainRegistry { domains: BTreeMap::new(), next_id: 1 });

pub fn init() {}

pub fn create_domain(name: String) -> Option<DomainId> {
    let mut reg = REGISTRY.lock();
    let id = reg.next_id;
    reg.next_id += 1;
    reg.domains.insert(id, Domain::new(name));
    Some(DomainId(id))
}

pub fn with_domain<F, R>(id: DomainId, f: F) -> Option<R> where F: FnOnce(&Domain) -> R {
    let reg = REGISTRY.lock();
    reg.domains.get(&id.0).map(f)
}

pub fn with_domain_mut<F, R>(id: DomainId, f: F) -> Option<R> where F: FnOnce(&mut Domain) -> R {
    let mut reg = REGISTRY.lock();
    reg.domains.get_mut(&id.0).map(f)
}

pub fn set_domain_state(id: DomainId, state: DomainState) {
    if let Some(d) = REGISTRY.lock().domains.get_mut(&id.0) {
        d.state = state;
    }
}

pub fn get_stats() -> DomainStats {
    let reg = REGISTRY.lock();
    let total = reg.domains.len();
    let running = reg.domains.values().filter(|d| d.state == DomainState::Running).count();
    let stopped = reg.domains.values().filter(|d| d.state == DomainState::Stopped).count();

    DomainStats {
        total_domains: total,
        active_domains: running,
        total,
        running,
        stopped,
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DomainStats {
    pub total_domains: usize,
    pub active_domains: usize,
    pub total: usize,
    pub running: usize,
    pub stopped: usize,
}

pub fn get_domain_stats() -> DomainStats {
    get_stats()
}

pub use crate::io::iommu::api::get_domain_numa;
