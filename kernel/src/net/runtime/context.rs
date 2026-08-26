// ============================================================================
// kernel/src/net/runtime/context.rs - ランタイム / context
// ============================================================================

use crate::cpu::CpuId;
use crate::net::datapath::mempool::Mempool;
use crate::net::l4::socket::SocketRegistry;
use crate::net::obs::NetObservability;
use crate::net::runtime::bridge::NetBridgeRuntimeState;
use crate::net::runtime::command::{
    CommandAdmissionState, CommandReplyRegistry, RuntimeCommandQueue,
};
use crate::net::runtime::device::{
    NetDeviceManager, TxCompletionState, TxLeaseState, TxOwnerGroupState,
};
use crate::net::runtime::icmp::IcmpRuntimeState;
use crate::net::runtime::manager::NetworkManager;
use crate::net::runtime::stack::NetworkStack;
use crate::net::runtime::transport::TransportState;
use crate::net::security::firewall::FirewallRuntimeState;
use crate::net::services::dhcp::DhcpRuntimeState;
use crate::net::services::dns::DnsRuntimeState;
use crate::net::services::http::server::HttpRuntimeState;
use crate::net::services::mdns::MdnsRuntimeState;
use crate::net::{l2::arp::ArpWaiterRegistry, l3::ndp::NdpWaiterRegistry};
use crate::sync::{PoisonLock, PoisonRwLock, WakerQueue};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct NetRuntimeId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct NetRuntimeGeneration(u32);

impl NetRuntimeGeneration {
    pub(crate) const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    pub(crate) const fn raw(self) -> u32 {
        self.0
    }

    fn next(self) -> Self {
        match self.0.checked_add(1) {
            Some(next) => Self(next),
            None => Self(1),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeAllocationError {
    IdSpaceExhausted,
    IdAlreadyAllocated,
    CpuTopologyUnavailable,
    CpuTopologyInconsistent,
    CpuResourceAllocationFailed,
    RegistryPoisoned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetCpuResourceError {
    NoCurrentCpu,
    CpuNotProvisioned(CpuId),
    RegistryPoisoned,
}

pub(crate) struct NetCpuResources {
    pub(crate) cpu_id: CpuId,
    pub(crate) stack: Arc<PoisonLock<Option<NetworkStack>>>,
    pub(crate) command_queue: Arc<RuntimeCommandQueue>,
    pub(crate) command_task_running: AtomicBool,
    pub(crate) command_task_ready_waiters: WakerQueue,
}

impl NetCpuResources {
    fn new(cpu_id: CpuId, admission: CommandAdmissionState) -> Self {
        Self {
            cpu_id,
            stack: Arc::new(PoisonLock::new(None)),
            command_queue: Arc::new(RuntimeCommandQueue::new(admission)),
            command_task_running: AtomicBool::new(false),
            command_task_ready_waiters: WakerQueue::new(),
        }
    }
}

#[derive(Clone, Copy)]
pub struct NetRuntimeHandle {
    context: &'static NetRuntimeContext,
}

impl NetRuntimeHandle {
    pub const fn new(context: &'static NetRuntimeContext) -> Self {
        Self { context }
    }

    pub const fn id(self) -> NetRuntimeId {
        self.context.id
    }

    pub(crate) const fn generation(self) -> NetRuntimeGeneration {
        self.context.generation
    }

    pub const fn context(self) -> &'static NetRuntimeContext {
        self.context
    }
}

impl core::fmt::Debug for NetRuntimeHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NetRuntimeHandle")
            .field("id", &self.id())
            .finish()
    }
}

impl PartialEq for NetRuntimeHandle {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.context, other.context)
    }
}

impl Eq for NetRuntimeHandle {}

pub struct NetRuntimeContext {
    id: NetRuntimeId,
    generation: NetRuntimeGeneration,
    cpu_resources: PoisonRwLock<Vec<Option<Arc<NetCpuResources>>>>,
    pub(crate) manager: PoisonLock<Option<NetworkManager>>,
    pub(crate) interface_topology_revision: AtomicU64,
    pub(crate) command_replies: CommandReplyRegistry,
    pub(crate) sockets: SocketRegistry,
    pub(crate) transport: TransportState,
    pub(crate) firewall: FirewallRuntimeState,
    pub(crate) icmp: IcmpRuntimeState,
    pub(crate) observability: NetObservability,
    pub(crate) arp_waiters: ArpWaiterRegistry,
    pub(crate) ndp_waiters: NdpWaiterRegistry,
    pub(crate) tx_completion_next_id: AtomicU64,
    pub(crate) tx_completions: PoisonRwLock<BTreeMap<u64, TxCompletionState>>,
    pub(crate) tx_owner_group_next_id: AtomicU64,
    pub(crate) tx_owner_groups: PoisonLock<BTreeMap<u64, TxOwnerGroupState>>,
    pub(crate) tx_lease_next_id: AtomicU64,
    pub(crate) tx_leases: PoisonLock<BTreeMap<kernel_api::netdev::TxLeaseId, TxLeaseState>>,
    pub(crate) packet_pool: Mempool,
    pub(crate) device_manager: PoisonRwLock<NetDeviceManager>,
    pub(crate) stack_initialized: AtomicBool,
    pub(crate) network_background_tasks_started: AtomicBool,
    pub(crate) bridge: NetBridgeRuntimeState,
    pub(crate) dhcp: DhcpRuntimeState,
    pub(crate) dns: DnsRuntimeState,
    pub(crate) http: HttpRuntimeState,
    pub(crate) mdns: MdnsRuntimeState,
}

impl NetRuntimeContext {
    fn new(
        id: NetRuntimeId,
        generation: NetRuntimeGeneration,
        cpu_snapshot: &crate::cpu::CpuSnapshot,
    ) -> Result<Self, RuntimeAllocationError> {
        let mut cpu_resources = Vec::new();
        cpu_resources
            .try_reserve_exact(cpu_snapshot.slots().len())
            .map_err(|_| RuntimeAllocationError::CpuResourceAllocationFailed)?;
        for slot in cpu_snapshot.slots() {
            if slot.id.as_usize() != cpu_resources.len() {
                return Err(RuntimeAllocationError::CpuTopologyInconsistent);
            }
            let admission = if slot.state.is_schedulable() {
                CommandAdmissionState::Open
            } else {
                CommandAdmissionState::Draining
            };
            cpu_resources.push(Some(Arc::new(NetCpuResources::new(slot.id, admission))));
        }
        let packet_pool = Mempool::new(id.0 as u32, cpu_snapshot)
            .map_err(|_| RuntimeAllocationError::CpuResourceAllocationFailed)?;

        Ok(Self {
            id,
            generation,
            cpu_resources: PoisonRwLock::new(cpu_resources),
            manager: PoisonLock::new(None),
            interface_topology_revision: AtomicU64::new(0),
            command_replies: CommandReplyRegistry::new(),
            sockets: SocketRegistry::new(),
            transport: TransportState::new(),
            firewall: FirewallRuntimeState::new(),
            icmp: IcmpRuntimeState::new(),
            observability: NetObservability::new(),
            arp_waiters: ArpWaiterRegistry::new(),
            ndp_waiters: NdpWaiterRegistry::new(),
            tx_completion_next_id: AtomicU64::new(1),
            tx_completions: PoisonRwLock::new(BTreeMap::new()),
            tx_owner_group_next_id: AtomicU64::new(1),
            tx_owner_groups: PoisonLock::new(BTreeMap::new()),
            tx_lease_next_id: AtomicU64::new(1),
            tx_leases: PoisonLock::new(BTreeMap::new()),
            packet_pool,
            device_manager: PoisonRwLock::new(NetDeviceManager::new()),
            stack_initialized: AtomicBool::new(false),
            network_background_tasks_started: AtomicBool::new(false),
            bridge: NetBridgeRuntimeState::new(),
            dhcp: DhcpRuntimeState::new(),
            dns: DnsRuntimeState::new(),
            http: HttpRuntimeState::new(),
            mdns: MdnsRuntimeState::new(),
        })
    }

    pub const fn id(&self) -> NetRuntimeId {
        self.id
    }

    pub(crate) const fn generation(&self) -> NetRuntimeGeneration {
        self.generation
    }

    pub const fn handle(&'static self) -> NetRuntimeHandle {
        NetRuntimeHandle::new(self)
    }

    pub(crate) fn cpu_resources(
        &self,
        cpu_id: CpuId,
    ) -> Result<Arc<NetCpuResources>, NetCpuResourceError> {
        let resources = self
            .cpu_resources
            .read()
            .map_err(|_| NetCpuResourceError::RegistryPoisoned)?;
        resources
            .get(cpu_id.as_usize())
            .and_then(Option::as_ref)
            .filter(|resources| resources.cpu_id == cpu_id)
            .cloned()
            .ok_or(NetCpuResourceError::CpuNotProvisioned(cpu_id))
    }

    pub(crate) fn current_cpu_resources(
        &self,
    ) -> Result<Arc<NetCpuResources>, NetCpuResourceError> {
        let cpu_id = crate::cpu::CurrentCpu::acquire()
            .map(|current| current.id())
            .ok_or(NetCpuResourceError::NoCurrentCpu)?;
        self.cpu_resources(cpu_id)
    }

    pub(crate) fn cpu_resources_snapshot(
        &self,
    ) -> Result<Vec<Arc<NetCpuResources>>, NetCpuResourceError> {
        let resources = self
            .cpu_resources
            .read()
            .map_err(|_| NetCpuResourceError::RegistryPoisoned)?;
        Ok(resources.iter().filter_map(Clone::clone).collect())
    }

    fn provision_possible_cpus(
        &self,
        cpu_snapshot: &crate::cpu::CpuSnapshot,
    ) -> Result<(), RuntimeAllocationError> {
        let mut resources = self
            .cpu_resources
            .write()
            .map_err(|_| RuntimeAllocationError::RegistryPoisoned)?;
        for index in 0..resources.len() {
            let Some(slot) = cpu_snapshot.slots().get(index) else {
                return Err(RuntimeAllocationError::CpuTopologyInconsistent);
            };
            if slot.id.as_usize() != index
                || resources[index]
                    .as_ref()
                    .is_none_or(|resource| resource.cpu_id != slot.id)
            {
                return Err(RuntimeAllocationError::CpuTopologyInconsistent);
            }
        }
        let current_len = resources.len();
        resources
            .try_reserve_exact(cpu_snapshot.slots().len().saturating_sub(current_len))
            .map_err(|_| RuntimeAllocationError::CpuResourceAllocationFailed)?;
        for slot in &cpu_snapshot.slots()[current_len..] {
            if slot.id.as_usize() != resources.len() {
                return Err(RuntimeAllocationError::CpuTopologyInconsistent);
            }
            resources.push(Some(Arc::new(NetCpuResources::new(
                slot.id,
                CommandAdmissionState::Draining,
            ))));
        }
        drop(resources);
        self.packet_pool
            .provision_possible_cpus(cpu_snapshot)
            .map_err(|_| RuntimeAllocationError::CpuResourceAllocationFailed)
    }
}

#[derive(Default)]
struct RuntimeRegistry {
    default: Option<NetRuntimeId>,
    next_id: Option<u64>,
    generation: NetRuntimeGeneration,
    runtimes: BTreeMap<NetRuntimeId, &'static NetRuntimeContext>,
}

impl RuntimeRegistry {
    const fn new() -> Self {
        Self {
            default: None,
            next_id: Some(0),
            generation: NetRuntimeGeneration(1),
            runtimes: BTreeMap::new(),
        }
    }

    fn allocate_runtime(
        &mut self,
        cpu_snapshot: &crate::cpu::CpuSnapshot,
    ) -> Result<&'static NetRuntimeContext, RuntimeAllocationError> {
        let raw_id = self
            .next_id
            .ok_or(RuntimeAllocationError::IdSpaceExhausted)?;
        let id = NetRuntimeId(raw_id);
        if self.runtimes.contains_key(&id) {
            return Err(RuntimeAllocationError::IdAlreadyAllocated);
        }

        let context = NetRuntimeContext::new(id, self.generation, cpu_snapshot)?;
        self.next_id = raw_id.checked_add(1);
        let context = Box::leak(Box::new(context));
        self.runtimes.insert(id, context);
        Ok(context)
    }

    fn default_runtime(
        &mut self,
        cpu_snapshot: &crate::cpu::CpuSnapshot,
    ) -> &'static NetRuntimeContext {
        if let Some(id) = self.default {
            if let Some(context) = self.runtimes.get(&id).copied() {
                return context;
            }
        }

        let context = self
            .allocate_runtime(cpu_snapshot)
            .expect("network runtime id space exhausted");
        self.default = Some(context.id());
        context
    }
}

static RUNTIME_REGISTRY: PoisonLock<RuntimeRegistry> = PoisonLock::new(RuntimeRegistry::new());

pub fn default_runtime() -> NetRuntimeHandle {
    let mut registry = RUNTIME_REGISTRY.lock_for_init("[NET] runtime registry init");
    let cpu_snapshot = crate::cpu::try_runtime()
        .expect("CPU runtime must be installed before the network runtime")
        .snapshot();
    registry.default_runtime(&cpu_snapshot).handle()
}

pub fn default_runtime_context() -> &'static NetRuntimeContext {
    default_runtime().context()
}

pub fn create_runtime() -> Result<NetRuntimeHandle, RuntimeAllocationError> {
    let mut registry = RUNTIME_REGISTRY.lock_for_init("[NET] runtime registry create");
    let cpu_snapshot = crate::cpu::try_runtime()
        .ok_or(RuntimeAllocationError::CpuTopologyUnavailable)?
        .snapshot();
    registry
        .allocate_runtime(&cpu_snapshot)
        .map(NetRuntimeContext::handle)
}

pub fn runtime(id: NetRuntimeId) -> Option<NetRuntimeHandle> {
    let registry = RUNTIME_REGISTRY.lock().ok()?;
    registry
        .runtimes
        .get(&id)
        .copied()
        .map(NetRuntimeContext::handle)
}

pub(crate) fn runtime_with_generation(
    id: NetRuntimeId,
    generation: NetRuntimeGeneration,
) -> Option<NetRuntimeHandle> {
    let registry = RUNTIME_REGISTRY.lock().ok()?;
    let context = registry.runtimes.get(&id).copied()?;
    (context.generation() == generation).then(|| context.handle())
}

pub fn list_runtimes() -> alloc::vec::Vec<NetRuntimeHandle> {
    let registry = match RUNTIME_REGISTRY.lock() {
        Ok(registry) => registry,
        Err(poisoned) => poisoned.into_inner(),
    };
    registry
        .runtimes
        .values()
        .copied()
        .map(NetRuntimeContext::handle)
        .collect()
}

pub(crate) fn provision_possible_cpus(
    cpu_snapshot: &crate::cpu::CpuSnapshot,
) -> Result<(), RuntimeAllocationError> {
    let registry = RUNTIME_REGISTRY
        .lock()
        .map_err(|_| RuntimeAllocationError::RegistryPoisoned)?;
    for runtime in registry.runtimes.values().copied() {
        runtime.provision_possible_cpus(cpu_snapshot)?;
    }
    Ok(())
}

pub(crate) fn begin_cpu_drain(cpu_id: CpuId) {
    for runtime in list_runtimes() {
        let resources = runtime
            .context()
            .cpu_resources(cpu_id)
            .unwrap_or_else(|error| {
                panic!(
                    "network runtime {} cannot close CPU {} command admission: {:?}",
                    runtime.id().0,
                    cpu_id,
                    error
                )
            });
        resources.command_queue.begin_drain();
    }
}

pub(crate) fn cpu_drain_blockers(cpu_id: CpuId) -> Arc<[crate::cpu::CpuBlocker]> {
    list_runtimes()
        .into_iter()
        .filter_map(|runtime| {
            let resources = runtime
                .context()
                .cpu_resources(cpu_id)
                .unwrap_or_else(|error| {
                    panic!(
                        "network runtime {} lost CPU {} resources during drain: {:?}",
                        runtime.id().0,
                        cpu_id,
                        error
                    )
                });
            (!resources.command_queue.is_quiescent()).then_some(
                crate::cpu::CpuBlocker::NetworkQueue {
                    runtime_id: runtime.id().0,
                },
            )
        })
        .collect::<Vec<_>>()
        .into()
}

pub(crate) fn publish_cpu_online(cpu_id: CpuId) {
    for runtime in list_runtimes() {
        let resources = runtime
            .context()
            .cpu_resources(cpu_id)
            .unwrap_or_else(|error| {
                panic!(
                    "network runtime {} cannot publish CPU {} command admission: {:?}",
                    runtime.id().0,
                    cpu_id,
                    error
                )
            });
        resources.command_queue.publish_online();
    }
}

pub fn set_default_runtime(handle: NetRuntimeHandle) {
    if let Ok(mut registry) = RUNTIME_REGISTRY.lock() {
        registry.default = Some(handle.id());
    }
}

#[cfg(test)]
pub fn reset_runtime_registry_for_tests() {
    if let Ok(mut registry) = RUNTIME_REGISTRY.lock() {
        registry.default = None;
        registry.next_id = Some(0);
        registry.generation = registry.generation.next();
        registry.runtimes.clear();
    }
}

pub fn stack_initialized(handle: NetRuntimeHandle) -> bool {
    handle.context().stack_initialized.load(Ordering::Acquire)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::runtime::command::RuntimeCommand;
    use crate::net::runtime::manager;

    fn cpu_snapshot() -> alloc::sync::Arc<crate::cpu::CpuSnapshot> {
        crate::cpu::CpuRuntime::bootstrap(crate::cpu::ApicId::new(0), None)
            .expect("bootstrap CPU topology")
            .snapshot()
    }

    fn firmware_cpu(uid: u64, apic_id: u32) -> crate::cpu::FirmwareCpuIdentity {
        crate::cpu::FirmwareCpuIdentity {
            uid: Some(crate::cpu::FirmwareCpuUid::Integer(uid)),
            apic_id: crate::cpu::ApicId::new(apic_id),
            proximity_domain: Some(0),
            eject: crate::cpu::CpuEjectCapability::FirmwareEject,
        }
    }

    #[test]
    fn runtime_provisions_closed_resources_for_new_possible_cpu() {
        let cpu_runtime = crate::cpu::CpuRuntime::bootstrap(crate::cpu::ApicId::new(0), None)
            .expect("bootstrap CPU topology");
        let context = NetRuntimeContext::new(
            NetRuntimeId(7),
            NetRuntimeGeneration::from_raw(1),
            &cpu_runtime.snapshot(),
        )
        .expect("network runtime allocation");
        let cpu_id = cpu_runtime
            .discover_possible(firmware_cpu(1, 1))
            .expect("possible CPU discovery");

        assert!(matches!(
            context.cpu_resources(cpu_id),
            Err(NetCpuResourceError::CpuNotProvisioned(id)) if id == cpu_id
        ));
        context
            .provision_possible_cpus(&cpu_runtime.snapshot())
            .expect("dynamic network CPU provisioning");
        let resources = context.cpu_resources(cpu_id).expect("new CPU resources");
        assert!(!resources.command_queue.is_accepting());
    }

    #[test]
    fn runtimes_keep_manager_and_event_state_isolated() {
        let cpu_snapshot = cpu_snapshot();
        let mut registry = RuntimeRegistry::new();
        let runtime_a = registry
            .allocate_runtime(&cpu_snapshot)
            .expect("first runtime allocation")
            .handle();
        let runtime_b = registry
            .allocate_runtime(&cpu_snapshot)
            .expect("second runtime allocation")
            .handle();

        assert_ne!(runtime_a.id(), runtime_b.id());
        assert_eq!(registry.runtimes.len(), 2);

        manager::init_network_manager_in(runtime_a);
        assert!(manager::list_interfaces_in(runtime_a).is_ok());
        assert!(manager::list_interfaces_in(runtime_b).is_err());

        let resources_a = runtime_a
            .context()
            .cpu_resources(CpuId::BOOTSTRAP)
            .expect("runtime A bootstrap resources");
        let resources_b = runtime_b
            .context()
            .cpu_resources(CpuId::BOOTSTRAP)
            .expect("runtime B bootstrap resources");
        assert!(resources_a.command_queue.send(RuntimeCommand::Transport(
            crate::net::runtime::command::TransportCommand::TxAvailable
        )));
        assert!(resources_a.command_queue.recv().is_some());
        assert!(resources_b.command_queue.recv().is_none());
    }

    #[test]
    fn background_service_task_claims_are_runtime_local() {
        let cpu_snapshot = cpu_snapshot();
        let mut registry = RuntimeRegistry::new();
        let runtime_a = registry
            .allocate_runtime(&cpu_snapshot)
            .expect("first runtime allocation")
            .handle();
        let runtime_b = registry
            .allocate_runtime(&cpu_snapshot)
            .expect("second runtime allocation")
            .handle();

        assert!(
            !runtime_a
                .context()
                .network_background_tasks_started
                .swap(true, Ordering::AcqRel)
        );
        assert!(
            !runtime_b
                .context()
                .network_background_tasks_started
                .load(Ordering::Acquire)
        );
        assert!(
            runtime_a
                .context()
                .network_background_tasks_started
                .load(Ordering::Acquire)
        );
    }

    #[test]
    fn runtime_ids_do_not_wrap_after_exhaustion() {
        let cpu_snapshot = cpu_snapshot();
        let mut registry = RuntimeRegistry::new();
        registry.next_id = Some(u64::MAX);

        let runtime = registry
            .allocate_runtime(&cpu_snapshot)
            .expect("last representable runtime id");
        assert_eq!(runtime.id(), NetRuntimeId(u64::MAX));
        assert!(matches!(
            registry.allocate_runtime(&cpu_snapshot),
            Err(RuntimeAllocationError::IdSpaceExhausted)
        ));
        assert_eq!(registry.runtimes.len(), 1);
    }

    #[test]
    fn runtime_registry_rejects_id_reuse() {
        let cpu_snapshot = cpu_snapshot();
        let mut registry = RuntimeRegistry::new();
        let runtime = registry
            .allocate_runtime(&cpu_snapshot)
            .expect("first runtime");
        assert_eq!(runtime.id(), NetRuntimeId(0));

        registry.next_id = Some(0);
        assert!(matches!(
            registry.allocate_runtime(&cpu_snapshot),
            Err(RuntimeAllocationError::IdAlreadyAllocated)
        ));
        assert_eq!(registry.runtimes.len(), 1);
    }

    #[test]
    fn runtime_generation_changes_when_registry_epoch_advances() {
        let cpu_snapshot = cpu_snapshot();
        let mut registry = RuntimeRegistry::new();
        let old = registry
            .allocate_runtime(&cpu_snapshot)
            .expect("old runtime")
            .handle();
        let old_id = old.id();
        let old_generation = old.generation();

        registry.next_id = Some(0);
        registry.generation = registry.generation.next();
        registry.runtimes.clear();
        let new = registry
            .allocate_runtime(&cpu_snapshot)
            .expect("new runtime")
            .handle();

        assert_eq!(old_id, new.id());
        assert_ne!(old_generation, new.generation());
        assert!(
            registry
                .runtimes
                .get(&new.id())
                .is_some_and(|context| core::ptr::eq(*context, new.context()))
        );
    }
}
