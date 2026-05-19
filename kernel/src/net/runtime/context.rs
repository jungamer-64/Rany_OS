// ============================================================================
// kernel/src/net/runtime/context.rs - ランタイム / context
// ============================================================================

use crate::net::datapath::mempool::Mempool;
use crate::net::l4::socket::SocketRegistry;
use crate::net::obs::NetObservability;
use crate::net::runtime::bridge::NetBridgeRuntimeState;
use crate::net::runtime::command::{CommandReplyRegistry, RuntimeCommandQueue};
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
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct NetRuntimeId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeAllocationError {
    IdSpaceExhausted,
    IdAlreadyAllocated,
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
    pub(crate) stack: PoisonLock<Option<NetworkStack>>,
    pub(crate) manager: PoisonLock<Option<NetworkManager>>,
    pub(crate) command_queue: RuntimeCommandQueue,
    pub(crate) command_replies: CommandReplyRegistry,
    pub(crate) command_task_running: AtomicBool,
    pub(crate) command_task_ready_waiters: WakerQueue,
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
    pub(crate) tx_leases: PoisonLock<BTreeMap<u64, TxLeaseState>>,
    pub(crate) packet_pool: spin::Once<Mempool>,
    pub(crate) device_manager: PoisonRwLock<NetDeviceManager>,
    pub(crate) stack_initialized: AtomicBool,
    pub(crate) dhcp_bound_primary_selected: AtomicBool,
    pub(crate) network_background_tasks_started: AtomicBool,
    pub(crate) bridge: NetBridgeRuntimeState,
    pub(crate) dhcp: DhcpRuntimeState,
    pub(crate) dns: DnsRuntimeState,
    pub(crate) http: HttpRuntimeState,
    pub(crate) mdns: MdnsRuntimeState,
}

impl NetRuntimeContext {
    fn new(id: NetRuntimeId) -> Self {
        Self {
            id,
            stack: PoisonLock::new(None),
            manager: PoisonLock::new(None),
            command_queue: RuntimeCommandQueue::new(),
            command_replies: CommandReplyRegistry::new(),
            command_task_running: AtomicBool::new(false),
            command_task_ready_waiters: WakerQueue::new(),
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
            packet_pool: spin::Once::new(),
            device_manager: PoisonRwLock::new(NetDeviceManager::new()),
            stack_initialized: AtomicBool::new(false),
            dhcp_bound_primary_selected: AtomicBool::new(false),
            network_background_tasks_started: AtomicBool::new(false),
            bridge: NetBridgeRuntimeState::new(),
            dhcp: DhcpRuntimeState::new(),
            dns: DnsRuntimeState::new(),
            http: HttpRuntimeState::new(),
            mdns: MdnsRuntimeState::new(),
        }
    }

    pub const fn id(&self) -> NetRuntimeId {
        self.id
    }

    pub const fn handle(&'static self) -> NetRuntimeHandle {
        NetRuntimeHandle::new(self)
    }
}

#[derive(Default)]
struct RuntimeRegistry {
    default: Option<NetRuntimeId>,
    next_id: Option<u64>,
    runtimes: BTreeMap<NetRuntimeId, &'static NetRuntimeContext>,
}

impl RuntimeRegistry {
    const fn new() -> Self {
        Self {
            default: None,
            next_id: Some(0),
            runtimes: BTreeMap::new(),
        }
    }

    fn allocate_runtime(&mut self) -> Result<&'static NetRuntimeContext, RuntimeAllocationError> {
        let raw_id = self
            .next_id
            .ok_or(RuntimeAllocationError::IdSpaceExhausted)?;
        let id = NetRuntimeId(raw_id);
        if self.runtimes.contains_key(&id) {
            return Err(RuntimeAllocationError::IdAlreadyAllocated);
        }

        self.next_id = raw_id.checked_add(1);
        let context = Box::leak(Box::new(NetRuntimeContext::new(id)));
        self.runtimes.insert(id, context);
        Ok(context)
    }

    fn default_runtime(&mut self) -> &'static NetRuntimeContext {
        if let Some(id) = self.default {
            if let Some(context) = self.runtimes.get(&id).copied() {
                return context;
            }
        }

        let context = self
            .allocate_runtime()
            .expect("network runtime id space exhausted");
        self.default = Some(context.id());
        context
    }
}

static RUNTIME_REGISTRY: PoisonLock<RuntimeRegistry> = PoisonLock::new(RuntimeRegistry::new());

pub fn default_runtime() -> NetRuntimeHandle {
    let mut registry = RUNTIME_REGISTRY.lock_for_init("[NET] runtime registry init");
    registry.default_runtime().handle()
}

pub fn default_runtime_context() -> &'static NetRuntimeContext {
    default_runtime().context()
}

pub fn create_runtime() -> Result<NetRuntimeHandle, RuntimeAllocationError> {
    let mut registry = RUNTIME_REGISTRY.lock_for_init("[NET] runtime registry create");
    registry.allocate_runtime().map(NetRuntimeContext::handle)
}

pub fn runtime(id: NetRuntimeId) -> Option<NetRuntimeHandle> {
    let registry = RUNTIME_REGISTRY.lock().ok()?;
    registry
        .runtimes
        .get(&id)
        .copied()
        .map(NetRuntimeContext::handle)
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

    #[test]
    fn runtimes_keep_manager_and_event_state_isolated() {
        reset_runtime_registry_for_tests();

        let runtime_a = default_runtime();
        let runtime_b = create_runtime().expect("second runtime allocation");

        assert_ne!(runtime_a.id(), runtime_b.id());
        assert_eq!(list_runtimes().len(), 2);

        runtime_a.context().command_queue.reset_for_tests();
        runtime_b.context().command_queue.reset_for_tests();

        manager::init_network_manager_in(runtime_a);
        assert!(manager::list_interfaces_in(runtime_a).is_ok());
        assert!(manager::list_interfaces_in(runtime_b).is_err());

        assert!(
            runtime_a
                .context()
                .command_queue
                .send(RuntimeCommand::Transport(
                    crate::net::runtime::command::TransportCommand::TxAvailable
                ))
        );
        assert!(runtime_a.context().command_queue.has_events());
        assert!(runtime_b.context().command_queue.is_empty());
    }

    #[test]
    fn background_service_task_claims_are_runtime_local() {
        reset_runtime_registry_for_tests();

        let runtime_a = default_runtime();
        let runtime_b = create_runtime().expect("second runtime allocation");

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
        let mut registry = RuntimeRegistry::new();
        registry.next_id = Some(u64::MAX);

        let runtime = registry
            .allocate_runtime()
            .expect("last representable runtime id");
        assert_eq!(runtime.id(), NetRuntimeId(u64::MAX));
        assert!(matches!(
            registry.allocate_runtime(),
            Err(RuntimeAllocationError::IdSpaceExhausted)
        ));
        assert_eq!(registry.runtimes.len(), 1);
    }

    #[test]
    fn runtime_registry_rejects_id_reuse() {
        let mut registry = RuntimeRegistry::new();
        let runtime = registry.allocate_runtime().expect("first runtime");
        assert_eq!(runtime.id(), NetRuntimeId(0));

        registry.next_id = Some(0);
        assert!(matches!(
            registry.allocate_runtime(),
            Err(RuntimeAllocationError::IdAlreadyAllocated)
        ));
        assert_eq!(registry.runtimes.len(), 1);
    }
}
