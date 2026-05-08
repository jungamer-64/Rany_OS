// ============================================================================
// kernel/src/net/runtime/context.rs - ランタイム / context
// ============================================================================

use crate::net::runtime::bridge::NetBridgeRuntimeState;
use crate::net::runtime::command::{CommandReplyRegistry, RuntimeCommandQueue};
use crate::net::runtime::device::{NetDeviceManager, TxCompletionState, TxLeaseState};
use crate::net::runtime::manager::NetworkManager;
use crate::net::runtime::stack::NetworkStack;
use crate::net::services::dhcp::DhcpRuntimeState;
use crate::net::services::dns::DnsRuntimeState;
use crate::net::services::mdns::MdnsRuntimeState;
use crate::sync::{PoisonLock, PoisonRwLock, WakerQueue};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct NetRuntimeId(pub u16);

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
    pub(crate) tx_completion_next_id: AtomicU64,
    pub(crate) tx_completions: PoisonRwLock<BTreeMap<u64, TxCompletionState>>,
    pub(crate) tx_lease_next_id: AtomicU64,
    pub(crate) tx_leases: PoisonLock<BTreeMap<u64, TxLeaseState>>,
    pub(crate) device_manager: PoisonRwLock<NetDeviceManager>,
    pub(crate) stack_initialized: AtomicBool,
    pub(crate) dhcp_bound_primary_selected: AtomicBool,
    pub(crate) bridge: NetBridgeRuntimeState,
    pub(crate) dhcp: DhcpRuntimeState,
    pub(crate) dns: DnsRuntimeState,
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
            tx_completion_next_id: AtomicU64::new(1),
            tx_completions: PoisonRwLock::new(BTreeMap::new()),
            tx_lease_next_id: AtomicU64::new(1),
            tx_leases: PoisonLock::new(BTreeMap::new()),
            device_manager: PoisonRwLock::new(NetDeviceManager::new()),
            stack_initialized: AtomicBool::new(false),
            dhcp_bound_primary_selected: AtomicBool::new(false),
            bridge: NetBridgeRuntimeState::new(),
            dhcp: DhcpRuntimeState::new(),
            dns: DnsRuntimeState::new(),
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
    next_id: u16,
    runtimes: BTreeMap<NetRuntimeId, &'static NetRuntimeContext>,
}

impl RuntimeRegistry {
    const fn new() -> Self {
        Self {
            default: None,
            next_id: 0,
            runtimes: BTreeMap::new(),
        }
    }

    fn allocate_runtime(&mut self) -> &'static NetRuntimeContext {
        let id = NetRuntimeId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);
        let context = Box::leak(Box::new(NetRuntimeContext::new(id)));
        self.runtimes.insert(id, context);
        context
    }

    fn default_runtime(&mut self) -> &'static NetRuntimeContext {
        if let Some(id) = self.default {
            if let Some(context) = self.runtimes.get(&id).copied() {
                return context;
            }
        }

        let context = self.allocate_runtime();
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

pub fn create_runtime() -> NetRuntimeHandle {
    let mut registry = RUNTIME_REGISTRY.lock_for_init("[NET] runtime registry create");
    registry.allocate_runtime().handle()
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

pub fn reset_runtime_registry_for_tests() {
    if let Ok(mut registry) = RUNTIME_REGISTRY.lock() {
        registry.default = None;
        registry.next_id = 0;
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
        let runtime_b = create_runtime();

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
}
