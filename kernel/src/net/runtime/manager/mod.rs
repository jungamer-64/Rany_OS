// ============================================================================
// kernel/src/net/runtime/manager/mod.rs - ランタイム / manager モジュール
// ============================================================================

use crate::net::l3::ipv4::Ipv4Address;
use crate::net::l3::ipv6::Ipv6Address;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::stack::NetworkConfig;
use crate::net::types::{InterfaceScope, NetworkError};
use crate::sync::PoisonLock;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Opaque network interface identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct NetIfId(pub u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdministrativeState {
    Enabled,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    Up,
    Down,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrimaryPreference {
    Prefer,
    Auto,
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TopologyChange {
    Unchanged,
    Changed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct InterfaceTopologyRevision(u64);

impl InterfaceTopologyRevision {
    pub(crate) const INITIAL: Self = Self(0);

    fn next_from(previous: u64) -> Self {
        Self(previous.wrapping_add(1))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ActiveInterfaceConfig {
    pub(crate) if_id: NetIfId,
    pub(crate) config: NetworkConfig,
}

pub(crate) struct InterfaceTopologySnapshot {
    revision: InterfaceTopologyRevision,
    primary: Option<NetIfId>,
    entries: Vec<ActiveInterfaceConfig>,
}

impl InterfaceTopologySnapshot {
    pub(crate) fn revision(&self) -> InterfaceTopologyRevision {
        self.revision
    }

    pub(crate) fn primary(&self) -> Option<NetIfId> {
        self.primary
    }

    pub(crate) fn contains(&self, if_id: NetIfId) -> bool {
        self.entries
            .binary_search_by_key(&if_id, |entry| entry.if_id)
            .is_ok()
    }

    pub(crate) fn into_entries(self) -> alloc::vec::IntoIter<ActiveInterfaceConfig> {
        self.entries.into_iter()
    }
}

/// Route flags for static/connected/default routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RouteFlags {
    pub connected: bool,
    pub static_route: bool,
    pub default_route: bool,
}

impl RouteFlags {
    pub const fn connected() -> Self {
        Self {
            connected: true,
            static_route: false,
            default_route: false,
        }
    }

    pub const fn static_route() -> Self {
        Self {
            connected: false,
            static_route: true,
            default_route: false,
        }
    }

    pub const fn default_static() -> Self {
        Self {
            connected: false,
            static_route: true,
            default_route: true,
        }
    }
}

/// Interface metadata managed by `NetworkManager`.
#[derive(Debug, Clone, Copy)]
pub struct NetworkInterfaceInfo {
    pub if_id: NetIfId,
    pub name: &'static str,
    pub administrative_state: AdministrativeState,
    pub link_state: LinkState,
    pub config: Option<NetworkConfig>,
    primary_preference: PrimaryPreference,
    was_operational: bool,
}

impl NetworkInterfaceInfo {
    pub const fn is_operational(self) -> bool {
        matches!(self.administrative_state, AdministrativeState::Enabled)
            && matches!(self.link_state, LinkState::Up)
            && self.config.is_some()
    }
}

/// IPv4 route entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Route {
    pub destination: Ipv4Address,
    pub prefix_len: u8,
    pub gateway: Option<Ipv4Address>,
    pub if_id: NetIfId,
    pub metric: u32,
    pub flags: RouteFlags,
    pub admin_enabled: bool,
    /// Route inserted/managed by interface config sync.
    pub managed_by_interface: bool,
}

/// IPv6 route entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Route {
    pub destination: Ipv6Address,
    pub prefix_len: u8,
    pub gateway: Option<Ipv6Address>,
    pub if_id: NetIfId,
    pub metric: u32,
    pub flags: RouteFlags,
    pub admin_enabled: bool,
    /// Route inserted/managed by interface config sync.
    pub managed_by_interface: bool,
}

/// Route lookup result alias.
pub type RouteLookupResultV4 = Option<Ipv4Route>;
pub type RouteLookupResultV6 = Option<Ipv6Route>;

/// Multi-interface network manager
#[derive(Debug)]
pub(crate) struct NetworkManager {
    interfaces: BTreeMap<NetIfId, NetworkInterfaceInfo>,
    routes_v4: Vec<Ipv4Route>,
    routes_v6: Vec<Ipv6Route>,
    next_if_id: Option<u16>,
    primary: Option<NetIfId>,
}

impl NetworkManager {
    fn new() -> Self {
        Self {
            interfaces: BTreeMap::new(),
            routes_v4: Vec::new(),
            routes_v6: Vec::new(),
            next_if_id: Some(0),
            primary: None,
        }
    }

    fn register_interface(
        &mut self,
        name: &'static str,
        primary_preference: PrimaryPreference,
    ) -> Result<NetIfId, NetworkError> {
        let raw_if_id = self.next_if_id.ok_or(NetworkError::ResourceExhausted)?;
        let if_id = NetIfId(raw_if_id);
        if self.interfaces.contains_key(&if_id) {
            return Err(NetworkError::ResourceExhausted);
        }

        self.next_if_id = raw_if_id.checked_add(1);
        self.interfaces.insert(
            if_id,
            NetworkInterfaceInfo {
                if_id,
                name,
                administrative_state: AdministrativeState::Enabled,
                link_state: LinkState::Down,
                config: None,
                primary_preference,
                was_operational: false,
            },
        );
        Ok(if_id)
    }

    fn list_interfaces(&self) -> Vec<NetworkInterfaceInfo> {
        self.interfaces.values().copied().collect()
    }

    fn get_interface(&self, if_id: NetIfId) -> Option<&NetworkInterfaceInfo> {
        self.interfaces.get(&if_id)
    }

    fn try_active_interfaces(&self) -> Option<Vec<ActiveInterfaceConfig>> {
        let mut active = Vec::new();
        active.try_reserve_exact(self.interfaces.len()).ok()?;
        active.extend(
            self.interfaces
                .iter()
                .filter(|(_, interface)| interface.is_operational())
                .filter_map(|(&if_id, interface)| {
                    interface
                        .config
                        .map(|config| ActiveInterfaceConfig { if_id, config })
                }),
        );
        Some(active)
    }

    fn unregister_interface(&mut self, if_id: NetIfId) -> bool {
        let removed = self.interfaces.remove(&if_id).is_some();
        if removed {
            self.routes_v4.retain(|route| route.if_id != if_id);
            self.routes_v6.retain(|route| route.if_id != if_id);
            self.reconcile_primary(None);
        }
        removed
    }

    fn automatic_primary(&self) -> Option<NetIfId> {
        [PrimaryPreference::Prefer, PrimaryPreference::Auto]
            .into_iter()
            .find_map(|preference| {
                self.interfaces.iter().find_map(|(&if_id, interface)| {
                    (interface.primary_preference == preference && interface.is_operational())
                        .then_some(if_id)
                })
            })
    }

    fn reconcile_primary(&mut self, first_operational: Option<NetIfId>) {
        if first_operational.is_some_and(|if_id| {
            self.interfaces.get(&if_id).is_some_and(|interface| {
                interface.primary_preference == PrimaryPreference::Prefer
                    && interface.is_operational()
            })
        }) {
            self.primary = first_operational;
            return;
        }

        if self.primary.is_some_and(|if_id| {
            self.interfaces
                .get(&if_id)
                .is_some_and(|interface| interface.is_operational())
        }) {
            return;
        }
        self.primary = self.automatic_primary();
    }

    fn note_first_operational(&mut self, if_id: NetIfId) -> Option<NetIfId> {
        let interface = self.interfaces.get_mut(&if_id)?;
        if interface.is_operational() && !interface.was_operational {
            interface.was_operational = true;
            Some(if_id)
        } else {
            None
        }
    }

    fn set_interface_config(
        &mut self,
        if_id: NetIfId,
        config: NetworkConfig,
    ) -> Result<TopologyChange, NetworkError> {
        let iface = self
            .interfaces
            .get_mut(&if_id)
            .ok_or(NetworkError::InvalidAddress)?;
        if iface.config == Some(config) {
            return Ok(TopologyChange::Unchanged);
        }
        iface.config = Some(config);
        self.refresh_managed_routes_for_interface(if_id, config);
        let first_operational = self.note_first_operational(if_id);
        self.reconcile_primary(first_operational);
        Ok(TopologyChange::Changed)
    }

    fn set_primary_preference(
        &mut self,
        if_id: NetIfId,
        preference: PrimaryPreference,
    ) -> Result<TopologyChange, NetworkError> {
        let interface = self
            .interfaces
            .get_mut(&if_id)
            .ok_or(NetworkError::InvalidAddress)?;
        if interface.primary_preference == preference {
            if preference == PrimaryPreference::Prefer && interface.is_operational() {
                return self.set_primary_interface(if_id);
            }
            return Ok(TopologyChange::Unchanged);
        }
        interface.primary_preference = preference;
        if preference == PrimaryPreference::Prefer && interface.is_operational() {
            self.primary = Some(if_id);
        } else {
            self.reconcile_primary(None);
        }
        Ok(TopologyChange::Changed)
    }

    fn set_administrative_state(
        &mut self,
        if_id: NetIfId,
        state: AdministrativeState,
    ) -> Result<TopologyChange, NetworkError> {
        let iface = self
            .interfaces
            .get_mut(&if_id)
            .ok_or(NetworkError::InvalidAddress)?;
        if iface.administrative_state == state {
            return Ok(TopologyChange::Unchanged);
        }
        iface.administrative_state = state;
        let first_operational = self.note_first_operational(if_id);
        self.reconcile_primary(first_operational);
        Ok(TopologyChange::Changed)
    }

    fn set_link_state(
        &mut self,
        if_id: NetIfId,
        state: LinkState,
    ) -> Result<TopologyChange, NetworkError> {
        let iface = self
            .interfaces
            .get_mut(&if_id)
            .ok_or(NetworkError::InvalidAddress)?;
        if iface.link_state == state {
            return Ok(TopologyChange::Unchanged);
        }
        iface.link_state = state;
        let first_operational = self.note_first_operational(if_id);
        self.reconcile_primary(first_operational);
        Ok(TopologyChange::Changed)
    }

    fn set_primary_interface(&mut self, if_id: NetIfId) -> Result<TopologyChange, NetworkError> {
        let interface = self
            .interfaces
            .get(&if_id)
            .ok_or(NetworkError::InvalidAddress)?;
        if !interface.is_operational() {
            return Err(NetworkError::NetworkUnreachable);
        }
        if self.primary == Some(if_id) {
            return Ok(TopologyChange::Unchanged);
        }
        self.primary = Some(if_id);
        Ok(TopologyChange::Changed)
    }

    fn add_ipv4_route(&mut self, route: Ipv4Route) -> Result<(), NetworkError> {
        if route.prefix_len > 32 {
            return Err(NetworkError::InvalidAddress);
        }
        if !self.interfaces.contains_key(&route.if_id) {
            return Err(NetworkError::InvalidAddress);
        }
        self.routes_v4.push(route);
        self.routes_v4.sort_unstable_by(|a, b| {
            b.prefix_len
                .cmp(&a.prefix_len)
                .then_with(|| a.metric.cmp(&b.metric))
                .then_with(|| a.if_id.cmp(&b.if_id))
        });
        Ok(())
    }

    fn del_ipv4_route(&mut self, route: Ipv4Route) -> bool {
        let before = self.routes_v4.len();
        self.routes_v4.retain(|r| *r != route);
        self.routes_v4.len() != before
    }

    fn list_ipv4_routes(&self) -> Vec<Ipv4Route> {
        self.routes_v4.iter().copied().collect()
    }

    fn lookup_ipv4_route(&self, dst: Ipv4Address) -> RouteLookupResultV4 {
        for route in &self.routes_v4 {
            if !route.admin_enabled {
                continue;
            }
            if let Some(iface) = self.interfaces.get(&route.if_id) {
                if !iface.is_operational() {
                    continue;
                }
            } else {
                continue;
            }
            if ipv4_prefix_match(dst, route.destination, route.prefix_len) {
                return Some(*route);
            }
        }
        None
    }

    fn add_ipv6_route(&mut self, route: Ipv6Route) -> Result<(), NetworkError> {
        if route.prefix_len > 128 {
            return Err(NetworkError::InvalidAddress);
        }
        if !self.interfaces.contains_key(&route.if_id) {
            return Err(NetworkError::InvalidAddress);
        }
        self.routes_v6.push(route);
        self.routes_v6.sort_unstable_by(|a, b| {
            b.prefix_len
                .cmp(&a.prefix_len)
                .then_with(|| a.metric.cmp(&b.metric))
                .then_with(|| a.if_id.cmp(&b.if_id))
        });
        Ok(())
    }

    fn del_ipv6_route(&mut self, route: Ipv6Route) -> bool {
        let before = self.routes_v6.len();
        self.routes_v6.retain(|r| *r != route);
        self.routes_v6.len() != before
    }

    fn list_ipv6_routes(&self) -> Vec<Ipv6Route> {
        self.routes_v6.iter().copied().collect()
    }

    fn lookup_ipv6_route(&self, dst: Ipv6Address) -> RouteLookupResultV6 {
        for route in &self.routes_v6 {
            if !route.admin_enabled {
                continue;
            }
            if let Some(iface) = self.interfaces.get(&route.if_id) {
                if !iface.is_operational() {
                    continue;
                }
            } else {
                continue;
            }
            if ipv6_prefix_match(dst, route.destination, route.prefix_len) {
                return Some(*route);
            }
        }
        None
    }

    fn set_default_route_v4(
        &mut self,
        if_id: NetIfId,
        gateway: Ipv4Address,
        metric: u32,
    ) -> Result<(), NetworkError> {
        if !self.interfaces.contains_key(&if_id) {
            return Err(NetworkError::InvalidAddress);
        }
        self.routes_v4.retain(|r| {
            !(r.if_id == if_id
                && r.prefix_len == 0
                && r.flags.default_route
                && !r.managed_by_interface)
        });
        self.routes_v4.push(Ipv4Route {
            destination: Ipv4Address::ANY,
            prefix_len: 0,
            gateway: Some(gateway),
            if_id,
            metric,
            flags: RouteFlags::default_static(),
            admin_enabled: true,
            managed_by_interface: false,
        });
        Ok(())
    }

    fn set_default_route_v6(
        &mut self,
        if_id: NetIfId,
        gateway: Ipv6Address,
        metric: u32,
    ) -> Result<(), NetworkError> {
        if !self.interfaces.contains_key(&if_id) {
            return Err(NetworkError::InvalidAddress);
        }
        self.routes_v6.retain(|r| {
            !(r.if_id == if_id
                && r.prefix_len == 0
                && r.flags.default_route
                && !r.managed_by_interface)
        });
        self.routes_v6.push(Ipv6Route {
            destination: Ipv6Address::UNSPECIFIED,
            prefix_len: 0,
            gateway: Some(gateway),
            if_id,
            metric,
            flags: RouteFlags::default_static(),
            admin_enabled: true,
            managed_by_interface: false,
        });
        Ok(())
    }

    fn refresh_managed_routes_for_interface(&mut self, if_id: NetIfId, config: NetworkConfig) {
        self.routes_v4
            .retain(|r| !(r.if_id == if_id && r.managed_by_interface));
        self.routes_v6
            .retain(|r| !(r.if_id == if_id && r.managed_by_interface));

        if !config.ipv4.address.is_any() {
            if let Some(prefix_len) = ipv4_mask_to_prefix_len(config.ipv4.subnet_mask) {
                self.routes_v4.push(Ipv4Route {
                    destination: config.ipv4.address.apply_mask(config.ipv4.subnet_mask),
                    prefix_len,
                    gateway: None,
                    if_id,
                    metric: 0,
                    flags: RouteFlags::connected(),
                    admin_enabled: true,
                    managed_by_interface: true,
                });
            }
            if !config.ipv4.gateway.is_any() {
                self.routes_v4.push(Ipv4Route {
                    destination: Ipv4Address::ANY,
                    prefix_len: 0,
                    gateway: Some(config.ipv4.gateway),
                    if_id,
                    metric: 100,
                    flags: RouteFlags::default_static(),
                    admin_enabled: true,
                    managed_by_interface: true,
                });
            }
        }

        if let Some(ipv6_cfg) = config.ipv6 {
            if let Some(global) = ipv6_cfg.global {
                self.routes_v6.push(Ipv6Route {
                    destination: ipv6_apply_prefix(global, ipv6_cfg.prefix_len),
                    prefix_len: ipv6_cfg.prefix_len,
                    gateway: None,
                    if_id,
                    metric: 0,
                    flags: RouteFlags::connected(),
                    admin_enabled: true,
                    managed_by_interface: true,
                });
            }
            if let Some(gateway) = ipv6_cfg.gateway {
                self.routes_v6.push(Ipv6Route {
                    destination: Ipv6Address::UNSPECIFIED,
                    prefix_len: 0,
                    gateway: Some(gateway),
                    if_id,
                    metric: 100,
                    flags: RouteFlags::default_static(),
                    admin_enabled: true,
                    managed_by_interface: true,
                });
            }
        }
    }
}

fn ipv4_prefix_match(addr: Ipv4Address, destination: Ipv4Address, prefix_len: u8) -> bool {
    if prefix_len > 32 {
        return false;
    }
    if prefix_len == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - prefix_len);
    (addr.to_u32() & mask) == (destination.to_u32() & mask)
}

fn ipv4_mask_to_prefix_len(mask: Ipv4Address) -> Option<u8> {
    let m = mask.to_u32();
    let prefix_len = m.leading_ones() as u8;
    let normalized = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    if m == normalized {
        Some(prefix_len)
    } else {
        None
    }
}

fn ipv6_prefix_match(addr: Ipv6Address, destination: Ipv6Address, prefix_len: u8) -> bool {
    if prefix_len > 128 {
        return false;
    }
    if prefix_len == 0 {
        return true;
    }
    let a = addr.octets();
    let d = destination.octets();
    let full_bytes = (prefix_len / 8) as usize;
    let rem_bits = (prefix_len % 8) as usize;

    if a[..full_bytes] != d[..full_bytes] {
        return false;
    }
    if rem_bits == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - rem_bits);
    (a[full_bytes] & mask) == (d[full_bytes] & mask)
}

fn ipv6_apply_prefix(addr: Ipv6Address, prefix_len: u8) -> Ipv6Address {
    if prefix_len >= 128 {
        return addr;
    }
    let mut octets = addr.octets();
    let full_bytes = (prefix_len / 8) as usize;
    let rem_bits = (prefix_len % 8) as usize;

    if rem_bits != 0 {
        let mask = 0xFFu8 << (8 - rem_bits);
        octets[full_bytes] &= mask;
        for b in octets.iter_mut().skip(full_bytes + 1) {
            *b = 0;
        }
    } else {
        for b in octets.iter_mut().skip(full_bytes) {
            *b = 0;
        }
    }
    Ipv6Address::new(octets)
}

pub fn init_network_manager_in(runtime: NetRuntimeHandle) {
    let mut guard = manager_slot_in(runtime).lock_for_init("[NET] NetworkManager init");
    if guard.is_none() {
        *guard = Some(NetworkManager::new());
    }
}

fn manager_slot_in(runtime: NetRuntimeHandle) -> &'static PoisonLock<Option<NetworkManager>> {
    &runtime.context().manager
}

fn with_manager_mut_in<F, R>(runtime: NetRuntimeHandle, f: F) -> Result<R, NetworkError>
where
    F: FnOnce(&mut NetworkManager) -> R,
{
    match manager_slot_in(runtime).lock() {
        Ok(mut guard) => {
            let Some(manager) = guard.as_mut() else {
                return Err(NetworkError::Unknown);
            };
            Ok(f(manager))
        }
        Err(poisoned) => {
            let mut manager_opt = poisoned.into_inner();
            let Some(manager) = manager_opt.as_mut() else {
                return Err(NetworkError::Unknown);
            };
            Ok(f(manager))
        }
    }
}

fn with_manager_in<F, R>(runtime: NetRuntimeHandle, f: F) -> Result<R, NetworkError>
where
    F: FnOnce(&NetworkManager) -> R,
{
    match manager_slot_in(runtime).lock() {
        Ok(guard) => {
            let Some(manager) = guard.as_ref() else {
                return Err(NetworkError::Unknown);
            };
            Ok(f(manager))
        }
        Err(poisoned) => {
            let manager_opt = poisoned.into_inner();
            let Some(manager) = manager_opt.as_ref() else {
                return Err(NetworkError::Unknown);
            };
            Ok(f(manager))
        }
    }
}

pub fn register_interface_in(
    runtime: NetRuntimeHandle,
    name: &'static str,
    primary_preference: PrimaryPreference,
) -> Result<NetIfId, NetworkError> {
    mutate_topology_in(runtime, |manager| {
        let if_id = manager.register_interface(name, primary_preference)?;
        Ok((if_id, TopologyChange::Changed))
    })
}

pub fn list_interfaces_in(
    runtime: NetRuntimeHandle,
) -> Result<Vec<NetworkInterfaceInfo>, NetworkError> {
    with_manager_in(runtime, |m| m.list_interfaces())
}

pub fn get_interface_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
) -> Result<Option<NetworkInterfaceInfo>, NetworkError> {
    with_manager_in(runtime, |m| m.get_interface(if_id).copied())
}

pub(crate) fn current_interface_topology_revision_in(
    runtime: NetRuntimeHandle,
) -> InterfaceTopologyRevision {
    InterfaceTopologyRevision(
        runtime
            .context()
            .interface_topology_revision
            .load(core::sync::atomic::Ordering::Acquire),
    )
}

pub(crate) fn try_interface_topology_in(
    runtime: NetRuntimeHandle,
) -> Option<InterfaceTopologySnapshot> {
    let guard = match manager_slot_in(runtime).try_lock() {
        Ok(guard) => guard,
        Err(crate::sync::poison_lock::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        Err(crate::sync::poison_lock::TryLockError::WouldBlock) => return None,
    };
    let manager = guard.as_ref()?;
    let entries = manager.try_active_interfaces()?;
    let revision = current_interface_topology_revision_in(runtime);
    debug_assert!(manager.primary.is_none_or(|if_id| {
        entries
            .binary_search_by_key(&if_id, |entry| entry.if_id)
            .is_ok()
    }));
    Some(InterfaceTopologySnapshot {
        revision,
        primary: manager.primary,
        entries,
    })
}

fn publish_interface_topology_change(
    runtime: NetRuntimeHandle,
    revision: InterfaceTopologyRevision,
) {
    crate::net::runtime::command::broadcast_command_in(runtime, move || {
        crate::net::runtime::command::RuntimeCommand::Control(
            crate::net::runtime::command::ControlCommand::InterfaceTopologyDirty { revision },
        )
    });
}

fn record_interface_topology_change(runtime: NetRuntimeHandle) -> InterfaceTopologyRevision {
    let previous = runtime
        .context()
        .interface_topology_revision
        .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    InterfaceTopologyRevision::next_from(previous)
}

fn mutate_topology_in<F, R>(runtime: NetRuntimeHandle, f: F) -> Result<R, NetworkError>
where
    F: FnOnce(&mut NetworkManager) -> Result<(R, TopologyChange), NetworkError>,
{
    let (result, revision) = match manager_slot_in(runtime).lock() {
        Ok(mut guard) => {
            let manager = guard.as_mut().ok_or(NetworkError::Unknown)?;
            let (result, change) = f(manager)?;
            let revision = matches!(change, TopologyChange::Changed)
                .then(|| record_interface_topology_change(runtime));
            (result, revision)
        }
        Err(poisoned) => {
            let mut manager_opt = poisoned.into_inner();
            let manager = manager_opt.as_mut().ok_or(NetworkError::Unknown)?;
            let (result, change) = f(manager)?;
            let revision = matches!(change, TopologyChange::Changed)
                .then(|| record_interface_topology_change(runtime));
            (result, revision)
        }
    };
    if let Some(revision) = revision {
        publish_interface_topology_change(runtime, revision);
    }
    Ok(result)
}

pub fn unregister_interface_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
) -> Result<bool, NetworkError> {
    mutate_topology_in(runtime, |manager| {
        let removed = manager.unregister_interface(if_id);
        let change = if removed {
            TopologyChange::Changed
        } else {
            TopologyChange::Unchanged
        };
        Ok((removed, change))
    })
}

pub fn set_interface_config_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    config: NetworkConfig,
) -> Result<(), NetworkError> {
    mutate_topology_in(runtime, |manager| {
        let change = manager.set_interface_config(if_id, config)?;
        Ok(((), change))
    })
}

pub(crate) fn set_primary_preference_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    preference: PrimaryPreference,
) -> Result<(), NetworkError> {
    mutate_topology_in(runtime, |manager| {
        let change = manager.set_primary_preference(if_id, preference)?;
        Ok(((), change))
    })
}

pub fn set_interface_up_in(runtime: NetRuntimeHandle, if_id: NetIfId) -> Result<(), NetworkError> {
    set_interface_administrative_state_in(runtime, if_id, AdministrativeState::Enabled)
}

pub fn set_interface_down_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
) -> Result<(), NetworkError> {
    set_interface_administrative_state_in(runtime, if_id, AdministrativeState::Disabled)
}

pub fn set_interface_administrative_state_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    state: AdministrativeState,
) -> Result<(), NetworkError> {
    mutate_topology_in(runtime, |manager| {
        let change = manager.set_administrative_state(if_id, state)?;
        Ok(((), change))
    })
}

pub fn set_interface_link_state_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    state: LinkState,
) -> Result<(), NetworkError> {
    mutate_topology_in(runtime, |manager| {
        let change = manager.set_link_state(if_id, state)?;
        Ok(((), change))
    })
}

pub fn primary_interface_in(runtime: NetRuntimeHandle) -> Option<NetIfId> {
    with_manager_in(runtime, |manager| manager.primary)
        .ok()
        .flatten()
}

pub fn set_primary_interface_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
) -> Result<(), NetworkError> {
    mutate_topology_in(runtime, |manager| {
        let change = manager.set_primary_interface(if_id)?;
        Ok(((), change))
    })
}

pub fn is_interface_operational_in(runtime: NetRuntimeHandle, if_id: NetIfId) -> bool {
    with_manager_in(runtime, |manager| {
        manager
            .get_interface(if_id)
            .copied()
            .is_some_and(NetworkInterfaceInfo::is_operational)
    })
    .unwrap_or(false)
}

pub fn add_ipv4_route_in(runtime: NetRuntimeHandle, route: Ipv4Route) -> Result<(), NetworkError> {
    with_manager_mut_in(runtime, |m| m.add_ipv4_route(route)).and_then(|r| r)
}

pub fn del_ipv4_route_in(
    runtime: NetRuntimeHandle,
    route: Ipv4Route,
) -> Result<bool, NetworkError> {
    with_manager_mut_in(runtime, |m| m.del_ipv4_route(route))
}

pub fn lookup_ipv4_route_in(
    runtime: NetRuntimeHandle,
    dst: Ipv4Address,
) -> Result<RouteLookupResultV4, NetworkError> {
    with_manager_in(runtime, |m| m.lookup_ipv4_route(dst))
}

pub(crate) fn resolve_ipv4_interface_in(
    runtime: NetRuntimeHandle,
    scope: InterfaceScope,
    dst: Ipv4Address,
) -> Result<NetIfId, NetworkError> {
    with_manager_in(runtime, |manager| match scope {
        InterfaceScope::Pinned(if_id) => manager
            .get_interface(if_id)
            .copied()
            .filter(|interface| interface.is_operational())
            .map(|_| if_id)
            .ok_or(NetworkError::NetworkUnreachable),
        InterfaceScope::Any => manager
            .lookup_ipv4_route(dst)
            .map(|route| route.if_id)
            .ok_or(NetworkError::NetworkUnreachable),
    })?
}

pub fn list_ipv4_routes_in(runtime: NetRuntimeHandle) -> Result<Vec<Ipv4Route>, NetworkError> {
    with_manager_in(runtime, |m| m.list_ipv4_routes())
}

pub fn add_ipv6_route_in(runtime: NetRuntimeHandle, route: Ipv6Route) -> Result<(), NetworkError> {
    with_manager_mut_in(runtime, |m| m.add_ipv6_route(route)).and_then(|r| r)
}

pub fn del_ipv6_route_in(
    runtime: NetRuntimeHandle,
    route: Ipv6Route,
) -> Result<bool, NetworkError> {
    with_manager_mut_in(runtime, |m| m.del_ipv6_route(route))
}

pub fn lookup_ipv6_route_in(
    runtime: NetRuntimeHandle,
    dst: Ipv6Address,
) -> Result<RouteLookupResultV6, NetworkError> {
    with_manager_in(runtime, |m| m.lookup_ipv6_route(dst))
}

pub(crate) fn resolve_ipv6_interface_in(
    runtime: NetRuntimeHandle,
    scope: InterfaceScope,
    dst: Ipv6Address,
) -> Result<NetIfId, NetworkError> {
    with_manager_in(runtime, |manager| match scope {
        InterfaceScope::Pinned(if_id) => manager
            .get_interface(if_id)
            .copied()
            .filter(|interface| interface.is_operational())
            .map(|_| if_id)
            .ok_or(NetworkError::NetworkUnreachable),
        InterfaceScope::Any => manager
            .lookup_ipv6_route(dst)
            .map(|route| route.if_id)
            .ok_or(NetworkError::NetworkUnreachable),
    })?
}

pub fn list_ipv6_routes_in(runtime: NetRuntimeHandle) -> Result<Vec<Ipv6Route>, NetworkError> {
    with_manager_in(runtime, |m| m.list_ipv6_routes())
}

pub fn set_default_route_v4_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    gateway: Ipv4Address,
    metric: u32,
) -> Result<(), NetworkError> {
    with_manager_mut_in(runtime, |m| m.set_default_route_v4(if_id, gateway, metric)).and_then(|r| r)
}

pub fn set_default_route_v6_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    gateway: Ipv6Address,
    metric: u32,
) -> Result<(), NetworkError> {
    with_manager_mut_in(runtime, |m| m.set_default_route_v6(if_id, gateway, metric)).and_then(|r| r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configured_manager_interface(
        manager: &mut NetworkManager,
        name: &'static str,
        preference: PrimaryPreference,
    ) -> NetIfId {
        let if_id = manager
            .register_interface(name, preference)
            .expect("register interface");
        manager
            .set_interface_config(if_id, NetworkConfig::default())
            .expect("configure interface");
        manager
            .set_link_state(if_id, LinkState::Up)
            .expect("raise link");
        if_id
    }

    #[test]
    fn interface_ids_do_not_wrap_after_exhaustion() {
        let mut manager = NetworkManager::new();
        manager.next_if_id = Some(u16::MAX);

        let if_id = manager
            .register_interface("last-if", PrimaryPreference::Auto)
            .expect("last representable interface id");
        assert_eq!(if_id, NetIfId(u16::MAX));
        assert_eq!(
            manager.register_interface("wrapped-if", PrimaryPreference::Auto),
            Err(NetworkError::ResourceExhausted)
        );
        assert_eq!(manager.interfaces.len(), 1);
    }

    #[test]
    fn network_manager_rejects_interface_id_reuse() {
        let mut manager = NetworkManager::new();
        let if_id = manager
            .register_interface("if0", PrimaryPreference::Auto)
            .expect("first interface");
        assert_eq!(if_id, NetIfId(0));

        manager.next_if_id = Some(0);
        assert_eq!(
            manager.register_interface("if0-reused", PrimaryPreference::Auto),
            Err(NetworkError::ResourceExhausted)
        );
        assert_eq!(manager.interfaces.len(), 1);
    }

    #[test]
    fn active_interfaces_preserve_ids_above_fixed_array_ranges() {
        let mut manager = NetworkManager::new();
        manager.next_if_id = Some(31);
        let if_31 = configured_manager_interface(&mut manager, "if31", PrimaryPreference::Auto);
        let if_32 = configured_manager_interface(&mut manager, "if32", PrimaryPreference::Auto);

        let active = manager
            .try_active_interfaces()
            .expect("active interface snapshot allocation");
        assert_eq!(active.len(), 2);
        assert!(active.iter().any(|entry| entry.if_id == if_31));
        assert!(active.iter().any(|entry| entry.if_id == if_32));
    }

    #[test]
    fn topology_revision_changes_once_per_real_mutation() {
        let runtime = crate::net::runtime::create_runtime().expect("test runtime allocation");
        init_network_manager_in(runtime);

        let initial = current_interface_topology_revision_in(runtime);
        let if_id = register_interface_in(runtime, "if0", PrimaryPreference::Auto)
            .expect("register interface");
        let registered = current_interface_topology_revision_in(runtime);
        assert_ne!(registered, initial);

        set_interface_administrative_state_in(runtime, if_id, AdministrativeState::Enabled)
            .expect("repeat enabled state");
        assert_eq!(current_interface_topology_revision_in(runtime), registered);

        set_interface_config_in(runtime, if_id, NetworkConfig::default())
            .expect("configure interface");
        let configured = current_interface_topology_revision_in(runtime);
        assert_ne!(configured, registered);
        set_interface_config_in(runtime, if_id, NetworkConfig::default())
            .expect("repeat configuration");
        assert_eq!(current_interface_topology_revision_in(runtime), configured);

        set_interface_link_state_in(runtime, if_id, LinkState::Up).expect("raise link");
        let linked = current_interface_topology_revision_in(runtime);
        assert_ne!(linked, configured);
        assert_eq!(primary_interface_in(runtime), Some(if_id));
        set_interface_link_state_in(runtime, if_id, LinkState::Up).expect("repeat link state");
        set_primary_interface_in(runtime, if_id).expect("repeat primary");
        assert_eq!(current_interface_topology_revision_in(runtime), linked);
    }

    #[test]
    fn primary_rejects_unknown_and_non_operational_interfaces() {
        let mut manager = NetworkManager::new();
        let if_id = manager
            .register_interface("down", PrimaryPreference::Never)
            .expect("register interface");

        assert_eq!(
            manager.set_primary_interface(NetIfId(99)),
            Err(NetworkError::InvalidAddress)
        );
        assert_eq!(
            manager.set_primary_interface(if_id),
            Err(NetworkError::NetworkUnreachable)
        );
    }

    #[test]
    fn primary_failover_is_deterministic_and_recovery_does_not_preempt() {
        let mut manager = NetworkManager::new();
        let auto_low =
            configured_manager_interface(&mut manager, "auto-low", PrimaryPreference::Auto);
        let prefer =
            configured_manager_interface(&mut manager, "prefer", PrimaryPreference::Prefer);
        let auto_high =
            configured_manager_interface(&mut manager, "auto-high", PrimaryPreference::Auto);
        let never = configured_manager_interface(&mut manager, "never", PrimaryPreference::Never);

        assert_eq!(manager.primary, Some(prefer));
        manager
            .set_link_state(prefer, LinkState::Down)
            .expect("lower preferred link");
        assert_eq!(manager.primary, Some(auto_low));
        manager
            .set_administrative_state(auto_low, AdministrativeState::Disabled)
            .expect("disable lower auto interface");
        assert_eq!(manager.primary, Some(auto_high));

        manager
            .set_link_state(prefer, LinkState::Up)
            .expect("recover preferred link");
        assert_eq!(manager.primary, Some(auto_high));

        assert!(manager.unregister_interface(auto_high));
        assert_eq!(manager.primary, Some(prefer));
        manager
            .set_link_state(prefer, LinkState::Down)
            .expect("lower preferred link again");
        assert_eq!(manager.primary, None);
        assert!(manager.get_interface(never).is_some());
    }

    #[test]
    fn egress_scope_requires_an_operational_interface_or_route() {
        let runtime = crate::net::runtime::create_runtime().expect("test runtime allocation");
        init_network_manager_in(runtime);
        let if_id = register_interface_in(runtime, "route-if", PrimaryPreference::Auto)
            .expect("register route interface");
        let destination = Ipv4Address::new([192, 0, 2, 99]);

        assert_eq!(
            resolve_ipv4_interface_in(runtime, InterfaceScope::Pinned(if_id), destination),
            Err(NetworkError::NetworkUnreachable)
        );

        let mut config = NetworkConfig::default();
        config.ipv4.address = Ipv4Address::new([192, 0, 2, 10]);
        config.ipv4.subnet_mask = Ipv4Address::new([255, 255, 255, 0]);
        set_interface_config_in(runtime, if_id, config).expect("configure route interface");
        set_interface_link_state_in(runtime, if_id, LinkState::Up).expect("raise route interface");

        assert_eq!(
            resolve_ipv4_interface_in(runtime, InterfaceScope::Pinned(if_id), destination),
            Ok(if_id)
        );
        assert_eq!(
            resolve_ipv4_interface_in(runtime, InterfaceScope::Any, destination),
            Ok(if_id)
        );
        assert_eq!(
            resolve_ipv4_interface_in(
                runtime,
                InterfaceScope::Any,
                Ipv4Address::new([198, 51, 100, 1]),
            ),
            Err(NetworkError::NetworkUnreachable)
        );

        set_interface_link_state_in(runtime, if_id, LinkState::Down)
            .expect("lower route interface");
        assert_eq!(
            resolve_ipv4_interface_in(runtime, InterfaceScope::Pinned(if_id), destination),
            Err(NetworkError::NetworkUnreachable)
        );
        assert_eq!(
            resolve_ipv4_interface_in(runtime, InterfaceScope::Any, destination),
            Err(NetworkError::NetworkUnreachable)
        );
    }
}
