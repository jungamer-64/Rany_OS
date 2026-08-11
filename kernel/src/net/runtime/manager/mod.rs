// ============================================================================
// kernel/src/net/runtime/manager/mod.rs - ランタイム / manager モジュール
// ============================================================================

use crate::net::l3::ipv4::Ipv4Address;
use crate::net::l3::ipv6::Ipv6Address;
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::stack::NetworkConfig;
use crate::net::types::NetworkError;
use crate::sync::PoisonLock;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Opaque network interface identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct NetIfId(pub u16);

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
    pub admin_up: bool,
    pub config: Option<NetworkConfig>,
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
}

impl NetworkManager {
    fn new() -> Self {
        Self {
            interfaces: BTreeMap::new(),
            routes_v4: Vec::new(),
            routes_v6: Vec::new(),
            next_if_id: Some(0),
        }
    }

    fn register_interface(&mut self, name: &'static str) -> Result<NetIfId, NetworkError> {
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
                admin_up: true,
                config: None,
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

    fn unregister_interface(&mut self, if_id: NetIfId) -> bool {
        let removed = self.interfaces.remove(&if_id).is_some();
        if removed {
            self.routes_v4.retain(|route| route.if_id != if_id);
            self.routes_v6.retain(|route| route.if_id != if_id);
        }
        removed
    }

    fn set_interface_config(
        &mut self,
        if_id: NetIfId,
        config: NetworkConfig,
    ) -> Result<(), NetworkError> {
        let iface = self
            .interfaces
            .get_mut(&if_id)
            .ok_or(NetworkError::InvalidAddress)?;
        iface.config = Some(config);
        self.refresh_managed_routes_for_interface(if_id, config);
        Ok(())
    }

    fn set_interface_up(&mut self, if_id: NetIfId) -> Result<(), NetworkError> {
        let iface = self
            .interfaces
            .get_mut(&if_id)
            .ok_or(NetworkError::InvalidAddress)?;
        iface.admin_up = true;
        Ok(())
    }

    fn set_interface_down(&mut self, if_id: NetIfId) -> Result<(), NetworkError> {
        let iface = self
            .interfaces
            .get_mut(&if_id)
            .ok_or(NetworkError::InvalidAddress)?;
        iface.admin_up = false;
        Ok(())
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
                if !iface.admin_up {
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
                if !iface.admin_up {
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
) -> Result<NetIfId, NetworkError> {
    with_manager_mut_in(runtime, |m| m.register_interface(name)).and_then(|r| r)
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

pub fn unregister_interface_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
) -> Result<bool, NetworkError> {
    with_manager_mut_in(runtime, |m| m.unregister_interface(if_id))
}

pub fn set_interface_config_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
    config: NetworkConfig,
) -> Result<(), NetworkError> {
    let result = with_manager_mut_in(runtime, |m| m.set_interface_config(if_id, config)).and_then(|r| r);
    if result.is_ok() {
        let idx = (if_id.0 as usize).min(31);
        runtime.context().config_generations[idx].fetch_add(1, core::sync::atomic::Ordering::Release);
    }
    result
}

pub fn set_interface_up_in(runtime: NetRuntimeHandle, if_id: NetIfId) -> Result<(), NetworkError> {
    with_manager_mut_in(runtime, |m| m.set_interface_up(if_id)).and_then(|r| r)
}

pub fn set_interface_down_in(
    runtime: NetRuntimeHandle,
    if_id: NetIfId,
) -> Result<(), NetworkError> {
    with_manager_mut_in(runtime, |m| m.set_interface_down(if_id)).and_then(|r| r)
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

    #[test]
    fn interface_ids_do_not_wrap_after_exhaustion() {
        let mut manager = NetworkManager::new();
        manager.next_if_id = Some(u16::MAX);

        let if_id = manager
            .register_interface("last-if")
            .expect("last representable interface id");
        assert_eq!(if_id, NetIfId(u16::MAX));
        assert_eq!(
            manager.register_interface("wrapped-if"),
            Err(NetworkError::ResourceExhausted)
        );
        assert_eq!(manager.interfaces.len(), 1);
    }

    #[test]
    fn network_manager_rejects_interface_id_reuse() {
        let mut manager = NetworkManager::new();
        let if_id = manager.register_interface("if0").expect("first interface");
        assert_eq!(if_id, NetIfId(0));

        manager.next_if_id = Some(0);
        assert_eq!(
            manager.register_interface("if0-reused"),
            Err(NetworkError::ResourceExhausted)
        );
        assert_eq!(manager.interfaces.len(), 1);
    }
}
