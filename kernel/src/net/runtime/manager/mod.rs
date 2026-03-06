use crate::net::l3::ipv4::Ipv4Address;
use crate::net::l3::ipv6::Ipv6Address;
use crate::net::runtime::stack::NetworkConfig;
use crate::net::types::NetworkError;
use crate::sync::PoisonLock;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// Global network manager instance (opt-in / transitional).
pub(crate) static NETWORK_MANAGER: PoisonLock<Option<NetworkManager>> = PoisonLock::new(None);

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
#[derive(Debug, Clone)]
pub struct NetworkInterfaceInfo {
    pub if_id: NetIfId,
    pub name: String,
    pub admin_up: bool,
    pub virtio_index: Option<u8>,
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

/// Multi-interface network manager (transitional groundwork for full multi-NIC migration).
#[derive(Debug, Default)]
pub struct NetworkManager {
    interfaces: BTreeMap<NetIfId, NetworkInterfaceInfo>,
    virtio_if_map: BTreeMap<u8, NetIfId>,
    routes_v4: Vec<Ipv4Route>,
    routes_v6: Vec<Ipv6Route>,
    next_if_id: u16,
}

impl NetworkManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_interface(&mut self, name: String) -> NetIfId {
        let if_id = NetIfId(self.next_if_id);
        self.next_if_id = self.next_if_id.wrapping_add(1);
        self.interfaces.insert(
            if_id,
            NetworkInterfaceInfo {
                if_id,
                name,
                admin_up: true,
                virtio_index: None,
                config: None,
            },
        );
        if_id
    }

    /// Register or return an existing VirtIO-backed interface mapping.
    pub fn register_virtio_port(
        &mut self,
        virtio_index: u8,
        initial_config: Option<NetworkConfig>,
    ) -> NetIfId {
        if let Some(existing) = self.virtio_if_map.get(&virtio_index).copied() {
            if let Some(cfg) = initial_config {
                let _ = self.set_interface_config(existing, cfg);
            }
            return existing;
        }

        let if_id = self.register_interface(alloc::format!("vnet{}", virtio_index));
        if let Some(iface) = self.interfaces.get_mut(&if_id) {
            iface.virtio_index = Some(virtio_index);
            iface.config = initial_config;
        }
        self.virtio_if_map.insert(virtio_index, if_id);

        if let Some(cfg) = initial_config {
            let _ = self.set_interface_config(if_id, cfg);
        }

        if_id
    }

    pub fn lookup_if_by_virtio_index(&self, virtio_index: u8) -> Option<NetIfId> {
        self.virtio_if_map.get(&virtio_index).copied()
    }

    pub fn list_interfaces(&self) -> Vec<NetworkInterfaceInfo> {
        self.interfaces.values().cloned().collect()
    }

    pub fn get_interface(&self, if_id: NetIfId) -> Option<&NetworkInterfaceInfo> {
        self.interfaces.get(&if_id)
    }

    pub fn set_interface_config(
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

    pub fn set_interface_up(&mut self, if_id: NetIfId) -> Result<(), NetworkError> {
        let iface = self
            .interfaces
            .get_mut(&if_id)
            .ok_or(NetworkError::InvalidAddress)?;
        iface.admin_up = true;
        Ok(())
    }

    pub fn set_interface_down(&mut self, if_id: NetIfId) -> Result<(), NetworkError> {
        let iface = self
            .interfaces
            .get_mut(&if_id)
            .ok_or(NetworkError::InvalidAddress)?;
        iface.admin_up = false;
        Ok(())
    }

    pub fn add_ipv4_route(&mut self, route: Ipv4Route) -> Result<(), NetworkError> {
        if route.prefix_len > 32 {
            return Err(NetworkError::InvalidAddress);
        }
        if !self.interfaces.contains_key(&route.if_id) {
            return Err(NetworkError::InvalidAddress);
        }
        self.routes_v4.push(route);
        // keep longest-prefix/lowest-metric routes first so lookup can stop early
        self.routes_v4.sort_unstable_by(|a, b| {
            b.prefix_len
                .cmp(&a.prefix_len)
                .then_with(|| a.metric.cmp(&b.metric))
                .then_with(|| a.if_id.cmp(&b.if_id))
        });
        Ok(())
    }

    pub fn del_ipv4_route(&mut self, route: Ipv4Route) -> bool {
        let before = self.routes_v4.len();
        self.routes_v4.retain(|r| *r != route);
        self.routes_v4.len() != before
    }

    pub fn list_ipv4_routes(&self) -> Vec<Ipv4Route> {
        self.routes_v4.clone()
    }

    pub fn lookup_ipv4_route(&self, dst: Ipv4Address) -> RouteLookupResultV4 {
        // routes_v4 is sorted by prefix_len/metric/if_id; pick first matching entry
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

    pub fn add_ipv6_route(&mut self, route: Ipv6Route) -> Result<(), NetworkError> {
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

    pub fn del_ipv6_route(&mut self, route: Ipv6Route) -> bool {
        let before = self.routes_v6.len();
        self.routes_v6.retain(|r| *r != route);
        self.routes_v6.len() != before
    }

    pub fn list_ipv6_routes(&self) -> Vec<Ipv6Route> {
        self.routes_v6.clone()
    }

    pub fn lookup_ipv6_route(&self, dst: Ipv6Address) -> RouteLookupResultV6 {
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

    pub fn set_default_route_v4(
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

    pub fn set_default_route_v6(
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

fn route_is_better_v4(candidate: Ipv4Route, current: Option<Ipv4Route>) -> bool {
    let Some(current) = current else {
        return true;
    };
    if candidate.prefix_len != current.prefix_len {
        return candidate.prefix_len > current.prefix_len;
    }
    if candidate.metric != current.metric {
        return candidate.metric < current.metric;
    }
    candidate.if_id < current.if_id
}

fn route_is_better_v6(candidate: Ipv6Route, current: Option<Ipv6Route>) -> bool {
    let Some(current) = current else {
        return true;
    };
    if candidate.prefix_len != current.prefix_len {
        return candidate.prefix_len > current.prefix_len;
    }
    if candidate.metric != current.metric {
        return candidate.metric < current.metric;
    }
    candidate.if_id < current.if_id
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

/// Initialize the global `NetworkManager` (idempotent).
pub fn init_network_manager() {
    let mut guard = NETWORK_MANAGER.lock_for_init("[NET] NetworkManager init");
    if guard.is_none() {
        *guard = Some(NetworkManager::new());
    }
}

/// Access the global `NetworkManager` lock.
pub fn network_manager() -> &'static PoisonLock<Option<NetworkManager>> {
    &NETWORK_MANAGER
}

fn with_manager_mut<F, R>(f: F) -> Result<R, NetworkError>
where
    F: FnOnce(&mut NetworkManager) -> R,
{
    match NETWORK_MANAGER.lock() {
        Ok(mut guard) => {
            let Some(manager) = guard.as_mut() else {
                return Err(NetworkError::Unknown);
            };
            Ok(f(manager))
        }
        Err(_) => Err(NetworkError::LockPoisoned),
    }
}

fn with_manager<F, R>(f: F) -> Result<R, NetworkError>
where
    F: FnOnce(&NetworkManager) -> R,
{
    match NETWORK_MANAGER.lock() {
        Ok(guard) => {
            let Some(manager) = guard.as_ref() else {
                return Err(NetworkError::Unknown);
            };
            Ok(f(manager))
        }
        Err(_) => Err(NetworkError::LockPoisoned),
    }
}

/// Register a generic interface.
pub fn register_interface(name: &str) -> Result<NetIfId, NetworkError> {
    with_manager_mut(|m| m.register_interface(String::from(name)))
}

/// Register a VirtIO-backed interface and return its `NetIfId`.
pub fn register_virtio_port(
    virtio_index: u8,
    initial_config: Option<NetworkConfig>,
) -> Result<NetIfId, NetworkError> {
    with_manager_mut(|m| m.register_virtio_port(virtio_index, initial_config))
}

/// Resolve a VirtIO index into a network interface id.
pub fn lookup_if_by_virtio_index(virtio_index: u8) -> Option<NetIfId> {
    with_manager(|m| m.lookup_if_by_virtio_index(virtio_index))
        .ok()
        .flatten()
}

pub fn list_interfaces() -> Result<Vec<NetworkInterfaceInfo>, NetworkError> {
    with_manager(|m| m.list_interfaces())
}

pub fn get_interface(if_id: NetIfId) -> Result<Option<NetworkInterfaceInfo>, NetworkError> {
    with_manager(|m| m.get_interface(if_id).cloned())
}

pub fn set_interface_config(if_id: NetIfId, config: NetworkConfig) -> Result<(), NetworkError> {
    with_manager_mut(|m| m.set_interface_config(if_id, config)).and_then(|r| r)
}

pub fn set_interface_up(if_id: NetIfId) -> Result<(), NetworkError> {
    with_manager_mut(|m| m.set_interface_up(if_id)).and_then(|r| r)
}

pub fn set_interface_down(if_id: NetIfId) -> Result<(), NetworkError> {
    with_manager_mut(|m| m.set_interface_down(if_id)).and_then(|r| r)
}

pub fn add_ipv4_route(route: Ipv4Route) -> Result<(), NetworkError> {
    with_manager_mut(|m| m.add_ipv4_route(route)).and_then(|r| r)
}

pub fn del_ipv4_route(route: Ipv4Route) -> Result<bool, NetworkError> {
    with_manager_mut(|m| m.del_ipv4_route(route))
}

pub fn lookup_ipv4_route(dst: Ipv4Address) -> Result<RouteLookupResultV4, NetworkError> {
    with_manager(|m| m.lookup_ipv4_route(dst))
}

pub fn list_ipv4_routes() -> Result<Vec<Ipv4Route>, NetworkError> {
    with_manager(|m| m.list_ipv4_routes())
}

pub fn add_ipv6_route(route: Ipv6Route) -> Result<(), NetworkError> {
    with_manager_mut(|m| m.add_ipv6_route(route)).and_then(|r| r)
}

pub fn del_ipv6_route(route: Ipv6Route) -> Result<bool, NetworkError> {
    with_manager_mut(|m| m.del_ipv6_route(route))
}

pub fn lookup_ipv6_route(dst: Ipv6Address) -> Result<RouteLookupResultV6, NetworkError> {
    with_manager(|m| m.lookup_ipv6_route(dst))
}

pub fn list_ipv6_routes() -> Result<Vec<Ipv6Route>, NetworkError> {
    with_manager(|m| m.list_ipv6_routes())
}

pub fn set_default_route_v4(
    if_id: NetIfId,
    gateway: Ipv4Address,
    metric: u32,
) -> Result<(), NetworkError> {
    with_manager_mut(|m| m.set_default_route_v4(if_id, gateway, metric)).and_then(|r| r)
}

pub fn set_default_route_v6(
    if_id: NetIfId,
    gateway: Ipv6Address,
    metric: u32,
) -> Result<(), NetworkError> {
    with_manager_mut(|m| m.set_default_route_v6(if_id, gateway, metric)).and_then(|r| r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4route(dest: [u8; 4], prefix_len: u8, if_id: NetIfId, metric: u32) -> Ipv4Route {
        Ipv4Route {
            destination: Ipv4Address::new(dest),
            prefix_len,
            gateway: None,
            if_id,
            metric,
            flags: RouteFlags::static_route(),
            admin_enabled: true,
            managed_by_interface: false,
        }
    }

    #[test_case]
    fn test_register_interface_allocates_unique_ids() {
        let mut mgr = NetworkManager::new();
        let a = mgr.register_interface(String::from("vnet0"));
        let b = mgr.register_interface(String::from("vnet1"));
        assert_ne!(a, b);
        assert_eq!(a, NetIfId(0));
        assert_eq!(b, NetIfId(1));
        assert_eq!(mgr.list_interfaces().len(), 2);
    }

    #[test_case]
    fn test_register_virtio_port_is_idempotent() {
        let mut mgr = NetworkManager::new();
        let if0 = mgr.register_virtio_port(0, None);
        let if0_again = mgr.register_virtio_port(0, None);
        let if1 = mgr.register_virtio_port(1, None);
        assert_eq!(if0, if0_again);
        assert_ne!(if0, if1);
        assert_eq!(mgr.lookup_if_by_virtio_index(0), Some(if0));
        assert_eq!(mgr.lookup_if_by_virtio_index(1), Some(if1));
    }

    #[test_case]
    fn test_ipv4_route_lookup_prefers_longest_prefix() {
        let mut mgr = NetworkManager::new();
        let if0 = mgr.register_interface(String::from("vnet0"));
        let if1 = mgr.register_interface(String::from("vnet1"));

        assert!(
            mgr.add_ipv4_route(v4route([10, 0, 0, 0], 8, if0, 1))
                .is_ok()
        );
        assert!(
            mgr.add_ipv4_route(v4route([10, 1, 0, 0], 16, if1, 100))
                .is_ok()
        );

        let route = mgr
            .lookup_ipv4_route(Ipv4Address::new([10, 1, 2, 3]))
            .expect("route");
        assert_eq!(route.if_id, if1);
        assert_eq!(route.prefix_len, 16);
    }

    #[test_case]
    fn test_ipv4_route_lookup_prefers_metric_then_ifid_tie_break() {
        let mut mgr = NetworkManager::new();
        let if0 = mgr.register_interface(String::from("vnet0"));
        let if1 = mgr.register_interface(String::from("vnet1"));

        assert!(
            mgr.add_ipv4_route(v4route([192, 168, 1, 0], 24, if0, 20))
                .is_ok()
        );
        assert!(
            mgr.add_ipv4_route(v4route([192, 168, 1, 0], 24, if1, 10))
                .is_ok()
        );

        let route = mgr
            .lookup_ipv4_route(Ipv4Address::new([192, 168, 1, 42]))
            .expect("route");
        assert_eq!(route.if_id, if1);

        let mut mgr2 = NetworkManager::new();
        let a = mgr2.register_interface(String::from("vnet0"));
        let b = mgr2.register_interface(String::from("vnet1"));
        assert!(
            mgr2.add_ipv4_route(v4route([172, 16, 0, 0], 12, b, 10))
                .is_ok()
        );
        assert!(
            mgr2.add_ipv4_route(v4route([172, 16, 0, 0], 12, a, 10))
                .is_ok()
        );
        let route2 = mgr2
            .lookup_ipv4_route(Ipv4Address::new([172, 16, 10, 1]))
            .expect("route");
        assert_eq!(route2.if_id, a);
    }

    #[test_case]
    fn test_ipv4_route_lookup_excludes_down_interface_and_uses_default() {
        let mut mgr = NetworkManager::new();
        let if0 = mgr.register_interface(String::from("vnet0"));
        let if1 = mgr.register_interface(String::from("vnet1"));
        assert!(
            mgr.add_ipv4_route(v4route([10, 0, 0, 0], 8, if0, 1))
                .is_ok()
        );
        assert!(
            mgr.set_default_route_v4(if1, Ipv4Address::new([192, 168, 0, 1]), 50)
                .is_ok()
        );
        assert!(mgr.set_interface_down(if0).is_ok());

        let route = mgr
            .lookup_ipv4_route(Ipv4Address::new([10, 2, 3, 4]))
            .expect("fallback default route");
        assert_eq!(route.if_id, if1);
        assert_eq!(route.prefix_len, 0);
        assert!(route.flags.default_route);
    }

    #[test_case]
    fn test_ipv6_route_lookup_lpm_metric_and_default() {
        let mut mgr = NetworkManager::new();
        let if0 = mgr.register_interface(String::from("vnet0"));
        let if1 = mgr.register_interface(String::from("vnet1"));
        let if2 = mgr.register_interface(String::from("vnet2"));

        assert!(
            mgr.add_ipv6_route(Ipv6Route {
                destination: Ipv6Address::new([
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                ]),
                prefix_len: 32,
                gateway: None,
                if_id: if0,
                metric: 100,
                flags: RouteFlags::static_route(),
                admin_enabled: true,
                managed_by_interface: false,
            })
            .is_ok()
        );
        assert!(
            mgr.add_ipv6_route(Ipv6Route {
                destination: Ipv6Address::new([
                    0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                ]),
                prefix_len: 48,
                gateway: None,
                if_id: if1,
                metric: 200,
                flags: RouteFlags::static_route(),
                admin_enabled: true,
                managed_by_interface: false,
            })
            .is_ok()
        );
        assert!(
            mgr.set_default_route_v6(
                if2,
                Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
                10
            )
            .is_ok()
        );

        let hit = mgr
            .lookup_ipv6_route(Ipv6Address::new([
                0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 9,
            ]))
            .expect("ipv6 route");
        assert_eq!(hit.if_id, if1);
        assert_eq!(hit.prefix_len, 48);

        let fallback = mgr
            .lookup_ipv6_route(Ipv6Address::new([
                0x26, 0x07, 0xf8, 0xb0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ]))
            .expect("ipv6 default route");
        assert_eq!(fallback.if_id, if2);
        assert_eq!(fallback.prefix_len, 0);
        assert!(fallback.flags.default_route);
    }
}
