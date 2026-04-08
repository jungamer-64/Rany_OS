// ============================================================================
// kernel/src/net/l4/endpoint/manager.rs
// ============================================================================
//! # EndpointManager - RwLockによる読み取り並列化
//!
//! ソケット管理マネージャ

use crate::sync::PoisonRwLock;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU32, Ordering};

use super::endpoint_core::Endpoint;
use super::types::{EndpointAddr, EndpointError, EndpointFd, EndpointResult, EndpointType};
use crate::net::runtime::manager::NetIfId;
use crate::net::types::InterfaceScope;
use kernel_api::resource::net::PacketPayload;

const EPHEMERAL_PORT_START: u16 = 49152;
const EPHEMERAL_PORT_END: u16 = 65535;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EndpointFamily {
    Ipv4,
    Ipv6,
}

impl EndpointFamily {
    pub(crate) fn from_addr(addr: EndpointAddr) -> Self {
        if addr.is_ipv6() {
            Self::Ipv6
        } else {
            Self::Ipv4
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct PortBindingKey {
    family: EndpointFamily,
    port: u16,
    scope: InterfaceScope,
}

impl PortBindingKey {
    fn new(family: EndpointFamily, port: u16, scope: InterfaceScope) -> Self {
        Self {
            family,
            port,
            scope,
        }
    }
}

fn scopes_conflict(lhs: InterfaceScope, rhs: InterfaceScope) -> bool {
    match (lhs, rhs) {
        (InterfaceScope::Any, _) | (_, InterfaceScope::Any) => true,
        (InterfaceScope::Pinned(a), InterfaceScope::Pinned(b)) => a == b,
    }
}

pub struct EndpointManager {
    endpoints: PoisonRwLock<BTreeMap<EndpointFd, Endpoint>>,
    tcp_ports: PoisonRwLock<BTreeMap<PortBindingKey, EndpointFd>>,
    udp_ports: PoisonRwLock<BTreeMap<PortBindingKey, EndpointFd>>,
    raw_endpoints: PoisonRwLock<BTreeMap<InterfaceScope, EndpointFd>>,
    next_ephemeral_port: AtomicU32,
}

impl EndpointManager {
    pub const fn new() -> Self {
        Self {
            endpoints: PoisonRwLock::new(BTreeMap::new()),
            tcp_ports: PoisonRwLock::new(BTreeMap::new()),
            udp_ports: PoisonRwLock::new(BTreeMap::new()),
            raw_endpoints: PoisonRwLock::new(BTreeMap::new()),
            next_ephemeral_port: AtomicU32::new(EPHEMERAL_PORT_START as u32),
        }
    }

    pub fn allocate_ephemeral_port(&self, endpoint_type: EndpointType) -> Option<u16> {
        let ports = match endpoint_type {
            EndpointType::Tcp => &self.tcp_ports,
            EndpointType::Udp => &self.udp_ports,
            _ => return Some(0),
        };

        // RFC 6056: Use a random starting point for port selection to prevent prediction attacks.
        let random_bytes = crate::net::security::tls::crypto::random::generate_random();
        let random_start = u16::from_be_bytes([random_bytes[0], random_bytes[1]]);

        let range_size = (EPHEMERAL_PORT_END - EPHEMERAL_PORT_START + 1) as u16;
        let start_port = EPHEMERAL_PORT_START + (random_start % range_size);

        let ports_guard = ports.read().unwrap_or_else(|e| e.into_inner());
        for i in 0..range_size {
            let port = EPHEMERAL_PORT_START
                + ((start_port
                    .wrapping_sub(EPHEMERAL_PORT_START)
                    .wrapping_add(i))
                    % range_size);
            let conflict = ports_guard
                .keys()
                .any(|key| key.port == port && matches!(key.scope, InterfaceScope::Any));
            if !conflict {
                // Update the counter for the next sequential-ish attempt (if we still want it)
                // but since we randomized the start above, the counter is less critical.
                self.next_ephemeral_port
                    .store(port.wrapping_add(1) as u32, Ordering::Relaxed);
                return Some(port);
            }
        }
        None
    }

    pub fn register(&self, endpoint: Endpoint) {
        self.endpoints
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(endpoint.fd(), endpoint);
    }

    pub fn unregister(&self, fd: EndpointFd) -> Option<Endpoint> {
        let removed = self
            .endpoints
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&fd);
        if let Some(ref s) = removed {
            match s.socket_type() {
                EndpointType::Tcp => {
                    self.tcp_ports
                        .write()
                        .unwrap_or_else(|e| e.into_inner())
                        .retain(|_, bound_fd| *bound_fd != fd);
                }
                EndpointType::Udp => {
                    self.udp_ports
                        .write()
                        .unwrap_or_else(|e| e.into_inner())
                        .retain(|_, bound_fd| *bound_fd != fd);
                    if let Some(token) = s
                        .inner()
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .udp_mut()
                        .and_then(|udp| udp.token.take())
                    {
                        let _ = crate::security::capability::manager().decrement_in_flight(token);
                    }
                }
                EndpointType::Raw => {
                    self.raw_endpoints
                        .write()
                        .unwrap_or_else(|e| e.into_inner())
                        .retain(|_, bound_fd| *bound_fd != fd);
                }
            }
        }
        removed
    }

    pub fn get(&self, fd: EndpointFd) -> Option<Endpoint> {
        self.endpoints
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&fd)
            .cloned()
    }

    pub fn bind_port(
        &self,
        endpoint_type: EndpointType,
        family: EndpointFamily,
        port: u16,
        scope: InterfaceScope,
        fd: EndpointFd,
    ) -> EndpointResult<()> {
        let ports = match endpoint_type {
            EndpointType::Tcp => &self.tcp_ports,
            EndpointType::Udp => &self.udp_ports,
            _ => return Ok(()),
        };

        let mut guard = ports.write().unwrap_or_else(|e| e.into_inner());
        if guard.keys().any(|key| {
            key.family == family && key.port == port && scopes_conflict(key.scope, scope)
        }) {
            return Err(EndpointError::PortInUse);
        }
        guard.insert(PortBindingKey::new(family, port, scope), fd);
        Ok(())
    }

    pub fn bind_udp_dual_stack(
        &self,
        port: u16,
        scope: InterfaceScope,
        fd: EndpointFd,
    ) -> EndpointResult<()> {
        let mut guard = self.udp_ports.write().unwrap_or_else(|e| e.into_inner());
        let ipv4 = PortBindingKey::new(EndpointFamily::Ipv4, port, scope);
        let ipv6 = PortBindingKey::new(EndpointFamily::Ipv6, port, scope);
        let ipv4_conflict = guard.keys().any(|key| {
            key.family == EndpointFamily::Ipv4
                && key.port == port
                && scopes_conflict(key.scope, scope)
        });
        let ipv6_conflict = guard.keys().any(|key| {
            key.family == EndpointFamily::Ipv6
                && key.port == port
                && scopes_conflict(key.scope, scope)
        });
        if ipv4_conflict || ipv6_conflict {
            return Err(EndpointError::PortInUse);
        }
        guard.insert(ipv4, fd);
        guard.insert(ipv6, fd);
        Ok(())
    }

    pub fn register_raw_scope(&self, scope: InterfaceScope, fd: EndpointFd) -> EndpointResult<()> {
        let mut guard = self
            .raw_endpoints
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if guard.contains_key(&scope) {
            return Err(EndpointError::ResourceExhausted);
        }
        guard.insert(scope, fd);
        Ok(())
    }

    pub fn find_raw_endpoint(&self, ingress_if_id: NetIfId) -> Option<Endpoint> {
        let fd = {
            let guard = self.raw_endpoints.read().unwrap_or_else(|e| e.into_inner());
            guard
                .get(&InterfaceScope::Pinned(ingress_if_id))
                .copied()
                .or_else(|| guard.get(&InterfaceScope::Any).copied())
        }?;
        self.get(fd)
    }

    pub fn find_by_port(
        &self,
        endpoint_type: EndpointType,
        family: EndpointFamily,
        port: u16,
        ingress_if_id: Option<NetIfId>,
    ) -> Option<Endpoint> {
        if endpoint_type == EndpointType::Udp {
            let guard = self.udp_ports.read().unwrap_or_else(|e| e.into_inner());
            let fd = ingress_if_id
                .map(|if_id| PortBindingKey::new(family, port, InterfaceScope::Pinned(if_id)))
                .and_then(|key| guard.get(&key).copied())
                .or_else(|| {
                    guard
                        .get(&PortBindingKey::new(family, port, InterfaceScope::Any))
                        .copied()
                })?;
            drop(guard);
            return self.get(fd);
        }

        let endpoints = self.endpoints.read().unwrap_or_else(|e| e.into_inner());
        let mut wildcard = None;
        for endpoint in endpoints.values() {
            if endpoint.socket_type() != endpoint_type {
                continue;
            }
            let inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
            let Some(local_addr) = inner.local_addr else {
                continue;
            };
            if EndpointFamily::from_addr(local_addr) != family || local_addr.port() != port {
                continue;
            }

            match (inner.scope, ingress_if_id) {
                (InterfaceScope::Pinned(bound_if), Some(ingress_if)) if bound_if == ingress_if => {
                    return Some(endpoint.clone());
                }
                (InterfaceScope::Any, _) => wildcard = Some(endpoint.clone()),
                _ => {}
            }
        }
        wildcard
    }

    pub fn unregister_udp_binding(&self, scope: InterfaceScope, port: u16) -> bool {
        let fds = {
            let guard = self.udp_ports.read().unwrap_or_else(|e| e.into_inner());
            let mut unique = alloc::collections::BTreeSet::new();
            for (key, fd) in guard.iter() {
                if key.port == port && key.scope == scope {
                    unique.insert(*fd);
                }
            }
            unique
        };

        if fds.is_empty() {
            return false;
        }

        for fd in fds {
            let _ = self.unregister(fd);
        }
        true
    }

    pub fn endpoint_count(&self) -> usize {
        self.endpoints
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    pub fn for_each<F>(&self, mut f: F)
    where
        F: FnMut(&Endpoint),
    {
        let endpoints = self.endpoints.read().unwrap_or_else(|e| e.into_inner());
        for ep in endpoints.values() {
            f(ep);
        }
    }

    pub fn generate_fd(&self) -> EndpointFd {
        static FD_COUNTER: AtomicU32 = AtomicU32::new(1);
        EndpointFd::from_raw(FD_COUNTER.fetch_add(1, Ordering::Relaxed))
    }
}

impl Default for EndpointManager {
    fn default() -> Self {
        Self::new()
    }
}

pub static ENDPOINT_MANAGER: PoisonRwLock<Option<EndpointManager>> = PoisonRwLock::new(None);

pub fn init_endpoint_manager() {
    *ENDPOINT_MANAGER.write().unwrap_or_else(|e| e.into_inner()) = Some(EndpointManager::new());
}

pub fn is_endpoint_manager_initialized() -> bool {
    ENDPOINT_MANAGER
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .is_some()
}

pub fn endpoint_manager() -> Option<&'static PoisonRwLock<Option<EndpointManager>>> {
    Some(&ENDPOINT_MANAGER)
}

pub fn find_listening_socket(
    local: EndpointAddr,
    ingress_if_id: Option<NetIfId>,
) -> Option<Endpoint> {
    let manager = ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner());
    let mgr = manager.as_ref()?;
    let socket = mgr.find_by_port(
        EndpointType::Tcp,
        EndpointFamily::from_addr(local),
        local.port(),
        ingress_if_id,
    )?;
    let inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
    if inner.state == super::types::EndpointState::Listening {
        Some(socket.clone())
    } else {
        None
    }
}

pub fn deliver_raw_payload(ingress_if_id: NetIfId, payload: PacketPayload) -> bool {
    let Some(mgr_lock) = endpoint_manager() else {
        return false;
    };
    let guard = mgr_lock.read().unwrap_or_else(|e| e.into_inner());
    let Some(mgr) = guard.as_ref() else {
        return false;
    };
    let Some(endpoint) = mgr.find_raw_endpoint(ingress_if_id) else {
        return false;
    };
    endpoint.deliver_raw_payload(ingress_if_id, payload).is_ok()
}
