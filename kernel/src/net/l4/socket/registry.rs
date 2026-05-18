// ============================================================================
// kernel/src/net/l4/socket/registry.rs - L4 / ソケット / レジストリ
// ============================================================================
//! Socket registry indexed by protocol-specific lookup tables.

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::net::l4::socket::Socket;
use crate::net::l4::socket::state::SocketState;
use crate::net::l4::types::{EndpointAddr, EndpointError, SocketId, SocketResult};
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::manager::NetIfId;
use crate::net::types::InterfaceScope;
use crate::sync::{PoisonLock, PoisonRwLock};

const EPHEMERAL_PORT_START: u16 = 49152;
const EPHEMERAL_PORT_END: u16 = 65535;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum SocketFamily {
    Ipv4,
    Ipv6,
}

impl SocketFamily {
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
    family: SocketFamily,
    port: u16,
    scope: InterfaceScope,
}

impl PortBindingKey {
    fn new(family: SocketFamily, port: u16, scope: InterfaceScope) -> Self {
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

fn random_ephemeral_start() -> u16 {
    let random_bytes = crate::net::security::tls::crypto::random_or_panic("network random");
    let random_start = u16::from_be_bytes([random_bytes[0], random_bytes[1]]);
    let range_size = EPHEMERAL_PORT_END - EPHEMERAL_PORT_START + 1;
    EPHEMERAL_PORT_START + (random_start % range_size)
}

fn allocate_ephemeral_port_from(
    ports: &PoisonRwLock<BTreeMap<PortBindingKey, SocketId>>,
    next_ephemeral_port: &AtomicU32,
) -> Option<u16> {
    let range_size = EPHEMERAL_PORT_END - EPHEMERAL_PORT_START + 1;
    let start_port = random_ephemeral_start();
    let ports_guard = ports.read().unwrap_or_else(|e| e.into_inner());
    for offset in 0..range_size {
        let port = EPHEMERAL_PORT_START
            + ((start_port
                .wrapping_sub(EPHEMERAL_PORT_START)
                .wrapping_add(offset))
                % range_size);
        let conflict = ports_guard
            .keys()
            .any(|key| key.port == port && matches!(key.scope, InterfaceScope::Any));
        if !conflict {
            next_ephemeral_port.store(port.wrapping_add(1) as u32, Ordering::Relaxed);
            return Some(port);
        }
    }
    None
}

fn bind_port(
    ports: &PoisonRwLock<BTreeMap<PortBindingKey, SocketId>>,
    family: SocketFamily,
    port: u16,
    scope: InterfaceScope,
    socket_id: SocketId,
) -> SocketResult<()> {
    let mut guard = ports.write().unwrap_or_else(|e| e.into_inner());
    if guard
        .keys()
        .any(|key| key.family == family && key.port == port && scopes_conflict(key.scope, scope))
    {
        return Err(EndpointError::PortInUse);
    }
    guard.insert(PortBindingKey::new(family, port, scope), socket_id);
    Ok(())
}

fn find_socket_by_port(
    ports: &PoisonRwLock<BTreeMap<PortBindingKey, SocketId>>,
    sockets: &PoisonRwLock<BTreeMap<SocketId, SocketRecord>>,
    family: SocketFamily,
    port: u16,
    ingress_if_id: Option<NetIfId>,
) -> Option<Socket> {
    let guard = ports.read().unwrap_or_else(|e| e.into_inner());
    let socket_id = ingress_if_id
        .map(|if_id| PortBindingKey::new(family, port, InterfaceScope::Pinned(if_id)))
        .and_then(|key| guard.get(&key).copied())
        .or_else(|| {
            guard
                .get(&PortBindingKey::new(family, port, InterfaceScope::Any))
                .copied()
        })?;
    drop(guard);
    sockets
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&socket_id)
        .map(|record| Socket::from_registered(socket_id, record.runtime))
}

pub(crate) struct SocketRecord {
    runtime: NetRuntimeHandle,
    state: PoisonLock<SocketState>,
}

impl SocketRecord {
    fn new(runtime: NetRuntimeHandle, state: SocketState) -> Self {
        Self {
            runtime,
            state: PoisonLock::new(state),
        }
    }
}

pub(crate) struct SocketRegistry {
    sockets: PoisonRwLock<BTreeMap<SocketId, SocketRecord>>,
    tcp_ports: PoisonRwLock<BTreeMap<PortBindingKey, SocketId>>,
    udp_ports: PoisonRwLock<BTreeMap<PortBindingKey, SocketId>>,
    raw_scopes: PoisonRwLock<BTreeMap<InterfaceScope, SocketId>>,
    next_socket_id: AtomicU32,
    next_ephemeral_port: AtomicU32,
}

impl SocketRegistry {
    pub const fn new() -> Self {
        Self {
            sockets: PoisonRwLock::new(BTreeMap::new()),
            tcp_ports: PoisonRwLock::new(BTreeMap::new()),
            udp_ports: PoisonRwLock::new(BTreeMap::new()),
            raw_scopes: PoisonRwLock::new(BTreeMap::new()),
            next_socket_id: AtomicU32::new(1),
            next_ephemeral_port: AtomicU32::new(EPHEMERAL_PORT_START as u32),
        }
    }

    pub fn allocate_tcp_ephemeral_port(&self) -> Option<u16> {
        allocate_ephemeral_port_from(&self.tcp_ports, &self.next_ephemeral_port)
    }

    pub fn allocate_udp_ephemeral_port(&self) -> Option<u16> {
        allocate_ephemeral_port_from(&self.udp_ports, &self.next_ephemeral_port)
    }

    pub fn register(&self, socket: Socket, state: SocketState) {
        self.sockets
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                socket.socket_id(),
                SocketRecord::new(socket.runtime(), state),
            );
    }

    pub fn unregister(&self, socket_id: SocketId) -> Option<Socket> {
        let removed = self
            .sockets
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&socket_id);
        if let Some(record) = removed.as_ref() {
            let socket = Socket::from_registered(socket_id, record.runtime);
            let state = record.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.is_tcp() {
                self.tcp_ports
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .retain(|_, bound_socket_id| *bound_socket_id != socket_id);
            } else if state.is_udp() {
                self.udp_ports
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .retain(|_, bound_socket_id| *bound_socket_id != socket_id);
                drop(state);
                let mut state = record.state.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(token) = state.udp_mut().and_then(|udp| udp.token.take()) {
                    let _ = crate::security::capability::manager().decrement_in_flight(token);
                }
            } else if state.is_raw() {
                self.raw_scopes
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .retain(|_, bound_socket_id| *bound_socket_id != socket_id);
            }
            return Some(socket);
        }
        None
    }

    pub fn get(&self, socket_id: SocketId) -> Option<Socket> {
        self.sockets
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&socket_id)
            .map(|record| Socket::from_registered(socket_id, record.runtime))
    }

    pub fn with_socket_state<R>(
        &self,
        socket_id: SocketId,
        f: impl FnOnce(&SocketState) -> R,
    ) -> Option<R> {
        let sockets = self.sockets.read().unwrap_or_else(|e| e.into_inner());
        let record = sockets.get(&socket_id)?;
        let state = record.state.lock().unwrap_or_else(|e| e.into_inner());
        Some(f(&state))
    }

    pub fn with_socket_state_mut<R>(
        &self,
        socket_id: SocketId,
        f: impl FnOnce(&mut SocketState) -> R,
    ) -> Option<R> {
        let sockets = self.sockets.read().unwrap_or_else(|e| e.into_inner());
        let record = sockets.get(&socket_id)?;
        let mut state = record.state.lock().unwrap_or_else(|e| e.into_inner());
        Some(f(&mut state))
    }

    pub fn bind_tcp_port(
        &self,
        family: SocketFamily,
        port: u16,
        scope: InterfaceScope,
        socket_id: SocketId,
    ) -> SocketResult<()> {
        bind_port(&self.tcp_ports, family, port, scope, socket_id)
    }

    pub fn bind_udp_dual_stack(
        &self,
        port: u16,
        scope: InterfaceScope,
        socket_id: SocketId,
    ) -> SocketResult<()> {
        let mut guard = self.udp_ports.write().unwrap_or_else(|e| e.into_inner());
        let ipv4 = PortBindingKey::new(SocketFamily::Ipv4, port, scope);
        let ipv6 = PortBindingKey::new(SocketFamily::Ipv6, port, scope);
        let ipv4_conflict = guard.keys().any(|key| {
            key.family == SocketFamily::Ipv4
                && key.port == port
                && scopes_conflict(key.scope, scope)
        });
        let ipv6_conflict = guard.keys().any(|key| {
            key.family == SocketFamily::Ipv6
                && key.port == port
                && scopes_conflict(key.scope, scope)
        });
        if ipv4_conflict || ipv6_conflict {
            return Err(EndpointError::PortInUse);
        }
        guard.insert(ipv4, socket_id);
        guard.insert(ipv6, socket_id);
        Ok(())
    }

    pub fn register_raw_scope(
        &self,
        scope: InterfaceScope,
        socket_id: SocketId,
    ) -> SocketResult<()> {
        let mut guard = self.raw_scopes.write().unwrap_or_else(|e| e.into_inner());
        if guard.contains_key(&scope) {
            return Err(EndpointError::ResourceExhausted);
        }
        guard.insert(scope, socket_id);
        Ok(())
    }

    pub fn find_tcp_by_port(
        &self,
        family: SocketFamily,
        port: u16,
        ingress_if_id: Option<NetIfId>,
    ) -> Option<Socket> {
        find_socket_by_port(&self.tcp_ports, &self.sockets, family, port, ingress_if_id)
    }

    pub fn find_udp_by_port(
        &self,
        family: SocketFamily,
        port: u16,
        ingress_if_id: Option<NetIfId>,
    ) -> Option<Socket> {
        find_socket_by_port(&self.udp_ports, &self.sockets, family, port, ingress_if_id)
    }

    pub fn find_raw_by_scope(&self, ingress_if_id: NetIfId) -> Option<Socket> {
        let socket_id = {
            let guard = self.raw_scopes.read().unwrap_or_else(|e| e.into_inner());
            guard
                .get(&InterfaceScope::Pinned(ingress_if_id))
                .copied()
                .or_else(|| guard.get(&InterfaceScope::Any).copied())
        }?;
        self.get(socket_id)
    }

    pub fn has_udp_port(&self, port: u16) -> bool {
        self.udp_ports
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .any(|key| key.port == port)
    }

    pub fn for_each<F>(&self, mut f: F)
    where
        F: FnMut(Socket),
    {
        let sockets = self.sockets.read().unwrap_or_else(|e| e.into_inner());
        for (socket_id, record) in sockets.iter() {
            f(Socket::from_registered(*socket_id, record.runtime));
        }
    }

    pub fn generate_socket_id(&self) -> Option<SocketId> {
        loop {
            let current = self.next_socket_id.load(Ordering::Relaxed);
            if current == SocketId::INVALID.raw() {
                return None;
            }
            let next = current.checked_add(1)?;
            if self
                .next_socket_id
                .compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return Some(SocketId::from_raw(current));
            }
        }
    }
}

impl Default for SocketRegistry {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn find_listening_tcp_socket_in(
    runtime: NetRuntimeHandle,
    local: EndpointAddr,
    ingress_if_id: Option<NetIfId>,
) -> Option<Socket> {
    let socket = runtime.context().sockets.find_tcp_by_port(
        SocketFamily::from_addr(local),
        local.port(),
        ingress_if_id,
    )?;
    socket
        .with_inner(|inner| inner.is_tcp_listening().then_some(socket))
        .flatten()
}
