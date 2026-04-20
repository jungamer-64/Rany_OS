//! Generic L4 socket substrate shared by transport facades and runtime glue.

mod entry;
mod registry;
mod state;

use self::registry::{SOCKET_REGISTRY, SocketRegistry};
use crate::net::l4::types::{EndpointAddr, EndpointError, SocketId};
use crate::net::runtime::manager::NetIfId;
use crate::net::types::InterfaceScope;

pub(crate) use self::entry::Socket;
pub(crate) use self::registry::SocketFamily;
pub(crate) use self::state::TcpSocketState;

pub(crate) const DEFAULT_TCP_ACCEPT_BACKLOG: usize = self::state::SocketState::DEFAULT_BACKLOG;

fn with_socket_registry<R>(f: impl FnOnce(&SocketRegistry) -> R) -> Option<R> {
    let guard = SOCKET_REGISTRY.read().unwrap_or_else(|e| e.into_inner());
    guard.as_ref().map(f)
}

pub(crate) fn socket_registry_initialized() -> bool {
    let guard = SOCKET_REGISTRY.read().unwrap_or_else(|e| e.into_inner());
    guard.is_some()
}

pub(crate) fn init_socket_registry() {
    registry::init_socket_registry();
}

pub(crate) fn lookup_socket(socket_id: SocketId) -> Option<Socket> {
    with_socket_registry(|registry| registry.get(socket_id)).flatten()
}

pub(crate) fn register_socket(socket: Socket) {
    let guard = SOCKET_REGISTRY.read().unwrap_or_else(|e| e.into_inner());
    if let Some(registry) = guard.as_ref() {
        registry.register(socket);
    }
}

pub(crate) fn unregister_socket(socket_id: SocketId) -> Option<Socket> {
    let guard = SOCKET_REGISTRY.read().unwrap_or_else(|e| e.into_inner());
    guard
        .as_ref()
        .and_then(|registry| registry.unregister(socket_id))
}

pub(crate) fn for_each_socket(mut f: impl FnMut(&Socket)) {
    let guard = SOCKET_REGISTRY.read().unwrap_or_else(|e| e.into_inner());
    if let Some(registry) = guard.as_ref() {
        registry.for_each(|socket| f(socket));
    }
}

pub(crate) fn allocate_tcp_ephemeral_port() -> Option<u16> {
    with_socket_registry(SocketRegistry::allocate_tcp_ephemeral_port).flatten()
}

pub(crate) fn allocate_udp_ephemeral_port() -> Option<u16> {
    with_socket_registry(SocketRegistry::allocate_udp_ephemeral_port).flatten()
}

pub(crate) fn bind_tcp_port(
    family: SocketFamily,
    port: u16,
    scope: InterfaceScope,
    socket_id: SocketId,
) -> Result<(), EndpointError> {
    let guard = SOCKET_REGISTRY.read().unwrap_or_else(|e| e.into_inner());
    if let Some(registry) = guard.as_ref() {
        registry.bind_tcp_port(family, port, scope, socket_id)
    } else {
        Err(EndpointError::NotFound)
    }
}

pub(crate) fn bind_udp_dual_stack(
    port: u16,
    scope: InterfaceScope,
    socket_id: SocketId,
) -> Result<(), EndpointError> {
    let guard = SOCKET_REGISTRY.read().unwrap_or_else(|e| e.into_inner());
    if let Some(registry) = guard.as_ref() {
        registry.bind_udp_dual_stack(port, scope, socket_id)
    } else {
        Err(EndpointError::NotFound)
    }
}

pub(crate) fn register_raw_scope(
    scope: InterfaceScope,
    socket_id: SocketId,
) -> Result<(), EndpointError> {
    let guard = SOCKET_REGISTRY.read().unwrap_or_else(|e| e.into_inner());
    if let Some(registry) = guard.as_ref() {
        registry.register_raw_scope(scope, socket_id)
    } else {
        Err(EndpointError::NotFound)
    }
}

pub(crate) fn find_tcp_by_port(
    family: SocketFamily,
    port: u16,
    ingress_if_id: Option<NetIfId>,
) -> Option<Socket> {
    with_socket_registry(|registry| registry.find_tcp_by_port(family, port, ingress_if_id))
        .flatten()
}

pub(crate) fn find_udp_by_port(
    family: SocketFamily,
    port: u16,
    ingress_if_id: Option<NetIfId>,
) -> Option<Socket> {
    with_socket_registry(|registry| registry.find_udp_by_port(family, port, ingress_if_id))
        .flatten()
}

pub(crate) fn find_raw_by_scope(ingress_if_id: NetIfId) -> Option<Socket> {
    with_socket_registry(|registry| registry.find_raw_by_scope(ingress_if_id)).flatten()
}

pub(crate) fn has_udp_port(port: u16) -> bool {
    with_socket_registry(|registry| registry.has_udp_port(port)).unwrap_or(false)
}

pub(crate) fn find_listening_tcp_socket(
    local: EndpointAddr,
    ingress_if_id: Option<NetIfId>,
) -> Option<Socket> {
    registry::find_listening_tcp_socket(local, ingress_if_id)
}

pub(crate) fn generate_socket_id() -> Option<SocketId> {
    with_socket_registry(SocketRegistry::generate_socket_id)
}
