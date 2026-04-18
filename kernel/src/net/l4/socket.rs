//! Generic L4 socket substrate shared by transport facades and runtime glue.

mod entry;
mod registry;
mod state;

use self::registry::{SOCKET_REGISTRY, SocketRegistry};
use crate::net::l4::types::{EndpointAddr, EndpointError, EndpointFd, EndpointType};
use crate::net::runtime::manager::NetIfId;
use crate::net::types::InterfaceScope;

pub(crate) use self::entry::Endpoint;
pub(crate) use self::registry::SocketFamily;

pub(crate) const DEFAULT_TCP_ACCEPT_BACKLOG: usize =
    self::state::EndpointInner::DEFAULT_BACKLOG;

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

pub(crate) fn lookup_endpoint(fd: EndpointFd) -> Option<Endpoint> {
    with_socket_registry(|registry| registry.get(fd)).flatten()
}

pub(crate) fn register_endpoint(endpoint: Endpoint) {
    let guard = SOCKET_REGISTRY.read().unwrap_or_else(|e| e.into_inner());
    if let Some(registry) = guard.as_ref() {
        registry.register(endpoint);
    }
}

pub(crate) fn unregister_endpoint(fd: EndpointFd) -> Option<Endpoint> {
    let guard = SOCKET_REGISTRY.read().unwrap_or_else(|e| e.into_inner());
    guard.as_ref().and_then(|registry| registry.unregister(fd))
}

pub(crate) fn for_each_endpoint(mut f: impl FnMut(&Endpoint)) {
    let guard = SOCKET_REGISTRY.read().unwrap_or_else(|e| e.into_inner());
    if let Some(registry) = guard.as_ref() {
        registry.for_each(|endpoint| f(endpoint));
    }
}

pub(crate) fn allocate_ephemeral_port(endpoint_type: EndpointType) -> Option<u16> {
    with_socket_registry(|registry| registry.allocate_ephemeral_port(endpoint_type)).flatten()
}

pub(crate) fn bind_udp_dual_stack(
    port: u16,
    scope: InterfaceScope,
    fd: EndpointFd,
) -> Result<(), EndpointError> {
    let guard = SOCKET_REGISTRY.read().unwrap_or_else(|e| e.into_inner());
    if let Some(registry) = guard.as_ref() {
        registry.bind_udp_dual_stack(port, scope, fd)
    } else {
        Err(EndpointError::NotFound)
    }
}

pub(crate) fn register_raw_scope(
    scope: InterfaceScope,
    fd: EndpointFd,
) -> Result<(), EndpointError> {
    let guard = SOCKET_REGISTRY.read().unwrap_or_else(|e| e.into_inner());
    if let Some(registry) = guard.as_ref() {
        registry.register_raw_scope(scope, fd)
    } else {
        Err(EndpointError::NotFound)
    }
}

pub(crate) fn find_endpoint_by_port(
    endpoint_type: EndpointType,
    family: SocketFamily,
    port: u16,
    ingress_if_id: Option<NetIfId>,
) -> Option<Endpoint> {
    with_socket_registry(|registry| registry.find_by_port(endpoint_type, family, port, ingress_if_id))
        .flatten()
}

pub(crate) fn find_raw_endpoint(ingress_if_id: NetIfId) -> Option<Endpoint> {
    with_socket_registry(|registry| registry.find_raw_endpoint(ingress_if_id)).flatten()
}

pub(crate) fn has_udp_port(port: u16) -> bool {
    with_socket_registry(|registry| registry.has_udp_port(port)).unwrap_or(false)
}

pub(crate) fn find_listening_tcp_socket(
    local: EndpointAddr,
    ingress_if_id: Option<NetIfId>,
) -> Option<Endpoint> {
    registry::find_listening_tcp_socket(local, ingress_if_id)
}

pub(crate) fn generate_endpoint_fd() -> Option<EndpointFd> {
    with_socket_registry(|registry| registry.generate_fd())
}
