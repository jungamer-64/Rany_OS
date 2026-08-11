// ============================================================================
// kernel/src/net/l4/socket.rs - L4 / ソケット
// ============================================================================
//! Generic L4 socket substrate shared by transport facades and runtime glue.

mod entry;
mod registry;
mod state;

use crate::net::l4::types::{EndpointAddr, EndpointError, SocketId};
use crate::net::runtime::{NetRuntimeHandle, manager::NetIfId};
use crate::net::types::InterfaceScope;

pub(crate) use self::entry::Socket;
pub(crate) use self::registry::{SocketFamily, SocketRegistry};
pub(crate) use self::state::TcpSocketState;

pub(crate) const DEFAULT_TCP_ACCEPT_BACKLOG: usize = self::state::SocketState::DEFAULT_BACKLOG;

fn with_socket_registry_in<R>(
    runtime: NetRuntimeHandle,
    f: impl FnOnce(&SocketRegistry) -> R,
) -> R {
    f(&runtime.context().sockets)
}

pub(crate) fn lookup_socket_in(runtime: NetRuntimeHandle, socket_id: SocketId) -> Option<Socket> {
    with_socket_registry_in(runtime, |registry| registry.get(socket_id))
}

pub(crate) fn unregister_socket_in(
    runtime: NetRuntimeHandle,
    socket_id: SocketId,
) -> Option<Socket> {
    with_socket_registry_in(runtime, |registry| registry.unregister(socket_id))
}

pub(crate) fn for_each_socket_in(runtime: NetRuntimeHandle, mut f: impl FnMut(Socket)) {
    with_socket_registry_in(runtime, |registry| registry.for_each(|socket| f(socket)));
}

pub(crate) fn allocate_tcp_ephemeral_port_in(runtime: NetRuntimeHandle) -> Option<u16> {
    with_socket_registry_in(runtime, SocketRegistry::allocate_tcp_ephemeral_port)
}

pub(crate) fn allocate_udp_ephemeral_port_in(runtime: NetRuntimeHandle) -> Option<u16> {
    with_socket_registry_in(runtime, SocketRegistry::allocate_udp_ephemeral_port)
}

pub(crate) fn bind_udp_dual_stack_in(
    runtime: NetRuntimeHandle,
    port: u16,
    scope: InterfaceScope,
    socket_id: SocketId,
) -> Result<(), EndpointError> {
    with_socket_registry_in(runtime, |registry| {
        registry.bind_udp_dual_stack(port, scope, socket_id)
    })
}

pub(crate) fn register_raw_scope_in(
    runtime: NetRuntimeHandle,
    scope: InterfaceScope,
    socket_id: SocketId,
) -> Result<(), EndpointError> {
    with_socket_registry_in(runtime, |registry| {
        registry.register_raw_scope(scope, socket_id)
    })
}

pub(crate) fn find_udp_by_port_in(
    runtime: NetRuntimeHandle,
    family: SocketFamily,
    port: u16,
    ingress_if_id: NetIfId,
) -> Option<Socket> {
    with_socket_registry_in(runtime, |registry| {
        registry.find_udp_by_port(family, port, ingress_if_id)
    })
}

pub(crate) fn find_raw_by_scope_in(
    runtime: NetRuntimeHandle,
    ingress_if_id: NetIfId,
) -> Option<Socket> {
    with_socket_registry_in(runtime, |registry| {
        registry.find_raw_by_scope(ingress_if_id)
    })
}

pub(crate) fn has_udp_port_in(runtime: NetRuntimeHandle, port: u16) -> bool {
    with_socket_registry_in(runtime, |registry| registry.has_udp_port(port))
}

pub(crate) fn find_listening_tcp_socket_in(
    runtime: NetRuntimeHandle,
    local: EndpointAddr,
    ingress_if_id: NetIfId,
) -> Option<Socket> {
    registry::find_listening_tcp_socket_in(runtime, local, ingress_if_id)
}

pub(crate) fn generate_socket_id_in(runtime: NetRuntimeHandle) -> Option<SocketId> {
    with_socket_registry_in(runtime, SocketRegistry::generate_socket_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::runtime::{create_runtime, default_runtime, reset_runtime_registry_for_tests};

    #[test]
    fn two_runtimes_can_bind_same_udp_port_independently() {
        reset_runtime_registry_for_tests();

        let runtime_a = default_runtime();
        let runtime_b = create_runtime().expect("second runtime");
        let socket_a = Socket::new_udp_in(runtime_a);
        let socket_b = Socket::new_udp_in(runtime_b);

        assert_eq!(socket_a.socket_id(), socket_b.socket_id());
        assert!(
            bind_udp_dual_stack_in(runtime_a, 80, InterfaceScope::Any, socket_a.socket_id())
                .is_ok()
        );
        assert!(
            bind_udp_dual_stack_in(runtime_b, 80, InterfaceScope::Any, socket_b.socket_id())
                .is_ok()
        );
        assert!(find_udp_by_port_in(runtime_a, SocketFamily::Ipv4, 80, None).is_some());
        assert!(find_udp_by_port_in(runtime_b, SocketFamily::Ipv4, 80, None).is_some());
    }
}
