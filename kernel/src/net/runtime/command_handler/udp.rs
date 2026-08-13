// ============================================================================
// kernel/src/net/runtime/command_handler/udp.rs - ランタイム / コマンドハンドラ / UDP
// ============================================================================
//! RuntimeCommandHandler UDP系メソッド

use super::*;
use crate::net::l3::ipv4::Ipv4Address;
use crate::net::l4::udp::UdpPorts;
use crate::net::runtime::command_handler::common::endpoint_error_from_network;

impl RuntimeCommandHandler {
    /// UDPパケットの処理
    pub(super) fn handle_udp_ingress_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        if_id: NetIfId,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        data_len: usize,
        ttl: u8,
        stack: &mut crate::net::runtime::stack::NetworkStack,
        packet: crate::net::payload::OwnedPayloadWindow,
        current_time: u64,
    ) -> EventHandleResult {
        if data_len > u16::MAX as usize {
            return EventHandleResult::Success;
        }

        let _ = runtime;
        let _ = src_port;
        let _ = dst_port;
        stack.process_udp_payload(
            if_id,
            packet,
            crate::net::l3::ipv4::Ipv4Address::new(src_ip),
            crate::net::l3::ipv4::Ipv4Address::new(dst_ip),
            ttl,
            current_time,
        );

        EventHandleResult::Success
    }

    /// SendToイベント処理 (UDP)
    pub(super) fn handle_send_to_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        fd: SocketId,
        remote: EndpointAddr,
        payload: PacketPayload,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        let Some(socket) = crate::net::l4::socket::lookup_socket_in(runtime, fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let Some((local_addr, scope)) = socket.with_inner(|inner| (inner.local_addr, inner.scope))
        else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let local_port = local_addr.map(|a| a.port()).unwrap_or(0);
        if local_port == 0 {
            return EventHandleResult::ProtocolError(EndpointError::NotConnected);
        }

        let sent = if let Some(dst_v4) = remote.as_ipv4() {
            let dst_ip = Ipv4Address::new(dst_v4);
            let explicit_src = local_addr
                .and_then(|addr| addr.as_ipv4())
                .map(Ipv4Address::new)
                .filter(|ip| !ip.is_any());
            let mut outbound_payload = Some(payload);

            let if_id = match crate::net::runtime::manager::resolve_ipv4_interface_in(
                runtime, scope, dst_ip,
            ) {
                Ok(if_id) => if_id,
                Err(error) => {
                    return EventHandleResult::ProtocolError(endpoint_error_from_network(error));
                }
            };
            if let Some(src_ip) = explicit_src {
                stack.send_udp_raw_payload_on_with_src_ttl(
                    if_id,
                    src_ip,
                    dst_ip,
                    UdpPorts::new(local_port, remote.port()),
                    outbound_payload.take().expect("UDP payload must exist"),
                    64,
                )
            } else {
                stack.send_udp_raw_payload_on_auto_ttl(
                    if_id,
                    dst_ip,
                    UdpPorts::new(local_port, remote.port()),
                    outbound_payload.take().expect("UDP payload must exist"),
                    64,
                )
            }
        } else if remote.is_ipv6() && local_addr.map_or(false, |a| a.is_ipv6()) {
            let src_v6 = local_addr
                .map(|addr| crate::net::l3::ipv6::Ipv6Address::new(addr.as_ipv6()))
                .unwrap_or(crate::net::l3::ipv6::Ipv6Address::UNSPECIFIED);
            let dst_v6 = crate::net::l3::ipv6::Ipv6Address::new(remote.as_ipv6());

            let if_id = match crate::net::runtime::manager::resolve_ipv6_interface_in(
                runtime, scope, dst_v6,
            ) {
                Ok(if_id) => if_id,
                Err(error) => {
                    return EventHandleResult::ProtocolError(endpoint_error_from_network(error));
                }
            };
            stack
                .send_udp_v6_payload_on_with_ttl(
                    if_id,
                    src_v6,
                    dst_v6,
                    UdpPorts::new(local_port, remote.port()),
                    payload,
                    64,
                )
                .is_ok()
        } else {
            false
        };

        if sent {
            EventHandleResult::Success
        } else {
            EventHandleResult::ProtocolError(EndpointError::NetworkUnreachable)
        }
    }
}
