// ============================================================================
// kernel/src/net/l4/endpoint/handler/udp.rs
// ============================================================================
//! NetworkEventHandler UDP系メソッド

use super::*;
use crate::net::l3::ipv4::Ipv4Address;
use crate::net::l4::endpoint::handler::common::{
    endpoint_error_from_network, resolve_ingress_if_id_in,
};
use crate::net::l4::endpoint::manager::EndpointFamily;

impl NetworkEventHandler {
    /// UDPパケットの処理
    pub(super) fn handle_udp_ingress_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        if_id: Option<NetIfId>,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        data_len: usize,
        udp_segment_payload: Option<PacketPayload>,
        ttl: u8,
        stack: &mut crate::net::runtime::stack::NetworkStack,
        original_packet: PacketPayload,
        current_time: u64,
    ) -> EventHandleResult {
        if data_len > u16::MAX as usize {
            return EventHandleResult::Success;
        }

        let remote = EndpointAddr::new(src_ip, src_port);
        let ingress_if_id = resolve_ingress_if_id_in(runtime, if_id);
        let Some(udp_segment_payload) = udp_segment_payload else {
            return EventHandleResult::ProtocolError(EndpointError::ResourceExhausted);
        };

        let mut found = false;
        if let Some(ref mgr) = *ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner()) {
            if let Some(socket) = mgr.find_by_port(
                EndpointType::Udp,
                EndpointFamily::Ipv4,
                dst_port,
                Some(ingress_if_id),
            ) {
                if let Some(payload) =
                    crate::net::payload::retain_payload_window_owned(udp_segment_payload, 8, data_len)
                {
                    let _ = socket.deliver_udp_payload(ingress_if_id, remote, ttl, payload);
                } else {
                    log::warn!(
                        "[NET] UDP ingress payload allocation failed for {}:{} -> {}:{}",
                        EndpointAddr::new(src_ip, src_port),
                        src_port,
                        EndpointAddr::new(dst_ip, dst_port),
                        dst_port,
                    );
                    return EventHandleResult::Success;
                }
                found = true;
            }
        }

        if !found {
            // RFC 1122: Send ICMP Port Unreachable
            use crate::net::l3::icmp::DestUnreachCode;
            use crate::net::l3::ipv4::Ipv4Address;

            let src_v4 = Ipv4Address::new(src_ip);
            let dst_v4 = Ipv4Address::new(dst_ip);

            // Only send if it wasn't broadcast/multicast (RFC 1122)
            if !dst_v4.is_broadcast() && !dst_v4.is_multicast() {
                stack.send_icmp_error_payload(
                    src_v4,
                    DestUnreachCode::PortUnreachable,
                    None,
                    &original_packet,
                    current_time,
                );
            }
        }

        EventHandleResult::Success
    }

    /// SendToイベント処理 (UDP)
    pub(super) fn handle_send_to_with_stack(
        &self,
        fd: EndpointFd,
        remote: EndpointAddr,
        payload: PacketPayload,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        let manager = ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner());
        let Some(ref mgr) = *manager else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let Some(socket) = mgr.get(fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let (local_addr, scope) = {
            let inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
            let scope = match inner.scope {
                crate::net::types::InterfaceScope::Pinned(if_id) => {
                    crate::net::types::InterfaceScope::Pinned(if_id)
                }
                crate::net::types::InterfaceScope::Any => inner
                    .last_ingress_if_id
                    .map(crate::net::types::InterfaceScope::Pinned)
                    .unwrap_or(crate::net::types::InterfaceScope::Any),
            };
            (inner.local_addr, scope)
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

            match stack.resolve_ipv4_egress(scope, None, explicit_src, dst_ip) {
                Ok((Some(if_id), _, _)) => {
                    let pinned = crate::net::types::InterfaceScope::Pinned(if_id);
                    if let Some(src_ip) = explicit_src {
                        stack.send_udp_raw_payload_scoped_with_src_ttl(
                            pinned,
                            src_ip,
                            local_port,
                            dst_ip,
                            remote.port(),
                            outbound_payload
                                .take()
                                .expect("UDP payload must exist"),
                            64,
                        )
                    } else {
                        stack.send_udp_raw_payload_scoped_auto_ttl(
                            pinned,
                            local_port,
                            dst_ip,
                            remote.port(),
                            outbound_payload
                                .take()
                                .expect("UDP payload must exist"),
                            64,
                        )
                    }
                }
                Ok((None, _, _)) => {
                    if let Some(src_ip) = explicit_src {
                        stack.send_udp_raw_payload_scoped_with_src_ttl(
                            crate::net::types::InterfaceScope::Any,
                            src_ip,
                            local_port,
                            dst_ip,
                            remote.port(),
                            outbound_payload
                                .take()
                                .expect("UDP payload must exist"),
                            64,
                        )
                    } else {
                        stack.send_udp_raw_payload_scoped_auto_ttl(
                            crate::net::types::InterfaceScope::Any,
                            local_port,
                            dst_ip,
                            remote.port(),
                            outbound_payload
                                .take()
                                .expect("UDP payload must exist"),
                            64,
                        )
                    }
                }
                Err(error) => {
                    return EventHandleResult::ProtocolError(endpoint_error_from_network(error));
                }
            }
        } else if remote.is_ipv6() && local_addr.map_or(false, |a| a.is_ipv6()) {
            let src_v6 = local_addr
                .map(|addr| crate::net::l3::ipv6::Ipv6Address::new(addr.as_ipv6()))
                .unwrap_or(crate::net::l3::ipv6::Ipv6Address::UNSPECIFIED);
            let dst_v6 = crate::net::l3::ipv6::Ipv6Address::new(remote.as_ipv6());

            match stack.resolve_ipv6_egress(scope, None, Some(src_v6), dst_v6) {
                Ok((Some(if_id), _, _)) => stack
                    .send_udp_v6_payload_scoped_with_ttl(
                        crate::net::types::InterfaceScope::Pinned(if_id),
                        local_port,
                        src_v6,
                        dst_v6,
                        remote.port(),
                        payload,
                        64,
                    )
                    .is_ok(),
                Ok((None, _, _)) => stack
                    .send_udp_v6_payload_scoped_with_ttl(
                        crate::net::types::InterfaceScope::Any,
                        local_port,
                        src_v6,
                        dst_v6,
                        remote.port(),
                        payload,
                        64,
                    )
                    .is_ok(),
                Err(error) => {
                    return EventHandleResult::ProtocolError(endpoint_error_from_network(error));
                }
            }
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
