// ============================================================================
// kernel/src/net/l4/endpoint/handler/udp.rs
// ============================================================================
//! NetworkEventHandler UDP系メソッド

use super::*;
use crate::net::l3::ipv4::Ipv4Address;
use crate::net::l4::endpoint::handler::common::{
    endpoint_error_from_network, endpoint_ipv4_pair, endpoint_is_native_v6_pair,
    resolve_ingress_if_id_in,
};
use crate::net::l4::endpoint::manager::EndpointFamily;
use crate::net::l4::endpoint::types::EndpointResult;
use crate::net::payload::PacketPayloadView;

impl NetworkEventHandler {
    /// UDPパケットの処理
    pub(super) fn handle_udp_ingress_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        if_id: Option<NetIfId>,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        payload: &[u8],
        udp_segment_payload: Option<PacketPayload>,
        ttl: u8,
        stack: &mut crate::net::runtime::stack::NetworkStack,
        original_packet: &[u8],
        current_time: u64,
    ) -> EventHandleResult {
        if payload.len() < 8 {
            return EventHandleResult::Success;
        }

        let src_port = u16::from_be_bytes([payload[0], payload[1]]);
        let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
        let data = &payload[8..];

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
                if let Some(payload) = udp_segment_payload.slice(8, data.len()) {
                    socket.push_packet_payload(ingress_if_id, remote, ttl, payload);
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
                if let Some(original_packet) =
                    crate::net::payload::packet_from_bytes(original_packet)
                        .map(kernel_api::resource::net::PacketPayload::single)
                {
                    stack.send_icmp_error_payload(
                        src_v4,
                        DestUnreachCode::PortUnreachable,
                        None,
                        &original_packet,
                        current_time,
                    );
                } else {
                    stack.stats.record_rx_error();
                }
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
            let payload_view = PacketPayloadView::new(&payload);

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
                            &payload_view,
                            64,
                        )
                    } else {
                        stack.send_udp_raw_payload_scoped_auto_ttl(
                            pinned,
                            local_port,
                            dst_ip,
                            remote.port(),
                            &payload_view,
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
                            &payload_view,
                            64,
                        )
                    } else {
                        stack.send_udp_raw_payload_scoped_auto_ttl(
                            crate::net::types::InterfaceScope::Any,
                            local_port,
                            dst_ip,
                            remote.port(),
                            &payload_view,
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
            let payload_view = PacketPayloadView::new(&payload);

            match stack.resolve_ipv6_egress(scope, None, Some(src_v6), dst_v6) {
                Ok((Some(if_id), _, _)) => stack
                    .send_udp_v6_payload_scoped_with_ttl(
                        crate::net::types::InterfaceScope::Pinned(if_id),
                        local_port,
                        src_v6,
                        dst_v6,
                        remote.port(),
                        &payload_view,
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
                        &payload_view,
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

    /// SendToイベント処理
    /// UDPパケットを送信
    pub(super) fn handle_send_to(
        &self,
        fd: EndpointFd,
        remote: EndpointAddr,
        payload: PacketPayload,
    ) -> EventHandleResult {
        let manager = ENDPOINT_MANAGER.read().unwrap_or_else(|e| e.into_inner());
        let Some(ref mgr) = *manager else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let Some(socket) = mgr.get(fd) else {
            return EventHandleResult::SocketNotFound(fd);
        };

        let inner = socket.inner().lock().unwrap_or_else(|e| e.into_inner());
        let local = match inner.local_addr {
            Some(addr) => addr,
            None => {
                // ローカルアドレスが未設定の場合はエフェメラルポートを使用
                let port = mgr
                    .allocate_ephemeral_port(EndpointType::Udp)
                    .unwrap_or(49152);
                EndpointAddr::new([0, 0, 0, 0], port)
            }
        };

        if inner.udp().is_some() {
            let ttl = inner.udp().map(|udp| udp.ttl).unwrap_or(64);
            let payload_len = payload.total_len();
            if let Err(e) = self.send_udp_payload(local, remote, payload, ttl) {
                log::info!("UDP: Failed to send packet: {:?}", e);
                return EventHandleResult::ProtocolError(match e {
                    EndpointError::InvalidArgument => EndpointError::InvalidArgument,
                    _ => EndpointError::Internal,
                });
            }

            log::info!(
                "UDP: Sent {} bytes to {} from port {}",
                payload_len,
                remote,
                local.port()
            );

            EventHandleResult::Success
        } else {
            EventHandleResult::ProtocolError(EndpointError::InvalidStateTransition)
        }
    }

    /// UDPパケット送信（非同期イベントキュー経由）
    pub(super) fn send_udp_payload(
        &self,
        src: EndpointAddr,
        dst: EndpointAddr,
        payload: PacketPayload,
        ttl: u8,
    ) -> EndpointResult<()> {
        let runtime = default_runtime();
        let (result_slot, waker) = crate::net::runtime::stack::new_detached_command_channel();

        // IPv4パス
        if let Some((src_v4, dst_v4)) = endpoint_ipv4_pair(src, dst) {
            let src_ip = crate::net::l3::ipv4::Ipv4Address::new(src_v4);
            let dst_ip = crate::net::l3::ipv4::Ipv4Address::new(dst_v4);
            crate::net::l4::endpoint::event::enqueue_event_ignore_in(
                runtime,
                NetworkEvent::RawUdpSend {
                    src_port: src.port(),
                    src_ip: (!src_ip.is_any()).then_some(src_ip.octets()),
                    dst_ip: dst_ip.octets(),
                    dst_port: dst.port(),
                    payload,
                    ttl,
                    completion_id: None,
                    result_slot,
                    waker,
                },
            );
            return Ok(());
        }

        // IPv6パス
        if endpoint_is_native_v6_pair(src, dst) {
            let src_v6 = crate::net::l3::ipv6::Ipv6Address::new(src.as_ipv6());
            let dst_v6 = crate::net::l3::ipv6::Ipv6Address::new(dst.as_ipv6());
            crate::net::l4::endpoint::event::enqueue_event_ignore_in(
                runtime,
                NetworkEvent::RawUdpV6Send {
                    src_port: src.port(),
                    src_ip: src_v6.octets(),
                    dst_ip: dst_v6.octets(),
                    dst_port: dst.port(),
                    payload,
                    ttl,
                    completion_id: None,
                    result_slot,
                    waker,
                },
            );
            return Ok(());
        }

        Err(EndpointError::InvalidArgument)
    }
}
