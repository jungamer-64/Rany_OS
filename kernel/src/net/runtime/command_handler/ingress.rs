// ============================================================================
// kernel/src/net/runtime/command_handler/ingress.rs - ランタイム / コマンドハンドラ / 受信処理
// ============================================================================
//! RuntimeCommandHandler Ingress系メソッド

use super::*;
use crate::net::l3::ipv4::{IpProtocol, Ipv4Packet};
use crate::net::l3::ipv6::{Ipv6HeaderChain, Ipv6Packet, Ipv6PacketBytes};
use crate::net::payload::{PacketPayloadView, PayloadSpanRef};
use crate::net::security::firewall::{admit_ingress_fragment_in, check_ingress_in};
use kernel_api::resource::net::PacketPayload;

fn ingress_transport_fields(protocol: IpProtocol, header: &[u8]) -> (u16, u16, u8) {
    let (src, dst) = match protocol {
        IpProtocol::Tcp if header.len() >= 20 => (
            u16::from_be_bytes([header[0], header[1]]),
            u16::from_be_bytes([header[2], header[3]]),
        ),
        IpProtocol::Udp if header.len() >= 8 => (
            u16::from_be_bytes([header[0], header[1]]),
            u16::from_be_bytes([header[2], header[3]]),
        ),
        IpProtocol::Icmp | IpProtocol::Icmpv6 if header.len() >= 2 => {
            (u16::from(header[0]), u16::from(header[1]))
        }
        _ => (0, 0),
    };
    let flags = if protocol == IpProtocol::Tcp && header.len() >= 20 {
        header[13]
    } else {
        0
    };
    (src, dst, flags)
}

impl RuntimeCommandHandler {
    /// IngressPacketイベント処理（スタック保持）
    pub(super) fn handle_ingress_packet_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        if_id: NetIfId,
        packet: PacketRef,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        let pkt_len = packet.len();
        let current_time = stack.current_time();
        if !crate::net::runtime::manager::is_interface_operational_in(runtime, if_id) {
            return EventHandleResult::Success;
        }
        let selected_if_id = if_id;

        let ethernet_result = {
            let Some((_, state)) = stack.interface_state_for_ingress_mut(selected_if_id) else {
                return EventHandleResult::Success;
            };
            state.process_ethernet(packet)
        };

        match ethernet_result {
            crate::net::l2::ethernet::EthernetIngress::Ipv4 {
                packet: ip_packet,
                src_mac,
            } => {
                self.handle_ipv4_ingress_with_stack(
                    runtime,
                    selected_if_id,
                    ip_packet,
                    src_mac,
                    current_time,
                    stack,
                );
                if let Some(stats) = stack.interface_stats(selected_if_id) {
                    stats.record_rx(pkt_len);
                }
                EventHandleResult::Success
            }
            crate::net::l2::ethernet::EthernetIngress::Arp { packet, src_mac } => {
                stack.process_arp(
                    runtime,
                    selected_if_id,
                    packet.data(),
                    current_time,
                    src_mac,
                );
                if let Some(stats) = stack.interface_stats(selected_if_id) {
                    stats.record_rx(pkt_len);
                }
                EventHandleResult::Success
            }
            crate::net::l2::ethernet::EthernetIngress::Ipv6 {
                packet: ip_packet,
                src_mac,
            } => {
                if !stack
                    .interface_state_for_ingress(selected_if_id)
                    .is_some_and(|(_, state)| state.has_ipv6())
                {
                    if let Some(stats) = stack.interface_stats(selected_if_id) {
                        stats.record_dropped();
                    }
                    return EventHandleResult::Success;
                }

                let data = ip_packet.data();
                let Some(packet) = Ipv6Packet::parse(data) else {
                    if let Some(stats) = stack.interface_stats(selected_if_id) {
                        stats.record_rx_error();
                    }
                    return EventHandleResult::Success;
                };
                let src = packet.source().octets();
                let dst = packet.destination().octets();
                let headers = Ipv6HeaderChain::parse(Ipv6PacketBytes::Contiguous(data));
                let allowed = match headers {
                    Ipv6HeaderChain::UpperLayer {
                        protocol,
                        offset,
                        len,
                        ..
                    } => {
                        let (src_port, dst_port, flags) =
                            ingress_transport_fields(protocol, &data[offset..offset + len]);
                        check_ingress_in(
                            runtime,
                            selected_if_id,
                            src,
                            dst,
                            protocol.into(),
                            src_port,
                            dst_port,
                            flags,
                        )
                    }
                    Ipv6HeaderChain::Fragment { .. } => {
                        admit_ingress_fragment_in(runtime, src, dst, None)
                    }
                    Ipv6HeaderChain::ParameterProblem { .. } => {
                        admit_ingress_fragment_in(runtime, src, dst, None)
                    }
                    Ipv6HeaderChain::Discard => false,
                };

                if let Some(stats) = stack.interface_stats(selected_if_id) {
                    if allowed {
                        stats.record_rx(pkt_len);
                    } else {
                        stats.record_dropped();
                    }
                }
                if !allowed {
                    return EventHandleResult::Success;
                }
                if matches!(headers, Ipv6HeaderChain::UpperLayer { .. })
                    && let Some(endpoint) =
                        crate::net::l4::socket::find_raw_by_scope_in(runtime, selected_if_id)
                {
                    if let Ok(payload) = PacketPayload::try_single(ip_packet) {
                        let _ = endpoint.deliver_raw_payload(selected_if_id, payload);
                    }
                    return EventHandleResult::Success;
                }
                stack.process_ipv6_data(
                    runtime,
                    selected_if_id,
                    current_time,
                    src_mac,
                    ip_packet,
                    headers,
                );
                EventHandleResult::Success
            }
            _ => EventHandleResult::Success,
        }
    }

    pub(super) fn handle_reassembled_packet_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        if_id: NetIfId,
        payload: PacketPayload,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        let current_time = stack.current_time();
        if !crate::net::runtime::manager::is_interface_operational_in(runtime, if_id) {
            return EventHandleResult::Success;
        }
        let ingress_if_id = if_id;
        let raw_endpoint = crate::net::l4::socket::find_raw_by_scope_in(runtime, ingress_if_id);
        let view = PacketPayloadView::new(&payload);

        if view.total_len() >= 20 && view.first_byte().map(|byte| byte >> 4) == Some(4) {
            let Some(fixed) = view.read_array::<20>(0) else {
                return EventHandleResult::Success;
            };
            let header_len = ((fixed[0] & 0x0f) as usize) * 4;
            if header_len < 20 || header_len > 60 {
                return EventHandleResult::Success;
            }
            let Some(header_prefix) = view.read_fixed_bytes::<60>(0, header_len) else {
                return EventHandleResult::Success;
            };
            let header = header_prefix.as_slice();

            let src_ip = crate::net::l3::ipv4::Ipv4Address::new([
                header[12], header[13], header[14], header[15],
            ]);
            let dst_ip = crate::net::l3::ipv4::Ipv4Address::new([
                header[16], header[17], header[18], header[19],
            ]);
            let protocol = crate::net::l3::ipv4::IpProtocol::from(header[9]);
            let transport_len = view.total_len().saturating_sub(header_len);
            let prefix_len = transport_len.min(20);
            let Some(prefix_storage) = view.read_fixed_bytes::<20>(header_len, prefix_len) else {
                return EventHandleResult::Success;
            };
            let prefix = prefix_storage.as_slice();
            let ttl = header[8];

            let (src_port, dst_port, tcp_flags) = ingress_transport_fields(protocol, prefix);

            if !check_ingress_in(
                runtime,
                ingress_if_id,
                src_ip.octets(),
                dst_ip.octets(),
                protocol.into(),
                src_port,
                dst_port,
                tcp_flags,
            ) {
                if let Some(stats) = stack.interface_stats(ingress_if_id) {
                    stats.record_dropped();
                }
                return EventHandleResult::Success;
            }

            if let Some(endpoint) = raw_endpoint.as_ref() {
                let _ = endpoint.deliver_raw_payload(ingress_if_id, payload);
                return EventHandleResult::Success;
            }

            match protocol {
                crate::net::l3::ipv4::IpProtocol::Tcp => {
                    if let Some(bounds) = crate::net::payload::OwnedPayloadBounds::checked(
                        &payload,
                        header_len,
                        transport_len,
                    ) {
                        let Some(transport_payload) = bounds
                            .take_from(payload)
                            .and_then(|window| window.into_payload().ok())
                        else {
                            return EventHandleResult::Success;
                        };
                        crate::net::l4::tcp::tcp_rx::process_tcp_segment_payload_on(
                            runtime,
                            ingress_if_id,
                            src_ip.octets(),
                            dst_ip.octets(),
                            transport_payload,
                        );
                    }
                }
                crate::net::l3::ipv4::IpProtocol::Udp => {
                    let Some(bounds) = crate::net::payload::OwnedPayloadBounds::checked(
                        &payload,
                        header_len,
                        transport_len,
                    ) else {
                        return EventHandleResult::Success;
                    };
                    let Some(packet) = bounds.take_from(payload) else {
                        return EventHandleResult::Success;
                    };
                    stack.process_udp_payload(
                        ingress_if_id,
                        packet,
                        src_ip,
                        dst_ip,
                        ttl,
                        current_time,
                    );
                }
                crate::net::l3::ipv4::IpProtocol::Icmp => {
                    if let Some(bounds) = crate::net::payload::OwnedPayloadBounds::checked(
                        &payload,
                        header_len,
                        transport_len,
                    ) {
                        let Some(transport_payload) = bounds
                            .take_from(payload)
                            .and_then(|window| window.into_payload().ok())
                        else {
                            return EventHandleResult::Success;
                        };
                        stack.process_icmp_payload(
                            runtime,
                            ingress_if_id,
                            transport_payload,
                            src_ip,
                            dst_ip,
                            ttl,
                            current_time,
                        );
                    }
                }
                crate::net::l3::ipv4::IpProtocol::Igmp => {
                    if let Some(bounds) = crate::net::payload::OwnedPayloadBounds::checked(
                        &payload,
                        header_len,
                        transport_len,
                    ) {
                        let Some(transport_payload) = bounds
                            .take_from(payload)
                            .and_then(|window| window.into_payload().ok())
                        else {
                            return EventHandleResult::Success;
                        };
                        stack.process_igmp_payload(ingress_if_id, &transport_payload, src_ip, ttl);
                    }
                }
                _ => {}
            }
            return EventHandleResult::Success;
        }

        if view.total_len() >= 40 && view.first_byte().map(|byte| byte >> 4) == Some(6) {
            let Some(header) = view.read_array::<40>(0) else {
                return EventHandleResult::Success;
            };
            let src = crate::net::l3::ipv6::Ipv6Address::new([
                header[8], header[9], header[10], header[11], header[12], header[13], header[14],
                header[15], header[16], header[17], header[18], header[19], header[20], header[21],
                header[22], header[23],
            ]);
            let dst = crate::net::l3::ipv6::Ipv6Address::new([
                header[24], header[25], header[26], header[27], header[28], header[29], header[30],
                header[31], header[32], header[33], header[34], header[35], header[36], header[37],
                header[38], header[39],
            ]);
            let headers = Ipv6HeaderChain::parse(Ipv6PacketBytes::Segmented(
                PayloadSpanRef::from_payload(&payload),
            ));
            let Ipv6HeaderChain::UpperLayer {
                protocol,
                offset: payload_offset,
                len: transport_len,
                ..
            } = headers
            else {
                if let Ipv6HeaderChain::ParameterProblem {
                    code,
                    pointer,
                    allow_multicast_dst,
                } = headers
                    && (allow_multicast_dst || !dst.is_multicast())
                {
                    stack.send_icmpv6_parameter_problem_payload(
                        ingress_if_id,
                        src,
                        code,
                        pointer,
                        payload,
                    );
                }
                return EventHandleResult::Success;
            };
            let prefix_len = transport_len.min(20);
            let Some(prefix) = view.read_fixed_bytes::<20>(payload_offset, prefix_len) else {
                return EventHandleResult::Success;
            };
            let hop_limit = header[7];
            let (src_port, dst_port, tcp_flags) =
                ingress_transport_fields(protocol, prefix.as_slice());

            if !check_ingress_in(
                runtime,
                ingress_if_id,
                crate::net::security::firewall::IpAddress::V6(src.octets()),
                crate::net::security::firewall::IpAddress::V6(dst.octets()),
                protocol.into(),
                src_port,
                dst_port,
                tcp_flags,
            ) {
                if let Some(stats) = stack.interface_stats(ingress_if_id) {
                    stats.record_dropped();
                }
                return EventHandleResult::Success;
            }

            if let Some(endpoint) = raw_endpoint.as_ref() {
                let _ = endpoint.deliver_raw_payload(ingress_if_id, payload);
                return EventHandleResult::Success;
            }

            match protocol {
                crate::net::l3::ipv4::IpProtocol::Tcp => {
                    if let Some(bounds) = crate::net::payload::OwnedPayloadBounds::checked(
                        &payload,
                        payload_offset,
                        transport_len,
                    ) {
                        let Some(transport_payload) = bounds
                            .take_from(payload)
                            .and_then(|window| window.into_payload().ok())
                        else {
                            return EventHandleResult::Success;
                        };
                        crate::net::l4::tcp::tcp_rx::process_tcp_segment_v6_payload_on(
                            runtime,
                            ingress_if_id,
                            src,
                            dst,
                            transport_payload,
                        );
                    }
                }
                crate::net::l3::ipv4::IpProtocol::Udp => {
                    let Some(bounds) = crate::net::payload::OwnedPayloadBounds::checked(
                        &payload,
                        payload_offset,
                        transport_len,
                    ) else {
                        return EventHandleResult::Success;
                    };
                    let Some(packet) = bounds.take_from(payload) else {
                        return EventHandleResult::Success;
                    };
                    stack.process_udp_payload_v6(ingress_if_id, packet, src, dst, hop_limit);
                }
                crate::net::l3::ipv4::IpProtocol::Icmpv6 => {
                    if let Some(bounds) = crate::net::payload::OwnedPayloadBounds::checked(
                        &payload,
                        payload_offset,
                        transport_len,
                    ) {
                        let Some(transport_payload) = bounds
                            .take_from(payload)
                            .and_then(|window| window.into_payload().ok())
                        else {
                            return EventHandleResult::Success;
                        };
                        stack.process_icmpv6_data(
                            runtime,
                            ingress_if_id,
                            transport_payload,
                            src,
                            dst,
                            crate::net::l2::ethernet::MacAddress::ZERO,
                            hop_limit,
                            current_time,
                        );
                    }
                }
                _ => {}
            }
        }

        EventHandleResult::Success
    }

    pub(super) fn handle_ipv4_ingress_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        if_id: NetIfId,
        ip_packet: PacketRef,
        src_mac: MacAddress,
        current_time: u64,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        if !crate::net::runtime::manager::is_interface_operational_in(runtime, if_id) {
            return EventHandleResult::Success;
        }
        let ingress_if_id = if_id;
        let Some(packet) = Ipv4Packet::parse(ip_packet.data()) else {
            if let Some(stats) = stack.interface_stats(ingress_if_id) {
                stats.record_rx_error();
            }
            return EventHandleResult::Success;
        };
        let protocol = packet.protocol();
        let src = packet.source().octets();
        let dst = packet.destination().octets();
        let fragmented = packet.header().more_fragments() || packet.header().fragment_offset() != 0;
        let allowed = if fragmented {
            admit_ingress_fragment_in(runtime, src, dst, Some(protocol.into()))
        } else {
            let (src_port, dst_port, flags) = ingress_transport_fields(protocol, packet.payload());
            check_ingress_in(
                runtime,
                ingress_if_id,
                src,
                dst,
                protocol.into(),
                src_port,
                dst_port,
                flags,
            )
        };
        if !allowed {
            if let Some(stats) = stack.interface_stats(ingress_if_id) {
                stats.record_dropped();
            }
            return EventHandleResult::Success;
        }

        if !fragmented
            && let Some(endpoint) =
                crate::net::l4::socket::find_raw_by_scope_in(runtime, ingress_if_id)
        {
            if let Ok(payload) = PacketPayload::try_single(ip_packet) {
                let _ = endpoint.deliver_raw_payload(ingress_if_id, payload);
            }
            return EventHandleResult::Success;
        }
        let Some((_, state)) = stack.interface_state_for_ingress_mut(ingress_if_id) else {
            return EventHandleResult::Success;
        };
        let result = state.process_ipv4_owned_packet(ip_packet, current_time);

        match result {
            crate::net::l3::ipv4::Ipv4ProcessResult::Icmp(packet, src_ip, dst_ip, ttl) => {
                let Ok(payload) = packet.into_payload() else {
                    return EventHandleResult::ProtocolError(EndpointError::ResourceExhausted);
                };
                stack.process_icmp_payload(
                    runtime,
                    ingress_if_id,
                    payload,
                    src_ip,
                    dst_ip,
                    ttl,
                    current_time,
                );
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Igmp(packet, src_ip, ttl) => {
                let Ok(payload) = packet.into_payload() else {
                    return EventHandleResult::ProtocolError(EndpointError::ResourceExhausted);
                };
                stack.process_igmp_payload(ingress_if_id, &payload, src_ip, ttl);
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Udp(packet, src_ip, dst_ip, ttl) => {
                let (src_port, dst_port, data_len) = {
                    let span = packet.span();
                    if span.total_len() < 8 {
                        return EventHandleResult::Success;
                    }
                    let Some(ports) = span.read_array::<4>(0) else {
                        return EventHandleResult::ProtocolError(EndpointError::ResourceExhausted);
                    };
                    (
                        u16::from_be_bytes([ports[0], ports[1]]),
                        u16::from_be_bytes([ports[2], ports[3]]),
                        span.total_len() - 8,
                    )
                };
                self.handle_udp_ingress_with_stack(
                    runtime,
                    ingress_if_id,
                    src_ip.octets(),
                    dst_ip.octets(),
                    src_port,
                    dst_port,
                    data_len,
                    ttl,
                    stack,
                    packet,
                    current_time,
                );
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Tcp(packet, src_ip, dst_ip) => {
                let Ok(tcp_segment_payload) = packet.into_payload() else {
                    return EventHandleResult::Success;
                };
                crate::net::l4::tcp::tcp_rx::process_tcp_segment_payload_on(
                    runtime,
                    ingress_if_id,
                    src_ip.octets(),
                    dst_ip.octets(),
                    tcp_segment_payload,
                );
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Reassembled(payload) => {
                let _ = src_mac;
                self.handle_event_with_stack_in(
                    runtime,
                    RuntimeCommand::Ingress(
                        crate::net::runtime::command::IngressCommand::Reassembled {
                            if_id: ingress_if_id,
                            payload,
                        },
                    ),
                    stack,
                );
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::FragmentPending => {}
            crate::net::l3::ipv4::Ipv4ProcessResult::Dropped => {
                if let Some(stats) = stack.interface_stats(ingress_if_id) {
                    stats.record_dropped();
                }
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Error => {
                if let Some(stats) = stack.interface_stats(ingress_if_id) {
                    stats.record_rx_error();
                }
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Success => {}
            crate::net::l3::ipv4::Ipv4ProcessResult::UnknownProtocol(
                proto,
                src,
                _dst,
                original_packet,
            ) => {
                log::warn!(
                    "[NET] Unknown protocol {} from {} - sending ICMP Protocol Unreachable",
                    proto,
                    src
                );
                stack.send_icmp_error_payload(
                    ingress_if_id,
                    src,
                    crate::net::l3::icmp::DestUnreachCode::ProtocolUnreachable,
                    None,
                    original_packet,
                    current_time,
                );
            }
        }

        EventHandleResult::Success
    }
}
