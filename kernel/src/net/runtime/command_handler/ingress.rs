// ============================================================================
// kernel/src/net/runtime/command_handler/ingress.rs - ランタイム / コマンドハンドラ / 受信処理
// ============================================================================
//! RuntimeCommandHandler Ingress系メソッド

use super::*;
use crate::net::runtime::command_handler::common::extract_ports;
use kernel_api::resource::net::PacketPayload;

impl RuntimeCommandHandler {
    /// IngressPacketイベント処理（スタック保持）
    pub(super) fn handle_ingress_packet_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        if_id: Option<NetIfId>,
        packet: PacketRef,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        let pkt_len = packet.len();
        let current_time = stack.current_time();
        let Some(selected_if_id) = stack.resolve_ingress_if(if_id) else {
            return EventHandleResult::Success;
        };

        let ethernet_result = {
            let Some((_, state)) = stack.interface_state_for_ingress_mut(Some(selected_if_id))
            else {
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
                    Some(selected_if_id),
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
                    Some(selected_if_id),
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
                let ipv6_enabled = stack
                    .interface_state_for_ingress(Some(selected_if_id))
                    .is_some_and(|(_, state)| state.has_ipv6());
                if ipv6_enabled {
                    let ip_data = ip_packet.data();
                    // ── ファイアウォール Ingress チェック (IPv6) ──
                    if ip_data.len() >= 40 {
                        let src_ip = [
                            ip_data[8],
                            ip_data[9],
                            ip_data[10],
                            ip_data[11],
                            ip_data[12],
                            ip_data[13],
                            ip_data[14],
                            ip_data[15],
                            ip_data[16],
                            ip_data[17],
                            ip_data[18],
                            ip_data[19],
                            ip_data[20],
                            ip_data[21],
                            ip_data[22],
                            ip_data[23],
                        ];
                        let dst_ip = [
                            ip_data[24],
                            ip_data[25],
                            ip_data[26],
                            ip_data[27],
                            ip_data[28],
                            ip_data[29],
                            ip_data[30],
                            ip_data[31],
                            ip_data[32],
                            ip_data[33],
                            ip_data[34],
                            ip_data[35],
                            ip_data[36],
                            ip_data[37],
                            ip_data[38],
                            ip_data[39],
                        ];
                        let next_header = ip_data[6];
                        let (protocol, transport_data) =
                            crate::net::l3::ipv6::skip_extension_headers(
                                crate::net::l3::ipv4::IpProtocol::from(next_header),
                                &ip_data[40..],
                            );

                        let (src_port, dst_port) = if (u8::from(protocol) == 6
                            || u8::from(protocol) == 17)
                            && transport_data.len() >= 4
                        {
                            let sp = u16::from_be_bytes([transport_data[0], transport_data[1]]);
                            let dp = u16::from_be_bytes([transport_data[2], transport_data[3]]);
                            (sp, dp)
                        } else if u8::from(protocol) == 58 && transport_data.len() >= 2 {
                            // ICMPv6: src_port = type, dst_port = code
                            (transport_data[0] as u16, transport_data[1] as u16)
                        } else {
                            (0, 0)
                        };

                        let tcp_flags = if u8::from(protocol) == 6 && transport_data.len() >= 14 {
                            transport_data[13]
                        } else {
                            0
                        };

                        // SECURITY: firewall check には完全な IPv6 address を使う。
                        if !crate::net::security::firewall::check_ingress_in(
                            runtime,
                            crate::net::security::firewall::IpAddress::V6(src_ip),
                            crate::net::security::firewall::IpAddress::V6(dst_ip),
                            u8::from(protocol),
                            src_port,
                            dst_port,
                            tcp_flags,
                        ) {
                            if let Some(stats) = stack.interface_stats(selected_if_id) {
                                stats.record_dropped();
                            }
                            return EventHandleResult::Success;
                        }
                    }

                    stack.process_ipv6_data(
                        runtime,
                        Some(selected_if_id),
                        current_time,
                        src_mac,
                        false,
                        ip_packet,
                    );
                    if let Some(stats) = stack.interface_stats(selected_if_id) {
                        stats.record_rx(pkt_len);
                    }
                } else {
                    if let Some(stats) = stack.interface_stats(selected_if_id) {
                        stats.record_dropped();
                    }
                }
                EventHandleResult::Success
            }
            _ => EventHandleResult::Success,
        }
    }

    pub(super) fn handle_reassembled_packet_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        if_id: Option<NetIfId>,
        payload: PacketPayload,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        let current_time = stack.current_time();
        let Some(ingress_if_id) = stack.resolve_ingress_if(if_id) else {
            return EventHandleResult::Success;
        };
        let raw_endpoint = crate::net::l4::socket::find_raw_by_scope_in(runtime, ingress_if_id);
        let view = crate::net::payload::PacketPayloadView::new(&payload);

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

            let (src_port, dst_port, tcp_flags) = match protocol {
                crate::net::l3::ipv4::IpProtocol::Tcp if prefix.len() >= 20 => (
                    u16::from_be_bytes([prefix[0], prefix[1]]),
                    u16::from_be_bytes([prefix[2], prefix[3]]),
                    prefix[13],
                ),
                crate::net::l3::ipv4::IpProtocol::Udp if prefix.len() >= 8 => (
                    u16::from_be_bytes([prefix[0], prefix[1]]),
                    u16::from_be_bytes([prefix[2], prefix[3]]),
                    0,
                ),
                crate::net::l3::ipv4::IpProtocol::Icmp
                | crate::net::l3::ipv4::IpProtocol::Icmpv6
                    if prefix.len() >= 2 =>
                {
                    (prefix[0] as u16, prefix[1] as u16, 0)
                }
                _ => (0, 0, 0),
            };

            if !crate::net::security::firewall::check_ingress_in(
                runtime,
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
                            Some(ingress_if_id),
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
                        Some(ingress_if_id),
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
                        stack.process_igmp_payload(&transport_payload, src_ip, ttl);
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
            let (protocol, _) = crate::net::l3::ipv6::skip_extension_headers(
                crate::net::l3::ipv4::IpProtocol::from(header[6]),
                &header[40..],
            );
            let payload_offset = header.len();
            let transport_len = view.total_len().saturating_sub(payload_offset);
            let prefix_len = transport_len.min(20);
            let Some(prefix_storage) = view.read_fixed_bytes::<20>(payload_offset, prefix_len)
            else {
                return EventHandleResult::Success;
            };
            let prefix = prefix_storage.as_slice();
            let hop_limit = header[7];

            let (src_port, dst_port, tcp_flags) = match protocol {
                crate::net::l3::ipv4::IpProtocol::Tcp if prefix.len() >= 20 => (
                    u16::from_be_bytes([prefix[0], prefix[1]]),
                    u16::from_be_bytes([prefix[2], prefix[3]]),
                    prefix[13],
                ),
                crate::net::l3::ipv4::IpProtocol::Udp if prefix.len() >= 8 => (
                    u16::from_be_bytes([prefix[0], prefix[1]]),
                    u16::from_be_bytes([prefix[2], prefix[3]]),
                    0,
                ),
                crate::net::l3::ipv4::IpProtocol::Icmp
                | crate::net::l3::ipv4::IpProtocol::Icmpv6
                    if prefix.len() >= 2 =>
                {
                    (prefix[0] as u16, prefix[1] as u16, 0)
                }
                _ => (0, 0, 0),
            };

            if !crate::net::security::firewall::check_ingress_in(
                runtime,
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
                            Some(ingress_if_id),
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
                    stack.process_udp_payload_v6(Some(ingress_if_id), packet, src, dst, hop_limit);
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
                            Some(ingress_if_id),
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
        if_id: Option<NetIfId>,
        ip_packet: PacketRef,
        src_mac: MacAddress,
        current_time: u64,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        let mut ip_packet = Some(ip_packet);
        let Some(ingress_if_id) = stack.resolve_ingress_if(if_id) else {
            return EventHandleResult::Success;
        };
        {
            let data = ip_packet.as_ref().map_or(&[][..], PacketRef::data);
            if data.len() >= 20 {
                let protocol = data[9];
                let src_ip: [u8; 4] = [data[12], data[13], data[14], data[15]];
                let dst_ip: [u8; 4] = [data[16], data[17], data[18], data[19]];
                let ihl = ((data[0] & 0x0F) as usize) * 4;
                let fragment_offset = (u16::from_be_bytes([data[6], data[7]]) & 0x1FFF) * 8;
                let more_fragments = (data[6] & 0x20) != 0;

                if fragment_offset == 0 && more_fragments {
                    let min_l4_len = match protocol {
                        6 => 20,
                        17 => 8,
                        _ => 0,
                    };
                    if data.len() < ihl + min_l4_len {
                        if let Some(stats) = stack.interface_stats(ingress_if_id) {
                            stats.record_dropped();
                        }
                        return EventHandleResult::Success;
                    }
                }

                let tcp_flags = if protocol == 6 && data.len() >= ihl + 14 {
                    data[ihl + 13]
                } else {
                    0
                };
                let (src_port, dst_port) = if fragment_offset == 0 {
                    extract_ports(data, ihl, protocol)
                } else {
                    (0, 0)
                };

                if !crate::net::security::firewall::check_ingress_in(
                    runtime, src_ip, dst_ip, protocol, src_port, dst_port, tcp_flags,
                ) {
                    if let Some(stats) = stack.interface_stats(ingress_if_id) {
                        stats.record_dropped();
                    }
                    return EventHandleResult::Success;
                }
            }
        }

        let raw_endpoint = crate::net::l4::socket::find_raw_by_scope_in(runtime, ingress_if_id);
        if let Some(endpoint) = raw_endpoint.as_ref() {
            if let Some(packet) = ip_packet.take() {
                let _ = endpoint.deliver_raw_payload(ingress_if_id, PacketPayload::single(packet));
                return EventHandleResult::Success;
            }
        }

        let Some(packet_ref) = ip_packet.take() else {
            return EventHandleResult::ProtocolError(EndpointError::ResourceExhausted);
        };
        let Some((_, state)) = stack.interface_state_for_ingress_mut(Some(ingress_if_id)) else {
            return EventHandleResult::Success;
        };
        let result = state.process_ipv4_owned_packet(packet_ref, current_time);

        match result {
            crate::net::l3::ipv4::Ipv4ProcessResult::Icmp(packet, src_ip, dst_ip, ttl) => {
                let Ok(payload) = packet.into_payload() else {
                    return EventHandleResult::ProtocolError(EndpointError::ResourceExhausted);
                };
                stack.process_icmp_payload(runtime, payload, src_ip, dst_ip, ttl, current_time);
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Igmp(packet, src_ip, ttl) => {
                let Ok(payload) = packet.into_payload() else {
                    return EventHandleResult::ProtocolError(EndpointError::ResourceExhausted);
                };
                stack.process_igmp_payload(&payload, src_ip, ttl);
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
                    Some(ingress_if_id),
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
                    Some(ingress_if_id),
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
                            if_id: Some(ingress_if_id),
                            payload,
                        },
                    ),
                    stack,
                );
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::FragmentPending => {}
            crate::net::l3::ipv4::Ipv4ProcessResult::ReassemblyTimeout(src, header_data) => {
                stack.send_icmp_time_exceeded_payload(
                    src,
                    crate::net::l3::icmp::TimeExceededCode::FragmentReassemblyExceeded,
                    header_data,
                );
            }
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
