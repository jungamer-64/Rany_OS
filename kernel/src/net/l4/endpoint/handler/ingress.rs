// ============================================================================
// kernel/src/net/l4/endpoint/handler/ingress.rs
// ============================================================================
//! NetworkEventHandler Ingress系メソッド

use super::*;
use crate::net::l4::endpoint::handler::common::{
    extract_ports, resolve_ingress_if_id_in, subslice_offset,
};
use kernel_api::resource::net::PacketPayload;

impl NetworkEventHandler {
    /// IngressPacketイベント処理
    ///
    /// 【完全非同期化】このメソッドはイベントキュー経由でのみ呼び出されるべき。
    /// `handle_event()` → `handle_event_with_stack_in()` のパスで呼ばれる場合は
    /// 既にスタックロックが保持されている。
    /// `handle_event()` → stackless パスで呼ばれた場合は
    /// イベントを再エンキューして非同期パスに委譲する。
    pub(super) fn handle_ingress_packet(
        &self,
        runtime: NetRuntimeHandle,
        if_id: Option<NetIfId>,
        packet: PacketRef,
    ) -> EventHandleResult {
        // スタックロックなしのコンテキストから呼ばれた場合:
        // イベントキュー経由で再エンキューし、network_event_taskが
        // スタックロック保持下で処理する（二重ロック取得を回避）
        crate::net::l4::endpoint::event::enqueue_event_ignore_in(
            runtime,
            NetworkEvent::IngressPacket { if_id, packet },
        );
        EventHandleResult::Success
    }

    /// IngressPacketイベント処理（スタック保持）
    pub(super) fn handle_ingress_packet_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        if_id: Option<NetIfId>,
        packet: PacketRef,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        let pkt_len = packet.len();
        let data = packet.data();
        let current_time = stack.current_time();

        match stack.ethernet.process(data) {
            crate::net::l2::ethernet::ProcessResult::Ipv4(payload, src_mac) => {
                let Some(offset) = subslice_offset(data, payload) else {
                    stack.stats.record_rx_error();
                    return EventHandleResult::Success;
                };
                let payload_len = payload.len();
                let mut ip_packet = packet;
                ip_packet.advance(offset);
                ip_packet.set_len(payload_len);
                self.handle_ipv4_ingress_with_stack(
                    runtime,
                    if_id,
                    ip_packet,
                    src_mac,
                    current_time,
                    stack,
                );
                stack.stats.record_rx(pkt_len);
                EventHandleResult::Success
            }
            crate::net::l2::ethernet::ProcessResult::Arp(payload, src_mac) => {
                stack.process_arp(if_id, payload, current_time, src_mac);
                stack.stats.record_rx(pkt_len);
                EventHandleResult::Success
            }
            crate::net::l2::ethernet::ProcessResult::Ipv6(payload, src_mac) => {
                if stack.ipv6.is_some() {
                    let Some(offset) = subslice_offset(data, payload) else {
                        stack.stats.record_rx_error();
                        return EventHandleResult::Success;
                    };
                    let payload_len = payload.len();
                    let mut ip_packet = packet;
                    ip_packet.advance(offset);
                    ip_packet.set_len(payload_len);
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

                        // Security Fix: Use full IPv6 addresses for firewall check
                        if !crate::net::security::firewall::check_ingress(
                            crate::net::security::firewall::IpAddress::V6(src_ip),
                            crate::net::security::firewall::IpAddress::V6(dst_ip),
                            u8::from(protocol),
                            src_port,
                            dst_port,
                            tcp_flags,
                        ) {
                            stack.stats.record_dropped();
                            return EventHandleResult::Success;
                        }
                    }

                    stack.process_ipv6_data(
                        if_id,
                        current_time,
                        src_mac,
                        false,
                        ip_packet,
                    );
                    stack.stats.record_rx(pkt_len);
                } else {
                    stack.stats.record_dropped();
                }
                EventHandleResult::Success
            }
            _ => EventHandleResult::Success,
        }
    }

    /// IngressBatchイベント処理（スタック保持）
    pub(super) fn handle_ingress_batch_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        if_id: Option<NetIfId>,
        packets: alloc::vec::Vec<PacketRef>,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        // バッチ着信: スタックロック保持中に全パケットを連続処理
        for packet in packets {
            self.handle_event_with_stack_in(
                runtime,
                NetworkEvent::IngressPacket { if_id, packet },
                stack,
            );
        }
        EventHandleResult::Success
    }

    /// ReassembledPacketイベント処理（スタック保持）
    pub(super) fn handle_reassembled_packet_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        if_id: Option<NetIfId>,
        payload: PacketPayload,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        let current_time = stack.current_time();
        let ingress_if_id = resolve_ingress_if_id_in(runtime, if_id);
        let raw_endpoint = {
            let guard = crate::net::l4::endpoint::manager::ENDPOINT_MANAGER
                .read()
                .unwrap_or_else(|e| e.into_inner());
            guard
                .as_ref()
                .and_then(|manager| manager.find_raw_endpoint(ingress_if_id))
        };
        let view = crate::net::payload::PacketPayloadView::new(&payload);

        // Determine if it's IPv4 or IPv6
        if view.total_len() >= 20 && view.first_byte().map(|byte| byte >> 4) == Some(4) {
            // IPv4
            if let Some(header_packet) = view.first_segment() {
                let header = header_packet.data();
                if header.len() < 20 {
                    return EventHandleResult::Success;
                }
                let header_len = ((header[0] & 0x0f) as usize) * 4;
                if header_len < 20 || header.len() < header_len || view.total_len() < header_len {
                    return EventHandleResult::Success;
                }
                let src_ip = crate::net::l3::ipv4::Ipv4Address::new([
                    header[12], header[13], header[14], header[15],
                ]);
                let dst_ip = crate::net::l3::ipv4::Ipv4Address::new([
                    header[16], header[17], header[18], header[19],
                ]);
                let protocol = crate::net::l3::ipv4::IpProtocol::from(header[9]);
                let transport_len = view.total_len().saturating_sub(header_len);
                let prefix_len = transport_len.min(20);
                let prefix = view.read_vec(header_len, prefix_len);
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
                    crate::net::l3::ipv4::IpProtocol::Icmp if prefix.len() >= 2 => {
                        (prefix[0] as u16, prefix[1] as u16, 0)
                    }
                    crate::net::l3::ipv4::IpProtocol::Icmpv6 if prefix.len() >= 2 => {
                        (prefix[0] as u16, prefix[1] as u16, 0)
                    }
                    _ => (0, 0, 0),
                };

                if !crate::net::security::firewall::check_ingress(
                    src_ip.octets(),
                    dst_ip.octets(),
                    protocol.into(),
                    src_port,
                    dst_port,
                    tcp_flags,
                ) {
                    stack.stats.record_dropped();
                    return EventHandleResult::Success;
                }

                if let Some(endpoint) = raw_endpoint.as_ref() {
                    let _ = endpoint.deliver_raw_payload(ingress_if_id, payload);
                    return EventHandleResult::Success;
                }

                let transport_payload = payload.slice(header_len, transport_len);
                match protocol {
                    crate::net::l3::ipv4::IpProtocol::Tcp => {
                        if let Some(transport_payload) = transport_payload {
                            crate::net::l4::endpoint::tcp_rx::process_tcp_segment_payload_on(
                                if_id,
                                src_ip.octets(),
                                dst_ip.octets(),
                                &transport_payload,
                            );
                        }
                    }
                    crate::net::l3::ipv4::IpProtocol::Udp => {
                        if let Some(transport_payload) = transport_payload {
                            stack.process_udp_payload(
                                if_id,
                                transport_payload,
                                src_ip,
                                dst_ip,
                                ttl,
                                &payload,
                                current_time,
                            );
                        }
                    }
                    crate::net::l3::ipv4::IpProtocol::Icmp => {
                        if let Some(transport_payload) = transport_payload {
                            stack.process_icmp_payload(
                                &transport_payload,
                                src_ip,
                                dst_ip,
                                ttl,
                                current_time,
                            );
                        }
                    }
                    crate::net::l3::ipv4::IpProtocol::Igmp => {
                        if let Some(transport_payload) = transport_payload {
                            stack.process_igmp_payload(&transport_payload, src_ip, ttl);
                        }
                    }
                    _ => {}
                }
            }
        } else if view.total_len() >= 40 && view.first_byte().map(|byte| byte >> 4) == Some(6) {
            // IPv6
            if let Some(header_packet) = view.first_segment() {
                let header = header_packet.data();
                if header.len() < 40 {
                    return EventHandleResult::Success;
                }
                let src = crate::net::l3::ipv6::Ipv6Address::new([
                    header[8], header[9], header[10], header[11], header[12], header[13],
                    header[14], header[15], header[16], header[17], header[18], header[19],
                    header[20], header[21], header[22], header[23],
                ]);
                let dst = crate::net::l3::ipv6::Ipv6Address::new([
                    header[24], header[25], header[26], header[27], header[28], header[29],
                    header[30], header[31], header[32], header[33], header[34], header[35],
                    header[36], header[37], header[38], header[39],
                ]);
                let (protocol, _) = crate::net::l3::ipv6::skip_extension_headers(
                    crate::net::l3::ipv4::IpProtocol::from(header[6]),
                    &header[40..],
                );
                let payload_offset = header.len();
                let transport_len = view.total_len().saturating_sub(payload_offset);
                let prefix_len = transport_len.min(20);
                let prefix = view.read_vec(payload_offset, prefix_len);
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
                    crate::net::l3::ipv4::IpProtocol::Icmp if prefix.len() >= 2 => {
                        (prefix[0] as u16, prefix[1] as u16, 0)
                    }
                    crate::net::l3::ipv4::IpProtocol::Icmpv6 if prefix.len() >= 2 => {
                        (prefix[0] as u16, prefix[1] as u16, 0)
                    }
                    _ => (0, 0, 0),
                };

                if !crate::net::security::firewall::check_ingress(
                    crate::net::security::firewall::IpAddress::V6(src.octets()),
                    crate::net::security::firewall::IpAddress::V6(dst.octets()),
                    protocol.into(),
                    src_port,
                    dst_port,
                    tcp_flags,
                ) {
                    stack.stats.record_dropped();
                    return EventHandleResult::Success;
                }

                if let Some(endpoint) = raw_endpoint.as_ref() {
                    let _ = endpoint.deliver_raw_payload(ingress_if_id, payload);
                    return EventHandleResult::Success;
                }

                let transport_payload = payload.slice(payload_offset, transport_len);
                match protocol {
                    crate::net::l3::ipv4::IpProtocol::Tcp => {
                        if let Some(transport_payload) = transport_payload {
                            crate::net::l4::endpoint::tcp_rx::process_tcp_segment_v6_payload_on(
                                if_id,
                                src,
                                dst,
                                &transport_payload,
                            );
                        }
                    }
                    crate::net::l3::ipv4::IpProtocol::Udp => {
                        if let Some(transport_payload) = transport_payload {
                            stack.process_udp_payload_v6(
                                if_id,
                                transport_payload,
                                src,
                                dst,
                                hop_limit,
                                &payload,
                            );
                        }
                    }
                    crate::net::l3::ipv4::IpProtocol::Icmpv6 => {
                        if let Some(transport_payload) = transport_payload {
                            stack.process_icmpv6_data(
                                if_id,
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
        }

        EventHandleResult::Success
    }

    /// IPv4パケットの処理
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
        // ── ファイアウォール Ingress チェック ──
        // IPv4ヘッダから最小限の 5-tuple を抽出してルール照合する。
        // ゼロコピー: データ参照のみでバッファコピーは行わない。
        {
            let data = ip_packet.as_ref().map_or(&[][..], PacketRef::data);
            if data.len() >= 20 {
            let protocol = data[9];
            let src_ip: [u8; 4] = [data[12], data[13], data[14], data[15]];
            let dst_ip: [u8; 4] = [data[16], data[17], data[18], data[19]];
            let ihl = ((data[0] & 0x0F) as usize) * 4;

            // Security Fix: フラグメントのチェック。
            // 2番目以降のフラグメント (Offset > 0) は L4 ヘッダを含まないため、ポート抽出をスキップする。
            let fragment_offset = (u16::from_be_bytes([data[6], data[7]]) & 0x1FFF) * 8;
            let more_fragments = (data[6] & 0x20) != 0;

            // Tiny Fragment Attack Protection (RFC 3128)
            // Offset 0 でかつ L4 ヘッダが不完全なフラグメントをドロップ
            if fragment_offset == 0 && more_fragments {
                let min_l4_len = match protocol {
                    6 => 20, // TCP
                    17 => 8, // UDP
                    _ => 0,
                };
                if data.len() < ihl + min_l4_len {
                    log::warn!(
                        "[FIREWALL] Dropping tiny fragment (RFC 3128): proto={}, len={}",
                        protocol,
                        data.len()
                    );
                    stack.stats.record_dropped();
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

            if !crate::net::security::firewall::check_ingress(
                src_ip, dst_ip, protocol, src_port, dst_port, tcp_flags,
            ) {
                stack.stats.record_dropped();
                return EventHandleResult::Success;
            }
        }
        }

        // Ipv4Processorを使用してプロトコル判定
        let ingress_if_id = resolve_ingress_if_id_in(runtime, if_id);
        let raw_endpoint = {
            let guard = crate::net::l4::endpoint::manager::ENDPOINT_MANAGER
                .read()
                .unwrap_or_else(|e| e.into_inner());
            guard
                .as_ref()
                .and_then(|manager| manager.find_raw_endpoint(ingress_if_id))
        };
        if let Some(endpoint) = raw_endpoint.as_ref() {
            if let Some(packet) = ip_packet.take() {
                let _ = endpoint.deliver_raw_payload(ingress_if_id, PacketPayload::single(packet));
                return EventHandleResult::Success;
            }
        }
        let result = {
            let data = ip_packet.as_ref().map_or(&[][..], PacketRef::data);
            stack
                .ipv4
                .process_with_time_and_packet(data, ip_packet.as_ref(), current_time)
        };

        match result {
            crate::net::l3::ipv4::Ipv4ProcessResult::Icmp(payload, src_ip, dst_ip, ttl, _orig) => {
                let data = ip_packet.as_ref().map_or(&[][..], PacketRef::data);
                let Some(payload) = ip_packet.as_ref().and_then(|ip_packet| {
                    crate::net::payload::payload_from_subslice(ip_packet, data, payload)
                }) else {
                    return EventHandleResult::ProtocolError(EndpointError::ResourceExhausted);
                };
                stack.process_icmp_payload(&payload, src_ip, dst_ip, ttl, current_time);
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Igmp(payload, src_ip, ttl, _orig) => {
                let data = ip_packet.as_ref().map_or(&[][..], PacketRef::data);
                let Some(payload) = ip_packet.as_ref().and_then(|ip_packet| {
                    crate::net::payload::payload_from_subslice(ip_packet, data, payload)
                }) else {
                    return EventHandleResult::ProtocolError(EndpointError::ResourceExhausted);
                };
                stack.process_igmp_payload(&payload, src_ip, ttl);
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Udp(payload, src_ip, dst_ip, orig) => {
                let data = ip_packet.as_ref().map_or(&[][..], PacketRef::data);
                let udp_segment_payload = ip_packet.as_ref().and_then(|packet| {
                    crate::net::payload::payload_from_subslice(packet, data, payload)
                });
                let original_packet = if let Some(packet) = ip_packet.as_ref() {
                    PacketPayload::single(packet.clone())
                } else {
                    let mut builder = crate::net::payload::PacketPayloadBuilder::new();
                    let Some(()) = builder.push_bytes(orig) else {
                        return EventHandleResult::ProtocolError(EndpointError::ResourceExhausted);
                    };
                    builder.build()
                };
                let ttl = data.get(8).copied().unwrap_or(64);
                self.handle_udp_ingress_with_stack(
                    runtime,
                    if_id,
                    src_ip.octets(),
                    dst_ip.octets(),
                    payload,
                    udp_segment_payload,
                    ttl,
                    stack,
                    original_packet,
                    current_time,
                );
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Tcp(payload, src_ip, dst_ip, _orig) => {
                let data = ip_packet.as_ref().map_or(&[][..], PacketRef::data);
                let Some(tcp_segment_payload) = ip_packet.as_ref().and_then(|ip_packet| {
                    crate::net::payload::payload_from_subslice(ip_packet, data, payload)
                }) else {
                    return EventHandleResult::Success;
                };
                crate::net::l4::endpoint::tcp_rx::process_tcp_segment_payload_on(
                    if_id,
                    src_ip.octets(),
                    dst_ip.octets(),
                    &tcp_segment_payload,
                );
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Reassembled(payload) => {
                // 再組立てパケットを再帰的に処理
                let _ = src_mac;
                self.handle_event_with_stack_in(
                    runtime,
                    NetworkEvent::ReassembledPacket { if_id, payload },
                    stack,
                );
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::FragmentPending => {}
            crate::net::l3::ipv4::Ipv4ProcessResult::ReassemblyTimeout(src, header_data) => {
                stack.send_icmp_time_exceeded_payload(
                    src,
                    crate::net::l3::icmp::TimeExceededCode::FragmentReassemblyExceeded,
                    &header_data,
                );
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Dropped => {
                stack.stats.record_dropped();
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Error => {
                stack.stats.record_rx_error();
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Success => {}
            crate::net::l3::ipv4::Ipv4ProcessResult::UnknownProtocol(
                _proto,
                src,
                _dst,
                orig_packet,
            ) => {
                // RFC 792: Send ICMP Destination Unreachable (Protocol Unreachable, Code 2)
                log::warn!(
                    "[NET] Unknown protocol {} from {} - sending ICMP Protocol Unreachable",
                    _proto,
                    src
                );
                stack.send_icmp_error_payload(
                    src,
                    crate::net::l3::icmp::DestUnreachCode::ProtocolUnreachable,
                    None,
                    &orig_packet,
                    current_time,
                );
            }
        }

        EventHandleResult::Success
    }
}
