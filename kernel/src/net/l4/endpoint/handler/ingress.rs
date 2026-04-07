// ============================================================================
// kernel/src/net/l4/endpoint/handler/ingress.rs
// ============================================================================
//! NetworkEventHandler Ingress系メソッド

use super::*;
use crate::net::l4::endpoint::handler::common::extract_ports;

impl NetworkEventHandler {
    /// IngressPacketイベント処理
    ///
    /// 【完全非同期化】このメソッドはイベントキュー経由でのみ呼び出されるべき。
    /// `handle_event()` → `handle_event_with_stack()` のパスで呼ばれる場合は
    /// 既にスタックロックが保持されている。
    /// `handle_event()` → `handle_event_stackless()` のパスで呼ばれた場合は
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

    /// IPv4パケットの処理
    pub(super) fn handle_ipv4_ingress_with_stack(
        &self,
        runtime: NetRuntimeHandle,
        if_id: Option<NetIfId>,
        data: &[u8],
        ip_packet: Option<PacketRef>,
        src_mac: MacAddress,
        current_time: u64,
        stack: &mut crate::net::runtime::stack::NetworkStack,
    ) -> EventHandleResult {
        // ── ファイアウォール Ingress チェック ──
        // IPv4ヘッダから最小限の 5-tuple を抽出してルール照合する。
        // ゼロコピー: データ参照のみでバッファコピーは行わない。
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

            if !crate::net::security::firewall::check_ingress_v4(
                src_ip, dst_ip, protocol, src_port, dst_port, tcp_flags,
            ) {
                stack.stats.record_dropped();
                return EventHandleResult::Success;
            }
        }

        // Ipv4Processorを使用してプロトコル判定
        let ingress_if_id = resolve_ingress_if_id_in(runtime, if_id);
        let result = stack
            .ipv4
            .process_with_time_and_packet(data, ip_packet.clone(), current_time);

        match result {
            crate::net::l3::ipv4::Ipv4ProcessResult::Icmp(payload, src_ip, dst_ip, ttl, _orig) => {
                if let Some(packet) = ip_packet.clone() {
                    if deliver_raw_payload_if_registered(
                        ingress_if_id,
                        PacketPayload::single(packet),
                    ) {
                        return EventHandleResult::Success;
                    }
                }
                let Some(payload) = ip_packet.as_ref().and_then(|ip_packet| {
                    crate::net::payload::payload_from_subslice(ip_packet, data, payload)
                }) else {
                    return EventHandleResult::ProtocolError(EndpointError::ResourceExhausted);
                };
                stack.process_icmp_payload(&payload, src_ip, dst_ip, ttl, current_time);
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Igmp(payload, src_ip, ttl, _orig) => {
                if let Some(packet) = ip_packet.clone() {
                    if deliver_raw_payload_if_registered(
                        ingress_if_id,
                        PacketPayload::single(packet),
                    ) {
                        return EventHandleResult::Success;
                    }
                }
                let Some(payload) = ip_packet.as_ref().and_then(|ip_packet| {
                    crate::net::payload::payload_from_subslice(ip_packet, data, payload)
                }) else {
                    return EventHandleResult::ProtocolError(EndpointError::ResourceExhausted);
                };
                stack.process_igmp_payload(&payload, src_ip, ttl);
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Udp(payload, src_ip, dst_ip, orig) => {
                if let Some(packet) = ip_packet.clone() {
                    if deliver_raw_payload_if_registered(
                        ingress_if_id,
                        PacketPayload::single(packet),
                    ) {
                        return EventHandleResult::Success;
                    }
                }
                let udp_segment_payload = ip_packet.as_ref().and_then(|ip_packet| {
                    crate::net::payload::payload_from_subslice(ip_packet, data, payload)
                });
                self.handle_udp_ingress_with_stack(
                    runtime,
                    if_id,
                    src_ip.octets(),
                    dst_ip.octets(),
                    payload,
                    udp_segment_payload,
                    data.get(8).copied().unwrap_or(64),
                    stack,
                    orig,
                    current_time,
                );
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::Tcp(payload, src_ip, dst_ip, _orig) => {
                if let Some(packet) = ip_packet.clone() {
                    if deliver_raw_payload_if_registered(
                        ingress_if_id,
                        PacketPayload::single(packet),
                    ) {
                        return EventHandleResult::Success;
                    }
                }
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
                self.handle_event_with_stack(
                    NetworkEvent::ReassembledPacket { if_id, payload },
                    stack,
                );
            }
            crate::net::l3::ipv4::Ipv4ProcessResult::FragmentPending => {}
            crate::net::l3::ipv4::Ipv4ProcessResult::ReassemblyTimeout(src, header_data) => {
                stack.send_icmp_time_exceeded(
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
                if let Some(packet) = ip_packet {
                    if deliver_raw_payload_if_registered(
                        ingress_if_id,
                        PacketPayload::single(packet),
                    ) {
                        return EventHandleResult::Success;
                    }
                }
                // RFC 792: Send ICMP Destination Unreachable (Protocol Unreachable, Code 2)
                log::warn!(
                    "[NET] Unknown protocol {} from {} - sending ICMP Protocol Unreachable",
                    _proto,
                    src
                );
                stack.send_icmp_error(
                    src,
                    crate::net::l3::icmp::DestUnreachCode::ProtocolUnreachable,
                    None,
                    orig_packet,
                    current_time,
                );
            }
        }

        EventHandleResult::Success
    }
}
