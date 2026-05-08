// ============================================================================
// kernel/src/net/runtime/stack/core_impl/receive.rs - ランタイム / スタック / コア実装 / 受信処理
// ============================================================================

// =============================================================================
// Receive Path — IPv4/IPv6 incoming packet processing
//
// Split from core_impl/mod.rs for clarity. Contains all methods that process
// incoming packets: process_ipv4, process_ipv6_data, process_icmpv6_data,
// process_ndp_message, process_igmp_payload, etc.
// =============================================================================

use super::*;

impl NetworkStack {
    /// Process IPv4 packet
    pub(crate) fn process_ipv4(
        &mut self,
        data: &[u8],
        current_time: u64,
        packet: PacketRef,
        _src_mac: MacAddress,
    ) {
        // Fragmented packets must keep packet ownership for reassembly tracking.
        // Non-fragmented packets can follow the normal parse path directly.
        let is_fragment = crate::net::l3::ipv4::Ipv4Packet::parse(data).is_some_and(|packet| {
            packet.header().more_fragments() || packet.header().fragment_offset() != 0
        });
        let mut packet = Some(packet);
        let result = if is_fragment {
            match packet.take() {
                Some(packet_ref) => self
                    .ipv4
                    .process_fragment_owned_packet(packet_ref, current_time),
                None => {
                    self.stats.record_rx_error();
                    return;
                }
            }
        } else {
            let Some(packet_ref) = packet.as_ref() else {
                self.stats.record_rx_error();
                return;
            };
            self.ipv4
                .process_with_time_and_packet(data, Some(packet_ref), current_time)
        };

        match result {
            Ipv4ProcessResult::Icmp(payload, src_ip, dst_ip, ttl, _orig) => {
                // SECURITY: multicast ICMP は joined group だけで受理する。
                if dst_ip.is_multicast() && !self.is_multicast_allowed(dst_ip) {
                    self.stats.record_dropped();
                    return;
                }
                // Keep zero-copy semantics by slicing from the owned packet payload.
                let Some(packet_ref) = packet.take() else {
                    self.stats.record_rx_error();
                    return;
                };
                let Some(offset) = crate::net::payload::subslice_offset(data, payload) else {
                    self.stats.record_rx_error();
                    return;
                };
                let original_packet = kernel_api::resource::net::PacketPayload::single(packet_ref);
                let Some(icmp_payload) = crate::net::payload::move_payload_window_owned(
                    original_packet,
                    offset,
                    payload.len(),
                ) else {
                    self.stats.record_rx_error();
                    return;
                };
                self.process_icmp_payload(&icmp_payload, src_ip, dst_ip, ttl, current_time);
            }
            Ipv4ProcessResult::Igmp(payload, src_ip, ttl, _orig) => {
                let Some(packet_ref) = packet.take() else {
                    self.stats.record_rx_error();
                    return;
                };
                let Some(offset) = crate::net::payload::subslice_offset(data, payload) else {
                    self.stats.record_rx_error();
                    return;
                };
                let original_packet = kernel_api::resource::net::PacketPayload::single(packet_ref);
                let Some(igmp_payload) = crate::net::payload::move_payload_window_owned(
                    original_packet,
                    offset,
                    payload.len(),
                ) else {
                    self.stats.record_rx_error();
                    return;
                };
                self.process_igmp_payload(&igmp_payload, src_ip, ttl);
            }
            Ipv4ProcessResult::Udp(_payload, _src_ip, dst_ip, _orig) => {
                // SECURITY: multicast UDP は joined group だけで受理する。
                if dst_ip.is_multicast() && !self.is_multicast_allowed(dst_ip) {
                    self.stats.record_dropped();
                    return;
                }
                // Offload transport handling to endpoint event path.
                if let Some(packet_ref) = packet.take() {
                    crate::net::runtime::command::enqueue_command_ignore(
                        crate::net::runtime::command::RuntimeCommand::Ingress(
                            crate::net::runtime::command::IngressCommand::Packet {
                                if_id: None,
                                packet: packet_ref,
                            },
                        ),
                    );
                }
            }
            Ipv4ProcessResult::Tcp(_payload, _src_ip, dst_ip, _orig) => {
                // SECURITY: multicast / broadcast 上の TCP は拒否する（RFC 793 / RFC 1122）。
                if dst_ip.is_multicast()
                    || dst_ip.is_broadcast()
                    || (self.config().ipv4.subnet_mask.as_bytes()[0] != 0
                        && dst_ip == self.config().ipv4.broadcast_address())
                {
                    self.stats.record_dropped();
                    return;
                }
                // Offload transport handling to endpoint event path.
                if let Some(packet_ref) = packet.take() {
                    crate::net::runtime::command::enqueue_command_ignore(
                        crate::net::runtime::command::RuntimeCommand::Ingress(
                            crate::net::runtime::command::IngressCommand::Packet {
                                if_id: None,
                                packet: packet_ref,
                            },
                        ),
                    );
                }
            }
            Ipv4ProcessResult::Reassembled(payload) => {
                // Reassembled packets are offloaded through the same async endpoint channel.
                if let Some(header) =
                    crate::net::payload::PacketPayloadView::new(&payload).read_array::<20>(0)
                {
                    let dst = Ipv4Address::new([header[16], header[17], header[18], header[19]]);
                    if IpProtocol::from(header[9]) == IpProtocol::Tcp
                        && (dst.is_multicast()
                            || dst.is_broadcast()
                            || (self.config().ipv4.subnet_mask.as_bytes()[0] != 0
                                && dst == self.config().ipv4.broadcast_address()))
                    {
                        self.stats.record_dropped();
                        return;
                    }
                }
                crate::net::runtime::command::enqueue_command_ignore(
                    crate::net::runtime::command::RuntimeCommand::Ingress(
                        crate::net::runtime::command::IngressCommand::Reassembled {
                            if_id: None,
                            payload,
                        },
                    ),
                );
            }
            Ipv4ProcessResult::FragmentPending => {
                // Waiting for the remaining fragments.
            }
            Ipv4ProcessResult::ReassemblyTimeout(src, header_data) => {
                // RFC 792: send Time Exceeded (fragment reassembly timeout).
                self.send_icmp_time_exceeded_payload(
                    src,
                    crate::net::l3::icmp::TimeExceededCode::FragmentReassemblyExceeded,
                    &header_data,
                );
            }
            Ipv4ProcessResult::UnknownProtocol(proto, src, _dst, orig_packet) => {
                // RFC 792: send Destination Unreachable / Protocol Unreachable.
                log::warn!(
                    "IPv4: Unknown protocol {} from {} - sending ICMP Protocol Unreachable",
                    proto,
                    src
                );
                self.send_icmp_error_payload(
                    src,
                    crate::net::l3::icmp::DestUnreachCode::ProtocolUnreachable,
                    None,
                    &orig_packet,
                    current_time,
                );
            }
            Ipv4ProcessResult::Dropped => self.stats.record_dropped(),
            Ipv4ProcessResult::Error => self.stats.record_rx_error(),
            Ipv4ProcessResult::Success => {}
        }
    }

    pub fn process_icmp_payload(
        &mut self,
        payload: &kernel_api::resource::net::PacketPayload,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        _ttl: u8,
        current_time: u64,
    ) {
        if !self.icmp_echo_enabled() {
            return;
        }

        if dst_ip.is_broadcast()
            || dst_ip.is_multicast()
            || dst_ip == self.ipv4.config().broadcast_address()
        {
            return;
        }

        let result = self
            .icmp
            .process_payload(payload, src_ip, dst_ip, current_time);

        match result {
            IcmpResult::SendEchoReply {
                src_ip,
                identifier,
                sequence,
                data_offset,
                data_len,
            } => {
                let Some(echo_data) =
                    crate::net::payload::PayloadSpanRef::from_range(payload, data_offset, data_len)
                else {
                    self.stats.record_rx_error();
                    return;
                };
                self.send_icmp_echo_reply_payload(
                    src_ip,
                    identifier,
                    sequence,
                    echo_data,
                    current_time,
                );
            }
            IcmpResult::EchoReplyReceived {
                identifier: _,
                sequence,
            } => {
                let rtt_us = 0;
                crate::net::api::icmp::notify_icmp_echo_reply(*src_ip.as_bytes(), sequence, rtt_us);
                crate::net::runtime::command::enqueue_command_ignore(
                    crate::net::runtime::command::RuntimeCommand::Control(
                        crate::net::runtime::command::ControlCommand::IcmpEchoReply {
                            source: *src_ip.as_bytes(),
                            sequence,
                            rtt_us,
                        },
                    ),
                );
            }
            IcmpResult::Error { icmp_type, code } => {
                self.handle_icmp_error_payload(payload, icmp_type, code, current_time);
            }
            IcmpResult::Redirect {
                code,
                gateway,
                destination,
            } => {
                self.handle_icmp_redirect(code, gateway, destination, src_ip);
            }
            IcmpResult::SendTimestampReply {
                src_ip,
                identifier,
                sequence,
                originate_ts,
                receive_ts,
                transmit_ts,
            } => {
                self.send_icmp_timestamp_reply(
                    src_ip,
                    identifier,
                    sequence,
                    originate_ts,
                    receive_ts,
                    transmit_ts,
                    current_time,
                );
            }
            IcmpResult::Invalid => self.stats.record_rx_error(),
            IcmpResult::Ignored => {}
        }
    }

    /// Process IPv6 packet data
    pub fn process_ipv6_data(
        &mut self,
        if_id: Option<super::NetIfId>,
        current_time: u64,
        src_mac: MacAddress,
        _reassembled: bool,
        ip_packet: PacketRef,
    ) {
        let mut ip_packet = Some(ip_packet);
        let ingress_if_id = self.resolve_ingress_if(if_id);
        let raw_endpoint = crate::net::l4::socket::find_raw_by_scope(ingress_if_id);
        if let Some(endpoint) = raw_endpoint.as_ref() {
            if let Some(packet) = ip_packet.take() {
                let _ = endpoint.deliver_raw_payload(
                    ingress_if_id,
                    kernel_api::resource::net::PacketPayload::single(packet),
                );
                return;
            }
        }

        // Detect fragment-header traffic up-front so ownership-preserving
        // reassembly path is selected before normal protocol dispatch.
        let is_fragment = matches!(
            crate::net::l3::ipv6::skip_extension_headers_fraginfo(
                ip_packet.as_ref().map_or(&[][..], PacketRef::data),
            ),
            crate::net::l3::ipv6::ExtHeaderResult::Fragment { .. }
        );
        let result = {
            let data = ip_packet.as_ref().map_or(&[][..], PacketRef::data);
            if is_fragment {
                let Some(packet_ref) = ip_packet.take() else {
                    self.stats.record_rx_error();
                    return;
                };
                if let Some(if_id) = if_id {
                    if let Some(state) = self.interfaces.get_mut(&if_id) {
                        if let Some(ref mut ipv6) = state.ipv6 {
                            ipv6.process_fragment_owned_packet(packet_ref, current_time)
                        } else if let Some(ref mut ipv6) = self.ipv6 {
                            ipv6.process_fragment_owned_packet(packet_ref, current_time)
                        } else {
                            return;
                        }
                    } else if let Some(ref mut ipv6) = self.ipv6 {
                        ipv6.process_fragment_owned_packet(packet_ref, current_time)
                    } else {
                        return;
                    }
                } else if let Some(ref mut ipv6) = self.ipv6 {
                    ipv6.process_fragment_owned_packet(packet_ref, current_time)
                } else {
                    return;
                }
            } else if let Some(if_id) = if_id {
                if let Some(state) = self.interfaces.get_mut(&if_id) {
                    if let Some(ref mut ipv6) = state.ipv6 {
                        ipv6.process_with_packet(data, current_time, ip_packet.as_ref())
                    } else if let Some(ref mut ipv6) = self.ipv6 {
                        ipv6.process_with_packet(data, current_time, ip_packet.as_ref())
                    } else {
                        return;
                    }
                } else if let Some(ref mut ipv6) = self.ipv6 {
                    ipv6.process_with_packet(data, current_time, ip_packet.as_ref())
                } else {
                    return;
                }
            } else if let Some(ref mut ipv6) = self.ipv6 {
                ipv6.process_with_packet(data, current_time, ip_packet.as_ref())
            } else {
                return;
            }
        };

        match result {
            Ipv6ProcessResult::Icmpv6(payload, src, dst, hop_limit) => {
                let (data_offset, payload_len) = {
                    let Some(packet_ref) = ip_packet.as_ref() else {
                        self.stats.record_rx_error();
                        return;
                    };
                    let Some(data_offset) =
                        crate::net::payload::subslice_offset(packet_ref.data(), payload)
                    else {
                        self.stats.record_rx_error();
                        return;
                    };
                    (data_offset, payload.len())
                };
                let Some(packet_ref) = ip_packet.take() else {
                    self.stats.record_rx_error();
                    return;
                };
                let original_packet = kernel_api::resource::net::PacketPayload::single(packet_ref);
                let Some(icmpv6_payload) = crate::net::payload::move_payload_window_owned(
                    original_packet,
                    data_offset,
                    payload_len,
                ) else {
                    self.stats.record_rx_error();
                    return;
                };
                self.process_icmpv6_data(
                    if_id,
                    icmpv6_payload,
                    src,
                    dst,
                    src_mac,
                    hop_limit,
                    current_time,
                );
            }
            Ipv6ProcessResult::Tcp(payload, src, dst, _hop_limit) => {
                let (offset, payload_len) = {
                    let Some(packet_ref) = ip_packet.as_ref() else {
                        self.stats.record_rx_error();
                        return;
                    };
                    let Some(offset) =
                        crate::net::payload::subslice_offset(packet_ref.data(), payload)
                    else {
                        self.stats.record_rx_error();
                        return;
                    };
                    (offset, payload.len())
                };
                let Some(packet_ref) = ip_packet.take() else {
                    self.stats.record_rx_error();
                    return;
                };
                let original_packet = kernel_api::resource::net::PacketPayload::single(packet_ref);
                let Some(tcp_segment_payload) = crate::net::payload::move_payload_window_owned(
                    original_packet,
                    offset,
                    payload_len,
                ) else {
                    self.stats.record_rx_error();
                    return;
                };
                crate::net::l4::tcp::tcp_rx::process_tcp_segment_v6_payload_on(
                    if_id,
                    src,
                    dst,
                    tcp_segment_payload,
                );
            }
            Ipv6ProcessResult::Udp(payload, src, dst, hop_limit) => {
                let (offset, payload_len) = {
                    let Some(packet_ref) = ip_packet.as_ref() else {
                        self.stats.record_rx_error();
                        return;
                    };
                    let Some(offset) =
                        crate::net::payload::subslice_offset(packet_ref.data(), payload)
                    else {
                        self.stats.record_rx_error();
                        return;
                    };
                    (offset, payload.len())
                };
                let Some(packet_ref) = ip_packet.take() else {
                    self.stats.record_rx_error();
                    return;
                };
                let original_packet = kernel_api::resource::net::PacketPayload::single(packet_ref);
                self.process_udp_payload_v6(
                    if_id,
                    original_packet,
                    offset,
                    payload_len,
                    src,
                    dst,
                    hop_limit,
                );
            }
            Ipv6ProcessResult::Reassembled(payload) => {
                // Reassembled IPv6 payload is offloaded to endpoint async path.
                crate::net::runtime::command::enqueue_command_ignore(
                    crate::net::runtime::command::RuntimeCommand::Ingress(
                        crate::net::runtime::command::IngressCommand::Reassembled {
                            if_id,
                            payload,
                        },
                    ),
                );
            }
            Ipv6ProcessResult::FragmentPending => {
                // Waiting for additional fragments.
            }
            Ipv6ProcessResult::ReassemblyTimeout(src, _dst, unfragmentable, frag_header) => {
                // RFC 8200: send ICMPv6 Time Exceeded (fragment reassembly timeout).
                log::info!(
                    "IPv6: Reassembly timeout for {} - sending ICMPv6 Time Exceeded",
                    src
                );

                // Include fragment header in quoted payload so sender can match
                // the Identification value.
                let mut quoted = unfragmentable;
                if let Some(fh) = frag_header {
                    let mut builder = crate::net::payload::PacketPayloadBuilder::new();
                    if builder.append_generated_bytes(&fh).is_some() {
                        crate::net::payload::append_payload(&mut quoted, builder.build());
                    } else {
                        self.stats.record_rx_error();
                        return;
                    }
                }
                let quoted = crate::net::payload::PacketPayloadView::new(&quoted);
                self.send_icmpv6_time_exceeded(src, 1, &quoted);
            }
            Ipv6ProcessResult::ReassemblyError(err, src, _dst, quoted_packet) => match err {
                crate::net::l3::ipv6::Ipv6ReassemblyError::Overlap => {
                    // RFC 8200 / RFC 5722: overlapping fragments are silently dropped.
                    log::warn!(
                        "IPv6: Fragment overlap from {} - discarding (RFC 8200)",
                        src
                    );
                }
                crate::net::l3::ipv6::Ipv6ReassemblyError::InvalidSize
                | crate::net::l3::ipv6::Ipv6ReassemblyError::PacketTooLarge => {
                    // RFC 8200: Parameter Problem, pointer to Payload Length field.
                    self.send_icmpv6_parameter_problem_payload(src, 0, 4, &quoted_packet);
                }
                crate::net::l3::ipv6::Ipv6ReassemblyError::IncompleteHeaderChain => {
                    // RFC 7112: pointer targets first byte of Fragment Header.
                    let fragment_header_pointer =
                        (quoted_packet.total_len() as u32).saturating_sub(8);
                    self.send_icmpv6_parameter_problem_payload(
                        src,
                        0,
                        fragment_header_pointer,
                        &quoted_packet,
                    );
                }
            },
            Ipv6ProcessResult::UnknownNextHeader(_proto, pointer, src, _dst, orig_packet) => {
                // RFC 4443 Section 3.4: Parameter Problem (Code 1).
                self.send_icmpv6_parameter_problem_payload(src, 1, pointer, &orig_packet);
            }
            Ipv6ProcessResult::HopLimitExceeded(src, _dst, orig_packet) => {
                // RFC 4443 Section 3.3: Time Exceeded (Code 0).
                let orig_packet = crate::net::payload::PacketPayloadView::new(&orig_packet);
                self.send_icmpv6_time_exceeded(src, 0, &orig_packet);
            }
            Ipv6ProcessResult::Dropped => self.stats.record_dropped(),
            Ipv6ProcessResult::Error => self.stats.record_rx_error(),
        }
    }

    // =========================================================================
    // IPv6 Processing
    // =========================================================================

    /// Process ICMPv6 data
    pub(crate) fn process_icmpv6_data(
        &mut self,
        if_id: Option<super::NetIfId>,
        payload: kernel_api::resource::net::PacketPayload,
        src: Ipv6Address,
        dst: Ipv6Address,
        src_mac: MacAddress,
        hop_limit: u8,
        current_time: u64,
    ) {
        let result = if let Some(if_id) = if_id {
            if let Some(state) = self.interfaces.get(&if_id) {
                if let Some(ref icmpv6) = state.icmpv6 {
                    icmpv6.process_payload(payload, src, dst, src_mac, hop_limit, current_time)
                } else if let Some(ref icmpv6) = self.icmpv6 {
                    icmpv6.process_payload(payload, src, dst, src_mac, hop_limit, current_time)
                } else {
                    return;
                }
            } else if let Some(ref icmpv6) = self.icmpv6 {
                icmpv6.process_payload(payload, src, dst, src_mac, hop_limit, current_time)
            } else {
                return;
            }
        } else if let Some(ref icmpv6) = self.icmpv6 {
            icmpv6.process_payload(payload, src, dst, src_mac, hop_limit, current_time)
        } else {
            return;
        };

        match result {
            Icmpv6Result::SendEchoReply {
                dst: reply_dst,
                identifier,
                sequence,
                data: echo_data,
            } => {
                // SECURITY: RFC 4443 に従い multicast Echo Request へ応答しない。
                if dst.is_multicast() {
                    return;
                }

                // Choose source address: if the original request was to our global address,
                // use that as source for the reply.
                let mut reply_src = None;
                if let Some(if_id) = if_id {
                    if let Some(config) = self
                        .interface_config_or_runtime(if_id)
                        .and_then(|cfg| cfg.ipv6)
                    {
                        if let Some(global) = config.global {
                            if dst == global {
                                reply_src = Some(global);
                            }
                        }
                        if reply_src.is_none() {
                            reply_src = Some(config.link_local);
                        }
                    }
                }
                if reply_src.is_none() {
                    if let Some(ref ipv6) = self.ipv6 {
                        let config = ipv6.config();
                        if let Some(global) = config.global {
                            if dst == global {
                                reply_src = Some(global);
                            }
                        }
                        if reply_src.is_none() {
                            reply_src = Some(config.link_local);
                        }
                    }
                }

                if let Some(src_addr) = reply_src {
                    if let Some(if_id) = if_id {
                        self.send_icmpv6_echo_reply_with_src_on(
                            if_id, src_addr, reply_dst, identifier, sequence, echo_data,
                        );
                    } else {
                        self.send_icmpv6_echo_reply_with_src(
                            src_addr, reply_dst, identifier, sequence, echo_data,
                        );
                    }
                }
            }
            Icmpv6Result::EchoReplyReceived {
                src: _,
                identifier,
                sequence,
            } => {
                log::info!(
                    "ICMPv6: Echo Reply received id={} seq={}",
                    identifier,
                    sequence
                );
            }
            Icmpv6Result::NdpMessage {
                msg_type,
                data: ndp_data,
                src: ndp_src,
                dst: ndp_dst,
                src_mac: ndp_src_mac,
                hop_limit,
            } => {
                self.process_ndp_message(
                    if_id,
                    msg_type,
                    ndp_data,
                    ndp_src,
                    ndp_dst,
                    ndp_src_mac,
                    hop_limit,
                    current_time,
                );
            }
            Icmpv6Result::PacketTooBig {
                quoted_src,
                dst,
                mtu,
                quoted_packet,
            } => {
                // SECURITY: RFC 8201 / RFC 5927 に従い、ICMPv6 message が
                // 自スタックの送信済み packet と active connection を引用していることを検証する。
                let mut is_our_packet = false;
                if let Some(if_id) = if_id {
                    if let Some(config) = self
                        .interface_config_or_runtime(if_id)
                        .and_then(|cfg| cfg.ipv6)
                    {
                        if quoted_src == config.link_local || config.global == Some(quoted_src) {
                            is_our_packet = true;
                        }
                    }
                }
                if !is_our_packet {
                    if let Some(ref ipv6) = self.ipv6 {
                        let config = ipv6.config();
                        if quoted_src == config.link_local {
                            is_our_packet = true;
                        } else if let Some(global) = config.global {
                            if quoted_src == global {
                                is_our_packet = true;
                            }
                        }
                    }
                }

                if is_our_packet {
                    // Further validation: check transport layer (ports/sequence numbers)
                    if let Some((final_proto, transport_payload)) =
                        crate::net::payload::ipv6_transport_payload(&quoted_packet)
                    {
                        match final_proto {
                            IpProtocol::Tcp => {
                                if let Some(header) = transport_payload.read_array::<8>(0) {
                                    let src_port = u16::from_be_bytes([header[0], header[1]]);
                                    let dst_port = u16::from_be_bytes([header[2], header[3]]);
                                    let seq_num = u32::from_be_bytes([
                                        header[4], header[5], header[6], header[7],
                                    ]);

                                    use crate::net::l4::tcp::EndpointAddr as TcpEndpointAddr;
                                    let local_addr =
                                        TcpEndpointAddr::new_v6(quoted_src.octets(), src_port);
                                    let remote_addr =
                                        TcpEndpointAddr::new_v6(dst.octets(), dst_port);

                                    if !crate::net::l4::tcp::tcb_table().validate_icmp_sequence(
                                        local_addr,
                                        remote_addr,
                                        seq_num,
                                    ) {
                                        log::warn!(
                                            "[NET] ICMPv6: PMTU error for {} rejected due to invalid TCP seq",
                                            dst
                                        );
                                        return;
                                    }
                                }
                            }
                            IpProtocol::Udp => {
                                if let Some(header) = transport_payload.read_array::<4>(0) {
                                    let src_port = u16::from_be_bytes([header[0], header[1]]);
                                    let has_udp_port =
                                        crate::net::l4::socket::has_udp_port(src_port);
                                    if !has_udp_port {
                                        log::warn!(
                                            "[NET] ICMPv6: PMTU error for {} rejected (no UDP socket on port {})",
                                            dst,
                                            src_port
                                        );
                                        return;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }

                    log::info!("ICMPv6: Packet Too Big for {}, MTU={}", dst, mtu);
                    // Update IPv6 Path MTU cache (RFC 8201)
                    let current_time = self.current_time();
                    if let Some(if_id) = if_id {
                        if let Some(state) = self.interfaces.get_mut(&if_id) {
                            state.ipv6_pmtu_cache.update(dst, mtu, current_time);
                        }
                    }
                    self.ipv6_pmtu_cache.update(dst, mtu, current_time);
                } else {
                    log::warn!(
                        "ICMPv6: Packet Too Big for {} rejected (quoted src {} is not local)",
                        dst,
                        quoted_src
                    );
                }
            }

            Icmpv6Result::DestinationUnreachable {
                code,
                quoted_src,
                quoted_dst,
                quoted_packet,
            } => {
                log::warn!(
                    "ICMPv6: Destination Unreachable (code={}) src={} dst={}",
                    code,
                    quoted_src,
                    quoted_dst
                );
                self.handle_icmpv6_error_transport_notification(
                    quoted_src,
                    quoted_dst,
                    Icmpv6Type::DestinationUnreachable,
                    code,
                    &quoted_packet,
                );
            }
            Icmpv6Result::TimeExceeded {
                code,
                quoted_src,
                quoted_dst,
                quoted_packet,
            } => {
                log::warn!(
                    "ICMPv6: Time Exceeded (code={}) src={} dst={}",
                    code,
                    quoted_src,
                    quoted_dst
                );
                self.handle_icmpv6_error_transport_notification(
                    quoted_src,
                    quoted_dst,
                    Icmpv6Type::TimeExceeded,
                    code,
                    &quoted_packet,
                );
            }
            Icmpv6Result::ParameterProblem {
                code,
                pointer,
                quoted_src,
                quoted_dst,
                quoted_packet,
            } => {
                log::warn!(
                    "ICMPv6: Parameter Problem (code={}, pointer={}) src={} dst={}",
                    code,
                    pointer,
                    quoted_src,
                    quoted_dst
                );
                self.handle_icmpv6_error_transport_notification(
                    quoted_src,
                    quoted_dst,
                    Icmpv6Type::ParameterProblem,
                    code,
                    &quoted_packet,
                );
            }
            Icmpv6Result::Dropped | Icmpv6Result::Error => {}
        }
    }

    /// Process NDP message
    pub(crate) fn process_ndp_message(
        &mut self,
        if_id: Option<super::NetIfId>,
        msg_type: crate::net::l3::icmpv6::Icmpv6Type,
        payload: kernel_api::resource::net::PacketPayload,
        src: Ipv6Address,
        dst: Ipv6Address,
        src_mac: MacAddress,
        hop_limit: u8,
        current_time: u64,
    ) {
        // SECURITY: RFC 4861 Section 6.1.1 に従い、IP Hop Limit は 255 でなければならない。
        // This ensures the packet was not forwarded by a router.
        if hop_limit != 255 {
            log::warn!("NDP: Dropping packet with invalid hop limit {}", hop_limit);
            return;
        }

        let result = if let Some(if_id) = if_id {
            if let Some(state) = self.interfaces.get_mut(&if_id) {
                if let Some(ref mut ndp) = state.ndp {
                    ndp.process_payload(
                        msg_type,
                        &payload,
                        src,
                        dst,
                        *src_mac.as_bytes(),
                        current_time,
                    )
                } else if let Some(ref mut ndp) = self.ndp {
                    ndp.process_payload(
                        msg_type,
                        &payload,
                        src,
                        dst,
                        *src_mac.as_bytes(),
                        current_time,
                    )
                } else {
                    return;
                }
            } else if let Some(ref mut ndp) = self.ndp {
                ndp.process_payload(
                    msg_type,
                    &payload,
                    src,
                    dst,
                    *src_mac.as_bytes(),
                    current_time,
                )
            } else {
                return;
            }
        } else if let Some(ref mut ndp) = self.ndp {
            ndp.process_payload(
                msg_type,
                &payload,
                src,
                dst,
                *src_mac.as_bytes(),
                current_time,
            )
        } else {
            return;
        };

        match result {
            NdpResult::SendNeighborAdvertisement {
                dst: na_dst,
                target,
                our_mac,
                solicited,
            } => {
                // Get our link-local address
                let our_addr = if let Some(if_id) = if_id {
                    self.interface_config_or_runtime(if_id)
                        .and_then(|cfg| cfg.ipv6)
                        .map(|cfg| cfg.link_local)
                } else {
                    self.ipv6.as_ref().map(|ipv6| ipv6.config().link_local)
                };
                if let Some(our_addr) = our_addr {
                    let Some(na_msg) =
                        NdpProcessor::build_na(&our_addr, &na_dst, &target, &our_mac, solicited)
                    else {
                        self.stats.record_dropped();
                        return;
                    };
                    if let Some(if_id) = if_id {
                        self.send_ipv6_icmpv6_on(if_id, &our_addr, &na_dst, na_msg);
                    } else {
                        self.send_ipv6_icmpv6(&our_addr, &na_dst, na_msg);
                    }
                    log::info!("NDP: Sent NA for {} to {}", target, na_dst);
                }
            }
            NdpResult::SendNeighborAdvertisementMulticast { target, our_mac } => {
                // Get our link-local address
                let our_addr = if let Some(if_id) = if_id {
                    self.interface_config_or_runtime(if_id)
                        .and_then(|cfg| cfg.ipv6)
                        .map(|cfg| cfg.link_local)
                } else {
                    self.ipv6.as_ref().map(|ipv6| ipv6.config().link_local)
                };
                if let Some(our_addr) = our_addr {
                    let mcast_dst = Ipv6Address::ALL_NODES_LINK_LOCAL;
                    let Some(na_msg) = NdpProcessor::build_na(
                        &our_addr, &mcast_dst, &target, &our_mac,
                        false, // solicited = false for multicast defense
                    ) else {
                        self.stats.record_dropped();
                        return;
                    };
                    if let Some(if_id) = if_id {
                        self.send_ipv6_icmpv6_on(if_id, &our_addr, &mcast_dst, na_msg);
                    } else {
                        self.send_ipv6_icmpv6(&our_addr, &mcast_dst, na_msg);
                    }
                    log::info!(
                        "NDP: Sent Multicast NA for {} to defend address (DAD)",
                        target
                    );
                }
            }
            NdpResult::SendNeighborSolicitation { src, dst, target } => {
                let src_mac = if let Some(if_id) = if_id {
                    self.interface_config_or_runtime(if_id)
                        .map(|cfg| *cfg.mac.as_bytes())
                        .unwrap_or(*self.config.mac.as_bytes())
                } else {
                    *self.config.mac.as_bytes()
                };
                let Some(ns_msg) = NdpProcessor::build_ns(&src, &dst, &target, &src_mac) else {
                    self.stats.record_dropped();
                    return;
                };
                if let Some(if_id) = if_id {
                    self.send_ipv6_icmpv6_on(if_id, &src, &dst, ns_msg);
                } else {
                    self.send_ipv6_icmpv6(&src, &dst, ns_msg);
                }
                log::info!("NDP: Sent NS from {} to {} for target {}", src, dst, target);
            }
            NdpResult::NeighborUpdated { ip, mac } => {
                log::info!(
                    "NDP: Neighbor {} -> {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    ip,
                    mac[0],
                    mac[1],
                    mac[2],
                    mac[3],
                    mac[4],
                    mac[5]
                );

                // NDP解決完了をウェイターレジストリへ通知（非同期NdpResolveFuture向け）
                crate::net::l3::ndp::notify_ndp_resolved(if_id.map(|id| id.0), ip.octets(), mac);

                // Drain any pending packets for this now-resolved neighbor
                if let Some(if_id) = if_id {
                    self.drain_ndp_pending_on(if_id, &ip);
                } else {
                    self.drain_ndp_pending(&ip);
                }
            }
            NdpResult::RouterAdvertisement {
                router,
                router_mac: _,
                prefixes,
            } => {
                log::info!(
                    "NDP: Router Advertisement from {}, {} prefixes",
                    router,
                    prefixes.len()
                );
                if let Some(if_id) = if_id {
                    let mut dad_messages = Vec::new();
                    if let Some(state) = self.interfaces.get_mut(&if_id) {
                        let mac_bytes = *state.config.mac.as_bytes();

                        for prefix_opt in &prefixes {
                            if let crate::net::l3::ndp::NdpOption::PrefixInfo {
                                prefix_len,
                                on_link: _,
                                autonomous,
                                valid_lifetime,
                                preferred_lifetime: _,
                                prefix,
                            } = prefix_opt
                            {
                                if *autonomous && *prefix_len == 64 && *valid_lifetime > 0 {
                                    let global_addr =
                                        Ipv6Address::from_prefix_eui64(prefix, &mac_bytes);

                                    if let Some(ref mut ipv6) = state.ipv6 {
                                        if ipv6.config().global != Some(global_addr) {
                                            ipv6.set_global_address(global_addr);
                                            if let Some(ref mut cfg) = state.config.ipv6 {
                                                cfg.global = Some(global_addr);
                                            }
                                            log::info!(
                                                "SLAAC: Configured interface {} global address {} from prefix {}",
                                                if_id.0,
                                                global_addr,
                                                prefix
                                            );

                                            if let Some(ref mut ndp_proc) = state.ndp {
                                                if let NdpResult::SendNeighborSolicitation {
                                                    src,
                                                    dst,
                                                    target,
                                                } = ndp_proc.initiate_dad(&global_addr)
                                                {
                                                    let Some(ns_msg) = NdpProcessor::build_ns(
                                                        &src, &dst, &target, &mac_bytes,
                                                    ) else {
                                                        self.stats.record_dropped();
                                                        continue;
                                                    };
                                                    dad_messages.push((src, dst, ns_msg, target));
                                                }
                                            }
                                        }
                                    }

                                    if let Some(ref mut ndp) = state.ndp {
                                        ndp.add_global_address(global_addr);
                                    }
                                }
                            } else if let crate::net::l3::ndp::NdpOption::RecursiveDnsServer {
                                lifetime,
                                servers,
                            } = prefix_opt
                            {
                                if *lifetime > 0 {
                                    for server in servers {
                                        crate::net::services::dns::add_ipv6_server(*server);
                                        log::info!(
                                            "NDP: Added DNS server {} from RDNSS option",
                                            server
                                        );
                                    }
                                }
                            }
                        }

                        if let Some(ref mut ipv6) = state.ipv6 {
                            if ipv6.config().gateway.is_none() {
                                ipv6.config_mut().gateway = Some(router);
                                if let Some(ref mut cfg) = state.config.ipv6 {
                                    cfg.gateway = Some(router);
                                }
                                log::info!(
                                    "SLAAC: Set interface {} default gateway to {}",
                                    if_id.0,
                                    router
                                );
                            }
                        }
                    }

                    for (src, dst, ns_msg, target) in dad_messages {
                        self.send_ipv6_icmpv6_on(if_id, &src, &dst, ns_msg);
                        log::info!("NDP: Sent DAD NS for target {}", target);
                    }
                    return;
                }

                // SLAAC (RFC 4862): Apply prefix information
                for prefix_opt in &prefixes {
                    if let crate::net::l3::ndp::NdpOption::PrefixInfo {
                        prefix_len,
                        on_link: _,
                        autonomous,
                        valid_lifetime,
                        preferred_lifetime: _,
                        prefix,
                    } = prefix_opt
                    {
                        // Only process /64 autonomous prefixes with non-zero lifetime
                        if *autonomous && *prefix_len == 64 && *valid_lifetime > 0 {
                            if let Some(ref mut ipv6) = self.ipv6 {
                                let mac_bytes = self.config.mac.as_bytes();
                                let global_addr = Ipv6Address::from_prefix_eui64(prefix, mac_bytes);
                                // Only set if we don't already have this address
                                if ipv6.config().global != Some(global_addr) {
                                    ipv6.set_global_address(global_addr);
                                    log::info!(
                                        "SLAAC: Configured global address {} from prefix {}",
                                        global_addr,
                                        prefix
                                    );

                                    // Initiate Duplicate Address Detection (RFC 4862)
                                    if let Some(ref mut ndp_proc) = self.ndp {
                                        let dad_res = ndp_proc.initiate_dad(&global_addr);
                                        match dad_res {
                                            NdpResult::SendNeighborSolicitation {
                                                src,
                                                dst,
                                                target,
                                            } => {
                                                let Some(ns_msg) = NdpProcessor::build_ns(
                                                    &src,
                                                    &dst,
                                                    &target,
                                                    self.config.mac.as_bytes(),
                                                ) else {
                                                    self.stats.record_dropped();
                                                    continue;
                                                };
                                                if let Some(if_id) = if_id {
                                                    self.send_ipv6_icmpv6_on(
                                                        if_id, &src, &dst, ns_msg,
                                                    );
                                                } else {
                                                    self.send_ipv6_icmpv6(&src, &dst, ns_msg);
                                                }
                                                log::info!(
                                                    "NDP: Sent DAD NS for target {}",
                                                    target
                                                );
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                            if let Some(ref mut ndp) = self.ndp {
                                let mac_bytes = self.config.mac.as_bytes();
                                let global_addr = Ipv6Address::from_prefix_eui64(prefix, mac_bytes);
                                ndp.add_global_address(global_addr);
                            }
                        }
                    } else if let crate::net::l3::ndp::NdpOption::RecursiveDnsServer {
                        lifetime,
                        servers,
                    } = prefix_opt
                    {
                        if *lifetime > 0 {
                            for server in servers {
                                crate::net::services::dns::add_ipv6_server(*server);
                                log::info!("NDP: Added DNS server {} from RDNSS option", server);
                            }
                        }
                    }
                }
                // Set router as default gateway
                if let Some(ref mut ipv6) = self.ipv6 {
                    if ipv6.config().gateway.is_none() {
                        ipv6.config_mut().gateway = Some(router);
                        log::info!("SLAAC: Set default gateway to {}", router);
                    }
                }
            }
            NdpResult::Redirect {
                target,
                destination,
            } => {
                // SECURITY: check 0: Redirect handling が global に有効か確認する。
                if !self.config.icmpv6_redirect_enabled {
                    log::warn!(
                        "NDP: Ignoring Redirect for {} to target router {} (Security: disabled by default)",
                        destination,
                        target
                    );
                } else {
                    log::info!(
                        "NDP: Applying Redirect for {} to target router {}",
                        destination,
                        target
                    );
                    // Update IPv6 Path MTU or routing table with redirect info
                    // Currently we don't have a separate IPv6 redirect cache like IPv4,
                    // but we could theoretically update the neighbor cache (already done in process_redirect).
                }
            }
            NdpResult::None | NdpResult::Error => {}
        }
    }

    pub fn process_igmp_payload(
        &mut self,
        payload: &kernel_api::resource::net::PacketPayload,
        src_ip: Ipv4Address,
        ttl: u8,
    ) {
        if ttl != 1 {
            log::warn!("IGMP: Dropping packet with invalid TTL {}", ttl);
            return;
        }

        let local_ip = self.config.ipv4.address;
        let subnet_mask = self.config.ipv4.subnet_mask;
        if local_ip.apply_mask(subnet_mask) != src_ip.apply_mask(subnet_mask) {
            log::warn!("IGMP: Dropping packet from different subnet {}", src_ip);
            return;
        }

        let current_time = self.current_time();
        self.igmp.update_time(current_time);

        match self.igmp.process_payload(payload, src_ip) {
            IgmpResult::GeneralQueryReceived { max_resp_time: _ } => {}
            IgmpResult::GroupQueryReceived {
                group: _,
                max_resp_time: _,
            } => {}
            IgmpResult::ReportReceived { group: _ } => {}
            IgmpResult::Ignored => {}
            IgmpResult::InvalidPacket | IgmpResult::InvalidChecksum => {
                self.stats.record_rx_error();
            }
            IgmpResult::UnknownType(_) => {
                self.stats.record_dropped();
            }
        }

        self.send_pending_igmp_reports();
    }
}
