// =============================================================================
// Receive Path — IPv4/IPv6 incoming packet processing
//
// Split from core_impl/mod.rs for clarity. Contains all methods that process
// incoming packets: process_ipv4, process_ipv6_data, process_icmpv6_data,
// process_ndp_message, process_igmp_data, etc.
// =============================================================================

use super::*;

impl NetworkStack {
    /// Process an incoming packet (main entry point)
    /// Receive a packet from the network
    pub fn receive(&mut self, packet: PacketRef) {
        self.receive_on(None, packet);
    }

    /// Process an incoming packet received on a specific interface.
    pub fn receive_on(&mut self, if_id: Option<super::NetIfId>, packet: PacketRef) {
        // Offload ALL packet processing to the asynchronous endpoint stack.
        // This minimizes time spent in the interrupt/polling context.
        crate::net::l4::endpoint::event::send_event_ignore(
            crate::net::l4::endpoint::event::NetworkEvent::IngressPacket { if_id, packet },
        );
    }

    /// Process a batch of incoming packets
    ///
    /// バッチイベントとして一括送信し、イベントキューのロック取得を
    /// 1回に削減することでハイスループット時のオーバーヘッドを低減する。
    pub fn receive_batch(&mut self, batch: PacketBatch) {
        self.receive_batch_on(None, batch);
    }

    /// Process a batch of incoming packets from the same ingress interface.
    pub fn receive_batch_on(&mut self, if_id: Option<super::NetIfId>, batch: PacketBatch) {
        let packets: Vec<PacketRef> = batch.into_iter().collect();
        if packets.is_empty() {
            return;
        }
        crate::net::l4::endpoint::event::send_batch_event_on(if_id, packets);
    }

    /// Process IPv4 packet
    pub(crate) fn process_ipv4(
        &mut self,
        data: &[u8],
        current_time: u64,
        packet: PacketRef,
        _src_mac: MacAddress,
    ) {
        let result = self.ipv4.process_with_time(data, current_time);

        match result {
            Ipv4ProcessResult::Icmp(payload, src_ip, dst_ip, ttl, _orig) => {
                // Security: Only process multicast ICMP if group is joined (except mandatory)
                if dst_ip.is_multicast() && !self.is_multicast_allowed(dst_ip) {
                    self.stats.record_dropped();
                    return;
                }
                if payload.as_ptr() < data.as_ptr()
                    || payload.as_ptr() as usize + payload.len()
                        > data.as_ptr() as usize + data.len()
                {
                    self.stats.record_rx_error();
                    return;
                }
                let offset = unsafe { payload.as_ptr().offset_from(data.as_ptr()) } as usize;
                let mut p = packet;
                p.advance(offset);
                self.process_icmp(payload, src_ip, dst_ip, ttl, current_time, p);
            }
            Ipv4ProcessResult::Igmp(payload, src_ip, ttl, _orig) => {
                self.process_igmp_data(payload, src_ip, ttl);
            }
            Ipv4ProcessResult::Udp(_payload, _src_ip, dst_ip, _orig) => {
                // Security: Only process multicast UDP if group is joined (except mandatory)
                if dst_ip.is_multicast() && !self.is_multicast_allowed(dst_ip) {
                    self.stats.record_dropped();
                    return;
                }

                // Offload to asynchronous endpoint stack
                crate::net::l4::endpoint::event::send_event_ignore(
                    crate::net::l4::endpoint::event::NetworkEvent::IngressPacket {
                        if_id: None,
                        packet: packet.clone(),
                    },
                );
            }
            Ipv4ProcessResult::Tcp(_payload, _src_ip, dst_ip, _orig) => {
                // Security: TCP multicast/broadcast is generally not allowed/supported (RFC 793 / RFC 1122)
                if dst_ip.is_multicast()
                    || dst_ip.is_broadcast()
                    || (self.config().ipv4.subnet_mask.as_bytes()[0] != 0
                        && dst_ip == self.config().ipv4.broadcast_address())
                {
                    self.stats.record_dropped();
                    return;
                }

                // Offload to asynchronous endpoint stack
                crate::net::l4::endpoint::event::send_event_ignore(
                    crate::net::l4::endpoint::event::NetworkEvent::IngressPacket {
                        if_id: None,
                        packet: packet.clone(),
                    },
                );
            }
            Ipv4ProcessResult::Reassembled(reassembled_data) => {
                // Security Fix: Offload reassembled packets to the asynchronous endpoint stack
                // instead of processing them directly. This ensures fragmented packets are
                // handled by the same stack as normal packets, preventing DoS and state bypass.

                // We perform basic filtering here as well
                if let Some(packet) = Ipv4Packet::parse(&reassembled_data) {
                    let dst = packet.destination();
                    if packet.protocol() == IpProtocol::Tcp
                        && (dst.is_multicast()
                            || dst.is_broadcast()
                            || (self.config().ipv4.subnet_mask.as_bytes()[0] != 0
                                && dst == self.config().ipv4.broadcast_address()))
                    {
                        self.stats.record_dropped();
                        return;
                    }
                }

                crate::net::l4::endpoint::event::send_event_ignore(
                    crate::net::l4::endpoint::event::NetworkEvent::ReassembledPacket {
                        if_id: None,
                        data: reassembled_data,
                    },
                );
            }
            Ipv4ProcessResult::FragmentPending => {
                // Fragment received, waiting for more fragments
                // Nothing to do here
            }
            Ipv4ProcessResult::ReassemblyTimeout(src, header_data) => {
                // RFC 792: Send ICMP Time Exceeded (Fragment Reassembly Time Exceeded)
                log::info!(
                    "IPv4: Reassembly timeout for {} - sending ICMP Time Exceeded",
                    src
                );
                self.send_icmp_time_exceeded(
                    src,
                    crate::net::l3::icmp::TimeExceededCode::FragmentReassemblyExceeded,
                    &header_data,
                );
            }
            Ipv4ProcessResult::UnknownProtocol(proto, src, _dst, orig_packet) => {
                // RFC 792: Send ICMP Destination Unreachable (Protocol Unreachable, Code 2)
                log::warn!(
                    "IPv4: Unknown protocol {} from {} - sending ICMP Protocol Unreachable",
                    proto,
                    src
                );
                self.send_icmp_error(
                    src,
                    crate::net::l3::icmp::DestUnreachCode::ProtocolUnreachable,
                    None,
                    orig_packet,
                    current_time,
                );
            }
            Ipv4ProcessResult::Dropped => {
                self.stats.record_dropped();
            }
            Ipv4ProcessResult::Error => {
                self.stats.record_rx_error();
            }
            Ipv4ProcessResult::Success => {}
        }
    }

    /// Process a reassembled IP packet
    pub fn process_reassembled_packet(
        &mut self,
        data: &[u8],
        current_time: u64,
        _src_mac: MacAddress,
    ) {
        // Parse the reassembled packet
        if let Some(packet) = Ipv4Packet::parse(data) {
            let src = packet.source();
            let dst = packet.destination();
            let payload = packet.payload();
            let protocol = packet.protocol();

            // ── ファイアウォール Reassembled パケットチェック ──
            // 再組立て後のパケットに対して再度ファイアウォールを適用する。
            // これにより、フラグメント化によるポートベースルールの回避を防止する。
            let (src_port, dst_port, tcp_flags) = match protocol {
                IpProtocol::Tcp if payload.len() >= 20 => {
                    let sp = u16::from_be_bytes([payload[0], payload[1]]);
                    let dp = u16::from_be_bytes([payload[2], payload[3]]);
                    let flags = payload[13];
                    (sp, dp, flags)
                }
                IpProtocol::Udp if payload.len() >= 8 => {
                    let sp = u16::from_be_bytes([payload[0], payload[1]]);
                    let dp = u16::from_be_bytes([payload[2], payload[3]]);
                    (sp, dp, 0)
                }
                IpProtocol::Icmp if payload.len() >= 2 => {
                    // ICMP type in src_port, code in dst_port
                    (payload[0] as u16, payload[1] as u16, 0)
                }
                _ => (0, 0, 0),
            };

            if !crate::net::security::firewall::check_ingress_v4(
                src.octets(),
                dst.octets(),
                protocol.into(),
                src_port,
                dst_port,
                tcp_flags,
            ) {
                log::warn!(
                    "[FIREWALL] Reassembled packet BLOCKED: {}:{} -> {}:{} proto={}",
                    src,
                    src_port,
                    dst,
                    dst_port,
                    u8::from(protocol)
                );
                self.stats.record_dropped();
                return;
            }

            // Security: Only process multicast/broadcast packets if intended (RFC 1122)
            if (dst.is_multicast() && !self.is_multicast_allowed(dst))
                || dst.is_broadcast()
                || (self.config().ipv4.subnet_mask.as_bytes()[0] != 0
                    && dst == self.config().ipv4.broadcast_address())
            {
                self.stats.record_dropped();
                return;
            }

            match packet.protocol() {
                IpProtocol::Tcp => {
                    // Security Fix: TCP multicast/broadcast is not allowed
                    if dst.is_multicast()
                        || dst.is_broadcast()
                        || (self.config().ipv4.subnet_mask.as_bytes()[0] != 0
                            && dst == self.config().ipv4.broadcast_address())
                    {
                        self.stats.record_dropped();
                        return;
                    }
                    // Security Fix: Process TCP through the endpoint stack
                    crate::net::l4::endpoint::tcp_rx::process_tcp_segment(
                        src.octets(),
                        dst.octets(),
                        payload,
                    );
                }
                IpProtocol::Igmp => {
                    // Process IGMP for multicast group management
                    self.process_igmp_data(payload, src, packet.ttl());
                }
                IpProtocol::Udp => {
                    // Security Fix: Process UDP through the endpoint stack
                    // Use process_udp_data instead of self.udp.process
                    self.process_udp_data(payload, src, dst, packet.ttl(), data, current_time);
                }
                _ => {
                    self.stats.record_dropped();
                }
            }
        }
    }

    /// Process ICMP data (for reassembled packets)
    pub fn process_icmp_data(
        &mut self,
        data: &[u8],
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        _ttl: u8,
        current_time: u64,
    ) {
        if !self.icmp_echo_enabled() {
            return;
        }

        // Security: Do not respond to broadcast/multicast ICMP Echo Requests (Smurf attack prevention)
        if dst_ip.is_broadcast()
            || dst_ip.is_multicast()
            || dst_ip == self.ipv4.config().broadcast_address()
        {
            return;
        }

        let result = self.icmp.process(data, src_ip, dst_ip, current_time);

        match result {
            IcmpResult::SendEchoReply {
                src_ip,
                identifier,
                sequence,
                data_offset,
                data_len,
            } => {
                let echo_data = if data_offset + data_len <= data.len() {
                    &data[data_offset..data_offset + data_len]
                } else {
                    &[]
                };
                self.send_icmp_echo_reply(src_ip, identifier, sequence, echo_data, current_time);
            }
            IcmpResult::EchoReplyReceived {
                identifier,
                sequence,
            } => {
                // ICMP Echo応答を非同期Futureレジストリに通知
                let _ = identifier;
                // RTTを概算（正確なタイムスタンプは別途管理が必要）
                let rtt_us = 0; // イベントキュー側で計算
                crate::net::l4::endpoint::futures::notify_icmp_echo_reply(
                    *src_ip.as_bytes(),
                    sequence,
                    rtt_us,
                );
                // イベントキュー経由でも通知（ハンドラ層での処理用）
                crate::net::l4::endpoint::event::send_event_ignore(
                    crate::net::l4::endpoint::event::NetworkEvent::IcmpEchoReply {
                        source: *src_ip.as_bytes(),
                        sequence,
                        rtt_us,
                    },
                );
            }
            IcmpResult::Error { icmp_type, code } => {
                // Handle ICMP errors for PMTUD (RFC 1191)
                self.handle_icmp_error(data, icmp_type, code, current_time);
            }
            IcmpResult::Redirect {
                code,
                gateway,
                destination,
            } => {
                // Handle ICMP Redirect for route optimization (RFC 792)
                self.handle_icmp_redirect(code, gateway, destination, src_ip);
            }
            _ => {}
        }
    }

    // =========================================================================
    // IPv6 Processing
    // =========================================================================

    /// Process IPv6 packet data
    pub fn process_ipv6_data(
        &mut self,
        if_id: Option<super::NetIfId>,
        data: &[u8],
        current_time: u64,
        src_mac: MacAddress,
        _reassembled: bool,
    ) {
        let result = if let Some(if_id) = if_id {
            if let Some(state) = self.interfaces.get_mut(&if_id) {
                if let Some(ref mut ipv6) = state.ipv6 {
                    ipv6.process(data, current_time)
                } else if let Some(ref mut ipv6) = self.ipv6 {
                    ipv6.process(data, current_time)
                } else {
                    return;
                }
            } else if let Some(ref mut ipv6) = self.ipv6 {
                ipv6.process(data, current_time)
            } else {
                return;
            }
        } else if let Some(ref mut ipv6) = self.ipv6 {
            ipv6.process(data, current_time)
        } else {
            return;
        };

        match result {
            Ipv6ProcessResult::Icmpv6(payload, src, dst, hop_limit) => {
                self.process_icmpv6_data(if_id, payload, src, dst, src_mac, hop_limit, current_time);
            }
            Ipv6ProcessResult::Tcp(payload, src, dst, _hop_limit) => {
                crate::net::l4::endpoint::tcp_rx::process_tcp_segment_v6_on(
                    if_id,
                    src,
                    dst,
                    payload,
                );
            }
            Ipv6ProcessResult::Udp(payload, src, dst, hop_limit) => {
                self.process_udp_data_v6(if_id, payload, src, dst, hop_limit, data);
            }
            Ipv6ProcessResult::Reassembled(reassembled_data) => {
                // Security Fix: Offload reassembled IPv6 packets to the asynchronous endpoint stack
                crate::net::l4::endpoint::event::send_event_ignore(
                    crate::net::l4::endpoint::event::NetworkEvent::ReassembledPacket {
                        if_id,
                        data: reassembled_data,
                    },
                );
            }
            Ipv6ProcessResult::FragmentPending => {}
            Ipv6ProcessResult::ReassemblyTimeout(src, _dst, unfragmentable, frag_header) => {
                // RFC 8200: Send ICMPv6 Time Exceeded (Fragment Reassembly Time Exceeded)
                log::info!(
                    "IPv6: Reassembly timeout for {} - sending ICMPv6 Time Exceeded",
                    src
                );

                // Security/RFC Compliance: Include the fragment header in the quoted packet
                // so the sender can identify the datagram via the Identification field.
                let mut quoted = unfragmentable;
                if let Some(fh) = frag_header {
                    quoted.extend_from_slice(&fh);
                }
                self.send_icmpv6_time_exceeded(src, 1, &quoted);
            }
            Ipv6ProcessResult::ReassemblyError(err, src, _dst, quoted_packet) => {
                match err {
                    crate::net::l3::ipv6::Ipv6ReassemblyError::Overlap => {
                        // RFC 8200/5722: Silent discard for overlapping fragments (no ICMP error required)
                        log::warn!(
                            "IPv6: Fragment overlap from {} - discarding (RFC 8200)",
                            src
                        );
                    }
                    crate::net::l3::ipv6::Ipv6ReassemblyError::InvalidSize => {
                        // RFC 8200: Send ICMPv6 Parameter Problem (Code 0), pointing to Payload Length
                        // Payload Length is at offset 4 in IPv6 header
                        log::warn!(
                            "IPv6: Invalid fragment size (not multiple of 8) from {} - sending ICMPv6 Parameter Problem (RFC 8200)",
                            src
                        );
                        self.send_icmpv6_parameter_problem(src, 0, 4, &quoted_packet);
                    }
                    crate::net::l3::ipv6::Ipv6ReassemblyError::PacketTooLarge => {
                        // RFC 8200: If the reassembled packet would be larger than 65,535 octets,
                        // send ICMPv6 Parameter Problem Code 0 pointing to Payload Length field.
                        log::warn!(
                            "IPv6: Fragmented packet too large from {} - sending ICMPv6 Parameter Problem (RFC 8200)",
                            src
                        );
                        self.send_icmpv6_parameter_problem(src, 0, 4, &quoted_packet);
                    }
                    crate::net::l3::ipv6::Ipv6ReassemblyError::IncompleteHeaderChain => {
                        // RFC 7112: Send ICMPv6 Parameter Problem (Code 0), pointing to the first octet
                        // of the Fragment Header.
                        // quoted_packet contains unfragmentable + 8-byte fragment header.
                        let fragment_header_pointer =
                            (quoted_packet.len() as u32).saturating_sub(8);
                        log::warn!(
                            "IPv6: Incomplete header chain in first fragment from {} - sending ICMPv6 Parameter Problem (RFC 7112)",
                            src
                        );
                        self.send_icmpv6_parameter_problem(
                            src,
                            0,
                            fragment_header_pointer,
                            &quoted_packet,
                        );
                    }
                }
            }
            Ipv6ProcessResult::UnknownNextHeader(_proto, pointer, src, _dst, orig_packet) => {
                // RFC 4443 Section 3.4: Send ICMPv6 Parameter Problem (Code 1)
                log::warn!(
                    "IPv6: Unknown Next Header from {} - sending ICMPv6 Parameter Problem",
                    src
                );
                self.send_icmpv6_parameter_problem(src, 1, pointer, orig_packet);
            }
            Ipv6ProcessResult::HopLimitExceeded(src, _dst, orig_packet) => {
                // RFC 4443 Section 3.3: Send ICMPv6 Time Exceeded (Code 0)
                log::warn!(
                    "IPv6: Hop Limit exceeded from {} - sending ICMPv6 Time Exceeded",
                    src
                );
                self.send_icmpv6_time_exceeded(src, 0, orig_packet);
            }
            Ipv6ProcessResult::Dropped => {
                self.stats.record_dropped();
            }
            Ipv6ProcessResult::Error => {
                self.stats.record_rx_error();
            }
        }
    }

    /// Process ICMPv6 data
    pub(crate) fn process_icmpv6_data(
        &mut self,
        if_id: Option<super::NetIfId>,
        data: &[u8],
        src: Ipv6Address,
        dst: Ipv6Address,
        src_mac: MacAddress,
        hop_limit: u8,
        current_time: u64,
    ) {
        let result = if let Some(if_id) = if_id {
            if let Some(state) = self.interfaces.get(&if_id) {
                if let Some(ref icmpv6) = state.icmpv6 {
                    icmpv6.process(data, src, dst, src_mac, hop_limit, current_time)
                } else if let Some(ref icmpv6) = self.icmpv6 {
                    icmpv6.process(data, src, dst, src_mac, hop_limit, current_time)
                } else {
                    return;
                }
            } else if let Some(ref icmpv6) = self.icmpv6 {
                icmpv6.process(data, src, dst, src_mac, hop_limit, current_time)
            } else {
                return;
            }
        } else if let Some(ref icmpv6) = self.icmpv6 {
            icmpv6.process(data, src, dst, src_mac, hop_limit, current_time)
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
                // Security (RFC 4443): SHOULD NOT respond to multicast Echo Requests
                if dst.is_multicast() {
                    return;
                }

                // Choose source address: if the original request was to our global address,
                // use that as source for the reply.
                let mut reply_src = None;
                if let Some(if_id) = if_id {
                    if let Some(config) = self.interface_config_or_runtime(if_id).and_then(|cfg| cfg.ipv6)
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
                            if_id,
                            src_addr,
                            reply_dst,
                            identifier,
                            sequence,
                            &echo_data,
                        );
                    } else {
                        self.send_icmpv6_echo_reply_with_src(
                            src_addr, reply_dst, identifier, sequence, &echo_data,
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
                    &ndp_data,
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
                // Security check (RFC 8201 / RFC 5927): Verify that the ICMPv6 message quotes
                // a packet that we actually sent and corresponds to an active connection.
                let mut is_our_packet = false;
                if let Some(if_id) = if_id {
                    if let Some(config) = self.interface_config_or_runtime(if_id).and_then(|cfg| cfg.ipv6)
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
                    // Quoted packet starts with an IPv6 header (40 bytes)
                    if quoted_packet.len() >= 40 {
                        let next_header = quoted_packet[6];
                        let payload = &quoted_packet[40..];

                        // Skip extension headers to find the upper-layer header
                        use crate::net::l3::ipv6::skip_extension_headers;
                        let (final_proto, transport_data) =
                            skip_extension_headers(IpProtocol::from(next_header), payload);

                        match final_proto {
                            IpProtocol::Tcp => {
                                if transport_data.len() >= 8 {
                                    let src_port =
                                        u16::from_be_bytes([transport_data[0], transport_data[1]]);
                                    let dst_port =
                                        u16::from_be_bytes([transport_data[2], transport_data[3]]);
                                    let seq_num = u32::from_be_bytes([
                                        transport_data[4],
                                        transport_data[5],
                                        transport_data[6],
                                        transport_data[7],
                                    ]);

                                    use crate::net::l4::tcp::EndpointAddr as TcpEndpointAddr;
                                    let local_addr =
                                        TcpEndpointAddr::new_v6(quoted_src.octets(), src_port);
                                    let remote_addr =
                                        TcpEndpointAddr::new_v6(dst.octets(), dst_port);

                                    if !self.tcp.validate_icmp_sequence(
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
                                if transport_data.len() >= 4 {
                                    let src_port =
                                        u16::from_be_bytes([transport_data[0], transport_data[1]]);
                                    if !self.udp.has_endpoint(src_port) {
                                        log::warn!(
                                            "[NET] ICMPv6: PMTU error for {} rejected (no UDP socket on port {})",
                                            dst,
                                            src_port
                                        );
                                        return;
                                    }
                                }
                            }
                            _ => {
                                // For other protocols, we've already checked the IP addresses
                            }
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
        data: &[u8],
        src: Ipv6Address,
        dst: Ipv6Address,
        src_mac: MacAddress,
        hop_limit: u8,
        current_time: u64,
    ) {
        // Security (RFC 4861 Section 6.1.1): The IP Hop Limit field MUST have a value of 255.
        // This ensures the packet was not forwarded by a router.
        if hop_limit != 255 {
            log::warn!("NDP: Dropping packet with invalid hop limit {}", hop_limit);
            return;
        }

        let result = if let Some(if_id) = if_id {
            if let Some(state) = self.interfaces.get_mut(&if_id) {
                if let Some(ref mut ndp) = state.ndp {
                    ndp.process(msg_type, data, src, dst, *src_mac.as_bytes(), current_time)
                } else if let Some(ref mut ndp) = self.ndp {
                    ndp.process(msg_type, data, src, dst, *src_mac.as_bytes(), current_time)
                } else {
                    return;
                }
            } else if let Some(ref mut ndp) = self.ndp {
                ndp.process(msg_type, data, src, dst, *src_mac.as_bytes(), current_time)
            } else {
                return;
            }
        } else if let Some(ref mut ndp) = self.ndp {
            ndp.process(msg_type, data, src, dst, *src_mac.as_bytes(), current_time)
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
                    let na_msg =
                        NdpProcessor::build_na(&our_addr, &na_dst, &target, &our_mac, solicited);
                    if let Some(if_id) = if_id {
                        self.send_ipv6_icmpv6_on(if_id, &our_addr, &na_dst, &na_msg);
                    } else {
                        self.send_ipv6_icmpv6(&our_addr, &na_dst, &na_msg);
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
                    let na_msg = NdpProcessor::build_na(
                        &our_addr, &mcast_dst, &target, &our_mac,
                        false, // solicited = false for multicast defense
                    );
                    if let Some(if_id) = if_id {
                        self.send_ipv6_icmpv6_on(if_id, &our_addr, &mcast_dst, &na_msg);
                    } else {
                        self.send_ipv6_icmpv6(&our_addr, &mcast_dst, &na_msg);
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
                let ns_msg = NdpProcessor::build_ns(&src, &dst, &target, &src_mac);
                if let Some(if_id) = if_id {
                    self.send_ipv6_icmpv6_on(if_id, &src, &dst, &ns_msg);
                } else {
                    self.send_ipv6_icmpv6(&src, &dst, &ns_msg);
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
                                                    let ns_msg = NdpProcessor::build_ns(
                                                        &src,
                                                        &dst,
                                                        &target,
                                                        &mac_bytes,
                                                    );
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
                        self.send_ipv6_icmpv6_on(if_id, &src, &dst, &ns_msg);
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
                                                let ns_msg = NdpProcessor::build_ns(
                                                    &src,
                                                    &dst,
                                                    &target,
                                                    self.config.mac.as_bytes(),
                                                );
                                                if let Some(if_id) = if_id {
                                                    self.send_ipv6_icmpv6_on(
                                                        if_id,
                                                        &src,
                                                        &dst,
                                                        &ns_msg,
                                                    );
                                                } else {
                                                    self.send_ipv6_icmpv6(&src, &dst, &ns_msg);
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
                // Security check 0: Is Redirect handling enabled globally?
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

    /// Process IGMP data for multicast group management
    pub fn process_igmp_data(&mut self, data: &[u8], src_ip: Ipv4Address, ttl: u8) {
        // Security (RFC 2236 Section 2): all IGMP messages MUST be sent with a IP TTL of 1.
        if ttl != 1 {
            log::warn!("IGMP: Dropping packet with invalid TTL {}", ttl);
            return;
        }

        // Security: Verify source is on the same subnet
        let local_ip = self.config.ipv4.address;
        let subnet_mask = self.config.ipv4.subnet_mask;
        if local_ip.apply_mask(subnet_mask) != src_ip.apply_mask(subnet_mask) {
            log::warn!("IGMP: Dropping packet from different subnet {}", src_ip);
            return;
        }

        let current_time = self.current_time();
        self.igmp.update_time(current_time);

        let result = self.igmp.process(data, src_ip);

        match result {
            IgmpResult::GeneralQueryReceived { max_resp_time: _ } => {
                // Timers are set internally, reports will be sent on timer expiry
            }
            IgmpResult::GroupQueryReceived {
                group: _,
                max_resp_time: _,
            } => {
                // Timer set for specific group
            }
            IgmpResult::ReportReceived { group: _ } => {
                // Report suppression handled internally
            }
            IgmpResult::Ignored => {}
            IgmpResult::InvalidPacket | IgmpResult::InvalidChecksum => {
                self.stats.record_rx_error();
            }
            IgmpResult::UnknownType(_) => {
                self.stats.record_dropped();
            }
        }

        // Process and send any pending IGMP reports
        self.send_pending_igmp_reports();
    }
}
