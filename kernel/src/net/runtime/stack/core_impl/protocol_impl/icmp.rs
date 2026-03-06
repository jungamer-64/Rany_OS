// ============================================================================
// ICMP-related NetworkStack impl methods
// ============================================================================
//! ICMP packet processing, error message construction, PMTUD handling,
//! ICMP Redirect processing, and ICMP echo request/reply.

use super::*;
use crate::net::l3::icmp::{IcmpBuilder, IcmpPacket, IcmpType};

impl NetworkStack {
    /// Process ICMP packet
    pub(crate) fn process_icmp(
        &mut self,
        data: &[u8],
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        _ttl: u8,
        current_time: u64,
        _packet: PacketRef,
    ) {
        if !self.icmp_echo_enabled() {
            return;
        }

        // IcmpProcessor::process now handles Smurf attack prevention and rate limiting.
        let result = self.icmp.process(data, src_ip, dst_ip, current_time);

        match result {
            IcmpResult::SendEchoReply {
                src_ip,
                identifier,
                sequence,
                data_offset,
                data_len,
            } => {
                // Get echo data
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
                crate::net::l4::endpoint::futures::notify_icmp_echo_reply(
                    *src_ip.as_bytes(),
                    sequence,
                    0,
                );
                crate::net::l4::endpoint::event::send_event_ignore(
                    crate::net::l4::endpoint::event::NetworkEvent::IcmpEchoReply {
                        source: *src_ip.as_bytes(),
                        sequence,
                        rtt_us: 0,
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
            IcmpResult::Ignored => {}
            IcmpResult::Invalid => {
                log::debug!("[NET] ICMP: Received invalid packet from {}", src_ip);
            }
        }
    }

    /// Send ICMP timestamp reply (RFC 792)
    pub(crate) fn send_icmp_timestamp_reply(
        &mut self,
        dst_ip: Ipv4Address,
        identifier: u16,
        sequence: u16,
        originate_ts: u32,
        receive_ts: u32,
        transmit_ts: u32,
        current_time: u64,
    ) {
        if !self.icmp.check_rate_limit(dst_ip, current_time) {
            return;
        }

        let config = self.config.clone();

        // Resolve next-hop gateway (considering redirects)
        let next_hop = self.resolve_ipv4_next_hop(dst_ip, current_time);

        // Resolve MAC address
        let dst_mac = match self.arp.resolve(next_hop, current_time) {
            Some(mac) => mac,
            None => {
                self.send_arp_request(next_hop);
                return;
            }
        };

        let mut buffer = [0u8; MAX_PACKET_SIZE];

        // Build Ethernet frame
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame
                .set_destination(dst_mac)
                .set_source(config.mac)
                .set_ether_type(EtherType::Ipv4);

            let eth_payload = frame.payload_mut();

            // Build IP packet
            if let Some(mut ip_packet) = Ipv4PacketMut::new(eth_payload) {
                ip_packet
                    .init_header()
                    .set_source(config.ipv4.address)
                    .set_destination(dst_ip)
                    .set_protocol(IpProtocol::Icmp)
                    .set_ttl(64);

                let ip_payload = ip_packet.payload_mut();

                // Build ICMP Timestamp Reply
                if let Some(mut icmp_builder) = IcmpBuilder::new(ip_payload) {
                    icmp_builder.set_type(IcmpType::TimestampReply).set_code(0);

                    let payload = icmp_builder.payload_mut();
                    // Identifier (2) + Sequence (2) + Originate (4) + Receive (4) + Transmit (4) = 16 bytes
                    payload[0..2].copy_from_slice(&identifier.to_be_bytes());
                    payload[2..4].copy_from_slice(&sequence.to_be_bytes());
                    payload[4..8].copy_from_slice(&originate_ts.to_be_bytes());
                    payload[8..12].copy_from_slice(&receive_ts.to_be_bytes());
                    payload[12..16].copy_from_slice(&transmit_ts.to_be_bytes());

                    icmp_builder.set_payload_len(16);
                    let icmp_len = icmp_builder.finalize();
                    ip_packet.finalize(icmp_len);

                    let total_len = EthernetHeader::SIZE + ip_packet.total_len();
                    if let Some(ref transmit) = self.transmit_fn {
                        transmit(None, &buffer[..total_len]);
                        self.stats.record_tx(total_len);
                    }
                }
            }
        }
    }

    /// Resolve the next-hop IPv4 address for a destination, considering redirects.
    pub(crate) fn resolve_ipv4_next_hop(
        &mut self,
        dst_ip: Ipv4Address,
        current_time: u64,
    ) -> Ipv4Address {
        let config = self.config.clone();

        if config.ipv4.is_local(&dst_ip) {
            dst_ip
        } else {
            // RFC 1122: Check redirect cache first for an alternative gateway
            self.redirect_cache.set_time(current_time);
            if let Some(redirected_gateway) = self.redirect_cache.get(dst_ip) {
                redirected_gateway
            } else {
                config.ipv4.gateway
            }
        }
    }

    /// Check if an ICMP error message should be sent (RFC 1122 Section 3.2.2)
    fn should_send_icmp_v4_error(&self, original_packet: &[u8], dst_ip: Ipv4Address) -> bool {
        let config = self.config.clone();

        // 1. MUST NOT send ICMP error for another ICMP error message.
        if let Some(ip) = Ipv4Packet::parse(original_packet) {
            if ip.protocol() == IpProtocol::Icmp {
                if let Some(icmp) = IcmpPacket::parse(ip.payload()) {
                    match icmp.icmp_type() {
                        IcmpType::DestinationUnreachable
                        | IcmpType::Redirect
                        | IcmpType::TimeExceeded
                        | IcmpType::ParameterProblem
                        | IcmpType::SourceQuench => {
                            return false;
                        }
                        _ => {}
                    }
                }
            }

            // 2. MUST NOT send ICMP error for a packet sent to an IP broadcast or multicast address.
            let orig_dst = ip.destination();
            if orig_dst.is_broadcast()
                || orig_dst.is_multicast()
                || (config.ipv4.subnet_mask.as_bytes()[0] != 0
                    && orig_dst == config.ipv4.broadcast_address())
            {
                return false;
            }

            // 3. MUST NOT send ICMP error for a packet that is not the first fragment.
            if ip.header().fragment_offset() != 0 {
                return false;
            }
        } else {
            // If we can't parse the IP header, we shouldn't send an ICMP error.
            return false;
        }

        // 4. MUST NOT send ICMP error for a packet whose source address is not a single host.
        // (e.g. 0.0.0.0, broadcast, multicast, or martian addresses)
        if dst_ip.is_any() || dst_ip.is_broadcast() || dst_ip.is_multicast() || dst_ip.is_martian()
        {
            return false;
        }

        true
    }

    /// Send ICMP error message (RFC 792 / RFC 1122)
    ///
    /// This method constructs and sends an ICMP error message in response to
    /// an offending packet. It strictly follows RFC 1122/1812 rules to avoid
    /// infinite error loops and broadcast storms.
    pub fn send_icmp_error(
        &mut self,
        dst_ip: Ipv4Address,
        code: DestUnreachCode,
        next_hop_mtu: Option<u16>,
        original_packet: &[u8],
        current_time: u64,
    ) {
        if !self.should_send_icmp_v4_error(original_packet, dst_ip) {
            return;
        }

        // Rate limiting
        if !self.icmp.check_rate_limit(dst_ip, current_time) {
            return;
        }

        let config = self.config.clone();

        // Resolve next-hop gateway (considering redirects)
        let next_hop = self.resolve_ipv4_next_hop(dst_ip, current_time);

        // Resolve MAC address
        let dst_mac = match self.arp.resolve(next_hop, current_time) {
            Some(mac) => mac,
            None => {
                self.send_arp_request(next_hop);
                return;
            }
        };

        let mut buffer = [0u8; MAX_PACKET_SIZE];

        // Build Ethernet frame
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame
                .set_destination(dst_mac)
                .set_source(config.mac)
                .set_ether_type(EtherType::Ipv4);

            let eth_payload = frame.payload_mut();

            // Build IP packet
            if let Some(mut ip_packet) = Ipv4PacketMut::new(eth_payload) {
                ip_packet
                    .init_header()
                    .set_source(config.ipv4.address)
                    .set_destination(dst_ip)
                    .set_protocol(IpProtocol::Icmp)
                    .set_ttl(64);

                let ip_payload = ip_packet.payload_mut();

                // Build ICMP packet (Type 3: Destination Unreachable)
                if let Some(len) = IcmpProcessor::build_dest_unreachable(
                    ip_payload,
                    code,
                    next_hop_mtu,
                    original_packet,
                ) {
                    ip_packet.finalize(len);
                    let total_len = EthernetHeader::SIZE + ip_packet.total_len();

                    if let Some(ref transmit) = self.transmit_fn {
                        transmit(None, &buffer[..total_len]);
                        self.stats.record_tx(total_len);
                    }
                }
            }
        }
    }

    /// Send ICMP echo reply
    pub(crate) fn send_icmp_echo_reply(
        &mut self,
        dst_ip: Ipv4Address,
        identifier: u16,
        sequence: u16,
        echo_data: &[u8],
        current_time: u64,
    ) {
        // Rate limiting for replies to prevent being part of an amplification attack.
        if !self.icmp.check_rate_limit(dst_ip, current_time) {
            return;
        }

        let config = self.config.clone();

        // Resolve next-hop gateway (considering redirects)
        let next_hop = self.resolve_ipv4_next_hop(dst_ip, current_time);

        // Resolve MAC address
        let dst_mac = match self.arp.resolve(next_hop, current_time) {
            Some(mac) => mac,
            None => {
                self.send_arp_request(next_hop);
                return;
            }
        };

        let mut buffer = [0u8; MAX_PACKET_SIZE];

        // Build Ethernet frame
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame
                .set_destination(dst_mac)
                .set_source(config.mac)
                .set_ether_type(EtherType::Ipv4);

            let eth_payload = frame.payload_mut();

            // Build IP packet
            if let Some(mut ip_packet) = Ipv4PacketMut::new(eth_payload) {
                ip_packet
                    .init_header()
                    .set_source(config.ipv4.address)
                    .set_destination(dst_ip)
                    .set_protocol(IpProtocol::Icmp)
                    .set_ttl(64);

                let ip_payload = ip_packet.payload_mut();

                // Build ICMP packet
                if let Some(mut icmp) = IcmpEchoBuilder::new(ip_payload) {
                    icmp.build_reply(identifier, sequence);
                    icmp.write_data(echo_data);
                    let icmp_len = icmp.finalize();

                    ip_packet.finalize(icmp_len);

                    let ip_len = ip_packet.total_len();
                    frame.set_payload_len(ip_len);

                    self.transmit(frame.as_bytes());
                }
            }
        }
    }

    /// Send an ICMP Time Exceeded error (RFC 792).
    ///
    /// `original_packet` should be the original IPv4 packet bytes that triggered
    /// the error (IP header + payload). The builder will quote the IPv4 header
    /// plus the first 8 bytes of payload as required.
    pub fn send_icmp_time_exceeded(
        &mut self,
        dst_ip: Ipv4Address,
        code: crate::net::l3::icmp::TimeExceededCode,
        original_packet: &[u8],
    ) -> bool {
        let current_time = self.current_time();

        if !self.should_send_icmp_v4_error(original_packet, dst_ip) {
            return false;
        }

        // Rate limiting
        if !self.icmp.check_rate_limit(dst_ip, current_time) {
            return false;
        }

        let config = self.config.clone();

        // Resolve next-hop gateway (considering redirects)
        let next_hop = self.resolve_ipv4_next_hop(dst_ip, current_time);

        // Resolve MAC address
        let dst_mac = match self.arp.resolve(next_hop, current_time) {
            Some(mac) => mac,
            None => {
                self.send_arp_request(next_hop);
                return false;
            }
        };

        let mut buffer = [0u8; MAX_PACKET_SIZE];
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame
                .set_destination(dst_mac)
                .set_source(config.mac)
                .set_ether_type(EtherType::Ipv4);

            if let Some(mut ip_packet) = Ipv4PacketMut::new(frame.payload_mut()) {
                ip_packet
                    .init_header()
                    .set_source(config.ipv4.address)
                    .set_destination(dst_ip)
                    .set_protocol(IpProtocol::Icmp)
                    .set_ttl(64);

                let ip_payload = ip_packet.payload_mut();
                if let Some(icmp_len) = crate::net::l3::icmp::IcmpProcessor::build_time_exceeded(
                    ip_payload,
                    code,
                    original_packet,
                ) {
                    ip_packet.finalize(icmp_len);
                    let ip_len = ip_packet.total_len();
                    frame.set_payload_len(ip_len);
                    return self.transmit(frame.as_bytes());
                }
            }
        }

        false
    }

    /// Send an ICMP Parameter Problem error (RFC 792).
    pub fn send_icmp_parameter_problem(
        &mut self,
        dst_ip: Ipv4Address,
        pointer: u8,
        original_packet: &[u8],
    ) -> bool {
        let current_time = self.current_time();

        if !self.should_send_icmp_v4_error(original_packet, dst_ip) {
            return false;
        }

        // Rate limiting
        if !self.icmp.check_rate_limit(dst_ip, current_time) {
            return false;
        }

        let config = self.config.clone();

        // Resolve next-hop gateway (considering redirects)
        let next_hop = self.resolve_ipv4_next_hop(dst_ip, current_time);

        // Resolve MAC address
        let dst_mac = match self.arp.resolve(next_hop, current_time) {
            Some(mac) => mac,
            None => {
                self.send_arp_request(next_hop);
                return false;
            }
        };

        let mut buffer = [0u8; MAX_PACKET_SIZE];
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame
                .set_destination(dst_mac)
                .set_source(config.mac)
                .set_ether_type(EtherType::Ipv4);

            if let Some(mut ip_packet) = Ipv4PacketMut::new(frame.payload_mut()) {
                ip_packet
                    .init_header()
                    .set_source(config.ipv4.address)
                    .set_destination(dst_ip)
                    .set_protocol(IpProtocol::Icmp)
                    .set_ttl(64);

                let ip_payload = ip_packet.payload_mut();
                if let Some(icmp_len) = crate::net::l3::icmp::IcmpProcessor::build_parameter_problem(
                    ip_payload,
                    pointer,
                    original_packet,
                ) {
                    ip_packet.finalize(icmp_len);
                    let ip_len = ip_packet.total_len();
                    frame.set_payload_len(ip_len);
                    return self.transmit(frame.as_bytes());
                }
            }
        }

        false
    }

    /// Send an ICMPv6 Destination Unreachable error (RFC 4443 Section 3.1).
    pub fn send_icmpv6_error(
        &mut self,
        dst_v6: Ipv6Address,
        code: u8,
        original_packet: &[u8],
    ) -> bool {
        let current_time = self.current_time();

        // Security: RFC 4443 compliance check (e.g. no errors for multicast)
        if !self.should_send_icmp_v6_error(
            original_packet,
            dst_v6,
            Icmpv6Type::DestinationUnreachable,
            code,
        ) {
            return false;
        }

        // Rate limiting
        if let Some(ref icmpv6) = self.icmpv6 {
            if !icmpv6.check_tx_rate_limit(current_time) {
                return false;
            }
        } else {
            return false;
        }

        // Determine our source address for the error message
        let src_v6 = match self.get_ipv6_source_for(&dst_v6) {
            Some(s) => s,
            None => return false,
        };

        // Build ICMPv6 Destination Unreachable (Type 1)
        let icmpv6_msg = crate::net::l3::icmpv6::Icmpv6Builder::build_dest_unreachable(
            &src_v6,
            &dst_v6,
            code,
            original_packet,
        );

        self.send_ipv6_icmpv6(&src_v6, &dst_v6, &icmpv6_msg);
        true
    }

    /// Send an ICMPv6 Parameter Problem error (RFC 4443 Section 3.4).
    pub fn send_icmpv6_parameter_problem(
        &mut self,
        dst_v6: Ipv6Address,
        code: u8,
        pointer: u32,
        original_packet: &[u8],
    ) -> bool {
        let current_time = self.current_time();

        // Security: RFC 4443 compliance check
        if !self.should_send_icmp_v6_error(
            original_packet,
            dst_v6,
            Icmpv6Type::ParameterProblem,
            code,
        ) {
            return false;
        }

        // Rate limiting
        if let Some(ref icmpv6) = self.icmpv6 {
            if !icmpv6.check_tx_rate_limit(current_time) {
                return false;
            }
        } else {
            return false;
        }

        let src_v6 = match self.get_ipv6_source_for(&dst_v6) {
            Some(s) => s,
            None => return false,
        };

        let icmpv6_msg = crate::net::l3::icmpv6::Icmpv6Builder::build_parameter_problem(
            &src_v6,
            &dst_v6,
            code,
            pointer,
            original_packet,
        );

        self.send_ipv6_icmpv6(&src_v6, &dst_v6, &icmpv6_msg);
        true
    }

    /// Helper to get the best IPv6 source address for a destination
    fn get_ipv6_source_for(&self, _dst: &Ipv6Address) -> Option<Ipv6Address> {
        if let Some(ref ipv6) = self.ipv6 {
            let config = ipv6.config();
            // Simple selection: use global if available, otherwise link-local
            if let Some(global) = config.global {
                Some(global)
            } else {
                Some(config.link_local)
            }
        } else {
            None
        }
    }

    /// Check if an ICMPv6 error message should be sent (RFC 4443 Section 2.4(e))
    pub(crate) fn should_send_icmp_v6_error(
        &self,
        original_packet: &[u8],
        dst_ip: Ipv6Address,
        error_type: Icmpv6Type,
        error_code: u8,
    ) -> bool {
        // (e.1) An ICMPv6 error message.
        // (e.2) An ICMPv6 redirect message.
        if original_packet.len() >= 40 {
            let next_header = original_packet[6];
            use crate::net::l3::ipv6::skip_extension_headers;
            let (final_proto, icmp_data) =
                skip_extension_headers(IpProtocol::from(next_header), &original_packet[40..]);
            if final_proto == IpProtocol::Icmpv6 && icmp_data.len() >= 1 {
                let icmp_type = icmp_data[0];
                if icmp_type < 128 || icmp_type == 137
                /* Redirect */
                {
                    return false;
                }
            }
        }

        // (e.3, e.4, e.5) A packet destined to a multicast address (with exceptions)
        if original_packet.len() >= 40 {
            let orig_dst = Ipv6Address::new([
                original_packet[24],
                original_packet[25],
                original_packet[26],
                original_packet[27],
                original_packet[28],
                original_packet[29],
                original_packet[30],
                original_packet[31],
                original_packet[32],
                original_packet[33],
                original_packet[34],
                original_packet[35],
                original_packet[36],
                original_packet[37],
                original_packet[38],
                original_packet[39],
            ]);
            if orig_dst.is_multicast() {
                // RFC 4443 Section 2.4(e.3) Exceptions:
                // 1. Packet Too Big is allowed for multicast
                let is_ptb = error_type == Icmpv6Type::PacketTooBig;

                // 2. Parameter Problem (Code 2: unrecognized Next Header) is allowed for multicast
                let is_pp_unrecognized_header =
                    error_type == Icmpv6Type::ParameterProblem && error_code == 2;

                if !is_ptb && !is_pp_unrecognized_header {
                    return false;
                }
            }
        }

        // (e.6) A packet whose source address does not uniquely identify a single node.
        if dst_ip.is_unspecified() || dst_ip.is_multicast() {
            return false;
        }

        true
    }

    /// Handle ICMP error messages for Path MTU Discovery (RFC 1191)
    ///
    /// When a router cannot forward a packet because it exceeds the next-hop MTU
    /// and the DF (Don't Fragment) bit is set, it sends back an ICMP Destination
    /// Unreachable message with code 4 (Fragmentation Needed).
    ///
    /// The Next-Hop MTU is encoded in bytes 6-7 of the ICMP message (after the
    /// 4-byte ICMP header). This value indicates the maximum MTU that should be
    /// used for that path.
    pub(crate) fn handle_icmp_error(
        &mut self,
        data: &[u8],
        icmp_type: IcmpType,
        code: u8,
        current_time: u64,
    ) {
        // Support ICMP errors (RFC 792/1122/1191):
        // - Destination Unreachable (Fragmentation Needed for PMTUD, Port Unreachable for transport)
        // - Source Quench (Flow control)
        match icmp_type {
            IcmpType::DestinationUnreachable => {
                // Allow all DestinationUnreachable codes to be processed for transport notification
                // RFC 1122 Section 4.2.3.9 requires TCP to notify the user.
            }
            IcmpType::SourceQuench => {
                // Proceed to handle
            }
            _ => return,
        }

        // ICMP error format (RFC 792):
        // Bytes 0-3: ICMP header (type, code, checksum)
        // Bytes 4-7: Contents depend on type (e.g. Next-Hop MTU for Type 3 Code 4)
        // Bytes 8+: Original IP header + first 8 bytes of payload

        const ORIGINAL_IP_OFFSET: usize = 8;
        if data.len() < ORIGINAL_IP_OFFSET + 20 {
            return;
        }

        // Extract original source/destination from embedded IP header
        let src_offset = ORIGINAL_IP_OFFSET + 12;
        let dst_offset = ORIGINAL_IP_OFFSET + 16;
        let original_src = Ipv4Address::from_octets(
            data[src_offset],
            data[src_offset + 1],
            data[src_offset + 2],
            data[src_offset + 3],
        );
        let original_dst = Ipv4Address::from_octets(
            data[dst_offset],
            data[dst_offset + 1],
            data[dst_offset + 2],
            data[dst_offset + 3],
        );

        // Security check: Verify original source matches our address
        if original_src != self.config.ipv4.address && !original_src.is_any() {
            return;
        }

        let protocol = data[ORIGINAL_IP_OFFSET + 9];
        let ihl = data[ORIGINAL_IP_OFFSET] & 0x0F;
        let ip_header_len = (ihl as usize) * 4;
        let transport_offset = ORIGINAL_IP_OFFSET + ip_header_len;

        if data.len() < transport_offset + 4 {
            return;
        }

        let src_port = u16::from_be_bytes([data[transport_offset], data[transport_offset + 1]]);
        let dst_port = u16::from_be_bytes([data[transport_offset + 2], data[transport_offset + 3]]);

        // Protocol-specific handling and validation
        match protocol {
            6 => {
                // TCP
                if data.len() < transport_offset + 8 {
                    return;
                }
                let seq_num = u32::from_be_bytes([
                    data[transport_offset + 4],
                    data[transport_offset + 5],
                    data[transport_offset + 6],
                    data[transport_offset + 7],
                ]);
                let local = TcpEndpointAddr::new(original_src.octets(), src_port);
                let remote = TcpEndpointAddr::new(original_dst.octets(), dst_port);

                // 1. 旧スタックの検証と通知
                let mut old_stack_valid = false;
                if self.tcp.validate_icmp_sequence(local, remote, seq_num) {
                    old_stack_valid = true;
                    if icmp_type == IcmpType::SourceQuench {
                        self.tcp.handle_source_quench(local, remote);
                    } else if icmp_type == IcmpType::DestinationUnreachable {
                        self.tcp.handle_icmp_error(local, remote, icmp_type, code);
                    }
                }

                // 2. 新エンドポイントスタック (l4/endpoint) の検証と通知
                let tcb_table = crate::net::l4::endpoint::tcb_table();
                if tcb_table.validate_icmp_sequence(local, remote, seq_num) {
                    if icmp_type == IcmpType::SourceQuench {
                        // handle_source_quench in endpoint
                        crate::net::l4::endpoint::tcp_rx::handle_source_quench(local, remote);
                    } else if icmp_type == IcmpType::DestinationUnreachable {
                        crate::net::l4::endpoint::tcp_rx::handle_icmp_error(
                            local, remote, icmp_type, code,
                        );
                    }
                } else if !old_stack_valid {
                    log::warn!(
                        "[NET] ICMP: error for {} rejected due to invalid TCP seq {} (RFC 5927)",
                        original_dst,
                        seq_num
                    );
                    return;
                }
            }
            17 => {
                // UDP
                if !self.udp.has_endpoint(src_port) {
                    return;
                }
                // Source Quench for UDP: We don't have per-socket congestion control for UDP,
                // but we could theoretically signal the application.
            }
            _ => return,
        }

        // PMTUD specific handling
        if icmp_type == IcmpType::DestinationUnreachable
            && code == DestUnreachCode::FragmentationNeeded as u8
        {
            let next_hop_mtu = u16::from_be_bytes([data[6], data[7]]);
            let mtu = if next_hop_mtu == 0 {
                // RFC 1191: If Next-Hop MTU is 0, use next smaller plateau
                let current_mtu = self.ipv4.get_pmtu(original_dst, current_time);
                crate::net::l3::ipv4::PmtuEntry::get_next_plateau(current_mtu)
            } else {
                next_hop_mtu
            };
            self.ipv4.update_pmtu(original_dst, mtu, current_time);
        }
    }

    /// Handle ICMP Redirect message (RFC 792)
    ///
    /// ICMP Redirect is sent by a router when it detects that a better route
    /// exists for a destination. The host should update its routing table
    /// to use the new gateway for future packets to that destination.
    ///
    /// Security considerations:
    /// - Only accept redirects from the current first-hop router
    /// - Validate that the new gateway is on a directly connected network
    /// - Ignore redirects for destinations not matching current routes
    pub(crate) fn handle_icmp_redirect(
        &mut self,
        code: RedirectCode,
        gateway: Ipv4Address,
        destination: Ipv4Address,
        redirect_source: Ipv4Address,
    ) {
        // Security check 1: Only accept redirects from our current gateway
        let current_gateway = self.config.ipv4.gateway;
        if redirect_source != current_gateway {
            // Ignore redirects from non-gateway sources (potential attack)
            return;
        }

        // Security check 2: Ensure the new gateway is on a directly connected network
        // (same subnet as the host)
        let local_ip = self.config.ipv4.address;
        let local_mask = self.config.ipv4.subnet_mask;
        let local_network = local_ip.apply_mask(local_mask);
        let gateway_network = gateway.apply_mask(local_mask);

        if local_network != gateway_network {
            // New gateway is not on the same network - reject
            return;
        }

        // Security check 3: Don't redirect to ourselves
        if gateway == local_ip {
            return;
        }

        // Security check 4: Validate redirect code and destination
        match code {
            RedirectCode::Network | RedirectCode::Host => {
                // Standard redirects - proceed
            }
            RedirectCode::TosNetwork | RedirectCode::TosHost => {
                // TOS-based redirects - less common but valid
            }
        }

        // Update redirect cache (temporary route override)
        // In a full implementation, this would update the routing table
        // For now, we store redirects in a simple cache
        self.redirect_cache.insert(destination, gateway);
    }

    pub(crate) fn send_icmp_echo_fallback(
        &mut self,
        target: Ipv4Address,
        dst_mac: MacAddress,
        local_ip: Ipv4Address,
        identifier: u16,
        sequence: u16,
    ) -> Result<u64, ()> {
        let mut buffer = self.tx_pool.alloc().ok_or(())?;
        let buf = buffer.as_mut_slice();

        let eth_hdr_len = 14;
        let ip_hdr_len = 20;
        let icmp_hdr_len = 8;
        let total_len = eth_hdr_len + ip_hdr_len + icmp_hdr_len;

        if buf.len() < total_len {
            return Err(());
        }

        let src_mac = self.mac_address();
        buf[0..6].copy_from_slice(dst_mac.as_bytes());
        buf[6..12].copy_from_slice(src_mac.as_bytes());
        buf[12] = 0x08;
        buf[13] = 0x00;

        let ip_start = eth_hdr_len;
        if let Some(mut ip_packet) = Ipv4PacketMut::new(&mut buf[ip_start..]) {
            ip_packet
                .init_header()
                .set_source(local_ip)
                .set_destination(target)
                .set_protocol(IpProtocol::Icmp)
                .set_ttl(64);

            if let Some(mut icmp) = IcmpEchoBuilder::new(ip_packet.payload_mut()) {
                icmp.build_request(identifier, sequence).write_data(&[]);
                let icmp_len = icmp.finalize();
                ip_packet.finalize(icmp_len);
            }
        }

        let send_time = self.current_time();

        if self.transmit(&buf[..total_len]) {
            log::info!("[NET-PING] Sent ICMP echo to {} seq={}", target, sequence);
            Ok(send_time)
        } else {
            log::warn!(
                "[NET-PING] Failed to transmit ICMP echo to {} seq={}",
                target,
                sequence
            );
            Err(())
        }
    }

    /// Send ICMP echo request (ping)
    pub fn send_icmp_echo_request(
        &mut self,
        target: Ipv4Address,
        sequence: u16,
    ) -> Result<u64, ()> {
        let local_ip = self.ipv4_address();
        let identifier = 0x1234u16; // Fixed identifier for now

        // Need to resolve destination MAC
        let config = self.config.clone();
        let current_time = self.current_time();
        let dst_mac = match self.resolve_mac(target, &config, current_time) {
            Some(mac) => mac,
            None => {
                log::info!(
                    "[NET-PING] Resolution required for {}.{}.{}.{} seq={} - resolution started",
                    target.as_bytes()[0],
                    target.as_bytes()[1],
                    target.as_bytes()[2],
                    target.as_bytes()[3],
                    sequence
                );
                return Err(());
            }
        };

        // Try zero-copy path first
        if let Some(mut packet) = crate::net::datapath::mempool::alloc_packet() {
            // 新規割り当てのPacketRefはlen=0なので、書き込み前にcapacityまで拡張する
            let cap = packet.capacity();
            packet.set_len(cap);
            if let Some(mut frame) = EthernetFrameMut::new(packet.data_mut()) {
                let src_mac = self.mac_address();
                frame
                    .set_destination(dst_mac)
                    .set_source(src_mac)
                    .set_ether_type(EtherType::Ipv4);

                if let Some(mut ip_packet) = Ipv4PacketMut::new(frame.payload_mut()) {
                    ip_packet
                        .init_header()
                        .set_source(local_ip)
                        .set_destination(target)
                        .set_protocol(IpProtocol::Icmp)
                        .set_ttl(64);

                    if let Some(mut icmp) = IcmpEchoBuilder::new(ip_packet.payload_mut()) {
                        icmp.build_request(identifier, sequence).write_data(&[]);
                        let icmp_len = icmp.finalize();
                        ip_packet.finalize(icmp_len);

                        let ip_len = ip_packet.total_len();
                        frame.set_payload_len(ip_len);

                        let total_len = frame.as_bytes().len();
                        let send_time = self.current_time();
                        drop(frame);
                        packet.set_len(total_len);

                        if crate::net::datapath::zero_copy::ZeroCopyWriter::enqueue_via_virtio(
                            packet,
                        )
                        .is_ok()
                        {
                            self.stats.record_tx(total_len);
                            log::info!(
                                "[NET-PING] Sent ICMP echo to {}.{}.{}.{} seq={}",
                                target.as_bytes()[0],
                                target.as_bytes()[1],
                                target.as_bytes()[2],
                                target.as_bytes()[3],
                                sequence
                            );
                            return Ok(send_time);
                        }
                    }
                }
            }
        }

        // Fallback to copy-based path
        self.send_icmp_echo_fallback(target, dst_mac, local_ip, identifier, sequence)
    }

    /// Handle ICMPv6 error messages for transport layer notification (RFC 5927 / RFC 4443)
    pub(crate) fn handle_icmpv6_error_transport_notification(
        &mut self,
        quoted_src: Ipv6Address,
        quoted_dst: Ipv6Address,
        icmp_type: Icmpv6Type,
        code: u8,
        quoted_packet: &[u8],
    ) {
        // Quoted packet starts with an IPv6 header (40 bytes)
        if quoted_packet.len() < 48 {
            // Header(40) + minimum transport(8)
            return;
        }

        let next_header = quoted_packet[6];
        let payload = &quoted_packet[40..];

        // Skip extension headers to find the upper-layer header
        use crate::net::l3::ipv6::skip_extension_headers;
        let (final_proto, transport_data) =
            skip_extension_headers(IpProtocol::from(next_header), payload);

        if transport_data.len() < 8 {
            return;
        }

        match final_proto {
            IpProtocol::Tcp => {
                let src_port = u16::from_be_bytes([transport_data[0], transport_data[1]]);
                let dst_port = u16::from_be_bytes([transport_data[2], transport_data[3]]);
                let seq_num = u32::from_be_bytes([
                    transport_data[4],
                    transport_data[5],
                    transport_data[6],
                    transport_data[7],
                ]);

                use crate::net::l4::tcp::EndpointAddr as TcpEndpointAddr;
                let local_addr = TcpEndpointAddr::new_v6(quoted_src.octets(), src_port);
                let remote_addr = TcpEndpointAddr::new_v6(quoted_dst.octets(), dst_port);

                // Validate sequence number (RFC 5927)
                let tcb_table = crate::net::l4::endpoint::tcb_table();
                if tcb_table.validate_icmp_sequence(local_addr, remote_addr, seq_num) {
                    // Notify TCP stack
                    crate::net::l4::endpoint::tcp_rx::handle_icmpv6_error(
                        local_addr,
                        remote_addr,
                        icmp_type,
                        code,
                    );
                } else {
                    log::warn!(
                        "[NET] ICMPv6: error type {:?} for {} rejected due to invalid TCP seq {} (RFC 5927)",
                        icmp_type,
                        quoted_dst,
                        seq_num
                    );
                }
            }
            IpProtocol::Udp => {
                let src_port = u16::from_be_bytes([transport_data[0], transport_data[1]]);
                if !self.udp.has_endpoint(src_port) {
                    return;
                }
                // UDP error notification could be implemented here
            }
            _ => {}
        }
    }

    /// Calculate IP/ICMP checksum
    pub(crate) fn checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;

        while i < data.len() - 1 {
            sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
            i += 2;
        }

        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }

        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !sum as u16
    }
}
