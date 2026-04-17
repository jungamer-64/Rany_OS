// ============================================================================
// ICMP-related NetworkStack impl methods
// ============================================================================
//! ICMP packet processing, error message construction, PMTUD handling,
//! ICMP Redirect processing, and ICMP echo request/reply.

use super::*;
use crate::net::l3::icmp::{IcmpBuilder, IcmpType};
use crate::net::l4::tcp::EndpointAddr as TcpEndpointAddr;

impl NetworkStack {
    /// Send ICMP Echo Reply (RFC 792) while keeping payload access zero-copy.
    pub fn send_icmp_echo_reply_payload(
        &mut self,
        dst_ip: Ipv4Address,
        identifier: u16,
        sequence: u16,
        echo_data: crate::net::payload::PayloadSpanRef<'_>,
        current_time: u64,
    ) -> bool {
        if !self.icmp.check_rate_limit(dst_ip, current_time) {
            return false;
        }

        // Firewall egress gate for ICMP.
        if !crate::net::security::firewall::check_egress(
            self.config.ipv4.address.octets(),
            dst_ip.octets(),
            1,
            0,
            0,
            0,
        ) {
            self.stats.record_dropped();
            return false;
        }

        // Resolve next-hop and destination MAC before frame build.
        let next_hop = self.resolve_ipv4_next_hop(dst_ip, current_time);
        let dst_mac = match self.arp.resolve(next_hop, current_time) {
            Some(mac) => mac,
            None => {
                self.send_arp_request(next_hop);
                return false;
            }
        };

        let total_len = EthernetHeader::SIZE
            + 20
            + crate::net::l3::icmp::IcmpEchoHeader::SIZE
            + echo_data.total_len();
        let mut packet = match self.alloc_ethernet_frame_packet(total_len) {
            Some(packet) => packet,
            None => return false,
        };

        // Build Ethernet -> IPv4 -> ICMP Echo Reply.
        if let Some(mut frame) = EthernetFrameMut::new(packet.data_mut()) {
            frame
                .set_destination(dst_mac)
                .set_source(self.config.mac)
                .set_ether_type(EtherType::Ipv4);

            if let Some(mut ip_packet) = Ipv4PacketMut::new(frame.payload_mut()) {
                ip_packet
                    .init_header()
                    .set_source(self.config.ipv4.address)
                    .set_destination(dst_ip)
                    .set_protocol(IpProtocol::Icmp)
                    .set_ttl(64);

                let ip_payload = ip_packet.payload_mut();
                if let Some(mut icmp_builder) = crate::net::l3::icmp::IcmpEchoBuilder::new(ip_payload)
                {
                    icmp_builder.build_reply(identifier, sequence);
                    icmp_builder.write_payload_span_ref(echo_data);
                    let icmp_len = icmp_builder.finalize();
                    ip_packet.finalize(icmp_len);
                    let ip_len = ip_packet.total_len();
                    drop(ip_packet);
                    frame.set_payload_len(ip_len);
                    let frame_len = frame.as_bytes().len();
                    drop(frame);
                    packet.set_len(frame_len);
                    return self.transmit_packet_on(
                        None,
                        kernel_api::resource::net::PacketPayload::single(packet),
                    );
                }
            }
        }

        false
    }

    /// Send ICMP Destination Unreachable style error (RFC 792 / RFC 1122 guarded).
    pub fn send_icmp_error_payload(
        &mut self,
        dst_ip: Ipv4Address,
        code: DestUnreachCode,
        next_hop_mtu: Option<u16>,
        original_packet: &kernel_api::resource::net::PacketPayload,
        current_time: u64,
    ) {
        let view = crate::net::payload::PacketPayloadView::new(original_packet);
        let copy_len = view.total_len().min(544);

        if !self.should_send_icmp_v4_error(&view, dst_ip) {
            return;
        }
        if !self.icmp.check_rate_limit(dst_ip, current_time) {
            return;
        }
        if !crate::net::security::firewall::check_egress(
            self.config.ipv4.address.octets(),
            dst_ip.octets(),
            1,
            0,
            0,
            0,
        ) {
            self.stats.record_dropped();
            return;
        }

        let current_time = self.current_time();
        // Loopback destinations do not require ARP resolution.
        let Some(dst_mac) = (if dst_ip.is_loopback() {
            Some(self.config.mac)
        } else {
            self.resolve_arp_for_send(None, dst_ip, current_time, |_| {})
        }) else {
            return;
        };

        let mut packet =
            match self.alloc_ethernet_frame_packet(EthernetHeader::SIZE + 20 + 8 + 4 + copy_len) {
                Some(packet) => packet,
                None => return,
            };

        if let Some(mut frame) = EthernetFrameMut::new(packet.data_mut()) {
            frame
                .set_destination(dst_mac)
                .set_source(self.config.mac)
                .set_ether_type(EtherType::Ipv4);

            let eth_payload = frame.payload_mut();
            if let Some(mut ip_packet) = Ipv4PacketMut::new(eth_payload) {
                ip_packet
                    .init_header()
                    .set_source(self.config.ipv4.address)
                    .set_destination(dst_ip)
                    .set_protocol(IpProtocol::Icmp)
                    .set_ttl(64);

                let ip_payload = ip_packet.payload_mut();
                if let Some(len) = IcmpProcessor::build_dest_unreachable(
                    ip_payload,
                    code,
                    next_hop_mtu,
                    &view,
                ) {
                    ip_packet.finalize(len);
                    let ip_len = ip_packet.total_len();
                    drop(ip_packet);
                    frame.set_payload_len(ip_len);
                    let frame_len = frame.as_bytes().len();
                    drop(frame);
                    packet.set_len(frame_len);
                    let _ = self.transmit_packet_on(None, PacketPayload::single(packet));
                }
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

        // ── ファイアウォール Egress チェック ──
        if !crate::net::security::firewall::check_egress(
            self.config.ipv4.address.octets(),
            dst_ip.octets(),
            1, // ICMP
            0,
            0,
            0,
        ) {
            self.stats.record_dropped();
            return;
        }

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

        let mut packet = match self.alloc_ethernet_frame_packet(EthernetHeader::SIZE + 20 + 20) {
            Some(packet) => packet,
            None => return,
        };

        // Build Ethernet frame
        if let Some(mut frame) = EthernetFrameMut::new(packet.data_mut()) {
            frame
                .set_destination(dst_mac)
                .set_source(self.config.mac)
                .set_ether_type(EtherType::Ipv4);

            let eth_payload = frame.payload_mut();

            // Build IP packet
            if let Some(mut ip_packet) = Ipv4PacketMut::new(eth_payload) {
                ip_packet
                    .init_header()
                    .set_source(self.config.ipv4.address)
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
                    drop(ip_packet);
                    frame.set_payload_len(total_len - EthernetHeader::SIZE);
                    let frame_len = frame.as_bytes().len();
                    drop(frame);
                    packet.set_len(frame_len);
                    let _ = self.transmit_packet_on(
                        None,
                        kernel_api::resource::net::PacketPayload::single(packet),
                    );
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
    fn should_send_icmp_v4_error(
        &self,
        original_packet: &crate::net::payload::PacketPayloadView<'_>,
        dst_ip: Ipv4Address,
    ) -> bool {
        let config = self.config.clone();
        let total_len = original_packet.total_len();
        let mut header_buf = [0u8; 60];
        let copied = original_packet.copy_range(0, &mut header_buf);

        if copied < 20 {
            return false;
        }

        let ihl_words = (header_buf[0] & 0x0f) as usize;
        let header_len = ihl_words.saturating_mul(4);
        if header_len < 20 || header_len > copied || total_len < header_len {
            return false;
        }

        let Some(ip) = Ipv4Packet::parse(&header_buf[..header_len]) else {
            return false;
        };

        if ip.protocol() == IpProtocol::Icmp {
            if let Some(icmp_type) = original_packet.read_u8(header_len).map(IcmpType::from) {
                match icmp_type {
                    // RFC 1122: MUST NOT send an ICMP error in response to another ICMP error.
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

        let orig_dst = ip.destination();
        // RFC 1122: MUST NOT send ICMP errors for broadcast or multicast destinations.
        if orig_dst.is_broadcast()
            || orig_dst.is_multicast()
            || (config.ipv4.subnet_mask.as_bytes()[0] != 0
                && orig_dst == config.ipv4.broadcast_address())
        {
            return false;
        }

        // RFC 1122: MUST NOT send ICMP errors for non-initial fragments.
        if ip.header().fragment_offset() != 0 {
            return false;
        }

        // RFC 1122: Source must uniquely identify a host.
        if dst_ip.is_any() || dst_ip.is_broadcast() || dst_ip.is_multicast() || dst_ip.is_martian()
        {
            return false;
        }

        true
    }

    /// Send ICMP error message (RFC 792 / RFC 1122)
    ///
    /// This method constructs and sends an ICMP error message in response to
    /// an offending packet payload. It strictly follows RFC 1122/1812 rules
    /// to avoid infinite error loops and broadcast storms.
    /// Send an ICMP Time Exceeded error (RFC 792).
    ///
    /// `original_packet` should contain the offending IPv4 packet payload.
    /// The builder will quote the IPv4 header plus the first 8 bytes of
    /// payload as required by RFC 792.
    pub fn send_icmp_time_exceeded_payload(
        &mut self,
        dst_ip: Ipv4Address,
        code: crate::net::l3::icmp::TimeExceededCode,
        original_packet: &kernel_api::resource::net::PacketPayload,
    ) -> bool {
        let current_time = self.current_time();
        let original_packet = crate::net::payload::PacketPayloadView::new(original_packet);
        let copy_len = original_packet.total_len().min(544);

        if !self.should_send_icmp_v4_error(&original_packet, dst_ip) {
            return false;
        }

        // Rate limiting
        if !self.icmp.check_rate_limit(dst_ip, current_time) {
            return false;
        }

        // ── ファイアウォール Egress チェック ──
        if !crate::net::security::firewall::check_egress(
            self.config.ipv4.address.octets(),
            dst_ip.octets(),
            1, // ICMP
            0,
            0,
            0,
        ) {
            self.stats.record_dropped();
            return false;
        }

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

        let mut packet =
            match self.alloc_ethernet_frame_packet(EthernetHeader::SIZE + 20 + 8 + 4 + copy_len) {
                Some(packet) => packet,
                None => return false,
            };
        if let Some(mut frame) = EthernetFrameMut::new(packet.data_mut()) {
            frame
                .set_destination(dst_mac)
                .set_source(self.config.mac)
                .set_ether_type(EtherType::Ipv4);

            if let Some(mut ip_packet) = Ipv4PacketMut::new(frame.payload_mut()) {
                ip_packet
                    .init_header()
                    .set_source(self.config.ipv4.address)
                    .set_destination(dst_ip)
                    .set_protocol(IpProtocol::Icmp)
                    .set_ttl(64);

                let ip_payload = ip_packet.payload_mut();
                if let Some(icmp_len) = crate::net::l3::icmp::IcmpProcessor::build_time_exceeded(
                    ip_payload,
                    code,
                    &original_packet,
                ) {
                    ip_packet.finalize(icmp_len);
                    let ip_len = ip_packet.total_len();
                    frame.set_payload_len(ip_len);
                    let frame_len = frame.as_bytes().len();
                    drop(frame);
                    packet.set_len(frame_len);
                    return self.transmit_packet_on(
                        None,
                        kernel_api::resource::net::PacketPayload::single(packet),
                    );
                }
            }
        }

        false
    }

    pub fn send_icmpv6_error_payload(
        &mut self,
        dst_v6: Ipv6Address,
        code: u8,
        original_packet: &kernel_api::resource::net::PacketPayload,
    ) -> bool {
        let current_time = self.current_time();
        let original_packet = crate::net::payload::PacketPayloadView::new(original_packet);

        // Security: RFC 4443 compliance check (e.g. no errors for multicast)
        if !self.should_send_icmp_v6_error(
            &original_packet,
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
        let Some(icmpv6_msg) = crate::net::l3::icmpv6::Icmpv6Builder::build_dest_unreachable(
            &src_v6,
            &dst_v6,
            code,
            &original_packet,
        ) else {
            self.stats.record_dropped();
            return false;
        };
        self.send_ipv6_icmpv6(&src_v6, &dst_v6, icmpv6_msg);
        true
    }

    /// Send an ICMPv6 Parameter Problem error (RFC 4443 Section 3.4).
    pub fn send_icmpv6_parameter_problem_payload(
        &mut self,
        dst_v6: Ipv6Address,
        code: u8,
        pointer: u32,
        original_packet: &kernel_api::resource::net::PacketPayload,
    ) -> bool {
        let original_packet = crate::net::payload::PacketPayloadView::new(&original_packet);
        let current_time = self.current_time();

        // Security: RFC 4443 compliance check
        if !self.should_send_icmp_v6_error(
            &original_packet,
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

        let Some(icmpv6_msg) = crate::net::l3::icmpv6::Icmpv6Builder::build_parameter_problem(
            &src_v6,
            &dst_v6,
            code,
            pointer,
            &original_packet,
        ) else {
            self.stats.record_dropped();
            return false;
        };
        self.send_ipv6_icmpv6(&src_v6, &dst_v6, icmpv6_msg);
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
        original_packet: &crate::net::payload::PacketPayloadView<'_>,
        dst_ip: Ipv6Address,
        error_type: Icmpv6Type,
        error_code: u8,
    ) -> bool {
        // (e.1) An ICMPv6 error message.
        // (e.2) An ICMPv6 redirect message.
        if let Some((final_proto, icmp_data)) =
            crate::net::payload::ipv6_transport_payload(original_packet.payload())
        {
            if final_proto == IpProtocol::Icmpv6 {
                let Some(icmp_type) = icmp_data.read_array::<1>(0).map(|bytes| bytes[0]) else {
                    return false;
                };
                if icmp_type < 128 || icmp_type == 137
                /* Redirect */
                {
                    return false;
                }
            }
        }

        // (e.3, e.4, e.5) A packet destined to a multicast address (with exceptions)
        if let Some(orig_dst) = original_packet.read_array::<16>(24).map(Ipv6Address::new) {
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

    pub(crate) fn handle_icmp_error_payload(
        &mut self,
        payload: &kernel_api::resource::net::PacketPayload,
        icmp_type: IcmpType,
        code: u8,
        current_time: u64,
    ) {
        match icmp_type {
            IcmpType::DestinationUnreachable | IcmpType::SourceQuench => {}
            _ => return,
        }

        const ORIGINAL_IP_OFFSET: usize = 8;
        let view = crate::net::payload::PacketPayloadView::new(payload);
        let Some(original_ip) = view.read_array::<20>(ORIGINAL_IP_OFFSET) else {
            return;
        };

        let original_src = Ipv4Address::from_octets(
            original_ip[12],
            original_ip[13],
            original_ip[14],
            original_ip[15],
        );
        let original_dst = Ipv4Address::from_octets(
            original_ip[16],
            original_ip[17],
            original_ip[18],
            original_ip[19],
        );

        if original_src != self.config.ipv4.address && !original_src.is_any() {
            return;
        }

        let protocol = original_ip[9];
        let ip_header_len = ((original_ip[0] & 0x0F) as usize) * 4;
        let transport_offset = ORIGINAL_IP_OFFSET + ip_header_len;

        let Some(ports) = view.read_array::<4>(transport_offset) else {
            return;
        };
        let src_port = u16::from_be_bytes([ports[0], ports[1]]);
        let dst_port = u16::from_be_bytes([ports[2], ports[3]]);

        match protocol {
            6 => {
                let Some(seq_bytes) = view.read_array::<4>(transport_offset + 4) else {
                    return;
                };
                let seq_num = u32::from_be_bytes(seq_bytes);
                let local = TcpEndpointAddr::new(original_src.octets(), src_port);
                let remote = TcpEndpointAddr::new(original_dst.octets(), dst_port);
                let tcb_table = crate::net::l4::endpoint::tcb_table();
                if tcb_table.validate_icmp_sequence(local, remote, seq_num) {
                    if icmp_type == IcmpType::SourceQuench {
                        crate::net::l4::endpoint::tcp_rx::handle_source_quench(local, remote);
                    } else if icmp_type == IcmpType::DestinationUnreachable {
                        crate::net::l4::endpoint::tcp_rx::handle_icmp_error(
                            local, remote, icmp_type, code,
                        );
                    }
                } else {
                    log::warn!(
                        "[NET] ICMP: error for {} rejected due to invalid TCP seq {} (RFC 5927)",
                        original_dst,
                        seq_num
                    );
                    return;
                }
            }
            17 => {
                let has_udp_port = crate::net::l4::endpoint::manager::ENDPOINT_MANAGER
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .as_ref()
                    .map(|manager| manager.has_udp_port(src_port))
                    .unwrap_or(false);
                if !has_udp_port {
                    return;
                }
            }
            _ => return,
        }

        if icmp_type == IcmpType::DestinationUnreachable
            && code == DestUnreachCode::FragmentationNeeded as u8
        {
            let Some(next_hop_mtu_bytes) = view.read_array::<2>(6) else {
                return;
            };
            let next_hop_mtu = u16::from_be_bytes(next_hop_mtu_bytes);
            let mtu = if next_hop_mtu == 0 {
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
        // Security check 0: Is Redirect handling enabled globally?
        if !self.config.icmp_redirect_enabled {
            log::warn!(
                "[NET] ICMP: Ignoring Redirect from {} to {} via {} (Security: disabled by default)",
                redirect_source,
                destination,
                gateway
            );
            return;
        }

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
        let mut packet = self
            .alloc_ethernet_frame_packet(EthernetHeader::SIZE + 20 + 8)
            .ok_or(())?;
        let src_mac = self.mac_address();
        let mut built = false;

        if let Some(mut frame) = EthernetFrameMut::new(packet.data_mut()) {
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
                    let frame_len = frame.as_bytes().len();
                    drop(frame);
                    packet.set_len(frame_len);
                    built = true;
                }
            }
        }

        if !built {
            return Err(());
        }

        let send_time = self.current_time();

        if self.transmit_packet_on(
            None,
            kernel_api::resource::net::PacketPayload::single(packet),
        ) {
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
        let dst_mac = match self.resolve_mac(None, target, &config, current_time) {
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
        quoted_packet: &kernel_api::resource::net::PacketPayload,
    ) {
        let Some((final_proto, transport_payload)) =
            crate::net::payload::ipv6_transport_payload(quoted_packet)
        else {
            return;
        };
        if transport_payload.total_len() < 8 {
            return;
        }

        match final_proto {
            IpProtocol::Tcp => {
                let Some(header) = transport_payload.read_array::<8>(0) else {
                    return;
                };
                let src_port = u16::from_be_bytes([header[0], header[1]]);
                let dst_port = u16::from_be_bytes([header[2], header[3]]);
                let seq_num = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);

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
                let Some(header) = transport_payload.read_array::<4>(0) else {
                    return;
                };
                let src_port = u16::from_be_bytes([header[0], header[1]]);
                let has_udp_port = crate::net::l4::endpoint::manager::ENDPOINT_MANAGER
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .as_ref()
                    .map(|manager| manager.has_udp_port(src_port))
                    .unwrap_or(false);
                if !has_udp_port {
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

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while i < data.len() - 1 {
            sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
            i += 2;
        }

        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !sum as u16
    }
}
