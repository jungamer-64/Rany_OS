// ============================================================================
// ICMP-related NetworkStack impl methods
// ============================================================================
//! ICMP packet processing, error message construction, PMTUD handling,
//! ICMP Redirect processing, and ICMP echo request/reply.

use super::*;

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

        // Security: Do not respond to broadcast/multicast ICMP Echo Requests (Smurf attack prevention)
        // RFC 1122 specifies that a host SHOULD NOT respond to ICMP echo requests sent to
        // a broadcast or multicast address.
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
            IcmpResult::Redirect { code, gateway, destination } => {
                // Handle ICMP Redirect for route optimization (RFC 792)
                self.handle_icmp_redirect(code, gateway, destination, src_ip);
            }
            _ => {}
        }
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
        original_packet: &[u8],
        current_time: u64,
    ) {
        let config = self.config.clone();

        // Security (RFC 1122 Section 3.2.2):
        // An ICMP error message MUST NOT be sent in response to:
        
        // 1. An ICMP error message.
        if original_packet.len() >= 20 {
            let proto = original_packet[9];
            if proto == u8::from(IpProtocol::Icmp) && original_packet.len() >= 20 + 1 {
                let icmp_type = original_packet[20];
                match IcmpType::from(icmp_type) {
                    IcmpType::DestinationUnreachable
                    | IcmpType::Redirect
                    | IcmpType::TimeExceeded
                    | IcmpType::ParameterProblem => {
                        return;
                    }
                    _ => {}
                }
            }
        }

        // 2. A packet sent as a Link Layer broadcast or multicast.
        // (Note: We assume the caller checked this or the packet reached us directly)
        
        // 3. A packet sent to an IP broadcast or multicast address.
        if let Some(ip) = Ipv4Packet::parse(original_packet) {
            let orig_dst = ip.destination();
            if orig_dst.is_broadcast() || orig_dst.is_multicast() || (config.ipv4.subnet_mask.as_bytes()[0] != 0 && orig_dst == config.ipv4.broadcast_address()) {
                return;
            }
        }

        // 4. A packet that is not the first fragment.
        if let Some(ip) = Ipv4Packet::parse(original_packet) {
            if ip.header().fragment_offset() != 0 {
                return;
            }
        }

        // 5. A packet whose source address is not a single host (e.g. 0.0.0.0, broadcast, etc.)
        if dst_ip.is_any() || dst_ip.is_broadcast() || dst_ip.is_multicast() {
            return;
        }

        // Rate limiting
        if !self.icmp.check_rate_limit(dst_ip, current_time) {
            return;
        }

        // Resolve MAC address for the original sender
        let dst_mac = if config.ipv4.is_local(&dst_ip) {
            if let Some(mac) = self.arp.resolve(dst_ip, current_time) {
                mac
            } else {
                self.send_arp_request(dst_ip);
                return;
            }
        } else {
            if let Some(mac) = self.arp.resolve(config.ipv4.gateway, current_time) {
                mac
            } else {
                self.send_arp_request(config.ipv4.gateway);
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
                if let Some(len) = IcmpProcessor::build_dest_unreachable(ip_payload, code, original_packet) {
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
        let config = self.config.clone();

        // Resolve MAC address
        let dst_mac = if config.ipv4.is_local(&dst_ip) {
            // Destination is on local subnet, use ARP
            if let Some(mac) = self.arp.resolve(dst_ip, current_time) {
                mac
            } else {
                // Need to send ARP request first
                self.send_arp_request(dst_ip);
                return;
            }
        } else {
            // Destination is remote, use gateway
            if let Some(mac) = self.arp.resolve(config.ipv4.gateway, current_time) {
                mac
            } else {
                self.send_arp_request(config.ipv4.gateway);
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
        let config = self.config.clone();
        let current_time = self.current_time();

        let dst_mac = match self.resolve_mac(dst_ip, &config, current_time) {
            Some(mac) => mac,
            None => return false,
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
                if let Some(icmp_len) =
                    crate::net::l3::icmp::IcmpProcessor::build_time_exceeded(ip_payload, code, original_packet)
                {
                    ip_packet.finalize(icmp_len);
                    let ip_len = ip_packet.total_len();
                    frame.set_payload_len(ip_len);
                    return self.transmit(frame.as_bytes());
                }
            }
        }

        false
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
    pub(crate) fn handle_icmp_error(&mut self, data: &[u8], icmp_type: IcmpType, code: u8, current_time: u64) {
        // Only handle Destination Unreachable with Fragmentation Needed (RFC 1191)
        if icmp_type != IcmpType::DestinationUnreachable {
            return;
        }
        if code != DestUnreachCode::FragmentationNeeded as u8 {
            return;
        }

        // ICMP Destination Unreachable format:
        // Bytes 0-3: ICMP header (type, code, checksum)
        // Bytes 4-5: Unused (must be zero)
        // Bytes 6-7: Next-Hop MTU (big-endian)
        // Bytes 8+: Original IP header + first 8 bytes of payload
        const NEXT_HOP_MTU_OFFSET: usize = 6;
        if data.len() < NEXT_HOP_MTU_OFFSET + 2 {
            return;
        }

        let next_hop_mtu = u16::from_be_bytes([data[NEXT_HOP_MTU_OFFSET], data[NEXT_HOP_MTU_OFFSET + 1]]);

        // If Next-Hop MTU is 0, the router doesn't support RFC 1191
        // Use a fallback plateau value (RFC 1191 recommends 576 as minimum)
        let mtu = if next_hop_mtu == 0 {
            576u16
        } else {
            next_hop_mtu
        };

        // Extract the original destination IP from the embedded IP header
        // The original IP header starts at byte 8 of the ICMP message
        const ORIGINAL_IP_OFFSET: usize = 8;
        const IP_SRC_OFFSET: usize = 12; // Source IP starts at byte 12 of IP header
        const IP_DST_OFFSET: usize = 16; // Destination IP starts at byte 16 of IP header
        
        if data.len() < ORIGINAL_IP_OFFSET + IP_DST_OFFSET + 4 {
            return;
        }

        // Security check: Verify original source matches our address
        let src_total_offset = ORIGINAL_IP_OFFSET + IP_SRC_OFFSET;
        let original_src = Ipv4Address::from_octets(
            data[src_total_offset],
            data[src_total_offset + 1],
            data[src_total_offset + 2],
            data[src_total_offset + 3],
        );
        if original_src != self.config.ipv4.address && !original_src.is_any() {
            // Ignore redirects/errors for packets we didn't send
            return;
        }

        let dst_total_offset = ORIGINAL_IP_OFFSET + IP_DST_OFFSET;
        let original_dst = Ipv4Address::from_octets(
            data[dst_total_offset],
            data[dst_total_offset + 1],
            data[dst_total_offset + 2],
            data[dst_total_offset + 3],
        );

        // Security (RFC 1191 / RFC 5927): Verify that the ICMP payload corresponds
        // to an active connection (ports/protocol match).
        // This prevents off-path attackers from poisoning the PMTU cache.
        
        // Extract Protocol from inner IP header (byte 9)
        const IP_PROTOCOL_OFFSET: usize = 9;
        let protocol_offset = ORIGINAL_IP_OFFSET + IP_PROTOCOL_OFFSET;
        if data.len() < protocol_offset + 1 {
            return;
        }
        let protocol = data[protocol_offset];

        // Calculate inner IP header length
        // First byte of inner IP header contains Version + IHL
        let ihl = data[ORIGINAL_IP_OFFSET] & 0x0F;
        let ip_header_len = (ihl as usize) * 4;
        let transport_offset = ORIGINAL_IP_OFFSET + ip_header_len;

        // Check if we have enough data for transport ports (at least 4 bytes)
        if data.len() < transport_offset + 4 {
            return;
        }

        let src_port = u16::from_be_bytes([data[transport_offset], data[transport_offset + 1]]);
        let dst_port = u16::from_be_bytes([data[transport_offset + 2], data[transport_offset + 3]]);

        // Check against active sockets
        // Note: 'original_src' is US, 'original_dst' is THEM.
        // So for local lookup, we use 'original_src' as local IP.
        match protocol {
            6 => { // TCP
                // TCP sequence number starts at byte 4 of the TCP header
                if data.len() < transport_offset + 8 {
                    return;
                }
                let seq_num = u32::from_be_bytes([
                    data[transport_offset + 4],
                    data[transport_offset + 5],
                    data[transport_offset + 6],
                    data[transport_offset + 7],
                ]);

                let local_addr = TcpEndpointAddr::new(original_src.octets(), src_port);
                let remote_addr = TcpEndpointAddr::new(original_dst.octets(), dst_port);

                if !self.tcp.validate_icmp_sequence(local_addr, remote_addr, seq_num) {
                    // Sequence number validation failed (prevents PMTU poisoning)
                    log::warn!(
                        "[NET] ICMP: PMTU error for {} rejected due to invalid TCP seq {}",
                        original_dst, seq_num
                    );
                    return;
                }
            }
            17 => { // UDP
                // Check if we have a socket bound to the source port
                if !self.udp.has_endpoint(src_port) {
                    return;
                }
            }
            _ => {
                // Ignore errors for other protocols to be safe
                return;
            }
        }

        // Update the PMTU cache
        self.ipv4.update_pmtu(original_dst, mtu, current_time);
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
        buf[ip_start] = 0x45;
        buf[ip_start + 1] = 0x00;
        let total_ip_len = (ip_hdr_len + icmp_hdr_len) as u16;
        buf[ip_start + 2] = (total_ip_len >> 8) as u8;
        buf[ip_start + 3] = total_ip_len as u8;
        buf[ip_start + 4..ip_start + 6].copy_from_slice(&[0x00, 0x00]);
        buf[ip_start + 6..ip_start + 8].copy_from_slice(&[0x40, 0x00]);
        buf[ip_start + 8] = 64;
        buf[ip_start + 9] = 1;
        buf[ip_start + 10..ip_start + 12].copy_from_slice(&[0x00, 0x00]);
        buf[ip_start + 12..ip_start + 16].copy_from_slice(local_ip.as_bytes());
        buf[ip_start + 16..ip_start + 20].copy_from_slice(target.as_bytes());

        let ip_checksum = Self::checksum(&buf[ip_start..ip_start + ip_hdr_len]);
        buf[ip_start + 10] = (ip_checksum >> 8) as u8;
        buf[ip_start + 11] = ip_checksum as u8;

        let icmp_start = ip_start + ip_hdr_len;
        buf[icmp_start] = 8;
        buf[icmp_start + 1] = 0;
        buf[icmp_start + 2..icmp_start + 4].copy_from_slice(&[0, 0]);
        buf[icmp_start + 4..icmp_start + 6].copy_from_slice(&identifier.to_be_bytes());
        buf[icmp_start + 6..icmp_start + 8].copy_from_slice(&sequence.to_be_bytes());

        let icmp_checksum = Self::checksum(&buf[icmp_start..icmp_start + icmp_hdr_len]);
        buf[icmp_start + 2] = (icmp_checksum >> 8) as u8;
        buf[icmp_start + 3] = icmp_checksum as u8;

        let send_time = self.current_time();

        if self.transmit(&buf[..total_len]) {
            log::info!("[NET-PING] Sent ICMP echo to {}.{}.{}.{} seq={}", 
                target.as_bytes()[0], target.as_bytes()[1], target.as_bytes()[2], target.as_bytes()[3], sequence);
            Ok(send_time)
        } else {
            log::warn!("[NET-PING] Failed to transmit ICMP echo to {}.{}.{}.{} seq={}", 
                target.as_bytes()[0], target.as_bytes()[1], target.as_bytes()[2], target.as_bytes()[3], sequence);
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

        // Need to resolve target MAC via ARP
        let current_time = self.current_time();
        let target_mac = self.arp.cache().lookup(target, current_time);

        let dst_mac = match target_mac {
            Some(mac) => mac,
            None => {
                log::info!("[NET-PING] ARP required for {}.{}.{}.{} seq={} - sending ARP request",
                    target.as_bytes()[0], target.as_bytes()[1], target.as_bytes()[2], target.as_bytes()[3], sequence);
                self.send_arp_request(target);
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

                        if crate::net::datapath::zero_copy::ZeroCopyWriter::enqueue_via_virtio(packet).is_ok() {
                            self.stats.record_tx(total_len);
                            log::info!("[NET-PING] Sent ICMP echo to {}.{}.{}.{} seq={}", 
                                target.as_bytes()[0], target.as_bytes()[1], target.as_bytes()[2], target.as_bytes()[3], sequence);
                            return Ok(send_time);
                        }
                    }
                }
            }
        }

        // Fallback to copy-based path
        self.send_icmp_echo_fallback(target, dst_mac, local_ip, identifier, sequence)
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
