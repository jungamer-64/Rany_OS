use super::*;

mod _split_1;
pub use _split_1::*;
impl NetworkStack {
    
    /// Send an IGMP Leave Group message
    pub(super) fn send_igmp_leave(&mut self, group_addr: Ipv4Address, current_time: u64) {
        let mut buffer = [0u8; MAX_PACKET_SIZE];
        let config = self.config.clone();
        
        // Build Ethernet frame
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            // Leave messages are sent to all-routers group (224.0.0.2)
            let all_routers = Ipv4Address::new([224, 0, 0, 2]);
            let dst_mac = multicast_ip_to_mac(all_routers);
            frame
                .set_destination(dst_mac)
                .set_source(config.mac)
                .set_ether_type(EtherType::Ipv4);
            
            let payload = frame.payload_mut();
            
            // Build IPv4 header
            if let Some(mut ip_pkt) = Ipv4PacketMut::new(payload) {
                ip_pkt
                    .set_version(4)
                    .set_ihl(5)
                    .set_dscp(0xc0)
                    .set_ttl(1)
                    .set_protocol(IpProtocol::Igmp)
                    .set_source(config.ipv4.address)
                    .set_destination(all_routers);

                // Build IGMP leave into IPv4 payload.
                let ip_payload = ip_pkt.payload_mut();
                if ip_payload.len() >= 8 {
                    if let Some(len) = super::igmp::IgmpProcessor::build_leave(group_addr, ip_payload) {
                        let total_len = (20 + len) as u16;
                        ip_pkt.set_total_length(total_len).update_checksum();

                        let frame_len = 14 + total_len as usize;
                        if let Some(tx_fn) = self.transmit_fn {
                            if tx_fn(&buffer[..frame_len]) {
                                self.stats.record_tx(frame_len);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Process UDP data (for reassembled packets)
    pub(super) fn process_udp_data(&mut self, data: &[u8], src_ip: Ipv4Address, dst_ip: Ipv4Address) {
        // For reassembled packets, we don't have a PacketRef for zero-copy
        // Use the non-zero-copy path
        let result = self.udp.process(data, src_ip, dst_ip);

        match result {
            UdpResult::Delivered => {}
            UdpResult::NoSocket => {
                self.stats.record_dropped();
            }
            UdpResult::ChecksumError | UdpResult::Invalid => {
                self.stats.record_rx_error();
            }
        }
    }

    /// Process TCP data (for reassembled packets)
    pub(super) fn process_tcp_data(&mut self, data: &[u8], src_ip: Ipv4Address, dst_ip: Ipv4Address, current_time: u64) {
        // For reassembled packets, use the non-zero-copy TCP processing path
        let result = self.tcp.process(data, src_ip, dst_ip, current_time);

        match result {
            TcpProcessResult::SendPacket {
                local,
                remote,
                seq,
                ack,
                flags,
                window,
                payload,
            } => {
                let mut buffer = [0u8; MAX_PACKET_SIZE];
                let header_len = 20;
                let total_len = header_len + payload.len();

                if total_len > buffer.len() {
                    return;
                }

                // Construct TCP header
                buffer[0..2].copy_from_slice(&local.port.to_be_bytes());
                buffer[2..4].copy_from_slice(&remote.port.to_be_bytes());
                buffer[4..8].copy_from_slice(&seq.to_be_bytes());
                buffer[8..12].copy_from_slice(&ack.to_be_bytes());
                let offset_flags = (5u16 << 12) | (flags & 0x01ff);
                buffer[12..14].copy_from_slice(&offset_flags.to_be_bytes());
                buffer[14..16].copy_from_slice(&window.to_be_bytes());
                buffer[16..18].fill(0);
                buffer[18..20].fill(0);
                if !payload.is_empty() {
                    buffer[20..total_len].copy_from_slice(&payload);
                }

                super::tcp::calculate_tcp_checksum(
                    &mut buffer[..total_len],
                    local.ip.octets(),
                    remote.ip.octets(),
                );

                let src_ip_out = Ipv4Address::new(local.ip.octets());
                let dst_ip_out = Ipv4Address::new(remote.ip.octets());
                let sent = self.send_tcp(src_ip_out, dst_ip_out, &buffer[..total_len]);
                let now = self.current_time();
                if sent {
                    self.tcp.record_sent_packet(local, remote, seq, flags, &payload, now);
                } else {
                    log::info!("[NET] send failed for {} -> {} (will retry)", local, remote);
                }
            }
            TcpProcessResult::None => {}
        }
    }

    /// Process ARP packet
    pub(super) fn process_arp(&mut self, data: &[u8], current_time: u64) {
        let result = self.arp.process(data, current_time);

        match result {
            ArpResult::SendReply {
                target_mac,
                target_ip,
            } => {
                self.send_arp_reply(target_mac, target_ip);
            }
            ArpResult::CacheUpdated => {
                // Cache was updated, check if we have pending sends
            }
            ArpResult::Ignored | ArpResult::Invalid => {} // _ => {} // Unreachable pattern removed
        }
    }

    /// Process ICMP packet
    pub(super) fn process_icmp(&mut self, data: &[u8], src_ip: Ipv4Address, current_time: u64, _packet: PacketRef) {
        if !self.icmp_echo_enabled() {
            return;
        }

        let result = self.icmp.process(data, src_ip);

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
                // Could notify waiting pingers
                let _ = (identifier, sequence);
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

    /// Process UDP packet
    pub(super) fn process_udp(&mut self, data: &[u8], src_ip: Ipv4Address, dst_ip: Ipv4Address, _packet: PacketRef) {
        let result = self.udp.process_with_packet(data, src_ip, dst_ip, _packet);

        match result {
            UdpResult::Delivered => {}
            UdpResult::NoSocket => {
                // Could send ICMP port unreachable
                self.stats.record_dropped();
            }
            UdpResult::ChecksumError | UdpResult::Invalid => {
                self.stats.record_rx_error();
            }
        }
    }

    /// Process TCP packet
    pub(super) fn process_tcp(&mut self, data: &[u8], src_ip: Ipv4Address, dst_ip: Ipv4Address, _packet: PacketRef, current_time: u64) {
        // Zero-copy path: pass PacketRef to the TCP processor so it can enqueue a zero-copy payload view.
        let result = self.tcp.process_with_packet(data, src_ip, dst_ip, _packet, current_time);

        match result {
            TcpProcessResult::SendPacket {
                local,
                remote,
                seq,
                ack,
                flags,
                window,
                payload,
            } => {
                // Construct and send TCP segment
                let mut buffer = [0u8; 1518]; // MAX_PACKET_SIZE
                let header_len = 20; // Default header size
                let total_len = header_len + payload.len();
                
                if total_len > buffer.len() {
                    return;
                }
                
                // Construct TCP header
                // Source Port
                buffer[0..2].copy_from_slice(&local.port.to_be_bytes());
                // Dest Port
                buffer[2..4].copy_from_slice(&remote.port.to_be_bytes());
                // Seq
                buffer[4..8].copy_from_slice(&seq.to_be_bytes());
                // Ack
                buffer[8..12].copy_from_slice(&ack.to_be_bytes());
                // Flags & Offset (Header Length 5 dwords = 20 bytes)
                let offset_flags = (5 << 12) | (flags & 0x1FF);
                buffer[12..14].copy_from_slice(&offset_flags.to_be_bytes());
                // Window
                buffer[14..16].copy_from_slice(&window.to_be_bytes());
                // Checksum (zero for now)
                buffer[16..18].fill(0);
                // Urgent Pointer
                buffer[18..20].fill(0);
                
                // Payload
                if !payload.is_empty() {
                    buffer[20..total_len].copy_from_slice(&payload);
                }
                
                // Calculate Checksum
                super::tcp::calculate_tcp_checksum(
                    &mut buffer[..total_len],
                    local.ip.octets(),
                    remote.ip.octets(),
                );
                
                // Send via IP
                // Convert TcpIpv4Addr -> Ipv4Address
                let src_ip_out = Ipv4Address::new(local.ip.octets());
                let dst_ip_out = Ipv4Address::new(remote.ip.octets());
                
                // Send segment via IP
                let sent = self.send_tcp(src_ip_out, dst_ip_out, &buffer[..total_len]);
                let now = self.current_time();
                if sent {
                    // Record that the segment was sent so that retransmission queues
                    // and snd_nxt/outstanding bytes are updated
                    self.tcp.record_sent_packet(local, remote, seq, flags, &payload, now);
                } else {
                    log::info!("[NET] send failed for {} -> {} (will retry)", local, remote);
                }
            }
            TcpProcessResult::None => {}
        }
    }


    /// Send an ARP reply
    pub(super) fn send_arp_reply(&mut self, target_mac: MacAddress, target_ip: Ipv4Address) {
        let mut buffer = [0u8; 64];
        let mac = self.mac_address();

        // Build Ethernet frame
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame
                .set_destination(target_mac)
                .set_source(mac)
                .set_ether_type(EtherType::Arp);

            let payload = frame.payload_mut();
            if let Some(len) = self.arp.build_reply(payload, target_mac, target_ip) {
                frame.set_payload_len(len);
                frame.pad_to_minimum();

                self.transmit(frame.as_bytes());
            }
        }
    }

    /// Send an ARP request
    pub fn send_arp_request(&mut self, target_ip: Ipv4Address) {
        let mut buffer = [0u8; 64];
        let mac = self.mac_address();
        let current_time = self.current_time();

        // Check if we already have a pending request
        if self.arp.cache().is_pending(target_ip, current_time) {
            return;
        }

        // Build Ethernet frame (broadcast)
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame
                .set_destination(MacAddress::BROADCAST)
                .set_source(mac)
                .set_ether_type(EtherType::Arp);

            let payload = frame.payload_mut();
            if let Some(len) = self.arp.build_request(payload, target_ip) {
                frame.set_payload_len(len);
                frame.pad_to_minimum();

                // Mark request as sent
                self.arp.request_sent(target_ip, current_time);

                self.transmit(frame.as_bytes());
                log::info!("[NET-ARP] ARP request sent for {}.{}.{}.{}",
                    target_ip.as_bytes()[0], target_ip.as_bytes()[1], target_ip.as_bytes()[2], target_ip.as_bytes()[3]);
            }
        }
    }

    /// Resolve an IP address to a MAC from the ARP cache (public wrapper)
    pub fn arp_resolve(&self, ip: Ipv4Address, current_time: u64) -> Option<MacAddress> {
        self.arp.resolve(ip, current_time)
    }

    /// Insert an entry into the ARP cache (public wrapper for tests/diagnostics)
    pub fn arp_cache_insert(&mut self, ip: Ipv4Address, mac: MacAddress, current_time: u64) {
        self.arp.cache().insert(ip, mac, current_time);
    }

    /// Send ICMP echo reply
    pub(super) fn send_icmp_echo_reply(
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

    /// Handle ICMP error messages for Path MTU Discovery (RFC 1191)
    ///
    /// When a router cannot forward a packet because it exceeds the next-hop MTU
    /// and the DF (Don't Fragment) bit is set, it sends back an ICMP Destination
    /// Unreachable message with code 4 (Fragmentation Needed).
    ///
    /// The Next-Hop MTU is encoded in bytes 6-7 of the ICMP message (after the
    /// 4-byte ICMP header). This value indicates the maximum MTU that should be
    /// used for that path.
    pub(super) fn handle_icmp_error(&mut self, data: &[u8], icmp_type: IcmpType, code: u8, current_time: u64) {
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
        const IP_DST_OFFSET: usize = 16; // Destination IP starts at byte 16 of IP header
        let total_offset = ORIGINAL_IP_OFFSET + IP_DST_OFFSET;
        
        if data.len() < total_offset + 4 {
            return;
        }

        let dst_octets = [
            data[total_offset],
            data[total_offset + 1],
            data[total_offset + 2],
            data[total_offset + 3],
        ];
        let original_dst = Ipv4Address::from_octets(
            dst_octets[0],
            dst_octets[1],
            dst_octets[2],
            dst_octets[3],
        );

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
    pub(super) fn handle_icmp_redirect(
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

    /// Send a UDP packet (raw helper)
    pub fn send_udp_raw(
        &mut self,
        src_port: u16,
        dst_ip: Ipv4Address,
        dst_port: u16,
        data: &[u8],
    ) -> bool {
        let config = self.config.clone();
        let current_time = self.current_time();

        // Resolve MAC address
        let dst_mac = self.resolve_mac(dst_ip, &config, current_time);
        let dst_mac = match dst_mac {
            Some(mac) => mac,
            None => return false,
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
                    .set_protocol(IpProtocol::Udp)
                    .set_ttl(64);

                let ip_payload = ip_packet.payload_mut();

                // Build UDP packet
                if let Some(udp_len) = super::udp::UdpProcessor::build_packet(
                    ip_payload,
                    config.ipv4.address,
                    src_port,
                    dst_ip,
                    dst_port,
                    data,
                ) {
                    ip_packet.finalize(udp_len);

                    let ip_len = ip_packet.total_len();
                    frame.set_payload_len(ip_len);

                    return self.transmit(frame.as_bytes());
                }
            }
        }

        false
    }

    /// Resolve IP to MAC address
    pub(super) fn resolve_mac(
        &mut self,
        dst_ip: Ipv4Address,
        config: &NetworkConfig,
        current_time: u64,
    ) -> Option<MacAddress> {
        // Broadcast address
        if dst_ip.is_broadcast() {
            return Some(MacAddress::BROADCAST);
        }

        // Determine next hop, considering ICMP Redirect cache
        let next_hop = if config.ipv4.is_local(&dst_ip) {
            dst_ip
        } else {
            // Check redirect cache first for an alternative gateway
            // Update cache time before lookup
            self.redirect_cache.set_time(current_time);
            if let Some(redirected_gateway) = self.redirect_cache.get(dst_ip) {
                // Use the redirected gateway instead of the default
                redirected_gateway
            } else {
                config.ipv4.gateway
            }
        };

        // Look up in ARP cache
        match self.arp.resolve(next_hop, current_time) {
            Some(mac) => Some(mac),
            None => {
                // Need ARP resolution
                self.send_arp_request(next_hop);
                None
            }
        }
    }

    /// Connect to a remote TCP address
    pub fn connect_tcp(&mut self, local_addr: TcpSocketAddr, remote_addr: TcpSocketAddr) -> Result<TcpStream, TcpError> {
        let stream = self.tcp.connect(local_addr, remote_addr)?;
        
        // Send initial SYN
        let initial_seq = {
             match stream.tcb.lock() {
                Ok(tcb) => tcb.snd_nxt,
                Err(_) => return Err(TcpError::InvalidState),
             }
        };
        
        // super::tcp::send_syn_packet(local_addr, remote_addr, initial_seq);
        // DEADLOCK AVOIDANCE: send_syn_packet locks NETWORK_STACK, but we already hold it.
        // We must construct and send manually.
        {
            let mut buffer = [0u8; 64]; // Minimum 20 bytes header, 64 is safe
            let header_len = 20;
            let total_len = header_len; // No payload for SYN
            
            // Construct TCP header
            // Source Port
            buffer[0..2].copy_from_slice(&local_addr.port.to_be_bytes());
            // Dest Port
            buffer[2..4].copy_from_slice(&remote_addr.port.to_be_bytes());
            // Seq
            buffer[4..8].copy_from_slice(&initial_seq.to_be_bytes());
            // Ack (0 for SYN)
            buffer[8..12].fill(0);
            // Flags & Offset (Header Length 5 dwords = 20 bytes)
            // SYN = 0x02
            let flags = 0x02u16; 
            let offset_flags = (5 << 12) | flags;
            buffer[12..14].copy_from_slice(&offset_flags.to_be_bytes());
            // Window (initial window 65535)
            buffer[14..16].copy_from_slice(&65535u16.to_be_bytes());
            // Checksum (zero for now)
            buffer[16..18].fill(0);
            // Urgent Pointer
            buffer[18..20].fill(0);
            
             // Calculate Checksum
            super::tcp::calculate_tcp_checksum(
                &mut buffer[..total_len],
                local_addr.ip.octets(),
                remote_addr.ip.octets(),
            );
            
            // Send via IP
            let src_ip_out = Ipv4Address::new(local_addr.ip.octets());
            let dst_ip_out = Ipv4Address::new(remote_addr.ip.octets());
            
            let sent = self.send_tcp(src_ip_out, dst_ip_out, &buffer[..total_len]);
            let now = self.current_time();
            if sent {
                // Record that a SYN was sent so TCB outstanding bytes and snd_nxt are updated
                self.tcp.record_sent_packet(local_addr, remote_addr, initial_seq, TcpHeader::FLAG_SYN, &[], now);
            } else {
                log::info!("[NET] SYN send failed (ARP unresolved) - will retry");
            }
        }

        Ok(stream)
    }
}
