use super::*;

impl NetworkStack {

    /// Bind a TCP listener
    pub fn bind_tcp(&mut self, addr: TcpSocketAddr) -> Result<TcpListener, TcpError> {
        // Delegate to processor
        self.tcp.bind(addr)
    }

    /// Test helper: insert a pre-built TCP connection into the stack.
    #[cfg(any(test, feature = "full_mm_tests", feature = "qemu-test-export"))]
    pub fn insert_test_tcp_connection(
        &mut self,
        local_addr: TcpSocketAddr,
        remote_addr: TcpSocketAddr,
        tcb: Arc<PoisonLock<TcpControlBlock>>,
    ) {
        self.tcp
            .insert_test_connection(local_addr, remote_addr, tcb);
    }

    pub(super) fn send_tcp_fallback(
        &mut self,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        tcp_segment: &[u8],
        dst_mac: MacAddress,
        src_mac: MacAddress,
    ) -> bool {
        self.send_tcp_fallback_with_ttl(src_ip, dst_ip, tcp_segment, dst_mac, src_mac, 64)
    }

    pub(super) fn send_tcp_fallback_with_ttl(
        &mut self,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        tcp_segment: &[u8],
        dst_mac: MacAddress,
        src_mac: MacAddress,
        ttl: u8,
    ) -> bool {
        let mut buffer = [0u8; MAX_PACKET_SIZE];
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame
                .set_destination(dst_mac)
                .set_source(src_mac)
                .set_ether_type(EtherType::Ipv4);
            let eth_payload = frame.payload_mut();
            if let Some(mut ip_packet) = Ipv4PacketMut::new(eth_payload) {
                ip_packet
                    .init_header()
                    .set_source(src_ip)
                    .set_destination(dst_ip)
                    .set_protocol(IpProtocol::Tcp)
                    .set_ttl(ttl);
                let ip_payload = ip_packet.payload_mut();
                if ip_payload.len() >= tcp_segment.len() {
                    ip_payload[..tcp_segment.len()].copy_from_slice(tcp_segment);
                    ip_packet.finalize(tcp_segment.len());
                    let ip_len = ip_packet.total_len();
                    frame.set_payload_len(ip_len);
                    return self.transmit(frame.as_bytes());
                }
            }
        }
        false
    }

    /// Send a raw TCP segment
    /// tcp_segment should already have the TCP header and data, with checksum calculated
    pub fn send_tcp(
        &mut self,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        tcp_segment: &[u8],
    ) -> bool {
        self.send_tcp_with_ttl(src_ip, dst_ip, tcp_segment, 64)
    }

    /// Send a raw TCP segment with explicit IPv4 TTL.
    pub fn send_tcp_with_ttl(
        &mut self,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        tcp_segment: &[u8],
        ttl: u8,
    ) -> bool {
        let config = self.config.clone();
        let current_time = self.current_time();

        // Resolve MAC address
        let dst_mac = self.resolve_mac(dst_ip, &config, current_time);
        let dst_mac = match dst_mac {
            Some(mac) => mac,
            None => return false, // ARP resolution pending
        };

        // Try zero-copy transmission first (allocate PacketRef and build packet directly into it)
        if let Some(mut packet) = crate::net::mempool::alloc_packet() {
            if let Some(mut frame) = EthernetFrameMut::new(packet.data_mut()) {
                frame
                    .set_destination(dst_mac)
                    .set_source(config.mac)
                    .set_ether_type(EtherType::Ipv4);

                let eth_payload = frame.payload_mut();

                // Build IP packet
                if let Some(mut ip_packet) = Ipv4PacketMut::new(eth_payload) {
                    ip_packet
                        .init_header()
                        .set_source(src_ip)
                        .set_destination(dst_ip)
                        .set_protocol(IpProtocol::Tcp)
                        .set_ttl(ttl);

                    let ip_payload = ip_packet.payload_mut();

                    // Copy TCP segment into PacketRef
                    if ip_payload.len() >= tcp_segment.len() {
                        ip_payload[..tcp_segment.len()].copy_from_slice(tcp_segment);
                        ip_packet.finalize(tcp_segment.len());

                        let ip_len = ip_packet.total_len();
                        frame.set_payload_len(ip_len);

                        // Set PacketRef length and attempt to enqueue zero-copy
                        let total_len = frame.as_bytes().len();
                        // Drop the mutable borrow on frame before moving packet
                        drop(frame);
                        packet.set_len(total_len);

                        match crate::net::zero_copy::ZeroCopyWriter::enqueue_via_virtio(packet) {
                            Ok(()) => {
                                // Zero-copy enqueue succeeded
                                // Update stats
                                self.stats.record_tx(total_len);
                                return true;
                            }
                            Err(_) => {
                                // Enqueue failed (queue full or device error) - drop packet and fall back
                            }
                        }
                    }
                }
            }
        }

        self.send_tcp_fallback_with_ttl(src_ip, dst_ip, tcp_segment, dst_mac, config.mac, ttl)
    }

    /// Process retransmission timeouts and attempt to resend timed-out segments.
    /// Also processes TCP keepalive timers.
    /// Call periodically with current time (ticks) to allow TCP retransmits.
    /// Build a raw TCP packet from TcpProcessResult fields and return the
    /// buffer and total length, or None if the result is not a SendPacket.
    pub(super) fn build_tcp_packet_from_result(
        res: &TcpProcessResult,
        buffer: &mut [u8; MAX_PACKET_SIZE],
    ) -> Option<(TcpSocketAddr, TcpSocketAddr, u32, usize)> {
        if let TcpProcessResult::SendPacket { local, remote, seq, ack, flags, window, ref payload } = *res {
            let header_len = 20usize;
            let total_len = header_len + payload.len();
            if total_len > buffer.len() {
                return None;
            }
            buffer[0..2].copy_from_slice(&local.port().to_be_bytes());
            buffer[2..4].copy_from_slice(&remote.port().to_be_bytes());
            buffer[4..8].copy_from_slice(&seq.to_be_bytes());
            buffer[8..12].copy_from_slice(&ack.to_be_bytes());
            let offset_flags = ((5u16 << 12) | (flags & 0x1FF)) as u16;
            buffer[12..14].copy_from_slice(&offset_flags.to_be_bytes());
            buffer[14..16].copy_from_slice(&window.to_be_bytes());
            buffer[16..18].fill(0);
            buffer[18..20].fill(0);
            if !payload.is_empty() {
                buffer[20..total_len].copy_from_slice(payload);
            }

            // Compute TCP checksum according to address family
            if local.is_ipv6() || remote.is_ipv6() {
                let src_v6 = local.as_ipv6();
                let dst_v6 = remote.as_ipv6();
                // IPv6 pseudo-header based checksum
                let pseudo = crate::net::ipv6::ipv6_pseudo_header_checksum(&src_v6, &dst_v6, crate::net::ipv4::IpProtocol::Tcp, total_len as u32);
                let checksum = crate::net::ipv4::data_checksum(&buffer[..total_len], pseudo);
                let final_checksum = if checksum == 0 { 0xFFFF } else { checksum };
                buffer[16..18].copy_from_slice(&final_checksum.to_be_bytes());
            } else {
                crate::net::tcp::calculate_tcp_checksum(&mut buffer[..total_len], local.as_ipv4().unwrap().octets(), remote.as_ipv4().unwrap().octets());
            }

            Some((local, remote, seq, total_len))
        } else {
            None
        }
    }

    pub fn process_timeouts(&mut self, current_time: u64) {
        let results = self.tcp.check_retransmissions(current_time);

        for res in results {
            let mut buffer = [0u8; MAX_PACKET_SIZE];
            if let Some((local, remote, seq, total_len)) = Self::build_tcp_packet_from_result(&res, &mut buffer) {
                let sent = if local.is_ipv6() && remote.is_ipv6() {
                    let src_v6 = local.as_ipv6();
                    let dst_v6 = remote.as_ipv6();
                    self.send_tcp_v6_raw(src_v6, dst_v6, &buffer[..total_len])
                } else if local.is_ipv4() && remote.is_ipv4() {
                    let src_ip_out = Ipv4Address::new(local.as_ipv4().unwrap().octets());
                    let dst_ip_out = Ipv4Address::new(remote.as_ipv4().unwrap().octets());
                    self.send_tcp(src_ip_out, dst_ip_out, &buffer[..total_len])
                } else {
                    // Mixed family — ignore
                    false
                };

                let now = self.current_time();
                if sent {
                    self.tcp.mark_retransmit_sent(local, remote, seq, now);
                } else {
                    log::info!("[NET] retransmit send failed for {} -> {}", local, remote);
                }
            }
        }

        // Process TCP keepalive probes
        let keepalive_results = self.tcp.process_keepalives(current_time);
        for res in keepalive_results {
            let mut buffer = [0u8; MAX_PACKET_SIZE];
            if let Some((local, remote, _seq, total_len)) = Self::build_tcp_packet_from_result(&res, &mut buffer) {
                if local.is_ipv6() && remote.is_ipv6() {
                    let src_v6 = local.as_ipv6();
                    let dst_v6 = remote.as_ipv6();
                    self.send_tcp_v6_raw(src_v6, dst_v6, &buffer[..total_len]);
                } else if local.is_ipv4() && remote.is_ipv4() {
                    let src_ip_out = Ipv4Address::new(local.as_ipv4().unwrap().octets());
                    let dst_ip_out = Ipv4Address::new(remote.as_ipv4().unwrap().octets());
                    self.send_tcp(src_ip_out, dst_ip_out, &buffer[..total_len]);
                }
            }
        }

        // Process zero-window probes (RFC 1122 Section 4.2.2.17)
        let zwp_results = self.tcp.process_zero_window_probes(current_time);
        for res in zwp_results {
            let mut buffer = [0u8; MAX_PACKET_SIZE];
            if let Some((local, remote, _seq, total_len)) = Self::build_tcp_packet_from_result(&res, &mut buffer) {
                if local.is_ipv6() && remote.is_ipv6() {
                    let src_v6 = local.as_ipv6();
                    let dst_v6 = remote.as_ipv6();
                    self.send_tcp_v6_raw(src_v6, dst_v6, &buffer[..total_len]);
                } else if local.is_ipv4() && remote.is_ipv4() {
                    let src_ip_out = Ipv4Address::new(local.as_ipv4().unwrap().octets());
                    let dst_ip_out = Ipv4Address::new(remote.as_ipv4().unwrap().octets());
                    self.send_tcp(src_ip_out, dst_ip_out, &buffer[..total_len]);
                }
            }
        }
    }

    /// Bind a UDP socket (uses token-based API)
    pub fn bind_udp(&mut self, port: u16) -> Option<UdpSocket> {
        self.udp.bind_with_token(port, None).ok()
    }

    /// Bind a UDP socket and associate it with an optional capability token
    pub fn bind_udp_with_token(&mut self, port: u16, token: Option<u64>) -> Option<UdpSocket> {
        self.udp.bind_with_token(port, token).ok()
    }

    /// Unbind a UDP socket (removes binding and decrements any associated token)
    pub fn unbind_udp(&mut self, port: u16) {
        self.udp.unbind(port);
    }

    // ========================================================================
    // Multicast Group Management (IGMP)
    // ========================================================================

    /// Join a multicast group
    /// 
    /// Sends an IGMP Membership Report and starts responding to queries
    /// for the specified group address.
    /// 
    /// # Parameters
    /// - `group`: Multicast group address (224.0.0.0 - 239.255.255.255)
    /// 
    /// # Returns
    /// - `Ok(())` if successfully joined
    /// - `Err(IgmpError::InvalidGroupAddress)` if not a multicast address
    /// - `Err(IgmpError::TooManyGroups)` if maximum groups reached
    pub fn join_multicast_group(&mut self, group: Ipv4Address) -> Result<(), IgmpError> {
        self.igmp.join_group(group)?;
        let current_time = self.current_time();
        self.send_pending_igmp_reports();
        Ok(())
    }

    /// Leave a multicast group
    /// 
    /// Sends an IGMP Leave Group message and stops responding to queries
    /// for the specified group address.
    /// 
    /// # Parameters
    /// - `group`: Multicast group address to leave
    /// 
    /// # Returns
    /// - `Ok(())` if successfully left
    /// - `Err(IgmpError::NotMember)` if not a member of the group
    pub fn leave_multicast_group(&mut self, group: Ipv4Address) -> Result<(), IgmpError> {
        self.igmp.leave_group(group)?;
        let current_time = self.current_time();
        self.send_pending_igmp_reports();
        Ok(())
    }

    /// Check if this host is a member of a multicast group
    pub fn is_multicast_member(&self, group: Ipv4Address) -> bool {
        self.igmp.is_member(group)
    }

    /// Get list of joined multicast groups
    pub fn multicast_groups(&self) -> &[crate::net::igmp::MulticastGroup] {
        self.igmp.joined_groups()
    }

    /// Send a UDP datagram (UdpAddr-based variant)
    /// ゼロコピーUDP送信を試行する
    pub(super) fn try_send_udp_zero_copy(
        &mut self,
        config: &NetworkConfig,
        src_ip: Ipv4Address,
        src_port: u16,
        dst_ip: Ipv4Address,
        dst_mac: MacAddress,
        dst_port: u16,
        data: &[u8],
    ) -> Option<Result<(), crate::net::NetworkError>> {
        let mut packet = crate::net::mempool::alloc_packet()?;
        let mut frame = EthernetFrameMut::new(packet.data_mut())?;
        frame
            .set_destination(dst_mac)
            .set_source(config.mac)
            .set_ether_type(EtherType::Ipv4);

        let eth_payload = frame.payload_mut();

        let mut ip_packet = Ipv4PacketMut::new(eth_payload)?;
        ip_packet
            .init_header()
            .set_source(src_ip)
            .set_destination(dst_ip)
            .set_protocol(IpProtocol::Udp)
            .set_ttl(64);

        let ip_payload = ip_packet.payload_mut();

        let udp_len = crate::net::udp::UdpProcessor::build_packet(
            ip_payload,
            config.ipv4.address,
            src_port,
            dst_ip,
            dst_port,
            data,
        )?;

        ip_packet.finalize(udp_len);
        let ip_len = ip_packet.total_len();
        frame.set_payload_len(ip_len);

        let total_len = frame.as_bytes().len();
        drop(frame);
        packet.set_len(total_len);

        if let Ok(()) = crate::net::zero_copy::ZeroCopyWriter::enqueue_via_virtio(packet) {
            self.stats.record_tx(total_len);
            return Some(Ok(()));
        }
        // Fall back to copy-based path on failure
        None
    }

    pub fn send_udp_addr(
        &mut self,
        src: crate::net::udp::UdpAddr,
        dst: crate::net::udp::UdpAddr,
        data: &[u8],
    ) -> Result<(), crate::net::NetworkError> {
        let config = self.config.clone();
        let current_time = self.current_time();

        // Use configured IP if source is ANY
        let src_ip = if src.ip.is_any() {
            config.ipv4.address
        } else {
            src.ip
        };
        let dst_ip = dst.ip;

        // Resolve MAC address
        let dst_mac = self.resolve_mac(dst_ip, &config, current_time)
            .ok_or(crate::net::NetworkError::ArpResolutionPending)?;

        // Try zero-copy first
        if let Some(result) = self.try_send_udp_zero_copy(
            &config, src_ip, src.port, dst_ip, dst_mac, dst.port, data,
        ) {
            return result;
        }

        let mut buffer = [0u8; MAX_PACKET_SIZE];

        // Build Ethernet frame
        let mut frame = EthernetFrameMut::new(&mut buffer)
            .ok_or(crate::net::NetworkError::BufferTooSmall)?;
        
        frame
            .set_destination(dst_mac)
            .set_source(config.mac)
            .set_ether_type(EtherType::Ipv4);

        let eth_payload = frame.payload_mut();

        // Build IP packet
        let mut ip_packet = Ipv4PacketMut::new(eth_payload)
            .ok_or(crate::net::NetworkError::BufferTooSmall)?;
        
        ip_packet
            .init_header()
            .set_source(src_ip)
            .set_destination(dst_ip)
            .set_protocol(IpProtocol::Udp)
            .set_ttl(64);

        let ip_payload = ip_packet.payload_mut();
        
        // Build UDP datagram
        let udp_len = crate::net::udp::UdpHeader::SIZE + data.len();
        if ip_payload.len() < udp_len {
            return Err(crate::net::NetworkError::BufferTooSmall);
        }

        // UDP Header
        ip_payload[0..2].copy_from_slice(&src.port.to_be_bytes());
        ip_payload[2..4].copy_from_slice(&dst.port.to_be_bytes());
        ip_payload[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        ip_payload[6..8].fill(0); // Checksum (optional for UDP over IPv4)
        
        // UDP Payload
        ip_payload[8..8 + data.len()].copy_from_slice(data);
        
        // Finalize IP packet
        ip_packet.finalize(udp_len);

        let ip_len = ip_packet.total_len();
        frame.set_payload_len(ip_len);

        if self.transmit(frame.as_bytes()) {
            Ok(())
        } else {
            Err(crate::net::NetworkError::TransmitFailed)
        }
    }

    /// Transmit a raw Ethernet frame
    pub fn transmit(&self, data: &[u8]) -> bool {
        if let Some(f) = self.transmit_fn {
            if f(None, data) {
                self.stats.record_tx(data.len());
                return true;
            } else {
                self.stats.record_tx_error();
                return false;
            }
        }

        false
    }

    /// Get ARP cache entries (for debugging)
    pub fn arp_cache(&self) -> Vec<(Ipv4Address, MacAddress)> {
        self.arp
            .cache()
            .all_entries()
            .iter()
            .filter(|e| e.state == crate::net::arp::ArpEntryState::Resolved)
            .map(|e| (e.ip, e.mac))
            .collect()
    }

    /// List all UDP sockets (for debugging/statistics)
    pub fn list_udp_sockets(&self) -> Vec<crate::net::udp::UdpSocketSnapshot> {
        self.udp.sockets().list_sockets()
    }

    /// Get configuration (for shell commands)
    pub fn get_config(&self) -> NetworkConfig {
        self.config.clone()
    }

    /// Update IP address (for DHCP)
    pub fn update_ip(&mut self, ip: Ipv4Address) {
        self.config.ipv4.address = ip;

        // Update dependent processors
        self.ipv4.set_config(self.config.ipv4.clone());
        self.arp.set_local(self.config.mac, ip);
    }

    pub(super) fn send_icmp_echo_fallback(
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
        if let Some(mut packet) = crate::net::mempool::alloc_packet() {
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

                        if crate::net::zero_copy::ZeroCopyWriter::enqueue_via_virtio(packet).is_ok() {
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
    pub(super) fn checksum(data: &[u8]) -> u16 {
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

    /// Periodic maintenance (call from timer)
    pub fn periodic(&mut self) {
        let current_time = self.current_time();

        // Expire old ARP entries
        self.arp.cache().expire_old(current_time);

        // Clean up closed and expired TIME_WAIT TCP connections
        self.tcp.cleanup_closed();

        // Process IGMP timers and send pending reports
        self.igmp.update_time(current_time);
        self.send_pending_igmp_reports();

        // Expire timed-out NDP pending packets
        self.expire_ndp_pending();

        // Run NDP periodic maintenance (expire stale neighbor cache entries + NUD probes)
        // Collect NS messages and link-local address first to avoid double borrow
        let ndp_ns_data: alloc::vec::Vec<(crate::net::ipv6::Ipv6Address, crate::net::ipv6::Ipv6Address, alloc::vec::Vec<u8>)> = {
            if let Some(ref mut ndp) = self.ndp {
                let ns_messages = ndp.tick(current_time);
                let our_ll = ndp.our_link_local;
                ns_messages
                    .into_iter()
                    .filter_map(|ns_msg| {
                        if ns_msg.len() >= 24 {
                            let mut target_bytes = [0u8; 16];
                            target_bytes.copy_from_slice(&ns_msg[8..24]);
                            let target = crate::net::ipv6::Ipv6Address::new(target_bytes);
                            let sn_mcast = target.solicited_node();
                            Some((our_ll, sn_mcast, ns_msg))
                        } else {
                            None
                        }
                    })
                    .collect()
            } else {
                alloc::vec::Vec::new()
            }
        };
        // Send NUD probe NS messages (borrow of self.ndp is released)
        for (our_ll, sn_mcast, ns_msg) in &ndp_ns_data {
            self.send_ipv6_icmpv6_raw(our_ll, sn_mcast, ns_msg);
        }

        // Cleanup expired DNS cache entries
        crate::net::dns::cleanup_cache(current_time);

        // Check DHCP (IPv4) lease timers (T1 renewal, T2 rebinding)
        // tick_rate = 1000 (current_time is in milliseconds, DHCP timers are in seconds)
        if let Ok(guard) = crate::net::dhcp::DHCP_CLIENT.lock() {
            if let Some(ref client) = *guard {
                if let Err(e) = client.drive(current_time, 1000) {
                    log::warn!("[NET] DHCPv4 drive failed: {}", e);
                }
            }
        }

        // Check DHCPv6 client timers
        if let Ok(guard6) = crate::net::dhcp::DHCPV6_CLIENT.lock() {
            if let Some(ref client6) = *guard6 {
                let _ = client6.check_timeout(current_time, 1000);
            }
        }

        // Evict expired IPv6 PMTU cache entries
        self.ipv6_pmtu_cache.evict_expired(current_time);
    }
}
