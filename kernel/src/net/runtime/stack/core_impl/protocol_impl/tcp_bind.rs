use super::*;
#[cfg(any(test, feature = "full_mm_tests", feature = "qemu-test-export"))]
use crate::net::l4::tcp::TcpControlBlock;

impl NetworkStack {
    /// Bind a UDP socket to a specific interface scope.
    pub fn bind_udp_scoped(
        &mut self,
        scope: crate::net::types::InterfaceScope,
        port: u16,
    ) -> Option<UdpEndpoint> {
        self.udp.bind_with_token(scope, port, None).ok()
    }

    /// Bind a TCP listener
    pub fn bind_tcp(&mut self, addr: TcpEndpointAddr) -> Result<TcpListener, TcpError> {
        // Default: no token
        self.tcp.bind(addr, None)
    }

    /// Bind a TCP listener with a capability token
    pub fn bind_tcp_with_token(
        &mut self,
        addr: TcpEndpointAddr,
        token: Option<u64>,
    ) -> Result<TcpListener, TcpError> {
        self.tcp.bind(addr, token)
    }

    /// Test helper: insert a pre-built TCP connection into the stack.
    #[cfg(any(test, feature = "full_mm_tests", feature = "qemu-test-export"))]
    pub fn insert_test_tcp_connection(
        &mut self,
        local_addr: TcpEndpointAddr,
        remote_addr: TcpEndpointAddr,
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
        // ── ファイアウォール Egress チェック ──
        if tcp_segment.len() >= 14 {
            let src_port = u16::from_be_bytes([tcp_segment[0], tcp_segment[1]]);
            let dst_port = u16::from_be_bytes([tcp_segment[2], tcp_segment[3]]);
            let tcp_flags = tcp_segment[13];
            if !crate::net::security::firewall::check_egress_v4(
                src_ip.octets(),
                dst_ip.octets(),
                6,
                src_port,
                dst_port,
                tcp_flags,
            ) {
                self.stats.record_dropped();
                return false;
            }
        }

        let config = self.config.clone();
        let current_time = self.current_time();

        // Resolve MAC address
        let dst_mac = self.resolve_mac(dst_ip, &config, current_time);
        let dst_mac = match dst_mac {
            Some(mac) => mac,
            None => return false, // ARP resolution pending
        };

        // Try zero-copy transmission first (allocate PacketRef and build packet directly into it)
        if let Some(mut packet) = crate::net::datapath::mempool::alloc_packet() {
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

                        match crate::net::datapath::zero_copy::ZeroCopyWriter::enqueue_via_virtio(
                            packet,
                        ) {
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
    pub(in crate::net::runtime::stack::core_impl) fn build_tcp_packet_from_result(
        res: &TcpProcessResult,
        buffer: &mut [u8; MAX_PACKET_SIZE],
    ) -> Option<(TcpEndpointAddr, TcpEndpointAddr, u32, usize)> {
        if let TcpProcessResult::SendPacket {
            local,
            remote,
            seq,
            ack,
            flags,
            window,
            ref payload,
            ref options,
        } = *res
        {
            let header_len = 20 + options.len();
            let total_len = header_len + payload.len();
            if total_len > buffer.len() {
                return None;
            }
            buffer[0..2].copy_from_slice(&local.port().to_be_bytes());
            buffer[2..4].copy_from_slice(&remote.port().to_be_bytes());
            buffer[4..8].copy_from_slice(&seq.to_be_bytes());
            buffer[8..12].copy_from_slice(&ack.to_be_bytes());
            let data_offset = (header_len / 4) as u16;
            let offset_flags = ((data_offset << 12) | (flags & 0x1FF)) as u16;
            buffer[12..14].copy_from_slice(&offset_flags.to_be_bytes());
            buffer[14..16].copy_from_slice(&window.to_be_bytes());
            buffer[16..18].fill(0);
            buffer[18..20].fill(0);

            // Copy options
            if !options.is_empty() {
                buffer[20..20 + options.len()].copy_from_slice(options);
            }

            // Copy payload
            if !payload.is_empty() {
                buffer[header_len..total_len].copy_from_slice(payload);
            }

            // Compute TCP checksum according to address family
            if local.is_ipv6() || remote.is_ipv6() {
                let src_v6 = Ipv6Address::new(local.as_ipv6());
                let dst_v6 = Ipv6Address::new(remote.as_ipv6());
                // IPv6 pseudo-header based checksum
                let pseudo = crate::net::l3::ipv6::ipv6_pseudo_header_checksum(
                    &src_v6,
                    &dst_v6,
                    crate::net::l3::ipv4::IpProtocol::Tcp,
                    total_len as u32,
                );
                let checksum = crate::net::l3::ipv4::data_checksum(&buffer[..total_len], pseudo);
                let final_checksum = checksum; // TCP checksums can be 0
                buffer[16..18].copy_from_slice(&final_checksum.to_be_bytes());
            } else if let (Some(lv4), Some(rv4)) = (local.as_ipv4(), remote.as_ipv4()) {
                crate::net::l4::tcp::calculate_tcp_checksum(&mut buffer[..total_len], lv4, rv4);
            }

            Some((local, remote, seq, total_len))
        } else {
            None
        }
    }

    pub fn process_tcp_retransmissions(&mut self, current_time: u64) {
        let results = self.tcp.check_retransmissions(current_time);

        for res in results {
            let mut buffer = [0u8; MAX_PACKET_SIZE];
            if let Some((local, remote, seq, total_len)) =
                Self::build_tcp_packet_from_result(&res, &mut buffer)
            {
                let sent = if local.is_ipv6() && remote.is_ipv6() {
                    let src_v6 = Ipv6Address::new(local.as_ipv6());
                    let dst_v6 = Ipv6Address::new(remote.as_ipv6());
                    self.send_tcp_v6_raw(src_v6, dst_v6, &buffer[..total_len])
                } else if let (Some(lv4), Some(rv4)) = (local.as_ipv4(), remote.as_ipv4()) {
                    let src_ip_out = Ipv4Address::new(lv4);
                    let dst_ip_out = Ipv4Address::new(rv4);
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
            if let Some((local, remote, _seq, total_len)) =
                Self::build_tcp_packet_from_result(&res, &mut buffer)
            {
                if local.is_ipv6() && remote.is_ipv6() {
                    let src_v6 = Ipv6Address::new(local.as_ipv6());
                    let dst_v6 = Ipv6Address::new(remote.as_ipv6());
                    self.send_tcp_v6_raw(src_v6, dst_v6, &buffer[..total_len]);
                } else if let (Some(lv4), Some(rv4)) = (local.as_ipv4(), remote.as_ipv4()) {
                    let src_ip_out = Ipv4Address::new(lv4);
                    let dst_ip_out = Ipv4Address::new(rv4);
                    self.send_tcp(src_ip_out, dst_ip_out, &buffer[..total_len]);
                }
            }
        }

        // Process zero-window probes (RFC 1122 Section 4.2.2.17)
        let zwp_results = self.tcp.process_zero_window_probes(current_time);
        for res in zwp_results {
            let mut buffer = [0u8; MAX_PACKET_SIZE];
            if let Some((local, remote, _seq, total_len)) =
                Self::build_tcp_packet_from_result(&res, &mut buffer)
            {
                if local.is_ipv6() && remote.is_ipv6() {
                    let src_v6 = Ipv6Address::new(local.as_ipv6());
                    let dst_v6 = Ipv6Address::new(remote.as_ipv6());
                    self.send_tcp_v6_raw(src_v6, dst_v6, &buffer[..total_len]);
                } else if let (Some(lv4), Some(rv4)) = (local.as_ipv4(), remote.as_ipv4()) {
                    let src_ip_out = Ipv4Address::new(lv4);
                    let dst_ip_out = Ipv4Address::new(rv4);
                    self.send_tcp(src_ip_out, dst_ip_out, &buffer[..total_len]);
                }
            }
        }
    }

    /// Bind a UDP socket (uses token-based API)
    pub fn bind_udp(&mut self, port: u16) -> Option<UdpEndpoint> {
        self.bind_udp_scoped(crate::net::types::InterfaceScope::Any, port)
    }

    /// Bind a UDP socket and associate it with an optional capability token
    pub fn bind_udp_with_token(&mut self, port: u16, token: Option<u64>) -> Option<UdpEndpoint> {
        self.bind_udp_with_token_scoped(crate::net::types::InterfaceScope::Any, port, token)
    }

    /// Bind a UDP socket with an optional capability token and explicit scope.
    pub fn bind_udp_with_token_scoped(
        &mut self,
        scope: crate::net::types::InterfaceScope,
        port: u16,
        token: Option<u64>,
    ) -> Option<UdpEndpoint> {
        self.udp.bind_with_token(scope, port, token).ok()
    }

    /// Unbind a UDP socket (removes binding and decrements any associated token)
    pub fn unbind_udp(&mut self, port: u16) {
        self.unbind_udp_scoped(crate::net::types::InterfaceScope::Any, port);
    }

    /// Unbind a UDP socket from an explicit scope.
    pub fn unbind_udp_scoped(
        &mut self,
        scope: crate::net::types::InterfaceScope,
        port: u16,
    ) {
        self.udp.unbind(scope, port);
    }

    /// TCP接続を解除
    pub fn unbind_tcp(&mut self, local: TcpEndpointAddr, remote: TcpEndpointAddr) {
        self.tcp.remove_connection(local, remote);
    }

    /// TCPリスナーを解除
    pub fn unbind_tcp_listener(&mut self, local: TcpEndpointAddr) {
        self.tcp.remove_listener(local);
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
        let _current_time = self.current_time();
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
        let _current_time = self.current_time();
        self.send_pending_igmp_reports();
        Ok(())
    }

    /// Check if this host is a member of a multicast group
    pub fn is_multicast_member(&self, group: Ipv4Address) -> bool {
        self.igmp.is_member(group)
    }

    /// Get list of joined multicast groups
    pub fn multicast_groups(&self) -> &[crate::net::l3::igmp::MulticastGroup] {
        self.igmp.joined_groups()
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

    /// List all UDP sockets (for debugging/statistics)
    pub fn list_udp_endpoints(&self) -> Vec<crate::net::l4::udp::UdpEndpointSnapshot> {
        self.udp.endpoints().list_endpoints()
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

    /// Periodic maintenance (call from timer)
    pub fn periodic(&mut self) {
        let current_time = self.current_time();

        // Expire old ARP entries
        self.arp.cache().expire_old(current_time);

        // Clean up closed and expired TIME_WAIT TCP connections
        self.tcp.cleanup_closed();

        // Process TCP timeouts (retransmissions, keepalives, zero-window probes)
        self.process_timeouts();

        // Process IGMP timers and send pending reports
        self.igmp.update_time(current_time);
        self.send_pending_igmp_reports();

        // Expire timed-out NDP pending packets
        self.expire_ndp_pending();

        // Run NDP periodic maintenance (expire stale neighbor cache entries + NUD probes)
        // Collect NS messages and link-local address first to avoid double borrow
        let ndp_ns_data: alloc::vec::Vec<(
            crate::net::l3::ipv6::Ipv6Address,
            crate::net::l3::ipv6::Ipv6Address,
            alloc::boxed::Box<[u8]>,
        )> = {
            if let Some(ref mut ndp) = self.ndp {
                let ns_messages = ndp.tick(current_time);
                let our_ll = ndp.our_link_local;
                ns_messages
                    .into_iter()
                    .filter_map(|ns_msg| {
                        if ns_msg.len() >= 24 {
                            let mut target_bytes = [0u8; 16];
                            target_bytes.copy_from_slice(&ns_msg[8..24]);
                            let target = crate::net::l3::ipv6::Ipv6Address::new(target_bytes);
                            let sn_mcast = target.solicited_node();
                            Some((our_ll, sn_mcast, ns_msg.into_boxed_slice()))
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
        crate::net::services::dns::cleanup_cache(current_time);

        // Evict expired IPv6 PMTU cache entries
        self.ipv6_pmtu_cache.evict_expired(current_time);
    }
}
