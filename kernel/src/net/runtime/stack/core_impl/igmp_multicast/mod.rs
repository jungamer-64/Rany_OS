use super::*;

mod tcp_bind;

#[inline]
fn tcp_ipv4_pair(
    local: TcpEndpointAddr,
    remote: TcpEndpointAddr,
) -> Option<([u8; 4], [u8; 4])> {
    Some((local.as_ipv4()?, remote.as_ipv4()?))
}

#[inline]
fn tcp_is_native_v6_pair(local: TcpEndpointAddr, remote: TcpEndpointAddr) -> bool {
    local.is_ipv6()
        && remote.is_ipv6()
        && local.as_ipv4().is_none()
        && remote.as_ipv4().is_none()
}

impl NetworkStack {
    
    /// Send an IGMP Leave Group message
    pub(super) fn send_igmp_leave(&mut self, group_addr: Ipv4Address, _current_time: u64) {
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
                    if let Some(len) = crate::net::l2::igmp::IgmpProcessor::build_leave(group_addr, ip_payload) {
                        let total_len = (20 + len) as u16;
                        ip_pkt.set_total_length(total_len).update_checksum();

                        let frame_len = 14 + total_len as usize;
                        if let Some(tx_fn) = self.transmit_fn {
                            if tx_fn(None, &buffer[..frame_len]) {
                                self.stats.record_tx(frame_len);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Apply DHCPv4 lease to live stack configuration and synchronize manager state.
    pub fn apply_dhcp_v4_lease(&mut self, lease: &crate::net::services::dhcp::DhcpLease) {
        let mut config = self.config();
        config.ipv4.address = lease.ip_address;
        config.ipv4.subnet_mask = lease.subnet_mask;
        if let Some(gateway) = lease.gateway {
            config.ipv4.gateway = gateway;
        }
        config.ipv4.dns = lease.dns_servers.first().copied();

        self.set_config(config);

        if let Some(if_id) = crate::net::runtime::manager::lookup_if_by_virtio_index(0) {
            let _ = crate::net::runtime::manager::set_interface_config(if_id, config);
        }
    }

    /// Process UDP data (for reassembled packets)
    pub fn process_udp_data(&mut self, data: &[u8], src_ip: Ipv4Address, dst_ip: Ipv4Address, ttl: u8, original_packet: &[u8], current_time: u64) {
        // For reassembled packets, we don't have a PacketRef for zero-copy
        // Use the non-zero-copy path
        let result = self.udp.process(data, src_ip, dst_ip, ttl);

        match result {
            UdpResult::Delivered => {}
            UdpResult::NoEndpoint => {
                self.stats.record_dropped();

                // RFC 1122: Send ICMP Port Unreachable
                // Only send if it wasn't broadcast/multicast
                if !dst_ip.is_broadcast() && !dst_ip.is_multicast() {
                    self.send_icmp_error(src_ip, DestUnreachCode::PortUnreachable, original_packet, current_time);
                }
            }
            UdpResult::ChecksumError | UdpResult::Invalid => {
                self.stats.record_rx_error();
            }
        }
    }

    /// Process TCP data (for reassembled packets)
    pub fn process_tcp_data(&mut self, data: &[u8], src_ip: Ipv4Address, dst_ip: Ipv4Address, current_time: u64) {
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
                options,
            } => {
                let mut buffer = [0u8; MAX_PACKET_SIZE];
                let header_len = 20 + options.len();
                let total_len = header_len + payload.len();

                if total_len > buffer.len() {
                    return;
                }

                // Construct TCP header
                buffer[0..2].copy_from_slice(&local.port().to_be_bytes());
                buffer[2..4].copy_from_slice(&remote.port().to_be_bytes());
                buffer[4..8].copy_from_slice(&seq.to_be_bytes());
                buffer[8..12].copy_from_slice(&ack.to_be_bytes());
                let data_offset = (header_len / 4) as u16;
                let offset_flags = (data_offset << 12) | (flags & 0x01ff);
                buffer[12..14].copy_from_slice(&offset_flags.to_be_bytes());
                buffer[14..16].copy_from_slice(&window.to_be_bytes());
                buffer[16..18].fill(0);
                buffer[18..20].fill(0);

                // Copy options
                if !options.is_empty() {
                    buffer[20..20 + options.len()].copy_from_slice(&options);
                }

                // Copy payload
                if !payload.is_empty() {
                    buffer[header_len..total_len].copy_from_slice(&payload);
                }

                let Some((local_v4, remote_v4)) = tcp_ipv4_pair(local, remote) else {
                    log::warn!("[NET] mixed TCP family dropped in IPv4 response path: {} -> {}", local, remote);
                    return;
                };
                crate::net::l4::tcp::calculate_tcp_checksum(
                    &mut buffer[..total_len],
                    local_v4,
                    remote_v4,
                );

                let src_ip_out = Ipv4Address::new(local_v4);
                let dst_ip_out = Ipv4Address::new(remote_v4);
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

    /// Process UDP data over IPv6
    ///
    /// IPv6擬似ヘッダーでチェックサムを検証し、ポート番号ベースで
    /// 既存のUDPソケットにデータグラムを配送する。
    pub(crate) fn process_udp_data_v6(
        &mut self,
        data: &[u8],
        src: crate::net::l3::ipv6::Ipv6Address,
        dst: crate::net::l3::ipv6::Ipv6Address,
        hop_limit: u8,
    ) {
        use crate::net::l3::ipv4::IpProtocol;
        use crate::net::l3::ipv6::ipv6_pseudo_header_checksum;
        use crate::net::l3::ipv4::data_checksum;

        // UDPヘッダー最小長チェック (8 bytes)
        if data.len() < 8 {
            self.stats.record_rx_error();
            return;
        }

        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let udp_length = u16::from_be_bytes([data[4], data[5]]);
        let checksum = u16::from_be_bytes([data[6], data[7]]);

        if udp_length < 8 || udp_length as usize > data.len() {
            self.stats.record_rx_error();
            return;
        }

        // RFC 8200: UDP over IPv6ではチェックサム0は許可されない
        if checksum == 0 {
            self.stats.record_rx_error();
            return;
        }

        // IPv6擬似ヘッダーでチェックサム検証
        let pseudo = ipv6_pseudo_header_checksum(
            &src, &dst, IpProtocol::Udp, udp_length as u32,
        );
        let verify = data_checksum(&data[..udp_length as usize], pseudo);
        if verify != 0 {
            self.stats.record_rx_error();
            return;
        }

        // ペイロード抽出
        let payload_end = core::cmp::min(udp_length as usize, data.len());
        if payload_end <= 8 {
            // ペイロードなし — 有効だがデータなし
            return;
        }
        let payload = &data[8..payload_end];

        // 既存のUDPソケットテーブルにポートベースで配送
        // src IPはIPv4マッピング不可のため0.0.0.0を使用（ソケット側で区別可能）
        let src_addr = crate::net::l4::udp::UdpAddr::new(
            Ipv4Address::new([0, 0, 0, 0]),
            src_port,
        );
        
        if let Some(mut pkt_ref) = crate::net::datapath::mempool::alloc_packet() {
            let buf = pkt_ref.data_mut();
            if payload.len() <= buf.len() {
                buf[..payload.len()].copy_from_slice(payload);
                pkt_ref.set_len(payload.len());
                if self.udp.endpoints().deliver(src_addr, dst_port, hop_limit, pkt_ref) {
                    self.stats.record_rx(data.len());
                } else {
                    self.stats.record_dropped();
                }
            } else {
                self.stats.record_dropped();
            }
        } else {
            self.stats.record_dropped();
        }
    }

    /// Process TCP data over IPv6
    ///
    /// IPv6擬似ヘッダーでチェックサムを検証する。
    /// 現在のTCPプロセッサはIPv4専用のため、検証後にログ記録のみ行う。
    /// 将来のデュアルスタック対応でフル処理を実装予定。
    pub(crate) fn process_tcp_data_v6(
        &mut self,
        data: &[u8],
        src: crate::net::l3::ipv6::Ipv6Address,
        dst: crate::net::l3::ipv6::Ipv6Address,
        _current_time: u64,
    ) {
        use crate::net::l3::ipv4::IpProtocol;
        use crate::net::l3::ipv6::ipv6_pseudo_header_checksum;
        use crate::net::l3::ipv4::data_checksum;

        // TCPヘッダー最小長チェック (20 bytes)
        if data.len() < 20 {
            self.stats.record_rx_error();
            return;
        }

        // IPv6擬似ヘッダーでチェックサム検証
        let pseudo = ipv6_pseudo_header_checksum(
            &src, &dst, IpProtocol::Tcp, data.len() as u32,
        );
        let verify = data_checksum(data, pseudo);
        if verify != 0 {
            self.stats.record_rx_error();
            return;
        }

        let _src_port = u16::from_be_bytes([data[0], data[1]]);
        let _dst_port = u16::from_be_bytes([data[2], data[3]]);

        // If addresses are IPv4-mapped (::ffff:a.b.c.d) we can route to the existing
        // IPv4 TCP processor (partial dual-stack / processor-level support).
        let sbytes = src.as_bytes();
        let dbytes = dst.as_bytes();
        let is_src_ipv4_mapped = sbytes[0..10] == [0u8; 10] && sbytes[10] == 0xff && sbytes[11] == 0xff;
        let is_dst_ipv4_mapped = dbytes[0..10] == [0u8; 10] && dbytes[10] == 0xff && dbytes[11] == 0xff;

        if is_src_ipv4_mapped && is_dst_ipv4_mapped {
            use crate::net::l3::ipv4::Ipv4Address;

            let src_v4 = Ipv4Address::new([sbytes[12], sbytes[13], sbytes[14], sbytes[15]]);
            let dst_v4 = Ipv4Address::new([dbytes[12], dbytes[13], dbytes[14], dbytes[15]]);

            // Security: TCP multicast/broadcast is not allowed (RFC 1122)
            if dst_v4.is_multicast() || dst_v4.is_broadcast() || (self.config().ipv4.subnet_mask.as_bytes()[0] != 0 && dst_v4 == self.config().ipv4.broadcast_address()) {
                self.stats.record_dropped();
                return;
            }

            // Delegate to existing IPv4 TCP processor (non-zero-copy path)
            let res = self.tcp.process(data, src_v4, dst_v4, self.current_time());

            match res {
                TcpProcessResult::SendPacket { local, remote, seq, ack, flags, window, payload, options } => {
                    let mut buffer = [0u8; 1518];
                    let header_len = 20 + options.len();
                    let total_len = header_len + payload.len();
                    if total_len > buffer.len() { return; }

                    buffer[0..2].copy_from_slice(&local.port().to_be_bytes());
                    buffer[2..4].copy_from_slice(&remote.port().to_be_bytes());
                    buffer[4..8].copy_from_slice(&seq.to_be_bytes());
                    buffer[8..12].copy_from_slice(&ack.to_be_bytes());
                    let data_offset = (header_len / 4) as u16;
                    let offset_flags = (data_offset << 12) | (flags & 0x1FF);
                    buffer[12..14].copy_from_slice(&offset_flags.to_be_bytes());
                    buffer[14..16].copy_from_slice(&window.to_be_bytes());
                    buffer[16..18].fill(0);
                    buffer[18..20].fill(0);

                    // Copy options
                    if !options.is_empty() {
                        buffer[20..20 + options.len()].copy_from_slice(&options);
                    }

                    // Copy payload
                    if !payload.is_empty() {
                        buffer[header_len..total_len].copy_from_slice(&payload);
                    }

                    // IPv4 TCP checksum (we're sending over IPv4 for mapped addresses)
                    let Some((local_v4, remote_v4)) = tcp_ipv4_pair(local, remote) else {
                        log::warn!(
                            "[NET] mixed TCP family dropped in v4-mapped TCPv6 response path: {} -> {}",
                            local,
                            remote
                        );
                        return;
                    };
                    crate::net::l4::tcp::calculate_tcp_checksum(
                        &mut buffer[..total_len],
                        local_v4,
                        remote_v4,
                    );

                    let src_ip_out = Ipv4Address::new(local_v4);
                    let dst_ip_out = Ipv4Address::new(remote_v4);

                    let sent = self.send_tcp(src_ip_out, dst_ip_out, &buffer[..total_len]);
                    let now = self.current_time();
                    if sent {
                        self.tcp.record_sent_packet(local, remote, seq, flags, &payload, now);
                    }
                }
                TcpProcessResult::None => {}
            }
            return;
        }

        // Native IPv6 TCP: delegate to the IPv6-capable TCP processor and
        // build/send any resulting TCP segments over IPv6.
        let res = self.tcp.process_v6(data, src, dst, self.current_time());
        match res {
            TcpProcessResult::SendPacket { local, remote, seq, ack, flags, window, payload, options } => {
                // Build TCP segment and send over IPv6
                let mut buffer = [0u8; 1518];
                let header_len = 20 + options.len();
                let total_len = header_len + payload.len();
                if total_len > buffer.len() { return; }

                buffer[0..2].copy_from_slice(&local.port().to_be_bytes());
                buffer[2..4].copy_from_slice(&remote.port().to_be_bytes());
                buffer[4..8].copy_from_slice(&seq.to_be_bytes());
                buffer[8..12].copy_from_slice(&ack.to_be_bytes());
                let data_offset = (header_len / 4) as u16;
                let offset_flags = (data_offset << 12) | (flags & 0x01ff);
                buffer[12..14].copy_from_slice(&offset_flags.to_be_bytes());
                buffer[14..16].copy_from_slice(&window.to_be_bytes());
                buffer[16..18].fill(0);
                buffer[18..20].fill(0);

                // Copy options
                if !options.is_empty() {
                    buffer[20..20 + options.len()].copy_from_slice(&options);
                }

                // Copy payload
                if !payload.is_empty() {
                    buffer[header_len..total_len].copy_from_slice(&payload);
                }

                // IPv6 TCP checksum
                let src_v6 = Ipv6Address::new(local.as_ipv6());
                let dst_v6 = Ipv6Address::new(remote.as_ipv6());
                let pseudo = crate::net::l3::ipv6::ipv6_pseudo_header_checksum(&src_v6, &dst_v6, crate::net::l3::ipv4::IpProtocol::Tcp, total_len as u32);
                let checksum = crate::net::l3::ipv4::data_checksum(&buffer[..total_len], pseudo);
                let final_checksum = if checksum == 0 { 0xFFFF } else { checksum };
                buffer[16..18].copy_from_slice(&final_checksum.to_be_bytes());

                // Send over IPv6
                let sent = self.send_tcp_v6_raw(src_v6, dst_v6, &buffer[..total_len]);
                let now = self.current_time();
                if sent {
                    self.tcp.record_sent_packet(local, remote, seq, flags, &payload, now);
                }
            }
            TcpProcessResult::None => {}
        }

    }

    /// Process ARP packet
    pub fn process_arp(&mut self, data: &[u8], current_time: u64, src_mac: MacAddress) {
        let result = self.arp.process(data, current_time, src_mac);

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
    pub(super) fn process_icmp(
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

    /// Process UDP packet
    pub fn process_udp(&mut self, data: &[u8], src_ip: Ipv4Address, dst_ip: Ipv4Address, _packet: PacketRef) {
        let result = self.udp.process_with_packet(data, src_ip, dst_ip, _packet, 64);

        match result {
            UdpResult::Delivered => {}
            UdpResult::NoEndpoint => {
                // Could send ICMP port unreachable
                self.stats.record_dropped();
            }
            UdpResult::ChecksumError | UdpResult::Invalid => {
                self.stats.record_rx_error();
            }
        }
    }

    /// Process TCP packet
    pub fn process_tcp(&mut self, data: &[u8], src_ip: Ipv4Address, dst_ip: Ipv4Address, _packet: PacketRef, current_time: u64) {
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
                options,
            } => {
                // Construct and send TCP segment
                let mut buffer = [0u8; 1518]; // MAX_PACKET_SIZE
                let header_len = 20 + options.len();
                let total_len = header_len + payload.len();
                
                if total_len > buffer.len() {
                    return;
                }
                
                // Construct TCP header
                // Source Port
                buffer[0..2].copy_from_slice(&local.port().to_be_bytes());
                // Dest Port
                buffer[2..4].copy_from_slice(&remote.port().to_be_bytes());
                // Seq
                buffer[4..8].copy_from_slice(&seq.to_be_bytes());
                // Ack
                buffer[8..12].copy_from_slice(&ack.to_be_bytes());
                // Data offset + flags
                let data_offset = (header_len / 4) as u16;
                let offset_flags = (data_offset << 12) | (flags & 0x1FF);
                buffer[12..14].copy_from_slice(&offset_flags.to_be_bytes());
                // Window
                buffer[14..16].copy_from_slice(&window.to_be_bytes());
                // Checksum
                buffer[16..18].fill(0);
                // Urgent pointer
                buffer[18..20].fill(0);

                // Copy options
                if !options.is_empty() {
                    buffer[20..20 + options.len()].copy_from_slice(&options);
                }

                // Copy payload
                if !payload.is_empty() {
                    buffer[header_len..total_len].copy_from_slice(&payload);
                }
                
                // Calculate Checksum
                let Some((local_v4, remote_v4)) = tcp_ipv4_pair(local, remote) else {
                    log::warn!("[NET] mixed TCP family dropped in IPv4 send path: {} -> {}", local, remote);
                    return;
                };
                crate::net::l4::tcp::calculate_tcp_checksum(
                    &mut buffer[..total_len],
                    local_v4,
                    remote_v4,
                );
                
                // Send via IP
                // Convert TcpIpv4Addr -> Ipv4Address
                let src_ip_out = Ipv4Address::new(local_v4);
                let dst_ip_out = Ipv4Address::new(remote_v4);
                
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

                if self.transmit(frame.as_bytes()) {
                    // Mark request as sent only when TX succeeded.
                    self.arp.request_sent(target_ip, current_time);
                    log::info!("[NET-ARP] ARP request sent for {}.{}.{}.{}",
                        target_ip.as_bytes()[0], target_ip.as_bytes()[1], target_ip.as_bytes()[2], target_ip.as_bytes()[3]);
                } else {
                    log::warn!("[NET-ARP] ARP request transmit failed for {}.{}.{}.{}",
                        target_ip.as_bytes()[0], target_ip.as_bytes()[1], target_ip.as_bytes()[2], target_ip.as_bytes()[3]);
                }
            }
        }
    }

    /// Send an ARP probe (RFC 5227 / RFC 2131 Section 2.2)
    /// 
    /// Probes are sent with sender_ip = 0.0.0.0 to detect address conflicts
    /// without polluting other hosts' ARP caches with unverified information.
    pub fn send_arp_probe(&mut self, target_ip: Ipv4Address) {
        let mut buffer = [0u8; 64];
        let mac = self.mac_address();
        let current_time = self.current_time();

        // Build Ethernet frame (broadcast)
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame
                .set_destination(MacAddress::BROADCAST)
                .set_source(mac)
                .set_ether_type(EtherType::Arp);

            let payload = frame.payload_mut();
            if let Some(len) = self.arp.build_probe(payload, target_ip) {
                frame.set_payload_len(len);
                frame.pad_to_minimum();

                if self.transmit(frame.as_bytes()) {
                    self.arp.request_sent(target_ip, current_time);
                    log::info!("[NET-ARP] ARP probe sent for {}", target_ip);
                }
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
        let src_ip = self.config.ipv4.address;
        self.send_udp_raw_with_src_ttl(src_ip, src_port, dst_ip, dst_port, data, 64)
    }

    /// Send a UDP packet with explicit IPv4 source address and TTL.
    pub fn send_udp_raw_with_src_ttl(
        &mut self,
        src_ip: Ipv4Address,
        src_port: u16,
        dst_ip: Ipv4Address,
        dst_port: u16,
        data: &[u8],
        ttl: u8,
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
                    .set_source(src_ip)
                    .set_destination(dst_ip)
                    .set_protocol(IpProtocol::Udp)
                    .set_identification(self.ipv4.next_id(dst_ip))
                    .set_ttl(ttl);

                let ip_payload = ip_packet.payload_mut();

                // Build UDP packet
                if let Some(udp_len) = crate::net::l4::udp::UdpProcessor::build_packet(
                    ip_payload,
                    src_ip,
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

        // Multicast address (RFC 1112)
        if dst_ip.is_multicast() {
            return Some(multicast_ip_to_mac(dst_ip));
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
    pub fn connect_tcp(&mut self, mut local_addr: TcpEndpointAddr, remote_addr: TcpEndpointAddr) -> Result<TcpStream, TcpError> {
        // Resolve local source address when unspecified.
        if local_addr.is_ipv4() {
            if local_addr.as_ipv4() == Some([0, 0, 0, 0]) {
                local_addr = TcpEndpointAddr::new(self.config.ipv4.address.octets(), local_addr.port());
            }
        } else if local_addr.as_ipv6() == [0u8; 16] {
            if let Some(ipv6_cfg) = self.config.ipv6 {
                let src_v6 = ipv6_cfg.global.unwrap_or(ipv6_cfg.link_local);
                if !src_v6.is_unspecified() {
                    local_addr = TcpEndpointAddr::new_v6(src_v6.octets(), local_addr.port());
                }
            }
        }

        // Allocate ephemeral port if not specified
        if local_addr.port() == 0 {
            let port = self.tcp.allocate_ephemeral_port(&local_addr, &remote_addr);
            if port == 0 {
                return Err(TcpError::BufferFull); // Or a better error for port exhaustion
            }
            local_addr = if local_addr.is_ipv4() {
                TcpEndpointAddr::new(
                    local_addr.as_ipv4().unwrap_or([0, 0, 0, 0]),
                    port,
                )
            } else {
                TcpEndpointAddr::new_v6(local_addr.as_ipv6(), port)
            };
        }

        let stream = self.tcp.connect(local_addr, remote_addr)?;
        
        // Send initial SYN
        let initial_seq = stream.initial_seq()?;
        
        // Construct and send SYN manually to avoid deadlock on NETWORK_STACK lock
        {
            let mut buffer = [0u8; 64]; 
            let header_len = 20;
            let total_len = header_len; 
            
            // Construct TCP header
            buffer[0..2].copy_from_slice(&local_addr.port().to_be_bytes());
            buffer[2..4].copy_from_slice(&remote_addr.port().to_be_bytes());
            buffer[4..8].copy_from_slice(&initial_seq.to_be_bytes());
            buffer[8..12].fill(0);
            let flags = 0x02u16; // SYN
            let offset_flags = (5 << 12) | flags;
            buffer[12..14].copy_from_slice(&offset_flags.to_be_bytes());
            buffer[14..16].copy_from_slice(&65535u16.to_be_bytes());
            buffer[16..18].fill(0);
            buffer[18..20].fill(0);
            
            // Calculate checksum and send (using the resolved local_addr)
            let sent = if let Some((local_v4, remote_v4)) = tcp_ipv4_pair(local_addr, remote_addr) {
                crate::net::l4::tcp::calculate_tcp_checksum(
                    &mut buffer[..total_len],
                    local_v4,
                    remote_v4,
                );
                self.send_tcp(Ipv4Address::new(local_v4), Ipv4Address::new(remote_v4), &buffer[..total_len])
            } else if tcp_is_native_v6_pair(local_addr, remote_addr) {
                let src_v6 = Ipv6Address::new(local_addr.as_ipv6());
                let dst_v6 = Ipv6Address::new(remote_addr.as_ipv6());
                let pseudo = crate::net::l3::ipv6::ipv6_pseudo_header_checksum(&src_v6, &dst_v6, crate::net::l3::ipv4::IpProtocol::Tcp, total_len as u32);
                let checksum = crate::net::l3::ipv4::data_checksum(&buffer[..total_len], pseudo);
                let final_checksum = if checksum == 0 { 0xFFFF } else { checksum };
                buffer[16..18].copy_from_slice(&final_checksum.to_be_bytes());
                self.send_tcp_v6_raw(src_v6, dst_v6, &buffer[..total_len])
            } else {
                false
            };

            let now = self.current_time();
            if sent {
                self.tcp.record_sent_packet(local_addr, remote_addr, initial_seq, TcpHeader::FLAG_SYN, &[], now);
            }
        }

        Ok(stream)
    }
}

#[cfg(any(test, feature = "qemu-test-export"))]
mod family_guard_tests {
    use super::*;

    #[cfg_attr(test, test_case)]
    fn tcp_ipv4_pair_rejects_mixed_family() {
        let local = TcpEndpointAddr::new([127, 0, 0, 1], 1234);
        let remote = TcpEndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 80);
        assert!(tcp_ipv4_pair(local, remote).is_none());
        assert!(!tcp_is_native_v6_pair(local, remote));
    }
}
