// ============================================================================
// Protocol-specific NetworkStack impl methods
// ============================================================================
//! Contains protocol-level `impl NetworkStack` methods, split into sub-files
//! by protocol responsibility:
//!
//!   - `arp.rs`      — ARP packet processing, request/reply/probe sending, ARP cache
//!   - `icmp.rs`     — ICMP processing, error messages, PMTUD, echo request/reply
//!   - `udp_tx.rs`   — UDP raw send, zero-copy send, MAC resolution
//!   - `tcp_bind.rs` — TCP listener binding, segment send, retransmissions
//!   - (this file)   — IGMP leave, DHCP lease, TCP/UDP data processing,
//!                      transmit wrapper, configuration, periodic maintenance

use super::*;

mod arp;
mod icmp;
mod tcp_bind;
mod udp_tx;

#[inline]
fn tcp_ipv4_pair(local: TcpEndpointAddr, remote: TcpEndpointAddr) -> Option<([u8; 4], [u8; 4])> {
    Some((local.as_ipv4()?, remote.as_ipv4()?))
}

#[inline]
fn tcp_is_native_v6_pair(local: TcpEndpointAddr, remote: TcpEndpointAddr) -> bool {
    local.is_ipv6() && remote.is_ipv6() && local.as_ipv4().is_none() && remote.as_ipv4().is_none()
}

impl NetworkStack {
    /// Send an IGMP Leave Group message
    pub(super) fn send_igmp_leave(&mut self, group_addr: Ipv4Address, _current_time: u64) {
        // ── ファイアウォール Egress チェック ──
        if !crate::net::security::firewall::check_egress_v4(
            self.config.ipv4.address.octets(),
            Ipv4Address::new([224, 0, 0, 2]).octets(), // all-routers
            2,                                         // IGMP
            0,
            0,
            0,
        ) {
            self.stats.record_dropped();
            return;
        }

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
                    if let Some(len) =
                        crate::net::l3::igmp::IgmpProcessor::build_leave(group_addr, ip_payload)
                    {
                        let total_len = (20 + len) as u16;
                        ip_pkt.set_total_length(total_len).update_checksum();

                        let frame_len = 14 + total_len as usize;
                        if let Some(tx_fn) = self.transmit_fn {
                            if tx_fn(None, &buffer[..frame_len], Default::default()) {
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
        if let Some(primary_if) = crate::net::runtime::device::primary_if() {
            self.apply_dhcp_v4_lease_for_interface(lease, primary_if, true);
            return;
        }

        let mut config = self.config();
        config.ipv4.address = lease.ip_address;
        config.ipv4.subnet_mask = lease.subnet_mask;
        if let Some(gateway) = lease.gateway {
            config.ipv4.gateway = gateway;
        }
        config.ipv4.dns = lease.dns_servers.first().copied();

        self.set_config(config);
    }

    pub fn apply_dhcp_v4_lease_for_interface(
        &mut self,
        lease: &crate::net::services::dhcp::DhcpLease,
        if_id: crate::net::runtime::manager::NetIfId,
        update_primary_runtime: bool,
    ) {
        let base_config = crate::net::runtime::manager::get_interface(if_id)
            .ok()
            .flatten()
            .and_then(|iface| iface.config)
            .unwrap_or_else(|| self.config());

        let mut iface_config = base_config;
        iface_config.ipv4.address = lease.ip_address;
        iface_config.ipv4.subnet_mask = lease.subnet_mask;
        iface_config.ipv4.gateway = if update_primary_runtime {
            lease
                .gateway
                .unwrap_or(crate::net::l3::ipv4::Ipv4Address::ANY)
        } else {
            crate::net::l3::ipv4::Ipv4Address::ANY
        };
        iface_config.ipv4.dns = if update_primary_runtime {
            lease.dns_servers.first().copied()
        } else {
            None
        };

        if update_primary_runtime {
            self.set_config(iface_config);
        }

        self.register_interface_state(if_id, iface_config);
        let _ = crate::net::runtime::manager::set_interface_config(if_id, iface_config);
    }

    pub fn clear_dhcp_v4_lease_for_interface(
        &mut self,
        if_id: crate::net::runtime::manager::NetIfId,
        clear_primary_runtime: bool,
    ) {
        let base_config = crate::net::runtime::manager::get_interface(if_id)
            .ok()
            .flatten()
            .and_then(|iface| iface.config)
            .unwrap_or_else(|| self.config());

        let mut iface_config = base_config;
        iface_config.ipv4.address = crate::net::l3::ipv4::Ipv4Address::ANY;
        iface_config.ipv4.subnet_mask = crate::net::l3::ipv4::Ipv4Config::default().subnet_mask;
        iface_config.ipv4.gateway = crate::net::l3::ipv4::Ipv4Address::ANY;
        iface_config.ipv4.dns = None;

        if clear_primary_runtime {
            self.set_config(iface_config);
        }

        self.register_interface_state(if_id, iface_config);
        let _ = crate::net::runtime::manager::set_interface_config(if_id, iface_config);
    }

    /// Process UDP data (for reassembled packets)
    pub fn process_udp_data(
        &mut self,
        data: &[u8],
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        ttl: u8,
        original_packet: &[u8],
        current_time: u64,
    ) {
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
                    self.send_icmp_error(
                        src_ip,
                        DestUnreachCode::PortUnreachable,
                        None,
                        original_packet,
                        current_time,
                    );
                }
            }
            UdpResult::ChecksumError | UdpResult::Invalid => {
                self.stats.record_rx_error();
            }
        }
    }

    /// Try to deliver a raw UDP segment (with header) to a stack-level UdpEndpoint.
    ///
    /// This is used as a fallback when ENDPOINT_MANAGER doesn't have a matching
    /// socket. Returns the UdpResult so the caller can decide what to do on miss.
    pub fn udp_process_raw(
        &self,
        udp_segment: &[u8],
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        ttl: u8,
    ) -> UdpResult {
        self.udp.process(udp_segment, src_ip, dst_ip, ttl)
    }

    /// Process TCP data (for reassembled packets)
    pub fn process_tcp_data(
        &mut self,
        data: &[u8],
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        current_time: u64,
    ) {
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
                    log::warn!(
                        "[NET] mixed TCP family dropped in IPv4 response path: {} -> {}",
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

                let sent = self.send_tcp_packet_for_flow(local, remote, &buffer[..total_len]);
                let now = self.current_time();
                if sent {
                    self.tcp
                        .record_sent_packet(local, remote, seq, flags, &payload, now);
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
        if_id: Option<crate::net::runtime::manager::NetIfId>,
        data: &[u8],
        src: crate::net::l3::ipv6::Ipv6Address,
        dst: crate::net::l3::ipv6::Ipv6Address,
        hop_limit: u8,
        original_packet: &[u8],
    ) {
        use crate::net::l4::udp::UdpResult;

        if data.len() >= 8 {
            let src_port = u16::from_be_bytes([data[0], data[1]]);
            let dst_port = u16::from_be_bytes([data[2], data[3]]);
            let remote =
                crate::net::l4::endpoint::types::EndpointAddr::new_v6(src.octets(), src_port);
            let ingress_if_id = self.resolve_ingress_if(if_id);

            if let Some(ref mgr) = *crate::net::l4::endpoint::manager::ENDPOINT_MANAGER
                .read()
                .unwrap_or_else(|e| e.into_inner())
            {
                if let Some(socket) = mgr.find_by_port(
                    crate::net::l4::endpoint::types::EndpointType::Udp,
                    crate::net::l4::endpoint::manager::EndpointFamily::Ipv6,
                    dst_port,
                    Some(ingress_if_id),
                ) {
                    socket.push_packet(ingress_if_id, remote, data[8..].to_vec());
                    return;
                }
            }
        }

        match self.udp.process_v6(data, src, dst, hop_limit) {
            UdpResult::Delivered => {}
            UdpResult::NoEndpoint => {
                self.stats.record_dropped();
                self.send_icmpv6_error(src, 4, original_packet);
            }
            UdpResult::ChecksumError | UdpResult::Invalid => {
                self.stats.record_rx_error();
            }
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
        use crate::net::l3::ipv4::data_checksum;
        use crate::net::l3::ipv6::ipv6_pseudo_header_checksum;

        // TCPヘッダー最小長チェック (20 bytes)
        if data.len() < 20 {
            self.stats.record_rx_error();
            return;
        }

        // IPv6擬似ヘッダーでチェックサム検証
        let pseudo = ipv6_pseudo_header_checksum(&src, &dst, IpProtocol::Tcp, data.len() as u32);
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
        let is_src_ipv4_mapped =
            sbytes[0..10] == [0u8; 10] && sbytes[10] == 0xff && sbytes[11] == 0xff;
        let is_dst_ipv4_mapped =
            dbytes[0..10] == [0u8; 10] && dbytes[10] == 0xff && dbytes[11] == 0xff;

        if is_src_ipv4_mapped && is_dst_ipv4_mapped {
            use crate::net::l3::ipv4::Ipv4Address;

            let src_v4 = Ipv4Address::new([sbytes[12], sbytes[13], sbytes[14], sbytes[15]]);
            let dst_v4 = Ipv4Address::new([dbytes[12], dbytes[13], dbytes[14], dbytes[15]]);

            // Security: TCP multicast/broadcast is not allowed (RFC 1122)
            if dst_v4.is_multicast()
                || dst_v4.is_broadcast()
                || (self.config().ipv4.subnet_mask.as_bytes()[0] != 0
                    && dst_v4 == self.config().ipv4.broadcast_address())
            {
                self.stats.record_dropped();
                return;
            }

            // Delegate to existing IPv4 TCP processor (non-zero-copy path)
            let res = self.tcp.process(data, src_v4, dst_v4, self.current_time());

            match res {
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
                    let mut buffer = [0u8; 1518];
                    let header_len = 20 + options.len();
                    let total_len = header_len + payload.len();
                    if total_len > buffer.len() {
                        return;
                    }

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

                    let sent = self.send_tcp_packet_for_flow(local, remote, &buffer[..total_len]);
                    let now = self.current_time();
                    if sent {
                        self.tcp
                            .record_sent_packet(local, remote, seq, flags, &payload, now);
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
                // Build TCP segment and send over IPv6
                let mut buffer = [0u8; 1518];
                let header_len = 20 + options.len();
                let total_len = header_len + payload.len();
                if total_len > buffer.len() {
                    return;
                }

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
                let pseudo = crate::net::l3::ipv6::ipv6_pseudo_header_checksum(
                    &Ipv6Address::new(local.as_ipv6()),
                    &Ipv6Address::new(remote.as_ipv6()),
                    crate::net::l3::ipv4::IpProtocol::Tcp,
                    total_len as u32,
                );
                let checksum = crate::net::l3::ipv4::data_checksum(&buffer[..total_len], pseudo);
                let final_checksum = checksum; // TCP checksums can be 0
                buffer[16..18].copy_from_slice(&final_checksum.to_be_bytes());

                // Send over IPv6
                let sent = self.send_tcp_packet_for_flow(local, remote, &buffer[..total_len]);
                let now = self.current_time();
                if sent {
                    self.tcp
                        .record_sent_packet(local, remote, seq, flags, &payload, now);
                }
            }
            TcpProcessResult::None => {}
        }
    }

    /// Process UDP packet
    pub fn process_udp(
        &mut self,
        data: &[u8],
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        packet: PacketRef,
    ) {
        let result = self
            .udp
            .process_with_packet(data, src_ip, dst_ip, packet.clone(), 64);

        match result {
            UdpResult::Delivered => {}
            UdpResult::NoEndpoint => {
                self.stats.record_dropped();

                // RFC 1122: Send ICMP Port Unreachable
                // Only send if it wasn't broadcast/multicast
                if !dst_ip.is_broadcast() && !dst_ip.is_multicast() {
                    let current_time = self.current_time();
                    self.send_icmp_error(
                        src_ip,
                        DestUnreachCode::PortUnreachable,
                        None,
                        packet.data(),
                        current_time,
                    );
                }
            }
            UdpResult::ChecksumError | UdpResult::Invalid => {
                self.stats.record_rx_error();
            }
        }
    }

    /// Process TCP packet
    pub fn process_tcp(
        &mut self,
        data: &[u8],
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        _packet: PacketRef,
        current_time: u64,
    ) {
        // Zero-copy path: pass PacketRef to the TCP processor so it can enqueue a zero-copy payload view.
        let result = self
            .tcp
            .process_with_packet(data, src_ip, dst_ip, _packet, current_time);

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
                    log::warn!(
                        "[NET] mixed TCP family dropped in IPv4 send path: {} -> {}",
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

                // Send via IP
                // Convert TcpIpv4Addr -> Ipv4Address
                let sent = self.send_tcp_packet_for_flow(local, remote, &buffer[..total_len]);
                let now = self.current_time();
                if sent {
                    // Record that the segment was sent so that retransmission queues
                    // and snd_nxt/outstanding bytes are updated
                    self.tcp
                        .record_sent_packet(local, remote, seq, flags, &payload, now);
                } else {
                    log::info!("[NET] send failed for {} -> {} (will retry)", local, remote);
                }
            }
            TcpProcessResult::None => {}
        }
    }

    /// Connect to a remote TCP address
    pub fn connect_tcp(
        &mut self,
        local_addr: TcpEndpointAddr,
        remote_addr: TcpEndpointAddr,
    ) -> Result<TcpStream, TcpError> {
        self.connect_tcp_in(
            crate::net::runtime::default_runtime(),
            local_addr,
            remote_addr,
        )
    }

    /// Connect to a remote TCP address in a specific runtime
    pub fn connect_tcp_in(
        &mut self,
        runtime: crate::net::runtime::NetRuntimeHandle,
        mut local_addr: TcpEndpointAddr,
        remote_addr: TcpEndpointAddr,
    ) -> Result<TcpStream, TcpError> {
        // Resolve local source address when unspecified.
        if local_addr.is_ipv4() {
            let explicit_src = local_addr
                .as_ipv4()
                .map(Ipv4Address::new)
                .filter(|ip| !ip.is_any());
            if let Some(remote_v4) = remote_addr.as_ipv4() {
                let (_, _, resolved_src) = self
                    .resolve_ipv4_egress(
                        crate::net::types::InterfaceScope::Any,
                        None,
                        explicit_src,
                        Ipv4Address::new(remote_v4),
                    )
                    .map_err(|_| TcpError::InvalidState)?;
                local_addr = TcpEndpointAddr::new(resolved_src.octets(), local_addr.port());
            }
        } else if tcp_is_native_v6_pair(local_addr, remote_addr) {
            let explicit_src = {
                let src = Ipv6Address::new(local_addr.as_ipv6());
                if src.is_unspecified() {
                    None
                } else {
                    Some(src)
                }
            };
            let (_, _, resolved_src) = self
                .resolve_ipv6_egress(
                    crate::net::types::InterfaceScope::Any,
                    None,
                    explicit_src,
                    Ipv6Address::new(remote_addr.as_ipv6()),
                )
                .map_err(|_| TcpError::InvalidState)?;
            local_addr = TcpEndpointAddr::new_v6(resolved_src.octets(), local_addr.port());
        } else if local_addr.as_ipv6() == [0u8; 16] {
            return Err(TcpError::InvalidState);
        }

        if local_addr.is_ipv4() && remote_addr.as_ipv4().is_none() {
            return Err(TcpError::InvalidState);
        }
        if local_addr.is_ipv6() && !tcp_is_native_v6_pair(local_addr, remote_addr) {
            return Err(TcpError::InvalidState);
        }

        // Allocate ephemeral port if not specified
        if local_addr.port() == 0 {
            let port = self.tcp.allocate_ephemeral_port(&local_addr, &remote_addr);
            if port == 0 {
                return Err(TcpError::BufferFull); // Or a better error for port exhaustion
            }
            local_addr = if local_addr.is_ipv4() {
                TcpEndpointAddr::new(local_addr.as_ipv4().unwrap_or([0, 0, 0, 0]), port)
            } else {
                TcpEndpointAddr::new_v6(local_addr.as_ipv6(), port)
            };
        }

        let stream = self.tcp.connect_in(runtime, local_addr, remote_addr)?;

        // Send initial SYN
        let initial_seq = stream.initial_seq()?;

        // Construct and send SYN manually to avoid deadlock on NETWORK_STACK lock
        {
            let mut options = Vec::new();
            if let Ok(mut tcb) = stream.tcb.lock() {
                options = tcb.build_options(TcpHeader::FLAG_SYN);
            }

            let mut buffer = [0u8; 128]; // Enough for header + max options
            let header_len = 20 + options.len();
            let total_len = header_len;

            // Construct TCP header
            buffer[0..2].copy_from_slice(&local_addr.port().to_be_bytes());
            buffer[2..4].copy_from_slice(&remote_addr.port().to_be_bytes());
            buffer[4..8].copy_from_slice(&initial_seq.to_be_bytes());
            buffer[8..12].fill(0);

            let data_offset = (header_len / 4) as u16;
            let offset_flags = (data_offset << 12) | TcpHeader::FLAG_SYN;
            buffer[12..14].copy_from_slice(&offset_flags.to_be_bytes());
            buffer[14..16].copy_from_slice(&65535u16.to_be_bytes());
            buffer[16..18].fill(0);
            buffer[18..20].fill(0);

            if !options.is_empty() {
                buffer[20..header_len].copy_from_slice(&options);
            }

            // Calculate checksum and send (using the resolved local_addr)
            let sent = if let Some((local_v4, remote_v4)) = tcp_ipv4_pair(local_addr, remote_addr) {
                crate::net::l4::tcp::calculate_tcp_checksum(
                    &mut buffer[..total_len],
                    local_v4,
                    remote_v4,
                );
                self.send_tcp_packet_for_flow(local_addr, remote_addr, &buffer[..total_len])
            } else if tcp_is_native_v6_pair(local_addr, remote_addr) {
                let src_v6 = Ipv6Address::new(local_addr.as_ipv6());
                let dst_v6 = Ipv6Address::new(remote_addr.as_ipv6());
                let pseudo = crate::net::l3::ipv6::ipv6_pseudo_header_checksum(
                    &src_v6,
                    &dst_v6,
                    crate::net::l3::ipv4::IpProtocol::Tcp,
                    total_len as u32,
                );
                let checksum = crate::net::l3::ipv4::data_checksum(&buffer[..total_len], pseudo);
                let final_checksum = checksum; // TCP checksums can be 0
                buffer[16..18].copy_from_slice(&final_checksum.to_be_bytes());
                self.send_tcp_packet_for_flow(local_addr, remote_addr, &buffer[..total_len])
            } else {
                false
            };

            let now = self.current_time();
            if sent {
                self.tcp.record_sent_packet(
                    local_addr,
                    remote_addr,
                    initial_seq,
                    TcpHeader::FLAG_SYN,
                    &[],
                    now,
                );
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
        let remote =
            TcpEndpointAddr::new_v6(crate::net::l3::ipv6::Ipv6Address::LOOPBACK.octets(), 80);
        assert!(tcp_ipv4_pair(local, remote).is_none());
        assert!(!tcp_is_native_v6_pair(local, remote));
    }
}
