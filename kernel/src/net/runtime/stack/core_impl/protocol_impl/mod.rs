// ============================================================================
// Protocol-specific NetworkStack impl methods
// ============================================================================
//! Contains protocol-level `impl NetworkStack` methods, split into sub-files
//! by protocol responsibility:
//!
//!   - `arp.rs`      — ARP packet processing, request/reply/probe sending, ARP cache
//!   - `icmp.rs`     — ICMP processing, error messages, PMTUD, echo request/reply
//!   - `udp_tx.rs`   — UDP raw send, zero-copy send, MAC resolution
//!   - (this file)   — IGMP leave, DHCP lease, TCP/UDP data processing,
//!                      transmit wrapper, configuration, periodic maintenance

use super::*;

mod arp;
mod icmp;
mod udp_tx;

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
        let Some(payload) = crate::net::payload::payload_from_bytes(data) else {
            self.stats.record_rx_error();
            return;
        };

        let result = self
            .udp
            .process_payload_on(None, payload, src_ip, dst_ip, ttl);

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

    pub fn process_udp_payload(
        &mut self,
        if_id: Option<crate::net::runtime::manager::NetIfId>,
        payload: PacketPayload,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        ttl: u8,
        original_packet: &PacketPayload,
        current_time: u64,
    ) {
        let result = self
            .udp
            .process_payload_on(if_id, payload, src_ip, dst_ip, ttl);

        match result {
            UdpResult::Delivered => {}
            UdpResult::NoEndpoint => {
                self.stats.record_dropped();
                if !dst_ip.is_broadcast() && !dst_ip.is_multicast() {
                    self.send_icmp_error_payload(
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
        let Some(payload) = crate::net::payload::payload_from_bytes(udp_segment) else {
            return UdpResult::Invalid;
        };
        self.udp_process_raw_payload(payload, src_ip, dst_ip, ttl)
    }

    pub fn udp_process_raw_payload(
        &self,
        udp_segment: PacketPayload,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        ttl: u8,
    ) -> UdpResult {
        self.udp.process_payload(udp_segment, src_ip, dst_ip, ttl)
    }

    /// Process TCP data (for reassembled packets)
    pub fn process_tcp_data(
        &mut self,
        data: &[u8],
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        _current_time: u64,
    ) {
        crate::net::l4::endpoint::tcp_rx::process_tcp_segment(
            src_ip.octets(),
            dst_ip.octets(),
            data,
        );
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
        udp_segment_packet: Option<PacketRef>,
    ) {
        use crate::net::l4::udp::UdpResult;

        let udp_segment_payload = udp_segment_packet
            .map(PacketPayload::single)
            .or_else(|| crate::net::payload::payload_from_bytes(data));

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
                    if let Some(payload) = udp_segment_payload
                        .as_ref()
                        .and_then(|segment| segment.slice(8, data.len() - 8))
                    {
                        let _ =
                            socket.deliver_udp_payload(ingress_if_id, remote, hop_limit, payload);
                        return;
                    }
                    self.stats.record_dropped();
                    return;
                }
            }
        }

        let Some(udp_segment_payload) = udp_segment_payload else {
            self.stats.record_rx_error();
            return;
        };

        match self
            .udp
            .process_payload_v6_on(if_id, udp_segment_payload, src, dst, hop_limit)
        {
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

    pub(crate) fn process_udp_payload_v6(
        &mut self,
        if_id: Option<crate::net::runtime::manager::NetIfId>,
        payload: PacketPayload,
        src: crate::net::l3::ipv6::Ipv6Address,
        dst: crate::net::l3::ipv6::Ipv6Address,
        hop_limit: u8,
        original_packet: &PacketPayload,
    ) {
        use crate::net::l4::udp::UdpResult;

        match self
            .udp
            .process_payload_v6_on(if_id, payload, src, dst, hop_limit)
        {
            UdpResult::Delivered => {}
            UdpResult::NoEndpoint => {
                self.stats.record_dropped();
                self.send_icmpv6_error_payload(src, 4, original_packet);
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
        crate::net::l4::endpoint::tcp_rx::process_tcp_segment_v6(src, dst, data);
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
        _current_time: u64,
    ) {
        let _ = _packet;
        crate::net::l4::endpoint::tcp_rx::process_tcp_segment(
            src_ip.octets(),
            dst_ip.octets(),
            data,
        );
    }

    /// Connect to a remote TCP address
    pub fn connect_tcp(
        &mut self,
        local_addr: TcpEndpointAddr,
        remote_addr: TcpEndpointAddr,
    ) -> Result<TcpStream, TcpError> {
        let _ = (local_addr, remote_addr);
        Err(TcpError::InvalidState)
    }

    /// Connect to a remote TCP address in a specific runtime
    pub fn connect_tcp_in(
        &mut self,
        runtime: crate::net::runtime::NetRuntimeHandle,
        local_addr: TcpEndpointAddr,
        remote_addr: TcpEndpointAddr,
    ) -> Result<TcpStream, TcpError> {
        let _ = (runtime, local_addr, remote_addr);
        Err(TcpError::InvalidState)
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
        assert!(local.is_ipv4());
        assert!(remote.is_ipv6());
        assert!(local.as_ipv4().is_some());
        assert!(remote.as_ipv4().is_none());
    }
}
