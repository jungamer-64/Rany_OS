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
        if !crate::net::security::firewall::check_egress(
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

        let config = self.config.clone();
        let mut packet = match self.alloc_ethernet_frame_packet(60) {
            Some(packet) => packet,
            None => return,
        };

        // Build Ethernet frame
        if let Some(mut frame) = EthernetFrameMut::new(packet.data_mut()) {
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
                        frame.set_payload_len(total_len as usize);
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
    }

    /// Apply DHCPv4 lease to live stack configuration and synchronize manager state.
    pub fn apply_dhcp_v4_lease(
        &mut self,
        lease: &crate::net::services::dhcp::DhcpLease,
        dns_server: Option<crate::net::l3::ipv4::Ipv4Address>,
    ) {
        if let Some(primary_if) =
            crate::net::runtime::device::primary_if_in(crate::net::runtime::default_runtime())
        {
            self.apply_dhcp_v4_lease_for_interface(lease, primary_if, true, dns_server);
            return;
        }

        let mut config = self.config();
        config.ipv4.address = lease.ip_address;
        config.ipv4.subnet_mask = lease.subnet_mask;
        if let Some(gateway) = lease.gateway {
            config.ipv4.gateway = gateway;
        }
        config.ipv4.dns = dns_server;

        self.set_config(config);
    }

    pub fn apply_dhcp_v4_lease_for_interface(
        &mut self,
        lease: &crate::net::services::dhcp::DhcpLease,
        if_id: crate::net::runtime::manager::NetIfId,
        update_primary_runtime: bool,
        dns_server: Option<crate::net::l3::ipv4::Ipv4Address>,
    ) {
        let runtime = crate::net::runtime::default_runtime();
        let base_config = crate::net::runtime::manager::get_interface_in(runtime, if_id)
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
        iface_config.ipv4.dns = dns_server;

        if update_primary_runtime {
            self.set_config(iface_config);
        }

        self.register_interface_state(if_id, iface_config);
        let _ = crate::net::runtime::manager::set_interface_config_in(runtime, if_id, iface_config);
    }

    pub fn clear_dhcp_v4_lease_for_interface(
        &mut self,
        if_id: crate::net::runtime::manager::NetIfId,
        clear_primary_runtime: bool,
    ) {
        let runtime = crate::net::runtime::default_runtime();
        let base_config = crate::net::runtime::manager::get_interface_in(runtime, if_id)
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
        let _ = crate::net::runtime::manager::set_interface_config_in(runtime, if_id, iface_config);
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

        let view = crate::net::payload::PacketPayloadView::new(&payload);
        if let Some(header) = view.read_array::<4>(0) {
            let src_port = u16::from_be_bytes([header[0], header[1]]);
            let dst_port = u16::from_be_bytes([header[2], header[3]]);
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
                    let data_len = view.total_len().saturating_sub(8);
                    if let Some(payload) = payload.slice(8, data_len) {
                        let _ =
                            socket.deliver_udp_payload(ingress_if_id, remote, hop_limit, payload);
                        return;
                    }
                    self.stats.record_dropped();
                    return;
                }
            }
        }

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
}

#[cfg(any(test, feature = "qemu-test-export"))]
mod family_guard_tests {
    use super::*;
    use crate::net::l4::tcp::EndpointAddr as TcpEndpointAddr;

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
