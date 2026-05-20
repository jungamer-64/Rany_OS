// ============================================================================
// kernel/src/net/runtime/stack/core_impl/protocol_impl/mod.rs - ランタイム / スタック / コア実装 / プロトコル実装 モジュール
// ============================================================================
//! Contains protocol-level `impl NetworkStack` methods, split into sub-files
//! by protocol responsibility:
//!
//!   - `arp.rs`      — ARP packet processing, request/reply/probe sending, ARP cache
//!   - `icmp.rs`     — ICMP processing, error messages, PMTUD, echo request/reply
//!   - `udp_tx.rs`   — UDP raw send, packet-native TX, MAC resolution
//!   - (this file)   — IGMP leave, DHCP lease, TCP/UDP data processing,
//!                      transmit wrapper, configuration, periodic maintenance

use super::*;

mod arp;
mod icmp;
mod udp_tx;

impl NetworkStack {
    pub(super) fn send_igmp_leave_on(
        &mut self,
        if_id: NetIfId,
        group_addr: Ipv4Address,
        _current_time: u64,
    ) {
        let Some(config) = self.interface_config(if_id) else {
            return;
        };
        // ── ファイアウォール Egress チェック ──
        if !crate::net::security::firewall::check_egress_in(
            self.runtime,
            config.ipv4.address.octets(),
            Ipv4Address::new([224, 0, 0, 2]).octets(), // all-routers
            2,                                         // IGMP
            0,
            0,
            0,
        ) {
            if let Some(stats) = self.interface_stats(if_id) {
                stats.record_dropped();
            }
            return;
        }

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
                        if packet.set_len(frame_len) {
                            let _ = self.transmit_packet_on(
                                Some(if_id),
                                kernel_api::resource::net::PacketPayload::single(packet),
                            );
                        }
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
        if let Some(primary_if) = crate::net::runtime::device::primary_if_in(self.runtime) {
            self.apply_dhcp_v4_lease_for_interface(lease, primary_if, true, dns_server);
            return;
        }

        log::warn!(
            target: "net::dhcp",
            "DHCPv4 lease ignored because no primary runtime interface is registered"
        );
    }

    pub fn apply_dhcp_v4_lease_for_interface(
        &mut self,
        lease: &crate::net::services::dhcp::DhcpLease,
        if_id: crate::net::runtime::manager::NetIfId,
        update_primary_runtime: bool,
        dns_server: Option<crate::net::l3::ipv4::Ipv4Address>,
    ) {
        let runtime = self.runtime;
        let Some(base_config) = crate::net::runtime::manager::get_interface_in(runtime, if_id)
            .ok()
            .flatten()
            .and_then(|iface| iface.config)
            .or_else(|| self.interface_config(if_id))
        else {
            return;
        };

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
        let runtime = self.runtime;
        let Some(base_config) = crate::net::runtime::manager::get_interface_in(runtime, if_id)
            .ok()
            .flatten()
            .and_then(|iface| iface.config)
            .or_else(|| self.interface_config(if_id))
        else {
            return;
        };

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
        packet: crate::net::payload::OwnedPayloadWindow,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        ttl: u8,
        current_time: u64,
    ) {
        let Some(resolved_if_id) = self.resolve_ingress_if(if_id) else {
            return;
        };
        let result = {
            let Some(state) = self.interfaces.get_mut(&resolved_if_id) else {
                return;
            };
            state.udp.process_window_on(
                self.runtime,
                Some(resolved_if_id),
                packet,
                src_ip,
                dst_ip,
                ttl,
            )
        };
        match result {
            Ok(()) => {}
            Err((UdpResult::NoEndpoint, original_packet)) => {
                if let Some(stats) = self.interface_stats(resolved_if_id) {
                    stats.record_dropped();
                }
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
            Err((UdpResult::NoIngressInterface, _)) => {
                if let Some(stats) = self.interface_stats(resolved_if_id) {
                    stats.record_dropped();
                }
            }
            Err((UdpResult::ChecksumError | UdpResult::Invalid, _)) => {
                if let Some(stats) = self.interface_stats(resolved_if_id) {
                    stats.record_rx_error();
                }
            }
            Err((UdpResult::Delivered, _)) => unreachable!(),
        }
    }

    pub(crate) fn process_udp_payload_v6(
        &mut self,
        if_id: Option<crate::net::runtime::manager::NetIfId>,
        packet: crate::net::payload::OwnedPayloadWindow,
        src: crate::net::l3::ipv6::Ipv6Address,
        dst: crate::net::l3::ipv6::Ipv6Address,
        hop_limit: u8,
    ) {
        let Some(resolved_if_id) = self.resolve_ingress_if(if_id) else {
            return;
        };
        let result = {
            let Some(state) = self.interfaces.get_mut(&resolved_if_id) else {
                return;
            };
            state.udp.process_window_v6_on(
                self.runtime,
                Some(resolved_if_id),
                packet,
                src,
                dst,
                hop_limit,
            )
        };
        match result {
            Ok(()) => {}
            Err((UdpResult::NoEndpoint, original_packet)) => {
                if let Some(stats) = self.interface_stats(resolved_if_id) {
                    stats.record_dropped();
                }
                self.send_icmpv6_error_payload(src, 4, original_packet);
            }
            Err((UdpResult::NoIngressInterface, _)) => {
                if let Some(stats) = self.interface_stats(resolved_if_id) {
                    stats.record_dropped();
                }
            }
            Err((UdpResult::ChecksumError | UdpResult::Invalid, _)) => {
                if let Some(stats) = self.interface_stats(resolved_if_id) {
                    stats.record_rx_error();
                }
            }
            Err((UdpResult::Delivered, _)) => unreachable!(),
        }
    }
}
