// ============================================================================
// UDP transmit and MAC resolution — NetworkStack impl methods
// ============================================================================
//! UDP raw send helpers (IPv4), MAC address resolution via ARP/IGMP multicast,
//! zero-copy UDP send, and UdpAddr-based send.

use super::*;

impl NetworkStack {
    pub(crate) fn resolve_ipv4_next_hop_on(
        &mut self,
        if_id: Option<super::NetIfId>,
        dst_ip: Ipv4Address,
        config: &NetworkConfig,
        current_time: u64,
    ) -> Option<Ipv4Address> {
        if dst_ip.is_loopback() {
            return None;
        }

        if config.ipv4.is_local(&dst_ip) {
            return Some(dst_ip);
        }

        if let Some(if_id) = if_id {
            if let Some(state) = self.interfaces.get_mut(&if_id) {
                state.redirect_cache.set_time(current_time);
                if let Some(redirected_gateway) = state.redirect_cache.get(dst_ip) {
                    return Some(redirected_gateway);
                }
            }

            if let Ok(Some(route)) = crate::net::runtime::manager::lookup_ipv4_route(dst_ip) {
                if route.if_id == if_id {
                    return Some(route.gateway.unwrap_or(dst_ip));
                }
            }

            if !config.ipv4.gateway.is_any() {
                return Some(config.ipv4.gateway);
            }

            return None;
        }

        Some(self.resolve_ipv4_next_hop(dst_ip, current_time))
    }

    pub(crate) fn send_udp_raw_with_config_and_if_ttl_payload(
        &mut self,
        if_id: Option<super::NetIfId>,
        config: &NetworkConfig,
        src_ip: Ipv4Address,
        src_port: u16,
        dst_ip: Ipv4Address,
        dst_port: u16,
        payload: &crate::net::payload::PacketPayloadView<'_>,
        ttl: u8,
    ) -> bool {
        if !crate::net::security::firewall::check_egress(
            src_ip.octets(),
            dst_ip.octets(),
            17,
            src_port,
            dst_port,
            0,
        ) {
            self.stats.record_dropped();
            return false;
        }

        let current_time = self.current_time();
        let dst_mac = if dst_ip.is_loopback() {
            config.mac
        } else {
            match self.resolve_mac(if_id, dst_ip, config, current_time) {
                Some(mac) => mac,
                None => return false,
            }
        };
        let path_mtu = self.effective_ipv4_pmtu(dst_ip, current_time);
        let Some(udp_buffer_len) = 8usize.checked_add(payload.total_len()) else {
            return false;
        };
        let mut udp_datagram = alloc::vec![0u8; udp_buffer_len];
        let Some(mut udp_packet) = crate::net::l4::udp::UdpPacketMut::new(&mut udp_datagram) else {
            return false;
        };
        udp_packet
            .set_src_port(src_port)
            .set_dst_port(dst_port)
            .write_payload_view(payload);
        let udp_len = udp_packet.finalize(src_ip, dst_ip);
        udp_datagram.truncate(udp_len);

        self.send_ipv4_l4_payload_with_pmtu(
            if_id,
            config.mac,
            dst_mac,
            src_ip,
            dst_ip,
            IpProtocol::Udp,
            ttl,
            &udp_datagram,
            path_mtu,
        )
        .is_ok()
    }

    pub fn send_udp_raw_payload_scoped_auto_ttl(
        &mut self,
        scope: crate::net::types::InterfaceScope,
        src_port: u16,
        dst_ip: Ipv4Address,
        dst_port: u16,
        payload: &crate::net::payload::PacketPayloadView<'_>,
        ttl: u8,
    ) -> bool {
        let Ok((if_id, config, src_ip)) = self.resolve_ipv4_egress(scope, None, None, dst_ip)
        else {
            self.stats.record_dropped();
            return false;
        };

        self.send_udp_raw_with_config_and_if_ttl_payload(
            if_id, &config, src_ip, src_port, dst_ip, dst_port, payload, ttl,
        )
    }

    pub fn send_udp_raw_payload_scoped_with_src_ttl(
        &mut self,
        scope: crate::net::types::InterfaceScope,
        src_ip: Ipv4Address,
        src_port: u16,
        dst_ip: Ipv4Address,
        dst_port: u16,
        payload: &crate::net::payload::PacketPayloadView<'_>,
        ttl: u8,
    ) -> bool {
        let Ok((if_id, config, resolved_src)) =
            self.resolve_ipv4_egress(scope, None, Some(src_ip), dst_ip)
        else {
            self.stats.record_dropped();
            return false;
        };

        self.send_udp_raw_with_config_and_if_ttl_payload(
            if_id,
            &config,
            resolved_src,
            src_port,
            dst_ip,
            dst_port,
            payload,
            ttl,
        )
    }

    /// Resolve IP to MAC address
    pub(crate) fn resolve_mac(
        &mut self,
        if_id: Option<super::NetIfId>,
        dst_ip: Ipv4Address,
        config: &NetworkConfig,
        current_time: u64,
    ) -> Option<MacAddress> {
        // RFC 1122: Loopback address MUST NOT be sent to a physical interface.
        if dst_ip.is_loopback() {
            return None;
        }

        // Broadcast address
        if dst_ip.is_broadcast() {
            return Some(MacAddress::BROADCAST);
        }

        // Multicast address (RFC 1112)
        if dst_ip.is_multicast() {
            return Some(multicast_ip_to_mac(dst_ip));
        }

        // Determine next hop, considering ICMP Redirect cache
        let next_hop = self.resolve_ipv4_next_hop_on(if_id, dst_ip, config, current_time)?;

        // Look up in ARP cache
        if let Some(if_id) = if_id {
            if let Some(state) = self.interfaces.get_mut(&if_id) {
                return match state.arp.resolve(next_hop, current_time) {
                    Some(mac) => Some(mac),
                    None => {
                        self.send_arp_request_on(if_id, next_hop);
                        None
                    }
                };
            }
        }

        match self.arp.resolve(next_hop, current_time) {
            Some(mac) => Some(mac),
            None => {
                self.send_arp_request(next_hop);
                None
            }
        }
    }

    /// Send a UDP datagram (UdpAddr-based variant)
    /// ゼロコピーUDP送信を試行する
    pub(crate) fn try_send_udp_zero_copy(
        &mut self,
        config: &NetworkConfig,
        src_ip: Ipv4Address,
        src_port: u16,
        dst_ip: Ipv4Address,
        dst_mac: MacAddress,
        dst_port: u16,
        data: &[u8],
    ) -> Option<Result<(), crate::net::types::NetworkError>> {
        let mut packet = crate::net::datapath::mempool::alloc_packet()?;
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

        let udp_len = crate::net::l4::udp::UdpProcessor::build_packet(
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

        if let Ok(()) = crate::net::datapath::zero_copy::ZeroCopyWriter::enqueue_via_virtio(packet)
        {
            self.stats.record_tx(total_len);
            return Some(Ok(()));
        }
        // Fall back to copy-based path on failure
        None
    }

    pub fn send_udp_addr(
        &mut self,
        src: crate::net::l4::udp::UdpAddr,
        dst: crate::net::l4::udp::UdpAddr,
        data: &[u8],
    ) -> Result<(), crate::net::types::NetworkError> {
        use crate::net::l4::udp::UdpAddr;

        match (src, dst) {
            (
                UdpAddr::V4 {
                    ip: s_ip,
                    port: s_port,
                },
                UdpAddr::V4 {
                    ip: d_ip,
                    port: d_port,
                },
            ) => {
                let current_time = self.current_time();
                let explicit_src = if s_ip.is_any() { None } else { Some(s_ip) };
                let (if_id, config, src_ip) = self.resolve_ipv4_egress(
                    crate::net::types::InterfaceScope::Any,
                    None,
                    explicit_src,
                    d_ip,
                )?;

                let dst_mac = if d_ip.is_loopback() {
                    config.mac
                } else {
                    self.resolve_mac(if_id, d_ip, &config, current_time)
                        .ok_or(crate::net::types::NetworkError::ArpResolutionPending)?
                };
                let path_mtu = self.effective_ipv4_pmtu(d_ip, current_time);
                let can_send_unfragmented = data
                    .len()
                    .checked_add(8)
                    .is_some_and(|udp_len| udp_len <= path_mtu.saturating_sub(20));

                // Try zero-copy first
                if if_id.is_none() && !d_ip.is_loopback() && can_send_unfragmented {
                    if let Some(result) = self.try_send_udp_zero_copy(
                        &config, src_ip, s_port, d_ip, dst_mac, d_port, data,
                    ) {
                        return result;
                    }
                }

                let Some(payload) = crate::net::payload::packet_from_bytes(data)
                    .map(kernel_api::resource::net::PacketPayload::single)
                else {
                    return Err(crate::net::types::NetworkError::TransmitFailed);
                };
                let payload = crate::net::payload::PacketPayloadView::new(&payload);

                if self.send_udp_raw_with_config_and_if_ttl_payload(
                    if_id, &config, src_ip, s_port, d_ip, d_port, &payload, 64,
                ) {
                    Ok(())
                } else {
                    Err(crate::net::types::NetworkError::TransmitFailed)
                }
            }
            (
                UdpAddr::V6 {
                    ip: s_ip,
                    port: s_port,
                },
                UdpAddr::V6 {
                    ip: d_ip,
                    port: d_port,
                },
            ) => {
                let Some(payload) = crate::net::payload::packet_from_bytes(data)
                    .map(kernel_api::resource::net::PacketPayload::single)
                else {
                    return Err(crate::net::types::NetworkError::TransmitFailed);
                };
                let payload = crate::net::payload::PacketPayloadView::new(&payload);
                self.send_udp_v6_payload_scoped_with_ttl(
                    crate::net::types::InterfaceScope::Any,
                    s_port,
                    s_ip,
                    d_ip,
                    d_port,
                    &payload,
                    64,
                )
            }
            _ => Err(crate::net::types::NetworkError::InvalidAddress),
        }
    }
}
