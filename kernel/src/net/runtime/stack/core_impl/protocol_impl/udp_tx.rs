// ============================================================================
// UDP transmit and MAC resolution — NetworkStack impl methods
// ============================================================================
//! UDP raw send helpers (IPv4), MAC address resolution via ARP/IGMP multicast,
//! zero-copy UDP send, and UdpAddr-based send.

use super::*;
use crate::net::payload::{PacketPayloadBuilder, PacketPayloadView};

fn payload_checksum(view: &PacketPayloadView<'_>, initial: u32) -> u16 {
    let mut sum = initial;
    let mut trailing = None;

    view.for_each_chunk(|chunk| {
        let mut index = 0usize;
        if let Some(prev) = trailing.take() {
            if let Some((&first, rest)) = chunk.split_first() {
                sum = sum.saturating_add(u16::from_be_bytes([prev, first]) as u32);
                index = 1;
                if rest.is_empty() {
                    return;
                }
            } else {
                trailing = Some(prev);
                return;
            }
        }

        while index + 1 < chunk.len() {
            sum = sum.saturating_add(u16::from_be_bytes([chunk[index], chunk[index + 1]]) as u32);
            index += 2;
        }
        if index < chunk.len() {
            trailing = Some(chunk[index]);
        }
    });

    if let Some(last) = trailing {
        sum = sum.saturating_add(u16::from_be_bytes([last, 0]) as u32);
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

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

            if let Ok(Some(route)) = crate::net::runtime::manager::lookup_ipv4_route_in(
                crate::net::runtime::default_runtime(),
                dst_ip,
            ) {
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
        payload: kernel_api::resource::net::PacketPayload,
        ttl: u8,
    ) -> bool {
        let payload_len = payload.total_len();
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
        let mut pending_payload = Some(payload);
        let dst_mac = if dst_ip.is_loopback() {
            config.mac
        } else {
            match self.resolve_arp_for_send(if_id, dst_ip, current_time, |pending| {
                pending.enqueue_udp(
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    ttl,
                    pending_payload
                        .take()
                        .expect("pending UDP payload must exist"),
                    current_time,
                );
            }) {
                Some(mac) => mac,
                None => return false,
            }
        };
        let path_mtu = self.effective_ipv4_pmtu(dst_ip, current_time);
        let Some(total_len) = 8usize.checked_add(payload_len) else {
            return false;
        };
        let Ok(total_len_u16) = u16::try_from(total_len) else {
            return false;
        };
        let mut header_packet = match crate::net::payload::alloc_packet_with_headroom(
            crate::net::l4::udp::UdpHeader::SIZE,
            kernel_api::resource::net::DEFAULT_PACKET_HEADROOM,
        ) {
            Some(packet) => packet,
            None => return false,
        };
        header_packet.set_len(crate::net::l4::udp::UdpHeader::SIZE);
        let Some(header) =
            crate::util::get_mut_ref::<crate::net::l4::udp::UdpHeader>(header_packet.data_mut(), 0)
        else {
            return false;
        };
        header.set_src_port(src_port);
        header.set_dst_port(dst_port);
        header.set_length(total_len_u16);
        header.set_checksum(0);

        let mut udp_payload = kernel_api::resource::net::PacketPayload::single(header_packet);
        crate::net::payload::append_payload(
            &mut udp_payload,
            pending_payload
                .take()
                .expect("resolved UDP payload must exist"),
        );
        let pseudo = crate::net::l3::ipv4::pseudo_header_checksum(
            src_ip,
            dst_ip,
            IpProtocol::Udp,
            total_len_u16,
        );
        let checksum = payload_checksum(&PacketPayloadView::new(&udp_payload), pseudo);
        let final_checksum = if checksum == 0 { 0xFFFF } else { checksum };
        if let Some(first) = udp_payload.segments_mut().first_mut() {
            first.data_mut()[6..8].copy_from_slice(&final_checksum.to_be_bytes());
        }
        let udp_payload = PacketPayloadView::new(&udp_payload);

        self.send_ipv4_l4_payload_with_pmtu(
            if_id,
            config.mac,
            dst_mac,
            src_ip,
            dst_ip,
            IpProtocol::Udp,
            ttl,
            &udp_payload,
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
        payload: kernel_api::resource::net::PacketPayload,
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
        payload: kernel_api::resource::net::PacketPayload,
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
        _config: &NetworkConfig,
        current_time: u64,
    ) -> Option<MacAddress> {
        self.resolve_arp_for_send(if_id, dst_ip, current_time, |_| {})
    }

    /// Resolve IP to MAC address with pending queue support
    pub(crate) fn resolve_arp_for_send<F>(
        &mut self,
        if_id: Option<super::NetIfId>,
        dst_ip: Ipv4Address,
        current_time: u64,
        queue_pending: F,
    ) -> Option<MacAddress>
    where
        F: FnOnce(&mut crate::net::runtime::stack::ArpPendingQueue),
    {
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

        let config = self.config.clone(); // Clone to avoid borrow issues

        // Determine next hop, considering ICMP Redirect cache
        let next_hop = self.resolve_ipv4_next_hop_on(if_id, dst_ip, &config, current_time)?;

        // Look up in ARP cache
        if let Some(if_id) = if_id {
            if let Some(state) = self.interfaces.get_mut(&if_id) {
                return match state.arp.resolve(next_hop, current_time) {
                    Some(mac) => Some(mac),
                    None => {
                        queue_pending(&mut state.arp_pending_queue);
                        self.send_arp_request_on(if_id, next_hop);
                        None
                    }
                };
            }
        }

        match self.arp.resolve(next_hop, current_time) {
            Some(mac) => Some(mac),
            None => {
                queue_pending(&mut self.arp_pending_queue);
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

                let mut builder = PacketPayloadBuilder::new();
                let Some(()) = builder.push_bytes(data) else {
                    return Err(crate::net::types::NetworkError::TransmitFailed);
                };
                if self.send_udp_raw_with_config_and_if_ttl_payload(
                    if_id,
                    &config,
                    src_ip,
                    s_port,
                    d_ip,
                    d_port,
                    builder.build(),
                    64,
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
                let mut builder = PacketPayloadBuilder::new();
                let Some(()) = builder.push_bytes(data) else {
                    return Err(crate::net::types::NetworkError::TransmitFailed);
                };
                let payload = builder.build();
                self.send_udp_v6_payload_scoped_with_ttl(
                    crate::net::types::InterfaceScope::Any,
                    s_port,
                    s_ip,
                    d_ip,
                    d_port,
                    payload,
                    64,
                )
            }
            _ => Err(crate::net::types::NetworkError::InvalidAddress),
        }
    }
}
