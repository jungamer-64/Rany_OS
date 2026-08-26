// ============================================================================
// kernel/src/net/runtime/stack/core_impl/protocol_impl/udp_tx.rs - ランタイム / スタック / コア実装 / プロトコル実装 / udp tx
// ============================================================================
//! UDP raw send helpers (IPv4), MAC address resolution via ARP/IGMP multicast,
//! and packet-owned UDP TX.

use super::*;
use crate::net::payload::PacketPayloadView;

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
        if_id: super::NetIfId,
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

        if let Some(state) = self.interfaces.get_mut(&if_id) {
            state.redirect_cache.set_time(current_time);
            if let Some(redirected_gateway) = state.redirect_cache.get(dst_ip) {
                return Some(redirected_gateway);
            }
        }

        if let Ok(Some(route)) =
            crate::net::runtime::manager::lookup_ipv4_route_in(self.runtime, dst_ip)
        {
            if route.if_id == if_id {
                return Some(route.gateway.unwrap_or(dst_ip));
            }
        }

        if !config.ipv4.gateway.is_any() {
            return Some(config.ipv4.gateway);
        }

        None
    }

    pub(crate) fn send_udp_raw_with_config_and_if_ttl_payload(
        &mut self,
        if_id: super::NetIfId,
        config: &NetworkConfig,
        src_ip: Ipv4Address,
        src_port: u16,
        dst_ip: Ipv4Address,
        dst_port: u16,
        payload: kernel_api::resource::net::PacketPayload,
        ttl: u8,
    ) -> bool {
        let payload_len = payload.total_len();
        if !crate::net::security::firewall::check_egress_in(
            self.runtime,
            src_ip.octets(),
            dst_ip.octets(),
            17,
            src_port,
            dst_port,
            0,
        ) {
            self.stats().record_dropped();
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
        let path_mtu = self.effective_ipv4_pmtu(if_id, dst_ip, current_time);
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
        if set_packet_visible_len(&mut header_packet, crate::net::l4::udp::UdpHeader::SIZE).is_err()
        {
            return false;
        }
        let Some(header) =
            crate::util::get_mut_ref::<crate::net::l4::udp::UdpHeader>(header_packet.data_mut(), 0)
        else {
            return false;
        };
        header.set_src_port(src_port);
        header.set_dst_port(dst_port);
        header.set_length(total_len_u16);
        header.set_checksum(0);

        let Ok(udp_payload) = kernel_api::resource::net::PacketPayload::try_single(header_packet)
        else {
            return false;
        };
        let Ok(mut udp_payload) = udp_payload.try_append(
            pending_payload
                .take()
                .expect("resolved UDP payload must exist"),
        ) else {
            return false;
        };
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
        self.send_ipv4_l4_payload_with_pmtu(
            if_id,
            config.mac,
            dst_mac,
            src_ip,
            dst_ip,
            IpProtocol::Udp,
            ttl,
            udp_payload,
            path_mtu,
        )
        .is_ok()
    }

    pub fn send_udp_raw_payload_on_auto_ttl(
        &mut self,
        if_id: super::NetIfId,
        dst_ip: Ipv4Address,
        ports: crate::net::l4::udp::UdpPorts,
        payload: kernel_api::resource::net::PacketPayload,
        ttl: u8,
    ) -> bool {
        let Ok((config, src_ip)) = self.resolve_ipv4_egress_on(if_id, None) else {
            self.stats().record_dropped();
            return false;
        };

        self.send_udp_raw_with_config_and_if_ttl_payload(
            if_id,
            &config,
            src_ip,
            ports.source(),
            dst_ip,
            ports.destination(),
            payload,
            ttl,
        )
    }

    pub fn send_udp_raw_payload_on_with_src_ttl(
        &mut self,
        if_id: super::NetIfId,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        ports: crate::net::l4::udp::UdpPorts,
        payload: kernel_api::resource::net::PacketPayload,
        ttl: u8,
    ) -> bool {
        let Ok((config, resolved_src)) = self.resolve_ipv4_egress_on(if_id, Some(src_ip)) else {
            self.stats().record_dropped();
            return false;
        };

        self.send_udp_raw_with_config_and_if_ttl_payload(
            if_id,
            &config,
            resolved_src,
            ports.source(),
            dst_ip,
            ports.destination(),
            payload,
            ttl,
        )
    }

    /// Resolve IP to MAC address
    pub(crate) fn resolve_mac(
        &mut self,
        if_id: super::NetIfId,
        dst_ip: Ipv4Address,
        _config: &NetworkConfig,
        current_time: u64,
    ) -> Option<MacAddress> {
        self.resolve_arp_for_send(if_id, dst_ip, current_time, |_| {})
    }

    /// Resolve IP to MAC address with pending queue support
    pub(crate) fn resolve_arp_for_send<F>(
        &mut self,
        if_id: super::NetIfId,
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

        let config = self.interface_config_or_runtime(if_id)?;

        // Determine next hop, considering ICMP Redirect cache
        let next_hop = self.resolve_ipv4_next_hop_on(if_id, dst_ip, &config, current_time)?;

        // Look up in ARP cache
        let Some(state) = self.interfaces.get_mut(&if_id) else {
            return None;
        };
        match state.arp.resolve(next_hop, current_time) {
            Some(mac) => Some(mac),
            None => {
                queue_pending(&mut state.arp_pending_queue);
                self.send_arp_request_on(if_id, next_hop);
                None
            }
        }
    }
}
