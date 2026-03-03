// ============================================================================
// UDP transmit and MAC resolution — NetworkStack impl methods
// ============================================================================
//! UDP raw send helpers (IPv4), MAC address resolution via ARP/IGMP multicast,
//! zero-copy UDP send, and UdpAddr-based send.

use super::*;

impl NetworkStack {
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
    pub(crate) fn resolve_mac(
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

        if let Ok(()) = crate::net::datapath::zero_copy::ZeroCopyWriter::enqueue_via_virtio(packet) {
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
            .ok_or(crate::net::types::NetworkError::ArpResolutionPending)?;

        // Try zero-copy first
        if let Some(result) = self.try_send_udp_zero_copy(
            &config, src_ip, src.port, dst_ip, dst_mac, dst.port, data,
        ) {
            return result;
        }

        let mut buffer = [0u8; MAX_PACKET_SIZE];

        // Build Ethernet frame
        let mut frame = EthernetFrameMut::new(&mut buffer)
            .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
        
        frame
            .set_destination(dst_mac)
            .set_source(config.mac)
            .set_ether_type(EtherType::Ipv4);

        let eth_payload = frame.payload_mut();

        // Build IP packet
        let mut ip_packet = Ipv4PacketMut::new(eth_payload)
            .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
        
        ip_packet
            .init_header()
            .set_source(src_ip)
            .set_destination(dst_ip)
            .set_protocol(IpProtocol::Udp)
            .set_ttl(64);

        let ip_payload = ip_packet.payload_mut();
        
        // Build UDP datagram
        let udp_len = crate::net::l4::udp::UdpHeader::SIZE + data.len();
        if ip_payload.len() < udp_len {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
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
            Err(crate::net::types::NetworkError::TransmitFailed)
        }
    }
}
