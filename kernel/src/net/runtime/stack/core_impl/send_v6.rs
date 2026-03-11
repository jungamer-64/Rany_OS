// =============================================================================
// Send Path — IPv6 / ICMPv6 / NDP outgoing packet construction & transmission
//
// Split from core_impl/mod.rs for clarity.  Contains all methods that build
// and send outgoing IPv6 packets: ICMPv6, UDP-over-IPv6, TCP-over-IPv6,
// NDP pending-queue draining, and IGMP reporting.
// =============================================================================

use super::*;

impl NetworkStack {
    /// Send ICMPv6 Echo Reply with explicit source
    pub(crate) fn send_icmpv6_echo_reply_with_src(
        &mut self,
        src: Ipv6Address,
        dst: Ipv6Address,
        identifier: u16,
        sequence: u16,
        echo_data: &[u8],
    ) {
        // Build ICMPv6 Echo Reply message (with checksum)
        let icmpv6_msg =
            Icmpv6Builder::build_echo_reply(&src, &dst, identifier, sequence, echo_data);

        self.send_ipv6_icmpv6(&src, &dst, &icmpv6_msg);

        log::info!(
            "ICMPv6: Echo Reply sent from {} to {} id={} seq={}",
            src,
            dst,
            identifier,
            sequence
        );
    }

    pub(crate) fn send_icmpv6_echo_reply_with_src_on(
        &mut self,
        if_id: super::NetIfId,
        src: Ipv6Address,
        dst: Ipv6Address,
        identifier: u16,
        sequence: u16,
        echo_data: &[u8],
    ) {
        let icmpv6_msg =
            Icmpv6Builder::build_echo_reply(&src, &dst, identifier, sequence, echo_data);

        self.send_ipv6_icmpv6_on(if_id, &src, &dst, &icmpv6_msg);

        log::info!(
            "ICMPv6: Echo Reply sent from {} to {} on {:?} id={} seq={}",
            src,
            dst,
            if_id,
            identifier,
            sequence
        );
    }

    /// Send an ICMPv6 Packet Too Big error (RFC 4443 Section 3.2).
    ///
    /// Used for Path MTU Discovery to notify the sender that a packet exceeded the MTU.
    pub fn send_icmpv6_packet_too_big(
        &mut self,
        dst_v6: Ipv6Address,
        mtu: u32,
        original_packet: &[u8],
    ) -> bool {
        if let Some(ref mut ipv6_proc) = self.ipv6 {
            let our_addr = ipv6_proc.config().link_local;

            // Security: RFC 4443 compliance check
            if !self.should_send_icmp_v6_error(original_packet, dst_v6, Icmpv6Type::PacketTooBig, 0)
            {
                return false;
            }

            // Rate limit ICMPv6 error messages
            let current_time = self.current_time();
            if let Some(ref icmpv6) = self.icmpv6 {
                if !icmpv6.check_tx_rate_limit(current_time) {
                    return false;
                }
            }

            let icmp_msg = crate::net::l3::icmpv6::Icmpv6Builder::build_packet_too_big(
                &our_addr,
                &dst_v6,
                mtu,
                original_packet,
            );
            self.send_ipv6_icmpv6(&our_addr, &dst_v6, &icmp_msg);
            true
        } else {
            false
        }
    }

    /// Send an ICMPv6 Time Exceeded error (RFC 4443).
    pub fn send_icmpv6_time_exceeded(
        &mut self,
        dst_v6: Ipv6Address,
        code: u8,
        original_packet: &[u8],
    ) -> bool {
        if let Some(ref mut ipv6_proc) = self.ipv6 {
            let our_addr = ipv6_proc.config().link_local;

            // Security: RFC 4443 compliance check (no errors for multicast etc)
            if !self.should_send_icmp_v6_error(
                original_packet,
                dst_v6,
                Icmpv6Type::TimeExceeded,
                code,
            ) {
                return false;
            }

            // Security: Rate limit ICMPv6 error messages (RFC 4443)
            let current_time = self.current_time();
            if let Some(ref icmpv6) = self.icmpv6 {
                if !icmpv6.check_tx_rate_limit(current_time) {
                    return false;
                }
            }

            let icmp_msg = crate::net::l3::icmpv6::Icmpv6Builder::build_time_exceeded(
                &our_addr,
                &dst_v6,
                code,
                original_packet,
            );
            self.send_ipv6_icmpv6(&our_addr, &dst_v6, &icmp_msg);
            true
        } else {
            false
        }
    }

    /// Send an IPv6 packet containing ICMPv6 payload
    pub(crate) fn send_ipv6_icmpv6(
        &mut self,
        src: &Ipv6Address,
        dst: &Ipv6Address,
        icmpv6_data: &[u8],
    ) {
        let config = self.config;
        let current_time = self.current_time.load(Ordering::Relaxed);

        // Resolve destination MAC
        let dst_mac = if dst.is_multicast() {
            dst.multicast_mac()
        } else {
            // Use NDP to resolve
            match self.ndp {
                Some(ref mut ndp) => {
                    match ndp.resolve(dst) {
                        Some(mac) => mac,
                        None => {
                            // Queue packet for later delivery
                            self.ndp_pending_queue
                                .enqueue(*src, *dst, icmpv6_data, current_time);

                            // Start NDP resolution (send NS)
                            let ns_msg = ndp.start_resolution(dst, current_time);
                            // Send NS via solicited-node multicast
                            let sn_mcast = dst.solicited_node();
                            log::debug!(
                                "IPv6: NDP resolution started for {}, packet queued ({} pending)",
                                dst,
                                self.ndp_pending_queue.packets.len()
                            );

                            // We need to send the NS message — use the link-local address as src
                            let our_ll = ndp.our_link_local;
                            // Send NS via the regular send path (multicast MAC is resolved directly)
                            self.send_ipv6_icmpv6_raw(&our_ll, &sn_mcast, &ns_msg);
                            return;
                        }
                    }
                }
                None => return,
            }
        };

        let dst_mac = MacAddress::new(dst_mac);

        let mut buffer = [0u8; MAX_PACKET_SIZE];

        // Build Ethernet frame
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame
                .set_destination(dst_mac)
                .set_source(config.mac)
                .set_ether_type(EtherType::Ipv6);

            let eth_payload = frame.payload_mut();

            // Build IPv6 packet
            if let Some(mut ip_packet) = Ipv6PacketMut::new(eth_payload) {
                ip_packet.init_header();
                ip_packet.set_source(src);
                ip_packet.set_destination(dst);
                ip_packet.set_next_header(IpProtocol::Icmpv6);
                ip_packet.set_hop_limit(255); // NDP/ICMPv6 uses 255

                // Copy ICMPv6 payload
                let payload = ip_packet.payload_mut();
                if icmpv6_data.len() <= payload.len() {
                    payload[..icmpv6_data.len()].copy_from_slice(icmpv6_data);
                    ip_packet.finalize(icmpv6_data.len());

                    let total_len = IPV6_HEADER_SIZE + icmpv6_data.len();
                    frame.set_payload_len(total_len);

                    self.transmit(frame.as_bytes());
                }
            }
        }
    }

    pub(crate) fn send_ipv6_icmpv6_on(
        &mut self,
        if_id: super::NetIfId,
        src: &Ipv6Address,
        dst: &Ipv6Address,
        icmpv6_data: &[u8],
    ) {
        let Ok((resolved_if, config, resolved_src)) = self.resolve_ipv6_egress(
            crate::net::types::InterfaceScope::Pinned(if_id),
            None,
            Some(*src),
            *dst,
        ) else {
            self.stats.record_dropped();
            return;
        };
        let current_time = self.current_time.load(Ordering::Relaxed);

        let dst_mac = if dst.is_multicast() {
            MacAddress::new(dst.multicast_mac())
        } else {
            match self.resolve_ndp_for_send(resolved_if, dst, current_time, |pending| {
                pending.enqueue(resolved_src, *dst, icmpv6_data, current_time);
            }) {
                Some(Ok(mac)) => MacAddress::new(mac),
                Some(Err((ns_if_id, our_ll, ns_msg))) => {
                    let sn_mcast = dst.solicited_node();
                    if let Some(ns_if_id) = ns_if_id {
                        self.send_ipv6_icmpv6_raw_on(ns_if_id, &our_ll, &sn_mcast, &ns_msg);
                    } else {
                        self.send_ipv6_icmpv6_raw(&our_ll, &sn_mcast, &ns_msg);
                    }
                    return;
                }
                None => return,
            }
        };

        let mut buffer = [0u8; MAX_PACKET_SIZE];
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame
                .set_destination(dst_mac)
                .set_source(config.mac)
                .set_ether_type(EtherType::Ipv6);

            let eth_payload = frame.payload_mut();
            if let Some(mut ip_packet) = Ipv6PacketMut::new(eth_payload) {
                ip_packet.init_header();
                ip_packet.set_source(&resolved_src);
                ip_packet.set_destination(dst);
                ip_packet.set_next_header(IpProtocol::Icmpv6);
                ip_packet.set_hop_limit(255);

                let payload = ip_packet.payload_mut();
                if icmpv6_data.len() <= payload.len() {
                    payload[..icmpv6_data.len()].copy_from_slice(icmpv6_data);
                    ip_packet.finalize(icmpv6_data.len());

                    let total_len = IPV6_HEADER_SIZE + icmpv6_data.len();
                    frame.set_payload_len(total_len);

                    let _ = self.transmit_on(resolved_if, frame.as_bytes());
                }
            }
        }
    }

    /// Send an IPv6/ICMPv6 packet without NDP resolution (for multicast destinations)
    ///
    /// NDP NS送信など、NDP解決自体の送信パスで再帰を避けるために使用。
    /// 宛先はマルチキャストアドレスのみ想定。
    pub(crate) fn send_ipv6_icmpv6_raw(
        &mut self,
        src: &Ipv6Address,
        dst: &Ipv6Address,
        icmpv6_data: &[u8],
    ) {
        let config = self.config;

        // Multicast MAC resolution (no NDP needed)
        let dst_mac = MacAddress::new(dst.multicast_mac());

        let mut buffer = [0u8; MAX_PACKET_SIZE];

        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame
                .set_destination(dst_mac)
                .set_source(config.mac)
                .set_ether_type(EtherType::Ipv6);

            let eth_payload = frame.payload_mut();

            if let Some(mut ip_packet) = Ipv6PacketMut::new(eth_payload) {
                ip_packet.init_header();
                ip_packet.set_source(src);
                ip_packet.set_destination(dst);
                ip_packet.set_next_header(IpProtocol::Icmpv6);
                ip_packet.set_hop_limit(255);

                let payload = ip_packet.payload_mut();
                if icmpv6_data.len() <= payload.len() {
                    payload[..icmpv6_data.len()].copy_from_slice(icmpv6_data);
                    ip_packet.finalize(icmpv6_data.len());

                    let total_len = IPV6_HEADER_SIZE + icmpv6_data.len();
                    frame.set_payload_len(total_len);

                    self.transmit(frame.as_bytes());
                }
            }
        }
    }

    pub(crate) fn send_ipv6_icmpv6_raw_on(
        &mut self,
        if_id: super::NetIfId,
        src: &Ipv6Address,
        dst: &Ipv6Address,
        icmpv6_data: &[u8],
    ) {
        let config = self.interface_config_or_runtime(if_id).unwrap_or_else(|| self.config());
        let dst_mac = MacAddress::new(dst.multicast_mac());
        let mut buffer = [0u8; MAX_PACKET_SIZE];

        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame
                .set_destination(dst_mac)
                .set_source(config.mac)
                .set_ether_type(EtherType::Ipv6);

            let eth_payload = frame.payload_mut();

            if let Some(mut ip_packet) = Ipv6PacketMut::new(eth_payload) {
                ip_packet.init_header();
                ip_packet.set_source(src);
                ip_packet.set_destination(dst);
                ip_packet.set_next_header(IpProtocol::Icmpv6);
                ip_packet.set_hop_limit(255);

                let payload = ip_packet.payload_mut();
                if icmpv6_data.len() <= payload.len() {
                    payload[..icmpv6_data.len()].copy_from_slice(icmpv6_data);
                    ip_packet.finalize(icmpv6_data.len());

                    let total_len = IPV6_HEADER_SIZE + icmpv6_data.len();
                    frame.set_payload_len(total_len);

                    self.transmit_on(Some(if_id), frame.as_bytes());
                }
            }
        }
    }

    fn resolve_ndp_for_send<F>(
        &mut self,
        if_id: Option<super::NetIfId>,
        dst: &Ipv6Address,
        current_time: u64,
        queue_pending: F,
    ) -> Option<Result<[u8; 6], (Option<super::NetIfId>, Ipv6Address, Vec<u8>)>>
    where
        F: FnOnce(&mut NdpPendingQueue),
    {
        if let Some(if_id) = if_id {
            if self
                .interfaces
                .get(&if_id)
                .and_then(|state| state.ndp.as_ref())
                .is_some()
            {
                let resolution = {
                    let state = self.interfaces.get_mut(&if_id).unwrap();
                    if let Some(mac) = state.ndp.as_ref().and_then(|ndp| ndp.resolve(dst)) {
                        Ok(mac)
                    } else {
                        queue_pending(&mut state.ndp_pending_queue);
                        let ndp = state.ndp.as_mut().unwrap();
                        let ns_msg = ndp.start_resolution(dst, current_time);
                        Err((Some(if_id), ndp.our_link_local, ns_msg))
                    }
                };
                return Some(resolution);
            }
        }

        if let Some(mac) = self.ndp.as_ref().and_then(|ndp| ndp.resolve(dst)) {
            return Some(Ok(mac));
        }

        queue_pending(&mut self.ndp_pending_queue);
        let ndp = self.ndp.as_mut()?;
        let ns_msg = ndp.start_resolution(dst, current_time);
        Some(Err((None, ndp.our_link_local, ns_msg)))
    }

    fn send_udp_v6_raw_scoped_with_ttl(
        &mut self,
        scope: crate::net::types::InterfaceScope,
        src_port: u16,
        src_ip: Ipv6Address,
        dst: Ipv6Address,
        dst_port: u16,
        data: &[u8],
        ttl: u8,
    ) -> bool {
        let Ok((if_id, config, resolved_src)) =
            self.resolve_ipv6_egress(scope, None, Some(src_ip), dst)
        else {
            self.stats.record_dropped();
            return false;
        };

        if !crate::net::security::firewall::check_egress(
            crate::net::security::firewall::IpAddress::V6(resolved_src.octets()),
            crate::net::security::firewall::IpAddress::V6(dst.octets()),
            17,
            src_port,
            dst_port,
            0,
        ) {
            self.stats.record_dropped();
            return false;
        }

        let current_time = self.current_time.load(Ordering::Relaxed);
        let dst_mac = if dst.is_multicast() {
            MacAddress::new(dst.multicast_mac())
        } else {
            match self.resolve_ndp_for_send(if_id, &dst, current_time, |pending| {
                pending.enqueue_udp(
                    resolved_src,
                    dst,
                    src_port,
                    dst_port,
                    ttl,
                    data,
                    current_time,
                );
            }) {
                Some(Ok(mac)) => MacAddress::new(mac),
                Some(Err((ns_if_id, our_ll, ns_msg))) => {
                    let sn_mcast = dst.solicited_node();
                    if let Some(ns_if_id) = ns_if_id {
                        self.send_ipv6_icmpv6_raw_on(ns_if_id, &our_ll, &sn_mcast, &ns_msg);
                    } else {
                        self.send_ipv6_icmpv6_raw(&our_ll, &sn_mcast, &ns_msg);
                    }
                    return false;
                }
                None => return false,
            }
        };

        let mut buffer = [0u8; MAX_PACKET_SIZE];
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame
                .set_destination(dst_mac)
                .set_source(config.mac)
                .set_ether_type(EtherType::Ipv6);

            let eth_payload = frame.payload_mut();
            if let Some(mut ip_packet) = Ipv6PacketMut::new(eth_payload) {
                ip_packet.init_header();
                ip_packet.set_source(&resolved_src);
                ip_packet.set_destination(&dst);
                ip_packet.set_next_header(IpProtocol::Udp);
                ip_packet.set_hop_limit(ttl);

                let payload_buf = ip_packet.payload_mut();
                if payload_buf.len() < 8 + data.len() {
                    return false;
                }

                payload_buf[0..2].copy_from_slice(&src_port.to_be_bytes());
                payload_buf[2..4].copy_from_slice(&dst_port.to_be_bytes());
                let udp_len = (8 + data.len()) as u16;
                payload_buf[4..6].copy_from_slice(&udp_len.to_be_bytes());
                payload_buf[6..8].copy_from_slice(&0u16.to_be_bytes());
                payload_buf[8..8 + data.len()].copy_from_slice(data);

                let pseudo = crate::net::l3::ipv6::ipv6_pseudo_header_checksum(
                    &resolved_src,
                    &dst,
                    IpProtocol::Udp,
                    udp_len as u32,
                );
                let checksum =
                    crate::net::l3::ipv4::data_checksum(&payload_buf[..udp_len as usize], pseudo);
                let final_checksum = if checksum == 0 { 0xFFFF } else { checksum };
                payload_buf[6..8].copy_from_slice(&final_checksum.to_be_bytes());

                ip_packet.finalize(udp_len as usize);
                let total_len = IPV6_HEADER_SIZE + udp_len as usize;
                frame.set_payload_len(total_len);

                return self.transmit_on(if_id, frame.as_bytes());
            }
        }

        false
    }

    /// Send a UDP/IPv6 datagram (with NDP resolution)
    pub fn send_udp_v6_raw(
        &mut self,
        src_port: u16,
        src_ip: Ipv6Address,
        dst: Ipv6Address,
        dst_port: u16,
        data: &[u8],
    ) -> bool {
        self.send_udp_v6_raw_with_ttl(src_port, src_ip, dst, dst_port, data, 64)
    }

    /// Send a UDP/IPv6 datagram with explicit hop limit (TTL)
    pub fn send_udp_v6_raw_with_ttl(
        &mut self,
        src_port: u16,
        src_ip: Ipv6Address,
        dst: Ipv6Address,
        dst_port: u16,
        data: &[u8],
        ttl: u8,
    ) -> bool {
        self.send_udp_v6_raw_scoped_with_ttl(
            crate::net::types::InterfaceScope::Any,
            src_port,
            src_ip,
            dst,
            dst_port,
            data,
            ttl,
        )
    }

    /// Transmit a UDP datagram on a given interface (portions of the stack still
    /// assume a single global configuration, so the interface ID is currently
    /// ignored).  This shim exists to exercise the new transmit callback
    /// signature from higher layers.
    pub fn send_udp_raw_on(
        &mut self,
        if_id: super::NetIfId,
        src_port: u16,
        dst: Ipv4Address,
        dst_port: u16,
        data: &[u8],
    ) -> bool {
        self.send_udp_raw_on_auto_ttl(if_id, src_port, dst, dst_port, data, 64)
    }

    pub fn send_udp_raw_on_auto_ttl(
        &mut self,
        if_id: super::NetIfId,
        src_port: u16,
        dst: Ipv4Address,
        dst_port: u16,
        data: &[u8],
        ttl: u8,
    ) -> bool {
        let Ok((resolved_if, config, src_ip)) = self.resolve_ipv4_egress(
            crate::net::types::InterfaceScope::Pinned(if_id),
            None,
            None,
            dst,
        ) else {
            self.stats.record_dropped();
            return false;
        };
        self.send_udp_raw_with_config_and_if_ttl(
            resolved_if,
            &config,
            src_ip,
            src_port,
            dst,
            dst_port,
            data,
            ttl,
        )
    }

    /// UDP transmit helper with explicit source IPv4 and TTL.
    /// Interface selection is currently ignored (transitional multi-NIC shim).
    pub fn send_udp_raw_on_with_src_ttl(
        &mut self,
        if_id: super::NetIfId,
        src_ip: Ipv4Address,
        src_port: u16,
        dst: Ipv4Address,
        dst_port: u16,
        data: &[u8],
        ttl: u8,
    ) -> bool {
        let Ok((resolved_if, config, resolved_src)) = self.resolve_ipv4_egress(
            crate::net::types::InterfaceScope::Pinned(if_id),
            None,
            Some(src_ip),
            dst,
        ) else {
            self.stats.record_dropped();
            return false;
        };
        self.send_udp_raw_with_config_and_if_ttl(
            resolved_if,
            &config,
            resolved_src,
            src_port,
            dst,
            dst_port,
            data,
            ttl,
        )
    }

    /// Transmit an IPv6 UDP datagram on a specific interface (ignored for now)
    pub fn send_udp_v6_raw_on(
        &mut self,
        if_id: super::NetIfId,
        src_port: u16,
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        dst_port: u16,
        data: &[u8],
    ) -> bool {
        self.send_udp_v6_raw_on_with_ttl(if_id, src_port, src_ip, dst_ip, dst_port, data, 64)
    }

    /// Transmit an IPv6 UDP datagram on a specific interface with explicit TTL
    pub fn send_udp_v6_raw_on_with_ttl(
        &mut self,
        if_id: super::NetIfId,
        src_port: u16,
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        dst_port: u16,
        data: &[u8],
        ttl: u8,
    ) -> bool {
        self.send_udp_v6_raw_scoped_with_ttl(
            crate::net::types::InterfaceScope::Pinned(if_id),
            src_port,
            src_ip,
            dst_ip,
            dst_port,
            data,
            ttl,
        )
    }

    fn send_tcp_v6_raw_scoped(
        &mut self,
        scope: crate::net::types::InterfaceScope,
        src_ip: Ipv6Address,
        dst: Ipv6Address,
        tcp_segment: &[u8],
    ) -> bool {
        let Ok((if_id, config, resolved_src)) =
            self.resolve_ipv6_egress(scope, None, Some(src_ip), dst)
        else {
            self.stats.record_dropped();
            return false;
        };
        // ── ファイアウォール Egress チェック (IPv6) ──
        if tcp_segment.len() >= 4 {
            let src_port = u16::from_be_bytes([tcp_segment[0], tcp_segment[1]]);
            let dst_port = u16::from_be_bytes([tcp_segment[2], tcp_segment[3]]);
            let tcp_flags = if tcp_segment.len() >= 14 {
                tcp_segment[13]
            } else {
                0
            };
            // Security Fix: Use full IPv6 addresses for firewall check
            if !crate::net::security::firewall::check_egress(
                crate::net::security::firewall::IpAddress::V6(resolved_src.octets()),
                crate::net::security::firewall::IpAddress::V6(dst.octets()),
                6, // TCP
                src_port,
                dst_port,
                tcp_flags,
            ) {
                self.stats.record_dropped();
                return false;
            }
        }

        let current_time = self.current_time.load(Ordering::Relaxed);

        // Resolve destination MAC (multicast -> multicast MAC, otherwise via NDP)
        let dst_mac = if dst.is_multicast() {
            MacAddress::new(dst.multicast_mac())
        } else {
            match self.resolve_ndp_for_send(if_id, &dst, current_time, |pending| {
                pending.enqueue_tcp(resolved_src, dst, tcp_segment, current_time);
            }) {
                Some(Ok(mac)) => MacAddress::new(mac),
                Some(Err((ns_if_id, our_ll, ns_msg))) => {
                    let sn_mcast = dst.solicited_node();
                    if let Some(ns_if_id) = ns_if_id {
                        self.send_ipv6_icmpv6_raw_on(ns_if_id, &our_ll, &sn_mcast, &ns_msg);
                    } else {
                        self.send_ipv6_icmpv6_raw(&our_ll, &sn_mcast, &ns_msg);
                    }
                    return false;
                }
                None => return false,
            }
        };

        let mut buffer = [0u8; MAX_PACKET_SIZE];
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame
                .set_destination(dst_mac)
                .set_source(config.mac)
                .set_ether_type(EtherType::Ipv6);

            let eth_payload = frame.payload_mut();
            if let Some(mut ip_packet) = Ipv6PacketMut::new(eth_payload) {
                ip_packet.init_header();
                ip_packet.set_source(&resolved_src);
                ip_packet.set_destination(&dst);
                ip_packet.set_next_header(IpProtocol::Tcp);
                ip_packet.set_hop_limit(64);

                let payload_buf = ip_packet.payload_mut();
                if payload_buf.len() < tcp_segment.len() {
                    return false;
                }

                payload_buf[..tcp_segment.len()].copy_from_slice(tcp_segment);
                ip_packet.finalize(tcp_segment.len());

                let total_len = IPV6_HEADER_SIZE + tcp_segment.len();
                frame.set_payload_len(total_len);

                return self.transmit_on(if_id, frame.as_bytes());
            }
        }

        false
    }

    /// Send a TCP segment over IPv6 (with NDP resolution)
    pub fn send_tcp_v6_raw(
        &mut self,
        src_ip: Ipv6Address,
        dst: Ipv6Address,
        tcp_segment: &[u8],
    ) -> bool {
        self.send_tcp_v6_raw_scoped(crate::net::types::InterfaceScope::Any, src_ip, dst, tcp_segment)
    }

    pub fn send_tcp_v6_raw_on(
        &mut self,
        if_id: super::NetIfId,
        src_ip: Ipv6Address,
        dst: Ipv6Address,
        tcp_segment: &[u8],
    ) -> bool {
        self.send_tcp_v6_raw_scoped(
            crate::net::types::InterfaceScope::Pinned(if_id),
            src_ip,
            dst,
            tcp_segment,
        )
    }

    /// Drain pending packets for a resolved neighbor
    ///
    /// NDP Neighbor Advertisementを受信してキャッシュが更新された際に呼び出す。
    /// 指定アドレス宛の保留パケットを全て送信する。
    fn drain_ndp_pending_queue(
        &mut self,
        if_id: Option<super::NetIfId>,
        resolved_ip: &Ipv6Address,
        pending: Vec<PendingIpv6Packet>,
    ) {
        if pending.is_empty() {
            return;
        }

        log::debug!(
            "NDP: Draining {} pending packets for {} on {:?}",
            pending.len(),
            resolved_ip,
            if_id
        );

        for pkt in pending {
            match pkt.payload {
                PendingIpv6Payload::Icmpv6(data) => {
                    if let Some(if_id) = if_id {
                        self.send_ipv6_icmpv6_on(if_id, &pkt.src, &pkt.dst, &data);
                    } else {
                        self.send_ipv6_icmpv6(&pkt.src, &pkt.dst, &data);
                    }
                }
                PendingIpv6Payload::Udp {
                    src_port,
                    dst_port,
                    hop_limit,
                    data,
                } => {
                    if let Some(if_id) = if_id {
                        let _ = self.send_udp_v6_raw_on_with_ttl(
                            if_id, src_port, pkt.src, pkt.dst, dst_port, &data, hop_limit,
                        );
                    } else {
                        let _ = self.send_udp_v6_raw_with_ttl(
                            src_port, pkt.src, pkt.dst, dst_port, &data, hop_limit,
                        );
                    }
                }
                PendingIpv6Payload::Tcp { segment } => {
                    if let Some(if_id) = if_id {
                        let _ = self.send_tcp_v6_raw_on(if_id, pkt.src, pkt.dst, &segment);
                    } else {
                        let _ = self.send_tcp_v6_raw(pkt.src, pkt.dst, &segment);
                    }
                }
            }
        }
    }

    pub(crate) fn drain_ndp_pending(&mut self, resolved_ip: &Ipv6Address) {
        let pending = self.ndp_pending_queue.drain_for(resolved_ip);
        self.drain_ndp_pending_queue(None, resolved_ip, pending);
    }

    pub(crate) fn drain_ndp_pending_on(
        &mut self,
        if_id: super::NetIfId,
        resolved_ip: &Ipv6Address,
    ) {
        let pending = if let Some(state) = self.interfaces.get_mut(&if_id) {
            state.ndp_pending_queue.drain_for(resolved_ip)
        } else {
            Vec::new()
        };

        if pending.is_empty() {
            self.drain_ndp_pending(resolved_ip);
            return;
        }

        self.drain_ndp_pending_queue(Some(if_id), resolved_ip, pending);
    }

    /// Send pending IGMP reports
    pub(crate) fn send_pending_igmp_reports(&mut self) {
        let pending = self.igmp.take_pending_reports();
        let current_time = self.current_time();

        for (group_addr, is_leave) in pending {
            if is_leave {
                self.send_igmp_leave(group_addr, current_time);
            } else {
                self.send_igmp_report(group_addr, current_time);
            }
        }
    }

    /// Send an IGMP Membership Report
    pub(crate) fn send_igmp_report(&mut self, group_addr: Ipv4Address, _current_time: u64) {
        // ── ファイアウォール Egress チェック ──
        if !crate::net::security::firewall::check_egress_v4(
            self.config.ipv4.address.octets(),
            group_addr.octets(),
            2, // IGMP
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
            // Destination is the multicast MAC address for the group
            let dst_mac = multicast_ip_to_mac(group_addr);
            frame
                .set_destination(dst_mac)
                .set_source(config.mac)
                .set_ether_type(EtherType::Ipv4);

            let payload = frame.payload_mut();

            // Build IPv4 header
            // IGMPv2 reports are sent to the group address
            if let Some(mut ip_pkt) = Ipv4PacketMut::new(payload) {
                ip_pkt
                    .set_version(4)
                    .set_ihl(5)
                    .set_dscp(0xc0) // Internetwork Control
                    .set_ttl(1) // IGMP messages use TTL=1
                    .set_protocol(IpProtocol::Igmp)
                    .set_source(config.ipv4.address)
                    .set_destination(group_addr);

                // Build IGMP message into IPv4 payload.
                let ip_payload = ip_pkt.payload_mut();
                if ip_payload.len() >= 8 {
                    if let Some(len) =
                        crate::net::l3::igmp::IgmpProcessor::build_report(group_addr, ip_payload)
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
}
