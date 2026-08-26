// ============================================================================
// kernel/src/net/runtime/stack/core_impl/send_v6.rs - ランタイム / スタック / コア実装 / IPv6送信処理
// ============================================================================

// =============================================================================
// kernel/src/net/runtime/stack/core_impl/send_v6.rs Send Path — IPv6 / ICMPv6 / NDP outgoing packet construction & transmission
//
// Split from core_impl/mod.rs for clarity.  Contains all methods that build
// and send outgoing IPv6 packets: ICMPv6, UDP-over-IPv6, TCP-over-IPv6,
// NDP pending-queue draining, and IGMP reporting.
// =============================================================================

use super::*;
use core::sync::atomic::AtomicU32;

fn set_packet_visible_len(
    packet: &mut PacketRef,
    len: usize,
) -> Result<(), crate::net::types::NetworkError> {
    let len = PacketByteCount::new(len).ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
    packet
        .try_resize(len.get())
        .map_err(|_| crate::net::types::NetworkError::BufferTooSmall)
}

fn payload_checksum(view: &crate::net::payload::PacketPayloadView<'_>, initial: u32) -> u16 {
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
    fn next_ipv6_fragment_identification() -> u32 {
        static IPV6_FRAGMENT_ID_COUNTER: AtomicU32 = AtomicU32::new(1);
        IPV6_FRAGMENT_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    fn effective_ipv6_pmtu(
        &mut self,
        if_id: super::NetIfId,
        dst: &Ipv6Address,
        current_time: u64,
    ) -> usize {
        let pmtu = self
            .interfaces
            .get_mut(&if_id)
            .map(|state| state.ipv6_pmtu_cache.get(dst, current_time))
            .unwrap_or(crate::net::runtime::stack::MTU as u32);
        pmtu.max(crate::net::l3::ipv6::Ipv6PmtuEntry::MIN_MTU)
            .min(crate::net::runtime::stack::MTU as u32) as usize
    }

    fn send_ipv6_l4_payload_with_pmtu(
        &mut self,
        if_id: super::NetIfId,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        src: Ipv6Address,
        dst: Ipv6Address,
        next_header: IpProtocol,
        hop_limit: u8,
        payload: kernel_api::resource::net::PacketPayload,
        path_mtu: usize,
    ) -> Result<(), crate::net::types::NetworkError> {
        let payload_view = crate::net::payload::PacketPayloadView::new(&payload);
        let Some(unfragmented_payload_limit) = path_mtu.checked_sub(IPV6_HEADER_SIZE) else {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        };

        if payload_view.total_len() <= unfragmented_payload_limit {
            let header_len = EthernetHeader::SIZE + IPV6_HEADER_SIZE;
            let mut packet = self
                .alloc_ethernet_frame_packet(header_len)
                .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
            set_packet_visible_len(&mut packet, header_len)?;
            let Some(mut frame) = EthernetFrameMut::new(packet.data_mut()) else {
                return Err(crate::net::types::NetworkError::BufferTooSmall);
            };
            frame
                .set_destination(dst_mac)
                .set_source(src_mac)
                .set_ether_type(EtherType::Ipv6);

            let eth_payload = frame.payload_mut();
            let Some(mut ip_packet) = Ipv6PacketMut::new(eth_payload) else {
                return Err(crate::net::types::NetworkError::BufferTooSmall);
            };
            ip_packet.init_header();
            ip_packet.set_source(&src);
            ip_packet.set_destination(&dst);
            ip_packet.set_next_header(next_header);
            ip_packet.set_hop_limit(hop_limit);
            ip_packet.finalize(payload_view.total_len());
            frame.set_payload_len(IPV6_HEADER_SIZE);
            let frame_len = frame.as_bytes().len();
            drop(frame);
            set_packet_visible_len(&mut packet, frame_len)?;

            let frame_payload = kernel_api::resource::net::PacketPayload::try_single(packet)
                .map_err(|_| crate::net::types::NetworkError::BufferTooSmall)?;
            let frame_payload = frame_payload
                .try_append(payload)
                .map_err(|_| crate::net::types::NetworkError::BufferTooSmall)?;
            if self.transmit_packet_on(if_id, frame_payload).is_ok() {
                return Ok(());
            }
            return Err(crate::net::types::NetworkError::TransmitFailed);
        }

        let Some(fragment_payload_limit) = path_mtu.checked_sub(IPV6_HEADER_SIZE + 8) else {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        };
        let non_last_fragment_len = fragment_payload_limit & !0x7;
        if non_last_fragment_len == 0 {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        }

        let identification = Self::next_ipv6_fragment_identification();
        let total_payload_len = payload_view.total_len();
        let owners = TxPayloadOwners::from_payload(payload)
            .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
        let mut fragments = Vec::new();
        let mut offset = 0usize;

        while offset < total_payload_len {
            let remaining = total_payload_len - offset;
            let fragment_data_len = if remaining > fragment_payload_limit {
                non_last_fragment_len.min(remaining)
            } else {
                remaining
            };
            let more_fragments = offset + fragment_data_len < total_payload_len;
            if more_fragments && (fragment_data_len % 8 != 0) {
                return Err(crate::net::types::NetworkError::BufferTooSmall);
            }

            let fragment_payload_len = 8 + fragment_data_len;
            let header_len = EthernetHeader::SIZE + IPV6_HEADER_SIZE + 8;
            let mut packet = self
                .alloc_ethernet_frame_packet(header_len)
                .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
            set_packet_visible_len(&mut packet, header_len)?;
            let Some(mut frame) = EthernetFrameMut::new(packet.data_mut()) else {
                return Err(crate::net::types::NetworkError::BufferTooSmall);
            };
            frame
                .set_destination(dst_mac)
                .set_source(src_mac)
                .set_ether_type(EtherType::Ipv6);

            let eth_payload = frame.payload_mut();
            let Some(mut ip_packet) = Ipv6PacketMut::new(eth_payload) else {
                return Err(crate::net::types::NetworkError::BufferTooSmall);
            };
            ip_packet.init_header();
            ip_packet.set_source(&src);
            ip_packet.set_destination(&dst);
            ip_packet.set_next_header(IpProtocol::Unknown(44));
            ip_packet.set_hop_limit(hop_limit);

            let payload_buf = ip_packet.payload_mut();
            if payload_buf.len() < 8 {
                return Err(crate::net::types::NetworkError::BufferTooSmall);
            }

            payload_buf[0] = u8::from(next_header);
            payload_buf[1] = 0;
            let fragment_offset_units = u16::try_from(offset / 8)
                .map_err(|_| crate::net::types::NetworkError::BufferTooSmall)?;
            let offset_and_flags = (fragment_offset_units << 3) | u16::from(more_fragments);
            payload_buf[2..4].copy_from_slice(&offset_and_flags.to_be_bytes());
            payload_buf[4..8].copy_from_slice(&identification.to_be_bytes());
            ip_packet.finalize(fragment_payload_len);

            frame.set_payload_len(IPV6_HEADER_SIZE + 8);
            let frame_len = frame.as_bytes().len();
            drop(frame);
            set_packet_visible_len(&mut packet, frame_len)?;

            let fragment_len = PacketByteCount::new(fragment_data_len)
                .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
            let payload_bounds = TxPayloadWindowBounds::checked(&owners, offset, fragment_len)
                .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
            let frame_len = packet
                .len()
                .checked_add(fragment_data_len)
                .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
            let lease =
                TxPayloadLease::from_header_and_owner_window(packet, &owners, payload_bounds)
                    .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
            fragments.push(FragmentTxPacket { lease, frame_len });

            offset += fragment_data_len;
        }

        self.transmit_fragment_packets_on(if_id, owners, fragments)
    }

    pub(crate) fn send_icmpv6_echo_reply_with_src_on(
        &mut self,
        if_id: super::NetIfId,
        src: Ipv6Address,
        dst: Ipv6Address,
        identifier: u16,
        sequence: u16,
        echo_data: kernel_api::resource::net::PacketPayload,
    ) {
        let Some(icmpv6_msg) =
            Icmpv6Builder::build_echo_reply(&src, &dst, identifier, sequence, echo_data)
        else {
            self.stats().record_dropped();
            return;
        };

        self.send_ipv6_icmpv6_payload_on(if_id, &src, &dst, icmpv6_msg);

        log::info!(
            "ICMPv6: Echo Reply sent from {} to {} on {:?} id={} seq={}",
            src,
            dst,
            if_id,
            identifier,
            sequence
        );
    }

    /// Send an ICMPv6 Time Exceeded error (RFC 4443).
    pub fn send_icmpv6_time_exceeded_on(
        &mut self,
        if_id: super::NetIfId,
        dst_v6: Ipv6Address,
        code: u8,
        original_packet: PacketPayload,
    ) -> bool {
        let Some(our_addr) = self.interfaces.get(&if_id).and_then(|state| {
            state
                .ipv6
                .as_ref()
                .map(|ipv6_proc| ipv6_proc.config().link_local)
        }) else {
            return false;
        };
        {
            let original_packet_view =
                crate::net::payload::PacketPayloadView::new(&original_packet);
            if !self.should_send_icmp_v6_error(
                &original_packet_view,
                dst_v6,
                Icmpv6Type::TimeExceeded,
                code,
            ) {
                return false;
            }
        }
        let current_time = self.current_time();
        if !self
            .interfaces
            .get(&if_id)
            .and_then(|state| state.icmpv6.as_ref())
            .is_some_and(|icmpv6| icmpv6.check_tx_rate_limit(current_time))
        {
            return false;
        }

        let Some(icmp_msg) = crate::net::l3::icmpv6::Icmpv6Builder::build_time_exceeded(
            &our_addr,
            &dst_v6,
            code,
            original_packet,
        ) else {
            self.stats().record_dropped();
            return false;
        };
        self.send_ipv6_icmpv6_payload_on(if_id, &our_addr, &dst_v6, icmp_msg);
        true
    }

    pub(crate) fn send_ipv6_icmpv6_on(
        &mut self,
        if_id: super::NetIfId,
        src: &Ipv6Address,
        dst: &Ipv6Address,
        icmpv6_data: PacketPayload,
    ) {
        self.send_ipv6_icmpv6_payload_on(if_id, src, dst, icmpv6_data);
    }

    pub(crate) fn send_ipv6_icmpv6_payload_on(
        &mut self,
        if_id: super::NetIfId,
        src: &Ipv6Address,
        dst: &Ipv6Address,
        icmpv6_payload: PacketPayload,
    ) {
        let Ok((config, resolved_src)) = self.resolve_ipv6_egress_on(if_id, Some(*src), *dst)
        else {
            self.stats().record_dropped();
            return;
        };
        let current_time = self.current_time.load(Ordering::Relaxed);
        let mut pending_payload = Some(icmpv6_payload);

        let dst_mac = if dst.is_multicast() {
            MacAddress::new(dst.multicast_mac())
        } else {
            let mut queued = false;
            match self.resolve_ndp_for_send(if_id, dst, current_time, |pending| {
                if let Some(payload) = pending_payload.take() {
                    pending.enqueue(resolved_src, *dst, payload, current_time);
                }
                queued = true;
            }) {
                Some(Ok(mac)) => MacAddress::new(mac),
                Some(Err(_)) if !queued => {
                    self.stats().record_dropped();
                    return;
                }
                Some(Err((ns_if_id, our_ll, ns_msg))) => {
                    let sn_mcast = dst.solicited_node();
                    self.send_ipv6_icmpv6_raw_on_payload(ns_if_id, &our_ll, &sn_mcast, ns_msg);
                    return;
                }
                None => return,
            }
        };

        let Some(icmpv6_payload) = pending_payload else {
            return;
        };
        let payload_len = icmpv6_payload.total_len();

        let mut packet =
            match self.alloc_ethernet_frame_packet(EthernetHeader::SIZE + IPV6_HEADER_SIZE) {
                Some(packet) => packet,
                None => return,
            };
        if let Some(mut frame) = EthernetFrameMut::new(packet.data_mut()) {
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
                ip_packet.finalize(payload_len);

                frame.set_payload_len(IPV6_HEADER_SIZE);
                let frame_len = frame.as_bytes().len();
                drop(frame);
                if set_packet_visible_len(&mut packet, frame_len).is_ok() {
                    let Ok(payload) = icmpv6_payload.try_prepend(packet) else {
                        self.stats().record_dropped();
                        return;
                    };
                    let _ = self.transmit_packet_on(if_id, payload);
                }
            }
        }
    }

    /// Send an IPv6/ICMPv6 packet without NDP resolution (for multicast destinations)
    ///
    /// NDP NS送信など、NDP解決自体の送信パスで再帰を避けるために使用。
    /// 宛先はマルチキャストアドレスのみ想定。
    pub(crate) fn send_ipv6_icmpv6_raw_on(
        &mut self,
        if_id: super::NetIfId,
        src: &Ipv6Address,
        dst: &Ipv6Address,
        icmpv6_data: PacketPayload,
    ) {
        self.send_ipv6_icmpv6_raw_on_payload(if_id, src, dst, icmpv6_data);
    }

    fn send_ipv6_icmpv6_raw_on_payload(
        &mut self,
        if_id: super::NetIfId,
        src: &Ipv6Address,
        dst: &Ipv6Address,
        icmpv6_payload: PacketPayload,
    ) {
        let Some(config) = self.interface_config_or_runtime(if_id) else {
            return;
        };
        let dst_mac = MacAddress::new(dst.multicast_mac());
        let mut packet =
            match self.alloc_ethernet_frame_packet(EthernetHeader::SIZE + IPV6_HEADER_SIZE) {
                Some(packet) => packet,
                None => return,
            };

        if let Some(mut frame) = EthernetFrameMut::new(packet.data_mut()) {
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

                let payload_len = icmpv6_payload.total_len();
                ip_packet.finalize(payload_len);

                frame.set_payload_len(IPV6_HEADER_SIZE);
                let frame_len = frame.as_bytes().len();
                drop(frame);
                if set_packet_visible_len(&mut packet, frame_len).is_ok() {
                    let Ok(payload) = icmpv6_payload.try_prepend(packet) else {
                        self.stats().record_dropped();
                        return;
                    };
                    // This generated control response is best-effort and has
                    // no transport owner that could retry a rejected frame.
                    drop(self.transmit_packet_on(if_id, payload));
                }
            }
        }
    }

    pub(crate) fn resolve_ndp_for_send<F>(
        &mut self,
        if_id: super::NetIfId,
        dst: &Ipv6Address,
        current_time: u64,
        queue_pending: F,
    ) -> Option<Result<[u8; 6], (super::NetIfId, Ipv6Address, PacketPayload)>>
    where
        F: FnOnce(&mut NdpPendingQueue),
    {
        let state = self.interfaces.get_mut(&if_id)?;
        if let Some(mac) = state.ndp.as_ref().and_then(|ndp| ndp.resolve(dst)) {
            return Some(Ok(mac));
        }

        queue_pending(&mut state.ndp_pending_queue);
        let ndp = state.ndp.as_mut()?;
        let ns_msg = ndp.start_resolution(dst, current_time)?;
        Some(Err((if_id, ndp.our_link_local, ns_msg)))
    }

    pub fn send_udp_v6_payload_on_with_ttl(
        &mut self,
        if_id: super::NetIfId,
        src_ip: Ipv6Address,
        dst: Ipv6Address,
        ports: crate::net::l4::udp::UdpPorts,
        data: PacketPayload,
        ttl: u8,
    ) -> Result<(), crate::net::types::NetworkError> {
        let data_total_len = data.total_len();
        let (config, resolved_src) = self
            .resolve_ipv6_egress_on(if_id, Some(src_ip), dst)
            .map_err(|error| {
                self.stats().record_dropped();
                error
            })?;

        if !crate::net::security::firewall::check_egress_in(
            self.runtime,
            crate::net::security::firewall::IpAddress::V6(resolved_src.octets()),
            crate::net::security::firewall::IpAddress::V6(dst.octets()),
            17,
            ports.source(),
            ports.destination(),
            0,
        ) {
            self.stats().record_dropped();
            return Err(crate::net::types::NetworkError::PermissionDenied);
        }

        let current_time = self.current_time.load(Ordering::Relaxed);
        let mut pending_data = Some(data);
        let dst_mac = if dst.is_multicast() {
            MacAddress::new(dst.multicast_mac())
        } else {
            match self.resolve_ndp_for_send(if_id, &dst, current_time, |pending| {
                let payload = pending_data
                    .take()
                    .expect("IPv6 UDP pending payload already moved");
                pending.enqueue_udp(
                    resolved_src,
                    dst,
                    ports.source(),
                    ports.destination(),
                    ttl,
                    payload,
                    current_time,
                );
            }) {
                Some(Ok(mac)) => MacAddress::new(mac),
                Some(Err((ns_if_id, our_ll, ns_msg))) => {
                    let sn_mcast = dst.solicited_node();
                    self.send_ipv6_icmpv6_raw_on(ns_if_id, &our_ll, &sn_mcast, ns_msg);
                    return Err(crate::net::types::NetworkError::ArpResolutionPending);
                }
                None => return Err(crate::net::types::NetworkError::NetworkUnreachable),
            }
        };

        let Some(total_len) = 8usize.checked_add(data_total_len) else {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        };
        let Ok(total_len_u16) = u16::try_from(total_len) else {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        };
        let mut header_packet = crate::net::payload::alloc_packet_with_headroom(
            crate::net::l4::udp::UdpHeader::SIZE,
            kernel_api::resource::net::DEFAULT_PACKET_HEADROOM,
        )
        .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
        set_packet_visible_len(&mut header_packet, crate::net::l4::udp::UdpHeader::SIZE)?;
        let Some(header) =
            crate::util::get_mut_ref::<crate::net::l4::udp::UdpHeader>(header_packet.data_mut(), 0)
        else {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        };
        header.set_src_port(ports.source());
        header.set_dst_port(ports.destination());
        header.set_length(total_len_u16);
        header.set_checksum(0);

        let udp_payload = kernel_api::resource::net::PacketPayload::try_single(header_packet)
            .map_err(|_| crate::net::types::NetworkError::BufferTooSmall)?;
        let payload = pending_data.take().expect("IPv6 UDP payload already moved");
        let mut udp_payload = udp_payload
            .try_append(payload)
            .map_err(|_| crate::net::types::NetworkError::BufferTooSmall)?;
        let pseudo = crate::net::l3::ipv6::ipv6_pseudo_header_checksum(
            &resolved_src,
            &dst,
            IpProtocol::Udp,
            total_len as u32,
        );
        let checksum = payload_checksum(
            &crate::net::payload::PacketPayloadView::new(&udp_payload),
            pseudo,
        );
        let final_checksum = if checksum == 0 { 0xFFFF } else { checksum };
        if let Some(first) = udp_payload.segments_mut().first_mut() {
            first.data_mut()[6..8].copy_from_slice(&final_checksum.to_be_bytes());
        }
        let path_mtu = self.effective_ipv6_pmtu(if_id, &dst, current_time);
        self.send_ipv6_l4_payload_with_pmtu(
            if_id,
            config.mac,
            dst_mac,
            resolved_src,
            dst,
            IpProtocol::Udp,
            ttl,
            udp_payload,
            path_mtu,
        )
    }

    pub fn send_tcp_v6_payload_on(
        &mut self,
        if_id: super::NetIfId,
        src_ip: Ipv6Address,
        dst: Ipv6Address,
        tcp_segment: PacketPayload,
    ) -> Result<(), crate::net::types::NetworkError> {
        let tcp_segment_view = PacketPayloadView::new(&tcp_segment);
        let (config, resolved_src) = self
            .resolve_ipv6_egress_on(if_id, Some(src_ip), dst)
            .map_err(|error| {
                self.stats().record_dropped();
                error
            })?;
        let Some(header) = tcp_segment_view.read_array::<14>(0) else {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        };
        let src_port = u16::from_be_bytes([header[0], header[1]]);
        let dst_port = u16::from_be_bytes([header[2], header[3]]);
        let tcp_flags = header[13];
        if !crate::net::security::firewall::check_egress_in(
            self.runtime,
            crate::net::security::firewall::IpAddress::V6(resolved_src.octets()),
            crate::net::security::firewall::IpAddress::V6(dst.octets()),
            6,
            src_port,
            dst_port,
            tcp_flags,
        ) {
            self.stats().record_dropped();
            return Err(crate::net::types::NetworkError::PermissionDenied);
        }

        let current_time = self.current_time.load(Ordering::Relaxed);
        let mut pending_segment = Some(tcp_segment);

        let dst_mac = if dst.is_multicast() {
            MacAddress::new(dst.multicast_mac())
        } else {
            match self.resolve_ndp_for_send(if_id, &dst, current_time, |pending| {
                let segment = pending_segment
                    .take()
                    .expect("IPv6 TCP pending segment already moved");
                pending.enqueue_tcp(resolved_src, dst, segment, current_time);
            }) {
                Some(Ok(mac)) => MacAddress::new(mac),
                Some(Err((ns_if_id, our_ll, ns_msg))) => {
                    let sn_mcast = dst.solicited_node();
                    self.send_ipv6_icmpv6_raw_on(ns_if_id, &our_ll, &sn_mcast, ns_msg);
                    return Err(crate::net::types::NetworkError::ArpResolutionPending);
                }
                None => return Err(crate::net::types::NetworkError::NetworkUnreachable),
            }
        };

        let path_mtu = self.effective_ipv6_pmtu(if_id, &dst, current_time);
        self.send_ipv6_l4_payload_with_pmtu(
            if_id,
            config.mac,
            dst_mac,
            resolved_src,
            dst,
            IpProtocol::Tcp,
            64,
            pending_segment
                .take()
                .expect("IPv6 TCP segment already moved"),
            path_mtu,
        )
    }

    /// Drain pending packets for a resolved neighbor
    ///
    /// NDP Neighbor Advertisementを受信してキャッシュが更新された際に呼び出す。
    /// 指定アドレス宛の保留パケットを全て送信する。
    fn drain_ndp_pending_queue(
        &mut self,
        if_id: super::NetIfId,
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
                    self.send_ipv6_icmpv6_payload_on(if_id, &pkt.src, &pkt.dst, data);
                }
                PendingIpv6Payload::Udp {
                    src_port,
                    dst_port,
                    hop_limit,
                    data,
                } => {
                    let _ = self.send_udp_v6_payload_on_with_ttl(
                        if_id,
                        pkt.src,
                        pkt.dst,
                        crate::net::l4::udp::UdpPorts::new(src_port, dst_port),
                        data,
                        hop_limit,
                    );
                }
                PendingIpv6Payload::Tcp { segment } => {
                    let _ = self.send_tcp_v6_payload_on(if_id, pkt.src, pkt.dst, segment);
                }
            }
        }
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

        self.drain_ndp_pending_queue(if_id, resolved_ip, pending);
    }

    /// Insert an entry into a specific interface's NDP neighbor cache.
    /// Used by NeighborResolvedV6 broadcast handler for cross-core NDP cache synchronization.
    pub(crate) fn ndp_cache_insert_on(
        &mut self,
        if_id: super::NetIfId,
        ip: &Ipv6Address,
        mac: [u8; 6],
        current_time: u64,
    ) {
        if let Some(state) = self.interfaces.get_mut(&if_id) {
            if let Some(ref mut ndp) = state.ndp {
                ndp.cache_mut().update_reachable(ip, mac, current_time);
            }
        }
    }

    /// Send pending IGMP reports
    pub(crate) fn send_pending_igmp_reports(&mut self) {
        let mut pending_by_interface = Vec::new();
        for (if_id, state) in self.interfaces.iter_mut() {
            let pending = state.igmp.take_pending_report_entries();
            let report_version = state.igmp.report_version();
            if !pending.is_empty() {
                pending_by_interface.push((*if_id, pending, report_version));
            }
        }
        let current_time = self.current_time();

        for (if_id, pending, report_version) in pending_by_interface {
            for entry in pending {
                if report_version == crate::net::l3::igmp::IgmpReportVersion::V3 {
                    self.send_igmp_v3_report_on(if_id, entry.group_addr, entry.kind, current_time);
                } else if entry.kind
                    == crate::net::l3::igmp::PendingIgmpReportKind::LeaveStateChange
                {
                    self.send_igmp_leave_on(if_id, entry.group_addr, current_time);
                } else {
                    self.send_igmp_report_on(if_id, entry.group_addr, current_time);
                }
            }
        }
    }

    pub(crate) fn send_igmp_report_on(
        &mut self,
        if_id: super::NetIfId,
        group_addr: Ipv4Address,
        _current_time: u64,
    ) {
        let Some(config) = self.interface_config_or_runtime(if_id) else {
            return;
        };
        // ── ファイアウォール Egress チェック ──
        if !crate::net::security::firewall::check_egress_in(
            self.runtime,
            config.ipv4.address.octets(),
            group_addr.octets(),
            2, // IGMP
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
                        frame.set_payload_len(total_len as usize);
                        let frame_len = frame.as_bytes().len();
                        drop(frame);
                        if set_packet_visible_len(&mut packet, frame_len).is_ok() {
                            if let Ok(payload) =
                                kernel_api::resource::net::PacketPayload::try_single(packet)
                            {
                                let _ = self.transmit_packet_on(if_id, payload);
                            }
                        }
                    }
                }
            }
        }
    }

    pub(crate) fn send_igmp_v3_report_on(
        &mut self,
        if_id: super::NetIfId,
        group_addr: Ipv4Address,
        kind: crate::net::l3::igmp::PendingIgmpReportKind,
        _current_time: u64,
    ) {
        let dst_group = crate::net::l3::igmp::ALL_ROUTERS_V3_GROUP;
        let Some(config) = self.interface_config_or_runtime(if_id) else {
            return;
        };

        if !crate::net::security::firewall::check_egress_in(
            self.runtime,
            config.ipv4.address.octets(),
            dst_group.octets(),
            2,
            0,
            0,
            0,
        ) {
            if let Some(stats) = self.interface_stats(if_id) {
                stats.record_dropped();
            }
            return;
        }

        let record_type = match kind {
            crate::net::l3::igmp::PendingIgmpReportKind::QueryResponseCurrentState => {
                crate::net::l3::igmp::IgmpV3GroupRecordType::ModeIsExclude
            }
            crate::net::l3::igmp::PendingIgmpReportKind::UnsolicitedJoinStateChange => {
                crate::net::l3::igmp::IgmpV3GroupRecordType::ChangeToExcludeMode
            }
            crate::net::l3::igmp::PendingIgmpReportKind::LeaveStateChange => {
                crate::net::l3::igmp::IgmpV3GroupRecordType::ChangeToIncludeMode
            }
        };

        let mut packet = match self.alloc_ethernet_frame_packet(60) {
            Some(packet) => packet,
            None => return,
        };

        if let Some(mut frame) = EthernetFrameMut::new(packet.data_mut()) {
            let dst_mac = multicast_ip_to_mac(dst_group);
            frame
                .set_destination(dst_mac)
                .set_source(config.mac)
                .set_ether_type(EtherType::Ipv4);

            let payload = frame.payload_mut();
            if let Some(mut ip_pkt) = Ipv4PacketMut::new(payload) {
                ip_pkt
                    .set_version(4)
                    .set_ihl(5)
                    .set_dscp(0xc0)
                    .set_ttl(1)
                    .set_protocol(IpProtocol::Igmp)
                    .set_source(config.ipv4.address)
                    .set_destination(dst_group);

                let ip_payload = ip_pkt.payload_mut();
                if let Some(len) =
                    crate::net::l3::igmp::IgmpProcessor::build_v3_single_record_report(
                        record_type,
                        group_addr,
                        &[],
                        ip_payload,
                    )
                {
                    let total_len = (20 + len) as u16;
                    ip_pkt.set_total_length(total_len).update_checksum();
                    frame.set_payload_len(total_len as usize);
                    let frame_len = frame.as_bytes().len();
                    drop(frame);
                    if set_packet_visible_len(&mut packet, frame_len).is_ok() {
                        if let Ok(payload) =
                            kernel_api::resource::net::PacketPayload::try_single(packet)
                        {
                            let _ = self.transmit_packet_on(if_id, payload);
                        }
                    }
                }
            }
        }
    }
}
