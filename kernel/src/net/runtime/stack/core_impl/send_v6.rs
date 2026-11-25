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
use crate::net::runtime::device::tx::TxReporter;
use crate::net::runtime::manager::Ipv6Path;
use crate::net::types::{InterfaceScope, NetworkError};
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

        // LOOP_PROOF: mode=bounded; reason=index advances by two through the finite IPv6 transport payload chunk, leaving at most one trailing byte.;
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

    // LOOP_PROOF: mode=condition; reason=Each carry fold reduces the high half of the 32-bit checksum accumulator until it fits in 16 bits.;
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Fragment header fields of one IPv6 fragment.
#[derive(Clone, Copy)]
struct Ipv6FragmentFields {
    offset_units: u16,
    more_fragments: bool,
    identification: u32,
}

/// Ethernet and IPv6 header fields shared by every frame of one packet.
struct Ipv6FrameHeader {
    src_mac: MacAddress,
    dst_mac: MacAddress,
    src: Ipv6Address,
    dst: Ipv6Address,
    hop_limit: u8,
}

impl Ipv6FrameHeader {
    const UNFRAGMENTED_BYTE_LEN: PacketByteCount = match PacketByteCount::new(Self::len(false)) {
        Some(len) => len,
        None => panic!("Ethernet and IPv6 headers are non-empty"),
    };

    const fn len(fragmented: bool) -> usize {
        EthernetHeader::SIZE + IPV6_HEADER_SIZE + if fragmented { 8 } else { 0 }
    }

    /// Write the Ethernet, IPv6 and optional fragment headers of a frame that
    /// carries `payload_len` bytes of `next_header` into `buffer`, which must be
    /// exactly as long as those headers.
    fn write(
        &self,
        buffer: &mut [u8],
        next_header: IpProtocol,
        payload_len: usize,
        fragment: Option<Ipv6FragmentFields>,
    ) -> Result<(), crate::net::types::NetworkError> {
        if buffer.len() != Self::len(fragment.is_some()) {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        }
        let Some(mut frame) = EthernetFrameMut::new(buffer) else {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        };
        frame
            .set_destination(self.dst_mac)
            .set_source(self.src_mac)
            .set_ether_type(EtherType::Ipv6);
        let Some(mut ip_packet) = Ipv6PacketMut::new(frame.payload_mut()) else {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        };
        ip_packet.init_header();
        ip_packet.set_source(&self.src);
        ip_packet.set_destination(&self.dst);
        ip_packet.set_hop_limit(self.hop_limit);
        // The payload follows in other segments, so its length is set
        // directly rather than bounded by this header buffer.
        let ip_payload_len = payload_len + if fragment.is_some() { 8 } else { 0 };
        let Ok(ip_payload_len) = u16::try_from(ip_payload_len) else {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        };
        ip_packet.set_payload_length(ip_payload_len);
        match fragment {
            None => {
                ip_packet.set_next_header(next_header);
            }
            Some(fields) => {
                ip_packet.set_next_header(IpProtocol::Unknown(44));
                let fragment_header = ip_packet.payload_mut();
                if fragment_header.len() < 8 {
                    return Err(crate::net::types::NetworkError::BufferTooSmall);
                }
                fragment_header[0] = u8::from(next_header);
                fragment_header[1] = 0;
                let offset_and_flags =
                    (fields.offset_units << 3) | u16::from(fields.more_fragments);
                fragment_header[2..4].copy_from_slice(&offset_and_flags.to_be_bytes());
                fragment_header[4..8].copy_from_slice(&fields.identification.to_be_bytes());
            }
        }
        Ok(())
    }
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

    /// Send `body` in one IPv6 packet, or in fragments when it exceeds the
    /// path MTU. An owned body takes its headers in place when its headroom
    /// allows; otherwise each frame carries its own generated header packet
    /// followed by a retained window of the body.
    fn send_ipv6_l4_payload_with_pmtu(
        &mut self,
        if_id: super::NetIfId,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        src: Ipv6Address,
        dst: Ipv6Address,
        next_header: IpProtocol,
        hop_limit: u8,
        body: TxBody,
        path_mtu: usize,
    ) -> Result<(), crate::net::types::NetworkError> {
        let Some(unfragmented_payload_limit) = path_mtu.checked_sub(IPV6_HEADER_SIZE) else {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        };
        let total_payload_len = body.total_len();
        let fold = |address: &Ipv6Address| {
            address.octets().chunks_exact(4).fold(0u32, |folded, word| {
                folded ^ u32::from_be_bytes([word[0], word[1], word[2], word[3]])
            })
        };
        let flow_hash = super::l4_flow_hash(fold(&src), fold(&dst), next_header, &body);
        let header = Ipv6FrameHeader {
            src_mac,
            dst_mac,
            src,
            dst,
            hop_limit,
        };

        if total_payload_len <= unfragmented_payload_limit {
            let frame = match body {
                TxBody::Owned(mut payload) => {
                    match payload.try_prepend_in_place(Ipv6FrameHeader::UNFRAGMENTED_BYTE_LEN) {
                        Ok(buffer) => {
                            header.write(buffer, next_header, total_payload_len, None)?;
                            TxFrame::whole(payload)
                        }
                        Err(_) => {
                            let packet = self.build_ipv6_header_packet(
                                &header,
                                next_header,
                                total_payload_len,
                                None,
                            )?;
                            TxFrame::with_header(packet, TxBody::Owned(payload))
                        }
                    }
                }
                retained @ TxBody::Retained(_) => {
                    let packet = self.build_ipv6_header_packet(
                        &header,
                        next_header,
                        total_payload_len,
                        None,
                    )?;
                    TxFrame::with_header(packet, retained)
                }
            };
            return self
                .transmit_frame_on(if_id, frame.in_flow(flow_hash))
                .map_err(|_| crate::net::types::NetworkError::TransmitFailed);
        }

        let Some(fragment_payload_limit) = path_mtu.checked_sub(IPV6_HEADER_SIZE + 8) else {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        };
        let non_last_fragment_len = fragment_payload_limit & !0x7;
        if non_last_fragment_len == 0 {
            return Err(crate::net::types::NetworkError::BufferTooSmall);
        }

        let identification = Self::next_ipv6_fragment_identification();
        let mut remaining_body = Some(body.into_retained());
        let mut offset = 0usize;
        // LOOP_PROOF: mode=condition; reason=Each iteration consumes the remaining body and keeps only a strictly shorter remainder, ending when the last fragment takes it whole.;
        while let Some(retained) = remaining_body.take() {
            let remaining = total_payload_len - offset;
            let more_fragments = remaining > fragment_payload_limit;
            let fragment_data_len = if more_fragments {
                non_last_fragment_len
            } else {
                remaining
            };
            let fragment_offset_units = u16::try_from(offset / 8)
                .map_err(|_| crate::net::types::NetworkError::BufferTooSmall)?;
            let fragment_body = if more_fragments {
                let fragment_len = PacketByteCount::new(fragment_data_len)
                    .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
                match retained.try_take_front(fragment_len) {
                    Ok(RetainedPayloadFront::Prefix { front, remainder }) => {
                        remaining_body = Some(remainder);
                        front
                    }
                    Ok(RetainedPayloadFront::Whole(front)) => front,
                    Err(_) => return Err(crate::net::types::NetworkError::ResourceExhausted),
                }
            } else {
                retained
            };
            let packet = self.build_ipv6_header_packet(
                &header,
                next_header,
                fragment_data_len,
                Some(Ipv6FragmentFields {
                    offset_units: fragment_offset_units,
                    more_fragments,
                    identification,
                }),
            )?;
            // A rejected fragment ends the packet; fragments already admitted
            // are discarded by the receiver's reassembly timeout.
            self.transmit_frame_on(
                if_id,
                TxFrame::with_header(packet, TxBody::Retained(fragment_body)).in_flow(flow_hash),
            )
            .map_err(|_| crate::net::types::NetworkError::TransmitFailed)?;
            offset += fragment_data_len;
        }
        Ok(())
    }

    fn build_ipv6_header_packet(
        &self,
        header: &Ipv6FrameHeader,
        next_header: IpProtocol,
        payload_len: usize,
        fragment: Option<Ipv6FragmentFields>,
    ) -> Result<PacketRef, crate::net::types::NetworkError> {
        let len = Ipv6FrameHeader::len(fragment.is_some());
        let mut packet = self
            .alloc_header_packet(len)
            .ok_or(crate::net::types::NetworkError::BufferTooSmall)?;
        header.write(packet.data_mut(), next_header, payload_len, fragment)?;
        Ok(packet)
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
            self.record_dropped_on(if_id);
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
        let Some(our_addr) = self
            .interface_config(if_id)
            .and_then(|cfg| cfg.ipv6)
            .and_then(|cfg| cfg.addresses.link_local())
        else {
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
            self.record_dropped_on(if_id);
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
        let Ok((path, config, resolved_src)) =
            self.resolve_ipv6_egress(InterfaceScope::Pinned(if_id), Some(*src), *dst)
        else {
            self.record_dropped_on(if_id);
            return;
        };
        if !self.allow_icmpv6_egress(if_id, resolved_src, *dst, &icmpv6_payload) {
            return;
        }
        let dst_mac = match self.resolve_ipv6_neighbor(path) {
            Ok(Some(mac)) => mac,
            Ok(None) => {
                if self
                    .defer_ipv6_packet(
                        path,
                        resolved_src,
                        *dst,
                        PendingIpv6Payload::Icmpv6(icmpv6_payload),
                    )
                    .is_err()
                {
                    self.record_dropped_on(if_id);
                }
                return;
            }
            Err(_) => {
                self.record_dropped_on(if_id);
                return;
            }
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
                        self.record_dropped_on(if_id);
                        return;
                    };
                    let _ = self.transmit_frame_on(if_id, TxFrame::whole(payload));
                }
            }
        }
    }

    fn allow_icmpv6_egress(
        &self,
        if_id: super::NetIfId,
        src: Ipv6Address,
        dst: Ipv6Address,
        payload: &PacketPayload,
    ) -> bool {
        let view = crate::net::payload::PacketPayloadView::new(payload);
        let allowed = view.read_array::<2>(0).is_some_and(|[kind, code]| {
            crate::net::security::firewall::check_egress_in(
                self.runtime,
                src.octets(),
                dst.octets(),
                58,
                kind.into(),
                code.into(),
                0,
            )
        });
        if !allowed {
            self.record_dropped_on(if_id);
        }
        allowed
    }

    /// Submit an unfragmented NDP probe directly to a known link-layer destination.
    pub(crate) fn send_ndp_probe(
        &mut self,
        if_id: super::NetIfId,
        src: Ipv6Address,
        dst: Ipv6Address,
        dst_mac: MacAddress,
        payload: PacketPayload,
        completion: Option<TxReporter>,
    ) -> Result<(), NetworkError> {
        if !self.allow_icmpv6_egress(if_id, src, dst, &payload) {
            return Err(NetworkError::PermissionDenied);
        }
        let config = self
            .interface_config_or_runtime(if_id)
            .ok_or(NetworkError::NetworkUnreachable)?;
        let header = Ipv6FrameHeader {
            src_mac: config.mac,
            dst_mac,
            src,
            dst,
            hop_limit: 255,
        };
        let packet =
            self.build_ipv6_header_packet(&header, IpProtocol::Icmpv6, payload.total_len(), None)?;
        let mut frame = TxFrame::with_header(packet, TxBody::Owned(payload));
        if let Some(completion) = completion {
            frame = frame.observe_completion(completion);
        }
        self.transmit_frame_on(if_id, frame)
            .map_err(|_| NetworkError::TransmitFailed)
    }

    /// Resolve an already selected next hop without taking ownership of a packet.
    pub(crate) fn resolve_ipv6_neighbor(
        &mut self,
        path: Ipv6Path,
    ) -> Result<Option<MacAddress>, NetworkError> {
        let Ipv6Path { if_id, next_hop } = path;
        if next_hop.is_multicast() {
            return Ok(Some(MacAddress::new(next_hop.multicast_mac())));
        }
        let current_time = self.current_time();
        let ndp = self
            .interfaces
            .get_mut(&if_id)
            .and_then(|state| state.ndp.as_mut())
            .ok_or(NetworkError::NetworkUnreachable)?;
        if let Some(mac) = ndp.resolve(&next_hop) {
            return Ok(Some(MacAddress::new(mac)));
        }
        let ns = ndp
            .start_resolution(&next_hop, current_time)
            .ok_or(NetworkError::ResourceExhausted)?;
        let source = ndp.link_local().ok_or(NetworkError::InvalidAddress)?;
        let dst = next_hop.solicited_node();
        self.send_ndp_probe(
            if_id,
            source,
            dst,
            MacAddress::new(dst.multicast_mac()),
            ns,
            None,
        )?;
        Ok(None)
    }

    fn defer_ipv6_packet(
        &mut self,
        path: Ipv6Path,
        src: Ipv6Address,
        dst: Ipv6Address,
        payload: PendingIpv6Payload,
    ) -> Result<(), NetworkError> {
        let now = self.current_time();
        let state = self
            .interfaces
            .get_mut(&path.if_id)
            .ok_or(NetworkError::NetworkUnreachable)?;
        state
            .ndp_pending_queue
            .try_enqueue(path.next_hop, src, dst, payload, now)
    }

    /// Accept a UDP datagram for transmission on a valid IPv6 path.
    ///
    /// # Errors
    /// A route, source, policy, length, or resource rejection happens before
    /// admission to the neighbor queue. A successful queue admission transfers
    /// ownership to the stack until resolution completes or the entry expires.
    pub fn send_udp_v6_payload(
        &mut self,
        scope: InterfaceScope,
        src_ip: Ipv6Address,
        dst: Ipv6Address,
        ports: crate::net::l4::udp::UdpPorts,
        data: PacketPayload,
        ttl: u8,
    ) -> Result<(), crate::net::types::NetworkError> {
        let data_total_len = data.total_len();
        let (path, config, resolved_src) = self.resolve_ipv6_egress(scope, Some(src_ip), dst)?;
        let if_id = path.if_id;
        let total_len_u16 = data_total_len
            .checked_add(8)
            .and_then(|len| u16::try_from(len).ok())
            .ok_or(NetworkError::BufferTooSmall)?;

        if !crate::net::security::firewall::check_egress_in(
            self.runtime,
            crate::net::security::firewall::IpAddress::V6(resolved_src.octets()),
            crate::net::security::firewall::IpAddress::V6(dst.octets()),
            17,
            ports.source(),
            ports.destination(),
            0,
        ) {
            self.record_dropped_on(if_id);
            return Err(crate::net::types::NetworkError::PermissionDenied);
        }

        let current_time = self.current_time();
        let Some(dst_mac) = self.resolve_ipv6_neighbor(path)? else {
            return self.defer_ipv6_packet(
                path,
                resolved_src,
                dst,
                PendingIpv6Payload::Udp {
                    src_port: ports.source(),
                    dst_port: ports.destination(),
                    hop_limit: ttl,
                    data,
                },
            );
        };

        let mut header_packet = crate::net::payload::alloc_packet_with_headroom_in(
            self.runtime,
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
        let payload = data;
        let mut udp_payload = udp_payload
            .try_append(payload)
            .map_err(|_| crate::net::types::NetworkError::BufferTooSmall)?;
        let pseudo = crate::net::l3::ipv6::ipv6_pseudo_header_checksum(
            &resolved_src,
            &dst,
            IpProtocol::Udp,
            u32::from(total_len_u16),
        );
        let checksum = payload_checksum(
            &crate::net::payload::PacketPayloadView::new(&udp_payload),
            pseudo,
        );
        let final_checksum = if checksum == 0 { 0xFFFF } else { checksum };
        if let Some(first) = udp_payload.chunks_mut().next() {
            first[6..8].copy_from_slice(&final_checksum.to_be_bytes());
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
            TxBody::Owned(udp_payload),
            path_mtu,
        )
    }

    pub(crate) fn send_tcp_v6_payload(
        &mut self,
        scope: InterfaceScope,
        src_ip: Ipv6Address,
        dst: Ipv6Address,
        tcp_segment: TxBody,
    ) -> Result<(), crate::net::types::NetworkError> {
        let tcp_segment_view = PacketPayloadView::new(tcp_segment.payload());
        let (path, config, resolved_src) = self.resolve_ipv6_egress(scope, Some(src_ip), dst)?;
        let if_id = path.if_id;
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
            self.record_dropped_on(if_id);
            return Err(crate::net::types::NetworkError::PermissionDenied);
        }

        let current_time = self.current_time.load(Ordering::Relaxed);
        let Some(dst_mac) = self.resolve_ipv6_neighbor(path)? else {
            return self.defer_ipv6_packet(
                path,
                resolved_src,
                dst,
                PendingIpv6Payload::Tcp {
                    segment: tcp_segment,
                },
            );
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
            tcp_segment,
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
                    let _ = self.send_udp_v6_payload(
                        InterfaceScope::Pinned(if_id),
                        pkt.src,
                        pkt.dst,
                        crate::net::l4::udp::UdpPorts::new(src_port, dst_port),
                        data,
                        hop_limit,
                    );
                }
                PendingIpv6Payload::Tcp { segment } => {
                    let _ = self.send_tcp_v6_payload(
                        InterfaceScope::Pinned(if_id),
                        pkt.src,
                        pkt.dst,
                        segment,
                    );
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
        if let Some(state) = self.interfaces.get_mut(&if_id)
            && let Some(ref mut ndp) = state.ndp
        {
            ndp.cache_mut().update_reachable(ip, mac, current_time);
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
                if ip_payload.len() >= 8
                    && let Some(len) =
                        crate::net::l3::igmp::IgmpProcessor::build_report(group_addr, ip_payload)
                {
                    let total_len = (20 + len) as u16;
                    ip_pkt.set_total_length(total_len).update_checksum();
                    frame.set_payload_len(total_len as usize);
                    let frame_len = frame.as_bytes().len();
                    drop(frame);
                    if set_packet_visible_len(&mut packet, frame_len).is_ok()
                        && let Ok(payload) =
                            kernel_api::resource::net::PacketPayload::try_single(packet)
                    {
                        let _ = self.transmit_frame_on(if_id, TxFrame::whole(payload));
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
                    if set_packet_visible_len(&mut packet, frame_len).is_ok()
                        && let Ok(payload) =
                            kernel_api::resource::net::PacketPayload::try_single(packet)
                    {
                        let _ = self.transmit_frame_on(if_id, TxFrame::whole(payload));
                    }
                }
            }
        }
    }
}
