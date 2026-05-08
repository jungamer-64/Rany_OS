// ============================================================================
// kernel/src/net/l4/udp/types.rs - L4 / UDP / 型定義
// ============================================================================

use super::*;
use crate::net::l4::socket::{SocketFamily, find_udp_by_port};

fn resolve_ingress_if_id(if_id: Option<NetIfId>) -> NetIfId {
    if let Some(if_id) = if_id {
        return if_id;
    }
    crate::net::runtime::device::primary_if_in(crate::net::runtime::default_runtime())
        .or_else(|| {
            crate::net::runtime::manager::list_interfaces_in(crate::net::runtime::default_runtime())
                .ok()
                .and_then(|ifaces| ifaces.first().map(|iface| iface.if_id))
        })
        .unwrap_or_default()
}

/// UDP processor for handling UDP packets

pub struct UdpProcessor {
    /// Codec / validation statistics
    stats: UdpStats,
}

/// Result of UDP processing
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum UdpResult {
    /// Delivered to socket
    Delivered,
    /// No socket for this port
    NoEndpoint,
    /// Checksum error
    ChecksumError,
    /// Invalid packet
    Invalid,
}

impl UdpProcessor {
    /// Create a new UDP processor
    pub fn new() -> Self {
        UdpProcessor {
            stats: UdpStats::default(),
        }
    }

    pub fn stats(&self) -> (u64, u64, u64, u64) {
        self.stats.snapshot()
    }

    fn deliver_payload(
        &self,
        if_id: NetIfId,
        src: crate::net::l4::EndpointAddr,
        dst_port: u16,
        ttl: u8,
        payload: PacketPayload,
    ) -> bool {
        let family = if src.is_ipv6() {
            SocketFamily::Ipv6
        } else {
            SocketFamily::Ipv4
        };

        let Some(endpoint) = find_udp_by_port(family, dst_port, Some(if_id)) else {
            self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        };

        if endpoint
            .deliver_udp_payload(if_id, src, ttl, payload)
            .is_ok()
        {
            self.stats.rx_datagrams.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    fn lookup_socket(&self, if_id: NetIfId, family: SocketFamily, dst_port: u16) -> Option<Socket> {
        let endpoint = find_udp_by_port(family, dst_port, Some(if_id));
        if endpoint.is_none() {
            self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
        }
        endpoint
    }

    fn payload_span_checksum(span: crate::net::payload::PayloadSpanRef<'_>, initial: u32) -> u16 {
        let mut sum = initial;
        let mut trailing = None;

        span.for_each_chunk(|chunk| {
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
                sum =
                    sum.saturating_add(u16::from_be_bytes([chunk[index], chunk[index + 1]]) as u32);
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

    pub fn process_window_on(
        &self,
        if_id: Option<NetIfId>,
        packet: PacketPayload,
        offset: usize,
        len: usize,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        ttl: u8,
    ) -> Result<(), (UdpResult, PacketPayload)> {
        let resolved_if_id = resolve_ingress_if_id(if_id);
        self.process_window_impl(resolved_if_id, packet, offset, len, src_ip, dst_ip, ttl)
    }

    fn process_window_impl(
        &self,
        if_id: NetIfId,
        packet: PacketPayload,
        offset: usize,
        len: usize,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        ttl: u8,
    ) -> Result<(), (UdpResult, PacketPayload)> {
        use core::sync::atomic::Ordering;

        let Some(segment) = crate::net::payload::PayloadSpanRef::from_range(&packet, offset, len)
        else {
            return Err((UdpResult::Invalid, packet));
        };
        let Some(header) = segment.read_array::<8>(0) else {
            return Err((UdpResult::Invalid, packet));
        };
        let length = u16::from_be_bytes([header[4], header[5]]) as usize;
        if !(UdpHeader::SIZE..=segment.total_len()).contains(&length)
            || length != segment.total_len()
        {
            return Err((UdpResult::Invalid, packet));
        }

        let checksum = u16::from_be_bytes([header[6], header[7]]);
        if checksum != 0 {
            let pseudo = pseudo_header_checksum(src_ip, dst_ip, IpProtocol::Udp, length as u16);
            let Some(checksum_span) = segment.subspan(0, length) else {
                return Err((UdpResult::Invalid, packet));
            };
            if Self::payload_span_checksum(checksum_span, pseudo) != 0 {
                self.stats.checksum_errors.fetch_add(1, Ordering::Relaxed);
                return Err((UdpResult::ChecksumError, packet));
            }
        }

        let src = crate::net::l4::EndpointAddr::new(
            src_ip.octets(),
            u16::from_be_bytes([header[0], header[1]]),
        );
        let dst_port = u16::from_be_bytes([header[2], header[3]]);
        let family = SocketFamily::Ipv4;
        let Some(endpoint) = self.lookup_socket(if_id, family, dst_port) else {
            return Err((UdpResult::NoEndpoint, packet));
        };

        let Some(udp_payload) = crate::net::payload::move_payload_window_owned(
            packet,
            offset + UdpHeader::SIZE,
            length - UdpHeader::SIZE,
        ) else {
            self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
            return Err((UdpResult::Invalid, PacketPayload::default()));
        };

        if endpoint
            .deliver_udp_payload(if_id, src, ttl, udp_payload)
            .is_ok()
        {
            self.stats.rx_datagrams.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
            Err((UdpResult::Invalid, PacketPayload::default()))
        }
    }

    pub fn process_window_v6_on(
        &self,
        if_id: Option<NetIfId>,
        packet: PacketPayload,
        offset: usize,
        len: usize,
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        ttl: u8,
    ) -> Result<(), (UdpResult, PacketPayload)> {
        let resolved_if_id = resolve_ingress_if_id(if_id);
        self.process_window_v6_impl(resolved_if_id, packet, offset, len, src_ip, dst_ip, ttl)
    }

    fn process_window_v6_impl(
        &self,
        if_id: NetIfId,
        packet: PacketPayload,
        offset: usize,
        len: usize,
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        ttl: u8,
    ) -> Result<(), (UdpResult, PacketPayload)> {
        use core::sync::atomic::Ordering;

        let Some(segment) = crate::net::payload::PayloadSpanRef::from_range(&packet, offset, len)
        else {
            return Err((UdpResult::Invalid, packet));
        };
        let Some(header) = segment.read_array::<8>(0) else {
            return Err((UdpResult::Invalid, packet));
        };
        let length = u16::from_be_bytes([header[4], header[5]]) as usize;
        if !(UdpHeader::SIZE..=segment.total_len()).contains(&length)
            || length != segment.total_len()
        {
            return Err((UdpResult::Invalid, packet));
        }

        let checksum = u16::from_be_bytes([header[6], header[7]]);
        if checksum == 0 {
            self.stats.checksum_errors.fetch_add(1, Ordering::Relaxed);
            return Err((UdpResult::ChecksumError, packet));
        }

        let pseudo = ipv6_pseudo_header_checksum(&src_ip, &dst_ip, IpProtocol::Udp, length as u32);
        let Some(checksum_span) = segment.subspan(0, length) else {
            return Err((UdpResult::Invalid, packet));
        };
        if Self::payload_span_checksum(checksum_span, pseudo) != 0 {
            self.stats.checksum_errors.fetch_add(1, Ordering::Relaxed);
            return Err((UdpResult::ChecksumError, packet));
        }

        let src = crate::net::l4::EndpointAddr::new_v6(
            src_ip.octets(),
            u16::from_be_bytes([header[0], header[1]]),
        );
        let dst_port = u16::from_be_bytes([header[2], header[3]]);
        let family = SocketFamily::Ipv6;
        let Some(endpoint) = self.lookup_socket(if_id, family, dst_port) else {
            return Err((UdpResult::NoEndpoint, packet));
        };

        let Some(udp_payload) = crate::net::payload::move_payload_window_owned(
            packet,
            offset + UdpHeader::SIZE,
            length - UdpHeader::SIZE,
        ) else {
            self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
            return Err((UdpResult::Invalid, PacketPayload::default()));
        };

        if endpoint
            .deliver_udp_payload(if_id, src, ttl, udp_payload)
            .is_ok()
        {
            self.stats.rx_datagrams.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
            Err((UdpResult::Invalid, PacketPayload::default()))
        }
    }

    /// Process an incoming UDP packet (IPv4)
    pub fn process_on(
        &self,
        if_id: Option<NetIfId>,
        data: &[u8],
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        ttl: u8,
    ) -> UdpResult {
        let resolved_if_id = resolve_ingress_if_id(if_id);
        self.process_impl(resolved_if_id, data, src_ip, dst_ip, ttl)
    }

    fn process_impl(
        &self,
        if_id: NetIfId,
        data: &[u8],
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        ttl: u8,
    ) -> UdpResult {
        use core::sync::atomic::Ordering;

        let packet = match UdpPacket::parse(data) {
            Some(p) => p,
            None => {
                return UdpResult::Invalid;
            }
        };

        // Verify checksum (optional for IPv4)
        if !packet.verify_checksum(src_ip, dst_ip) {
            self.stats.checksum_errors.fetch_add(1, Ordering::Relaxed);
            return UdpResult::ChecksumError;
        }

        let payload = packet.payload();
        if let Some(mut pkt_ref) = crate::net::datapath::mempool::alloc_packet() {
            if payload.len() > pkt_ref.capacity() {
                return UdpResult::Invalid;
            }
            // Set length BEFORE data_mut() — freshly allocated buffers have len=0,
            // so data_mut() would return an empty slice without this.
            pkt_ref.set_len(payload.len());
            let buf = pkt_ref.data_mut();
            buf[..payload.len()].copy_from_slice(payload);

            let src = crate::net::l4::EndpointAddr::new(src_ip.octets(), packet.src_port());
            let dst_port = packet.dst_port();

            if self.deliver_payload(if_id, src, dst_port, ttl, PacketPayload::single(pkt_ref)) {
                UdpResult::Delivered
            } else {
                UdpResult::NoEndpoint
            }
        } else {
            // Buffer exhaustion fallback
            UdpResult::NoEndpoint
        }
    }

    /// Process an incoming UDP packet (IPv6, mandatory checksum)
    pub fn process_v6_on(
        &self,
        if_id: Option<NetIfId>,
        data: &[u8],
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        ttl: u8,
    ) -> UdpResult {
        let resolved_if_id = resolve_ingress_if_id(if_id);
        self.process_v6_impl(resolved_if_id, data, src_ip, dst_ip, ttl)
    }

    fn process_v6_impl(
        &self,
        if_id: NetIfId,
        data: &[u8],
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        ttl: u8,
    ) -> UdpResult {
        use core::sync::atomic::Ordering;

        let packet = match UdpPacket::parse(data) {
            Some(p) => p,
            None => return UdpResult::Invalid,
        };

        // Verify checksum (mandatory for IPv6 per RFC 8200)
        if !packet.verify_checksum_v6(src_ip, dst_ip) {
            self.stats.checksum_errors.fetch_add(1, Ordering::Relaxed);
            return UdpResult::ChecksumError;
        }

        let payload = packet.payload();
        if let Some(mut pkt_ref) = crate::net::datapath::mempool::alloc_packet() {
            if payload.len() > pkt_ref.capacity() {
                return UdpResult::Invalid;
            }
            // Set length BEFORE data_mut() — freshly allocated buffers have len=0
            pkt_ref.set_len(payload.len());
            let buf = pkt_ref.data_mut();
            buf[..payload.len()].copy_from_slice(payload);

            let src = crate::net::l4::EndpointAddr::new_v6(src_ip.octets(), packet.src_port());
            let dst_port = packet.dst_port();

            if self.deliver_payload(if_id, src, dst_port, ttl, PacketPayload::single(pkt_ref)) {
                UdpResult::Delivered
            } else {
                UdpResult::NoEndpoint
            }
        } else {
            UdpResult::NoEndpoint
        }
    }

    /// Process an incoming UDP packet with an existing PacketRef (zero-copy, IPv4)
    pub fn process_with_packet_on(
        &self,
        if_id: Option<NetIfId>,
        data: &[u8],
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        packet: PacketRef,
        ttl: u8,
    ) -> UdpResult {
        let resolved_if_id = resolve_ingress_if_id(if_id);
        self.process_with_packet_impl(resolved_if_id, data, src_ip, dst_ip, packet, ttl)
    }

    fn process_with_packet_impl(
        &self,
        if_id: NetIfId,
        data: &[u8],
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        mut packet: PacketRef,
        ttl: u8,
    ) -> UdpResult {
        use core::sync::atomic::Ordering;

        let packet_view = match UdpPacket::parse(data) {
            Some(p) => p,
            None => return UdpResult::Invalid,
        };

        if !packet_view.verify_checksum(src_ip, dst_ip) {
            self.stats.checksum_errors.fetch_add(1, Ordering::Relaxed);
            return UdpResult::ChecksumError;
        }

        let payload_len = packet_view.payload().len();
        if packet.len() < UdpHeader::SIZE + payload_len {
            return UdpResult::Invalid;
        }

        // Advance PacketRef to skip UDP header for zero-copy delivery
        packet.advance(UdpHeader::SIZE);
        packet.set_len(payload_len);

        let src = crate::net::l4::EndpointAddr::new(src_ip.octets(), packet_view.src_port());
        let dst_port = packet_view.dst_port();

        if self.deliver_payload(if_id, src, dst_port, ttl, PacketPayload::single(packet)) {
            UdpResult::Delivered
        } else {
            UdpResult::NoEndpoint
        }
    }

    /// Process an incoming UDP payload that may be backed by a packet chain (zero-copy, IPv4).
    pub fn process_payload_on(
        &self,
        if_id: Option<NetIfId>,
        payload: PacketPayload,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        ttl: u8,
    ) -> UdpResult {
        let resolved_if_id = resolve_ingress_if_id(if_id);
        self.process_payload_impl(resolved_if_id, payload, src_ip, dst_ip, ttl)
    }

    fn process_payload_impl(
        &self,
        if_id: NetIfId,
        payload: PacketPayload,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        ttl: u8,
    ) -> UdpResult {
        use core::sync::atomic::Ordering;

        let view = PacketPayloadView::new(&payload);
        let Some(header) = view.read_array::<8>(0) else {
            return UdpResult::Invalid;
        };
        let length = u16::from_be_bytes([header[4], header[5]]) as usize;
        if !(UdpHeader::SIZE..=view.total_len()).contains(&length) || length != view.total_len() {
            return UdpResult::Invalid;
        }

        let checksum = u16::from_be_bytes([header[6], header[7]]);
        if checksum != 0 {
            let pseudo = pseudo_header_checksum(src_ip, dst_ip, IpProtocol::Udp, length as u16);
            if payload_checksum(&view, pseudo) != 0 {
                self.stats.checksum_errors.fetch_add(1, Ordering::Relaxed);
                return UdpResult::ChecksumError;
            }
        }

        let Some(udp_payload) = crate::net::payload::move_payload_window_owned(
            payload,
            UdpHeader::SIZE,
            length - UdpHeader::SIZE,
        ) else {
            return UdpResult::Invalid;
        };
        let src = crate::net::l4::EndpointAddr::new(
            src_ip.octets(),
            u16::from_be_bytes([header[0], header[1]]),
        );
        let dst_port = u16::from_be_bytes([header[2], header[3]]);

        if self.deliver_payload(if_id, src, dst_port, ttl, udp_payload) {
            UdpResult::Delivered
        } else {
            UdpResult::NoEndpoint
        }
    }

    /// Process an incoming UDP packet with an existing PacketRef (zero-copy, IPv6)
    pub fn process_with_packet_v6_on(
        &self,
        if_id: Option<NetIfId>,
        data: &[u8],
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        packet: PacketRef,
        ttl: u8,
    ) -> UdpResult {
        let resolved_if_id = resolve_ingress_if_id(if_id);
        self.process_with_packet_v6_impl(resolved_if_id, data, src_ip, dst_ip, packet, ttl)
    }

    fn process_with_packet_v6_impl(
        &self,
        if_id: NetIfId,
        data: &[u8],
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        mut packet: PacketRef,
        ttl: u8,
    ) -> UdpResult {
        use core::sync::atomic::Ordering;

        let packet_view = match UdpPacket::parse(data) {
            Some(p) => p,
            None => return UdpResult::Invalid,
        };

        if !packet_view.verify_checksum_v6(src_ip, dst_ip) {
            self.stats.checksum_errors.fetch_add(1, Ordering::Relaxed);
            return UdpResult::ChecksumError;
        }

        let payload_len = packet_view.payload().len();
        if packet.len() < UdpHeader::SIZE + payload_len {
            return UdpResult::Invalid;
        }

        // Advance PacketRef to skip UDP header
        packet.advance(UdpHeader::SIZE);
        packet.set_len(payload_len);

        let src = crate::net::l4::EndpointAddr::new_v6(src_ip.octets(), packet_view.src_port());
        let dst_port = packet_view.dst_port();

        if self.deliver_payload(if_id, src, dst_port, ttl, PacketPayload::single(packet)) {
            UdpResult::Delivered
        } else {
            UdpResult::NoEndpoint
        }
    }

    /// Process an incoming UDP payload that may be backed by a packet chain (zero-copy, IPv6).
    pub fn process_payload_v6_on(
        &self,
        if_id: Option<NetIfId>,
        payload: PacketPayload,
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        ttl: u8,
    ) -> UdpResult {
        let resolved_if_id = resolve_ingress_if_id(if_id);
        self.process_payload_v6_impl(resolved_if_id, payload, src_ip, dst_ip, ttl)
    }

    fn process_payload_v6_impl(
        &self,
        if_id: NetIfId,
        payload: PacketPayload,
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        ttl: u8,
    ) -> UdpResult {
        use core::sync::atomic::Ordering;

        let view = PacketPayloadView::new(&payload);
        let Some(header) = view.read_array::<8>(0) else {
            return UdpResult::Invalid;
        };
        let length = u16::from_be_bytes([header[4], header[5]]) as usize;
        if !(UdpHeader::SIZE..=view.total_len()).contains(&length) || length != view.total_len() {
            return UdpResult::Invalid;
        }

        let checksum = u16::from_be_bytes([header[6], header[7]]);
        if checksum == 0 {
            return UdpResult::ChecksumError;
        }

        let pseudo = ipv6_pseudo_header_checksum(&src_ip, &dst_ip, IpProtocol::Udp, length as u32);
        if payload_checksum(&view, pseudo) != 0 {
            self.stats.checksum_errors.fetch_add(1, Ordering::Relaxed);
            return UdpResult::ChecksumError;
        }

        let Some(udp_payload) = crate::net::payload::move_payload_window_owned(
            payload,
            UdpHeader::SIZE,
            length - UdpHeader::SIZE,
        ) else {
            return UdpResult::Invalid;
        };
        let src = crate::net::l4::EndpointAddr::new_v6(
            src_ip.octets(),
            u16::from_be_bytes([header[0], header[1]]),
        );
        let dst_port = u16::from_be_bytes([header[2], header[3]]);

        if self.deliver_payload(if_id, src, dst_port, ttl, udp_payload) {
            UdpResult::Delivered
        } else {
            UdpResult::NoEndpoint
        }
    }

    /// Build a UDP packet for transmission from a packet-backed payload.
    pub fn build_packet_view<'a>(
        buffer: &'a mut [u8],
        src_ip: Ipv4Address,
        src_port: u16,
        dst_ip: Ipv4Address,
        dst_port: u16,
        payload: &PacketPayloadView<'_>,
    ) -> Option<usize> {
        let mut packet = UdpPacketMut::new(buffer)?;
        packet
            .set_src_port(src_port)
            .set_dst_port(dst_port)
            .write_payload_view(payload);
        Some(packet.finalize(src_ip, dst_ip))
    }
}

impl Default for UdpProcessor {
    fn default() -> Self {
        Self::new()
    }
}
