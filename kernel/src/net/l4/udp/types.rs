use super::*;

fn resolve_ingress_if_id(if_id: Option<NetIfId>) -> NetIfId {
    if let Some(if_id) = if_id {
        return if_id;
    }
    crate::net::runtime::device::primary_if()
        .or_else(|| {
            crate::net::runtime::manager::list_interfaces()
                .ok()
                .and_then(|ifaces| ifaces.first().map(|iface| iface.if_id))
        })
        .unwrap_or_default()
}

/// UDP socket snapshot for monitoring
#[derive(Debug, Clone)]
pub struct UdpEndpointSnapshot {
    /// Local port
    pub local_port: u16,
    /// Number of pending datagrams in receive queue
    pub rx_queue_len: usize,
}

/// UDP processor for handling UDP packets

pub struct UdpProcessor {
    /// Socket table
    endpoints: UdpEndpointTable,
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
            endpoints: UdpEndpointTable::new(),
        }
    }

    /// Get socket table
    pub fn endpoints(&self) -> &UdpEndpointTable {
        &self.endpoints
    }

    /// Check if a socket exists on the given port
    pub fn has_endpoint(&self, port: u16) -> bool {
        let if_id = resolve_ingress_if_id(None);
        self.endpoints
            .find(UdpAddressFamily::Ipv4, port, if_id)
            .is_some()
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

    pub fn process(
        &self,
        data: &[u8],
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        ttl: u8,
    ) -> UdpResult {
        self.process_on(None, data, src_ip, dst_ip, ttl)
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
            self.endpoints
                .stats
                .checksum_errors
                .fetch_add(1, Ordering::Relaxed);
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

            let src = UdpAddr::new(src_ip, packet.src_port());
            let dst_port = packet.dst_port();

            if self.endpoints.deliver(if_id, src, dst_port, ttl, pkt_ref) {
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

    pub fn process_v6(
        &self,
        data: &[u8],
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        ttl: u8,
    ) -> UdpResult {
        self.process_v6_on(None, data, src_ip, dst_ip, ttl)
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
            self.endpoints
                .stats
                .checksum_errors
                .fetch_add(1, Ordering::Relaxed);
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

            let src = UdpAddr::new_v6(src_ip, packet.src_port());
            let dst_port = packet.dst_port();

            if self.endpoints.deliver(if_id, src, dst_port, ttl, pkt_ref) {
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

    pub fn process_with_packet(
        &self,
        data: &[u8],
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        packet: PacketRef,
        ttl: u8,
    ) -> UdpResult {
        self.process_with_packet_on(None, data, src_ip, dst_ip, packet, ttl)
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
            self.endpoints
                .stats
                .checksum_errors
                .fetch_add(1, Ordering::Relaxed);
            return UdpResult::ChecksumError;
        }

        let payload_len = packet_view.payload().len();
        if packet.len() < UdpHeader::SIZE + payload_len {
            return UdpResult::Invalid;
        }

        // Advance PacketRef to skip UDP header for zero-copy delivery
        packet.advance(UdpHeader::SIZE);
        packet.set_len(payload_len);

        let src = UdpAddr::new(src_ip, packet_view.src_port());
        let dst_port = packet_view.dst_port();

        if self.endpoints.deliver(if_id, src, dst_port, ttl, packet) {
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

    pub fn process_with_packet_v6(
        &self,
        data: &[u8],
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        packet: PacketRef,
        ttl: u8,
    ) -> UdpResult {
        self.process_with_packet_v6_on(None, data, src_ip, dst_ip, packet, ttl)
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
            self.endpoints
                .stats
                .checksum_errors
                .fetch_add(1, Ordering::Relaxed);
            return UdpResult::ChecksumError;
        }

        let payload_len = packet_view.payload().len();
        if packet.len() < UdpHeader::SIZE + payload_len {
            return UdpResult::Invalid;
        }

        // Advance PacketRef to skip UDP header
        packet.advance(UdpHeader::SIZE);
        packet.set_len(payload_len);

        let src = UdpAddr::new_v6(src_ip, packet_view.src_port());
        let dst_port = packet_view.dst_port();

        if self.endpoints.deliver(if_id, src, dst_port, ttl, packet) {
            UdpResult::Delivered
        } else {
            UdpResult::NoEndpoint
        }
    }

    // Legacy `bind` removed; use `bind_with_token(port, None)` instead.

    /// Bind to a port with a capability token
    pub fn bind_with_token(
        &self,
        scope: InterfaceScope,
        port: u16,
        token: Option<u64>,
    ) -> Result<UdpEndpoint, NetworkError> {
        if let Some(t) = token {
            // Token present - validate ownership and capability
            let caller_domain = crate::task::context::current_subject().domain;
            if !crate::security::capability::manager().validate_token(
                caller_domain.as_u64(),
                t,
                crate::security::capability::CAP_NET_BIND,
            ) {
                return Err(NetworkError::PermissionDenied);
            }
        }
        self.endpoints
            .bind_dual_stack_with_token(scope, port, token)
            .ok_or(NetworkError::PortInUse)
    }

    /// Unbind a socket
    pub fn unbind(&self, scope: InterfaceScope, port: u16) {
        self.endpoints.unbind(scope, port)
    }

    /// Build a UDP packet for transmission
    pub fn build_packet<'a>(
        buffer: &'a mut [u8],
        src_ip: Ipv4Address,
        src_port: u16,
        dst_ip: Ipv4Address,
        dst_port: u16,
        payload: &[u8],
    ) -> Option<usize> {
        let mut packet = UdpPacketMut::new(buffer)?;
        packet
            .set_src_port(src_port)
            .set_dst_port(dst_port)
            .write_payload(payload);
        Some(packet.finalize(src_ip, dst_ip))
    }
}

impl Default for UdpProcessor {
    fn default() -> Self {
        Self::new()
    }
}
