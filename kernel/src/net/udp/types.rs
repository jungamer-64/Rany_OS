use super::*;


/// UDP socket snapshot for monitoring
#[derive(Debug, Clone)]
pub struct UdpSocketSnapshot {
    /// Local port
    pub local_port: u16,
    /// Number of pending datagrams in receive queue
    pub rx_queue_len: usize,
}

/// UDP processor for handling UDP packets

pub struct UdpProcessor {
    /// Socket table
    sockets: UdpSocketTable,
}

/// Result of UDP processing
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum UdpResult {
    /// Delivered to socket
    Delivered,
    /// No socket for this port
    NoSocket,
    /// Checksum error
    ChecksumError,
    /// Invalid packet
    Invalid,
}

impl UdpProcessor {
    /// Create a new UDP processor
    pub fn new() -> Self {
        UdpProcessor {
            sockets: UdpSocketTable::new(),
        }
    }

    /// Get socket table
    pub fn sockets(&self) -> &UdpSocketTable {
        &self.sockets
    }

    /// Process an incoming UDP packet
    pub fn process(&self, data: &[u8], src_ip: Ipv4Address, dst_ip: Ipv4Address) -> UdpResult {
        use core::sync::atomic::Ordering;

        let packet = match UdpPacket::parse(data) {
            Some(p) => p,
            None => return UdpResult::Invalid,
        };

        // Verify checksum
        if !packet.verify_checksum(src_ip, dst_ip) {
            self.sockets
                .stats
                .checksum_errors
                .fetch_add(1, Ordering::Relaxed);
            return UdpResult::ChecksumError;
        }

        let datagram = UdpDatagram {
            src: UdpAddr::new(src_ip, packet.src_port()),
            dst_port: packet.dst_port(),
            data: packet.payload().to_vec(),
        };

        if self.sockets.deliver(datagram) {
            UdpResult::Delivered
        } else {
            UdpResult::NoSocket
        }
    }

    /// Process an incoming UDP packet with an existing PacketRef (zero-copy)
    pub fn process_with_packet(&self, data: &[u8], src_ip: Ipv4Address, dst_ip: Ipv4Address, packet: PacketRef) -> UdpResult {
        use core::sync::atomic::Ordering;

        let packet_view = match UdpPacket::parse(data) {
            Some(p) => p,
            None => return UdpResult::Invalid,
        };

        if !packet_view.verify_checksum(src_ip, dst_ip) {
            self.sockets
                .stats
                .checksum_errors
                .fetch_add(1, Ordering::Relaxed);
            return UdpResult::ChecksumError;
        }

        let src = UdpAddr::new(src_ip, packet_view.src_port());
        let dst_port = packet_view.dst_port();

        if self.sockets.deliver_packet(src, dst_port, packet) {
            UdpResult::Delivered
        } else {
            UdpResult::NoSocket
        }
    }

    // Legacy `bind` removed; use `bind_with_token(port, None)` instead.

    /// Bind to a port with a capability token
    pub fn bind_with_token(&self, port: u16, token: Option<u64>) -> Result<UdpSocket, NetworkError> {
        // If no token provided, delegate directly to socket table's token-aware bind
        if token.is_none() {
            return self.sockets.bind_with_token(port, None).ok_or(NetworkError::PortInUse);
        }

        // Token present - validate ownership and capability
        let t = token.unwrap();
        let caller_domain = crate::task::context::current_subject().domain;
        if !crate::security::capability::manager().validate_token(caller_domain.as_u64(), t, crate::security::capability::CAP_NET_BIND) {
             return Err(NetworkError::PermissionDenied);
        }
        
        self.sockets.bind_with_token(port, Some(t)).ok_or(NetworkError::PortInUse)
    }

    /// Unbind a socket
    pub fn unbind(&self, port: u16) {
        self.sockets.unbind(port)
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

#[cfg(any(test, feature = "qemu-test-export"))]
#[path = "tests.rs"]
pub mod tests;
