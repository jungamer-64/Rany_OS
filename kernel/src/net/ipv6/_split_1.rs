use super::*;


impl Ipv6Processor {
    /// Create a new processor with config
    pub fn new(config: Ipv6Config) -> Self {
        Self {
            config,
            stats: Ipv6Stats::default(),
        }
    }

    /// Get config reference
    #[inline]
    pub fn config(&self) -> &Ipv6Config {
        &self.config
    }

    /// Get mutable config reference
    #[inline]
    pub fn config_mut(&mut self) -> &mut Ipv6Config {
        &mut self.config
    }

    /// Get stats reference
    #[inline]
    pub fn stats(&self) -> &Ipv6Stats {
        &self.stats
    }

    /// Process an incoming IPv6 packet
    pub fn process<'a>(&self, data: &'a [u8]) -> Ipv6ProcessResult<'a> {
        // Parse the packet
        let packet = match Ipv6Packet::parse(data) {
            Some(p) => p,
            None => {
                self.stats.record_header_error();
                return Ipv6ProcessResult::Error;
            }
        };

        self.stats.record_rx();

        let src = packet.source();
        let dst = packet.destination();

        // Check if the packet is for us
        if !self.is_for_us(&dst) {
            self.stats.record_dropped();
            return Ipv6ProcessResult::Dropped;
        }

        // Check hop limit
        if packet.hop_limit() == 0 {
            self.stats.record_hop_limit_exceeded();
            return Ipv6ProcessResult::Dropped;
        }

        // Skip extension headers to find upper-layer protocol
        let (final_protocol, upper_payload) = packet.skip_extension_headers();

        // Dispatch based on upper-layer protocol
        match final_protocol {
            IpProtocol::Icmpv6 => Ipv6ProcessResult::Icmpv6(upper_payload, src, dst),
            IpProtocol::Tcp => Ipv6ProcessResult::Tcp(upper_payload, src, dst),
            IpProtocol::Udp => Ipv6ProcessResult::Udp(upper_payload, src, dst),
            _ => {
                self.stats.record_dropped();
                Ipv6ProcessResult::Dropped
            }
        }
    }

    /// Check if a destination address is for this interface
    pub(super) fn is_for_us(&self, addr: &Ipv6Address) -> bool {
        // Direct matches: link-local, all-nodes multicast, solicited-node, loopback
        if *addr == self.config.link_local
            || *addr == Ipv6Address::ALL_NODES_LINK_LOCAL
            || *addr == self.config.link_local.solicited_node()
            || addr.is_loopback()
        {
            return true;
        }

        // Global address and its solicited-node multicast
        if let Some(ref global) = self.config.global {
            if addr == global || *addr == global.solicited_node() {
                return true;
            }
        }

        false
    }

    /// Update global address (e.g. from SLAAC/RA)
    pub fn set_global_address(&mut self, addr: Ipv6Address) {
        self.config.global = Some(addr);
    }

    /// Update gateway (from RA)
    pub fn set_gateway(&mut self, addr: Ipv6Address) {
        self.config.gateway = Some(addr);
    }
}

// =====================================================
// IPv6 Pseudo-Header Checksum (RFC 8200 Section 8.1)
// =====================================================

/// Calculate IPv6 pseudo-header checksum for ICMPv6/TCP/UDP
///
/// Pseudo-header layout:
/// - Source Address (16 bytes)
/// - Destination Address (16 bytes)
/// - Upper-Layer Packet Length (4 bytes, big-endian)
/// - Next Header (4 bytes: 3 zero bytes + 1 byte)
///
/// Returns the accumulated 32-bit sum (caller should fold and complement)
pub fn ipv6_pseudo_header_checksum(
    src: &Ipv6Address,
    dst: &Ipv6Address,
    next_header: IpProtocol,
    payload_len: u32,
) -> u32 {
    let mut sum: u32 = 0;

    // Source address (16 bytes, 8 u16 words)
    let s = src.as_bytes();
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([s[i], s[i + 1]]) as u32;
    }

    // Destination address (16 bytes, 8 u16 words)
    let d = dst.as_bytes();
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([d[i], d[i + 1]]) as u32;
    }

    // Upper-layer packet length (32-bit, big-endian)
    let len_bytes = payload_len.to_be_bytes();
    sum += u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as u32;
    sum += u16::from_be_bytes([len_bytes[2], len_bytes[3]]) as u32;

    // Next header (zero-padded to 32 bits)
    sum += u8::from(next_header) as u32;

    sum
}

/// Compute full checksum over pseudo-header + data
///
/// Uses the same folding algorithm as IPv4's data_checksum
pub fn ipv6_checksum(
    src: &Ipv6Address,
    dst: &Ipv6Address,
    next_header: IpProtocol,
    data: &[u8],
) -> u16 {
    let pseudo = ipv6_pseudo_header_checksum(src, dst, next_header, data.len() as u32);
    super::ipv4::data_checksum(data, pseudo)
}

// =====================================================
// Tests
// =====================================================

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
