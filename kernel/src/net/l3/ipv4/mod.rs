// ============================================================================
// kernel/src/net/l3/ipv4/mod.rs
// ============================================================================
//! IPv4 Protocol Implementation for ExoRust
//!
//! Zero-copy IPv4 packet processing as specified in Section 6.2
//! of the ExoRust specification.
//!
//! ## IP Fragmentation Support
//!
//! This module includes RFC 791-compliant IP fragment reassembly:
//! - Fragment caching with timeout-based eviction
//! - Hole-filling algorithm for efficient reassembly
//! - Protection against fragment overlap attacks

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

/// IPv4 address (4 bytes)
mod pmtu_cache_impl;
pub use pmtu_cache_impl::*;
#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests;
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct Ipv4Address([u8; 4]);

impl Ipv4Address {
    /// Any address (0.0.0.0)
    pub const ANY: Ipv4Address = Ipv4Address([0, 0, 0, 0]);

    /// Broadcast address (255.255.255.255)
    pub const BROADCAST: Ipv4Address = Ipv4Address([255, 255, 255, 255]);

    /// Loopback address (127.0.0.1)
    pub const LOOPBACK: Ipv4Address = Ipv4Address([127, 0, 0, 1]);

    /// Create from bytes
    pub const fn new(bytes: [u8; 4]) -> Self {
        Ipv4Address(bytes)
    }

    /// Create from individual octets
    pub const fn from_octets(a: u8, b: u8, c: u8, d: u8) -> Self {
        Ipv4Address([a, b, c, d])
    }

    /// Get the underlying bytes
    pub const fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }

    /// Get the underlying bytes as octets (alias for as_bytes)
    pub const fn octets(&self) -> [u8; 4] {
        self.0
    }

    /// Convert to u32 (network byte order)
    pub const fn to_u32(&self) -> u32 {
        ((self.0[0] as u32) << 24)
            | ((self.0[1] as u32) << 16)
            | ((self.0[2] as u32) << 8)
            | (self.0[3] as u32)
    }

    /// Create from u32 (network byte order)
    pub const fn from_u32(value: u32) -> Self {
        Ipv4Address([
            (value >> 24) as u8,
            (value >> 16) as u8,
            (value >> 8) as u8,
            value as u8,
        ])
    }

    /// Check if this is a broadcast address
    pub const fn is_broadcast(&self) -> bool {
        self.0[0] == 255 && self.0[1] == 255 && self.0[2] == 255 && self.0[3] == 255
    }

    /// Check if this is the any address
    pub const fn is_any(&self) -> bool {
        self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }

    /// Check if this is a loopback address (127.x.x.x)
    pub const fn is_loopback(&self) -> bool {
        self.0[0] == 127
    }

    /// Check if this is a multicast address (224.0.0.0 - 239.255.255.255)
    pub const fn is_multicast(&self) -> bool {
        self.0[0] >= 224 && self.0[0] <= 239
    }

    /// Check if this is a link-local address (169.254.x.x)
    pub const fn is_link_local(&self) -> bool {
        self.0[0] == 169 && self.0[1] == 254
    }

    /// Check if this is a private address
    pub const fn is_private(&self) -> bool {
        // 10.0.0.0/8
        self.0[0] == 10 ||
        // 172.16.0.0/12
        (self.0[0] == 172 && (self.0[1] & 0xf0) == 16) ||
        // 192.168.0.0/16
        (self.0[0] == 192 && self.0[1] == 168)
    }

    /// Check if this is a shared address space (CGNAT, 100.64.0.0/10)
    pub const fn is_shared_address(&self) -> bool {
        self.0[0] == 100 && (self.0[1] & 0xc0) == 64
    }

    /// Check if this is a Martian/Reserved address that should not appear on the public internet
    /// as a source address (RFC 1812, RFC 6890)
    pub const fn is_martian(&self) -> bool {
        // 0.0.0.0/8 (Current network)
        if self.0[0] == 0 {
            return true;
        }
        // 127.0.0.0/8 (Loopback)
        if self.is_loopback() {
            return true;
        }
        // 169.254.0.0/16 (Link Local)
        if self.is_link_local() {
            return true;
        }
        // 192.0.0.0/24 (IETF Protocol Assignments)
        if self.0[0] == 192 && self.0[1] == 0 && self.0[2] == 0 {
            return true;
        }
        // 192.0.2.0/24 (TEST-NET-1)
        if self.0[0] == 192 && self.0[1] == 0 && self.0[2] == 2 {
            return true;
        }
        // 198.51.100.0/24 (TEST-NET-2)
        if self.0[0] == 198 && self.0[1] == 51 && self.0[2] == 100 {
            return true;
        }
        // 203.0.113.0/24 (TEST-NET-3)
        if self.0[0] == 203 && self.0[1] == 0 && self.0[2] == 113 {
            return true;
        }
        // 240.0.0.0/4 (Reserved / Future Use)
        if (self.0[0] & 0xf0) == 240 {
            // 255.255.255.255 is handled separately as broadcast
            return !self.is_broadcast();
        }
        false
    }

    /// Apply a subnet mask
    pub const fn apply_mask(&self, mask: Ipv4Address) -> Ipv4Address {
        Ipv4Address([
            self.0[0] & mask.0[0],
            self.0[1] & mask.0[1],
            self.0[2] & mask.0[2],
            self.0[3] & mask.0[3],
        ])
    }

    /// Check if two addresses are in the same subnet
    pub const fn same_subnet(&self, other: &Ipv4Address, mask: Ipv4Address) -> bool {
        (self.0[0] & mask.0[0]) == (other.0[0] & mask.0[0])
            && (self.0[1] & mask.0[1]) == (other.0[1] & mask.0[1])
            && (self.0[2] & mask.0[2]) == (other.0[2] & mask.0[2])
            && (self.0[3] & mask.0[3]) == (other.0[3] & mask.0[3])
    }
}

impl fmt::Debug for Ipv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

impl fmt::Display for Ipv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// IPv4 protocol numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum IpProtocol {
    /// Internet Control Message Protocol
    Icmp = 1,
    /// Internet Group Management Protocol
    Igmp = 2,
    /// Transmission Control Protocol
    Tcp = 6,
    /// User Datagram Protocol
    Udp = 17,
    /// Generic Routing Encapsulation
    Gre = 47,
    /// ICMPv6 (RFC 4443)
    Icmpv6 = 58,
    /// Unknown protocol
    Unknown(u8),
}

impl From<u8> for IpProtocol {
    fn from(value: u8) -> Self {
        match value {
            1 => IpProtocol::Icmp,
            2 => IpProtocol::Igmp,
            6 => IpProtocol::Tcp,
            17 => IpProtocol::Udp,
            47 => IpProtocol::Gre,
            58 => IpProtocol::Icmpv6,
            other => IpProtocol::Unknown(other),
        }
    }
}

impl From<IpProtocol> for u8 {
    fn from(value: IpProtocol) -> Self {
        match value {
            IpProtocol::Icmp => 1,
            IpProtocol::Igmp => 2,
            IpProtocol::Tcp => 6,
            IpProtocol::Udp => 17,
            IpProtocol::Gre => 47,
            IpProtocol::Icmpv6 => 58,
            IpProtocol::Unknown(v) => v,
        }
    }
}

/// IPv4 header (20-60 bytes)
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Ipv4Header {
    /// Version (4 bits) + IHL (4 bits)
    pub version_ihl: u8,
    /// DSCP (6 bits) + ECN (2 bits)
    pub dscp_ecn: u8,
    /// Total length (big-endian)
    pub total_length: [u8; 2],
    /// Identification (big-endian)
    pub identification: [u8; 2],
    /// Flags (3 bits) + Fragment offset (13 bits) (big-endian)
    pub flags_fragment: [u8; 2],
    /// Time to live
    pub ttl: u8,
    /// Protocol
    pub protocol: u8,
    /// Header checksum (big-endian)
    pub checksum: [u8; 2],
    /// Source address
    pub src_addr: [u8; 4],
    /// Destination address
    pub dst_addr: [u8; 4],
    // Options may follow (if IHL > 5)
}

impl Ipv4Header {
    /// Minimum header size (no options)
    pub const MIN_SIZE: usize = 20;
    /// Maximum header size (with options)
    pub const MAX_SIZE: usize = 60;

    /// Get IP version (should be 4)
    pub const fn version(&self) -> u8 {
        self.version_ihl >> 4
    }

    /// Get Internet Header Length in 32-bit words
    pub const fn ihl(&self) -> u8 {
        self.version_ihl & 0x0F
    }

    /// Get header length in bytes
    pub const fn header_len(&self) -> usize {
        (self.ihl() as usize) * 4
    }

    /// Get DSCP (Differentiated Services Code Point)
    pub const fn dscp(&self) -> u8 {
        self.dscp_ecn >> 2
    }

    /// Get ECN (Explicit Congestion Notification)
    pub const fn ecn(&self) -> u8 {
        self.dscp_ecn & 0x03
    }

    /// Get total length
    pub fn total_length(&self) -> u16 {
        u16::from_be_bytes(self.total_length)
    }

    /// Set total length
    pub fn set_total_length(&mut self, len: u16) {
        self.total_length = len.to_be_bytes();
    }

    /// Get identification
    pub fn identification(&self) -> u16 {
        u16::from_be_bytes(self.identification)
    }

    /// Set identification
    pub fn set_identification(&mut self, id: u16) {
        self.identification = id.to_be_bytes();
    }

    /// Get flags
    pub fn flags(&self) -> u8 {
        self.flags_fragment[0] >> 5
    }

    /// Check "Don't Fragment" flag
    pub fn dont_fragment(&self) -> bool {
        (self.flags_fragment[0] & 0x40) != 0
    }

    /// Check "More Fragments" flag
    pub fn more_fragments(&self) -> bool {
        (self.flags_fragment[0] & 0x20) != 0
    }

    /// Get fragment offset (in 8-byte units)
    pub fn fragment_offset(&self) -> u16 {
        u16::from_be_bytes([self.flags_fragment[0] & 0x1F, self.flags_fragment[1]])
    }

    /// Get TTL
    pub const fn ttl(&self) -> u8 {
        self.ttl
    }

    /// Set TTL
    pub fn set_ttl(&mut self, ttl: u8) {
        self.ttl = ttl;
    }

    /// Get protocol
    pub fn protocol(&self) -> IpProtocol {
        IpProtocol::from(self.protocol)
    }

    /// Set protocol
    pub fn set_protocol(&mut self, protocol: IpProtocol) {
        self.protocol = protocol.into();
    }

    /// Get checksum
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.checksum)
    }

    /// Set checksum
    pub fn set_checksum(&mut self, checksum: u16) {
        self.checksum = checksum.to_be_bytes();
    }

    /// Get source address
    pub fn source(&self) -> Ipv4Address {
        Ipv4Address::new(self.src_addr)
    }

    /// Set source address
    pub fn set_source(&mut self, addr: Ipv4Address) {
        self.src_addr = *addr.as_bytes();
    }

    /// Get destination address
    pub fn destination(&self) -> Ipv4Address {
        Ipv4Address::new(self.dst_addr)
    }

    /// Set destination address
    pub fn set_destination(&mut self, addr: Ipv4Address) {
        self.dst_addr = *addr.as_bytes();
    }

    /// Get payload length
    pub fn payload_len(&self) -> usize {
        (self.total_length() as usize).saturating_sub(self.header_len())
    }

    /// Calculate header checksum from a raw byte slice.
    /// The slice MUST be at least as long as the header length specified in the first byte.
    pub fn compute_checksum_static(header_bytes: &[u8]) -> u16 {
        if header_bytes.is_empty() {
            return 0;
        }
        let ihl = (header_bytes[0] & 0x0F) as usize;
        let header_len = ihl * 4;

        if header_bytes.len() < header_len {
            return 0; // Or panic? Returning 0 is safer for now.
        }

        let mut sum: u32 = 0;

        // Sum 16-bit words, skipping checksum field (bytes 10-11)
        for i in (0..header_len).step_by(2) {
            if i == 10 {
                continue; // Skip checksum field
            }
            let word = if i + 1 < header_len {
                u16::from_be_bytes([header_bytes[i], header_bytes[i + 1]])
            } else {
                u16::from_be_bytes([header_bytes[i], 0])
            };
            sum += word as u32;
        }

        // Fold 32-bit sum to 16 bits
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        let result = !(sum as u16);
        if result == 0 {
            0xFFFF
        } else {
            result
        }
    }
}

/// Zero-copy IPv4 packet view
pub struct Ipv4Packet<'a> {
    header: &'a Ipv4Header,
    /// Raw packet data
    data: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    /// Parse an IPv4 packet from raw bytes (zero-copy)
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < Ipv4Header::MIN_SIZE {
            return None;
        }

        let header = crate::util::get_ref::<Ipv4Header>(data, 0)?;
        let packet = Ipv4Packet { header, data };

        // Verify version
        if packet.header().version() != 4 {
            return None;
        }

        // Verify header length
        let header_len = packet.header().header_len();
        if header_len < Ipv4Header::MIN_SIZE || header_len > data.len() {
            return None;
        }

        // Verify total length
        let total_len = packet.header().total_length() as usize;
        if total_len < header_len || total_len > data.len() {
            return None;
        }

        Some(packet)
    }

    /// Get the IPv4 header
    pub fn header(&self) -> &Ipv4Header {
        self.header
    }

    /// Get source address
    pub fn source(&self) -> Ipv4Address {
        self.header().source()
    }

    /// Get destination address
    pub fn destination(&self) -> Ipv4Address {
        self.header().destination()
    }

    /// Get protocol
    pub fn protocol(&self) -> IpProtocol {
        self.header().protocol()
    }

    /// Get TTL
    pub fn ttl(&self) -> u8 {
        self.header().ttl()
    }

    /// Get the payload (zero-copy)
    pub fn payload(&self) -> &'a [u8] {
        let header_len = self.header().header_len();
        let total_len = self.header().total_length() as usize;
        &self.data[header_len..total_len]
    }

    /// Get IP options (if any)
    pub fn options(&self) -> &'a [u8] {
        let header_len = self.header().header_len();
        if header_len > Ipv4Header::MIN_SIZE {
            &self.data[Ipv4Header::MIN_SIZE..header_len]
        } else {
            &[]
        }
    }

    /// Get raw packet data
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        let total_len = self.header().total_length() as usize;
        // Security: Clamp to physical buffer size to prevent panic in slice indexing
        &self.data[..core::cmp::min(total_len, self.data.len())]
    }

    /// Verify header checksum
    pub fn verify_checksum(&self) -> bool {
        let header_len = self.header().header_len();
        if self.data.len() < header_len {
            return false;
        }
        let expected = self.header().checksum();
        let calculated = Ipv4Header::compute_checksum_static(&self.data[..header_len]);
        expected == calculated
    }
}

/// Mutable IPv4 packet builder
pub struct Ipv4PacketMut<'a> {
    /// Raw buffer
    data: &'a mut [u8],
}

impl<'a> Ipv4PacketMut<'a> {
    /// Create a new IPv4 packet builder
    pub fn new(buffer: &'a mut [u8]) -> Option<Self> {
        if buffer.len() < Ipv4Header::MIN_SIZE {
            return None;
        }

        // Initialize header
        let packet = Ipv4PacketMut { data: buffer };

        Some(packet)
    }

    /// Get mutable header
    pub fn header_mut(&mut self) -> Option<&mut Ipv4Header> {
        crate::util::get_mut_ref::<Ipv4Header>(self.data, 0)
    }

    /// Initialize header with default values
    pub fn init_header(&mut self) -> &mut Self {
        if let Some(header) = self.header_mut() {
            header.version_ihl = 0x45; // IPv4, IHL=5 (20 bytes)
            header.dscp_ecn = 0;
            header.total_length = [0, 20]; // Will be updated
            header.identification = [0, 0];
            header.flags_fragment = [0x40, 0]; // Don't Fragment
            header.ttl = 64;
            header.protocol = 0;
            header.checksum = [0, 0];
            header.src_addr = [0; 4];
            header.dst_addr = [0; 4];
        }
        self
    }

    /// Set source address
    pub fn set_source(&mut self, addr: Ipv4Address) -> &mut Self {
        if let Some(h) = self.header_mut() {
            h.set_source(addr);
        }
        self
    }

    /// Set destination address
    pub fn set_destination(&mut self, addr: Ipv4Address) -> &mut Self {
        if let Some(h) = self.header_mut() {
            h.set_destination(addr);
        }
        self
    }

    /// Set protocol
    pub fn set_protocol(&mut self, protocol: IpProtocol) -> &mut Self {
        if let Some(h) = self.header_mut() {
            h.set_protocol(protocol);
        }
        self
    }

    /// Set TTL
    pub fn set_ttl(&mut self, ttl: u8) -> &mut Self {
        if let Some(h) = self.header_mut() {
            h.set_ttl(ttl);
        }
        self
    }

    /// Set version (should be 4 for IPv4)
    pub fn set_version(&mut self, version: u8) -> &mut Self {
        if let Some(h) = self.header_mut() {
            h.version_ihl = (version << 4) | (h.version_ihl & 0x0f);
        }
        self
    }

    /// Set IHL (Internet Header Length in 32-bit words)
    pub fn set_ihl(&mut self, ihl: u8) -> &mut Self {
        // Valid IHL is 5 (20 bytes) to 15 (60 bytes)
        if ihl >= 5 && ihl <= 15 {
            if let Some(h) = self.header_mut() {
                h.version_ihl = (h.version_ihl & 0xf0) | (ihl & 0x0f);
            }
        }
        self
    }

    /// Set DSCP (Differentiated Services Code Point)
    pub fn set_dscp(&mut self, dscp: u8) -> &mut Self {
        if let Some(h) = self.header_mut() {
            h.dscp_ecn = (dscp & 0xfc) | (h.dscp_ecn & 0x03);
        }
        self
    }

    /// Set total length
    pub fn set_total_length(&mut self, len: u16) -> &mut Self {
        if let Some(h) = self.header_mut() {
            h.set_total_length(len);
        }
        self
    }

    /// Update checksum
    pub fn update_checksum(&mut self) -> &mut Self {
        let header_len = if let Some(h) = self.header_mut() {
            h.header_len()
        } else {
            return self;
        };

        if self.data.len() >= header_len {
            let checksum = Ipv4Header::compute_checksum_static(&self.data[..header_len]);
            if let Some(h) = self.header_mut() {
                h.set_checksum(checksum);
            }
        }
        self
    }

    /// Set identification
    pub fn set_identification(&mut self, id: u16) -> &mut Self {
        if let Some(h) = self.header_mut() {
            h.set_identification(id);
        }
        self
    }

    /// Get mutable payload buffer
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let header_len = self
            .header_mut()
            .map(|h| h.header_len())
            .unwrap_or(Ipv4Header::MIN_SIZE);
        if self.data.len() < header_len {
            &mut []
        } else {
            &mut self.data[header_len..]
        }
    }

    /// Set total length and update checksum
    pub fn finalize(&mut self, payload_len: usize) {
        let header_len = if let Some(h) = self.header_mut() {
            h.header_len()
        } else {
            return;
        };

        // Security: Clamp payload length to physical buffer size to prevent buffer overflow/panic
        let max_payload = self.data.len().saturating_sub(header_len);
        let actual_payload = payload_len.min(max_payload);

        let total_len_usize = header_len + actual_payload;
        let total_len = total_len_usize.min(65535) as u16;

        if let Some(h) = self.header_mut() {
            h.set_total_length(total_len);
        }
        self.update_checksum();
    }

    /// Get total packet length
    pub fn total_len(&self) -> usize {
        // Use safe helper to read header; buffer length was validated in new()
        let declared_len = crate::util::get_ref::<Ipv4Header>(self.data, 0)
            .map(|h| h.total_length() as usize)
            .unwrap_or(Ipv4Header::MIN_SIZE);

        // Security: Clamp to physical buffer size to prevent panic in slice indexing
        core::cmp::min(declared_len, self.data.len())
    }

    /// Get packet as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.total_len()]
    }
}

#[cfg(test)]
mod packet_mut_tests {
    use super::*;

    #[test_case]
    fn test_ipv4_packet_mut_finalize_clamp() {
        let mut buffer = [0u8; 30]; // 20 bytes header + 10 bytes payload
        let mut packet = Ipv4PacketMut::new(&mut buffer).unwrap();
        packet.init_header();

        // Try to finalize with a payload larger than buffer
        packet.finalize(100);

        // Check that it was clamped
        assert_eq!(packet.total_len(), 30);
        assert_eq!(packet.as_bytes().len(), 30);

        // Check header total length
        if let Some(h) = packet.header_mut() {
            assert_eq!(h.total_length(), 30);
        }
    }

    #[test_case]
    fn test_ipv4_packet_mut_manual_overflow_protection() {
        let mut buffer = [0u8; 30];
        let mut packet = Ipv4PacketMut::new(&mut buffer).unwrap();
        packet.init_header();

        // Manually set a large total length
        if let Some(h) = packet.header_mut() {
            h.set_total_length(100);
        }

        // total_len() should still be clamped to buffer size
        assert_eq!(packet.total_len(), 30);

        // as_bytes() should not panic
        let bytes = packet.as_bytes();
        assert_eq!(bytes.len(), 30);
    }
}

/// IPv4 network configuration
///
/// Note: 全フィールドが Copy 型のため、Copy を実装。
/// clone() のコストが実質的にゼロになる。
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Config {
    /// Local IP address
    pub address: Ipv4Address,
    /// Subnet mask
    pub subnet_mask: Ipv4Address,
    /// Gateway address
    pub gateway: Ipv4Address,
    /// DNS server (optional)
    pub dns: Option<Ipv4Address>,
}

impl Default for Ipv4Config {
    fn default() -> Self {
        Ipv4Config {
            address: Ipv4Address::ANY,
            subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
            gateway: Ipv4Address::ANY,
            dns: None,
        }
    }
}

impl Ipv4Config {
    /// Check if an address is on the local subnet
    pub fn is_local(&self, addr: &Ipv4Address) -> bool {
        self.address.same_subnet(addr, self.subnet_mask)
    }

    /// Get broadcast address for the subnet
    pub fn broadcast_address(&self) -> Ipv4Address {
        let net = self.address.apply_mask(self.subnet_mask);
        let inv_mask = Ipv4Address::new([
            !self.subnet_mask.as_bytes()[0],
            !self.subnet_mask.as_bytes()[1],
            !self.subnet_mask.as_bytes()[2],
            !self.subnet_mask.as_bytes()[3],
        ]);
        Ipv4Address::new([
            net.as_bytes()[0] | inv_mask.as_bytes()[0],
            net.as_bytes()[1] | inv_mask.as_bytes()[1],
            net.as_bytes()[2] | inv_mask.as_bytes()[2],
            net.as_bytes()[3] | inv_mask.as_bytes()[3],
        ])
    }
}

// ============================================================================
// Path MTU Discovery (RFC 1191 / RFC 8899)
// ============================================================================

/// Path MTU Discovery entry
#[derive(Debug, Clone, Copy)]
pub struct PmtuEntry {
    /// Path MTU in bytes
    pub pmtu: u16,
    /// Timestamp when this entry was last updated (ms)
    pub updated_at: u64,
    /// Timestamp for next probe (for PLPMTUD)
    pub next_probe: u64,
}

impl PmtuEntry {
    /// Default MTU (standard Ethernet)
    pub const DEFAULT_MTU: u16 = 1500;
    /// Minimum MTU (RFC 791)
    pub const MIN_MTU: u16 = 68;
    /// Maximum MTU
    pub const MAX_MTU: u16 = 65535;
    /// Cache entry timeout in milliseconds (10 minutes, RFC 1191)
    pub const TIMEOUT_MS: u64 = 600_000;

    /// Create a new PMTU entry
    pub fn new(pmtu: u16, timestamp: u64) -> Self {
        Self {
            pmtu: pmtu.clamp(Self::MIN_MTU, Self::MAX_MTU),
            updated_at: timestamp,
            next_probe: timestamp + Self::TIMEOUT_MS,
        }
    }

    /// Check if the entry has expired
    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time.saturating_sub(self.updated_at) > Self::TIMEOUT_MS
    }

    /// Check if we should probe for a larger MTU
    pub fn should_probe(&self, current_time: u64) -> bool {
        current_time >= self.next_probe && self.pmtu < Self::DEFAULT_MTU
    }

    /// RFC 1191: Get the next smaller MTU from the plateau list.
    /// Used when a router doesn't provide the next-hop MTU in ICMP.
    pub fn get_next_plateau(current_mtu: u16) -> u16 {
        // RFC 1191 Section 4: "A host MUST use the next smaller MTU from the following list"
        // List is recommended: 65535, 32000, 17914, 8166, 4352, 2048, 1492, 1006, 508, 296, 68.
        const PLATEAUS: &[u16] = &[
            65535, 32000, 17914, 8166, 4352, 2048, 1500, 1492, 1006, 576, 508, 296, 68,
        ];

        for &p in PLATEAUS {
            if p < current_mtu {
                return p;
            }
        }
        Self::MIN_MTU
    }
}

/// Path MTU Discovery cache
pub struct PmtuCache {
    /// PMTU entries keyed by destination IP
    entries: BTreeMap<Ipv4Address, PmtuEntry>,
    /// Maximum number of entries
    max_entries: usize,
    /// Statistics
    stats: PmtuStats,
}

/// PMTU statistics
#[derive(Debug, Default, Clone)]
pub struct PmtuStats {
    /// Number of PMTU discoveries
    pub discoveries: u64,
    /// Number of PMTU updates (reductions)
    pub reductions: u64,
    /// Number of cache hits
    pub hits: u64,
    /// Number of cache misses
    pub misses: u64,
}
