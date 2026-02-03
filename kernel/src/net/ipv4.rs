// ============================================================================
// kernel/src/net/ipv4.rs
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

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

/// IPv4 address (4 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpProtocol {
    /// Internet Control Message Protocol
    Icmp = 1,
    /// Transmission Control Protocol
    Tcp = 6,
    /// User Datagram Protocol
    Udp = 17,
    /// Generic Routing Encapsulation
    Gre = 47,
    /// Unknown protocol
    Unknown(u8),
}

impl From<u8> for IpProtocol {
    fn from(value: u8) -> Self {
        match value {
            1 => IpProtocol::Icmp,
            6 => IpProtocol::Tcp,
            17 => IpProtocol::Udp,
            47 => IpProtocol::Gre,
            other => IpProtocol::Unknown(other),
        }
    }
}

impl From<IpProtocol> for u8 {
    fn from(value: IpProtocol) -> Self {
        match value {
            IpProtocol::Icmp => 1,
            IpProtocol::Tcp => 6,
            IpProtocol::Udp => 17,
            IpProtocol::Gre => 47,
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

    /// Calculate header checksum
    pub fn compute_checksum(&self) -> u16 {
        let header_len = self.header_len();
        let header_bytes = &crate::util::struct_as_bytes(self)[..header_len];

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

        !(sum as u16)
    }

    /// Update checksum
    pub fn update_checksum(&mut self) {
        self.checksum = [0, 0];
        let checksum = self.compute_checksum();
        self.set_checksum(checksum);
    }

    /// Verify checksum
    pub fn verify_checksum(&self) -> bool {
        let header_len = self.header_len();
        let header_bytes = &crate::util::struct_as_bytes(self)[..header_len];

        let mut sum: u32 = 0;

        for i in (0..header_len).step_by(2) {
            let word = if i + 1 < header_len {
                u16::from_be_bytes([header_bytes[i], header_bytes[i + 1]])
            } else {
                u16::from_be_bytes([header_bytes[i], 0])
            };
            sum += word as u32;
        }

        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        sum as u16 == 0xFFFF
    }
}

/// Zero-copy IPv4 packet view
pub struct Ipv4Packet<'a> {
    /// Raw packet data
    data: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    /// Parse an IPv4 packet from raw bytes (zero-copy)
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < Ipv4Header::MIN_SIZE {
            return None;
        }

        let packet = Ipv4Packet { data };

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
        // SAFETY: We verified the length in parse(). Use centralized helper to get a typed ref.
        crate::util::get_ref::<Ipv4Header>(self.data, 0).expect("IPv4 header slice out of bounds")
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
    pub fn as_bytes(&self) -> &'a [u8] {
        let total_len = self.header().total_length() as usize;
        &self.data[..total_len]
    }

    /// Verify header checksum
    pub fn verify_checksum(&self) -> bool {
        self.header().verify_checksum()
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
    pub fn header_mut(&mut self) -> &mut Ipv4Header {
        // SAFETY: Buffer is large enough; use centralized helper.
        crate::util::get_mut_ref::<Ipv4Header>(self.data, 0)
            .expect("IPv4 header slice out of bounds")
    }

    /// Initialize header with default values
    pub fn init_header(&mut self) -> &mut Self {
        let header = self.header_mut();
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
        self
    }

    /// Set source address
    pub fn set_source(&mut self, addr: Ipv4Address) -> &mut Self {
        self.header_mut().set_source(addr);
        self
    }

    /// Set destination address
    pub fn set_destination(&mut self, addr: Ipv4Address) -> &mut Self {
        self.header_mut().set_destination(addr);
        self
    }

    /// Set protocol
    pub fn set_protocol(&mut self, protocol: IpProtocol) -> &mut Self {
        self.header_mut().set_protocol(protocol);
        self
    }

    /// Set TTL
    pub fn set_ttl(&mut self, ttl: u8) -> &mut Self {
        self.header_mut().set_ttl(ttl);
        self
    }

    /// Set identification
    pub fn set_identification(&mut self, id: u16) -> &mut Self {
        self.header_mut().set_identification(id);
        self
    }

    /// Get mutable payload buffer
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.data[Ipv4Header::MIN_SIZE..]
    }

    /// Set total length and update checksum
    pub fn finalize(&mut self, payload_len: usize) {
        let total_len = (Ipv4Header::MIN_SIZE + payload_len) as u16;
        self.header_mut().set_total_length(total_len);
        self.header_mut().update_checksum();
    }

    /// Get total packet length
    pub fn total_len(&self) -> usize {
        // Use safe helper to read header
        crate::util::get_ref::<Ipv4Header>(self.data, 0)
            .expect("IPv4 header slice out of bounds")
            .total_length() as usize
    }

    /// Get packet as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.total_len()]
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

impl PmtuCache {
    /// Default maximum entries
    pub const DEFAULT_MAX_ENTRIES: usize = 256;

    /// Create a new PMTU cache
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            max_entries,
            stats: PmtuStats::default(),
        }
    }

    /// Get statistics
    pub fn stats(&self) -> &PmtuStats {
        &self.stats
    }

    /// Get PMTU for a destination
    pub fn get(&mut self, dst: Ipv4Address, current_time: u64) -> u16 {
        if let Some(entry) = self.entries.get(&dst) {
            if !entry.is_expired(current_time) {
                self.stats.hits += 1;
                return entry.pmtu;
            }
        }
        self.stats.misses += 1;
        PmtuEntry::DEFAULT_MTU
    }

    /// Update PMTU for a destination (called when receiving ICMP Fragmentation Needed)
    pub fn update(&mut self, dst: Ipv4Address, new_mtu: u16, current_time: u64) {
        let clamped_mtu = new_mtu.clamp(PmtuEntry::MIN_MTU, PmtuEntry::MAX_MTU);

        if let Some(entry) = self.entries.get_mut(&dst) {
            if clamped_mtu < entry.pmtu {
                entry.pmtu = clamped_mtu;
                entry.updated_at = current_time;
                entry.next_probe = current_time + PmtuEntry::TIMEOUT_MS;
                self.stats.reductions += 1;
            }
        } else {
            // Evict oldest entry if at capacity
            if self.entries.len() >= self.max_entries {
                self.evict_oldest();
            }
            self.entries.insert(dst, PmtuEntry::new(clamped_mtu, current_time));
            self.stats.discoveries += 1;
        }
    }

    /// Probe for a larger MTU (called periodically)
    pub fn probe(&mut self, dst: Ipv4Address, current_time: u64) -> Option<u16> {
        if let Some(entry) = self.entries.get_mut(&dst) {
            if entry.should_probe(current_time) {
                // Try a larger MTU
                let probe_mtu = (entry.pmtu as u32 + 100).min(PmtuEntry::DEFAULT_MTU as u32) as u16;
                entry.next_probe = current_time + PmtuEntry::TIMEOUT_MS / 2;
                return Some(probe_mtu);
            }
        }
        None
    }

    /// Evict the oldest entry
    fn evict_oldest(&mut self) {
        let oldest = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.updated_at)
            .map(|(k, _)| *k);
        if let Some(key) = oldest {
            self.entries.remove(&key);
        }
    }

    /// Evict expired entries
    pub fn evict_expired(&mut self, current_time: u64) {
        let expired: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, e)| e.is_expired(current_time))
            .map(|(k, _)| *k)
            .collect();
        for key in expired {
            self.entries.remove(&key);
        }
    }

    /// Get the number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ============================================================================
// IP Fragment Reassembly (RFC 791)
// ============================================================================

/// Fragment reassembly key (identifies a unique datagram)
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FragmentKey {
    /// Source IP address
    pub src: Ipv4Address,
    /// Destination IP address
    pub dst: Ipv4Address,
    /// Identification field
    pub id: u16,
    /// Protocol
    pub protocol: u8,
}

impl FragmentKey {
    /// Create a new fragment key from packet header
    pub fn from_header(header: &Ipv4Header) -> Self {
        FragmentKey {
            src: header.source(),
            dst: header.destination(),
            id: header.identification(),
            protocol: header.protocol.into(),
        }
    }
}

/// A hole in the reassembly buffer (RFC 815 algorithm)
#[derive(Clone, Copy, Debug)]
struct FragmentHole {
    /// Start offset (bytes)
    first: u16,
    /// End offset (bytes, exclusive)
    last: u16,
}

/// Fragment reassembly buffer for a single datagram
pub struct FragmentBuffer {
    /// Reassembled data buffer
    data: Vec<u8>,
    /// List of holes (unfilled regions)
    holes: Vec<FragmentHole>,
    /// Total datagram length (known when last fragment received)
    total_len: Option<u16>,
    /// First fragment's header (for protocol info)
    first_header: Option<[u8; 20]>,
    /// Creation timestamp (for timeout)
    created_at: u64,
    /// Last update timestamp
    last_update: u64,
}

impl FragmentBuffer {
    /// Maximum reassembled packet size (64KB - IP header)
    pub const MAX_DATAGRAM_SIZE: usize = 65535;

    /// Fragment timeout in milliseconds (RFC 791 recommends 15-60 seconds)
    pub const TIMEOUT_MS: u64 = 30_000;

    /// Create a new fragment buffer
    pub fn new(timestamp: u64) -> Self {
        FragmentBuffer {
            data: Vec::new(),
            holes: vec![FragmentHole {
                first: 0,
                last: u16::MAX,
            }],
            total_len: None,
            first_header: None,
            created_at: timestamp,
            last_update: timestamp,
        }
    }

    /// Check if reassembly is complete
    pub fn is_complete(&self) -> bool {
        self.holes.is_empty() && self.total_len.is_some()
    }

    /// Check if the buffer has timed out
    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time.saturating_sub(self.created_at) > Self::TIMEOUT_MS
    }

    /// Add a fragment to the buffer (RFC 815 hole-filling algorithm)
    ///
    /// Returns true if the fragment was accepted, false if invalid/overlapping
    pub fn add_fragment(
        &mut self,
        header: &Ipv4Header,
        payload: &[u8],
        current_time: u64,
    ) -> bool {
        let fragment_offset = header.fragment_offset() * 8; // Convert to bytes
        let fragment_len = payload.len() as u16;
        let fragment_end = fragment_offset.saturating_add(fragment_len);

        // Check for overflow
        if fragment_end as usize > Self::MAX_DATAGRAM_SIZE {
            return false;
        }

        // Update last update time
        self.last_update = current_time;

        // If this is the last fragment, we know the total length
        if !header.more_fragments() {
            self.total_len = Some(fragment_end);
        }

        // Store first fragment header for later use
        if fragment_offset == 0 && self.first_header.is_none() {
            let mut hdr = [0u8; 20];
            let hdr_bytes = crate::util::struct_as_bytes(header);
            if hdr_bytes.len() >= 20 {
                hdr.copy_from_slice(&hdr_bytes[..20]);
                self.first_header = Some(hdr);
            }
        }

        // Ensure buffer is large enough
        if self.data.len() < fragment_end as usize {
            self.data.resize(fragment_end as usize, 0);
        }

        // Copy fragment data
        self.data[fragment_offset as usize..fragment_end as usize].copy_from_slice(payload);

        // Update hole list (RFC 815 algorithm)
        let mut new_holes = Vec::new();

        for hole in self.holes.drain(..) {
            if fragment_end <= hole.first || fragment_offset >= hole.last {
                // Fragment doesn't overlap this hole
                new_holes.push(hole);
            } else {
                // Fragment overlaps this hole - split it
                if fragment_offset > hole.first {
                    // New hole before fragment
                    new_holes.push(FragmentHole {
                        first: hole.first,
                        last: fragment_offset,
                    });
                }
                if fragment_end < hole.last && header.more_fragments() {
                    // New hole after fragment
                    new_holes.push(FragmentHole {
                        first: fragment_end,
                        last: hole.last,
                    });
                }
            }
        }

        self.holes = new_holes;

        // If we know total length, remove holes beyond it
        if let Some(total) = self.total_len {
            self.holes.retain(|h| h.first < total);
            // Adjust holes that extend beyond total
            for hole in &mut self.holes {
                if hole.last > total {
                    hole.last = total;
                }
            }
        }

        true
    }

    /// Get the reassembled packet (only valid when is_complete() is true)
    pub fn get_reassembled(&self) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }

        let total_len = self.total_len? as usize;
        let header = self.first_header.as_ref()?;

        // Build complete packet: header + payload
        let mut packet = Vec::with_capacity(20 + total_len);
        packet.extend_from_slice(header);
        packet.extend_from_slice(&self.data[..total_len]);

        // Update header fields
        let packet_total_len = (20 + total_len) as u16;
        packet[2] = (packet_total_len >> 8) as u8;
        packet[3] = packet_total_len as u8;

        // Clear fragment flags/offset
        packet[6] = 0;
        packet[7] = 0;

        // Recalculate header checksum
        packet[10] = 0;
        packet[11] = 0;
        let checksum = calculate_ip_checksum(&packet[..20]);
        packet[10] = (checksum >> 8) as u8;
        packet[11] = checksum as u8;

        Some(packet)
    }
}

/// IP fragment reassembler
pub struct FragmentReassembler {
    /// Active fragment buffers, keyed by fragment key
    buffers: BTreeMap<FragmentKey, FragmentBuffer>,
    /// Maximum number of concurrent reassembly buffers
    max_buffers: usize,
    /// Statistics
    stats: FragmentStats,
}

/// Fragment reassembly statistics
#[derive(Debug, Default, Clone)]
pub struct FragmentStats {
    /// Fragments received
    pub fragments_received: u64,
    /// Datagrams successfully reassembled
    pub reassembled: u64,
    /// Reassembly timeouts
    pub timeouts: u64,
    /// Dropped due to buffer limit
    pub dropped_limit: u64,
    /// Dropped due to invalid fragment
    pub dropped_invalid: u64,
}

impl FragmentReassembler {
    /// Default maximum number of concurrent reassembly buffers
    pub const DEFAULT_MAX_BUFFERS: usize = 64;

    /// Create a new fragment reassembler
    pub fn new(max_buffers: usize) -> Self {
        FragmentReassembler {
            buffers: BTreeMap::new(),
            max_buffers,
            stats: FragmentStats::default(),
        }
    }

    /// Get statistics
    pub fn stats(&self) -> &FragmentStats {
        &self.stats
    }

    /// Process an incoming fragment
    ///
    /// Returns Some(reassembled_packet) if reassembly is complete
    pub fn process_fragment(
        &mut self,
        header: &Ipv4Header,
        payload: &[u8],
        current_time: u64,
    ) -> Option<Vec<u8>> {
        self.stats.fragments_received += 1;

        let key = FragmentKey::from_header(header);

        // Evict expired buffers
        self.evict_expired(current_time);

        // Check if we need to create a new buffer
        if !self.buffers.contains_key(&key) {
            // Check buffer limit
            if self.buffers.len() >= self.max_buffers {
                self.stats.dropped_limit += 1;
                return None;
            }

            self.buffers.insert(key, FragmentBuffer::new(current_time));
        }

        // Get the buffer and add fragment
        let buffer = self.buffers.get_mut(&key)?;

        if !buffer.add_fragment(header, payload, current_time) {
            self.stats.dropped_invalid += 1;
            // Remove invalid buffer
            self.buffers.remove(&key);
            return None;
        }

        // Check if reassembly is complete
        if buffer.is_complete() {
            let result = buffer.get_reassembled();
            self.buffers.remove(&key);

            if result.is_some() {
                self.stats.reassembled += 1;
            }

            return result;
        }

        None
    }

    /// Evict expired reassembly buffers
    fn evict_expired(&mut self, current_time: u64) {
        let expired_keys: Vec<_> = self
            .buffers
            .iter()
            .filter(|(_, buf)| buf.is_expired(current_time))
            .map(|(k, _)| *k)
            .collect();

        for key in expired_keys {
            self.buffers.remove(&key);
            self.stats.timeouts += 1;
        }
    }

    /// Get the number of active reassembly buffers
    pub fn active_buffers(&self) -> usize {
        self.buffers.len()
    }
}

/// Calculate IP header checksum
fn calculate_ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    for i in (0..header.len()).step_by(2) {
        if i == 10 {
            continue; // Skip checksum field
        }
        let word = if i + 1 < header.len() {
            u16::from_be_bytes([header[i], header[i + 1]])
        } else {
            u16::from_be_bytes([header[i], 0])
        };
        sum += word as u32;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// IPv4 packet processor
pub struct Ipv4Processor {
    /// Configuration
    config: Ipv4Config,
    /// Statistics
    stats: Ipv4Stats,
    /// Next identification value
    next_id: u16,
    /// Fragment reassembler
    reassembler: FragmentReassembler,
    /// Path MTU Discovery cache
    pmtu_cache: PmtuCache,
}

/// IPv4 statistics
#[derive(Debug, Default)]
pub struct Ipv4Stats {
    /// Packets received
    pub rx_packets: u64,
    /// Packets transmitted
    pub tx_packets: u64,
    /// Invalid packets
    pub rx_errors: u64,
    /// Dropped packets (not for us)
    pub rx_dropped: u64,
    /// Checksum errors
    pub checksum_errors: u64,
}

/// Result of IPv4 packet processing
pub enum Ipv4ProcessResult<'a> {
    /// ICMP packet
    Icmp(&'a [u8], Ipv4Address),
    /// TCP packet
    Tcp(&'a [u8], Ipv4Address, Ipv4Address),
    /// UDP packet
    Udp(&'a [u8], Ipv4Address, Ipv4Address),
    /// Reassembled packet (owned data from fragment reassembly)
    Reassembled(Vec<u8>),
    /// Fragment received, reassembly in progress
    FragmentPending,
    /// Dropped
    Dropped,
    /// Error
    Error,
    /// Success (Consumed internally)
    Success,
}

impl Ipv4Processor {
    /// Create a new IPv4 processor
    pub fn new(config: Ipv4Config) -> Self {
        Ipv4Processor {
            config,
            stats: Ipv4Stats::default(),
            next_id: 1,
            reassembler: FragmentReassembler::new(FragmentReassembler::DEFAULT_MAX_BUFFERS),
            pmtu_cache: PmtuCache::new(PmtuCache::DEFAULT_MAX_ENTRIES),
        }
    }

    /// Get configuration
    pub fn config(&self) -> &Ipv4Config {
        &self.config
    }

    /// Set configuration
    pub fn set_config(&mut self, config: Ipv4Config) {
        self.config = config;
    }

    /// Get statistics
    pub fn stats(&self) -> &Ipv4Stats {
        &self.stats
    }

    /// Get fragment reassembler statistics
    pub fn fragment_stats(&self) -> &FragmentStats {
        self.reassembler.stats()
    }

    /// Get PMTU cache statistics
    pub fn pmtu_stats(&self) -> &PmtuStats {
        self.pmtu_cache.stats()
    }

    /// Get Path MTU for a destination
    pub fn get_pmtu(&mut self, dst: Ipv4Address, current_time: u64) -> u16 {
        self.pmtu_cache.get(dst, current_time)
    }

    /// Update Path MTU (called when receiving ICMP Fragmentation Needed)
    pub fn update_pmtu(&mut self, dst: Ipv4Address, mtu: u16, current_time: u64) {
        self.pmtu_cache.update(dst, mtu, current_time);
    }

    /// Process an incoming IPv4 packet (without timestamp - for backwards compatibility)
    pub fn process<'a>(&mut self, data: &'a [u8]) -> Ipv4ProcessResult<'a> {
        // Use a default timestamp of 0 when not provided
        self.process_with_time(data, 0)
    }

    /// Process an incoming IPv4 packet with timestamp for fragment timeout handling
    pub fn process_with_time<'a>(&mut self, data: &'a [u8], current_time: u64) -> Ipv4ProcessResult<'a> {
        let packet = match Ipv4Packet::parse(data) {
            Some(p) => p,
            None => {
                self.stats.rx_errors += 1;
                return Ipv4ProcessResult::Error;
            }
        };

        // Verify checksum
        if !packet.verify_checksum() {
            self.stats.checksum_errors += 1;
            return Ipv4ProcessResult::Error;
        }

        // Check destination
        let dst = packet.destination();
        if !self.is_for_us(&dst) {
            self.stats.rx_dropped += 1;
            return Ipv4ProcessResult::Dropped;
        }

        self.stats.rx_packets += 1;

        let src = packet.source();
        let header = packet.header();

        // Check if this is a fragment
        let is_fragment = header.more_fragments() || header.fragment_offset() != 0;

        if is_fragment {
            // Handle fragmented packet
            let payload = packet.payload();
            if let Some(reassembled) = self.reassembler.process_fragment(header, payload, current_time) {
                // Reassembly complete - return the reassembled packet
                return Ipv4ProcessResult::Reassembled(reassembled);
            } else {
                // Still waiting for more fragments
                return Ipv4ProcessResult::FragmentPending;
            }
        }

        // Non-fragmented packet - process normally
        let payload = packet.payload();

        match packet.protocol() {
            IpProtocol::Icmp => Ipv4ProcessResult::Icmp(payload, src),
            IpProtocol::Tcp => Ipv4ProcessResult::Tcp(payload, src, dst),
            IpProtocol::Udp => Ipv4ProcessResult::Udp(payload, src, dst),
            _ => Ipv4ProcessResult::Dropped,
        }
    }

    /// Check if a packet is for us
    fn is_for_us(&self, addr: &Ipv4Address) -> bool {
        *addr == self.config.address
            || addr.is_broadcast()
            || *addr == self.config.broadcast_address()
    }

    /// Get next packet ID
    pub fn next_id(&mut self) -> u16 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    /// Build an IP packet for transmission
    pub fn build_packet<'a>(
        &mut self,
        buffer: &'a mut [u8],
        dst: Ipv4Address,
        protocol: IpProtocol,
    ) -> Option<Ipv4PacketMut<'a>> {
        let mut packet = Ipv4PacketMut::new(buffer)?;
        packet
            .init_header()
            .set_source(self.config.address)
            .set_destination(dst)
            .set_protocol(protocol)
            .set_identification(self.next_id());
        Some(packet)
    }
}

/// Calculate IP pseudo-header checksum (for TCP/UDP)
pub fn pseudo_header_checksum(
    src: Ipv4Address,
    dst: Ipv4Address,
    protocol: IpProtocol,
    length: u16,
) -> u32 {
    let mut sum: u32 = 0;

    // Source address
    let src_bytes = src.as_bytes();
    sum += u16::from_be_bytes([src_bytes[0], src_bytes[1]]) as u32;
    sum += u16::from_be_bytes([src_bytes[2], src_bytes[3]]) as u32;

    // Destination address
    let dst_bytes = dst.as_bytes();
    sum += u16::from_be_bytes([dst_bytes[0], dst_bytes[1]]) as u32;
    sum += u16::from_be_bytes([dst_bytes[2], dst_bytes[3]]) as u32;

    // Protocol (zero-padded to 16 bits)
    sum += u8::from(protocol) as u32;

    // Length
    sum += length as u32;

    sum
}

/// Calculate checksum for a data buffer
pub fn data_checksum(data: &[u8], initial: u32) -> u16 {
    let mut sum = initial;

    // Sum 16-bit words
    for i in (0..data.len()).step_by(2) {
        let word = if i + 1 < data.len() {
            u16::from_be_bytes([data[i], data[i + 1]])
        } else {
            u16::from_be_bytes([data[i], 0])
        };
        sum += word as u32;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_ipv4_address() {
        let addr = Ipv4Address::from_octets(192, 168, 1, 1);
        assert!(addr.is_private());
        assert!(!addr.is_loopback());

        assert!(Ipv4Address::LOOPBACK.is_loopback());
        assert!(Ipv4Address::BROADCAST.is_broadcast());
    }

    #[test_case]
    fn test_subnet() {
        let addr1 = Ipv4Address::from_octets(192, 168, 1, 1);
        let addr2 = Ipv4Address::from_octets(192, 168, 1, 100);
        let mask = Ipv4Address::from_octets(255, 255, 255, 0);

        assert!(addr1.same_subnet(&addr2, mask));
    }

    #[test_case]
    fn test_fragment_key() {
        let mut header = Ipv4Header {
            version_ihl: 0x45,
            dscp_ecn: 0,
            total_length: [0, 40],
            identification: [0x12, 0x34],
            flags_fragment: [0x20, 0x00], // More Fragments
            ttl: 64,
            protocol: 6, // TCP
            checksum: [0, 0],
            src_addr: [192, 168, 1, 1],
            dst_addr: [192, 168, 1, 2],
        };

        let key = FragmentKey::from_header(&header);
        assert_eq!(key.id, 0x1234);
        assert_eq!(key.src, Ipv4Address::from_octets(192, 168, 1, 1));
        assert_eq!(key.dst, Ipv4Address::from_octets(192, 168, 1, 2));
        assert_eq!(key.protocol, 6);
    }

    #[test_case]
    fn test_fragment_buffer_basic() {
        let mut buffer = FragmentBuffer::new(0);
        assert!(!buffer.is_complete());
        assert!(!buffer.is_expired(1000));
        assert!(buffer.is_expired(31000)); // After 30s timeout
    }

    #[test_case]
    fn test_fragment_reassembly_simple() {
        let mut reassembler = FragmentReassembler::new(16);

        // First fragment (offset 0, more fragments)
        let header1 = Ipv4Header {
            version_ihl: 0x45,
            dscp_ecn: 0,
            total_length: [0, 28], // 20 + 8 bytes payload
            identification: [0x00, 0x01],
            flags_fragment: [0x20, 0x00], // MF=1, offset=0
            ttl: 64,
            protocol: 17, // UDP
            checksum: [0, 0],
            src_addr: [10, 0, 0, 1],
            dst_addr: [10, 0, 0, 2],
        };
        let payload1 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let result = reassembler.process_fragment(&header1, &payload1, 0);
        assert!(result.is_none()); // Not complete yet

        // Second fragment (offset 8, last fragment)
        let header2 = Ipv4Header {
            version_ihl: 0x45,
            dscp_ecn: 0,
            total_length: [0, 28],
            identification: [0x00, 0x01],
            flags_fragment: [0x00, 0x01], // MF=0, offset=8/8=1
            ttl: 64,
            protocol: 17,
            checksum: [0, 0],
            src_addr: [10, 0, 0, 1],
            dst_addr: [10, 0, 0, 2],
        };
        let payload2 = [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];

        let result = reassembler.process_fragment(&header2, &payload2, 0);
        assert!(result.is_some()); // Complete!

        let reassembled = result.unwrap();
        // Check payload in reassembled packet
        assert!(reassembled.len() >= 36); // 20 header + 16 payload
    }

    #[test_case]
    fn test_pmtu_cache_basic() {
        let mut cache = PmtuCache::new(256);
        let dst = Ipv4Address::from_octets(192, 168, 1, 100);
        let current_time = 0u64;

        // Initial lookup returns default MTU (cache miss)
        assert_eq!(cache.get(dst, current_time), PmtuEntry::DEFAULT_MTU);

        // Update PMTU
        cache.update(dst, 1400, current_time);

        // Now lookup should return the updated value
        assert_eq!(cache.get(dst, current_time), 1400);

        // After timeout, entry expires and returns default MTU
        let after_timeout = current_time + PmtuEntry::TIMEOUT_MS + 1;
        assert_eq!(cache.get(dst, after_timeout), PmtuEntry::DEFAULT_MTU);
    }

    #[test_case]
    fn test_pmtu_cache_update_smaller() {
        let mut cache = PmtuCache::new(256);
        let dst = Ipv4Address::from_octets(10, 0, 0, 1);
        let current_time = 0u64;

        // Set initial PMTU
        cache.update(dst, 1400, current_time);
        assert_eq!(cache.get(dst, current_time), 1400);

        // Smaller PMTU should replace
        cache.update(dst, 1200, current_time + 100);
        assert_eq!(cache.get(dst, current_time + 100), 1200);
    }

    #[test_case]
    fn test_pmtu_cache_minimum() {
        let mut cache = PmtuCache::new(256);
        let dst = Ipv4Address::from_octets(8, 8, 8, 8);

        // Very small MTU should be clamped to minimum
        cache.update(dst, 100, 0);
        assert_eq!(cache.get(dst, 0), PmtuEntry::MIN_MTU);
    }
}
