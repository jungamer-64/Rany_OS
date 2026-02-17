// ============================================================================
// kernel/src/net/ipv6.rs
// ============================================================================
//! IPv6 Protocol Implementation for ExoRust
//!
//! Zero-copy IPv6 packet processing as specified in RFC 8200.
//!
//! ## Features
//! - Fixed 40-byte header (no header checksum)
//! - Extension header chain traversal
//! - IPv6 pseudo-header checksum (RFC 8200 Section 8.1)
//! - EUI-64 link-local address generation
//! - Solicited-node multicast address computation

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

use super::ipv4::IpProtocol;

// =====================================================
// IPv6 Address
// =====================================================

/// IPv6 address (16 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct Ipv6Address([u8; 16]);

impl Ipv6Address {
    /// Unspecified address (::)
    pub const UNSPECIFIED: Self = Self([0; 16]);

    /// Loopback address (::1)
    pub const LOOPBACK: Self = Self([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    /// All-nodes link-local multicast (ff02::1)
    pub const ALL_NODES_LINK_LOCAL: Self =
        Self([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    /// All-routers link-local multicast (ff02::2)
    pub const ALL_ROUTERS_LINK_LOCAL: Self =
        Self([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    /// Solicited-node multicast prefix (ff02::1:ff00:0/104)
    pub const SOLICITED_NODE_PREFIX: Self =
        Self([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xff, 0, 0, 0]);

    /// Create from raw octets
    #[inline]
    pub const fn new(octets: [u8; 16]) -> Self {
        Self(octets)
    }

    /// Create from two 64-bit halves (network byte order)
    #[inline]
    pub const fn from_u64_pair(high: u64, low: u64) -> Self {
        let h = high.to_be_bytes();
        let l = low.to_be_bytes();
        Self([
            h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
            l[0], l[1], l[2], l[3], l[4], l[5], l[6], l[7],
        ])
    }

    /// Create link-local address from MAC address using EUI-64
    ///
    /// fe80::xxxx:xxff:fexx:xxxx (with 7th bit flipped)
    pub const fn from_eui64(mac: &[u8; 6]) -> Self {
        Self([
            0xfe, 0x80, 0, 0, 0, 0, 0, 0,
            mac[0] ^ 0x02, mac[1], mac[2], 0xff,
            0xfe, mac[3], mac[4], mac[5],
        ])
    }

    /// Get raw bytes
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Get raw octets
    #[inline]
    pub const fn octets(&self) -> [u8; 16] {
        self.0
    }

    /// Check if unspecified (::)
    #[inline]
    pub const fn is_unspecified(&self) -> bool {
        let o = &self.0;
        o[0] == 0 && o[1] == 0 && o[2] == 0 && o[3] == 0
            && o[4] == 0 && o[5] == 0 && o[6] == 0 && o[7] == 0
            && o[8] == 0 && o[9] == 0 && o[10] == 0 && o[11] == 0
            && o[12] == 0 && o[13] == 0 && o[14] == 0 && o[15] == 0
    }

    /// Check if loopback (::1)
    #[inline]
    pub const fn is_loopback(&self) -> bool {
        let o = &self.0;
        o[0] == 0 && o[1] == 0 && o[2] == 0 && o[3] == 0
            && o[4] == 0 && o[5] == 0 && o[6] == 0 && o[7] == 0
            && o[8] == 0 && o[9] == 0 && o[10] == 0 && o[11] == 0
            && o[12] == 0 && o[13] == 0 && o[14] == 0 && o[15] == 1
    }

    /// Check if multicast (ff00::/8)
    #[inline]
    pub const fn is_multicast(&self) -> bool {
        self.0[0] == 0xff
    }

    /// Check if link-local unicast (fe80::/10)
    #[inline]
    pub const fn is_unicast_link_local(&self) -> bool {
        self.0[0] == 0xfe && (self.0[1] & 0xc0) == 0x80
    }

    /// Check if link-local (unicast or multicast with scope 2)
    #[inline]
    pub const fn is_link_local(&self) -> bool {
        self.is_unicast_link_local() || (self.is_multicast() && (self.0[1] & 0x0f) == 0x02)
    }

    /// Check if global unicast (not multicast, not link-local, not loopback, not unspecified)
    #[inline]
    pub fn is_global(&self) -> bool {
        !self.is_unspecified()
            && !self.is_loopback()
            && !self.is_multicast()
            && !self.is_unicast_link_local()
    }

    /// Compute solicited-node multicast address for this address
    ///
    /// ff02::1:ffXX:XXXX (last 3 bytes of unicast address)
    #[inline]
    pub const fn solicited_node(&self) -> Self {
        Self([
            0xff, 0x02, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0x01, 0xff,
            self.0[13], self.0[14], self.0[15],
        ])
    }

    /// Convert multicast IPv6 address to Ethernet multicast MAC
    ///
    /// 33:33:xx:xx:xx:xx (last 4 bytes of IPv6 multicast)
    #[inline]
    pub const fn multicast_mac(&self) -> [u8; 6] {
        [0x33, 0x33, self.0[12], self.0[13], self.0[14], self.0[15]]
    }

    /// Check if this is a solicited-node multicast address (ff02::1:ff00:0/104)
    #[inline]
    pub const fn is_solicited_node_multicast(&self) -> bool {
        self.0[0] == 0xff && self.0[1] == 0x02
            && self.0[2] == 0 && self.0[3] == 0
            && self.0[4] == 0 && self.0[5] == 0
            && self.0[6] == 0 && self.0[7] == 0
            && self.0[8] == 0 && self.0[9] == 0
            && self.0[10] == 0 && self.0[11] == 0x01
            && self.0[12] == 0xff
    }
}

impl fmt::Debug for Ipv6Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

/// Find the start and length of the longest consecutive zero-word run (≥ 2) for :: compression (RFC 5952)
fn find_longest_zero_run(words: &[u16; 8]) -> (usize, usize) {
    let mut best_start = 8usize;
    let mut best_len = 0usize;
    let mut cur_start = 0usize;
    let mut cur_len = 0usize;

    for i in 0..8 {
        if words[i] == 0 {
            if cur_len == 0 {
                cur_start = i;
            }
            cur_len += 1;
        } else {
            if cur_len > best_len && cur_len >= 2 {
                best_start = cur_start;
                best_len = cur_len;
            }
            cur_len = 0;
        }
    }
    if cur_len > best_len && cur_len >= 2 {
        best_start = cur_start;
        best_len = cur_len;
    }

    (best_start, best_len)
}

/// IPv6アドレスの1ワードを出力する
fn write_ipv6_word(f: &mut fmt::Formatter<'_>, word: u16, first: bool) -> fmt::Result {
    if !first {
        write!(f, ":")?;
    }
    write!(f, "{:x}", word)
}

/// Write IPv6 address words with :: compression
fn write_ipv6_compressed(f: &mut fmt::Formatter<'_>, words: &[u16; 8], best_start: usize, best_len: usize) -> fmt::Result {
    let mut i = 0;
    let mut first = true;
    while i < 8 {
        if i == best_start && best_len > 0 {
            if i == 0 {
                write!(f, "::")?;
            } else {
                write!(f, ":")?;
            }
            i += best_len;
            first = i >= 8;
            continue;
        }
        write_ipv6_word(f, words[i], first)?;
        first = false;
        i += 1;
    }
    Ok(())
}

impl fmt::Display for Ipv6Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let words: [u16; 8] = [
            u16::from_be_bytes([self.0[0], self.0[1]]),
            u16::from_be_bytes([self.0[2], self.0[3]]),
            u16::from_be_bytes([self.0[4], self.0[5]]),
            u16::from_be_bytes([self.0[6], self.0[7]]),
            u16::from_be_bytes([self.0[8], self.0[9]]),
            u16::from_be_bytes([self.0[10], self.0[11]]),
            u16::from_be_bytes([self.0[12], self.0[13]]),
            u16::from_be_bytes([self.0[14], self.0[15]]),
        ];

        let (best_start, best_len) = find_longest_zero_run(&words);
        write_ipv6_compressed(f, &words, best_start, best_len)
    }
}

// =====================================================
// IPv6 Header
// =====================================================

/// IPv6 header size (fixed 40 bytes)
pub const IPV6_HEADER_SIZE: usize = 40;

/// IPv6 header (RFC 8200, 40 bytes fixed)
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Ipv6Header {
    /// Version (4 bits) + Traffic Class (8 bits) + Flow Label (20 bits)
    pub version_tc_fl: [u8; 4],
    /// Payload Length (big-endian, excludes header)
    pub payload_length: [u8; 2],
    /// Next Header (same as IPv4 Protocol field)
    pub next_header: u8,
    /// Hop Limit (decremented per hop, like TTL)
    pub hop_limit: u8,
    /// Source Address (16 bytes)
    pub src_addr: [u8; 16],
    /// Destination Address (16 bytes)
    pub dst_addr: [u8; 16],
}

impl Ipv6Header {
    /// Get version field (should be 6)
    #[inline]
    pub fn version(&self) -> u8 {
        self.version_tc_fl[0] >> 4
    }

    /// Get Traffic Class (8 bits, similar to IPv4 DSCP+ECN)
    #[inline]
    pub fn traffic_class(&self) -> u8 {
        ((self.version_tc_fl[0] & 0x0f) << 4) | (self.version_tc_fl[1] >> 4)
    }

    /// Get Flow Label (20 bits)
    #[inline]
    pub fn flow_label(&self) -> u32 {
        let b1 = (self.version_tc_fl[1] & 0x0f) as u32;
        let b2 = self.version_tc_fl[2] as u32;
        let b3 = self.version_tc_fl[3] as u32;
        (b1 << 16) | (b2 << 8) | b3
    }

    /// Get payload length (excludes 40-byte header)
    #[inline]
    pub fn payload_length(&self) -> u16 {
        u16::from_be_bytes(self.payload_length)
    }

    /// Get next header (protocol)
    #[inline]
    pub fn next_header(&self) -> IpProtocol {
        IpProtocol::from(self.next_header)
    }

    /// Get hop limit
    #[inline]
    pub fn hop_limit(&self) -> u8 {
        self.hop_limit
    }

    /// Get source address
    #[inline]
    pub fn source(&self) -> Ipv6Address {
        Ipv6Address::new(self.src_addr)
    }

    /// Get destination address
    #[inline]
    pub fn destination(&self) -> Ipv6Address {
        Ipv6Address::new(self.dst_addr)
    }

    // === Setters ===

    /// Set version + traffic class + flow label
    #[inline]
    pub fn set_version_tc_fl(&mut self, version: u8, tc: u8, fl: u32) {
        self.version_tc_fl[0] = (version << 4) | (tc >> 4);
        self.version_tc_fl[1] = (tc << 4) | ((fl >> 16) as u8 & 0x0f);
        self.version_tc_fl[2] = (fl >> 8) as u8;
        self.version_tc_fl[3] = fl as u8;
    }

    /// Set payload length
    #[inline]
    pub fn set_payload_length(&mut self, len: u16) {
        self.payload_length = len.to_be_bytes();
    }

    /// Set next header (protocol)
    #[inline]
    pub fn set_next_header(&mut self, protocol: IpProtocol) {
        self.next_header = u8::from(protocol);
    }

    /// Set hop limit
    #[inline]
    pub fn set_hop_limit(&mut self, limit: u8) {
        self.hop_limit = limit;
    }

    /// Set source address
    #[inline]
    pub fn set_source(&mut self, addr: &Ipv6Address) {
        self.src_addr = *addr.as_bytes();
    }

    /// Set destination address
    #[inline]
    pub fn set_destination(&mut self, addr: &Ipv6Address) {
        self.dst_addr = *addr.as_bytes();
    }
}

// =====================================================
// IPv6 Packet (read-only zero-copy view)
// =====================================================

/// Zero-copy IPv6 packet view (read-only)
pub struct Ipv6Packet<'a> {
    data: &'a [u8],
}

impl<'a> Ipv6Packet<'a> {
    /// Parse an IPv6 packet from raw data
    ///
    /// Validates: minimum length, version == 6, payload length consistency
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < IPV6_HEADER_SIZE {
            return None;
        }

        // Version check (upper 4 bits of first byte)
        if (data[0] >> 4) != 6 {
            return None;
        }

        // Payload length check
        let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
        if data.len() < IPV6_HEADER_SIZE + payload_len {
            return None;
        }

        Some(Self { data })
    }

    /// Get header reference (zero-copy)
    #[inline]
    pub fn header(&self) -> &Ipv6Header {
        // Safety: parse() validated that data.len() >= IPV6_HEADER_SIZE
        crate::util::get_ref::<Ipv6Header>(self.data, 0).unwrap()
    }

    /// Get payload (everything after the 40-byte header)
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let payload_len = self.header().payload_length() as usize;
        &self.data[IPV6_HEADER_SIZE..IPV6_HEADER_SIZE + payload_len]
    }

    /// Get source address
    #[inline]
    pub fn source(&self) -> Ipv6Address {
        self.header().source()
    }

    /// Get destination address
    #[inline]
    pub fn destination(&self) -> Ipv6Address {
        self.header().destination()
    }

    /// Get next header (protocol)
    #[inline]
    pub fn next_header(&self) -> IpProtocol {
        self.header().next_header()
    }

    /// Get hop limit
    #[inline]
    pub fn hop_limit(&self) -> u8 {
        self.header().hop_limit()
    }

    /// Get raw bytes
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        let total = IPV6_HEADER_SIZE + self.header().payload_length() as usize;
        &self.data[..total]
    }

    /// Get total packet length
    #[inline]
    pub fn total_length(&self) -> usize {
        IPV6_HEADER_SIZE + self.header().payload_length() as usize
    }

    /// Skip extension headers and find the upper-layer payload
    ///
    /// Returns (final_next_header, payload_offset_within_payload)
    pub fn skip_extension_headers(&self) -> (IpProtocol, &'a [u8]) {
        let payload = self.payload();
        skip_extension_headers(self.next_header(), payload)
    }
}

// =====================================================
// IPv6 Packet (mutable zero-copy view)
// =====================================================

/// Zero-copy IPv6 packet view (mutable, for building packets)
pub struct Ipv6PacketMut<'a> {
    data: &'a mut [u8],
}

impl<'a> Ipv6PacketMut<'a> {
    /// Create a new mutable packet view
    ///
    /// Buffer must be at least IPV6_HEADER_SIZE bytes
    pub fn new(buffer: &'a mut [u8]) -> Option<Self> {
        if buffer.len() < IPV6_HEADER_SIZE {
            return None;
        }
        Some(Self { data: buffer })
    }

    /// Initialize header with defaults (version=6, hop_limit=64)
    pub fn init_header(&mut self) {
        let header = self.header_mut();
        header.set_version_tc_fl(6, 0, 0);
        header.set_payload_length(0);
        header.set_next_header(IpProtocol::Tcp); // default, caller should override
        header.set_hop_limit(64);
        header.src_addr = [0; 16];
        header.dst_addr = [0; 16];
    }

    /// Get mutable header reference
    #[inline]
    pub fn header_mut(&mut self) -> &mut Ipv6Header {
        crate::util::get_mut_ref::<Ipv6Header>(self.data, 0).unwrap()
    }

    /// Get immutable header reference
    #[inline]
    pub fn header(&self) -> &Ipv6Header {
        crate::util::get_ref::<Ipv6Header>(self.data, 0).unwrap()
    }

    /// Set source address
    #[inline]
    pub fn set_source(&mut self, addr: &Ipv6Address) {
        self.header_mut().set_source(addr);
    }

    /// Set destination address
    #[inline]
    pub fn set_destination(&mut self, addr: &Ipv6Address) {
        self.header_mut().set_destination(addr);
    }

    /// Set next header (protocol)
    #[inline]
    pub fn set_next_header(&mut self, protocol: IpProtocol) {
        self.header_mut().set_next_header(protocol);
    }

    /// Set hop limit
    #[inline]
    pub fn set_hop_limit(&mut self, limit: u8) {
        self.header_mut().set_hop_limit(limit);
    }

    /// Set payload length
    #[inline]
    pub fn set_payload_length(&mut self, len: u16) {
        self.header_mut().set_payload_length(len);
    }

    /// Get mutable payload slice
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.data[IPV6_HEADER_SIZE..]
    }

    /// Get the full buffer as bytes
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..IPV6_HEADER_SIZE + self.header().payload_length() as usize]
    }

    /// Finalize packet (set payload length based on actual data written)
    pub fn finalize(&mut self, payload_len: usize) {
        self.header_mut().set_payload_length(payload_len as u16);
    }
}

// =====================================================
// Extension Header Traversal
// =====================================================

/// Known extension header types that can be skipped
const EXT_HEADER_HOP_BY_HOP: u8 = 0;
const EXT_HEADER_ROUTING: u8 = 43;
const EXT_HEADER_FRAGMENT: u8 = 44;
const EXT_HEADER_DESTINATION: u8 = 60;
const EXT_HEADER_NO_NEXT: u8 = 59;

/// Skip extension headers in a payload and return the final protocol and remaining data
///
/// Extension headers use a common format:
/// - Byte 0: Next Header
/// - Byte 1: Header Extension Length (in 8-byte units, excluding first 8 bytes)
/// - Exception: Fragment Header is always 8 bytes (length field has different meaning)
pub fn skip_extension_headers<'a>(
    mut next_header: IpProtocol,
    mut data: &'a [u8],
) -> (IpProtocol, &'a [u8]) {
    loop {
        let nh = u8::from(next_header);

        match nh {
            EXT_HEADER_HOP_BY_HOP | EXT_HEADER_ROUTING | EXT_HEADER_DESTINATION => {
                // Standard extension header format
                if data.len() < 2 {
                    return (next_header, data);
                }
                let ext_next = data[0];
                let ext_len = (data[1] as usize + 1) * 8; // length in 8-byte units + first 8 bytes
                if data.len() < ext_len {
                    return (next_header, data);
                }
                next_header = IpProtocol::from(ext_next);
                data = &data[ext_len..];
            }
            EXT_HEADER_FRAGMENT => {
                // Fragment header: always 8 bytes
                if data.len() < 8 {
                    return (next_header, data);
                }
                let ext_next = data[0];
                next_header = IpProtocol::from(ext_next);
                data = &data[8..];
                // Note: actual fragment reassembly not implemented yet
            }
            EXT_HEADER_NO_NEXT => {
                // No next header — end of chain
                return (next_header, data);
            }
            _ => {
                // Upper-layer protocol (TCP, UDP, ICMPv6, etc.)
                return (next_header, data);
            }
        }
    }
}

// =====================================================
// IPv6 Configuration
// =====================================================

/// IPv6 interface configuration
#[derive(Debug, Clone, Copy)]
pub struct Ipv6Config {
    /// Link-local address (fe80::/10, auto-generated from MAC)
    pub link_local: Ipv6Address,
    /// Global unicast address (via SLAAC or manual)
    pub global: Option<Ipv6Address>,
    /// Prefix length (default 64)
    pub prefix_len: u8,
    /// Default gateway (link-local of router)
    pub gateway: Option<Ipv6Address>,
    /// Default hop limit (default 64)
    pub hop_limit: u8,
}

impl Ipv6Config {
    /// Create from MAC address (auto-generates link-local via EUI-64)
    pub fn from_mac(mac: &[u8; 6]) -> Self {
        Self {
            link_local: Ipv6Address::from_eui64(mac),
            global: None,
            prefix_len: 64,
            gateway: None,
            hop_limit: 64,
        }
    }
}

impl Default for Ipv6Config {
    fn default() -> Self {
        Self {
            link_local: Ipv6Address::UNSPECIFIED,
            global: None,
            prefix_len: 64,
            gateway: None,
            hop_limit: 64,
        }
    }
}

// =====================================================
// IPv6 Statistics
// =====================================================

/// IPv6 packet processing statistics
#[derive(Debug, Default)]
pub struct Ipv6Stats {
    /// Packets received
    pub rx_packets: AtomicU64,
    /// Packets dropped (not for us, malformed, etc.)
    pub dropped: AtomicU64,
    /// Packets with invalid header
    pub header_errors: AtomicU64,
    /// Hop limit exceeded
    pub hop_limit_exceeded: AtomicU64,
}

impl Ipv6Stats {
    pub fn record_rx(&self) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dropped(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_header_error(&self) {
        self.header_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_hop_limit_exceeded(&self) {
        self.hop_limit_exceeded.fetch_add(1, Ordering::Relaxed);
    }
}

// =====================================================
// IPv6 Process Result
// =====================================================

/// Result of IPv6 packet processing
pub enum Ipv6ProcessResult<'a> {
    /// ICMPv6 payload with addresses
    Icmpv6(&'a [u8], Ipv6Address, Ipv6Address),
    /// TCP payload with addresses
    Tcp(&'a [u8], Ipv6Address, Ipv6Address),
    /// UDP payload with addresses
    Udp(&'a [u8], Ipv6Address, Ipv6Address),
    /// Packet dropped (not for us, malformed, etc.)
    Dropped,
    /// Processing error
    Error,
}

// =====================================================
// IPv6 Processor
// =====================================================

/// IPv6 packet processor
pub struct Ipv6Processor {
    /// Configuration
    config: Ipv6Config,
    /// Statistics
    stats: Ipv6Stats,
}

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
    fn is_for_us(&self, addr: &Ipv6Address) -> bool {
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
mod tests {
    use super::*;

    // --- Address tests ---

    #[test_case]
    fn test_unspecified() {
        let addr = Ipv6Address::UNSPECIFIED;
        assert!(addr.is_unspecified());
        assert!(!addr.is_loopback());
        assert!(!addr.is_multicast());
        assert!(!addr.is_unicast_link_local());
    }

    #[test_case]
    fn test_loopback() {
        let addr = Ipv6Address::LOOPBACK;
        assert!(!addr.is_unspecified());
        assert!(addr.is_loopback());
        assert!(!addr.is_multicast());
    }

    #[test_case]
    fn test_multicast() {
        let addr = Ipv6Address::ALL_NODES_LINK_LOCAL;
        assert!(addr.is_multicast());
        assert!(addr.is_link_local());
        assert!(!addr.is_unicast_link_local());
    }

    #[test_case]
    fn test_link_local() {
        // fe80::1
        let addr = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(addr.is_unicast_link_local());
        assert!(addr.is_link_local());
        assert!(!addr.is_multicast());
        assert!(!addr.is_global());
    }

    #[test_case]
    fn test_global() {
        // 2001:db8::1
        let addr = Ipv6Address::new([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(addr.is_global());
        assert!(!addr.is_unicast_link_local());
        assert!(!addr.is_multicast());
        assert!(!addr.is_loopback());
    }

    #[test_case]
    fn test_eui64() {
        // MAC: 52:54:00:12:34:56
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let addr = Ipv6Address::from_eui64(&mac);

        assert!(addr.is_unicast_link_local());
        // fe80::5054:00ff:fe12:3456
        // 7th bit flipped: 0x52 ^ 0x02 = 0x50
        assert_eq!(addr.as_bytes()[0], 0xfe);
        assert_eq!(addr.as_bytes()[1], 0x80);
        assert_eq!(addr.as_bytes()[8], 0x50); // 0x52 ^ 0x02
        assert_eq!(addr.as_bytes()[9], 0x54);
        assert_eq!(addr.as_bytes()[10], 0x00);
        assert_eq!(addr.as_bytes()[11], 0xff);
        assert_eq!(addr.as_bytes()[12], 0xfe);
        assert_eq!(addr.as_bytes()[13], 0x12);
        assert_eq!(addr.as_bytes()[14], 0x34);
        assert_eq!(addr.as_bytes()[15], 0x56);
    }

    #[test_case]
    fn test_solicited_node() {
        // fe80::5054:00ff:fe12:3456 → ff02::1:ff12:3456
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let addr = Ipv6Address::from_eui64(&mac);
        let sn = addr.solicited_node();

        assert!(sn.is_multicast());
        assert!(sn.is_solicited_node_multicast());
        assert_eq!(sn.as_bytes()[12], 0xff);
        assert_eq!(sn.as_bytes()[13], 0x12); // last 3 bytes of unicast
        assert_eq!(sn.as_bytes()[14], 0x34);
        assert_eq!(sn.as_bytes()[15], 0x56);
    }

    #[test_case]
    fn test_multicast_mac() {
        // ff02::1:ff12:3456 → 33:33:ff:12:34:56
        let addr = Ipv6Address::new([
            0xff, 0x02, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0x01, 0xff, 0x12, 0x34, 0x56,
        ]);
        let mac = addr.multicast_mac();
        assert_eq!(mac, [0x33, 0x33, 0xff, 0x12, 0x34, 0x56]);
    }

    // --- Header / Packet tests ---

    #[test_case]
    fn test_header_size() {
        assert_eq!(core::mem::size_of::<Ipv6Header>(), IPV6_HEADER_SIZE);
    }

    #[test_case]
    fn test_packet_parse_valid() {
        // Construct a minimal valid IPv6 packet (ICMPv6 Echo Request)
        let mut buf = [0u8; 48]; // 40 header + 8 payload
        buf[0] = 0x60; // version = 6
        buf[4] = 0; buf[5] = 8; // payload length = 8
        buf[6] = 58; // next header = ICMPv6 (58)
        buf[7] = 64; // hop limit = 64

        let packet = Ipv6Packet::parse(&buf).unwrap();
        assert_eq!(packet.header().version(), 6);
        assert_eq!(packet.header().payload_length(), 8);
        assert_eq!(packet.next_header(), IpProtocol::Icmpv6);
        assert_eq!(packet.hop_limit(), 64);
        assert_eq!(packet.payload().len(), 8);
    }

    #[test_case]
    fn test_packet_parse_wrong_version() {
        let mut buf = [0u8; 48];
        buf[0] = 0x40; // version = 4 (IPv4)
        assert!(Ipv6Packet::parse(&buf).is_none());
    }

    #[test_case]
    fn test_packet_parse_too_short() {
        let buf = [0x60u8; 20]; // too short for IPv6 header
        assert!(Ipv6Packet::parse(&buf).is_none());
    }

    #[test_case]
    fn test_packet_mut_build() {
        let mut buf = [0u8; 60]; // 40 header + 20 payload
        let mut pkt = Ipv6PacketMut::new(&mut buf).unwrap();
        pkt.init_header();

        let src = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

        pkt.set_source(&src);
        pkt.set_destination(&dst);
        pkt.set_next_header(IpProtocol::Icmpv6);
        pkt.set_hop_limit(255);
        pkt.finalize(20);

        assert_eq!(pkt.header().version(), 6);
        assert_eq!(pkt.header().source(), src);
        assert_eq!(pkt.header().destination(), dst);
        assert_eq!(pkt.header().next_header(), IpProtocol::Icmpv6);
        assert_eq!(pkt.header().hop_limit(), 255);
        assert_eq!(pkt.header().payload_length(), 20);
    }

    // --- Extension header tests ---

    #[test_case]
    fn test_skip_no_extension_headers() {
        // Payload that starts directly with upper-layer data
        let data = [1, 2, 3, 4, 5, 6, 7, 8];
        let (proto, remaining) = skip_extension_headers(IpProtocol::Tcp, &data);
        assert_eq!(proto, IpProtocol::Tcp);
        assert_eq!(remaining.len(), 8);
    }

    #[test_case]
    fn test_skip_hop_by_hop() {
        // Hop-by-Hop Options header: next=ICMPv6(58), len=0 → 8 bytes total
        let mut data = [0u8; 16];
        data[0] = 58; // next header = ICMPv6
        data[1] = 0;  // length = 0 → (0+1)*8 = 8 bytes
        // data[2..8] = padding/options
        data[8] = 0x80; // fake ICMPv6 echo request

        let (proto, remaining) = skip_extension_headers(
            IpProtocol::Unknown(0), // Hop-by-Hop = 0
            &data,
        );
        assert_eq!(proto, IpProtocol::Icmpv6);
        assert_eq!(remaining.len(), 8);
        assert_eq!(remaining[0], 0x80);
    }

    #[test_case]
    fn test_skip_fragment_header() {
        // Fragment header: next=TCP(6), always 8 bytes
        let mut data = [0u8; 16];
        data[0] = 6; // next header = TCP
        data[1] = 0; // reserved
        // data[2..4] = fragment offset + M flag
        // data[4..8] = identification

        let (proto, remaining) = skip_extension_headers(
            IpProtocol::Unknown(44), // Fragment = 44
            &data,
        );
        assert_eq!(proto, IpProtocol::Tcp);
        assert_eq!(remaining.len(), 8);
    }

    // --- Pseudo-header checksum test ---

    #[test_case]
    fn test_pseudo_header_checksum() {
        let src = Ipv6Address::LOOPBACK;
        let dst = Ipv6Address::LOOPBACK;
        let sum = ipv6_pseudo_header_checksum(&src, &dst, IpProtocol::Icmpv6, 8);

        // Both addresses = ::1, so sum contributions from addresses:
        // src: 7 words of 0 + 1 word of 1 = 1
        // dst: same = 1
        // length = 8 → 0 + 8 = 8
        // next_header = 58
        // total = 1 + 1 + 8 + 58 = 68
        assert_eq!(sum, 68);
    }

    // --- Display test ---

    #[test_case]
    fn test_display_loopback() {
        let addr = Ipv6Address::LOOPBACK;
        let s = alloc::format!("{}", addr);
        assert_eq!(s, "::1");
    }

    #[test_case]
    fn test_display_link_local() {
        // fe80::1
        let addr = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let s = alloc::format!("{}", addr);
        assert_eq!(s, "fe80::1");
    }

    #[test_case]
    fn test_display_all_nodes() {
        let addr = Ipv6Address::ALL_NODES_LINK_LOCAL;
        let s = alloc::format!("{}", addr);
        assert_eq!(s, "ff02::1");
    }

    #[test_case]
    fn test_display_full() {
        // 2001:db8:1:2:3:4:5:6 (no zero run >= 2)
        let addr = Ipv6Address::new([
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x02,
            0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06,
        ]);
        let s = alloc::format!("{}", addr);
        assert_eq!(s, "2001:db8:1:2:3:4:5:6");
    }

    #[test_case]
    fn test_from_u64_pair() {
        let addr = Ipv6Address::from_u64_pair(
            0xfe80_0000_0000_0000,
            0x0000_0000_0000_0001,
        );
        assert!(addr.is_unicast_link_local());
        assert_eq!(addr.as_bytes()[15], 1);
    }
}
