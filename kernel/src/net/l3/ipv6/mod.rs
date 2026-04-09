// ============================================================================
// kernel/src/net/l3/ipv6/mod.rs
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

// Building block: IPv6 processor fields retained for PMTU support
#![allow(dead_code)]

use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

use super::ipv4::IpProtocol;

// =====================================================
// IPv6 Address
// =====================================================

pub mod fragment;
/// IPv6 address (16 bytes)
mod processor_impl;
pub use fragment::{Ipv6FragmentHeader, Ipv6FragmentReassembler};
pub use processor_impl::*;
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
            h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], l[0], l[1], l[2], l[3], l[4], l[5],
            l[6], l[7],
        ])
    }

    /// Create link-local address from MAC address using EUI-64
    ///
    /// fe80::xxxx:xxff:fexx:xxxx (with 7th bit flipped)
    pub const fn from_eui64(mac: &[u8; 6]) -> Self {
        Self([
            0xfe,
            0x80,
            0,
            0,
            0,
            0,
            0,
            0,
            mac[0] ^ 0x02,
            mac[1],
            mac[2],
            0xff,
            0xfe,
            mac[3],
            mac[4],
            mac[5],
        ])
    }

    /// Create a global address from a /64 prefix + MAC address using EUI-64
    ///
    /// prefix[0..8] || EUI-64(mac)
    /// Used by SLAAC (RFC 4862) to generate autoconfigured global addresses.
    pub fn from_prefix_eui64(prefix: &Ipv6Address, mac: &[u8; 6]) -> Self {
        let p = prefix.as_bytes();
        Self([
            p[0],
            p[1],
            p[2],
            p[3],
            p[4],
            p[5],
            p[6],
            p[7],
            mac[0] ^ 0x02,
            mac[1],
            mac[2],
            0xff,
            0xfe,
            mac[3],
            mac[4],
            mac[5],
        ])
    }

    /// Create a global address from a /64 prefix + random interface ID (RFC 4941)
    ///
    /// Used for IPv6 Privacy Extensions to prevent tracking via the MAC address.
    pub fn from_prefix_random(prefix: &Ipv6Address) -> Self {
        let p = prefix.as_bytes();
        // Generate 8 bytes of entropy for the interface identifier
        let rand = crate::net::security::tls::crypto::random::generate_random();

        let mut addr = [0u8; 16];
        addr[0..8].copy_from_slice(&p[0..8]);
        addr[8..16].copy_from_slice(&rand[0..8]);

        // Security: Ensure the "universal/local" bit is set to 0 (local)
        // per RFC 4941, although many implementations just use full randomness.
        addr[8] &= !0x02;

        Self(addr)
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
        o[0] == 0
            && o[1] == 0
            && o[2] == 0
            && o[3] == 0
            && o[4] == 0
            && o[5] == 0
            && o[6] == 0
            && o[7] == 0
            && o[8] == 0
            && o[9] == 0
            && o[10] == 0
            && o[11] == 0
            && o[12] == 0
            && o[13] == 0
            && o[14] == 0
            && o[15] == 0
    }

    /// Check if loopback (::1)
    #[inline]
    pub const fn is_loopback(&self) -> bool {
        let o = &self.0;
        o[0] == 0
            && o[1] == 0
            && o[2] == 0
            && o[3] == 0
            && o[4] == 0
            && o[5] == 0
            && o[6] == 0
            && o[7] == 0
            && o[8] == 0
            && o[9] == 0
            && o[10] == 0
            && o[11] == 0
            && o[12] == 0
            && o[13] == 0
            && o[14] == 0
            && o[15] == 1
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
            0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xff, self.0[13], self.0[14], self.0[15],
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
        self.0[0] == 0xff
            && self.0[1] == 0x02
            && self.0[2] == 0
            && self.0[3] == 0
            && self.0[4] == 0
            && self.0[5] == 0
            && self.0[6] == 0
            && self.0[7] == 0
            && self.0[8] == 0
            && self.0[9] == 0
            && self.0[10] == 0
            && self.0[11] == 0x01
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
fn write_ipv6_compressed(
    f: &mut fmt::Formatter<'_>,
    words: &[u16; 8],
    best_start: usize,
    best_len: usize,
) -> fmt::Result {
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
    header: &'a Ipv6Header,
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

        let header = crate::util::get_ref::<Ipv6Header>(data, 0)?;
        Some(Self { header, data })
    }

    /// Get header reference (zero-copy)
    #[inline]
    pub fn header(&self) -> &Ipv6Header {
        self.header
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
        let payload_len = self.header().payload_length() as usize;
        let total = IPV6_HEADER_SIZE + payload_len;
        // Security: Ensure we don't panic on packets with invalid payload length
        &self.data[..core::cmp::min(total, self.data.len())]
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
        if let Some(header) = self.header_mut() {
            header.set_version_tc_fl(6, 0, 0);
            header.set_payload_length(0);
            header.set_next_header(IpProtocol::Tcp); // default, caller should override
            header.set_hop_limit(64);
            header.src_addr = [0; 16];
            header.dst_addr = [0; 16];
        }
    }

    /// Get mutable header reference
    #[inline]
    pub fn header_mut(&mut self) -> Option<&mut Ipv6Header> {
        crate::util::get_mut_ref::<Ipv6Header>(self.data, 0)
    }

    /// Get immutable header reference
    #[inline]
    pub fn header(&self) -> Option<&Ipv6Header> {
        crate::util::get_ref::<Ipv6Header>(self.data, 0)
    }

    /// Set source address
    #[inline]
    pub fn set_source(&mut self, addr: &Ipv6Address) {
        if let Some(h) = self.header_mut() {
            h.set_source(addr);
        }
    }

    /// Set destination address
    #[inline]
    pub fn set_destination(&mut self, addr: &Ipv6Address) {
        if let Some(h) = self.header_mut() {
            h.set_destination(addr);
        }
    }

    /// Set next header (protocol)
    #[inline]
    pub fn set_next_header(&mut self, protocol: IpProtocol) {
        if let Some(h) = self.header_mut() {
            h.set_next_header(protocol);
        }
    }

    /// Set hop limit
    #[inline]
    pub fn set_hop_limit(&mut self, limit: u8) {
        if let Some(h) = self.header_mut() {
            h.set_hop_limit(limit);
        }
    }

    /// Set payload length
    #[inline]
    pub fn set_payload_length(&mut self, len: u16) {
        if let Some(h) = self.header_mut() {
            h.set_payload_length(len);
        }
    }

    /// Get mutable payload slice
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.data[IPV6_HEADER_SIZE..]
    }

    /// Get the full buffer as bytes
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        let payload_len = self
            .header()
            .map(|h| h.payload_length() as usize)
            .unwrap_or(0);
        let total_len = IPV6_HEADER_SIZE + payload_len;
        // Security: Clamp to physical buffer size to prevent panic
        &self.data[..core::cmp::min(total_len, self.data.len())]
    }

    /// Finalize packet (set payload length based on actual data written)
    pub fn finalize(&mut self, payload_len: usize) {
        // Security: Clamp payload length to physical buffer size and u16 limit (65535)
        let max_payload = self.data.len().saturating_sub(IPV6_HEADER_SIZE).min(65535);
        let actual_payload = payload_len.min(max_payload);

        if let Some(h) = self.header_mut() {
            h.set_payload_length(actual_payload as u16);
        }
    }
}

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests;

// =====================================================
// Extension Header Traversal
// =====================================================

/// Known extension header types that can be skipped
const EXT_HEADER_HOP_BY_HOP: u8 = 0;
const EXT_HEADER_ROUTING: u8 = 43;
const EXT_HEADER_FRAGMENT: u8 = 44;
const EXT_HEADER_ESP: u8 = 50;
const EXT_HEADER_AUTH: u8 = 51;
const EXT_HEADER_DESTINATION: u8 = 60;
const EXT_HEADER_NO_NEXT: u8 = 59;

/// Maximum number of extension headers to traverse in a single packet.
pub const MAX_EXTENSION_HEADERS: usize = 16;

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
    let mut headers_seen = 0;
    loop {
        headers_seen += 1;
        if headers_seen > MAX_EXTENSION_HEADERS {
            // Safety: stop traversal after too many headers
            return (next_header, data);
        }

        let nh = u8::from(next_header);

        match nh {
            EXT_HEADER_HOP_BY_HOP | EXT_HEADER_ROUTING | EXT_HEADER_DESTINATION => {
                // Standard extension header format
                if data.len() < 2 {
                    return (next_header, data);
                }

                // Security (RFC 5095): Reject Routing Header Type 0
                if nh == EXT_HEADER_ROUTING && data.len() >= 3 && data[2] == 0 {
                    log::warn!(
                        "[NET-IPV6] Dropping packet with deprecated Routing Header Type 0 (RFC 5095)"
                    );
                    // Stop traversal and treat as malformed/dropped
                    return (IpProtocol::from(EXT_HEADER_NO_NEXT), &[]);
                }

                let ext_next = data[0];
                let ext_len = (data[1] as usize + 1) * 8; // length in 8-byte units + first 8 bytes
                if data.len() < ext_len {
                    return (next_header, data);
                }
                next_header = IpProtocol::from(ext_next);
                data = &data[ext_len..];
            }
            EXT_HEADER_AUTH => {
                // RFC 4302 Authentication Header
                if data.len() < 2 {
                    return (next_header, data);
                }
                let ext_next = data[0];
                let ext_len = (data[1] as usize + 2) * 4; // length in 4-byte units - 2
                if data.len() < ext_len {
                    return (next_header, data);
                }
                next_header = IpProtocol::from(ext_next);
                data = &data[ext_len..];
            }
            EXT_HEADER_FRAGMENT => {
                // Fragment header found.
                // RFC 6946: Atomic Fragment (Offset=0, M=0)
                // If it's an atomic fragment, skip it and continue processing the next header.
                // This allows the datagram to be processed as if it did not include a Fragment Header.
                if data.len() >= 8 {
                    let off_and_flags = u16::from_be_bytes([data[2], data[3]]);
                    let fragment_offset = off_and_flags >> 3;
                    let more_fragments = (off_and_flags & 0x01) != 0;

                    if fragment_offset == 0 && !more_fragments {
                        let ext_next = data[0];
                        next_header = IpProtocol::from(ext_next);
                        data = &data[8..];
                        continue;
                    }
                }

                // Non-atomic fragment: reassembly MUST happen before upper-layer processing.
                // If we reach here, it means reassembly was bypassed or failed.
                return (next_header, data);
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

/// Check if a buffer contains a complete IPv6 header chain (RFC 8200/7112).
///
/// Returns true if the chain ends with an upper-layer protocol or NoNextHeader
/// within the provided buffer.
pub fn is_header_chain_complete(mut next_header: u8, mut data: &[u8]) -> bool {
    let mut headers_seen = 0;
    // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
    loop {
        headers_seen += 1;
        if headers_seen > MAX_EXTENSION_HEADERS {
            return false;
        }

        match next_header {
            EXT_HEADER_HOP_BY_HOP | EXT_HEADER_ROUTING | EXT_HEADER_DESTINATION => {
                if data.len() < 8 {
                    return false;
                }

                // Security (RFC 5095): Reject Routing Header Type 0
                if next_header == EXT_HEADER_ROUTING && data[2] == 0 {
                    return false;
                }

                let ext_next = data[0];
                let ext_len = (data[1] as usize + 1) * 8;
                if data.len() < ext_len {
                    return false;
                }
                next_header = ext_next;
                data = &data[ext_len..];
            }
            EXT_HEADER_AUTH => {
                if data.len() < 8 {
                    return false;
                }
                let ext_next = data[0];
                let ext_len = (data[1] as usize + 2) * 4;
                if data.len() < ext_len {
                    return false;
                }
                next_header = ext_next;
                data = &data[ext_len..];
            }
            EXT_HEADER_FRAGMENT => {
                // RFC 8200: A packet must not contain more than one Fragment header.
                return false;
            }
            EXT_HEADER_NO_NEXT => {
                return true;
            }
            EXT_HEADER_ESP => {
                // RFC 7112: ESP terminates the header chain for parsing purposes.
                return true;
            }
            _ => {
                // Upper-layer protocol found.
                // RFC 7112: The first fragment MUST contain the entire IPv6 header chain,
                // up to and including the first upper-layer header.
                let min_len = match next_header {
                    6 => 20, // TCP: 20 bytes
                    17 => 8, // UDP: 8 bytes
                    58 => 8, // ICMPv6: 8 bytes
                    _ => 0,
                };
                return data.len() >= min_len;
            }
        }
    }
}

/// Result of extension-header walk with fragment awareness.
pub enum ExtHeaderResult<'a> {
    /// No fragment header encountered — upper-layer protocol, payload, and pointer to final next_header field
    NoFragment(IpProtocol, &'a [u8], u32),
    /// Fragment header found.
    /// Fields: (unfragmentable part, fragment header, fragment payload)
    Fragment {
        /// Everything before the fragment header (IPv6 fixed header + pre-fragment exts)
        unfragmentable: &'a [u8],
        /// Parsed fragment header
        frag_header: Ipv6FragmentHeader,
        /// Fragment payload (data after the fragment header)
        frag_payload: &'a [u8],
    },
}

/// Walk extension headers returning fragment info if present.
///
/// `raw_packet` is the entire IPv6 packet from byte 0 (fixed header start).
/// Returns `ExtHeaderResult` describing the final state.
pub fn skip_extension_headers_fraginfo(raw_packet: &[u8]) -> ExtHeaderResult<'_> {
    if raw_packet.len() < 40 {
        return ExtHeaderResult::NoFragment(IpProtocol::from(0), &[], 6);
    }

    let mut next_header = raw_packet[6];
    let mut next_header_ptr = 6usize;
    let mut offset = 40usize; // after fixed header
    let mut headers_seen = 0;

    loop {
        headers_seen += 1;
        if headers_seen > MAX_EXTENSION_HEADERS {
            return ExtHeaderResult::NoFragment(
                IpProtocol::from(next_header),
                &raw_packet[offset..],
                next_header_ptr as u32,
            );
        }

        match next_header {
            EXT_HEADER_HOP_BY_HOP | EXT_HEADER_ROUTING | EXT_HEADER_DESTINATION => {
                if offset + 2 > raw_packet.len() {
                    return ExtHeaderResult::NoFragment(
                        IpProtocol::from(next_header),
                        &raw_packet[offset..],
                        next_header_ptr as u32,
                    );
                }

                // Security (RFC 5095): Reject Routing Header Type 0
                if next_header == EXT_HEADER_ROUTING
                    && offset + 3 <= raw_packet.len()
                    && raw_packet[offset + 2] == 0
                {
                    return ExtHeaderResult::NoFragment(
                        IpProtocol::from(EXT_HEADER_NO_NEXT),
                        &[],
                        next_header_ptr as u32,
                    );
                }

                let ext_next = raw_packet[offset];
                let ext_len = (raw_packet[offset + 1] as usize + 1) * 8;
                if offset + ext_len > raw_packet.len() {
                    return ExtHeaderResult::NoFragment(
                        IpProtocol::from(next_header),
                        &raw_packet[offset..],
                        next_header_ptr as u32,
                    );
                }
                next_header_ptr = offset;
                next_header = ext_next;
                offset += ext_len;
            }
            EXT_HEADER_FRAGMENT => {
                if offset + 8 > raw_packet.len() {
                    return ExtHeaderResult::NoFragment(
                        IpProtocol::from(next_header),
                        &raw_packet[offset..],
                        next_header_ptr as u32,
                    );
                }
                if let Some(frag) = Ipv6FragmentHeader::parse(&raw_packet[offset..]) {
                    // RFC 6946: Atomic Fragment (Offset=0, M=0)
                    // "A host that receives an IPv6 packet that includes a Fragment header
                    // with the Fragment Offset field set to zero and the M flag set to zero
                    // MUST NOT use the Fragment header as a basis for reassembling the
                    // packet. Instead, the packet MUST be processed as if it did not
                    // include a Fragment header."
                    if frag.fragment_offset == 0 && !frag.more_fragments {
                        next_header_ptr = offset;
                        next_header = frag.next_header;
                        offset += 8;
                        continue;
                    }

                    // Security (RFC 8200): Nested fragmentation check.
                    // If the Fragment Header's Next Header is also 44 (Fragment),
                    // it MUST be discarded.
                    if frag.next_header == EXT_HEADER_FRAGMENT {
                        log::warn!(
                            "[NET-IPV6] Nested fragmentation detected (Next Header=44 in Fragment Header), dropping"
                        );
                        return ExtHeaderResult::NoFragment(
                            IpProtocol::from(EXT_HEADER_NO_NEXT),
                            &[],
                            next_header_ptr as u32,
                        );
                    }

                    let unfragmentable = &raw_packet[..offset];
                    let frag_payload = &raw_packet[offset + 8..];
                    return ExtHeaderResult::Fragment {
                        unfragmentable,
                        frag_header: frag,
                        frag_payload,
                    };
                }
                // Failed to parse — treat as no fragment
                return ExtHeaderResult::NoFragment(
                    IpProtocol::from(next_header),
                    &raw_packet[offset..],
                    next_header_ptr as u32,
                );
            }
            EXT_HEADER_NO_NEXT => {
                return ExtHeaderResult::NoFragment(
                    IpProtocol::from(next_header),
                    &raw_packet[offset..],
                    next_header_ptr as u32,
                );
            }
            _ => {
                return ExtHeaderResult::NoFragment(
                    IpProtocol::from(next_header),
                    &raw_packet[offset..],
                    next_header_ptr as u32,
                );
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
    /// Temporary global address (RFC 4941 Privacy Extensions)
    pub temporary: Option<Ipv6Address>,
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
            temporary: None,
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
            temporary: None,
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

/// Result of IPv6 fragment reassembly (RFC 8200)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6ReassemblyError {
    /// Overlapping fragments detected (RFC 8200 Section 4.5)
    /// Discard datagram, no ICMP error required.
    Overlap,
    /// Fragment length not a multiple of 8 octets while M=1 (RFC 8200 Section 4.5)
    /// Discard datagram, send ICMPv6 Parameter Problem Code 0, pointer to Payload Length.
    InvalidSize,
    /// Sum of Fragment Offset and Payload Length > 65535, or reassembled size too large (RFC 8200 Section 4.5)
    /// Discard datagram, send ICMPv6 Parameter Problem Code 0, pointer to Payload Length.
    PacketTooLarge,
    /// Incomplete header chain in the first fragment (RFC 7112 Section 5)
    /// Discard datagram, send ICMPv6 Parameter Problem Code 0, pointer to Fragment Offset.
    IncompleteHeaderChain,
}

/// Result of IPv6 packet processing
pub enum Ipv6ProcessResult<'a> {
    /// ICMPv6 payload with addresses and hop limit
    Icmpv6(&'a [u8], Ipv6Address, Ipv6Address, u8),
    /// TCP payload with addresses and hop limit
    Tcp(&'a [u8], Ipv6Address, Ipv6Address, u8),
    /// UDP payload with addresses and hop limit
    Udp(&'a [u8], Ipv6Address, Ipv6Address, u8),
    /// Reassembled packet backed by the fragment ownership chain
    Reassembled(kernel_api::resource::net::PacketPayload),
    /// Fragment received, reassembly in progress
    FragmentPending,
    /// Reassembly timeout (src, dst, unfragmentable_part, fragment_header for ICMPv6)
    ReassemblyTimeout(
        Ipv6Address,
        Ipv6Address,
        kernel_api::resource::net::PacketPayload,
        Option<[u8; 8]>,
    ),
    /// Reassembly error (type, src, dst, unfragmentable_part + fragment_header)
    ReassemblyError(
        Ipv6ReassemblyError,
        Ipv6Address,
        Ipv6Address,
        kernel_api::resource::net::PacketPayload,
    ),
    /// Unknown Next Header encountered (RFC 4443 Parameter Problem Code 1)
    UnknownNextHeader(u8, u32, Ipv6Address, Ipv6Address, &'a [u8]),
    /// Hop Limit exceeded (RFC 4443 Time Exceeded Code 0)
    HopLimitExceeded(Ipv6Address, Ipv6Address, &'a [u8]),
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
    /// Fragment reassembly state (RFC 8200)
    reassembler: Ipv6FragmentReassembler,
    /// Path MTU cache (RFC 8201)
    pmtu_cache: Ipv6PmtuCache,
}

// ============================================================================
// IPv6 Path MTU Discovery (RFC 8201)
// ============================================================================

/// IPv6 Path MTU Discovery entry
#[derive(Debug, Clone, Copy)]
pub struct Ipv6PmtuEntry {
    /// Path MTU in bytes
    pub pmtu: u32,
    /// Timestamp when this entry was last updated (ms)
    pub updated_at: u64,
    /// Timestamp for next probe
    pub next_probe: u64,
}

impl Ipv6PmtuEntry {
    /// Default MTU (standard Ethernet)
    pub const DEFAULT_MTU: u32 = 1500;
    /// Minimum MTU for IPv6 (RFC 8200)
    pub const MIN_MTU: u32 = 1280;
    /// Maximum MTU
    pub const MAX_MTU: u32 = 65535;
    /// Cache entry timeout in milliseconds (10 minutes, RFC 8201)
    pub const TIMEOUT_MS: u64 = 600_000;

    /// Create a new PMTU entry
    pub fn new(pmtu: u32, timestamp: u64) -> Self {
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

/// IPv6 Path MTU Discovery cache
pub struct Ipv6PmtuCache {
    /// PMTU entries keyed by destination IPv6 address
    entries: BTreeMap<Ipv6Address, Ipv6PmtuEntry>,
    /// O(log N) LRU timestamp tracker for fast eviction DOS protection
    lru: BTreeSet<(u64, Ipv6Address)>,
    /// Maximum number of entries
    max_entries: usize,
    /// Statistics
    stats: Ipv6PmtuStats,
}

/// IPv6 PMTU statistics
#[derive(Debug, Default, Clone)]
pub struct Ipv6PmtuStats {
    /// Number of PMTU discoveries
    pub discoveries: u64,
    /// Number of PMTU updates (reductions)
    pub reductions: u64,
    /// Number of cache hits
    pub hits: u64,
    /// Number of cache misses
    pub misses: u64,
}

impl Ipv6PmtuCache {
    /// Default maximum entries
    pub const DEFAULT_MAX_ENTRIES: usize = 256;

    /// Create a new IPv6 PMTU cache
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            lru: BTreeSet::new(),
            max_entries,
            stats: Ipv6PmtuStats::default(),
        }
    }

    /// Get statistics
    pub fn stats(&self) -> &Ipv6PmtuStats {
        &self.stats
    }

    /// Get PMTU for a destination
    pub fn get(&mut self, dst: &Ipv6Address, current_time: u64) -> u32 {
        if let Some(entry) = self.entries.get(dst) {
            if !entry.is_expired(current_time) {
                self.stats.hits += 1;
                return entry.pmtu;
            }
        }
        self.stats.misses += 1;
        Ipv6PmtuEntry::DEFAULT_MTU
    }

    /// Update PMTU for a destination (called when receiving ICMPv6 Packet Too Big)
    pub fn update(&mut self, dst: Ipv6Address, new_mtu: u32, current_time: u64) {
        let clamped_mtu = new_mtu.clamp(Ipv6PmtuEntry::MIN_MTU, Ipv6PmtuEntry::MAX_MTU);

        if let Some(entry) = self.entries.get_mut(&dst) {
            if clamped_mtu < entry.pmtu {
                self.lru.remove(&(entry.updated_at, dst));

                entry.pmtu = clamped_mtu;
                entry.updated_at = current_time;
                entry.next_probe = current_time + Ipv6PmtuEntry::TIMEOUT_MS;
                self.stats.reductions += 1;

                self.lru.insert((current_time, dst));
            }
        } else {
            if self.entries.len() >= self.max_entries {
                self.evict_oldest();
            }
            self.entries
                .insert(dst, Ipv6PmtuEntry::new(clamped_mtu, current_time));
            self.lru.insert((current_time, dst));
            self.stats.discoveries += 1;
        }
    }

    /// Probe for a larger MTU (called periodically)
    pub fn probe(&mut self, dst: &Ipv6Address, current_time: u64) -> Option<u32> {
        if let Some(entry) = self.entries.get_mut(dst) {
            if entry.should_probe(current_time) {
                let probe_mtu = (entry.pmtu + 100).min(Ipv6PmtuEntry::DEFAULT_MTU);
                entry.next_probe = current_time + Ipv6PmtuEntry::TIMEOUT_MS / 2;
                return Some(probe_mtu);
            }
        }
        None
    }

    /// Evict the oldest entry
    fn evict_oldest(&mut self) {
        if let Some((_oldest_time, oldest_key)) = self.lru.pop_first() {
            self.entries.remove(&oldest_key);
        }
    }

    /// Evict expired entries
    pub fn evict_expired(&mut self, current_time: u64) {
        // Remove entries from the head while they are expired.
        // This avoids temporary allocation in runtime paths and keeps O(k log N).
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while let Some((time, key)) = self.lru.first().copied() {
            if current_time.saturating_sub(time) <= Ipv6PmtuEntry::TIMEOUT_MS {
                break;
            }
            self.lru.remove(&(time, key));
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
