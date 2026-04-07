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

mod address_impl;
mod checksum_impl;
mod config_impl;
mod fragment_impl;
mod header_impl;
/// IPv4 address (4 bytes)
mod packet_impl;
mod pmtu_impl;
mod processor_config_impl;
mod processor_id_impl;
mod processor_impl;
mod processor_packet_path_impl;
mod processor_runtime_impl;
mod processor_security_impl;
mod processor_tx_impl;
mod protocol_impl;
pub use checksum_impl::{data_checksum, pseudo_header_checksum};
pub use fragment_impl::*;
pub use processor_impl::*;
#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests;
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct Ipv4Address([u8; 4]);

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

/// Zero-copy IPv4 packet view
pub struct Ipv4Packet<'a> {
    header: &'a Ipv4Header,
    /// Raw packet data
    data: &'a [u8],
}

/// Mutable IPv4 packet builder
pub struct Ipv4PacketMut<'a> {
    /// Raw buffer
    data: &'a mut [u8],
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
