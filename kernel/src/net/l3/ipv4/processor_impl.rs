// ============================================================================
// kernel/src/net/l3/ipv4/processor_impl.rs - L3 / IPv4 / プロセッサ実装
// ============================================================================

use super::*;
use kernel_api::resource::net::PacketPayload;

/// IPv4 packet processor
pub struct Ipv4Processor {
    /// Configuration
    pub(super) config: Ipv4Config,
    /// Statistics
    pub(super) stats: Ipv4Stats,
    /// Internal ID counter
    pub(super) next_id: u16,
    /// ID generation secret (per-boot, 32-bit for better scrambling)
    pub(super) id_secret: u32,
    /// Fragment reassembler
    pub(super) reassembler: FragmentReassembler,
    /// Path MTU Discovery cache
    pub(super) pmtu_cache: PmtuCache,
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
    /// ICMP packet with source address, destination address, TTL, and original packet data
    Icmp(&'a [u8], Ipv4Address, Ipv4Address, u8, &'a [u8]),
    /// IGMP packet with source address, TTL, and original packet data
    Igmp(&'a [u8], Ipv4Address, u8, &'a [u8]),
    /// TCP packet with source address, destination address, and original packet data
    Tcp(&'a [u8], Ipv4Address, Ipv4Address, &'a [u8]),
    /// UDP packet with source address, destination address, and original packet data
    Udp(&'a [u8], Ipv4Address, Ipv4Address, &'a [u8]),
    /// Reassembled packet backed by the fragment ownership chain
    Reassembled(PacketPayload),
    /// Fragment received, reassembly in progress
    FragmentPending,
    /// Reassembly timeout (source address and first fragment's header for ICMP)
    ReassemblyTimeout(Ipv4Address, PacketPayload),
    /// Unknown protocol (RFC 792 Protocol Unreachable)
    UnknownProtocol(u8, Ipv4Address, Ipv4Address, PacketPayload),
    /// Dropped
    Dropped,
    /// Error
    Error,
    /// Success (Consumed internally)
    Success,
}
