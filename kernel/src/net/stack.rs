// ============================================================================
// Network Stack Integration for ExoRust
// ============================================================================

//! Network Stack Integration for ExoRust
//!
//! This module integrates all network protocol layers into
//! a unified zero-copy network stack as specified in Section 6.2.

use super::arp::{ArpProcessor, ArpResult};
use super::ethernet::{EtherType, EthernetFrameMut, EthernetProcessor, MacAddress, ProcessResult};
use super::icmp::{DestUnreachCode, IcmpEchoBuilder, IcmpProcessor, IcmpResult, IcmpType, RedirectCode};
use super::icmpv6::{Icmpv6EchoBuilder, Icmpv6Processor, Icmpv6Result};
use super::igmp::{IgmpProcessor, IgmpResult, IgmpError, multicast_ip_to_mac};
use super::ipv4::{
    IpProtocol, Ipv4Address, Ipv4Config, Ipv4Packet, Ipv4PacketMut, Ipv4ProcessResult, Ipv4Processor,
};
use super::ipv6::{
    Ipv6Address, Ipv6Config, Ipv6PacketMut, Ipv6ProcessResult, Ipv6Processor, IPV6_HEADER_SIZE,
    Ipv6FragmentReassembler, Ipv6PmtuCache,
};
use super::ndp::{NdpProcessor, NdpResult};
use super::mempool::{PacketPool, PacketRef};
use super::optimization::PacketBatch;
use super::tcp::{
    TcpError, TcpListener, TcpProcessor, TcpProcessResult, TcpStream,
    SocketAddr as TcpSocketAddr, TcpHeader,
};

use super::udp::{UdpProcessor, UdpResult, UdpSocket};
use super::NetIfId; // required for new transmit callback signature

use crate::sync::PoisonLock;
#[cfg(any(test, feature = "full_mm_tests", feature = "qemu-test-export"))]
use alloc::sync::Arc;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
mod core_impl;
pub use core_impl::*;

extern crate alloc;

/// Maximum packet size including Ethernet header
pub const MAX_PACKET_SIZE: usize = 1518;

/// Ethernet MTU
pub const MTU: usize = 1500;

/// Network interface configuration
///
/// Note: 全フィールドが Copy 型のため、Copy を実装。
/// clone() 呼び出しが単純なビットコピーに最適化される。
#[derive(Debug, Clone, Copy)]
pub struct NetworkConfig {
    /// MAC address
    pub mac: MacAddress,
    /// IPv4 configuration
    pub ipv4: Ipv4Config,
    /// IPv6 configuration (optional)
    pub ipv6: Option<Ipv6Config>,
    /// Enable ICMP echo responses
    pub icmp_echo_enabled: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            mac: MacAddress::from_octets(0x02, 0x00, 0x00, 0x00, 0x00, 0x01),
            ipv4: Ipv4Config::default(),
            ipv6: None,
            icmp_echo_enabled: true,
        }
    }
}

/// Network stack statistics
#[derive(Debug, Default)]
pub struct NetworkStats {
    /// Packets received
    pub rx_packets: AtomicU64,
    /// Packets transmitted  
    pub tx_packets: AtomicU64,
    /// Bytes received
    pub rx_bytes: AtomicU64,
    /// Bytes transmitted
    pub tx_bytes: AtomicU64,
    /// Receive errors
    pub rx_errors: AtomicU64,
    /// Transmit errors
    pub tx_errors: AtomicU64,
    /// Packets dropped
    pub rx_dropped: AtomicU64,
}

impl NetworkStats {
    /// Record received packet
    pub fn record_rx(&self, len: usize) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes.fetch_add(len as u64, Ordering::Relaxed);
    }

    /// Record transmitted packet
    pub fn record_tx(&self, len: usize) {
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(len as u64, Ordering::Relaxed);
    }

    /// Record receive error
    pub fn record_rx_error(&self) {
        self.rx_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record transmit error
    pub fn record_tx_error(&self) {
        self.tx_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record dropped packet
    pub fn record_dropped(&self) {
        self.rx_dropped.fetch_add(1, Ordering::Relaxed);
    }
}

/// Transmit callback function type
/// Transmit callback invoked by the network stack when it needs to send
/// an Ethernet frame out to the wire.
///
/// The `Option<NetIfId>` parameter indicates which logical interface the
/// packet should be emitted on.  `None` is used when the stack has no
/// particular interface preference (e.g. legacy single-NIC mode or when the
/// caller elected not to specify an interface).  This extra metadata allows
/// the bridge layer to support multiple VirtIO ports and other multi‑NIC
/// configurations without racing for a single global transmit function.
///
/// The callback should return `true` if the packet was successfully queued
/// for transmission; `false` indicates failure and will usually result in the
/// stack dropping the packet and recording an error statistic.
pub type TransmitFn = fn(Option<NetIfId>, &[u8]) -> bool;

/// ICMP Redirect Cache Entry
/// 
/// Stores temporary route overrides received from ICMP Redirect messages.
/// These entries have limited lifetime and should be aged out periodically.
#[derive(Debug, Clone, Copy)]
struct RedirectCacheEntry {
    /// Destination address
    destination: Ipv4Address,
    /// Gateway to use
    gateway: Ipv4Address,
    /// Timestamp when entry was created (for aging)
    timestamp: u64,
}

/// ICMP Redirect Cache
/// 
/// A simple fixed-size cache for storing ICMP redirect information.
/// RFC 792 recommends caching redirects temporarily.
const REDIRECT_CACHE_SIZE: usize = 32;
const REDIRECT_CACHE_TTL: u64 = 600_000; // 10 minutes in milliseconds

#[derive(Debug)]
struct RedirectCache {
    entries: [Option<RedirectCacheEntry>; REDIRECT_CACHE_SIZE],
    current_time: u64,
}

impl RedirectCache {
    /// Create an empty redirect cache
    fn new() -> Self {
        Self {
            entries: [None; REDIRECT_CACHE_SIZE],
            current_time: 0,
        }
    }

    /// Update the current time for aging
    fn set_time(&mut self, time: u64) {
        self.current_time = time;
    }

    /// Insert or update a redirect entry using linear search to avoid hash collision DoS.
    fn insert(&mut self, destination: Ipv4Address, gateway: Ipv4Address) {
        let mut first_empty: Option<usize> = None;
        let mut oldest_idx = 0;
        let mut oldest_time = u64::MAX;

        for (i, entry) in self.entries.iter_mut().enumerate() {
            match entry {
                Some(e) if e.destination == destination => {
                    // update existing
                    e.gateway = gateway;
                    e.timestamp = self.current_time;
                    return;
                }
                Some(e) => {
                    // Track oldest entry for potential eviction
                    if e.timestamp < oldest_time {
                        oldest_time = e.timestamp;
                        oldest_idx = i;
                    }
                    if self.current_time.saturating_sub(e.timestamp) > REDIRECT_CACHE_TTL {
                        // replace expired entry immediately
                        *entry = Some(RedirectCacheEntry { destination, gateway, timestamp: self.current_time });
                        return;
                    }
                }
                None => {
                    if first_empty.is_none() {
                        first_empty = Some(i);
                    }
                }
            }
        }

        if let Some(empty_idx) = first_empty {
            self.entries[empty_idx] = Some(RedirectCacheEntry { destination, gateway, timestamp: self.current_time });
            return;
        }

        // Cache is full and no expired slot; replace the one with oldest timestamp
        self.entries[oldest_idx] = Some(RedirectCacheEntry { destination, gateway, timestamp: self.current_time });
    }

    /// Look up a redirect for a destination
    fn get(&self, destination: Ipv4Address) -> Option<Ipv4Address> {
        for entry in self.entries.iter() {
            if let Some(e) = entry {
                if e.destination == destination {
                    if self.current_time.saturating_sub(e.timestamp) <= REDIRECT_CACHE_TTL {
                        return Some(e.gateway);
                    } else {
                        return None; // Found but expired
                    }
                }
            }
        }
        None
    }

    /// Remove all expired entries
    fn cleanup(&mut self) {
        for entry in self.entries.iter_mut() {
            if let Some(e) = entry {
                if self.current_time.saturating_sub(e.timestamp) > REDIRECT_CACHE_TTL {
                    *entry = None;
                }
            }
        }
    }
}

/// Integrated network stack
pub struct NetworkStack {
    /// Configuration
    config: NetworkConfig,
    /// Ethernet processor
    ethernet: EthernetProcessor,
    /// IPv4 processor
    ipv4: Ipv4Processor,
    /// IPv6 processor (optional)
    ipv6: Option<Ipv6Processor>,
    /// ARP processor
    arp: ArpProcessor,
    /// ICMP processor
    icmp: IcmpProcessor,
    /// ICMPv6 processor (optional)
    icmpv6: Option<Icmpv6Processor>,
    /// IGMP processor (multicast group management)
    igmp: IgmpProcessor,
    /// NDP processor (optional, IPv6 neighbor discovery)
    ndp: Option<NdpProcessor>,
    /// UDP processor
    udp: UdpProcessor,
    /// TCP processor
    tcp: TcpProcessor,
    /// Packet pool for transmit buffers
    tx_pool: PacketPool,
    /// Statistics
    stats: NetworkStats,
    /// Transmit callback
    transmit_fn: Option<TransmitFn>,
    /// Current timestamp (ticks)
    current_time: AtomicU64,
    /// ICMP Redirect cache
    redirect_cache: RedirectCache,
    /// Pending IPv6 packets awaiting NDP resolution
    ndp_pending_queue: NdpPendingQueue,
    /// IPv6 fragment reassembler
    ipv6_fragment_reassembler: Ipv6FragmentReassembler,
    /// IPv6 Path MTU Discovery cache
    ipv6_pmtu_cache: Ipv6PmtuCache,
}

/// NDP解決待ちパケットキュー
///
/// IPv6パケット送信時にNDP解決が未完了の場合、パケットをキューに
/// 保管し、NA受信時に自動的に送信を再試行する。
const NDP_PENDING_QUEUE_SIZE: usize = 16;
const NDP_PENDING_TIMEOUT_MS: u64 = 3000; // 3秒タイムアウト

/// NDP解決待ちパケット
#[derive(Clone)]
struct PendingIpv6Packet {
    /// 送信先IPv6アドレス
    dst: Ipv6Address,
    /// 送信元IPv6アドレス
    src: Ipv6Address,
    /// ICMPv6ペイロード
    icmpv6_data: Vec<u8>,
    /// キューイング時刻
    queued_at: u64,
}

/// NDP解決待ちキュー
struct NdpPendingQueue {
    packets: VecDeque<PendingIpv6Packet>,
}

impl NdpPendingQueue {
    fn new() -> Self {
        Self {
            packets: VecDeque::new(),
        }
    }

    /// パケットをキューに追加
    fn enqueue(&mut self, src: Ipv6Address, dst: Ipv6Address, icmpv6_data: &[u8], current_time: u64) {
        if self.packets.len() >= NDP_PENDING_QUEUE_SIZE {
            // VecDeque provides efficient pop_front
            self.packets.pop_front();
        }
        self.packets.push_back(PendingIpv6Packet {
            dst,
            src,
            icmpv6_data: icmpv6_data.to_vec(),
            queued_at: current_time,
        });
    }

    /// 指定アドレス宛のパケットを取り出す
    fn drain_for(&mut self, dst: &Ipv6Address) -> Vec<PendingIpv6Packet> {
        let mut matched = Vec::new();
        let len = self.packets.len();
        
        // Rotate elements in-place to avoid new VecDeque allocations
        for _ in 0..len {
            if let Some(pkt) = self.packets.pop_front() {
                if pkt.dst == *dst {
                    matched.push(pkt);
                } else {
                    self.packets.push_back(pkt);
                }
            }
        }

        matched
    }

    /// タイムアウトしたパケットを削除
    fn expire(&mut self, current_time: u64) {
        self.packets.retain(|pkt| {
            current_time.saturating_sub(pkt.queued_at) < NDP_PENDING_TIMEOUT_MS
        });
    }
}
