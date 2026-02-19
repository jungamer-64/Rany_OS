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
use super::igmp::{IgmpProcessor, IgmpResult, IgmpError, IGMP_PROTOCOL, multicast_ip_to_mac};
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
    TcpControlBlock, TcpError, TcpListener, TcpProcessor, TcpProcessResult, TcpStream,
    SocketAddr as TcpSocketAddr, Ipv4Addr as TcpIpv4Addr, TcpHeader,
};

use super::udp::{UdpProcessor, UdpResult, UdpSocket};

use crate::sync::PoisonLock;
#[cfg(any(test, feature = "full_mm_tests", feature = "qemu-test-export"))]
use alloc::sync::Arc;
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
pub type TransmitFn = fn(&[u8]) -> bool;

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

    /// Insert or update a redirect entry
    fn insert(&mut self, destination: Ipv4Address, gateway: Ipv4Address) {
        // First, try to find existing entry for this destination
        for entry in self.entries.iter_mut() {
            if let Some(e) = entry {
                if e.destination == destination {
                    e.gateway = gateway;
                    e.timestamp = self.current_time;
                    return;
                }
            }
        }

        // Find an empty slot or the oldest entry
        let mut oldest_idx = 0;
        let mut oldest_time = u64::MAX;
        
        for (i, entry) in self.entries.iter().enumerate() {
            match entry {
                None => {
                    // Empty slot - use it immediately
                    self.entries[i] = Some(RedirectCacheEntry {
                        destination,
                        gateway,
                        timestamp: self.current_time,
                    });
                    return;
                }
                Some(e) => {
                    // Check if expired
                    if self.current_time.saturating_sub(e.timestamp) > REDIRECT_CACHE_TTL {
                        // Expired entry - can be replaced
                        self.entries[i] = Some(RedirectCacheEntry {
                            destination,
                            gateway,
                            timestamp: self.current_time,
                        });
                        return;
                    }
                    if e.timestamp < oldest_time {
                        oldest_time = e.timestamp;
                        oldest_idx = i;
                    }
                }
            }
        }

        // Replace oldest entry
        self.entries[oldest_idx] = Some(RedirectCacheEntry {
            destination,
            gateway,
            timestamp: self.current_time,
        });
    }

    /// Look up a redirect for a destination
    fn get(&self, destination: Ipv4Address) -> Option<Ipv4Address> {
        for entry in self.entries.iter() {
            if let Some(e) = entry {
                if e.destination == destination {
                    // Check if entry is still valid
                    if self.current_time.saturating_sub(e.timestamp) <= REDIRECT_CACHE_TTL {
                        return Some(e.gateway);
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
    packets: Vec<PendingIpv6Packet>,
}

impl NdpPendingQueue {
    fn new() -> Self {
        Self {
            packets: Vec::new(),
        }
    }

    /// パケットをキューに追加
    fn enqueue(&mut self, src: Ipv6Address, dst: Ipv6Address, icmpv6_data: &[u8], current_time: u64) {
        // キュー満杯なら最古のエントリを破棄
        if self.packets.len() >= NDP_PENDING_QUEUE_SIZE {
            self.packets.remove(0);
        }
        self.packets.push(PendingIpv6Packet {
            dst,
            src,
            icmpv6_data: icmpv6_data.to_vec(),
            queued_at: current_time,
        });
    }

    /// 指定アドレス宛のパケットを取り出す
    fn drain_for(&mut self, dst: &Ipv6Address) -> Vec<PendingIpv6Packet> {
        let mut matched = Vec::new();
        let mut remaining = Vec::new();

        for pkt in self.packets.drain(..) {
            if pkt.dst == *dst {
                matched.push(pkt);
            } else {
                remaining.push(pkt);
            }
        }

        self.packets = remaining;
        matched
    }

    /// タイムアウトしたパケットを削除
    fn expire(&mut self, current_time: u64) {
        self.packets.retain(|pkt| {
            current_time.saturating_sub(pkt.queued_at) < NDP_PENDING_TIMEOUT_MS
        });
    }
}
