// ============================================================================
// Network Stack Integration for ExoRust
// ============================================================================

//! Network Stack Integration for ExoRust
//!
//! This module integrates all network protocol layers into
//! a unified zero-copy network stack as specified in Section 6.2.

use crate::net::l2::arp::{ArpProcessor, ArpResult};
use crate::net::l2::ethernet::{EtherType, EthernetFrameMut, EthernetHeader, EthernetProcessor, MacAddress};
use crate::net::l3::icmp::{DestUnreachCode, IcmpEchoBuilder, IcmpProcessor, IcmpResult, IcmpType, RedirectCode};
use crate::net::l3::icmpv6::{Icmpv6EchoBuilder, Icmpv6Processor, Icmpv6Result};
use crate::net::l2::igmp::{IgmpError, IgmpProcessor, IgmpResult, multicast_ip_to_mac};
use crate::net::l3::ipv4::{
    IpProtocol, Ipv4Address, Ipv4Config, Ipv4Packet, Ipv4PacketMut, Ipv4ProcessResult, Ipv4Processor,
};
use crate::net::l3::ipv6::{
    Ipv6Address, Ipv6Config, Ipv6PacketMut, Ipv6ProcessResult, Ipv6Processor, IPV6_HEADER_SIZE,
    Ipv6FragmentReassembler, Ipv6PmtuCache,
};
use crate::net::l3::ndp::{NdpProcessor, NdpResult};
use crate::net::datapath::mempool::{PacketPool, PacketRef};
use crate::net::datapath::optimization::PacketBatch;
use crate::net::l4::tcp::{
    TcpError, TcpListener, TcpProcessor, TcpProcessResult, TcpStream,
    EndpointAddr as TcpEndpointAddr, TcpHeader,
};

use crate::net::l4::udp::{UdpProcessor, UdpResult, UdpEndpoint};
use crate::net::runtime::timeouts::{TimeoutWheel, TimerKind};
use crate::net::obs::{
    counters,
    trace::{self, NetEventKind, NetLayer},
};
use crate::net::runtime::manager::NetIfId; // required for new transmit callback signature

use crate::sync::PoisonLock;
#[cfg(any(test, feature = "full_mm_tests", feature = "qemu-test-export"))]
use alloc::sync::Arc;
use alloc::collections::VecDeque;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
mod core_impl;
pub use core_impl::*;
#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests;

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
        trace::push_event(NetLayer::L3, NetEventKind::Rx, "stack receive");
    }

    /// Record transmitted packet
    pub fn record_tx(&self, len: usize) {
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(len as u64, Ordering::Relaxed);
        trace::push_event(NetLayer::L4, NetEventKind::Tx, "stack transmit");
    }

    /// Record receive error
    pub fn record_rx_error(&self) {
        self.rx_errors.fetch_add(1, Ordering::Relaxed);
        counters::global().record_error();
        trace::push_event(NetLayer::L3, NetEventKind::Error, "stack rx error");
    }

    /// Record transmit error
    pub fn record_tx_error(&self) {
        self.tx_errors.fetch_add(1, Ordering::Relaxed);
        counters::global().record_error();
        trace::push_event(NetLayer::L4, NetEventKind::Error, "stack tx error");
    }

    /// Record header parse error
    pub fn record_header_error(&self) {
        self.rx_errors.fetch_add(1, Ordering::Relaxed);
        counters::global().record_error();
        trace::push_event(NetLayer::L3, NetEventKind::Error, "header error");
    }

    /// Record dropped packet
    pub fn record_dropped(&self) {
        self.rx_dropped.fetch_add(1, Ordering::Relaxed);
        counters::global().record_drop();
        trace::push_event(NetLayer::L3, NetEventKind::Drop, "stack drop");
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

// ICMP Redirect Cache Entry (map-backed)
//
// Only the gateway and timestamp are stored; the map key is the destination
// address itself.
#[derive(Debug)]
pub(crate) struct RedirectCacheEntry {
    gateway: Ipv4Address,
    timestamp: u64,
}

const REDIRECT_CACHE_SIZE: usize = 32;
const REDIRECT_CACHE_TTL: u64 = 600_000;

#[derive(Debug)]
pub struct RedirectCache {
    map: BTreeMap<Ipv4Address, RedirectCacheEntry>,
    current_time: u64,
}

impl RedirectCache {
    fn new() -> Self {
        Self {
            map: BTreeMap::new(),
            current_time: 0,
        }
    }

    fn set_time(&mut self, time: u64) {
        self.current_time = time;
        self.map.retain(|_, e| self.current_time.saturating_sub(e.timestamp) <= REDIRECT_CACHE_TTL);
    }

    fn insert(&mut self, destination: Ipv4Address, gateway: Ipv4Address) {
        self.map.retain(|_, e| self.current_time.saturating_sub(e.timestamp) <= REDIRECT_CACHE_TTL);

        if let Some(e) = self.map.get_mut(&destination) {
            e.gateway = gateway;
            e.timestamp = self.current_time;
            return;
        }

        if self.map.len() >= REDIRECT_CACHE_SIZE {
            if let Some((oldest, _)) = self.map.iter().min_by_key(|(_, e)| e.timestamp).map(|(k, _)| (*k, ())) {
                self.map.remove(&oldest);
            }
        }

        self.map.insert(destination, RedirectCacheEntry { gateway, timestamp: self.current_time });
    }

    fn get(&self, destination: Ipv4Address) -> Option<Ipv4Address> {
        self.map.get(&destination).and_then(|e| {
            if self.current_time.saturating_sub(e.timestamp) <= REDIRECT_CACHE_TTL {
                Some(e.gateway)
            } else {
                None
            }
        })
    }
}

/// Integrated network stack
pub struct NetworkStack {
    /// Configuration
    pub config: NetworkConfig,
    /// Ethernet processor
    pub ethernet: EthernetProcessor,
    /// IPv4 processor
    pub ipv4: Ipv4Processor,
    /// IPv6 processor (optional)
    pub ipv6: Option<Ipv6Processor>,
    /// ARP processor
    pub arp: ArpProcessor,
    /// ICMP processor
    pub icmp: IcmpProcessor,
    /// ICMPv6 processor (optional)
    pub icmpv6: Option<Icmpv6Processor>,
    /// IGMP processor (multicast group management)
    pub igmp: IgmpProcessor,
    /// NDP processor (optional, IPv6 neighbor discovery)
    pub ndp: Option<NdpProcessor>,
    /// UDP processor
    pub udp: UdpProcessor,
    /// TCP processor
    pub tcp: TcpProcessor,
    /// Packet pool for transmit buffers
    pub tx_pool: PacketPool,
    /// Statistics
    pub stats: NetworkStats,
    /// Timeout wheel for periodic tasks
    pub timeout_wheel: TimeoutWheel,
    /// Transmit callback
    pub transmit_fn: Option<TransmitFn>,
    /// Current timestamp (ticks)
    pub current_time: AtomicU64,
    /// ICMP Redirect cache
    pub redirect_cache: RedirectCache,
    /// Pending IPv6 packets awaiting NDP resolution
    pub ndp_pending_queue: NdpPendingQueue,
    /// IPv6 fragment reassembler
    pub ipv6_fragment_reassembler: Ipv6FragmentReassembler,
    /// IPv6 Path MTU Discovery cache
    pub ipv6_pmtu_cache: Ipv6PmtuCache,
}

/// NDP解決待ちパケットキュー
///
/// IPv6パケット送信時にNDP解決が未完了の場合、パケットをキューに
/// 保管し、NA受信時に自動的に送信を再試行する。
const NDP_PENDING_QUEUE_SIZE: usize = 16;
const NDP_PENDING_TIMEOUT_MS: u64 = 3000; // 3秒タイムアウト

/// NDP解決待ちパケット
#[derive(Clone)]
pub(crate) struct PendingIpv6Packet {
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
pub struct NdpPendingQueue {
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
        // use retain to avoid expensive rotations; this also keeps order for
        // packets not matching the destination.
        let mut matched = Vec::new();
        self.packets.retain(|pkt| {
            if pkt.dst == *dst {
                // clone is cheap (~3 words) and PendingIpv6Packet derives Clone
                matched.push(pkt.clone());
                false
            } else {
                true
            }
        });
        matched
    }

    /// タイムアウトしたパケットを削除
    fn expire(&mut self, current_time: u64) {
        self.packets.retain(|pkt| {
            current_time.saturating_sub(pkt.queued_at) < NDP_PENDING_TIMEOUT_MS
        });
    }
}
