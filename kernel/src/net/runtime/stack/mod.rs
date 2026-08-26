// ============================================================================
// kernel/src/net/runtime/stack/mod.rs - ランタイム / スタック モジュール
// ============================================================================
//! Network Stack Integration for ExoRust
//!
//! This module integrates all network protocol layers into
//! a unified zero-copy network stack as specified in Section 6.2.

use crate::net::l2::arp::{ArpProcessor, ArpResult};
use crate::net::l2::ethernet::{
    EtherType, EthernetFrameMut, EthernetHeader, EthernetProcessor, MacAddress,
};
use crate::net::l3::icmp::{
    DestUnreachCode, IcmpEchoBuilder, IcmpProcessor, IcmpResult, RedirectCode,
};
use crate::net::l3::icmpv6::{Icmpv6Builder, Icmpv6Processor, Icmpv6Result, Icmpv6Type};
use crate::net::l3::igmp::{IgmpProcessor, IgmpResult, multicast_ip_to_mac};
use crate::net::l3::ipv4::{
    IpProtocol, Ipv4Address, Ipv4Config, Ipv4Packet, Ipv4PacketMut, Ipv4ProcessResult,
    Ipv4Processor,
};
use crate::net::l3::ipv6::{
    IPV6_HEADER_SIZE, Ipv6Address, Ipv6Config, Ipv6PacketMut, Ipv6PmtuCache, Ipv6ProcessResult,
    Ipv6Processor,
};
use crate::net::l3::ndp::{NdpProcessor, NdpResult};
use crate::net::l4::udp::{UdpProcessor, UdpResult};
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::manager::NetIfId;
use crate::net::runtime::timeouts::TimeoutWheel; // required for new transmit callback signature

use crate::sync::PoisonLock;
use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_api::resource::net::PacketPayload;
use kernel_api::service::netdev::NetTxMeta;
mod core_impl;
pub(crate) use core_impl::*;

extern crate alloc;

/// Maximum packet size including Ethernet header
pub const MAX_PACKET_SIZE: usize = 1518;

/// Ethernet MTU
pub const MTU: usize = 1500;

/// Network interface configuration
///
/// 全フィールドが Copy 型のため、Copy を実装。
/// clone() 呼び出しが単純なビットコピーに最適化される。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkConfig {
    /// MAC address
    pub mac: MacAddress,
    /// IPv4 configuration
    pub ipv4: Ipv4Config,
    /// IPv6 configuration (optional)
    pub ipv6: Option<Ipv6Config>,
    /// Enable ICMP echo responses
    pub icmp_echo_enabled: bool,
    /// Enable ICMPv4 Redirect handling (Security: default false)
    pub icmp_redirect_enabled: bool,
    /// Enable ICMPv6/NDP Redirect handling (Security: default false)
    pub icmpv6_redirect_enabled: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            mac: MacAddress::from_octets(0x02, 0x00, 0x00, 0x00, 0x00, 0x01),
            ipv4: Ipv4Config::default(),
            ipv6: None,
            icmp_echo_enabled: true,
            icmp_redirect_enabled: false,
            icmpv6_redirect_enabled: false,
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

    /// Record header parse error
    pub fn record_header_error(&self) {
        self.rx_errors.fetch_add(1, Ordering::Relaxed);
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
/// The `NetIfId` parameter identifies the exact logical interface selected by
/// routing before the frame crosses the device boundary.
///
/// The callback should return `true` if the packet was successfully queued
/// for transmission; `false` indicates failure and will usually result in the
/// stack dropping the packet and recording an error statistic.
pub type TransmitFn = fn(
    NetRuntimeHandle,
    NetIfId,
    PacketPayload,
    NetTxMeta,
    Option<u64>,
) -> Result<(), PacketPayload>;

// ICMP Redirect Cache Entry
#[derive(Debug)]
pub(crate) struct RedirectCacheEntry {
    destination: Ipv4Address,
    gateway: Ipv4Address,
    timestamp: u64,
    next: Option<usize>,
}

const REDIRECT_CACHE_SIZE: usize = 32;
const REDIRECT_CACHE_BUCKETS: usize = 32;
const REDIRECT_CACHE_TTL: u64 = 600_000;

#[derive(Debug)]
pub struct RedirectCache {
    buckets: [Option<usize>; REDIRECT_CACHE_BUCKETS],
    entries: Vec<RedirectCacheEntry>,
    current_time: u64,
}

impl RedirectCache {
    fn new() -> Self {
        Self {
            buckets: [None; REDIRECT_CACHE_BUCKETS],
            entries: Vec::new(),
            current_time: 0,
        }
    }

    fn bucket_for(destination: Ipv4Address) -> usize {
        let mut hash = u32::from_be_bytes(destination.octets());
        hash ^= hash >> 16;
        hash = hash.wrapping_mul(0x7FEB_352D);
        hash ^= hash >> 15;
        hash = hash.wrapping_mul(0x846C_A68B);
        ((hash ^ (hash >> 16)) as usize) & (REDIRECT_CACHE_BUCKETS - 1)
    }

    fn find_index(&self, destination: Ipv4Address) -> Option<usize> {
        let mut index = self.buckets[Self::bucket_for(destination)];
        while let Some(current) = index {
            let entry = &self.entries[current];
            if entry.destination == destination {
                return Some(current);
            }
            index = entry.next;
        }
        None
    }

    fn rebuild_index(&mut self) {
        self.buckets = [None; REDIRECT_CACHE_BUCKETS];
        for index in 0..self.entries.len() {
            let bucket = Self::bucket_for(self.entries[index].destination);
            self.entries[index].next = self.buckets[bucket];
            self.buckets[bucket] = Some(index);
        }
    }

    fn retain_fresh(&mut self) {
        self.entries
            .retain(|e| self.current_time.saturating_sub(e.timestamp) <= REDIRECT_CACHE_TTL);
        self.rebuild_index();
    }

    fn set_time(&mut self, time: u64) {
        self.current_time = time;
        self.retain_fresh();
    }

    fn insert(&mut self, destination: Ipv4Address, gateway: Ipv4Address) {
        self.retain_fresh();

        if let Some(index) = self.find_index(destination) {
            let e = &mut self.entries[index];
            e.gateway = gateway;
            e.timestamp = self.current_time;
            return;
        }

        if self.entries.len() >= REDIRECT_CACHE_SIZE {
            if let Some(oldest) = self
                .entries
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.timestamp)
                .map(|(index, _)| index)
            {
                self.entries.swap_remove(oldest);
                self.rebuild_index();
            }
        }

        let bucket = Self::bucket_for(destination);
        let next = self.buckets[bucket];
        self.entries.push(RedirectCacheEntry {
            destination,
            gateway,
            timestamp: self.current_time,
            next,
        });
        self.buckets[bucket] = Some(self.entries.len() - 1);
    }

    fn get(&self, destination: Ipv4Address) -> Option<Ipv4Address> {
        let index = self.find_index(destination)?;
        let e = &self.entries[index];
        if e.destination == destination {
            if self.current_time.saturating_sub(e.timestamp) <= REDIRECT_CACHE_TTL {
                return Some(e.gateway);
            } else {
                return None;
            }
        }
        None
    }
}

/// Integrated network stack
pub struct NetworkStack {
    /// Runtime that owns this stack instance.
    runtime: NetRuntimeHandle,
    /// Per-core protocol state derived from the manager-owned configurations.
    interfaces: BTreeMap<NetIfId, InterfaceStackState>,
    /// Manager topology revision fully reconciled into this core-local replica.
    applied_topology_revision: crate::net::runtime::manager::InterfaceTopologyRevision,
    /// Primary interface copied only as part of an atomic topology reconciliation.
    reconciled_primary: Option<NetIfId>,
    /// Manager revision fully applied to this per-core stack.
    /// Timeout wheel for periodic tasks
    timeout_wheel: TimeoutWheel,
    /// Canonical device transmit boundary shared by every core-local stack.
    transmit_fn: TransmitFn,
    /// Completion observer for the next frame, separate from DMA metadata.
    pending_tx_completion_id: Option<u64>,
    /// Current timestamp (ticks)
    current_time: AtomicU64,
}

/// Per-interface stack state used by multi-interface APIs.
pub struct InterfaceStackState {
    config: NetworkConfig,
    ethernet: EthernetProcessor,
    ipv4: Ipv4Processor,
    ipv6: Option<Ipv6Processor>,
    arp: ArpProcessor,
    icmp: IcmpProcessor,
    icmpv6: Option<Icmpv6Processor>,
    igmp: IgmpProcessor,
    ndp: Option<NdpProcessor>,
    udp: UdpProcessor,
    stats: NetworkStats,
    redirect_cache: RedirectCache,
    arp_pending_queue: ArpPendingQueue,
    ndp_pending_queue: NdpPendingQueue,
    ipv6_pmtu_cache: Ipv6PmtuCache,
}

impl InterfaceStackState {
    pub fn new(config: NetworkConfig) -> Self {
        let mac = config.mac;
        let ip = config.ipv4.address;
        let (ipv6_proc, icmpv6_proc, ndp_proc) = if let Some(ref ipv6_config) = config.ipv6 {
            let mac_bytes = mac.as_bytes();
            (
                Some(Ipv6Processor::new(*ipv6_config)),
                Some(Icmpv6Processor::new(config.icmp_echo_enabled)),
                Some(NdpProcessor::new(ipv6_config.link_local, *mac_bytes)),
            )
        } else {
            (None, None, None)
        };

        Self {
            ethernet: EthernetProcessor::new(mac),
            ipv4: Ipv4Processor::new(config.ipv4),
            ipv6: ipv6_proc,
            arp: ArpProcessor::new(mac, ip),
            icmp: IcmpProcessor::new(ip),
            icmpv6: icmpv6_proc,
            igmp: IgmpProcessor::new(ip),
            ndp: ndp_proc,
            udp: UdpProcessor::new(),
            stats: NetworkStats::default(),
            config,
            redirect_cache: RedirectCache::new(),
            arp_pending_queue: ArpPendingQueue::new(),
            ndp_pending_queue: NdpPendingQueue::new(),
            ipv6_pmtu_cache: Ipv6PmtuCache::new(Ipv6PmtuCache::DEFAULT_MAX_ENTRIES),
        }
    }

    pub fn set_config(&mut self, config: NetworkConfig) {
        self.ethernet.set_local_mac(config.mac);
        self.ipv4.set_config(config.ipv4);
        self.arp.set_local(config.mac, config.ipv4.address);
        self.igmp.set_local_ip(config.ipv4.address);
        if let Some(ref ipv6_config) = config.ipv6 {
            if self.ipv6.is_none() {
                self.ipv6 = Some(Ipv6Processor::new(*ipv6_config));
            } else if let Some(ref mut ipv6) = self.ipv6 {
                *ipv6 = Ipv6Processor::new(*ipv6_config);
            }
            if self.icmpv6.is_none() {
                self.icmpv6 = Some(Icmpv6Processor::new(config.icmp_echo_enabled));
            }
            let mac_bytes = config.mac.as_bytes();
            self.ndp = Some(NdpProcessor::new(ipv6_config.link_local, *mac_bytes));
        } else {
            self.ipv6 = None;
            self.icmpv6 = None;
            self.ndp = None;
        }
        self.config = config;
    }

    pub(crate) fn config(&self) -> NetworkConfig {
        self.config
    }

    pub(crate) fn ipv6_link_local(&self) -> Option<Ipv6Address> {
        self.config.ipv6.map(|config| config.link_local)
    }

    pub(crate) fn has_ipv6(&self) -> bool {
        self.ipv6.is_some()
    }

    pub(crate) fn process_ethernet(
        &mut self,
        packet: kernel_api::resource::net::PacketRef,
    ) -> crate::net::l2::ethernet::EthernetIngress {
        self.ethernet.process_packet(packet)
    }

    pub(crate) fn process_ipv4_owned_packet(
        &mut self,
        packet: kernel_api::resource::net::PacketRef,
        current_time: u64,
    ) -> Ipv4ProcessResult {
        self.ipv4.process_owned_packet(packet, current_time)
    }
}

/// NDP解決待ちパケットキュー
///
/// IPv6パケット送信時にNDP解決が未完了の場合、パケットをキューに
/// 保管し、NA受信時に自動的に送信を再試行する。
const NDP_PENDING_QUEUE_SIZE: usize = 16;
const NDP_PENDING_TIMEOUT_MS: u64 = 3000; // 3秒タイムアウト

/// NDP解決待ちパケット
pub(crate) enum PendingIpv6Payload {
    Icmpv6(PacketPayload),
    Udp {
        src_port: u16,
        dst_port: u16,
        hop_limit: u8,
        data: PacketPayload,
    },
    Tcp {
        segment: PacketPayload,
    },
}

/// NDP解決待ちパケット
pub(crate) struct PendingIpv6Packet {
    /// 送信先IPv6アドレス
    dst: Ipv6Address,
    /// 送信元IPv6アドレス
    src: Ipv6Address,
    /// 保留中の上位レイヤーペイロード
    payload: PendingIpv6Payload,
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
    fn enqueue(
        &mut self,
        src: Ipv6Address,
        dst: Ipv6Address,
        icmpv6_data: PacketPayload,
        current_time: u64,
    ) {
        if self.packets.len() >= NDP_PENDING_QUEUE_SIZE {
            // VecDeque provides efficient pop_front
            self.packets.pop_front();
        }
        self.packets.push_back(PendingIpv6Packet {
            dst,
            src,
            payload: PendingIpv6Payload::Icmpv6(icmpv6_data),
            queued_at: current_time,
        });
    }

    fn enqueue_udp(
        &mut self,
        src: Ipv6Address,
        dst: Ipv6Address,
        src_port: u16,
        dst_port: u16,
        hop_limit: u8,
        data: PacketPayload,
        current_time: u64,
    ) {
        if self.packets.len() >= NDP_PENDING_QUEUE_SIZE {
            self.packets.pop_front();
        }
        self.packets.push_back(PendingIpv6Packet {
            dst,
            src,
            payload: PendingIpv6Payload::Udp {
                src_port,
                dst_port,
                hop_limit,
                data,
            },
            queued_at: current_time,
        });
    }

    fn enqueue_tcp(
        &mut self,
        src: Ipv6Address,
        dst: Ipv6Address,
        segment: PacketPayload,
        current_time: u64,
    ) {
        if self.packets.len() >= NDP_PENDING_QUEUE_SIZE {
            self.packets.pop_front();
        }
        self.packets.push_back(PendingIpv6Packet {
            dst,
            src,
            payload: PendingIpv6Payload::Tcp { segment },
            queued_at: current_time,
        });
    }

    /// 指定アドレス宛のパケットを取り出す
    fn drain_for(&mut self, dst: &Ipv6Address) -> Vec<PendingIpv6Packet> {
        let mut matched = Vec::new();
        let mut i = 0;
        while i < self.packets.len() {
            if self.packets[i].dst == *dst {
                if let Some(pkt) = self.packets.remove(i) {
                    matched.push(pkt);
                }
            } else {
                i += 1;
            }
        }
        matched
    }

    /// タイムアウトしたパケットを削除
    fn expire(&mut self, current_time: u64) {
        self.packets
            .retain(|pkt| current_time.saturating_sub(pkt.queued_at) < NDP_PENDING_TIMEOUT_MS);
    }
}

/// ARP解決待ちパケットキュー
///
/// IPv4パケット送信時にARP解決が未完了の場合、パケットをキューに
/// 保管し、ARP Reply受信時に自動的に送信を再試行する。
const ARP_PENDING_QUEUE_SIZE: usize = 16;
const ARP_PENDING_TIMEOUT_MS: u64 = 3000; // 3秒タイムアウト

/// ARP解決待ちペイロード
pub(crate) enum PendingIpv4Payload {
    Udp {
        src_port: u16,
        dst_port: u16,
        ttl: u8,
        data: PacketPayload,
    },
    Tcp {
        ttl: u8,
        segment: PacketPayload,
    },
    Raw {
        protocol: IpProtocol,
        ttl: u8,
        payload: PacketPayload,
    },
}

/// ARP解決待ちパケット
pub(crate) struct PendingIpv4Packet {
    /// 送信先IPv4アドレス
    dst: Ipv4Address,
    /// 送信元IPv4アドレス
    src: Ipv4Address,
    /// 保留中の上位レイヤーペイロード
    payload: PendingIpv4Payload,
    /// キューイング時刻
    queued_at: u64,
}

/// ARP解決待ちキュー
pub struct ArpPendingQueue {
    packets: VecDeque<PendingIpv4Packet>,
}

impl ArpPendingQueue {
    fn new() -> Self {
        Self {
            packets: VecDeque::new(),
        }
    }

    /// パケットをキューに追加 (UDP)
    pub(crate) fn enqueue_udp(
        &mut self,
        src: Ipv4Address,
        dst: Ipv4Address,
        src_port: u16,
        dst_port: u16,
        ttl: u8,
        data: PacketPayload,
        current_time: u64,
    ) {
        if self.packets.len() >= ARP_PENDING_QUEUE_SIZE {
            self.packets.pop_front();
        }
        self.packets.push_back(PendingIpv4Packet {
            dst,
            src,
            payload: PendingIpv4Payload::Udp {
                src_port,
                dst_port,
                ttl,
                data,
            },
            queued_at: current_time,
        });
    }

    /// パケットをキューに追加 (TCP)
    pub(crate) fn enqueue_tcp(
        &mut self,
        src: Ipv4Address,
        dst: Ipv4Address,
        ttl: u8,
        segment: PacketPayload,
        current_time: u64,
    ) {
        if self.packets.len() >= ARP_PENDING_QUEUE_SIZE {
            self.packets.pop_front();
        }
        self.packets.push_back(PendingIpv4Packet {
            dst,
            src,
            payload: PendingIpv4Payload::Tcp { ttl, segment },
            queued_at: current_time,
        });
    }

    /// パケットをキューに追加 (Raw)
    pub(crate) fn enqueue_raw(
        &mut self,
        src: Ipv4Address,
        dst: Ipv4Address,
        protocol: IpProtocol,
        ttl: u8,
        payload: PacketPayload,
        current_time: u64,
    ) {
        if self.packets.len() >= ARP_PENDING_QUEUE_SIZE {
            self.packets.pop_front();
        }
        self.packets.push_back(PendingIpv4Packet {
            dst,
            src,
            payload: PendingIpv4Payload::Raw {
                protocol,
                ttl,
                payload,
            },
            queued_at: current_time,
        });
    }

    /// 指定アドレス宛のパケットを取り出す
    pub(crate) fn drain_for(&mut self, dst: &Ipv4Address) -> Vec<PendingIpv4Packet> {
        let mut matched = Vec::new();
        let mut i = 0;
        while i < self.packets.len() {
            if self.packets[i].dst == *dst {
                if let Some(pkt) = self.packets.remove(i) {
                    matched.push(pkt);
                }
            } else {
                i += 1;
            }
        }
        matched
    }

    /// タイムアウトしたパケットを削除
    pub(crate) fn expire(&mut self, current_time: u64) {
        self.packets
            .retain(|pkt| current_time.saturating_sub(pkt.queued_at) < ARP_PENDING_TIMEOUT_MS);
    }
}
