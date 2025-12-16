//! Network Stack Integration for ExoRust
//!
//! This module integrates all network protocol layers into
//! a unified zero-copy network stack as specified in Section 6.2.

use super::arp::{ArpProcessor, ArpResult};
use super::ethernet::{EtherType, EthernetFrameMut, EthernetProcessor, MacAddress, ProcessResult};
use super::icmp::{IcmpEchoBuilder, IcmpProcessor, IcmpResult};
use super::ipv4::{
    IpProtocol, Ipv4Address, Ipv4Config, Ipv4PacketMut, Ipv4ProcessResult, Ipv4Processor,
};
use super::mempool::{PacketPool, PacketRef};
use super::tcp::TcpProcessor;
use super::udp::{UdpProcessor, UdpResult, UdpSocket};

use crate::sync::PoisonLock;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

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
    /// Enable ICMP echo responses
    pub icmp_echo_enabled: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            mac: MacAddress::from_octets(0x02, 0x00, 0x00, 0x00, 0x00, 0x01),
            ipv4: Ipv4Config::default(),
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

/// Integrated network stack
pub struct NetworkStack {
    /// Configuration
    config: NetworkConfig,
    /// Ethernet processor
    ethernet: EthernetProcessor,
    /// IPv4 processor
    ipv4: Ipv4Processor,
    /// ARP processor
    arp: ArpProcessor,
    /// ICMP processor
    icmp: IcmpProcessor,
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
}

impl NetworkStack {
    /// Create a new network stack with configuration
    ///
    /// # パフォーマンス注意
    /// Ipv4Config が Clone を実装しているが、内部データが Copy なら
    /// clone() はゼロコストでインライン化される
    pub fn new(config: NetworkConfig) -> Self {
        let mac = config.mac;
        let ip = config.ipv4.address;

        // Note: ipv4.clone() は Ipv4Config が小さい構造体のため
        // アセンブリでは memcpy やレジスタコピーに展開される
        NetworkStack {
            ethernet: EthernetProcessor::new(mac),
            ipv4: Ipv4Processor::new(config.ipv4.clone()),
            arp: ArpProcessor::new(mac, ip),
            icmp: IcmpProcessor::new(ip),
            udp: UdpProcessor::new(),
            tcp: TcpProcessor::new(),
            tx_pool: PacketPool::new(64, MAX_PACKET_SIZE),
            config: config,
            stats: NetworkStats::default(),
            transmit_fn: None,
            current_time: AtomicU64::new(0),
        }
    }

    /// Create with default configuration
    pub fn new_default() -> Self {
        Self::new(NetworkConfig::default())
    }

    /// Set transmit callback
    pub fn set_transmit_fn(&mut self, f: TransmitFn) {
        self.transmit_fn = Some(f);
    }

    /// Update current time (call periodically)
    pub fn update_time(&self, ticks: u64) {
        self.current_time.store(ticks, Ordering::Release);
    }

    /// Get current time
    pub fn current_time(&self) -> u64 {
        self.current_time.load(Ordering::Acquire)
    }

    /// Get configuration (full clone - use sparingly)
    pub fn config(&self) -> NetworkConfig {
        self.config.clone()
    }

    /// ICMP echo が有効かチェック
    #[inline]
    pub fn icmp_echo_enabled(&self) -> bool {
        self.config.icmp_echo_enabled
    }

    /// MAC アドレスを取得
    #[inline]
    pub fn mac_address(&self) -> MacAddress {
        self.config.mac
    }

    /// IPv4 アドレスを取得
    #[inline]
    pub fn ipv4_address(&self) -> Ipv4Address {
        self.config.ipv4.address
    }

    /// Update configuration
    pub fn set_config(&mut self, config: NetworkConfig) {
        // Update all processors
        self.ethernet.set_local_mac(config.mac);
        self.ipv4.set_config(config.ipv4.clone());
        self.arp.set_local(config.mac, config.ipv4.address);

        self.config = config;
    }

    /// Get statistics
    pub fn stats(&self) -> &NetworkStats {
        &self.stats
    }

    /// Process an incoming packet (main entry point)
    pub fn receive(&mut self, packet: PacketRef) {
        let current_time = self.current_time();

        // Process Ethernet frame (zero-copy via PacketRef view)
        let result = self.ethernet.process(packet.data());

        match result {
            ProcessResult::Ipv4(payload) => {
                self.process_ipv4(payload, current_time);
            }
            ProcessResult::Arp(payload) => {
                self.process_arp(payload, current_time);
            }
            ProcessResult::Ipv6(_payload) => {
                // IPv6 not yet implemented
                self.stats.record_dropped();
            }
            ProcessResult::Dropped => {
                self.stats.record_dropped();
            }
            ProcessResult::Error => {
                self.stats.record_rx_error();
            }
        }

        self.stats.record_rx(packet.len());
    }

    /// Process IPv4 packet
    fn process_ipv4(&mut self, data: &[u8], current_time: u64) {
        let result = self.ipv4.process(data);

        match result {
            Ipv4ProcessResult::Icmp(payload, src_ip) => {
                self.process_icmp(payload, src_ip, current_time);
            }
            Ipv4ProcessResult::Udp(payload, src_ip, dst_ip) => {
                self.process_udp(payload, src_ip, dst_ip);
            }
            Ipv4ProcessResult::Tcp(payload, src_ip, dst_ip) => {
                self.process_tcp(payload, src_ip, dst_ip);
            }
            Ipv4ProcessResult::Dropped => {
                self.stats.record_dropped();
            }
            Ipv4ProcessResult::Error => {
                self.stats.record_rx_error();
            }
            Ipv4ProcessResult::Success => {}
        }
    }

    /// Process ARP packet
    fn process_arp(&mut self, data: &[u8], current_time: u64) {
        let result = self.arp.process(data, current_time);

        match result {
            ArpResult::SendReply {
                target_mac,
                target_ip,
            } => {
                self.send_arp_reply(target_mac, target_ip);
            }
            ArpResult::CacheUpdated => {
                // Cache was updated, check if we have pending sends
            }
            ArpResult::Ignored | ArpResult::Invalid => {} // _ => {} // Unreachable pattern removed
        }
    }

    /// Process ICMP packet
    fn process_icmp(&mut self, data: &[u8], src_ip: Ipv4Address, current_time: u64) {
        if !self.icmp_echo_enabled() {
            return;
        }

        let result = self.icmp.process(data, src_ip);

        match result {
            IcmpResult::SendEchoReply {
                src_ip,
                identifier,
                sequence,
                data_offset,
                data_len,
            } => {
                // Get echo data
                let echo_data = if data_offset + data_len <= data.len() {
                    &data[data_offset..data_offset + data_len]
                } else {
                    &[]
                };

                self.send_icmp_echo_reply(src_ip, identifier, sequence, echo_data, current_time);
            }
            IcmpResult::EchoReplyReceived {
                identifier,
                sequence,
            } => {
                // Could notify waiting pingers
                let _ = (identifier, sequence);
            }
            _ => {}
        }
    }

    /// Process UDP packet
    fn process_udp(&mut self, data: &[u8], src_ip: Ipv4Address, dst_ip: Ipv4Address) {
        let result = self.udp.process(data, src_ip, dst_ip);

        match result {
            UdpResult::Delivered => {}
            UdpResult::NoSocket => {
                // Could send ICMP port unreachable
                self.stats.record_dropped();
            }
            UdpResult::ChecksumError | UdpResult::Invalid => {
                self.stats.record_rx_error();
            }
        }
    }

    /// Process TCP packet
    fn process_tcp(&mut self, data: &[u8], src_ip: Ipv4Address, dst_ip: Ipv4Address) {
        self.tcp.process(data, src_ip, dst_ip);
    }

    /// Send an ARP reply
    fn send_arp_reply(&mut self, target_mac: MacAddress, target_ip: Ipv4Address) {
        let mut buffer = [0u8; 64];
        let mac = self.mac_address();

        // Build Ethernet frame
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame
                .set_destination(target_mac)
                .set_source(mac)
                .set_ether_type(EtherType::Arp);

            let payload = frame.payload_mut();
            if let Some(len) = self.arp.build_reply(payload, target_mac, target_ip) {
                frame.set_payload_len(len);
                frame.pad_to_minimum();

                self.transmit(frame.as_bytes());
            }
        }
    }

    /// Send an ARP request
    pub fn send_arp_request(&mut self, target_ip: Ipv4Address) {
        let mut buffer = [0u8; 64];
        let mac = self.mac_address();
        let current_time = self.current_time();

        // Check if we already have a pending request
        if self.arp.cache().is_pending(target_ip, current_time) {
            return;
        }

        // Build Ethernet frame (broadcast)
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame
                .set_destination(MacAddress::BROADCAST)
                .set_source(mac)
                .set_ether_type(EtherType::Arp);

            let payload = frame.payload_mut();
            if let Some(len) = self.arp.build_request(payload, target_ip) {
                frame.set_payload_len(len);
                frame.pad_to_minimum();

                // Mark request as sent
                self.arp.request_sent(target_ip, current_time);

                self.transmit(frame.as_bytes());
            }
        }
    }

    /// Send ICMP echo reply
    fn send_icmp_echo_reply(
        &mut self,
        dst_ip: Ipv4Address,
        identifier: u16,
        sequence: u16,
        echo_data: &[u8],
        current_time: u64,
    ) {
        let config = self.config.clone();

        // Resolve MAC address
        let dst_mac = if config.ipv4.is_local(&dst_ip) {
            // Destination is on local subnet, use ARP
            if let Some(mac) = self.arp.resolve(dst_ip, current_time) {
                mac
            } else {
                // Need to send ARP request first
                self.send_arp_request(dst_ip);
                return;
            }
        } else {
            // Destination is remote, use gateway
            if let Some(mac) = self.arp.resolve(config.ipv4.gateway, current_time) {
                mac
            } else {
                self.send_arp_request(config.ipv4.gateway);
                return;
            }
        };

        let mut buffer = [0u8; MAX_PACKET_SIZE];

        // Build Ethernet frame
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame
                .set_destination(dst_mac)
                .set_source(config.mac)
                .set_ether_type(EtherType::Ipv4);

            let eth_payload = frame.payload_mut();

            // Build IP packet
            if let Some(mut ip_packet) = Ipv4PacketMut::new(eth_payload) {
                ip_packet
                    .init_header()
                    .set_source(config.ipv4.address)
                    .set_destination(dst_ip)
                    .set_protocol(IpProtocol::Icmp)
                    .set_ttl(64);

                let ip_payload = ip_packet.payload_mut();

                // Build ICMP packet
                if let Some(mut icmp) = IcmpEchoBuilder::new(ip_payload) {
                    icmp.build_reply(identifier, sequence);
                    icmp.write_data(echo_data);
                    let icmp_len = icmp.finalize();

                    ip_packet.finalize(icmp_len);

                    let ip_len = ip_packet.total_len();
                    frame.set_payload_len(ip_len);

                    self.transmit(frame.as_bytes());
                }
            }
        }
    }

    /// Send a UDP packet
    pub fn send_udp(
        &mut self,
        src_port: u16,
        dst_ip: Ipv4Address,
        dst_port: u16,
        data: &[u8],
    ) -> bool {
        let config = self.config.clone();
        let current_time = self.current_time();

        // Resolve MAC address
        let dst_mac = self.resolve_mac(dst_ip, &config, current_time);
        let dst_mac = match dst_mac {
            Some(mac) => mac,
            None => return false,
        };

        let mut buffer = [0u8; MAX_PACKET_SIZE];

        // Build Ethernet frame
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame
                .set_destination(dst_mac)
                .set_source(config.mac)
                .set_ether_type(EtherType::Ipv4);

            let eth_payload = frame.payload_mut();

            // Build IP packet
            if let Some(mut ip_packet) = Ipv4PacketMut::new(eth_payload) {
                ip_packet
                    .init_header()
                    .set_source(config.ipv4.address)
                    .set_destination(dst_ip)
                    .set_protocol(IpProtocol::Udp)
                    .set_ttl(64);

                let ip_payload = ip_packet.payload_mut();

                // Build UDP packet
                if let Some(udp_len) = super::udp::UdpProcessor::build_packet(
                    ip_payload,
                    config.ipv4.address,
                    src_port,
                    dst_ip,
                    dst_port,
                    data,
                ) {
                    ip_packet.finalize(udp_len);

                    let ip_len = ip_packet.total_len();
                    frame.set_payload_len(ip_len);

                    return self.transmit(frame.as_bytes());
                }
            }
        }

        false
    }

    /// Resolve IP to MAC address
    fn resolve_mac(
        &mut self,
        dst_ip: Ipv4Address,
        config: &NetworkConfig,
        current_time: u64,
    ) -> Option<MacAddress> {
        // Broadcast address
        if dst_ip.is_broadcast() {
            return Some(MacAddress::BROADCAST);
        }

        // Determine next hop
        let next_hop = if config.ipv4.is_local(&dst_ip) {
            dst_ip
        } else {
            config.ipv4.gateway
        };

        // Look up in ARP cache
        match self.arp.resolve(next_hop, current_time) {
            Some(mac) => Some(mac),
            None => {
                // Need ARP resolution
                self.send_arp_request(next_hop);
                None
            }
        }
    }

    /// Send a raw TCP segment
    /// tcp_segment should already have the TCP header and data, with checksum calculated
    pub fn send_tcp(
        &mut self,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        tcp_segment: &[u8],
    ) -> bool {
        let config = self.config.clone();
        let current_time = self.current_time();

        // Resolve MAC address
        let dst_mac = self.resolve_mac(dst_ip, &config, current_time);
        let dst_mac = match dst_mac {
            Some(mac) => mac,
            None => return false, // ARP resolution pending
        };

        let mut buffer = [0u8; MAX_PACKET_SIZE];

        // Build Ethernet frame
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame
                .set_destination(dst_mac)
                .set_source(config.mac)
                .set_ether_type(EtherType::Ipv4);

            let eth_payload = frame.payload_mut();

            // Build IP packet
            if let Some(mut ip_packet) = Ipv4PacketMut::new(eth_payload) {
                ip_packet
                    .init_header()
                    .set_source(src_ip)
                    .set_destination(dst_ip)
                    .set_protocol(IpProtocol::Tcp)
                    .set_ttl(64);

                let ip_payload = ip_packet.payload_mut();

                // Copy TCP segment
                if ip_payload.len() >= tcp_segment.len() {
                    ip_payload[..tcp_segment.len()].copy_from_slice(tcp_segment);
                    ip_packet.finalize(tcp_segment.len());

                    let ip_len = ip_packet.total_len();
                    frame.set_payload_len(ip_len);

                    return self.transmit(frame.as_bytes());
                }
            }
        }

        false
    }

    /// Bind a UDP socket
    pub fn bind_udp(&mut self, port: u16) -> Option<UdpSocket> {
        self.udp.bind(port)
    }

    /// Transmit a raw Ethernet frame
    pub fn transmit(&self, data: &[u8]) -> bool {
        if let Some(f) = self.transmit_fn {
            if f(data) {
                self.stats.record_tx(data.len());
                return true;
            } else {
                self.stats.record_tx_error();
                return false;
            }
        }

        false
    }

    /// Get ARP cache entries (for debugging)
    pub fn arp_cache(&self) -> Vec<(Ipv4Address, MacAddress)> {
        self.arp
            .cache()
            .all_entries()
            .iter()
            .filter(|e| e.state == super::arp::ArpEntryState::Resolved)
            .map(|e| (e.ip, e.mac))
            .collect()
    }

    /// Get configuration (for shell commands)
    pub fn get_config(&self) -> NetworkConfig {
        self.config.clone()
    }

    /// Update IP address (for DHCP)
    pub fn update_ip(&mut self, ip: Ipv4Address) {
        self.config.ipv4.address = ip;

        // Update dependent processors
        self.ipv4.set_config(self.config.ipv4.clone());
        self.arp.set_local(self.config.mac, ip);
    }

    /// Send ICMP echo request (ping)
    pub fn send_icmp_echo_request(
        &mut self,
        target: Ipv4Address,
        sequence: u16,
    ) -> Result<u64, ()> {
        let local_ip = self.ipv4_address();
        let identifier = 0x1234u16; // Fixed identifier for now

        // Allocate packet buffer
        let mut buffer = self.tx_pool.alloc().ok_or(())?;
        let buf = buffer.as_mut_slice();

        // Build packet: Ethernet + IPv4 + ICMP
        let eth_hdr_len = 14;
        let ip_hdr_len = 20;
        let icmp_hdr_len = 8; // ICMP echo header
        let total_len = eth_hdr_len + ip_hdr_len + icmp_hdr_len;

        if buf.len() < total_len {
            return Err(());
        }

        // Need to resolve target MAC via ARP
        let current_time = self.current_time();
        // arp.cache() is accessible directly now
        let target_mac = self.arp.cache().lookup(target, current_time);

        let dst_mac = match target_mac {
            Some(mac) => mac,
            None => {
                // For gateway, use broadcast initially
                // In a real implementation, we'd send ARP request and wait
                // Trigger ARP request
                self.send_arp_request(target);
                return Err(());
            }
        };

        // Build Ethernet header
        let src_mac = self.mac_address();
        buf[0..6].copy_from_slice(dst_mac.as_bytes());
        buf[6..12].copy_from_slice(src_mac.as_bytes());
        buf[12] = 0x08; // EtherType IPv4
        buf[13] = 0x00;

        // Build IPv4 header
        let ip_start = eth_hdr_len;
        buf[ip_start] = 0x45; // Version 4, IHL 5
        buf[ip_start + 1] = 0x00; // DSCP/ECN
        let total_ip_len = (ip_hdr_len + icmp_hdr_len) as u16;
        buf[ip_start + 2] = (total_ip_len >> 8) as u8;
        buf[ip_start + 3] = total_ip_len as u8;
        buf[ip_start + 4..ip_start + 6].copy_from_slice(&[0x00, 0x00]); // ID
        buf[ip_start + 6..ip_start + 8].copy_from_slice(&[0x40, 0x00]); // Flags + Fragment
        buf[ip_start + 8] = 64; // TTL
        buf[ip_start + 9] = 1; // Protocol: ICMP
        buf[ip_start + 10..ip_start + 12].copy_from_slice(&[0x00, 0x00]); // Checksum placeholder
        buf[ip_start + 12..ip_start + 16].copy_from_slice(local_ip.as_bytes());
        buf[ip_start + 16..ip_start + 20].copy_from_slice(target.as_bytes());

        // Calculate IP checksum
        let ip_checksum = Self::checksum(&buf[ip_start..ip_start + ip_hdr_len]);
        buf[ip_start + 10] = (ip_checksum >> 8) as u8;
        buf[ip_start + 11] = ip_checksum as u8;

        // Build ICMP echo request manually
        let icmp_start = ip_start + ip_hdr_len;
        buf[icmp_start] = 8; // Type: Echo Request
        buf[icmp_start + 1] = 0; // Code: 0
        buf[icmp_start + 2..icmp_start + 4].copy_from_slice(&[0, 0]); // Checksum placeholder
        buf[icmp_start + 4..icmp_start + 6].copy_from_slice(&identifier.to_be_bytes());
        buf[icmp_start + 6..icmp_start + 8].copy_from_slice(&sequence.to_be_bytes());

        // Calculate ICMP checksum
        let icmp_checksum = Self::checksum(&buf[icmp_start..icmp_start + icmp_hdr_len]);
        buf[icmp_start + 2] = (icmp_checksum >> 8) as u8;
        buf[icmp_start + 3] = icmp_checksum as u8;

        // Record send time
        let send_time = self.current_time();

        // Transmit
        if self.transmit(&buf[..total_len]) {
            // In a real implementation, we'd wait for echo reply
            // For now, return estimated RTT
            Ok(send_time)
        } else {
            Err(())
        }
    }

    /// Calculate IP/ICMP checksum
    fn checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;

        while i < data.len() - 1 {
            sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
            i += 2;
        }

        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }

        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !sum as u16
    }

    /// Periodic maintenance (call from timer)
    pub fn periodic(&mut self) {
        let current_time = self.current_time();

        // Expire old ARP entries
        self.arp.cache().expire_old(current_time);
    }
}

/// Global network stack instance
static NETWORK_STACK: PoisonLock<Option<NetworkStack>> = PoisonLock::new(None);

/// Initialize the global network stack
pub fn init(config: NetworkConfig) {
    let mut stack = NETWORK_STACK.lock().unwrap_or_else(|e| {
        log::warn!("[NET] Global Stack poisoned");
        e.into_inner()
    });
    *stack = Some(NetworkStack::new(config));
}

/// Initialize with default configuration
pub fn init_default() {
    init(NetworkConfig::default());
}

/// Get the global network stack
pub fn stack() -> &'static PoisonLock<Option<NetworkStack>> {
    &NETWORK_STACK
}

/// Process a received packet
pub fn receive(data: &[u8]) {
    use crate::net::mempool::alloc_packet;

    // Allocate PacketRef to bridge legacy driver to Zero-Copy stack
    if let Some(mut packet) = alloc_packet() {
        // Copy data (Bridge)
        let len = data.len().min(packet.capacity());
        packet.data_mut()[..len].copy_from_slice(&data[..len]);
        packet.set_len(len);

        if let Some(ref mut stack) = *NETWORK_STACK.lock().unwrap_or_else(|e| {
            log::warn!("[NET] Global Stack poisoned");
            e.into_inner()
        }) {
            stack.receive(packet);
        }
    } else {
        // Drop packet due to OOM
        // Ideally record stats
    }
}

/// Send a UDP datagram
pub fn send_udp(src_port: u16, dst_ip: Ipv4Address, dst_port: u16, data: &[u8]) -> bool {
    if let Some(ref mut stack) = *NETWORK_STACK.lock().unwrap_or_else(|e| {
        log::warn!("[NET] Global Stack poisoned");
        e.into_inner()
    }) {
        stack.send_udp(src_port, dst_ip, dst_port, data)
    } else {
        false
    }
}

/// Send a TCP segment
pub fn send_tcp(src_ip: Ipv4Address, dst_ip: Ipv4Address, tcp_segment: &[u8]) -> bool {
    if let Some(ref mut stack) = *NETWORK_STACK.lock().unwrap_or_else(|e| {
        log::warn!("[NET] Global Stack poisoned");
        e.into_inner()
    }) {
        stack.send_tcp(src_ip, dst_ip, tcp_segment)
    } else {
        false
    }
}

/// Bind a UDP socket
pub fn bind_udp(port: u16) -> Option<UdpSocket> {
    NETWORK_STACK
        .lock()
        .unwrap_or_else(|e| {
            log::warn!("[NET] Global Stack poisoned");
            e.into_inner()
        })
        .as_mut()
        .and_then(|s| s.bind_udp(port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_stack_creation() {
        let stack = NetworkStack::new_default();
        let config = stack.config();

        assert_eq!(
            config.mac,
            MacAddress::from_octets(0x02, 0x00, 0x00, 0x00, 0x00, 0x01)
        );
        assert!(config.icmp_echo_enabled);
    }
}
