//! Network Stack Integration for ExoRust
//!
//! This module integrates all network protocol layers into
//! a unified zero-copy network stack as specified in Section 6.2.

use super::ethernet::{MacAddress, EtherType, EthernetProcessor, EthernetFrame, EthernetFrameMut, ProcessResult};
use super::ipv4::{Ipv4Address, Ipv4Config, Ipv4Processor, Ipv4Packet, Ipv4PacketMut, IpProtocol, Ipv4ProcessResult};
use super::arp::{ArpProcessor, ArpResult, ArpPacket};
use super::icmp::{IcmpProcessor, IcmpResult, IcmpEchoBuilder};
use super::udp::{UdpProcessor, UdpResult, UdpSocket};
use super::tcp::TcpProcessor;
use super::mempool::PacketPool;

use spin::Mutex;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

extern crate alloc;

/// Maximum packet size including Ethernet header
pub const MAX_PACKET_SIZE: usize = 1518;

/// Ethernet MTU
pub const MTU: usize = 1500;

/// Network interface configuration
#[derive(Debug, Clone)]
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
    config: Mutex<NetworkConfig>,
    /// Ethernet processor
    ethernet: Mutex<EthernetProcessor>,
    /// IPv4 processor
    ipv4: Mutex<Ipv4Processor>,
    /// ARP processor
    arp: Mutex<ArpProcessor>,
    /// ICMP processor
    icmp: Mutex<IcmpProcessor>,
    /// UDP processor
    udp: UdpProcessor,
    /// TCP processor
    tcp: Mutex<TcpProcessor>,
    /// Packet pool for transmit buffers
    tx_pool: PacketPool,
    /// Statistics
    stats: NetworkStats,
    /// Transmit callback
    transmit_fn: Mutex<Option<TransmitFn>>,
    /// Current timestamp (ticks)
    current_time: AtomicU64,
}

impl NetworkStack {
    /// Create a new network stack with configuration
    pub fn new(config: NetworkConfig) -> Self {
        let mac = config.mac;
        let ip = config.ipv4.address;
        
        NetworkStack {
            ethernet: Mutex::new(EthernetProcessor::new(mac)),
            ipv4: Mutex::new(Ipv4Processor::new(config.ipv4.clone())),
            arp: Mutex::new(ArpProcessor::new(mac, ip)),
            icmp: Mutex::new(IcmpProcessor::new(ip)),
            udp: UdpProcessor::new(),
            tcp: Mutex::new(TcpProcessor::new()),
            tx_pool: PacketPool::new(64, MAX_PACKET_SIZE),
            config: Mutex::new(config),
            stats: NetworkStats::default(),
            transmit_fn: Mutex::new(None),
            current_time: AtomicU64::new(0),
        }
    }
    
    /// Create with default configuration
    pub fn new_default() -> Self {
        Self::new(NetworkConfig::default())
    }
    
    /// Set transmit callback
    pub fn set_transmit_fn(&self, f: TransmitFn) {
        *self.transmit_fn.lock() = Some(f);
    }
    
    /// Update current time (call periodically)
    pub fn update_time(&self, ticks: u64) {
        self.current_time.store(ticks, Ordering::Release);
    }
    
    /// Get current time
    pub fn current_time(&self) -> u64 {
        self.current_time.load(Ordering::Acquire)
    }
    
    /// Get configuration
    pub fn config(&self) -> NetworkConfig {
        self.config.lock().clone()
    }
    
    /// Update configuration
    pub fn set_config(&self, config: NetworkConfig) {
        let mut cfg = self.config.lock();
        
        // Update all processors
        self.ethernet.lock().set_local_mac(config.mac);
        self.ipv4.lock().set_config(config.ipv4.clone());
        self.arp.lock().set_local(config.mac, config.ipv4.address);
        
        *cfg = config;
    }
    
    /// Get statistics
    pub fn stats(&self) -> &NetworkStats {
        &self.stats
    }
    
    /// Process an incoming packet (main entry point)
    pub fn receive(&self, data: &[u8]) {
        let current_time = self.current_time();
        
        // Process Ethernet frame
        let result = {
            let mut eth = self.ethernet.lock();
            eth.process(data)
        };
        
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
        
        self.stats.record_rx(data.len());
    }
    
    /// Process IPv4 packet
    fn process_ipv4(&self, data: &[u8], current_time: u64) {
        let result = {
            let mut ipv4 = self.ipv4.lock();
            ipv4.process(data)
        };
        
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
        }
    }
    
    /// Process ARP packet
    fn process_arp(&self, data: &[u8], current_time: u64) {
        let result = {
            let arp = self.arp.lock();
            arp.process(data, current_time)
        };
        
        match result {
            ArpResult::SendReply { target_mac, target_ip } => {
                self.send_arp_reply(target_mac, target_ip);
            }
            ArpResult::CacheUpdated => {
                // Cache was updated, check if we have pending sends
            }
            ArpResult::Ignored | ArpResult::Invalid => {}
        }
    }
    
    /// Process ICMP packet
    fn process_icmp(&self, data: &[u8], src_ip: Ipv4Address, current_time: u64) {
        let config = self.config.lock().clone();
        
        if !config.icmp_echo_enabled {
            return;
        }
        
        let result = {
            let mut icmp = self.icmp.lock();
            icmp.process(data, src_ip)
        };
        
        match result {
            IcmpResult::SendEchoReply { src_ip, identifier, sequence, data_offset, data_len } => {
                // Get echo data
                let echo_data = if data_offset + data_len <= data.len() {
                    &data[data_offset..data_offset + data_len]
                } else {
                    &[]
                };
                
                self.send_icmp_echo_reply(src_ip, identifier, sequence, echo_data, current_time);
            }
            IcmpResult::EchoReplyReceived { identifier, sequence } => {
                // Could notify waiting pingers
                let _ = (identifier, sequence);
            }
            _ => {}
        }
    }
    
    /// Process UDP packet
    fn process_udp(&self, data: &[u8], src_ip: Ipv4Address, dst_ip: Ipv4Address) {
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
    fn process_tcp(&self, data: &[u8], src_ip: Ipv4Address, dst_ip: Ipv4Address) {
        let mut tcp = self.tcp.lock();
        tcp.process(data, src_ip, dst_ip);
    }
    
    /// Send an ARP reply
    fn send_arp_reply(&self, target_mac: MacAddress, target_ip: Ipv4Address) {
        let mut buffer = [0u8; 64];
        let config = self.config.lock().clone();
        
        // Build Ethernet frame
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame.set_destination(target_mac)
                 .set_source(config.mac)
                 .set_ether_type(EtherType::Arp);
            
            let payload = frame.payload_mut();
            if let Some(len) = self.arp.lock().build_reply(payload, target_mac, target_ip) {
                frame.set_payload_len(len);
                frame.pad_to_minimum();
                
                self.transmit(frame.as_bytes());
            }
        }
    }
    
    /// Send an ARP request
    pub fn send_arp_request(&self, target_ip: Ipv4Address) {
        let mut buffer = [0u8; 64];
        let config = self.config.lock().clone();
        let current_time = self.current_time();
        
        // Check if we already have a pending request
        {
            let arp = self.arp.lock();
            if arp.cache().is_pending(target_ip, current_time) {
                return;
            }
        }
        
        // Build Ethernet frame (broadcast)
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame.set_destination(MacAddress::BROADCAST)
                 .set_source(config.mac)
                 .set_ether_type(EtherType::Arp);
            
            let payload = frame.payload_mut();
            if let Some(len) = self.arp.lock().build_request(payload, target_ip) {
                frame.set_payload_len(len);
                frame.pad_to_minimum();
                
                // Mark request as sent
                self.arp.lock().request_sent(target_ip, current_time);
                
                self.transmit(frame.as_bytes());
            }
        }
    }
    
    /// Send ICMP echo reply
    fn send_icmp_echo_reply(
        &self,
        dst_ip: Ipv4Address,
        identifier: u16,
        sequence: u16,
        echo_data: &[u8],
        current_time: u64,
    ) {
        let config = self.config.lock().clone();
        
        // Resolve MAC address
        let dst_mac = if config.ipv4.is_local(&dst_ip) {
            // Destination is on local subnet, use ARP
            match self.arp.lock().resolve(dst_ip, current_time) {
                Some(mac) => mac,
                None => {
                    // Need to send ARP request first
                    self.send_arp_request(dst_ip);
                    return;
                }
            }
        } else {
            // Destination is remote, use gateway
            match self.arp.lock().resolve(config.ipv4.gateway, current_time) {
                Some(mac) => mac,
                None => {
                    self.send_arp_request(config.ipv4.gateway);
                    return;
                }
            }
        };
        
        let mut buffer = [0u8; MAX_PACKET_SIZE];
        
        // Build Ethernet frame
        if let Some(mut frame) = EthernetFrameMut::new(&mut buffer) {
            frame.set_destination(dst_mac)
                 .set_source(config.mac)
                 .set_ether_type(EtherType::Ipv4);
            
            let eth_payload = frame.payload_mut();
            
            // Build IP packet
            if let Some(mut ip_packet) = Ipv4PacketMut::new(eth_payload) {
                ip_packet.init_header()
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
        &self,
        src_port: u16,
        dst_ip: Ipv4Address,
        dst_port: u16,
        data: &[u8],
    ) -> bool {
        let config = self.config.lock().clone();
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
            frame.set_destination(dst_mac)
                 .set_source(config.mac)
                 .set_ether_type(EtherType::Ipv4);
            
            let eth_payload = frame.payload_mut();
            
            // Build IP packet
            if let Some(mut ip_packet) = Ipv4PacketMut::new(eth_payload) {
                ip_packet.init_header()
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
        &self,
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
        let arp = self.arp.lock();
        match arp.resolve(next_hop, current_time) {
            Some(mac) => Some(mac),
            None => {
                drop(arp);
                // Need ARP resolution
                self.send_arp_request(next_hop);
                None
            }
        }
    }
    
    /// Bind a UDP socket
    pub fn bind_udp(&self, port: u16) -> Option<UdpSocket> {
        self.udp.bind(port)
    }
    
    /// Transmit a raw Ethernet frame
    pub fn transmit(&self, data: &[u8]) -> bool {
        let tx_fn = self.transmit_fn.lock();
        
        if let Some(f) = *tx_fn {
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
        self.arp.lock().cache().all_entries()
            .iter()
            .filter(|e| e.state == super::arp::ArpEntryState::Resolved)
            .map(|e| (e.ip, e.mac))
            .collect()
    }
    
    /// Periodic maintenance (call from timer)
    pub fn periodic(&self) {
        let current_time = self.current_time();
        
        // Expire old ARP entries
        self.arp.lock().cache().expire_old(current_time);
    }
}

/// Global network stack instance
static NETWORK_STACK: Mutex<Option<NetworkStack>> = Mutex::new(None);

/// Initialize the global network stack
pub fn init(config: NetworkConfig) {
    let mut stack = NETWORK_STACK.lock();
    *stack = Some(NetworkStack::new(config));
}

/// Initialize with default configuration
pub fn init_default() {
    init(NetworkConfig::default());
}

/// Get the global network stack
pub fn stack() -> &'static Mutex<Option<NetworkStack>> {
    &NETWORK_STACK
}

/// Process a received packet
pub fn receive(data: &[u8]) {
    if let Some(ref stack) = *NETWORK_STACK.lock() {
        stack.receive(data);
    }
}

/// Send a UDP datagram
pub fn send_udp(src_port: u16, dst_ip: Ipv4Address, dst_port: u16, data: &[u8]) -> bool {
    if let Some(ref stack) = *NETWORK_STACK.lock() {
        stack.send_udp(src_port, dst_ip, dst_port, data)
    } else {
        false
    }
}

/// Bind a UDP socket
pub fn bind_udp(port: u16) -> Option<UdpSocket> {
    NETWORK_STACK.lock().as_ref().and_then(|s| s.bind_udp(port))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_network_stack_creation() {
        let stack = NetworkStack::new_default();
        let config = stack.config();
        
        assert_eq!(config.mac, MacAddress::from_octets(0x02, 0x00, 0x00, 0x00, 0x00, 0x01));
        assert!(config.icmp_echo_enabled);
    }
}
