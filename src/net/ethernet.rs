//! Ethernet frame processing for ExoRust
//!
//! This module implements zero-copy Ethernet frame handling
//! as specified in Section 6.2 of the ExoRust specification.

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use core::fmt;

/// Ethernet frame type (EtherType)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum EtherType {
    /// IPv4 Protocol
    Ipv4 = 0x0800,
    /// ARP Protocol
    Arp = 0x0806,
    /// IPv6 Protocol
    Ipv6 = 0x86DD,
    /// VLAN Tagged Frame
    Vlan = 0x8100,
    /// Unknown/Other
    Unknown(u16),
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        match value {
            0x0800 => EtherType::Ipv4,
            0x0806 => EtherType::Arp,
            0x86DD => EtherType::Ipv6,
            0x8100 => EtherType::Vlan,
            other => EtherType::Unknown(other),
        }
    }
}

impl From<EtherType> for u16 {
    fn from(value: EtherType) -> Self {
        match value {
            EtherType::Ipv4 => 0x0800,
            EtherType::Arp => 0x0806,
            EtherType::Ipv6 => 0x86DD,
            EtherType::Vlan => 0x8100,
            EtherType::Unknown(v) => v,
        }
    }
}

/// MAC address (6 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    /// Broadcast MAC address (FF:FF:FF:FF:FF:FF)
    pub const BROADCAST: MacAddress = MacAddress([0xff; 6]);

    /// Zero MAC address (00:00:00:00:00:00)
    pub const ZERO: MacAddress = MacAddress([0; 6]);

    /// Create a new MAC address from bytes
    pub const fn new(bytes: [u8; 6]) -> Self {
        MacAddress(bytes)
    }

    /// Create MAC address from individual octets
    pub const fn from_octets(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        MacAddress([a, b, c, d, e, f])
    }

    /// Get the underlying bytes
    pub const fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }

    /// Check if this is a broadcast address
    pub const fn is_broadcast(&self) -> bool {
        self.0[0] == 0xff
            && self.0[1] == 0xff
            && self.0[2] == 0xff
            && self.0[3] == 0xff
            && self.0[4] == 0xff
            && self.0[5] == 0xff
    }

    /// Check if this is a multicast address (LSB of first byte is 1)
    pub const fn is_multicast(&self) -> bool {
        (self.0[0] & 0x01) != 0
    }

    /// Check if this is a unicast address
    pub const fn is_unicast(&self) -> bool {
        !self.is_multicast()
    }

    /// Check if this is a locally administered address
    pub const fn is_local(&self) -> bool {
        (self.0[0] & 0x02) != 0
    }
}

impl fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Ethernet frame header (14 bytes)
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct EthernetHeader {
    /// Destination MAC address
    pub dst_mac: [u8; 6],
    /// Source MAC address
    pub src_mac: [u8; 6],
    /// EtherType (big-endian)
    pub ether_type: [u8; 2],
}

impl EthernetHeader {
    /// Size of Ethernet header in bytes
    pub const SIZE: usize = 14;

    /// Get destination MAC address
    pub fn destination(&self) -> MacAddress {
        MacAddress::new(self.dst_mac)
    }

    /// Get source MAC address
    pub fn source(&self) -> MacAddress {
        MacAddress::new(self.src_mac)
    }

    /// Get EtherType
    pub fn ether_type(&self) -> EtherType {
        let value = u16::from_be_bytes(self.ether_type);
        EtherType::from(value)
    }

    /// Set destination MAC address
    pub fn set_destination(&mut self, mac: MacAddress) {
        self.dst_mac = *mac.as_bytes();
    }

    /// Set source MAC address
    pub fn set_source(&mut self, mac: MacAddress) {
        self.src_mac = *mac.as_bytes();
    }

    /// Set EtherType
    pub fn set_ether_type(&mut self, ether_type: EtherType) {
        self.ether_type = u16::to_be_bytes(ether_type.into());
    }
}

/// Zero-copy Ethernet frame view
pub struct EthernetFrame<'a> {
    /// Raw frame data
    data: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    /// Minimum Ethernet frame size (without FCS)
    pub const MIN_SIZE: usize = 60;
    /// Maximum Ethernet frame size (without FCS)  
    pub const MAX_SIZE: usize = 1514;
    /// Maximum payload size (MTU)
    pub const MTU: usize = 1500;

    /// Parse an Ethernet frame from raw bytes (zero-copy)
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < EthernetHeader::SIZE {
            return None;
        }
        Some(EthernetFrame { data })
    }

    /// Get the Ethernet header
    pub fn header(&self) -> &EthernetHeader {
        // SAFETY: We verified the length in parse()
        unsafe { &*(self.data.as_ptr() as *const EthernetHeader) }
    }

    /// Get destination MAC address
    pub fn destination(&self) -> MacAddress {
        self.header().destination()
    }

    /// Get source MAC address
    pub fn source(&self) -> MacAddress {
        self.header().source()
    }

    /// Get EtherType
    pub fn ether_type(&self) -> EtherType {
        self.header().ether_type()
    }

    /// Get the payload (zero-copy)
    pub fn payload(&self) -> &'a [u8] {
        &self.data[EthernetHeader::SIZE..]
    }

    /// Get the entire raw frame data
    pub fn as_bytes(&self) -> &'a [u8] {
        self.data
    }
}

/// Mutable Ethernet frame for building frames
pub struct EthernetFrameMut<'a> {
    /// Raw frame buffer
    data: &'a mut [u8],
    /// Current payload length
    payload_len: usize,
}

impl<'a> EthernetFrameMut<'a> {
    /// Create a new Ethernet frame builder with a buffer
    pub fn new(buffer: &'a mut [u8]) -> Option<Self> {
        if buffer.len() < EthernetHeader::SIZE {
            return None;
        }
        Some(EthernetFrameMut {
            data: buffer,
            payload_len: 0,
        })
    }

    /// Get mutable header
    pub fn header_mut(&mut self) -> &mut EthernetHeader {
        // SAFETY: Buffer is large enough (checked in new())
        unsafe { &mut *(self.data.as_mut_ptr() as *mut EthernetHeader) }
    }

    /// Set destination MAC address
    pub fn set_destination(&mut self, mac: MacAddress) -> &mut Self {
        self.header_mut().set_destination(mac);
        self
    }

    /// Set source MAC address
    pub fn set_source(&mut self, mac: MacAddress) -> &mut Self {
        self.header_mut().set_source(mac);
        self
    }

    /// Set EtherType
    pub fn set_ether_type(&mut self, ether_type: EtherType) -> &mut Self {
        self.header_mut().set_ether_type(ether_type);
        self
    }

    /// Get mutable payload buffer
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.data[EthernetHeader::SIZE..]
    }

    /// Set payload length (after writing payload)
    pub fn set_payload_len(&mut self, len: usize) -> &mut Self {
        self.payload_len = len.min(self.data.len() - EthernetHeader::SIZE);
        self
    }

    /// Copy payload data
    pub fn write_payload(&mut self, payload: &[u8]) -> usize {
        let max_len = self.data.len() - EthernetHeader::SIZE;
        let copy_len = payload.len().min(max_len);
        self.data[EthernetHeader::SIZE..EthernetHeader::SIZE + copy_len]
            .copy_from_slice(&payload[..copy_len]);
        self.payload_len = copy_len;
        copy_len
    }

    /// Get total frame length
    pub fn total_len(&self) -> usize {
        EthernetHeader::SIZE + self.payload_len
    }

    /// Get the complete frame as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.total_len()]
    }

    /// Pad frame to minimum size if needed
    pub fn pad_to_minimum(&mut self) {
        let current_len = self.total_len();
        if current_len < EthernetFrame::MIN_SIZE {
            // Zero out padding
            for byte in &mut self.data[current_len..EthernetFrame::MIN_SIZE] {
                *byte = 0;
            }
            self.payload_len = EthernetFrame::MIN_SIZE - EthernetHeader::SIZE;
        }
    }
}

/// Ethernet frame processor for zero-copy packet handling
pub struct EthernetProcessor {
    /// Local MAC address
    local_mac: MacAddress,
    /// Statistics
    stats: EthernetStats,
}

/// Ethernet statistics
#[derive(Debug, Default)]
pub struct EthernetStats {
    /// Packets received
    pub rx_packets: u64,
    /// Bytes received
    pub rx_bytes: u64,
    /// Packets transmitted
    pub tx_packets: u64,
    /// Bytes transmitted
    pub tx_bytes: u64,
    /// Packets dropped (wrong destination)
    pub rx_dropped: u64,
    /// Invalid frames
    pub rx_errors: u64,
}

/// Result of processing an Ethernet frame
pub enum ProcessResult<'a> {
    /// IPv4 packet to process
    Ipv4(&'a [u8]),
    /// IPv6 packet to process
    Ipv6(&'a [u8]),
    /// ARP packet to process
    Arp(&'a [u8]),
    /// Frame was dropped (not for us)
    Dropped,
    /// Frame was invalid
    Error,
}

impl EthernetProcessor {
    /// Create a new Ethernet processor
    pub fn new(local_mac: MacAddress) -> Self {
        EthernetProcessor {
            local_mac,
            stats: EthernetStats::default(),
        }
    }

    /// Get local MAC address
    pub fn local_mac(&self) -> MacAddress {
        self.local_mac
    }

    /// Set local MAC address
    pub fn set_local_mac(&mut self, mac: MacAddress) {
        self.local_mac = mac;
    }

    /// Get statistics
    pub fn stats(&self) -> &EthernetStats {
        &self.stats
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = EthernetStats::default();
    }

    /// Process an incoming Ethernet frame (zero-copy)
    pub fn process<'a>(&mut self, data: &'a [u8]) -> ProcessResult<'a> {
        let frame = match EthernetFrame::parse(data) {
            Some(f) => f,
            None => {
                self.stats.rx_errors += 1;
                return ProcessResult::Error;
            }
        };

        // Check destination
        let dst = frame.destination();
        if !dst.is_broadcast() && !self.is_for_us(&dst) {
            self.stats.rx_dropped += 1;
            return ProcessResult::Dropped;
        }

        // Update stats
        self.stats.rx_packets += 1;
        self.stats.rx_bytes += data.len() as u64;

        // Dispatch by EtherType
        match frame.ether_type() {
            EtherType::Ipv4 => ProcessResult::Ipv4(frame.payload()),
            EtherType::Ipv6 => ProcessResult::Ipv6(frame.payload()),
            EtherType::Arp => ProcessResult::Arp(frame.payload()),
            _ => ProcessResult::Dropped,
        }
    }

    /// Check if a MAC address is for us
    fn is_for_us(&self, mac: &MacAddress) -> bool {
        *mac == self.local_mac || mac.is_broadcast()
    }

    /// Build a reply frame (swaps src/dst)
    pub fn build_reply<'a>(
        &mut self,
        buffer: &'a mut [u8],
        dst_mac: MacAddress,
        ether_type: EtherType,
    ) -> Option<EthernetFrameMut<'a>> {
        let mut frame = EthernetFrameMut::new(buffer)?;
        frame
            .set_destination(dst_mac)
            .set_source(self.local_mac)
            .set_ether_type(ether_type);
        Some(frame)
    }

    /// Record transmitted frame
    pub fn record_tx(&mut self, len: usize) {
        self.stats.tx_packets += 1;
        self.stats.tx_bytes += len as u64;
    }
}

/// VLAN tag (802.1Q)
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct VlanTag {
    /// Tag Protocol Identifier (0x8100)
    pub tpid: [u8; 2],
    /// Tag Control Information
    pub tci: [u8; 2],
}

impl VlanTag {
    /// Size of VLAN tag
    pub const SIZE: usize = 4;

    /// Get VLAN ID (12 bits)
    pub fn vlan_id(&self) -> u16 {
        u16::from_be_bytes(self.tci) & 0x0FFF
    }

    /// Get Priority Code Point (3 bits)
    pub fn pcp(&self) -> u8 {
        (self.tci[0] >> 5) & 0x07
    }

    /// Get Drop Eligible Indicator
    pub fn dei(&self) -> bool {
        (self.tci[0] & 0x10) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_address() {
        let mac = MacAddress::from_octets(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        assert!(!mac.is_broadcast());
        assert!(mac.is_unicast());

        assert!(MacAddress::BROADCAST.is_broadcast());
        assert!(MacAddress::BROADCAST.is_multicast());
    }

    #[test]
    fn test_ether_type() {
        assert_eq!(EtherType::from(0x0800), EtherType::Ipv4);
        assert_eq!(EtherType::from(0x0806), EtherType::Arp);
        assert_eq!(u16::from(EtherType::Ipv4), 0x0800);
    }
}
