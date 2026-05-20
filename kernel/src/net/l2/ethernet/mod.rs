// ============================================================================
// kernel/src/net/l2/ethernet/mod.rs - L2 / Ethernet モジュール
// ============================================================================
//! Ethernet frame processing for ExoRust
//!
//! This module implements zero-copy Ethernet frame handling
//! as specified in Section 6.2 of the ExoRust specification.

use core::fmt;
use kernel_api::resource::net::{PacketByteCount, PacketRef};

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
    header: &'a EthernetHeader,
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
        let header = crate::util::get_ref::<EthernetHeader>(data, 0)?;
        Some(EthernetFrame { header, data })
    }

    /// Get the Ethernet header
    pub fn header(&self) -> &EthernetHeader {
        self.header
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
    pub fn header_mut(&mut self) -> Option<&mut EthernetHeader> {
        crate::util::get_mut_ref::<EthernetHeader>(self.data, 0)
    }

    /// Set destination MAC address
    pub fn set_destination(&mut self, mac: MacAddress) -> &mut Self {
        if let Some(h) = self.header_mut() {
            h.set_destination(mac);
        }
        self
    }

    /// Set source MAC address
    pub fn set_source(&mut self, mac: MacAddress) -> &mut Self {
        if let Some(h) = self.header_mut() {
            h.set_source(mac);
        }
        self
    }

    /// Set EtherType
    pub fn set_ether_type(&mut self, ether_type: EtherType) -> &mut Self {
        if let Some(h) = self.header_mut() {
            h.set_ether_type(ether_type);
        }
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
            // SECURITY: 実 buffer 末尾を越えて書き込まないことを保証する。
            let pad_end = EthernetFrame::MIN_SIZE.min(self.data.len());
            // Zero out padding
            for byte in &mut self.data[current_len..pad_end] {
                *byte = 0;
            }
            self.payload_len = pad_end - EthernetHeader::SIZE;
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

/// Result of consuming an Ethernet frame owner.
pub enum EthernetIngress {
    /// IPv4 packet to process
    Ipv4 {
        packet: PacketRef,
        src_mac: MacAddress,
    },
    /// IPv6 packet to process
    Ipv6 {
        packet: PacketRef,
        src_mac: MacAddress,
    },
    /// ARP packet to process
    Arp {
        packet: PacketRef,
        src_mac: MacAddress,
    },
    /// VLAN tagged frame - contains (VLAN ID, inner payload, inner EtherType)
    VlanTagged {
        vlan_id: u16,
        pcp: u8,
        dei: bool,
        inner_type: EtherType,
        packet: PacketRef,
        src_mac: MacAddress,
    },
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

    /// Process an incoming Ethernet frame by consuming the packet owner.
    pub fn process_packet(&mut self, packet: PacketRef) -> EthernetIngress {
        let (frame_len, src_mac, ether_type, payload_len) = {
            let data = packet.data();
            let frame = match EthernetFrame::parse(data) {
                Some(f) => f,
                None => {
                    self.stats.rx_errors += 1;
                    return EthernetIngress::Error;
                }
            };

            // Check destination
            let dst = frame.destination();
            if !dst.is_broadcast() && !self.is_for_us(&dst) {
                self.stats.rx_dropped += 1;
                return EthernetIngress::Dropped;
            }

            (
                data.len(),
                frame.source(),
                frame.ether_type(),
                frame.payload().len(),
            )
        };

        // Update stats
        self.stats.rx_packets += 1;
        self.stats.rx_bytes += frame_len as u64;

        // Dispatch by EtherType
        match ether_type {
            EtherType::Ipv4 => {
                self.finish_payload_packet(packet, EthernetHeader::SIZE, payload_len, |packet| {
                    EthernetIngress::Ipv4 { packet, src_mac }
                })
            }
            EtherType::Ipv6 => {
                self.finish_payload_packet(packet, EthernetHeader::SIZE, payload_len, |packet| {
                    EthernetIngress::Ipv6 { packet, src_mac }
                })
            }
            EtherType::Arp => {
                self.finish_payload_packet(packet, EthernetHeader::SIZE, payload_len, |packet| {
                    EthernetIngress::Arp { packet, src_mac }
                })
            }
            EtherType::Vlan => self.process_vlan_packet(packet, src_mac),
            _ => EthernetIngress::Dropped,
        }
    }

    /// Process a VLAN-tagged frame (802.1Q)
    fn process_vlan_packet(&mut self, packet: PacketRef, src_mac: MacAddress) -> EthernetIngress {
        let Some((vlan_id, pcp, dei, inner_type, inner_payload_len)) =
            self.parse_vlan_payload(packet.data())
        else {
            return EthernetIngress::Error;
        };

        let inner_payload_offset = EthernetHeader::SIZE + 4;
        match inner_type {
            EtherType::Ipv4 => self.finish_payload_packet(
                packet,
                inner_payload_offset,
                inner_payload_len,
                |packet| EthernetIngress::Ipv4 { packet, src_mac },
            ),
            EtherType::Ipv6 => self.finish_payload_packet(
                packet,
                inner_payload_offset,
                inner_payload_len,
                |packet| EthernetIngress::Ipv6 { packet, src_mac },
            ),
            EtherType::Arp => self.finish_payload_packet(
                packet,
                inner_payload_offset,
                inner_payload_len,
                |packet| EthernetIngress::Arp { packet, src_mac },
            ),
            _ => self.finish_payload_packet(
                packet,
                inner_payload_offset,
                inner_payload_len,
                |packet| EthernetIngress::VlanTagged {
                    vlan_id,
                    pcp,
                    dei,
                    inner_type,
                    packet,
                    src_mac,
                },
            ),
        }
    }

    fn parse_vlan_payload(
        &mut self,
        frame_data: &[u8],
    ) -> Option<(u16, u8, bool, EtherType, usize)> {
        let payload = frame_data.get(EthernetHeader::SIZE..)?;
        // Payload starts after the outer 0x8100 EtherType: TCI (2 bytes),
        // inner EtherType (2 bytes), then the inner payload.
        if payload.len() < 4 {
            self.stats.rx_errors += 1;
            return None;
        }
        let tci = u16::from_be_bytes([payload[0], payload[1]]);
        let vlan_id = tci & 0x0FFF;
        let pcp = ((tci >> 13) & 0x07) as u8;
        let dei = (tci & 0x1000) != 0;
        let inner_ethertype = u16::from_be_bytes([payload[2], payload[3]]);
        let inner_type = EtherType::from(inner_ethertype);
        Some((vlan_id, pcp, dei, inner_type, payload.len() - 4))
    }

    fn finish_payload_packet(
        &mut self,
        mut packet: PacketRef,
        offset: usize,
        len: usize,
        make_result: impl FnOnce(PacketRef) -> EthernetIngress,
    ) -> EthernetIngress {
        let Some(len) = PacketByteCount::new(len) else {
            self.stats.rx_errors += 1;
            return EthernetIngress::Error;
        };
        if offset > 0
            && !packet.advance(PacketByteCount::new(offset).expect("positive Ethernet offset"))
        {
            self.stats.rx_errors += 1;
            return EthernetIngress::Error;
        }
        if !packet.set_len(len) {
            self.stats.rx_errors += 1;
            return EthernetIngress::Error;
        }
        make_result(packet)
    }

    /// Check if a MAC address is for us
    ///
    /// ユニキャスト: 自分のMAC宛のみ受理
    /// ブロードキャスト/マルチキャスト: 全て受理（上位レイヤでIGMPグループフィルタリング）
    fn is_for_us(&self, mac: &MacAddress) -> bool {
        *mac == self.local_mac || mac.is_broadcast() || mac.is_multicast()
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

    /// Create a new VLAN tag
    pub const fn new(vlan_id: u16, pcp: u8, dei: bool) -> Self {
        let tci_val =
            (vlan_id & 0x0FFF) | ((pcp as u16 & 0x07) << 13) | if dei { 0x1000 } else { 0 };
        Self {
            tpid: [0x81, 0x00],
            tci: tci_val.to_be_bytes(),
        }
    }

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

    /// Serialize the VLAN tag to bytes
    pub fn to_bytes(&self) -> [u8; 4] {
        [self.tpid[0], self.tpid[1], self.tci[0], self.tci[1]]
    }
}

// ============================================================================
// VLAN-Aware Ethernet Frame Builder (802.1Q TX)
// ============================================================================

/// Ethernet frame with 802.1Q VLAN tag for transmission
///
/// Frame layout: DST(6) + SRC(6) + TPID(2) + TCI(2) + EtherType(2) + Payload
/// Total header = 18 bytes (vs 14 for untagged)
pub struct VlanEthernetFrameMut<'a> {
    /// Raw frame buffer
    data: &'a mut [u8],
    /// Current payload length
    payload_len: usize,
}

impl<'a> VlanEthernetFrameMut<'a> {
    /// VLAN-tagged Ethernet header size (14 + 4 = 18 bytes)
    pub const HEADER_SIZE: usize = 18;

    /// Maximum frame size (1518 + 4 for VLAN tag)
    pub const MAX_SIZE: usize = 1522;

    /// Create a new VLAN-tagged Ethernet frame builder
    pub fn new(buffer: &'a mut [u8]) -> Option<Self> {
        if buffer.len() < Self::HEADER_SIZE {
            return None;
        }
        Some(VlanEthernetFrameMut {
            data: buffer,
            payload_len: 0,
        })
    }

    /// Set destination MAC address
    pub fn set_destination(&mut self, mac: MacAddress) -> &mut Self {
        self.data[0..6].copy_from_slice(mac.as_bytes());
        self
    }

    /// Set source MAC address
    pub fn set_source(&mut self, mac: MacAddress) -> &mut Self {
        self.data[6..12].copy_from_slice(mac.as_bytes());
        self
    }

    /// Set VLAN tag (TPID + TCI)
    pub fn set_vlan_tag(&mut self, vlan_id: u16, pcp: u8, dei: bool) -> &mut Self {
        let tag = VlanTag::new(vlan_id, pcp, dei);
        let tag_bytes = tag.to_bytes();
        self.data[12..16].copy_from_slice(&tag_bytes);
        self
    }

    /// Set inner EtherType (after VLAN tag)
    pub fn set_ether_type(&mut self, ether_type: EtherType) -> &mut Self {
        let et_bytes = u16::to_be_bytes(ether_type.into());
        self.data[16..18].copy_from_slice(&et_bytes);
        self
    }

    /// Get mutable payload buffer (after VLAN + EtherType)
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.data[Self::HEADER_SIZE..]
    }

    /// Set payload length
    pub fn set_payload_len(&mut self, len: usize) -> &mut Self {
        self.payload_len = len.min(self.data.len() - Self::HEADER_SIZE);
        self
    }

    /// Get total frame length
    pub fn total_len(&self) -> usize {
        Self::HEADER_SIZE + self.payload_len
    }

    /// Get the complete frame as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.total_len()]
    }

    /// Pad frame to minimum size (64 bytes for tagged)
    pub fn pad_to_minimum(&mut self) {
        let min_size = 64; // 802.1Q minimum frame size
        let current_len = self.total_len();
        if current_len < min_size {
            // SECURITY: 実 buffer 末尾を越えて書き込まないことを保証する。
            let pad_end = min_size.min(self.data.len());
            for byte in &mut self.data[current_len..pad_end] {
                *byte = 0;
            }
            self.payload_len = pad_end - Self::HEADER_SIZE;
        }
    }
}

/// Insert a VLAN tag into an existing untagged Ethernet frame
///
/// Takes an untagged frame buffer, shifts the payload to make room for the
/// 4-byte VLAN tag, and inserts the tag. Returns the new frame length.
///
/// `frame` must be large enough to hold the additional 4 bytes.
/// `frame_len` is the current length of the untagged frame.
pub fn insert_vlan_tag(
    frame: &mut [u8],
    frame_len: usize,
    vlan_id: u16,
    pcp: u8,
    dei: bool,
) -> Option<usize> {
    let new_len = frame_len + VlanTag::SIZE;
    if new_len > frame.len() || frame_len < EthernetHeader::SIZE {
        return None;
    }

    // Shift payload (everything after dst+src MAC, i.e. from offset 12) by 4 bytes
    // We need to move bytes [12..frame_len] to [16..frame_len+4]
    frame.copy_within(12..frame_len, 16);

    // Insert VLAN tag at offset 12
    let tag = VlanTag::new(vlan_id, pcp, dei);
    let tag_bytes = tag.to_bytes();
    frame[12..16].copy_from_slice(&tag_bytes);

    Some(new_len)
}

/// Strip a VLAN tag from a tagged frame
///
/// Removes the 4-byte VLAN tag and shifts payload back.
/// Returns (vlan_id, new_frame_len).
pub fn strip_vlan_tag(frame: &mut [u8], frame_len: usize) -> Option<(u16, usize)> {
    if frame_len < VlanEthernetFrameMut::HEADER_SIZE || frame_len > frame.len() {
        return None;
    }

    // Check TPID
    let tpid = u16::from_be_bytes([frame[12], frame[13]]);
    if tpid != 0x8100 {
        return None;
    }

    // Read VLAN ID
    let tci = u16::from_be_bytes([frame[14], frame[15]]);
    let vlan_id = tci & 0x0FFF;

    // Shift payload back: move [16..frame_len] to [12..frame_len-4]
    let new_len = frame_len - VlanTag::SIZE;
    frame.copy_within(16..frame_len, 12);

    Some((vlan_id, new_len))
}

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests {
    use super::*;
    use crate::net::payload::alloc_packet_with_headroom;
    use kernel_api::resource::net::DEFAULT_PACKET_HEADROOM;

    #[cfg_attr(test, test_case)]
    pub fn test_mac_address() {
        let mac = MacAddress::from_octets(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        assert!(!mac.is_broadcast());
        assert!(mac.is_unicast());

        assert!(MacAddress::BROADCAST.is_broadcast());
        assert!(MacAddress::BROADCAST.is_multicast());
    }

    #[cfg_attr(test, test_case)]
    pub fn test_ether_type() {
        assert_eq!(EtherType::from(0x0800), EtherType::Ipv4);
        assert_eq!(EtherType::from(0x0806), EtherType::Arp);
        assert_eq!(u16::from(EtherType::Ipv4), 0x0800);
    }

    fn test_packet_with_contents(bytes: &[u8]) -> PacketRef {
        let mut packet =
            alloc_packet_with_headroom(bytes.len(), DEFAULT_PACKET_HEADROOM).expect("packet");
        packet.data_mut().copy_from_slice(bytes);
        packet
    }

    #[cfg_attr(test, test_case)]
    pub fn test_process_packet_returns_owned_ipv4_payload() {
        let local = MacAddress::from_octets(0x02, 0, 0, 0, 0, 1);
        let src = MacAddress::from_octets(0x02, 0, 0, 0, 0, 2);
        let mut frame = [0u8; EthernetHeader::SIZE + 4];
        frame[0..6].copy_from_slice(local.as_bytes());
        frame[6..12].copy_from_slice(src.as_bytes());
        frame[12..14].copy_from_slice(&u16::to_be_bytes(EtherType::Ipv4.into()));
        frame[EthernetHeader::SIZE..].copy_from_slice(b"ipv4");

        let mut processor = EthernetProcessor::new(local);

        match processor.process_packet(test_packet_with_contents(&frame)) {
            EthernetIngress::Ipv4 { packet, src_mac } => {
                assert_eq!(src_mac, src);
                assert_eq!(packet.data(), b"ipv4");
            }
            _ => panic!("expected owned IPv4 ingress"),
        }
    }
}
