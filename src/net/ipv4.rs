//! IPv4 Protocol Implementation for ExoRust
//!
//! Zero-copy IPv4 packet processing as specified in Section 6.2
//! of the ExoRust specification.

use core::fmt;

/// IPv4 address (4 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Ipv4Address([u8; 4]);

impl Ipv4Address {
    /// Any address (0.0.0.0)
    pub const ANY: Ipv4Address = Ipv4Address([0, 0, 0, 0]);

    /// Broadcast address (255.255.255.255)
    pub const BROADCAST: Ipv4Address = Ipv4Address([255, 255, 255, 255]);

    /// Loopback address (127.0.0.1)
    pub const LOOPBACK: Ipv4Address = Ipv4Address([127, 0, 0, 1]);

    /// Create from bytes
    pub const fn new(bytes: [u8; 4]) -> Self {
        Ipv4Address(bytes)
    }

    /// Create from individual octets
    pub const fn from_octets(a: u8, b: u8, c: u8, d: u8) -> Self {
        Ipv4Address([a, b, c, d])
    }

    /// Get the underlying bytes
    pub const fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }

    /// Convert to u32 (network byte order)
    pub const fn to_u32(&self) -> u32 {
        ((self.0[0] as u32) << 24)
            | ((self.0[1] as u32) << 16)
            | ((self.0[2] as u32) << 8)
            | (self.0[3] as u32)
    }

    /// Create from u32 (network byte order)
    pub const fn from_u32(value: u32) -> Self {
        Ipv4Address([
            (value >> 24) as u8,
            (value >> 16) as u8,
            (value >> 8) as u8,
            value as u8,
        ])
    }

    /// Check if this is a broadcast address
    pub const fn is_broadcast(&self) -> bool {
        self.0[0] == 255 && self.0[1] == 255 && self.0[2] == 255 && self.0[3] == 255
    }

    /// Check if this is the any address
    pub const fn is_any(&self) -> bool {
        self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }

    /// Check if this is a loopback address (127.x.x.x)
    pub const fn is_loopback(&self) -> bool {
        self.0[0] == 127
    }

    /// Check if this is a multicast address (224.0.0.0 - 239.255.255.255)
    pub const fn is_multicast(&self) -> bool {
        self.0[0] >= 224 && self.0[0] <= 239
    }

    /// Check if this is a link-local address (169.254.x.x)
    pub const fn is_link_local(&self) -> bool {
        self.0[0] == 169 && self.0[1] == 254
    }

    /// Check if this is a private address
    pub const fn is_private(&self) -> bool {
        // 10.0.0.0/8
        self.0[0] == 10 ||
        // 172.16.0.0/12
        (self.0[0] == 172 && (self.0[1] & 0xf0) == 16) ||
        // 192.168.0.0/16
        (self.0[0] == 192 && self.0[1] == 168)
    }

    /// Apply a subnet mask
    pub const fn apply_mask(&self, mask: Ipv4Address) -> Ipv4Address {
        Ipv4Address([
            self.0[0] & mask.0[0],
            self.0[1] & mask.0[1],
            self.0[2] & mask.0[2],
            self.0[3] & mask.0[3],
        ])
    }

    /// Check if two addresses are in the same subnet
    pub const fn same_subnet(&self, other: &Ipv4Address, mask: Ipv4Address) -> bool {
        (self.0[0] & mask.0[0]) == (other.0[0] & mask.0[0])
            && (self.0[1] & mask.0[1]) == (other.0[1] & mask.0[1])
            && (self.0[2] & mask.0[2]) == (other.0[2] & mask.0[2])
            && (self.0[3] & mask.0[3]) == (other.0[3] & mask.0[3])
    }
}

impl fmt::Debug for Ipv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

impl fmt::Display for Ipv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// IPv4 protocol numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpProtocol {
    /// Internet Control Message Protocol
    Icmp = 1,
    /// Transmission Control Protocol
    Tcp = 6,
    /// User Datagram Protocol
    Udp = 17,
    /// Generic Routing Encapsulation
    Gre = 47,
    /// Unknown protocol
    Unknown(u8),
}

impl From<u8> for IpProtocol {
    fn from(value: u8) -> Self {
        match value {
            1 => IpProtocol::Icmp,
            6 => IpProtocol::Tcp,
            17 => IpProtocol::Udp,
            47 => IpProtocol::Gre,
            other => IpProtocol::Unknown(other),
        }
    }
}

impl From<IpProtocol> for u8 {
    fn from(value: IpProtocol) -> Self {
        match value {
            IpProtocol::Icmp => 1,
            IpProtocol::Tcp => 6,
            IpProtocol::Udp => 17,
            IpProtocol::Gre => 47,
            IpProtocol::Unknown(v) => v,
        }
    }
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

impl Ipv4Header {
    /// Minimum header size (no options)
    pub const MIN_SIZE: usize = 20;
    /// Maximum header size (with options)
    pub const MAX_SIZE: usize = 60;

    /// Get IP version (should be 4)
    pub const fn version(&self) -> u8 {
        self.version_ihl >> 4
    }

    /// Get Internet Header Length in 32-bit words
    pub const fn ihl(&self) -> u8 {
        self.version_ihl & 0x0F
    }

    /// Get header length in bytes
    pub const fn header_len(&self) -> usize {
        (self.ihl() as usize) * 4
    }

    /// Get DSCP (Differentiated Services Code Point)
    pub const fn dscp(&self) -> u8 {
        self.dscp_ecn >> 2
    }

    /// Get ECN (Explicit Congestion Notification)
    pub const fn ecn(&self) -> u8 {
        self.dscp_ecn & 0x03
    }

    /// Get total length
    pub fn total_length(&self) -> u16 {
        u16::from_be_bytes(self.total_length)
    }

    /// Set total length
    pub fn set_total_length(&mut self, len: u16) {
        self.total_length = len.to_be_bytes();
    }

    /// Get identification
    pub fn identification(&self) -> u16 {
        u16::from_be_bytes(self.identification)
    }

    /// Set identification
    pub fn set_identification(&mut self, id: u16) {
        self.identification = id.to_be_bytes();
    }

    /// Get flags
    pub fn flags(&self) -> u8 {
        self.flags_fragment[0] >> 5
    }

    /// Check "Don't Fragment" flag
    pub fn dont_fragment(&self) -> bool {
        (self.flags_fragment[0] & 0x40) != 0
    }

    /// Check "More Fragments" flag
    pub fn more_fragments(&self) -> bool {
        (self.flags_fragment[0] & 0x20) != 0
    }

    /// Get fragment offset (in 8-byte units)
    pub fn fragment_offset(&self) -> u16 {
        u16::from_be_bytes([self.flags_fragment[0] & 0x1F, self.flags_fragment[1]])
    }

    /// Get TTL
    pub const fn ttl(&self) -> u8 {
        self.ttl
    }

    /// Set TTL
    pub fn set_ttl(&mut self, ttl: u8) {
        self.ttl = ttl;
    }

    /// Get protocol
    pub fn protocol(&self) -> IpProtocol {
        IpProtocol::from(self.protocol)
    }

    /// Set protocol
    pub fn set_protocol(&mut self, protocol: IpProtocol) {
        self.protocol = protocol.into();
    }

    /// Get checksum
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.checksum)
    }

    /// Set checksum
    pub fn set_checksum(&mut self, checksum: u16) {
        self.checksum = checksum.to_be_bytes();
    }

    /// Get source address
    pub fn source(&self) -> Ipv4Address {
        Ipv4Address::new(self.src_addr)
    }

    /// Set source address
    pub fn set_source(&mut self, addr: Ipv4Address) {
        self.src_addr = *addr.as_bytes();
    }

    /// Get destination address
    pub fn destination(&self) -> Ipv4Address {
        Ipv4Address::new(self.dst_addr)
    }

    /// Set destination address
    pub fn set_destination(&mut self, addr: Ipv4Address) {
        self.dst_addr = *addr.as_bytes();
    }

    /// Get payload length
    pub fn payload_len(&self) -> usize {
        (self.total_length() as usize).saturating_sub(self.header_len())
    }

    /// Calculate header checksum
    pub fn compute_checksum(&self) -> u16 {
        let header_len = self.header_len();
        let header_bytes =
            unsafe { core::slice::from_raw_parts(self as *const _ as *const u8, header_len) };

        let mut sum: u32 = 0;

        // Sum 16-bit words, skipping checksum field (bytes 10-11)
        for i in (0..header_len).step_by(2) {
            if i == 10 {
                continue; // Skip checksum field
            }
            let word = if i + 1 < header_len {
                u16::from_be_bytes([header_bytes[i], header_bytes[i + 1]])
            } else {
                u16::from_be_bytes([header_bytes[i], 0])
            };
            sum += word as u32;
        }

        // Fold 32-bit sum to 16 bits
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !(sum as u16)
    }

    /// Update checksum
    pub fn update_checksum(&mut self) {
        self.checksum = [0, 0];
        let checksum = self.compute_checksum();
        self.set_checksum(checksum);
    }

    /// Verify checksum
    pub fn verify_checksum(&self) -> bool {
        let header_len = self.header_len();
        let header_bytes =
            unsafe { core::slice::from_raw_parts(self as *const _ as *const u8, header_len) };

        let mut sum: u32 = 0;

        for i in (0..header_len).step_by(2) {
            let word = if i + 1 < header_len {
                u16::from_be_bytes([header_bytes[i], header_bytes[i + 1]])
            } else {
                u16::from_be_bytes([header_bytes[i], 0])
            };
            sum += word as u32;
        }

        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        sum as u16 == 0xFFFF
    }
}

/// Zero-copy IPv4 packet view
pub struct Ipv4Packet<'a> {
    /// Raw packet data
    data: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    /// Parse an IPv4 packet from raw bytes (zero-copy)
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < Ipv4Header::MIN_SIZE {
            return None;
        }

        let packet = Ipv4Packet { data };

        // Verify version
        if packet.header().version() != 4 {
            return None;
        }

        // Verify header length
        let header_len = packet.header().header_len();
        if header_len < Ipv4Header::MIN_SIZE || header_len > data.len() {
            return None;
        }

        // Verify total length
        let total_len = packet.header().total_length() as usize;
        if total_len < header_len || total_len > data.len() {
            return None;
        }

        Some(packet)
    }

    /// Get the IPv4 header
    pub fn header(&self) -> &Ipv4Header {
        // SAFETY: We verified the length in parse()
        unsafe { &*(self.data.as_ptr() as *const Ipv4Header) }
    }

    /// Get source address
    pub fn source(&self) -> Ipv4Address {
        self.header().source()
    }

    /// Get destination address
    pub fn destination(&self) -> Ipv4Address {
        self.header().destination()
    }

    /// Get protocol
    pub fn protocol(&self) -> IpProtocol {
        self.header().protocol()
    }

    /// Get TTL
    pub fn ttl(&self) -> u8 {
        self.header().ttl()
    }

    /// Get the payload (zero-copy)
    pub fn payload(&self) -> &'a [u8] {
        let header_len = self.header().header_len();
        let total_len = self.header().total_length() as usize;
        &self.data[header_len..total_len]
    }

    /// Get IP options (if any)
    pub fn options(&self) -> &'a [u8] {
        let header_len = self.header().header_len();
        if header_len > Ipv4Header::MIN_SIZE {
            &self.data[Ipv4Header::MIN_SIZE..header_len]
        } else {
            &[]
        }
    }

    /// Get raw packet data
    pub fn as_bytes(&self) -> &'a [u8] {
        let total_len = self.header().total_length() as usize;
        &self.data[..total_len]
    }

    /// Verify header checksum
    pub fn verify_checksum(&self) -> bool {
        self.header().verify_checksum()
    }
}

/// Mutable IPv4 packet builder
pub struct Ipv4PacketMut<'a> {
    /// Raw buffer
    data: &'a mut [u8],
}

impl<'a> Ipv4PacketMut<'a> {
    /// Create a new IPv4 packet builder
    pub fn new(buffer: &'a mut [u8]) -> Option<Self> {
        if buffer.len() < Ipv4Header::MIN_SIZE {
            return None;
        }

        // Initialize header
        let packet = Ipv4PacketMut { data: buffer };

        Some(packet)
    }

    /// Get mutable header
    pub fn header_mut(&mut self) -> &mut Ipv4Header {
        // SAFETY: Buffer is large enough
        unsafe { &mut *(self.data.as_mut_ptr() as *mut Ipv4Header) }
    }

    /// Initialize header with default values
    pub fn init_header(&mut self) -> &mut Self {
        let header = self.header_mut();
        header.version_ihl = 0x45; // IPv4, IHL=5 (20 bytes)
        header.dscp_ecn = 0;
        header.total_length = [0, 20]; // Will be updated
        header.identification = [0, 0];
        header.flags_fragment = [0x40, 0]; // Don't Fragment
        header.ttl = 64;
        header.protocol = 0;
        header.checksum = [0, 0];
        header.src_addr = [0; 4];
        header.dst_addr = [0; 4];
        self
    }

    /// Set source address
    pub fn set_source(&mut self, addr: Ipv4Address) -> &mut Self {
        self.header_mut().set_source(addr);
        self
    }

    /// Set destination address
    pub fn set_destination(&mut self, addr: Ipv4Address) -> &mut Self {
        self.header_mut().set_destination(addr);
        self
    }

    /// Set protocol
    pub fn set_protocol(&mut self, protocol: IpProtocol) -> &mut Self {
        self.header_mut().set_protocol(protocol);
        self
    }

    /// Set TTL
    pub fn set_ttl(&mut self, ttl: u8) -> &mut Self {
        self.header_mut().set_ttl(ttl);
        self
    }

    /// Set identification
    pub fn set_identification(&mut self, id: u16) -> &mut Self {
        self.header_mut().set_identification(id);
        self
    }

    /// Get mutable payload buffer
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.data[Ipv4Header::MIN_SIZE..]
    }

    /// Set total length and update checksum
    pub fn finalize(&mut self, payload_len: usize) {
        let total_len = (Ipv4Header::MIN_SIZE + payload_len) as u16;
        self.header_mut().set_total_length(total_len);
        self.header_mut().update_checksum();
    }

    /// Get total packet length
    pub fn total_len(&self) -> usize {
        let header = unsafe { &*(self.data.as_ptr() as *const Ipv4Header) };
        header.total_length() as usize
    }

    /// Get packet as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.total_len()]
    }
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

impl Default for Ipv4Config {
    fn default() -> Self {
        Ipv4Config {
            address: Ipv4Address::ANY,
            subnet_mask: Ipv4Address::new([255, 255, 255, 0]),
            gateway: Ipv4Address::ANY,
            dns: None,
        }
    }
}

impl Ipv4Config {
    /// Check if an address is on the local subnet
    pub fn is_local(&self, addr: &Ipv4Address) -> bool {
        self.address.same_subnet(addr, self.subnet_mask)
    }

    /// Get broadcast address for the subnet
    pub fn broadcast_address(&self) -> Ipv4Address {
        let net = self.address.apply_mask(self.subnet_mask);
        let inv_mask = Ipv4Address::new([
            !self.subnet_mask.as_bytes()[0],
            !self.subnet_mask.as_bytes()[1],
            !self.subnet_mask.as_bytes()[2],
            !self.subnet_mask.as_bytes()[3],
        ]);
        Ipv4Address::new([
            net.as_bytes()[0] | inv_mask.as_bytes()[0],
            net.as_bytes()[1] | inv_mask.as_bytes()[1],
            net.as_bytes()[2] | inv_mask.as_bytes()[2],
            net.as_bytes()[3] | inv_mask.as_bytes()[3],
        ])
    }
}

/// IPv4 packet processor
pub struct Ipv4Processor {
    /// Configuration
    config: Ipv4Config,
    /// Statistics
    stats: Ipv4Stats,
    /// Next identification value
    next_id: u16,
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
    /// ICMP packet
    Icmp(&'a [u8], Ipv4Address),
    /// TCP packet
    Tcp(&'a [u8], Ipv4Address, Ipv4Address),
    /// UDP packet
    Udp(&'a [u8], Ipv4Address, Ipv4Address),
    /// Dropped
    Dropped,
    /// Error
    Error,
}

impl Ipv4Processor {
    /// Create a new IPv4 processor
    pub fn new(config: Ipv4Config) -> Self {
        Ipv4Processor {
            config,
            stats: Ipv4Stats::default(),
            next_id: 1,
        }
    }

    /// Get configuration
    pub fn config(&self) -> &Ipv4Config {
        &self.config
    }

    /// Set configuration
    pub fn set_config(&mut self, config: Ipv4Config) {
        self.config = config;
    }

    /// Get statistics
    pub fn stats(&self) -> &Ipv4Stats {
        &self.stats
    }

    /// Process an incoming IPv4 packet
    pub fn process<'a>(&mut self, data: &'a [u8]) -> Ipv4ProcessResult<'a> {
        let packet = match Ipv4Packet::parse(data) {
            Some(p) => p,
            None => {
                self.stats.rx_errors += 1;
                return Ipv4ProcessResult::Error;
            }
        };

        // Verify checksum
        if !packet.verify_checksum() {
            self.stats.checksum_errors += 1;
            return Ipv4ProcessResult::Error;
        }

        // Check destination
        let dst = packet.destination();
        if !self.is_for_us(&dst) {
            self.stats.rx_dropped += 1;
            return Ipv4ProcessResult::Dropped;
        }

        self.stats.rx_packets += 1;

        let src = packet.source();
        let payload = packet.payload();

        match packet.protocol() {
            IpProtocol::Icmp => Ipv4ProcessResult::Icmp(payload, src),
            IpProtocol::Tcp => Ipv4ProcessResult::Tcp(payload, src, dst),
            IpProtocol::Udp => Ipv4ProcessResult::Udp(payload, src, dst),
            _ => Ipv4ProcessResult::Dropped,
        }
    }

    /// Check if a packet is for us
    fn is_for_us(&self, addr: &Ipv4Address) -> bool {
        *addr == self.config.address
            || addr.is_broadcast()
            || *addr == self.config.broadcast_address()
    }

    /// Get next packet ID
    pub fn next_id(&mut self) -> u16 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    /// Build an IP packet for transmission
    pub fn build_packet<'a>(
        &mut self,
        buffer: &'a mut [u8],
        dst: Ipv4Address,
        protocol: IpProtocol,
    ) -> Option<Ipv4PacketMut<'a>> {
        let mut packet = Ipv4PacketMut::new(buffer)?;
        packet
            .init_header()
            .set_source(self.config.address)
            .set_destination(dst)
            .set_protocol(protocol)
            .set_identification(self.next_id());
        Some(packet)
    }
}

/// Calculate IP pseudo-header checksum (for TCP/UDP)
pub fn pseudo_header_checksum(
    src: Ipv4Address,
    dst: Ipv4Address,
    protocol: IpProtocol,
    length: u16,
) -> u32 {
    let mut sum: u32 = 0;

    // Source address
    let src_bytes = src.as_bytes();
    sum += u16::from_be_bytes([src_bytes[0], src_bytes[1]]) as u32;
    sum += u16::from_be_bytes([src_bytes[2], src_bytes[3]]) as u32;

    // Destination address
    let dst_bytes = dst.as_bytes();
    sum += u16::from_be_bytes([dst_bytes[0], dst_bytes[1]]) as u32;
    sum += u16::from_be_bytes([dst_bytes[2], dst_bytes[3]]) as u32;

    // Protocol (zero-padded to 16 bits)
    sum += u8::from(protocol) as u32;

    // Length
    sum += length as u32;

    sum
}

/// Calculate checksum for a data buffer
pub fn data_checksum(data: &[u8], initial: u32) -> u16 {
    let mut sum = initial;

    // Sum 16-bit words
    for i in (0..data.len()).step_by(2) {
        let word = if i + 1 < data.len() {
            u16::from_be_bytes([data[i], data[i + 1]])
        } else {
            u16::from_be_bytes([data[i], 0])
        };
        sum += word as u32;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_address() {
        let addr = Ipv4Address::from_octets(192, 168, 1, 1);
        assert!(addr.is_private());
        assert!(!addr.is_loopback());

        assert!(Ipv4Address::LOOPBACK.is_loopback());
        assert!(Ipv4Address::BROADCAST.is_broadcast());
    }

    #[test]
    fn test_subnet() {
        let addr1 = Ipv4Address::from_octets(192, 168, 1, 1);
        let addr2 = Ipv4Address::from_octets(192, 168, 1, 100);
        let mask = Ipv4Address::from_octets(255, 255, 255, 0);

        assert!(addr1.same_subnet(&addr2, mask));
    }
}
