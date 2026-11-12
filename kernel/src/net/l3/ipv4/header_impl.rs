// ============================================================================
// kernel/src/net/l3/ipv4/header_impl.rs - L3 / IPv4 / ヘッダ実装
// ============================================================================

use super::*;

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

    /// Set IPv4 fragmentation flags and fragment offset.
    pub fn set_fragmentation(
        &mut self,
        dont_fragment: bool,
        more_fragments: bool,
        fragment_offset: u16,
    ) {
        let offset = fragment_offset & 0x1FFF;
        let mut flags = 0u8;
        if dont_fragment {
            flags |= 0x40;
        }
        if more_fragments {
            flags |= 0x20;
        }
        self.flags_fragment = [flags | ((offset >> 8) as u8), offset as u8];
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

    /// Header checksum to store in bytes 10-11 of `header` (RFC 791), computed
    /// with the checksum field taken as zero. `header` is exactly the header,
    /// options included.
    ///
    /// Unlike UDP, the IPv4 header has no "no checksum" encoding, so a result
    /// of 0x0000 is transmitted as is.
    pub fn compute_checksum_static(header: &[u8]) -> u16 {
        !Self::ones_complement_sum(header, true)
    }

    /// Whether `header` (exactly the header, options included) carries a
    /// valid checksum: the one's-complement sum over every word, the checksum
    /// field included, is 0xFFFF (RFC 1071). This accepts both one's-complement
    /// zero encodings that a sender may produce.
    pub fn header_checksum_is_valid(header: &[u8]) -> bool {
        Self::ones_complement_sum(header, false) == 0xFFFF
    }

    fn ones_complement_sum(header: &[u8], skip_checksum_field: bool) -> u16 {
        let mut sum: u32 = 0;
        for (index, word) in header.chunks(2).enumerate() {
            if skip_checksum_field && index == 5 {
                continue;
            }
            let high = word[0];
            let low = word.get(1).copied().unwrap_or(0);
            sum += u32::from(u16::from_be_bytes([high, low]));
        }

        // LOOP_PROOF: mode=condition; reason=Carry folding reduces the high half of this 32-bit checksum until the accumulator fits in 16 bits.;
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        sum as u16
    }
}
