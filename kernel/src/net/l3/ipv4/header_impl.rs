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

    /// Calculate header checksum from a raw byte slice.
    /// The slice MUST be at least as long as the header length specified in the first byte.
    pub fn compute_checksum_static(header_bytes: &[u8]) -> u16 {
        if header_bytes.is_empty() {
            return 0;
        }
        let ihl = (header_bytes[0] & 0x0F) as usize;
        let header_len = ihl * 4;

        if header_bytes.len() < header_len {
            return 0; // Or panic? Returning 0 is safer for now.
        }

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
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        let result = !(sum as u16);
        if result == 0 { 0xFFFF } else { result }
    }
}
