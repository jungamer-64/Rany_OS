use super::*;

impl<'a> Ipv4Packet<'a> {
    /// Parse an IPv4 packet from raw bytes (zero-copy)
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < Ipv4Header::MIN_SIZE {
            return None;
        }

        let header = crate::util::get_ref::<Ipv4Header>(data, 0)?;
        let packet = Ipv4Packet { header, data };

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
        self.header
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
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        let total_len = self.header().total_length() as usize;
        // Security: Clamp to physical buffer size to prevent panic in slice indexing
        &self.data[..core::cmp::min(total_len, self.data.len())]
    }

    /// Verify header checksum
    pub fn verify_checksum(&self) -> bool {
        let header_len = self.header().header_len();
        if self.data.len() < header_len {
            return false;
        }
        let expected = self.header().checksum();
        let calculated = Ipv4Header::compute_checksum_static(&self.data[..header_len]);
        expected == calculated
    }
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
    pub fn header_mut(&mut self) -> Option<&mut Ipv4Header> {
        crate::util::get_mut_ref::<Ipv4Header>(self.data, 0)
    }

    /// Initialize header with default values
    pub fn init_header(&mut self) -> &mut Self {
        if let Some(header) = self.header_mut() {
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
        }
        self
    }

    /// Set source address
    pub fn set_source(&mut self, addr: Ipv4Address) -> &mut Self {
        if let Some(h) = self.header_mut() {
            h.set_source(addr);
        }
        self
    }

    /// Set destination address
    pub fn set_destination(&mut self, addr: Ipv4Address) -> &mut Self {
        if let Some(h) = self.header_mut() {
            h.set_destination(addr);
        }
        self
    }

    /// Set protocol
    pub fn set_protocol(&mut self, protocol: IpProtocol) -> &mut Self {
        if let Some(h) = self.header_mut() {
            h.set_protocol(protocol);
        }
        self
    }

    /// Set TTL
    pub fn set_ttl(&mut self, ttl: u8) -> &mut Self {
        if let Some(h) = self.header_mut() {
            h.set_ttl(ttl);
        }
        self
    }

    /// Set version (should be 4 for IPv4)
    pub fn set_version(&mut self, version: u8) -> &mut Self {
        if let Some(h) = self.header_mut() {
            h.version_ihl = (version << 4) | (h.version_ihl & 0x0f);
        }
        self
    }

    /// Set IHL (Internet Header Length in 32-bit words)
    pub fn set_ihl(&mut self, ihl: u8) -> &mut Self {
        // Valid IHL is 5 (20 bytes) to 15 (60 bytes)
        if (5..=15).contains(&ihl) {
            if let Some(h) = self.header_mut() {
                h.version_ihl = (h.version_ihl & 0xf0) | (ihl & 0x0f);
            }
        }
        self
    }

    /// Set DSCP (Differentiated Services Code Point)
    pub fn set_dscp(&mut self, dscp: u8) -> &mut Self {
        if let Some(h) = self.header_mut() {
            h.dscp_ecn = (dscp & 0xfc) | (h.dscp_ecn & 0x03);
        }
        self
    }

    /// Set total length
    pub fn set_total_length(&mut self, len: u16) -> &mut Self {
        if let Some(h) = self.header_mut() {
            h.set_total_length(len);
        }
        self
    }

    /// Update checksum
    pub fn update_checksum(&mut self) -> &mut Self {
        let header_len = if let Some(h) = self.header_mut() {
            h.header_len()
        } else {
            return self;
        };

        if self.data.len() >= header_len {
            let checksum = Ipv4Header::compute_checksum_static(&self.data[..header_len]);
            if let Some(h) = self.header_mut() {
                h.set_checksum(checksum);
            }
        }
        self
    }

    /// Set identification
    pub fn set_identification(&mut self, id: u16) -> &mut Self {
        if let Some(h) = self.header_mut() {
            h.set_identification(id);
        }
        self
    }

    /// Get mutable payload buffer
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let header_len = self
            .header_mut()
            .map(|h| h.header_len())
            .unwrap_or(Ipv4Header::MIN_SIZE);
        if self.data.len() < header_len {
            &mut []
        } else {
            &mut self.data[header_len..]
        }
    }

    /// Set total length and update checksum
    pub fn finalize(&mut self, payload_len: usize) {
        let header_len = if let Some(h) = self.header_mut() {
            h.header_len()
        } else {
            return;
        };

        // Security: Clamp payload length to physical buffer size to prevent buffer overflow/panic
        let max_payload = self.data.len().saturating_sub(header_len);
        let actual_payload = payload_len.min(max_payload);

        let total_len_usize = header_len + actual_payload;
        let total_len = total_len_usize.min(65535) as u16;

        if let Some(h) = self.header_mut() {
            h.set_total_length(total_len);
        }
        self.update_checksum();
    }

    /// Get total packet length
    pub fn total_len(&self) -> usize {
        // Use safe helper to read header; buffer length was validated in new()
        let declared_len = crate::util::get_ref::<Ipv4Header>(self.data, 0)
            .map(|h| h.total_length() as usize)
            .unwrap_or(Ipv4Header::MIN_SIZE);

        // Security: Clamp to physical buffer size to prevent panic in slice indexing
        core::cmp::min(declared_len, self.data.len())
    }

    /// Get packet as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.total_len()]
    }
}

#[cfg(test)]
mod packet_mut_tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_ipv4_packet_mut_finalize_clamp() {
        let mut buffer = [0u8; 30]; // 20 bytes header + 10 bytes payload
        let mut packet = Ipv4PacketMut::new(&mut buffer).expect("packet should initialize");
        packet.init_header();

        // Try to finalize with a payload larger than buffer
        packet.finalize(100);

        // Check that it was clamped
        assert_eq!(packet.total_len(), 30);
        assert_eq!(packet.as_bytes().len(), 30);

        // Check header total length
        if let Some(h) = packet.header_mut() {
            assert_eq!(h.total_length(), 30);
        }
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_ipv4_packet_mut_manual_overflow_protection() {
        let mut buffer = [0u8; 30];
        let mut packet = Ipv4PacketMut::new(&mut buffer).expect("packet should initialize");
        packet.init_header();

        // Manually set a large total length
        if let Some(h) = packet.header_mut() {
            h.set_total_length(100);
        }

        // total_len() should still be clamped to buffer size
        assert_eq!(packet.total_len(), 30);

        // as_bytes() should not panic
        let bytes = packet.as_bytes();
        assert_eq!(bytes.len(), 30);
    }
}
