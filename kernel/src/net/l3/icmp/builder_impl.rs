// ============================================================================
// kernel/src/net/l3/icmp/builder_impl.rs - L3 / ICMP / ビルダー実装
// ============================================================================

use super::*;

impl<'a> IcmpBuilder<'a> {
    /// Create a new ICMP builder
    pub fn new(buffer: &'a mut [u8]) -> Option<Self> {
        if buffer.len() < IcmpHeader::SIZE {
            return None;
        }
        Some(IcmpBuilder {
            buffer,
            payload_len: 0,
        })
    }

    /// Get mutable header
    pub fn header_mut(&mut self) -> &mut IcmpHeader {
        crate::util::get_mut_ref::<IcmpHeader>(self.buffer, 0)
            .expect("Icmp header mutable slice out of bounds")
    }

    /// Set message type
    pub fn set_type(&mut self, icmp_type: IcmpType) -> &mut Self {
        self.header_mut().set_type(icmp_type);
        self
    }

    /// Set code
    pub fn set_code(&mut self, code: u8) -> &mut Self {
        self.header_mut().set_code(code);
        self
    }

    /// Get mutable payload
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[IcmpHeader::SIZE..]
    }

    /// Write payload
    pub fn write_payload(&mut self, data: &[u8]) -> usize {
        let max = self.buffer.len() - IcmpHeader::SIZE;
        let len = data.len().min(max);
        self.buffer[IcmpHeader::SIZE..IcmpHeader::SIZE + len].copy_from_slice(&data[..len]);
        self.payload_len = len;
        len
    }

    /// Set payload length
    pub fn set_payload_len(&mut self, len: usize) {
        self.payload_len = len.min(self.buffer.len() - IcmpHeader::SIZE);
    }

    /// Finalize the packet (compute checksum)
    pub fn finalize(&mut self) -> usize {
        let total_len = IcmpHeader::SIZE + self.payload_len;

        // Clear checksum for calculation
        self.header_mut().set_checksum(0);

        // Calculate checksum
        let checksum = data_checksum(&self.buffer[..total_len], 0);
        self.header_mut().set_checksum(checksum);

        total_len
    }

    /// Get packet as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer[..IcmpHeader::SIZE + self.payload_len]
    }
}

impl<'a> IcmpEchoBuilder<'a> {
    /// Create a new echo builder
    pub fn new(buffer: &'a mut [u8]) -> Option<Self> {
        if buffer.len() < IcmpEchoHeader::SIZE {
            return None;
        }
        Some(IcmpEchoBuilder {
            buffer,
            data_len: 0,
        })
    }

    /// Get mutable header
    pub fn header_mut(&mut self) -> &mut IcmpEchoHeader {
        crate::util::get_mut_ref::<IcmpEchoHeader>(self.buffer, 0)
            .expect("Icmp echo header mutable slice out of bounds")
    }

    /// Build echo request
    pub fn build_request(&mut self, identifier: u16, sequence: u16) -> &mut Self {
        let header = self.header_mut();
        header.base.set_type(IcmpType::EchoRequest);
        header.base.set_code(0);
        header.set_identifier(identifier);
        header.set_sequence(sequence);
        self
    }

    /// Build echo reply
    pub fn build_reply(&mut self, identifier: u16, sequence: u16) -> &mut Self {
        let header = self.header_mut();
        header.base.set_type(IcmpType::EchoReply);
        header.base.set_code(0);
        header.set_identifier(identifier);
        header.set_sequence(sequence);
        self
    }

    /// Write echo data
    pub fn write_data(&mut self, data: &[u8]) -> usize {
        let max = self.buffer.len() - IcmpEchoHeader::SIZE;
        let len = data.len().min(max);
        self.buffer[IcmpEchoHeader::SIZE..IcmpEchoHeader::SIZE + len].copy_from_slice(&data[..len]);
        self.data_len = len;
        len
    }

    pub fn write_payload_view(
        &mut self,
        view: &crate::net::payload::PacketPayloadView<'_>,
    ) -> usize {
        let max = self.buffer.len() - IcmpEchoHeader::SIZE;
        let len = view.total_len().min(max);
        let copied = view.copy_range(
            0,
            &mut self.buffer[IcmpEchoHeader::SIZE..IcmpEchoHeader::SIZE + len],
        );
        self.data_len = copied;
        copied
    }

    pub fn write_payload_span_ref(
        &mut self,
        span: crate::net::payload::PayloadSpanRef<'_>,
    ) -> usize {
        let max = self.buffer.len() - IcmpEchoHeader::SIZE;
        let len = span.total_len().min(max);
        let copied = span.copy_into(&mut self.buffer[IcmpEchoHeader::SIZE..IcmpEchoHeader::SIZE + len]);
        self.data_len = copied;
        copied
    }

    /// Finalize the packet
    pub fn finalize(&mut self) -> usize {
        let total_len = IcmpEchoHeader::SIZE + self.data_len;

        // Clear checksum
        self.header_mut().base.set_checksum(0);

        // Calculate checksum
        let checksum = data_checksum(&self.buffer[..total_len], 0);
        self.header_mut().base.set_checksum(checksum);

        total_len
    }

    /// Get packet as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer[..IcmpEchoHeader::SIZE + self.data_len]
    }
}
