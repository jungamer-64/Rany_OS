use super::*;

impl<'a> IcmpPacket<'a> {
    /// Parse an ICMP packet from raw bytes
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < IcmpHeader::SIZE {
            return None;
        }
        Some(IcmpPacket { data })
    }

    /// Get the ICMP header
    pub fn header(&self) -> &IcmpHeader {
        // Use util helper to return a referenced header from the slice
        crate::util::get_ref::<IcmpHeader>(self.data, 0).expect("Icmp header slice out of bounds")
    }

    /// Get message type
    pub fn icmp_type(&self) -> IcmpType {
        self.header().icmp_type()
    }

    /// Get code
    pub fn code(&self) -> u8 {
        self.header().code()
    }

    /// Get the payload
    pub fn payload(&self) -> &'a [u8] {
        &self.data[IcmpHeader::SIZE..]
    }

    /// Get raw packet data
    pub fn as_bytes(&self) -> &'a [u8] {
        self.data
    }

    /// Verify checksum
    pub fn verify_checksum(&self) -> bool {
        data_checksum(self.data, 0) == 0
    }

    /// Try to parse as echo request/reply
    pub fn as_echo(&self) -> Option<IcmpEcho<'a>> {
        if self.data.len() < IcmpEchoHeader::SIZE {
            return None;
        }

        match self.icmp_type() {
            IcmpType::EchoRequest | IcmpType::EchoReply => Some(IcmpEcho { data: self.data }),
            _ => None,
        }
    }
}

impl<'a> IcmpEcho<'a> {
    /// Get the echo header
    pub fn header(&self) -> &IcmpEchoHeader {
        crate::util::get_ref::<IcmpEchoHeader>(self.data, 0)
            .expect("Icmp echo header slice out of bounds")
    }

    /// Get identifier
    pub fn identifier(&self) -> u16 {
        self.header().identifier()
    }

    /// Get sequence number
    pub fn sequence(&self) -> u16 {
        self.header().sequence()
    }

    /// Get echo data
    pub fn data(&self) -> &'a [u8] {
        &self.data[IcmpEchoHeader::SIZE..]
    }

    /// Is this an echo request?
    pub fn is_request(&self) -> bool {
        self.header().base.icmp_type() == IcmpType::EchoRequest
    }

    /// Is this an echo reply?
    pub fn is_reply(&self) -> bool {
        self.header().base.icmp_type() == IcmpType::EchoReply
    }
}
