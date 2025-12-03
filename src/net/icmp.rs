//! ICMP (Internet Control Message Protocol) Implementation for ExoRust
//!
//! This module implements ICMP for ping/pong and error messages.

use super::ipv4::{Ipv4Address, data_checksum};

/// ICMP message type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IcmpType {
    /// Echo Reply (pong)
    EchoReply = 0,
    /// Destination Unreachable
    DestinationUnreachable = 3,
    /// Redirect
    Redirect = 5,
    /// Echo Request (ping)
    EchoRequest = 8,
    /// Time Exceeded
    TimeExceeded = 11,
    /// Parameter Problem
    ParameterProblem = 12,
    /// Timestamp Request
    TimestampRequest = 13,
    /// Timestamp Reply
    TimestampReply = 14,
    /// Unknown type
    Unknown(u8),
}

impl From<u8> for IcmpType {
    fn from(value: u8) -> Self {
        match value {
            0 => IcmpType::EchoReply,
            3 => IcmpType::DestinationUnreachable,
            5 => IcmpType::Redirect,
            8 => IcmpType::EchoRequest,
            11 => IcmpType::TimeExceeded,
            12 => IcmpType::ParameterProblem,
            13 => IcmpType::TimestampRequest,
            14 => IcmpType::TimestampReply,
            other => IcmpType::Unknown(other),
        }
    }
}

impl From<IcmpType> for u8 {
    fn from(value: IcmpType) -> Self {
        match value {
            IcmpType::EchoReply => 0,
            IcmpType::DestinationUnreachable => 3,
            IcmpType::Redirect => 5,
            IcmpType::EchoRequest => 8,
            IcmpType::TimeExceeded => 11,
            IcmpType::ParameterProblem => 12,
            IcmpType::TimestampRequest => 13,
            IcmpType::TimestampReply => 14,
            IcmpType::Unknown(v) => v,
        }
    }
}

/// Destination Unreachable codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DestUnreachCode {
    /// Network unreachable
    NetworkUnreachable = 0,
    /// Host unreachable
    HostUnreachable = 1,
    /// Protocol unreachable
    ProtocolUnreachable = 2,
    /// Port unreachable
    PortUnreachable = 3,
    /// Fragmentation needed but DF set
    FragmentationNeeded = 4,
    /// Source route failed
    SourceRouteFailed = 5,
}

/// Time Exceeded codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TimeExceededCode {
    /// TTL exceeded in transit
    TtlExceeded = 0,
    /// Fragment reassembly time exceeded
    FragmentReassemblyExceeded = 1,
}

/// ICMP header
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct IcmpHeader {
    /// Message type
    pub icmp_type: u8,
    /// Message code
    pub code: u8,
    /// Checksum (big-endian)
    pub checksum: [u8; 2],
}

impl IcmpHeader {
    /// Header size
    pub const SIZE: usize = 4;

    /// Get message type
    pub fn icmp_type(&self) -> IcmpType {
        IcmpType::from(self.icmp_type)
    }

    /// Set message type
    pub fn set_type(&mut self, icmp_type: IcmpType) {
        self.icmp_type = icmp_type.into();
    }

    /// Get code
    pub const fn code(&self) -> u8 {
        self.code
    }

    /// Set code
    pub fn set_code(&mut self, code: u8) {
        self.code = code;
    }

    /// Get checksum
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.checksum)
    }

    /// Set checksum
    pub fn set_checksum(&mut self, checksum: u16) {
        self.checksum = checksum.to_be_bytes();
    }
}

/// ICMP Echo (ping/pong) header extension
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct IcmpEchoHeader {
    /// Base ICMP header
    pub base: IcmpHeader,
    /// Identifier (big-endian)
    pub identifier: [u8; 2],
    /// Sequence number (big-endian)
    pub sequence: [u8; 2],
}

impl IcmpEchoHeader {
    /// Header size
    pub const SIZE: usize = 8;

    /// Get identifier
    pub fn identifier(&self) -> u16 {
        u16::from_be_bytes(self.identifier)
    }

    /// Set identifier
    pub fn set_identifier(&mut self, id: u16) {
        self.identifier = id.to_be_bytes();
    }

    /// Get sequence number
    pub fn sequence(&self) -> u16 {
        u16::from_be_bytes(self.sequence)
    }

    /// Set sequence number
    pub fn set_sequence(&mut self, seq: u16) {
        self.sequence = seq.to_be_bytes();
    }
}

/// Zero-copy ICMP packet view
pub struct IcmpPacket<'a> {
    /// Raw packet data
    data: &'a [u8],
}

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
        // SAFETY: We verified the length in parse()
        unsafe { &*(self.data.as_ptr() as *const IcmpHeader) }
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
        data_checksum(self.data, 0) == 0xFFFF
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

/// ICMP Echo packet view
pub struct IcmpEcho<'a> {
    data: &'a [u8],
}

impl<'a> IcmpEcho<'a> {
    /// Get the echo header
    pub fn header(&self) -> &IcmpEchoHeader {
        // SAFETY: Validated in IcmpPacket::as_echo()
        unsafe { &*(self.data.as_ptr() as *const IcmpEchoHeader) }
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

/// ICMP packet builder
pub struct IcmpBuilder<'a> {
    buffer: &'a mut [u8],
    payload_len: usize,
}

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
        // SAFETY: Buffer size checked in new()
        unsafe { &mut *(self.buffer.as_mut_ptr() as *mut IcmpHeader) }
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

/// ICMP Echo builder
pub struct IcmpEchoBuilder<'a> {
    buffer: &'a mut [u8],
    data_len: usize,
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
        // SAFETY: Buffer size checked in new()
        unsafe { &mut *(self.buffer.as_mut_ptr() as *mut IcmpEchoHeader) }
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

/// ICMP processor for handling ICMP packets
pub struct IcmpProcessor {
    /// Local IP address (for replies)
    _local_ip: Ipv4Address,
    /// Statistics
    stats: IcmpStats,
}

/// ICMP statistics
#[derive(Debug, Default)]
pub struct IcmpStats {
    /// Echo requests received
    pub echo_requests_rx: u64,
    /// Echo replies received
    pub echo_replies_rx: u64,
    /// Echo replies sent
    pub echo_replies_tx: u64,
    /// Error messages received
    pub errors_rx: u64,
    /// Invalid packets
    pub invalid: u64,
}

/// Result of ICMP processing
pub enum IcmpResult {
    /// Need to send echo reply
    SendEchoReply {
        src_ip: Ipv4Address,
        identifier: u16,
        sequence: u16,
        data_offset: usize,
        data_len: usize,
    },
    /// Received echo reply
    EchoReplyReceived { identifier: u16, sequence: u16 },
    /// Error message
    Error { icmp_type: IcmpType, code: u8 },
    /// Ignored/dropped
    Ignored,
    /// Invalid packet
    Invalid,
}

impl IcmpProcessor {
    /// Create a new ICMP processor
    pub fn new(local_ip: Ipv4Address) -> Self {
        IcmpProcessor {
            _local_ip: local_ip,
            stats: IcmpStats::default(),
        }
    }

    /// Get statistics
    pub fn stats(&self) -> &IcmpStats {
        &self.stats
    }

    /// Process an incoming ICMP packet
    pub fn process(&mut self, data: &[u8], src_ip: Ipv4Address) -> IcmpResult {
        let packet = match IcmpPacket::parse(data) {
            Some(p) => p,
            None => {
                self.stats.invalid += 1;
                return IcmpResult::Invalid;
            }
        };

        // Verify checksum
        if !packet.verify_checksum() {
            self.stats.invalid += 1;
            return IcmpResult::Invalid;
        }

        match packet.icmp_type() {
            IcmpType::EchoRequest => {
                self.stats.echo_requests_rx += 1;

                if let Some(echo) = packet.as_echo() {
                    IcmpResult::SendEchoReply {
                        src_ip,
                        identifier: echo.identifier(),
                        sequence: echo.sequence(),
                        data_offset: IcmpEchoHeader::SIZE,
                        data_len: echo.data().len(),
                    }
                } else {
                    IcmpResult::Invalid
                }
            }
            IcmpType::EchoReply => {
                self.stats.echo_replies_rx += 1;

                if let Some(echo) = packet.as_echo() {
                    IcmpResult::EchoReplyReceived {
                        identifier: echo.identifier(),
                        sequence: echo.sequence(),
                    }
                } else {
                    IcmpResult::Invalid
                }
            }
            IcmpType::DestinationUnreachable
            | IcmpType::TimeExceeded
            | IcmpType::ParameterProblem => {
                self.stats.errors_rx += 1;
                IcmpResult::Error {
                    icmp_type: packet.icmp_type(),
                    code: packet.code(),
                }
            }
            _ => IcmpResult::Ignored,
        }
    }

    /// Build an echo reply packet
    pub fn build_echo_reply(
        buffer: &mut [u8],
        identifier: u16,
        sequence: u16,
        echo_data: &[u8],
    ) -> Option<usize> {
        let mut builder = IcmpEchoBuilder::new(buffer)?;
        builder
            .build_reply(identifier, sequence)
            .write_data(echo_data);
        Some(builder.finalize())
    }

    /// Build an echo request packet
    pub fn build_echo_request(
        buffer: &mut [u8],
        identifier: u16,
        sequence: u16,
        data: &[u8],
    ) -> Option<usize> {
        let mut builder = IcmpEchoBuilder::new(buffer)?;
        builder.build_request(identifier, sequence).write_data(data);
        Some(builder.finalize())
    }

    /// Build a destination unreachable packet
    pub fn build_dest_unreachable(
        buffer: &mut [u8],
        code: DestUnreachCode,
        original_packet: &[u8],
    ) -> Option<usize> {
        if buffer.len() < IcmpHeader::SIZE + 4 + 8 {
            return None;
        }

        let mut builder = IcmpBuilder::new(buffer)?;
        builder
            .set_type(IcmpType::DestinationUnreachable)
            .set_code(code as u8);

        // 4 bytes unused, then original IP header + 8 bytes
        let payload = builder.payload_mut();
        payload[0..4].copy_from_slice(&[0, 0, 0, 0]); // Unused

        let copy_len = original_packet.len().min(payload.len() - 4).min(28);
        payload[4..4 + copy_len].copy_from_slice(&original_packet[..copy_len]);

        builder.set_payload_len(4 + copy_len);
        Some(builder.finalize())
    }

    /// Build a time exceeded packet
    pub fn build_time_exceeded(
        buffer: &mut [u8],
        code: TimeExceededCode,
        original_packet: &[u8],
    ) -> Option<usize> {
        if buffer.len() < IcmpHeader::SIZE + 4 + 8 {
            return None;
        }

        let mut builder = IcmpBuilder::new(buffer)?;
        builder
            .set_type(IcmpType::TimeExceeded)
            .set_code(code as u8);

        let payload = builder.payload_mut();
        payload[0..4].copy_from_slice(&[0, 0, 0, 0]); // Unused

        let copy_len = original_packet.len().min(payload.len() - 4).min(28);
        payload[4..4 + copy_len].copy_from_slice(&original_packet[..copy_len]);

        builder.set_payload_len(4 + copy_len);
        Some(builder.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_type() {
        assert_eq!(IcmpType::from(8), IcmpType::EchoRequest);
        assert_eq!(IcmpType::from(0), IcmpType::EchoReply);
        assert_eq!(u8::from(IcmpType::EchoRequest), 8);
    }

    #[test]
    fn test_echo_builder() {
        let mut buffer = [0u8; 64];
        let mut builder = IcmpEchoBuilder::new(&mut buffer).unwrap();

        builder.build_request(1234, 1).write_data(b"hello");
        let len = builder.finalize();

        assert_eq!(len, IcmpEchoHeader::SIZE + 5);

        // Verify we can parse it back
        let packet = IcmpPacket::parse(&buffer[..len]).unwrap();
        assert_eq!(packet.icmp_type(), IcmpType::EchoRequest);
        assert!(packet.verify_checksum());

        let echo = packet.as_echo().unwrap();
        assert_eq!(echo.identifier(), 1234);
        assert_eq!(echo.sequence(), 1);
        assert_eq!(echo.data(), b"hello");
    }
}
