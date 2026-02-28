// ============================================================================
// kernel/src/net/icmp.rs
// ============================================================================
//! ICMP (Internet Control Message Protocol) Implementation for ExoRust
//!
//! This module implements ICMP for ping/pong and error messages.


use super::ipv4::{Ipv4Address, data_checksum};

/// ICMP message type
pub(crate) mod processor_impl;
#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests;
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

/// ICMP Redirect codes (RFC 792)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RedirectCode {
    /// Redirect for the Network
    Network = 0,
    /// Redirect for the Host
    Host = 1,
    /// Redirect for Type of Service and Network
    TosNetwork = 2,
    /// Redirect for Type of Service and Host
    TosHost = 3,
}

impl From<u8> for RedirectCode {
    fn from(value: u8) -> Self {
        match value {
            0 => RedirectCode::Network,
            1 => RedirectCode::Host,
            2 => RedirectCode::TosNetwork,
            3 => RedirectCode::TosHost,
            _ => RedirectCode::Host, // Default to host redirect
        }
    }
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
    /// Per-IP rate limiting: (last_update_ms, tokens)
    per_ip_rate_limits: alloc::collections::BTreeMap<Ipv4Address, (u64, u32)>,
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
    /// ICMP Redirect message (RFC 792)
    Redirect {
        /// Redirect code (Network, Host, etc.)
        code: RedirectCode,
        /// Gateway IP address to use for the destination
        gateway: Ipv4Address,
        /// Original destination IP from the offending packet
        destination: Ipv4Address,
    },
    /// Need to send timestamp reply (RFC 792)
    SendTimestampReply {
        src_ip: Ipv4Address,
        identifier: u16,
        sequence: u16,
        originate_ts: u32,
    },
    /// Ignored/dropped
    Ignored,
    /// Invalid packet
    Invalid,
}
