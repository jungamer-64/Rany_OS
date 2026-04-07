// ============================================================================
// kernel/src/net/l3/icmp/mod.rs
// ============================================================================
//! ICMP (Internet Control Message Protocol) Implementation for ExoRust
//!
//! This module implements ICMP for ping/pong and error messages.

use super::ipv4::{Ipv4Address, data_checksum};

/// ICMP message type
mod builder_impl;
mod packet_impl;
mod processor_build_impl;
mod processor_control_impl;
pub(crate) mod processor_impl;
mod processor_payload_impl;
mod processor_rate_limit_impl;
#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IcmpType {
    /// Echo Reply (pong)
    EchoReply = 0,
    /// Destination Unreachable
    DestinationUnreachable = 3,
    /// Source Quench
    SourceQuench = 4,
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
            4 => IcmpType::SourceQuench,
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
            IcmpType::SourceQuench => 4,
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

impl From<u8> for DestUnreachCode {
    fn from(value: u8) -> Self {
        match value {
            0 => DestUnreachCode::NetworkUnreachable,
            1 => DestUnreachCode::HostUnreachable,
            2 => DestUnreachCode::ProtocolUnreachable,
            3 => DestUnreachCode::PortUnreachable,
            4 => DestUnreachCode::FragmentationNeeded,
            5 => DestUnreachCode::SourceRouteFailed,
            _ => DestUnreachCode::HostUnreachable, // Default to host unreachable
        }
    }
}

impl From<u8> for TimeExceededCode {
    fn from(value: u8) -> Self {
        match value {
            0 => TimeExceededCode::TtlExceeded,
            1 => TimeExceededCode::FragmentReassemblyExceeded,
            _ => TimeExceededCode::TtlExceeded,
        }
    }
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

/// ICMP Echo packet view
pub struct IcmpEcho<'a> {
    data: &'a [u8],
}

/// ICMP packet builder
pub struct IcmpBuilder<'a> {
    buffer: &'a mut [u8],
    payload_len: usize,
}

/// ICMP Echo builder
pub struct IcmpEchoBuilder<'a> {
    buffer: &'a mut [u8],
    data_len: usize,
}

/// ICMP processor for handling ICMP packets
pub struct IcmpProcessor {
    /// Local IP address (for replies)
    _local_ip: Ipv4Address,
    /// Statistics
    stats: IcmpStats,
    /// Per-IP rate limiting: (last_update_ms, tokens)
    per_ip_rate_limits: alloc::collections::BTreeMap<Ipv4Address, (u64, u32)>,
    /// Global rate limiting: last_update_ms
    global_last_time: u64,
    /// Global rate limiting: tokens
    global_tokens: u32,
    /// Ingress rate limiting: tokens
    ingress_tokens: u32,
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
        receive_ts: u32,
        transmit_ts: u32,
    },
    /// Ignored/dropped
    Ignored,
    /// Invalid packet
    Invalid,
}
