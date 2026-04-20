// ============================================================================
// kernel/src/net/l3/icmpv6/mod.rs - L3 / ICMPv6 モジュール
// ============================================================================
//! ICMPv6 (Internet Control Message Protocol for IPv6) Implementation
//!
//! RFC 4443 compliant ICMPv6 processing.
//! ICMPv6 checksum is mandatory and uses the IPv6 pseudo-header.
//!
//! ## Supported Messages
//! - Echo Request / Echo Reply (ping6)
//! - Destination Unreachable
//! - Packet Too Big
//! - Time Exceeded
//! - Parameter Problem
//! - NDP messages (delegated to ndp.rs)

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::ipv4::IpProtocol;
use super::ipv6::{Ipv6Address, ipv6_pseudo_header_checksum};
use crate::net::payload::{PacketPayloadView, alloc_packet_with_headroom};
use kernel_api::resource::net::PacketPayload;

fn payload_checksum(view: &PacketPayloadView<'_>, initial: u32) -> u16 {
    let mut sum = initial;
    let mut trailing = None;

    view.for_each_chunk(|chunk| {
        let mut index = 0usize;
        if let Some(prev) = trailing.take() {
            if let Some((&first, rest)) = chunk.split_first() {
                sum = sum.saturating_add(u16::from_be_bytes([prev, first]) as u32);
                index = 1;
                if rest.is_empty() {
                    return;
                }
            } else {
                trailing = Some(prev);
                return;
            }
        }

        while index + 1 < chunk.len() {
            sum = sum.saturating_add(u16::from_be_bytes([chunk[index], chunk[index + 1]]) as u32);
            index += 2;
        }
        if index < chunk.len() {
            trailing = Some(chunk[index]);
        }
    });

    if let Some(last) = trailing {
        sum = sum.saturating_add(u16::from_be_bytes([last, 0]) as u32);
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

// =====================================================
// ICMPv6 Types
// =====================================================

/// ICMPv6 message type (RFC 4443 + NDP types from RFC 4861)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Icmpv6Type {
    // Error messages (0-127)
    /// Destination Unreachable
    DestinationUnreachable = 1,
    /// Packet Too Big
    PacketTooBig = 2,
    /// Time Exceeded
    TimeExceeded = 3,
    /// Parameter Problem
    ParameterProblem = 4,

    // Informational messages (128-255)
    /// Echo Request (ping6)
    EchoRequest = 128,
    /// Echo Reply (pong6)
    EchoReply = 129,

    // NDP messages (RFC 4861)
    /// Router Solicitation
    RouterSolicitation = 133,
    /// Router Advertisement
    RouterAdvertisement = 134,
    /// Neighbor Solicitation
    NeighborSolicitation = 135,
    /// Neighbor Advertisement
    NeighborAdvertisement = 136,
    /// Redirect
    Redirect = 137,

    /// Unknown type
    Unknown(u8),
}

impl From<u8> for Icmpv6Type {
    fn from(value: u8) -> Self {
        match value {
            1 => Icmpv6Type::DestinationUnreachable,
            2 => Icmpv6Type::PacketTooBig,
            3 => Icmpv6Type::TimeExceeded,
            4 => Icmpv6Type::ParameterProblem,
            128 => Icmpv6Type::EchoRequest,
            129 => Icmpv6Type::EchoReply,
            133 => Icmpv6Type::RouterSolicitation,
            134 => Icmpv6Type::RouterAdvertisement,
            135 => Icmpv6Type::NeighborSolicitation,
            136 => Icmpv6Type::NeighborAdvertisement,
            137 => Icmpv6Type::Redirect,
            other => Icmpv6Type::Unknown(other),
        }
    }
}

impl From<Icmpv6Type> for u8 {
    fn from(value: Icmpv6Type) -> Self {
        match value {
            Icmpv6Type::DestinationUnreachable => 1,
            Icmpv6Type::PacketTooBig => 2,
            Icmpv6Type::TimeExceeded => 3,
            Icmpv6Type::ParameterProblem => 4,
            Icmpv6Type::EchoRequest => 128,
            Icmpv6Type::EchoReply => 129,
            Icmpv6Type::RouterSolicitation => 133,
            Icmpv6Type::RouterAdvertisement => 134,
            Icmpv6Type::NeighborSolicitation => 135,
            Icmpv6Type::NeighborAdvertisement => 136,
            Icmpv6Type::Redirect => 137,
            Icmpv6Type::Unknown(v) => v,
        }
    }
}

impl Icmpv6Type {
    /// Check if this is an error message (type 0-127)
    #[inline]
    pub fn is_error(&self) -> bool {
        u8::from(*self) < 128
    }

    /// Check if this is an NDP message (133-137)
    #[inline]
    pub fn is_ndp(&self) -> bool {
        let v = u8::from(*self);
        (133..=137).contains(&v)
    }
}

// =====================================================
// ICMPv6 Header
// =====================================================

/// ICMPv6 header (4 bytes)
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Icmpv6Header {
    /// Message type
    pub icmp_type: u8,
    /// Message code
    pub code: u8,
    /// Checksum (mandatory, uses IPv6 pseudo-header)
    pub checksum: [u8; 2],
}

/// ICMPv6 header size
pub const ICMPV6_HEADER_SIZE: usize = 4;

/// ICMPv6 Echo header size (type + code + checksum + identifier + sequence)
pub const ICMPV6_ECHO_HEADER_SIZE: usize = 8;

impl Icmpv6Header {
    /// Get message type
    #[inline]
    pub fn msg_type(&self) -> Icmpv6Type {
        Icmpv6Type::from(self.icmp_type)
    }

    /// Get code
    #[inline]
    pub fn code(&self) -> u8 {
        self.code
    }

    /// Get checksum
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.checksum)
    }
}

// =====================================================
// ICMPv6 Process Result
// =====================================================

/// Result of ICMPv6 processing
#[derive(Debug)]
pub enum Icmpv6Result {
    /// Echo Request received - should send Reply
    SendEchoReply {
        /// Destination for reply (= original source)
        dst: Ipv6Address,
        /// Echo identifier
        identifier: u16,
        /// Echo sequence number
        sequence: u16,
        /// Echo data payload
        data: PacketPayload,
    },
    /// Echo Reply received (from our ping)
    EchoReplyReceived {
        /// Source of reply
        src: Ipv6Address,
        /// Echo identifier
        identifier: u16,
        /// Echo sequence number
        sequence: u16,
    },
    /// NDP message - delegate to NDP processor
    NdpMessage {
        /// NDP message type
        msg_type: Icmpv6Type,
        /// Full ICMPv6 data (including header)
        data: PacketPayload,
        /// Source address
        src: Ipv6Address,
        /// Destination address
        dst: Ipv6Address,
        /// Source MAC address
        src_mac: crate::net::l2::ethernet::MacAddress,
        /// IPv6 hop limit from fixed header
        hop_limit: u8,
    },
    /// Packet Too Big received (Path MTU Discovery)
    PacketTooBig {
        /// Original source address from the invoking packet (should be US)
        quoted_src: Ipv6Address,
        /// Original destination that triggered the error
        dst: Ipv6Address,
        /// MTU from the message
        mtu: u32,
        /// Quoted portion of the original packet for validation (ports/seq)
        quoted_packet: PacketPayload,
    },
    /// Destination Unreachable received
    DestinationUnreachable {
        /// Unreachable code (0-6)
        code: u8,
        /// Original source
        quoted_src: Ipv6Address,
        /// Original destination
        quoted_dst: Ipv6Address,
        /// Quoted portion of original packet
        quoted_packet: PacketPayload,
    },
    /// Time Exceeded received (Hop limit exceeded or fragment reassembly timeout)
    TimeExceeded {
        /// Code (0=hop limit, 1=reassembly timeout)
        code: u8,
        /// Original source
        quoted_src: Ipv6Address,
        /// Original destination
        quoted_dst: Ipv6Address,
        /// Quoted portion of original packet
        quoted_packet: PacketPayload,
    },
    /// Parameter Problem received
    ParameterProblem {
        /// Code
        code: u8,
        /// Offset where error was detected
        pointer: u32,
        /// Original source
        quoted_src: Ipv6Address,
        /// Original destination
        quoted_dst: Ipv6Address,
        /// Quoted portion of original packet
        quoted_packet: PacketPayload,
    },
    /// Packet dropped (unknown type, checksum error, etc.)
    Dropped,
    /// Processing error
    Error,
}

// =====================================================
// ICMPv6 Statistics
// =====================================================

/// ICMPv6 processing statistics
#[derive(Debug, Default)]
pub struct Icmpv6Stats {
    /// Total messages received
    pub rx_messages: AtomicU64,
    /// Echo Requests received
    pub rx_echo_requests: AtomicU64,
    /// Echo Replies received
    pub rx_echo_replies: AtomicU64,
    /// NDP messages received
    pub rx_ndp: AtomicU64,
    /// Messages with checksum errors
    pub checksum_errors: AtomicU64,
    /// Total messages transmitted
    pub tx_messages: AtomicU64,
    /// Total messages dropped due to rate limit
    pub dropped_rate_limit: AtomicU64,
}

// =====================================================
// ICMPv6 Processor
// =====================================================

/// ICMPv6 message processor
pub struct Icmpv6Processor {
    /// Whether to respond to Echo Requests
    echo_enabled: bool,
    /// Statistics
    stats: Icmpv6Stats,
    /// Rate limiting: last time tokens were added (ms)
    last_token_time: AtomicU64,
    /// Rate limiting: tokens for bucket (egress/sending)
    tx_tokens: AtomicU32,
    /// Rate limiting: tokens for bucket (ingress/receiving)
    rx_tokens: AtomicU32,
}

mod processor_impl;

// =====================================================
// ICMPv6 Builder
// =====================================================

/// Builder for ICMPv6 messages
pub struct Icmpv6Builder;

mod builder_impl;
