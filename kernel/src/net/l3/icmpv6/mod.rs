// ============================================================================
// kernel/src/net/l3/icmpv6/mod.rs
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

use super::ipv4::{IpProtocol, data_checksum};
use super::ipv6::{Ipv6Address, ipv6_pseudo_header_checksum};
use crate::net::payload::{PacketPayloadView, alloc_packet_with_headroom, payload_range};
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

// =====================================================
// Tests
// =====================================================

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    fn payload_bytes(payload: &PacketPayload) -> Vec<u8> {
        let mut out = vec![0u8; payload.total_len()];
        let copied = PacketPayloadView::new(payload).copy_all_into(&mut out);
        out.truncate(copied);
        out
    }

    fn test_payload(data: &[u8]) -> PacketPayload {
        crate::net::payload::payload_from_bytes(data).expect("payload allocation")
    }

    #[cfg_attr(test, test_case)]
    pub fn test_icmpv6_type_from_u8() {
        assert_eq!(Icmpv6Type::from(128), Icmpv6Type::EchoRequest);
        assert_eq!(Icmpv6Type::from(129), Icmpv6Type::EchoReply);
        assert_eq!(Icmpv6Type::from(135), Icmpv6Type::NeighborSolicitation);
        assert_eq!(Icmpv6Type::from(136), Icmpv6Type::NeighborAdvertisement);
        assert_eq!(Icmpv6Type::from(2), Icmpv6Type::PacketTooBig);
        assert_eq!(Icmpv6Type::from(99), Icmpv6Type::Unknown(99));
    }

    #[cfg_attr(test, test_case)]
    pub fn test_icmpv6_type_classification() {
        assert!(Icmpv6Type::DestinationUnreachable.is_error());
        assert!(Icmpv6Type::PacketTooBig.is_error());
        assert!(!Icmpv6Type::EchoRequest.is_error());
        assert!(!Icmpv6Type::EchoReply.is_error());

        assert!(Icmpv6Type::NeighborSolicitation.is_ndp());
        assert!(Icmpv6Type::NeighborAdvertisement.is_ndp());
        assert!(Icmpv6Type::RouterSolicitation.is_ndp());
        assert!(!Icmpv6Type::EchoRequest.is_ndp());
    }

    #[cfg_attr(test, test_case)]
    pub fn test_echo_reply_build_and_verify() {
        let src = Ipv6Address::LOOPBACK;
        let dst = Ipv6Address::LOOPBACK;
        let payload = [0xDE, 0xAD, 0xBE, 0xEF];
        let payload = test_payload(&payload);

        let msg = Icmpv6Builder::build_echo_reply(
            &src,
            &dst,
            0x1234,
            1,
            &PacketPayloadView::new(&payload),
        )
        .expect("echo reply");
        let msg = payload_bytes(&msg);

        // Verify structure
        assert_eq!(msg[0], u8::from(Icmpv6Type::EchoReply));
        assert_eq!(msg[1], 0); // code
        assert_eq!(u16::from_be_bytes([msg[4], msg[5]]), 0x1234); // identifier
        assert_eq!(u16::from_be_bytes([msg[6], msg[7]]), 1); // sequence
        assert_eq!(&msg[8..12], payload_bytes(&payload).as_slice());

        // Verify checksum
        let pseudo = ipv6_pseudo_header_checksum(&src, &dst, IpProtocol::Icmpv6, msg.len() as u32);
        let cksum = data_checksum(&msg, pseudo);
        assert_eq!(cksum, 0); // valid checksum should fold to 0
    }

    #[cfg_attr(test, test_case)]
    pub fn test_echo_request_build_and_verify() {
        let src = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

        let msg = Icmpv6Builder::build_echo_request(
            &src,
            &dst,
            42,
            7,
            &PacketPayloadView::new(&test_payload(&[1, 2, 3])),
        )
        .expect("echo request");
        let msg = payload_bytes(&msg);

        assert_eq!(msg[0], u8::from(Icmpv6Type::EchoRequest));
        assert_eq!(msg.len(), ICMPV6_ECHO_HEADER_SIZE + 3);

        // Verify checksum
        let pseudo = ipv6_pseudo_header_checksum(&src, &dst, IpProtocol::Icmpv6, msg.len() as u32);
        let cksum = data_checksum(&msg, pseudo);
        assert_eq!(cksum, 0);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_processor_echo_request() {
        let processor = Icmpv6Processor::new(true);
        let src = Ipv6Address::LOOPBACK;
        let dst = Ipv6Address::LOOPBACK;

        // Build a valid Echo Request
        let msg = Icmpv6Builder::build_echo_request(
            &src,
            &dst,
            100,
            5,
            &PacketPayloadView::new(&test_payload(&[0xAB])),
        )
        .expect("echo request");
        let msg = payload_bytes(&msg);

        // Process it
        let mac = crate::net::l2::ethernet::MacAddress::new([0x02, 0, 0, 0, 0, 0]);
        let result = processor.process_payload(test_payload(&msg), src, dst, mac, 64, 100);
        match result {
            Icmpv6Result::SendEchoReply {
                dst: reply_dst,
                identifier,
                sequence,
                data,
            } => {
                assert_eq!(reply_dst, src);
                assert_eq!(identifier, 100);
                assert_eq!(sequence, 5);
                assert_eq!(payload_bytes(&data), vec![0xAB]);
            }
            _ => panic!("Expected SendEchoReply"),
        }
    }

    #[cfg_attr(test, test_case)]
    pub fn test_processor_echo_disabled() {
        let processor = Icmpv6Processor::new(false);
        let src = Ipv6Address::LOOPBACK;
        let dst = Ipv6Address::LOOPBACK;

        let msg = Icmpv6Builder::build_echo_request(
            &src,
            &dst,
            1,
            1,
            &PacketPayloadView::new(&test_payload(&[])),
        )
        .expect("echo request");
        let msg = payload_bytes(&msg);
        let mac = crate::net::l2::ethernet::MacAddress::new([0x02, 0, 0, 0, 0, 0]);
        let result = processor.process_payload(test_payload(&msg), src, dst, mac, 64, 100);
        assert!(matches!(result, Icmpv6Result::Dropped));
    }

    #[cfg_attr(test, test_case)]
    pub fn test_processor_checksum_error() {
        let processor = Icmpv6Processor::new(true);
        let src = Ipv6Address::LOOPBACK;
        let dst = Ipv6Address::LOOPBACK;

        // Build a valid message, then corrupt the checksum
        let mut msg = payload_bytes(
            &Icmpv6Builder::build_echo_request(
                &src,
                &dst,
                1,
                1,
                &PacketPayloadView::new(&test_payload(&[])),
            )
            .expect("echo request"),
        );
        msg[2] ^= 0xFF; // corrupt checksum

        let mac = crate::net::l2::ethernet::MacAddress::new([0x02, 0, 0, 0, 0, 0]);
        let result = processor.process_payload(test_payload(&msg), src, dst, mac, 64, 100);
        assert!(matches!(result, Icmpv6Result::Dropped));
    }

    #[cfg_attr(test, test_case)]
    pub fn test_ndp_delegation() {
        let processor = Icmpv6Processor::new(true);
        let src = Ipv6Address::LOOPBACK;
        let dst = Ipv6Address::ALL_NODES_LINK_LOCAL;

        // Build a fake Neighbor Solicitation (type 135, code 0)
        // Must have valid checksum
        let mut msg = vec![0u8; 24]; // NS is at least 24 bytes
        msg[0] = 135; // Neighbor Solicitation
        msg[1] = 0; // code
        // bytes 4-7: reserved
        // bytes 8-23: target address (zeros = ::)

        // Compute checksum
        let pseudo = ipv6_pseudo_header_checksum(&src, &dst, IpProtocol::Icmpv6, msg.len() as u32);
        let cksum = data_checksum(&msg, pseudo);
        let cksum_bytes = cksum.to_be_bytes();
        msg[2] = cksum_bytes[0];
        msg[3] = cksum_bytes[1];

        let mac = crate::net::l2::ethernet::MacAddress::new([0x02, 0, 0, 0, 0, 0]);
        let result = processor.process_payload(test_payload(&msg), src, dst, mac, 255, 100);
        match result {
            Icmpv6Result::NdpMessage { msg_type, .. } => {
                assert_eq!(msg_type, Icmpv6Type::NeighborSolicitation);
            }
            _ => panic!("Expected NdpMessage"),
        }
    }

    #[cfg_attr(test, test_case)]
    pub fn test_header_size() {
        assert_eq!(core::mem::size_of::<Icmpv6Header>(), ICMPV6_HEADER_SIZE);
    }
}
