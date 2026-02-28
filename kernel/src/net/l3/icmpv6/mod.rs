// ============================================================================
// kernel/src/net/icmpv6.rs
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


use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::ipv4::{IpProtocol, data_checksum};
use super::ipv6::{Ipv6Address, ipv6_pseudo_header_checksum};

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
        data: Vec<u8>,
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
        data: Vec<u8>,
        /// Source address
        src: Ipv6Address,
        /// Destination address
        dst: Ipv6Address,
        /// IPv6 hop limit from fixed header
        hop_limit: u8,
    },
    /// Packet Too Big received (Path MTU Discovery)
    PacketTooBig {
        /// Original destination that triggered the error
        dst: Ipv6Address,
        /// MTU from the message
        mtu: u32,
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
    /// Rate limiting: last time an echo reply was sent (ms)
    last_echo_reply_time: AtomicU64,
    /// Rate limiting: tokens for bucket
    echo_reply_tokens: AtomicU32,
}

impl Icmpv6Processor {
    /// Create a new ICMPv6 processor
    pub fn new(echo_enabled: bool) -> Self {
        Self {
            echo_enabled,
            stats: Icmpv6Stats::default(),
            last_echo_reply_time: AtomicU64::new(0),
            echo_reply_tokens: AtomicU32::new(10), // Initial burst capacity
        }
    }

    /// Get stats reference
    #[inline]
    pub fn stats(&self) -> &Icmpv6Stats {
        &self.stats
    }

    /// Process an incoming ICMPv6 message
    ///
    /// `data` is the ICMPv6 payload (after IPv6 header + extension headers)
    /// `src` and `dst` are the IPv6 addresses from the enclosing IPv6 header
    /// `hop_limit` is the IPv6 hop limit from the fixed header
    pub fn process(
        &self,
        data: &[u8],
        src: Ipv6Address,
        dst: Ipv6Address,
        hop_limit: u8,
        current_time: u64,
    ) -> Icmpv6Result {
        if data.len() < ICMPV6_HEADER_SIZE {
            return Icmpv6Result::Error;
        }

        self.stats.rx_messages.fetch_add(1, Ordering::Relaxed);

        // Verify checksum (mandatory for ICMPv6)
        if !self.verify_checksum(data, &src, &dst) {
            self.stats.checksum_errors.fetch_add(1, Ordering::Relaxed);
            return Icmpv6Result::Dropped;
        }

        let msg_type = Icmpv6Type::from(data[0]);
        let code = data[1];

        match msg_type {
            Icmpv6Type::EchoRequest => {
                self.stats.rx_echo_requests.fetch_add(1, Ordering::Relaxed);

                // Rate limiting (Token Bucket)
                // Add 1 token per 100ms
                let last_time = self.last_echo_reply_time.load(Ordering::Relaxed);
                let elapsed = current_time.saturating_sub(last_time);
                let new_tokens = (elapsed / 100) as u32;
                
                if new_tokens > 0 {
                    let old_tokens = self.echo_reply_tokens.load(Ordering::Relaxed);
                    let val = (old_tokens + new_tokens).min(20);
                    self.echo_reply_tokens.store(val, Ordering::Relaxed);
                    self.last_echo_reply_time.store(current_time, Ordering::Relaxed);
                }

                let current_tokens = self.echo_reply_tokens.load(Ordering::Relaxed);
                if current_tokens == 0 {
                    self.stats.dropped_rate_limit.fetch_add(1, Ordering::Relaxed);
                    return Icmpv6Result::Dropped;
                }
                self.echo_reply_tokens.fetch_sub(1, Ordering::Relaxed);

                self.handle_echo_request(data, src, dst)
            }
            Icmpv6Type::EchoReply => {
                self.stats.rx_echo_replies.fetch_add(1, Ordering::Relaxed);
                self.handle_echo_reply(data, src)
            }
            Icmpv6Type::PacketTooBig => {
                self.handle_packet_too_big(data)
            }
            // NDP messages → delegate
            Icmpv6Type::RouterSolicitation
            | Icmpv6Type::RouterAdvertisement
            | Icmpv6Type::NeighborSolicitation
            | Icmpv6Type::NeighborAdvertisement
            | Icmpv6Type::Redirect => {
                self.stats.rx_ndp.fetch_add(1, Ordering::Relaxed);
                Icmpv6Result::NdpMessage {
                    msg_type,
                    data: data.to_vec(),
                    src,
                    dst,
                    hop_limit,
                }
            }
            _ => {
                log::debug!("ICMPv6: Unknown type {} code {}", u8::from(msg_type), code);
                Icmpv6Result::Dropped
            }
        }
    }

    /// Verify ICMPv6 checksum using IPv6 pseudo-header
    fn verify_checksum(&self, data: &[u8], src: &Ipv6Address, dst: &Ipv6Address) -> bool {
        let pseudo = ipv6_pseudo_header_checksum(src, dst, IpProtocol::Icmpv6, data.len() as u32);
        let checksum = data_checksum(data, pseudo);
        checksum == 0
    }

    /// Handle Echo Request → produce Echo Reply
    fn handle_echo_request(&self, data: &[u8], src: Ipv6Address, _dst: Ipv6Address) -> Icmpv6Result {
        if !self.echo_enabled {
            return Icmpv6Result::Dropped;
        }

        if data.len() < ICMPV6_ECHO_HEADER_SIZE {
            return Icmpv6Result::Error;
        }

        let identifier = u16::from_be_bytes([data[4], data[5]]);
        let sequence = u16::from_be_bytes([data[6], data[7]]);
        let echo_data = if data.len() > ICMPV6_ECHO_HEADER_SIZE {
            data[ICMPV6_ECHO_HEADER_SIZE..].to_vec()
        } else {
            Vec::new()
        };

        Icmpv6Result::SendEchoReply {
            dst: src, // reply goes back to sender
            identifier,
            sequence,
            data: echo_data,
        }
    }

    /// Handle Echo Reply (response to our ping)
    fn handle_echo_reply(&self, data: &[u8], src: Ipv6Address) -> Icmpv6Result {
        if data.len() < ICMPV6_ECHO_HEADER_SIZE {
            return Icmpv6Result::Error;
        }

        let identifier = u16::from_be_bytes([data[4], data[5]]);
        let sequence = u16::from_be_bytes([data[6], data[7]]);

        Icmpv6Result::EchoReplyReceived {
            src,
            identifier,
            sequence,
        }
    }

    /// Handle Packet Too Big (Path MTU Discovery)
    fn handle_packet_too_big(&self, data: &[u8]) -> Icmpv6Result {
        if data.len() < 8 {
            return Icmpv6Result::Error;
        }

        let mtu = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        // Extract original destination IP from the invoking packet (RFC 4443)
        // Invoking packet starts at offset 8. Invoking IPv6 header destination is at offset 24 within it.
        // Total offset = 8 + 24 = 32.
        if data.len() >= 32 + 16 {
            let dst_bytes = &data[32..32 + 16];
            let mut arr = [0u8; 16];
            arr.copy_from_slice(dst_bytes);
            let dst = Ipv6Address::new(arr);
            Icmpv6Result::PacketTooBig { dst, mtu }
        } else {
            // Not enough data to extract destination, but we still have the MTU.
            // However, without destination we can't reliably update PMTU cache.
            Icmpv6Result::Error
        }
    }
}

impl Default for Icmpv6Processor {
    fn default() -> Self {
        Self::new(true)
    }
}

// =====================================================
// ICMPv6 Echo Builder
// =====================================================

/// Builder for ICMPv6 Echo Request/Reply messages
pub struct Icmpv6EchoBuilder;

impl Icmpv6EchoBuilder {
    /// Build an ICMPv6 Echo Reply
    ///
    /// Returns the complete ICMPv6 message with correct checksum
    pub fn build_echo_reply(
        src: &Ipv6Address,
        dst: &Ipv6Address,
        identifier: u16,
        sequence: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        Self::build_echo(src, dst, Icmpv6Type::EchoReply, identifier, sequence, payload)
    }

    /// Build an ICMPv6 Echo Request
    ///
    /// Returns the complete ICMPv6 message with correct checksum
    pub fn build_echo_request(
        src: &Ipv6Address,
        dst: &Ipv6Address,
        identifier: u16,
        sequence: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        Self::build_echo(src, dst, Icmpv6Type::EchoRequest, identifier, sequence, payload)
    }

    /// Build ICMPv6 Echo message (shared by Request and Reply)
    fn build_echo(
        src: &Ipv6Address,
        dst: &Ipv6Address,
        msg_type: Icmpv6Type,
        identifier: u16,
        sequence: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let total_len = ICMPV6_ECHO_HEADER_SIZE + payload.len();
        let mut message = vec![0u8; total_len];

        // Type
        message[0] = u8::from(msg_type);
        // Code = 0 for Echo
        message[1] = 0;
        // Checksum placeholder (computed below)
        message[2] = 0;
        message[3] = 0;
        // Identifier
        let id_bytes = identifier.to_be_bytes();
        message[4] = id_bytes[0];
        message[5] = id_bytes[1];
        // Sequence number
        let seq_bytes = sequence.to_be_bytes();
        message[6] = seq_bytes[0];
        message[7] = seq_bytes[1];
        // Payload
        if !payload.is_empty() {
            message[ICMPV6_ECHO_HEADER_SIZE..].copy_from_slice(payload);
        }

        // Compute checksum with IPv6 pseudo-header
        let pseudo = ipv6_pseudo_header_checksum(src, dst, IpProtocol::Icmpv6, total_len as u32);
        let cksum = data_checksum(&message, pseudo);
        let cksum_bytes = cksum.to_be_bytes();
        message[2] = cksum_bytes[0];
        message[3] = cksum_bytes[1];

        message
    }

    /// Build a Destination Unreachable message
    pub fn build_dest_unreachable(
        src: &Ipv6Address,
        dst: &Ipv6Address,
        code: u8,
        trigger_packet: &[u8],
    ) -> Vec<u8> {
        // ICMPv6 header (4) + unused (4) + as much of trigger as fits
        let max_trigger = 1232.min(trigger_packet.len()); // stay under minimum MTU of 1280
        let total_len = 8 + max_trigger;
        let mut message = vec![0u8; total_len];

        message[0] = u8::from(Icmpv6Type::DestinationUnreachable);
        message[1] = code;
        // Checksum placeholder
        // Bytes 4-7 = unused (zeros)
        // Trigger packet
        message[8..8 + max_trigger].copy_from_slice(&trigger_packet[..max_trigger]);

        // Compute checksum
        let pseudo = ipv6_pseudo_header_checksum(src, dst, IpProtocol::Icmpv6, total_len as u32);
        let cksum = data_checksum(&message, pseudo);
        let cksum_bytes = cksum.to_be_bytes();
        message[2] = cksum_bytes[0];
        message[3] = cksum_bytes[1];

        message
    }
}

// =====================================================
// Tests
// =====================================================

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests {
    use super::*;

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

        let msg = Icmpv6EchoBuilder::build_echo_reply(&src, &dst, 0x1234, 1, &payload);

        // Verify structure
        assert_eq!(msg[0], u8::from(Icmpv6Type::EchoReply));
        assert_eq!(msg[1], 0); // code
        assert_eq!(u16::from_be_bytes([msg[4], msg[5]]), 0x1234); // identifier
        assert_eq!(u16::from_be_bytes([msg[6], msg[7]]), 1); // sequence
        assert_eq!(&msg[8..12], &payload);

        // Verify checksum
        let pseudo = ipv6_pseudo_header_checksum(&src, &dst, IpProtocol::Icmpv6, msg.len() as u32);
        let cksum = data_checksum(&msg, pseudo);
        assert_eq!(cksum, 0); // valid checksum should fold to 0
    }

    #[cfg_attr(test, test_case)]
    pub fn test_echo_request_build_and_verify() {
        let src = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

        let msg = Icmpv6EchoBuilder::build_echo_request(&src, &dst, 42, 7, &[1, 2, 3]);

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
        let msg = Icmpv6EchoBuilder::build_echo_request(&src, &dst, 100, 5, &[0xAB]);

        // Process it
        let result = processor.process(&msg, src, dst, 64, 100);
        match result {
            Icmpv6Result::SendEchoReply { dst: reply_dst, identifier, sequence, data } => {
                assert_eq!(reply_dst, src);
                assert_eq!(identifier, 100);
                assert_eq!(sequence, 5);
                assert_eq!(data, vec![0xAB]);
            }
            _ => panic!("Expected SendEchoReply"),
        }
    }

    #[cfg_attr(test, test_case)]
    pub fn test_processor_echo_disabled() {
        let processor = Icmpv6Processor::new(false);
        let src = Ipv6Address::LOOPBACK;
        let dst = Ipv6Address::LOOPBACK;

        let msg = Icmpv6EchoBuilder::build_echo_request(&src, &dst, 1, 1, &[]);
        let result = processor.process(&msg, src, dst, 64, 100);
        assert!(matches!(result, Icmpv6Result::Dropped));
    }

    #[cfg_attr(test, test_case)]
    pub fn test_processor_checksum_error() {
        let processor = Icmpv6Processor::new(true);
        let src = Ipv6Address::LOOPBACK;
        let dst = Ipv6Address::LOOPBACK;

        // Build a valid message, then corrupt the checksum
        let mut msg = Icmpv6EchoBuilder::build_echo_request(&src, &dst, 1, 1, &[]);
        msg[2] ^= 0xFF; // corrupt checksum

        let result = processor.process(&msg, src, dst, 64, 100);
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
        msg[1] = 0;   // code
        // bytes 4-7: reserved
        // bytes 8-23: target address (zeros = ::)

        // Compute checksum
        let pseudo = ipv6_pseudo_header_checksum(&src, &dst, IpProtocol::Icmpv6, msg.len() as u32);
        let cksum = data_checksum(&msg, pseudo);
        let cksum_bytes = cksum.to_be_bytes();
        msg[2] = cksum_bytes[0];
        msg[3] = cksum_bytes[1];

        let result = processor.process(&msg, src, dst, 255, 100);
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
