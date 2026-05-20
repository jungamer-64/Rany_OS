// ============================================================================
// kernel/src/net/l3/ipv6/processor_impl.rs - L3 / IPv6 / プロセッサ実装
// ============================================================================

use super::*;
use crate::net::datapath::mempool::PacketRef;
use crate::net::l3::ipv6::{ExtHeaderResult, Ipv6Packet, skip_extension_headers_fraginfo};
use crate::net::payload::{GeneratedPacketWriter, VerifiedPayloadWindow, append_payload};
use kernel_api::resource::net::PacketPayload;

fn generated_ipv6_header_payload(header: &[u8]) -> Option<PacketPayload> {
    let mut writer = GeneratedPacketWriter::new(
        header.len(),
        kernel_api::resource::net::DEFAULT_PACKET_HEADROOM,
    )?;
    writer.write_bytes(header)?;
    writer.finish()
}

impl Ipv6Processor {
    /// Create a new IPv6 processor
    pub fn new(config: Ipv6Config) -> Self {
        Ipv6Processor {
            config,
            stats: Ipv6Stats::default(),
            reassembler: Ipv6FragmentReassembler::new(Ipv6FragmentReassembler::DEFAULT_MAX_BUFFERS),
        }
    }

    /// Get config reference
    #[inline]
    pub fn config(&self) -> &Ipv6Config {
        &self.config
    }

    /// Get mutable config reference
    #[inline]
    pub fn config_mut(&mut self) -> &mut Ipv6Config {
        &mut self.config
    }

    /// Get stats reference
    #[inline]
    pub fn stats(&self) -> &Ipv6Stats {
        &self.stats
    }

    /// Process an incoming IPv6 packet
    pub fn process<'a>(&mut self, data: &'a [u8], current_time: u64) -> Ipv6ProcessResult<'a> {
        self.process_with_packet(data, current_time, None)
    }

    pub fn process_with_packet<'a>(
        &mut self,
        data: &'a [u8],
        _current_time: u64,
        _packet_ref: Option<&PacketRef>,
    ) -> Ipv6ProcessResult<'a> {
        // Parse the packet
        let packet = match Ipv6Packet::parse(data) {
            Some(p) => p,
            None => {
                self.stats.record_header_error();
                return Ipv6ProcessResult::Error;
            }
        };

        self.stats.record_rx();

        let src = packet.source();

        // SECURITY: Martian packet を破棄する。
        // 1. Source IP cannot be multicast (RFC 4291 Section 2.7)
        // 2. Source IP cannot be the loopback address unless it's truly a loopback packet
        if src.is_multicast() || (src.is_loopback() && !self.config.link_local.is_loopback()) {
            self.stats.record_dropped();
            log::warn!("[NET-IPV6] Dropping Martian packet with source {}", src);
            return Ipv6ProcessResult::Dropped;
        }

        let dst = packet.destination();

        // Check if the packet is for us
        if !self.is_for_us(&dst) {
            self.stats.record_dropped();
            return Ipv6ProcessResult::Dropped;
        }

        // Check hop limit
        if packet.hop_limit() == 0 {
            self.stats.record_hop_limit_exceeded();
            return Ipv6ProcessResult::HopLimitExceeded(src, dst);
        }

        // Walk extension headers with fragment awareness
        match skip_extension_headers_fraginfo(data) {
            ExtHeaderResult::NoFragment(final_protocol, upper_payload, next_header_ptr) => {
                // Dispatch based on upper-layer protocol
                match final_protocol {
                    IpProtocol::Icmpv6 => {
                        Ipv6ProcessResult::Icmpv6(upper_payload, src, dst, packet.hop_limit())
                    }
                    IpProtocol::Tcp => {
                        Ipv6ProcessResult::Tcp(upper_payload, src, dst, packet.hop_limit())
                    }
                    IpProtocol::Udp => {
                        Ipv6ProcessResult::Udp(upper_payload, src, dst, packet.hop_limit())
                    }
                    p => {
                        // RFC 4443 Section 3.4: Parameter Problem Code 1 for unrecognized Next Header
                        // The pointer indicates the octet of the unrecognized Next Header type
                        Ipv6ProcessResult::UnknownNextHeader(p.into(), next_header_ptr, src, dst)
                    }
                }
            }
            ExtHeaderResult::Fragment { .. } => Ipv6ProcessResult::Error,
        }
    }

    pub(crate) fn process_fragment_owned_packet(
        &mut self,
        packet_ref: PacketRef,
        current_time: u64,
    ) -> Ipv6ProcessResult<'static> {
        let fragment_info = {
            let raw_packet = packet_ref.data();
            let packet = match Ipv6Packet::parse(raw_packet) {
                Some(packet) => packet,
                None => {
                    self.stats.record_header_error();
                    return Ipv6ProcessResult::Error;
                }
            };

            self.stats.record_rx();

            let src = packet.source();
            if src.is_multicast() || (src.is_loopback() && !self.config.link_local.is_loopback()) {
                self.stats.record_dropped();
                log::warn!("[NET-IPV6] Dropping Martian packet with source {}", src);
                return Ipv6ProcessResult::Dropped;
            }

            let dst = packet.destination();
            if !self.is_for_us(&dst) {
                self.stats.record_dropped();
                return Ipv6ProcessResult::Dropped;
            }

            if packet.hop_limit() == 0 {
                return Ipv6ProcessResult::HopLimitExceededOwned(
                    src,
                    dst,
                    PacketPayload::single(packet_ref),
                );
            }

            match skip_extension_headers_fraginfo(raw_packet) {
                ExtHeaderResult::Fragment {
                    unfragmentable,
                    frag_header,
                    frag_payload,
                } => {
                    let unfrag_len = unfragmentable.len();
                    let quoted_unfragmentable = if unfrag_len == 0 {
                        PacketPayload::default()
                    } else if let Some(payload) =
                        generated_ipv6_header_payload(&raw_packet[..unfrag_len])
                    {
                        payload
                    } else {
                        self.stats.record_header_error();
                        return Ipv6ProcessResult::Error;
                    };
                    let reassembly_unfragmentable = if unfrag_len == 0 {
                        None
                    } else if let Some(payload) =
                        generated_ipv6_header_payload(&raw_packet[..unfrag_len])
                    {
                        Some(payload)
                    } else {
                        self.stats.record_header_error();
                        return Ipv6ProcessResult::Error;
                    };
                    let Some(frag_payload_offset) =
                        raw_packet.len().checked_sub(frag_payload.len())
                    else {
                        self.stats.record_header_error();
                        return Ipv6ProcessResult::Error;
                    };
                    (
                        src,
                        dst,
                        quoted_unfragmentable,
                        reassembly_unfragmentable,
                        frag_payload_offset,
                        frag_payload.len(),
                        frag_header,
                    )
                }
                _ => return Ipv6ProcessResult::Error,
            }
        };

        let original = PacketPayload::single(packet_ref);
        let (
            src,
            dst,
            quoted_unfragmentable,
            unfragmentable_payload,
            frag_payload_offset,
            frag_payload_len,
            frag_header,
        ) = fragment_info;
        let Some(window) =
            VerifiedPayloadWindow::for_payload(&original, frag_payload_offset, frag_payload_len)
        else {
            self.stats.record_header_error();
            return Ipv6ProcessResult::Error;
        };
        let Ok(frag_payload_packet) = window.move_from(original) else {
            self.stats.record_header_error();
            return Ipv6ProcessResult::Error;
        };

        let (result, expired) = self.reassembler.process_fragment(
            src,
            dst,
            unfragmentable_payload,
            &frag_header,
            frag_payload_packet,
            current_time,
        );

        match result {
            Ok(Some(payload)) => Ipv6ProcessResult::Reassembled(payload),
            Ok(None) => {
                if let Some((expired_src, expired_dst, quoted, frag_header)) =
                    expired.into_iter().next()
                {
                    Ipv6ProcessResult::ReassemblyTimeout(
                        expired_src,
                        expired_dst,
                        quoted,
                        frag_header,
                    )
                } else {
                    Ipv6ProcessResult::FragmentPending
                }
            }
            Err(error) => {
                let mut quoted = quoted_unfragmentable;
                let mut frag_bytes = [0u8; 8];
                frag_bytes[0] = frag_header.next_header;
                let off_and_flags = (frag_header.fragment_offset << 3)
                    | if frag_header.more_fragments { 0x01 } else { 0 };
                frag_bytes[2..4].copy_from_slice(&off_and_flags.to_be_bytes());
                frag_bytes[4..8].copy_from_slice(&frag_header.identification.to_be_bytes());
                let Some(frag_header_payload) = generated_ipv6_header_payload(&frag_bytes) else {
                    self.stats.record_header_error();
                    return Ipv6ProcessResult::Error;
                };
                append_payload(&mut quoted, frag_header_payload);
                Ipv6ProcessResult::ReassemblyError(error, src, dst, quoted)
            }
        }
    }

    /// Check if a destination address is for this interface
    pub(crate) fn is_for_us(&self, addr: &Ipv6Address) -> bool {
        // Direct matches: link-local, all-nodes multicast, solicited-node
        if *addr == self.config.link_local
            || *addr == Ipv6Address::ALL_NODES_LINK_LOCAL
            || *addr == self.config.link_local.solicited_node()
        {
            return true;
        }

        // SECURITY: RFC 4291 に従い、loopback address (::1) の受理範囲を制限する。
        // if the interface itself is the loopback interface.
        if addr.is_loopback() {
            return self.config.link_local.is_loopback();
        }

        // Global address and its solicited-node multicast
        if let Some(ref global) = self.config.global {
            if addr == global || *addr == global.solicited_node() {
                return true;
            }
        }

        false
    }

    /// Update global address (e.g. from SLAAC/RA)
    pub fn set_global_address(&mut self, addr: Ipv6Address) {
        self.config.global = Some(addr);
    }

    /// Update gateway (from RA)
    pub fn set_gateway(&mut self, addr: Ipv6Address) {
        self.config.gateway = Some(addr);
    }
}

// =====================================================
// IPv6 Pseudo-Header Checksum (RFC 8200 Section 8.1)
// =====================================================

/// Calculate IPv6 pseudo-header checksum for ICMPv6/TCP/UDP
///
/// Pseudo-header layout:
/// - Source Address (16 bytes)
/// - Destination Address (16 bytes)
/// - Upper-Layer Packet Length (4 bytes, big-endian)
/// - Next Header (4 bytes: 3 zero bytes + 1 byte)
///
/// Returns the accumulated 32-bit sum (caller should fold and complement)
pub fn ipv6_pseudo_header_checksum(
    src: &Ipv6Address,
    dst: &Ipv6Address,
    next_header: IpProtocol,
    payload_len: u32,
) -> u32 {
    let mut sum: u32 = 0;

    // Source address (16 bytes, 8 u16 words)
    let s = src.as_bytes();
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([s[i], s[i + 1]]) as u32;
    }

    // Destination address (16 bytes, 8 u16 words)
    let d = dst.as_bytes();
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([d[i], d[i + 1]]) as u32;
    }

    // Upper-layer packet length (32-bit, big-endian)
    let len_bytes = payload_len.to_be_bytes();
    sum += u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as u32;
    sum += u16::from_be_bytes([len_bytes[2], len_bytes[3]]) as u32;

    // Next Header (padded to 32 bits)
    sum += u8::from(next_header) as u32;

    sum
}
