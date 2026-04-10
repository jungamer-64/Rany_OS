use super::*;
use crate::net::datapath::mempool::PacketRef;
use crate::net::l3::ipv6::{ExtHeaderResult, Ipv6Packet, skip_extension_headers_fraginfo};
use alloc::vec;
use kernel_api::resource::net::PacketPayload;

impl Ipv6Processor {
    fn packet_payload_from_frame(
        data: &[u8],
        packet_ref: Option<&PacketRef>,
    ) -> Option<PacketPayload> {
        if let Some(packet_ref) = packet_ref {
            return Some(PacketPayload::single(packet_ref.clone()));
        }

        let mut builder = crate::net::payload::PacketPayloadBuilder::new();
        builder.push_bytes(data)?;
        Some(builder.build())
    }

    /// Create a new IPv6 processor
    pub fn new(config: Ipv6Config) -> Self {
        Ipv6Processor {
            config,
            stats: Ipv6Stats::default(),
            reassembler: Ipv6FragmentReassembler::new(Ipv6FragmentReassembler::DEFAULT_MAX_BUFFERS),
            pmtu_cache: Ipv6PmtuCache::new(Ipv6PmtuCache::DEFAULT_MAX_ENTRIES),
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
        current_time: u64,
        packet_ref: Option<PacketRef>,
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

        // Security: Drop Martian packets
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
            let Some(orig_packet) = Self::packet_payload_from_frame(data, packet_ref.as_ref())
            else {
                self.stats.record_header_error();
                return Ipv6ProcessResult::Error;
            };
            return Ipv6ProcessResult::HopLimitExceeded(src, dst, orig_packet);
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
                        let Some(orig_packet) =
                            Self::packet_payload_from_frame(data, packet_ref.as_ref())
                        else {
                            self.stats.record_header_error();
                            return Ipv6ProcessResult::Error;
                        };
                        Ipv6ProcessResult::UnknownNextHeader(
                            p.into(),
                            next_header_ptr,
                            src,
                            dst,
                            orig_packet,
                        )
                    }
                }
            }
            ExtHeaderResult::Fragment {
                unfragmentable,
                frag_header,
                frag_payload,
            } => {
                let (res, expired) = self.reassembler.process_fragment(
                    src,
                    dst,
                    unfragmentable,
                    packet_ref.as_ref().map(|ip_packet| {
                        let mut header_packet = ip_packet.clone();
                        header_packet.set_len(unfragmentable.len());
                        header_packet
                    }),
                    &frag_header,
                    frag_payload,
                    packet_ref.as_ref().and_then(|ip_packet| {
                        let payload_offset =
                            (frag_payload.as_ptr() as usize).checked_sub(data.as_ptr() as usize)?;
                        let mut payload_packet = ip_packet.clone();
                        payload_packet.advance(payload_offset);
                        payload_packet.set_len(frag_payload.len());
                        Some(payload_packet)
                    }),
                    current_time,
                );

                match res {
                    Ok(Some(data)) => Ipv6ProcessResult::Reassembled(data),
                    Ok(None) => {
                        if !expired.is_empty() {
                            let (e_src, e_dst, e_unfrag, e_frag_header) = expired[0].clone();
                            Ipv6ProcessResult::ReassemblyTimeout(
                                e_src,
                                e_dst,
                                e_unfrag,
                                e_frag_header,
                            )
                        } else {
                            Ipv6ProcessResult::FragmentPending
                        }
                    }
                    Err(e) => {
                        let Some(ip_packet) = packet_ref.as_ref() else {
                            return Ipv6ProcessResult::Error;
                        };
                        let mut unfragmentable_packet = ip_packet.clone();
                        unfragmentable_packet.set_len(unfragmentable.len());
                        let mut fragment_header_packet = ip_packet.clone();
                        fragment_header_packet.advance(unfragmentable.len());
                        fragment_header_packet.set_len(8);
                        Ipv6ProcessResult::ReassemblyError(
                            e,
                            src,
                            dst,
                            kernel_api::resource::net::PacketPayload::chain(
                                kernel_api::resource::net::PacketChain::from_segments(vec![
                                    unfragmentable_packet,
                                    fragment_header_packet,
                                ]),
                            ),
                        )
                    }
                }
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

        // Security (RFC 4291): Loopback address (::1) must only be accepted
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
