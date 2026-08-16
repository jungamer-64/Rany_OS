// ============================================================================
// kernel/src/net/l3/ipv6/fragment.rs - L3 / IPv6 / フラグメント
// ============================================================================
//! IPv6 Fragment Reassembly (RFC 8200 Section 4.5)
//!
//! IPv6 fragmentation uses a dedicated extension header. Unlike IPv4, only the
//! source host may fragment; routers never do. The fragment header is 8 bytes:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Next Header  |   Reserved    |      Fragment Offset    |Res|M|
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Identification                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Fragment Offset: 13 bits, measured in units of 8 octets.
//! M (More Fragments): 1 bit flag.
//! Identification: 32-bit value unique per original datagram.
//!
//! The "unfragmentable part" (fixed header + extension headers before the
//! fragment header) is sent only in the first fragment (offset == 0).

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use super::Ipv6Address;
use super::Ipv6ReassemblyError;
use crate::net::payload::{GeneratedPacketWriter, PacketPayloadView, append_payload};
use kernel_api::resource::net::{DEFAULT_PACKET_HEADROOM, PacketPayload};

// =====================================================
// Fragment Header Parsing
// =====================================================

/// Parsed IPv6 Fragment Header (8 bytes)
#[derive(Debug, Clone, Copy)]
pub struct Ipv6FragmentHeader {
    /// Next Header (upper-layer or next extension)
    pub next_header: u8,
    /// Fragment Offset in 8-octet units (13 bits)
    pub fragment_offset: u16,
    /// More Fragments flag
    pub more_fragments: bool,
    /// 32-bit Identification
    pub identification: u32,
}

impl Ipv6FragmentHeader {
    /// Fragment header is always 8 bytes
    pub const SIZE: usize = 8;

    /// Parse from 8 bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }

        let next_header = data[0];
        // data[1] is reserved
        let off_and_flags = u16::from_be_bytes([data[2], data[3]]);
        let fragment_offset = off_and_flags >> 3; // upper 13 bits
        let more_fragments = (off_and_flags & 0x01) != 0;
        let identification = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        Some(Self {
            next_header,
            fragment_offset,
            more_fragments,
            identification,
        })
    }

    /// Fragment offset in bytes (multiply 8-octet units by 8)
    #[inline]
    pub fn offset_bytes(&self) -> u32 {
        (self.fragment_offset as u32) * 8
    }
}

// =====================================================
// Key for identifying a fragment group
// =====================================================

/// Unique key for a set of IPv6 fragments belonging to one datagram.
/// RFC 8200: (Source, Destination, Identification)
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv6FragmentKey {
    src: Ipv6Address,
    dst: Ipv6Address,
    id: u32,
}

impl Ipv6FragmentKey {
    pub fn new(src: Ipv6Address, dst: Ipv6Address, id: u32) -> Self {
        Self { src, dst, id }
    }
}

// =====================================================
// Hole descriptor (RFC 815 algorithm)
// =====================================================

#[derive(Clone, Copy, Debug)]
struct Hole {
    first: u32,
    last: u32, // exclusive
}

// =====================================================
// Per-datagram reassembly buffer
// =====================================================

/// Reassembly buffer for a single IPv6 datagram.
struct FragmentSegment {
    offset: u32,
    payload: PacketPayload,
}

pub struct Ipv6FragmentBuffer {
    /// Hole list (unfilled regions)
    holes: Vec<Hole>,
    /// Total payload length — known once the last fragment (M=0) arrives
    total_len: Option<u32>,
    /// Next Header value from the fragment header (upper-layer protocol)
    next_header: Option<u8>,
    /// Unfragmentable part (IPv6 fixed header + pre-fragment extension headers)
    /// captured from the first fragment (offset == 0).
    unfragmentable_part: Option<PacketPayload>,
    /// 8-byte Fragment Header captured from the first fragment (offset == 0).
    /// RFC 8200: Required for ICMPv6 error messages to identify the datagram.
    first_frag_header: Option<[u8; 8]>,
    /// Timestamp of first fragment arrival
    created_at: u64,
    /// Original fragment ownership chain used to rebuild a packet-backed result.
    segments: Vec<FragmentSegment>,
}

impl Ipv6FragmentBuffer {
    fn read_payload_u8(payload: &PacketPayload, offset: usize) -> Option<u8> {
        PacketPayloadView::new(payload).read_u8(offset)
    }

    fn write_payload_byte(payload: &mut PacketPayload, offset: usize, value: u8) -> bool {
        let mut remaining = offset;
        for segment in payload.segments_mut() {
            if remaining < segment.len() {
                segment.data_mut()[remaining] = value;
                return true;
            }
            remaining -= segment.len();
        }
        false
    }

    fn write_payload_u16_be(payload: &mut PacketPayload, offset: usize, value: u16) -> bool {
        let [high, low] = value.to_be_bytes();
        Self::write_payload_byte(payload, offset, high)
            && Self::write_payload_byte(payload, offset + 1, low)
    }

    /// Maximum number of holes allowed in the reassembly buffer
    const MAX_HOLES: usize = 64;

    /// Timeout for reassembly (RFC 8200 recommends 60 seconds)
    const TIMEOUT_MS: u64 = 60_000;

    fn new(timestamp: u64) -> Self {
        Self {
            holes: vec![Hole {
                first: 0,
                last: u32::MAX,
            }],
            total_len: None,
            next_header: None,
            unfragmentable_part: None,
            first_frag_header: None,
            created_at: timestamp,
            segments: Vec::new(),
        }
    }

    /// Is reassembly complete?
    fn is_complete(&self) -> bool {
        self.holes.is_empty() && self.total_len.is_some()
    }

    /// Is the buffer expired?
    fn is_expired(&self, now: u64) -> bool {
        now.saturating_sub(self.created_at) > Self::TIMEOUT_MS
    }

    /// Add a fragment.
    ///
    /// `unfragmentable` is the bytes before the fragment header (IPv6 fixed header +
    /// pre-fragment extension headers). It is captured from the first fragment (offset == 0).
    /// `frag` is the parsed fragment header and `payload` is the fragment payload.
    /// Incorporate a fragment into the buffer.
    ///
    /// Returns `Ok(())` if the fragment was successfully incorporated.
    fn add_fragment(
        &mut self,
        unfragmentable_packet: Option<PacketPayload>,
        frag: &Ipv6FragmentHeader,
        payload_packet: PacketPayload,
    ) -> Result<(), Ipv6ReassemblyError> {
        let offset = frag.offset_bytes();
        let payload_len = payload_packet.total_len() as u32;
        let end = offset + payload_len;

        // RFC 8200: 8-octet multiple check for non-last fragments
        if frag.more_fragments && (payload_len % 8 != 0) {
            log::warn!(
                "[NET-IPV6] Fragment length ({}) not a multiple of 8 while M=1, dropping (RFC 8200)",
                payload_len
            );
            return Err(Ipv6ReassemblyError::InvalidSize);
        }

        // RFC 8200: Sum of Fragment Offset and Payload Length > 65535
        // fragmentable part の先頭から見たオフセットで判定する。
        if end > 65535 {
            log::warn!("[NET-IPV6] Fragment offset + length exceeds 65535, discarding (RFC 8200)");
            return Err(Ipv6ReassemblyError::PacketTooLarge);
        }

        // RFC 8200: Reassembled packet size check (Payload Length field is 16 bits)
        // Reassembled Payload Length = (unfragmentable_part_len - 40) + total_payload_len
        // This MUST NOT exceed 65,535 octets.
        if let Some(unfrag) = &self.unfragmentable_part {
            let reassembled_payload_len = unfrag.total_len().saturating_sub(40) + end as usize;
            if reassembled_payload_len > 65535 {
                log::warn!(
                    "[NET-IPV6] Reassembled packet Payload Length {} exceeds 65535, discarding (RFC 8200)",
                    reassembled_payload_len
                );
                return Err(Ipv6ReassemblyError::PacketTooLarge);
            }
        } else if let Some(unfrag) = &unfragmentable_packet {
            // We are processing the first fragment right now
            let reassembled_payload_len = unfrag.total_len().saturating_sub(40) + end as usize;
            if reassembled_payload_len > 65535 {
                log::warn!(
                    "[NET-IPV6] Reassembled packet Payload Length {} exceeds 65535, discarding (RFC 8200)",
                    reassembled_payload_len
                );
                return Err(Ipv6ReassemblyError::PacketTooLarge);
            }
        }

        // RFC 8200: Check for consistent total length
        if !frag.more_fragments {
            if let Some(existing_total) = self.total_len {
                if existing_total != end {
                    log::warn!(
                        "[NET-IPV6] Inconsistent total length in fragments: expected {}, got {}",
                        existing_total,
                        end
                    );
                    return Err(Ipv6ReassemblyError::Overlap);
                }
            }
            self.total_len = Some(end);
        } else if let Some(total) = self.total_len {
            if end > total {
                log::warn!(
                    "[NET-IPV6] Fragment beyond end of datagram: {} > {}",
                    end,
                    total
                );
                return Err(Ipv6ReassemblyError::Overlap);
            }
        }

        // RFC 8200 overlap check: if any of the fragments overlap, discard entire datagram.
        // We detect overlap if the fragment range [offset, end) covers any byte that
        // is not currently in a hole.
        let mut covered_hole_bytes: u32 = 0;
        for hole in &self.holes {
            let intersection_start = offset.max(hole.first);
            let intersection_end = end.min(hole.last);
            if intersection_start < intersection_end {
                covered_hole_bytes += intersection_end - intersection_start;
            }
        }
        if covered_hole_bytes == 0 && payload_len > 0 {
            // Duplicate fragment - RFC 5722 requires dropping the entire datagram
            log::warn!(
                "[NET-IPV6] Duplicate fragment detected (offset={}, len={}), discarding datagram (RFC 5722)",
                offset,
                payload_len
            );
            return Err(Ipv6ReassemblyError::Overlap);
        }
        if covered_hole_bytes < payload_len {
            // Overlap detected with already received data
            log::warn!(
                "[NET-IPV6] Overlapping fragment detected (offset={}, len={}), discarding datagram (RFC 8200)",
                offset,
                payload_len
            );
            return Err(Ipv6ReassemblyError::Overlap);
        }

        // Record Next Header (should be consistent across fragments of same datagram)
        if self.next_header.is_none() {
            self.next_header = Some(frag.next_header);
        }

        // Capture unfragmentable part and fragment header from the first fragment
        if frag.fragment_offset == 0 && self.unfragmentable_part.is_none() {
            // RFC 8200/7112: The first fragment (offset 0) MUST contain the entire header chain
            // (all extension headers + upper-layer header).
            let payload_view = PacketPayloadView::new(&payload_packet);
            // 256 bytes covers all realistic extension header chains while still providing DoS protection.
            let mut header_chain = [0u8; 256];
            let chain_len = payload_view.total_len().min(header_chain.len());
            let mut copied = 0usize;
            payload_view.for_each_chunk(|chunk| {
                if copied == chain_len {
                    return;
                }
                let take = chunk.len().min(chain_len - copied);
                header_chain[copied..copied + take].copy_from_slice(&chunk[..take]);
                copied += take;
            });
            if copied != chain_len
                || !super::is_header_chain_complete(frag.next_header, &header_chain[..chain_len])
            {
                log::warn!(
                    "[NET-IPV6] Dropping IPv6 datagram due to incomplete header chain in first fragment (Tiny Fragment Attack prevention)"
                );
                return Err(Ipv6ReassemblyError::IncompleteHeaderChain);
            }
            let Some(header_packet) = unfragmentable_packet else {
                return Err(Ipv6ReassemblyError::InvalidSize);
            };
            self.unfragmentable_part = Some(header_packet);

            // Store the 8-byte fragment header for ICMPv6 error messages (RFC 8200)
            let mut frag_bytes = [0u8; 8];
            frag_bytes[0] = frag.next_header;
            frag_bytes[1] = 0; // Reserved
            let off_and_flags =
                (frag.fragment_offset << 3) | (if frag.more_fragments { 0x01 } else { 0 });
            frag_bytes[2..4].copy_from_slice(&off_and_flags.to_be_bytes());
            frag_bytes[4..8].copy_from_slice(&frag.identification.to_be_bytes());
            self.first_frag_header = Some(frag_bytes);
        }

        // Last fragment determines total length
        if !frag.more_fragments {
            self.total_len = Some(end);
        }

        if payload_len > 0 {
            self.segments.push(FragmentSegment {
                offset,
                payload: payload_packet,
            });
        }

        // RFC 815 hole-list update
        self.update_holes(offset, end, frag.more_fragments);

        // Check for hole list exhaustion attack
        if self.holes.len() > Self::MAX_HOLES {
            return Err(Ipv6ReassemblyError::Overlap);
        }

        self.trim_holes();

        Ok(())
    }

    /// RFC 815 hole-list update
    fn update_holes(&mut self, frag_start: u32, frag_end: u32, more: bool) {
        let mut new_holes = Vec::new();

        for hole in self.holes.drain(..) {
            if frag_end <= hole.first || frag_start >= hole.last {
                // Fragment doesn't overlap this hole
                new_holes.push(hole);
            } else {
                // Fragment overlaps — split the hole
                if frag_start > hole.first {
                    new_holes.push(Hole {
                        first: hole.first,
                        last: frag_start,
                    });
                }
                if frag_end < hole.last && more {
                    new_holes.push(Hole {
                        first: frag_end,
                        last: hole.last,
                    });
                }
            }
        }

        self.holes = new_holes;
    }

    /// Remove/clamp holes past total_len
    fn trim_holes(&mut self) {
        if let Some(total) = self.total_len {
            self.holes.retain(|h| h.first < total);
            for hole in &mut self.holes {
                if hole.last > total {
                    hole.last = total;
                }
            }
        }
    }

    /// Build the reassembled packet once complete.
    ///
    /// The result is: unfragmentable_part (with Next Header patched) + reassembled payload.
    /// The caller receives a fully-formed IPv6 packet that can be re-processed.
    fn reassemble(self) -> Option<PacketPayload> {
        if !self.is_complete() {
            return None;
        }

        let total = self.total_len? as usize;
        let nh = self.next_header?;
        let mut unfrag = self.unfragmentable_part?;
        let unfrag_len = unfrag.total_len();

        // Check if reassembled length fits in IPv6 Payload Length field (16 bits)
        // RFC 8200: Payload Length excludes the 40-byte fixed header.
        if (unfrag_len + total).saturating_sub(40) > 65535 {
            log::warn!(
                "[NET-IPV6] Reassembled packet too large for u16 Payload Length: {} bytes (Jumbo Payloads not supported)",
                unfrag_len + total
            );
            return None;
        }

        // Patch the Next Header field.
        //
        // The unfragmentable part's last Next Header byte currently says "Fragment (44)".
        // We need to replace that with the actual next header from the fragment header.
        if unfrag_len >= 40 {
            // Walk the extension header chain in the unfragmentable part
            let pos = 6; // Next Header offset in IPv6 fixed header
            let mut nh_value = Self::read_payload_u8(&unfrag, pos)?;

            // If the fixed header's Next Header is already 44, just patch it
            if nh_value == super::EXT_HEADER_FRAGMENT {
                if !Self::write_payload_byte(&mut unfrag, pos, nh) {
                    return None;
                }
            } else {
                // Walk extension headers inside unfragmentable part
                let mut ext_offset = 40usize;
                // SECURITY: malformed header による infinite loop を防ぐため反復回数を制限する。
                for _ in 0..16 {
                    if ext_offset + 2 > unfrag_len {
                        break;
                    }

                    // Previous extension header's Next Header field is at 'pos'
                    // We need to update nh_value to the CURRENT extension header's Next Header
                    let current_nh = nh_value;
                    nh_value = Self::read_payload_u8(&unfrag, ext_offset)?;

                    if nh_value == super::EXT_HEADER_FRAGMENT {
                        if !Self::write_payload_byte(&mut unfrag, ext_offset, nh) {
                            return None;
                        }
                        break;
                    }

                    let ext_len_byte = Self::read_payload_u8(&unfrag, ext_offset + 1)?;
                    let ext_len = if current_nh == 51 {
                        // EXT_HEADER_AUTH
                        (ext_len_byte as usize + 2) * 4
                    } else {
                        (ext_len_byte as usize + 1) * 8
                    };

                    if ext_len == 0 {
                        break;
                    }

                    ext_offset += ext_len;
                    if ext_offset >= unfrag_len {
                        break;
                    }
                }
            }

            // Update Payload Length in the IPv6 header
            let payload_len = (unfrag_len.saturating_sub(40) + total) as u16;
            if !Self::write_payload_u16_be(&mut unfrag, 4, payload_len) {
                return None;
            }
        }

        let mut reassembled = unfrag;
        let mut payload_segments = self.segments;
        payload_segments.sort_unstable_by_key(|segment| segment.offset);
        for segment in payload_segments {
            append_payload(&mut reassembled, segment.payload);
        }

        Some(reassembled)
    }
}

// =====================================================
// IPv6 Fragment Reassembler
// =====================================================

/// IPv6 fragment reassembler.
///
/// Manages concurrent reassembly buffers keyed by (src, dst, id).
/// Expired buffers are evicted lazily on incoming fragments.
pub struct Ipv6FragmentReassembler {
    buffers: BTreeMap<Ipv6FragmentKey, Ipv6FragmentBuffer>,
    max_buffers: usize,
    stats: Ipv6FragmentStats,
}

/// Reassembly statistics
#[derive(Debug, Default)]
pub struct Ipv6FragmentStats {
    /// Total fragments received
    pub fragments_received: u64,
    /// Datagrams successfully reassembled
    pub reassembled: u64,
    /// Buffers evicted due to timeout
    pub timeouts: u64,
    /// Fragments dropped due to buffer limit
    pub dropped_limit: u64,
    /// Fragments dropped due to invalid data
    pub dropped_invalid: u64,
}

impl Ipv6FragmentReassembler {
    /// Default maximum concurrent reassembly buffers
    pub const DEFAULT_MAX_BUFFERS: usize = 64;

    /// Maximum concurrent reassembly buffers from a single source address.
    /// Prevents a single attacker from monopolizing the entire buffer pool.
    const MAX_BUFFERS_PER_SOURCE: usize = 8;

    /// Create a new reassembler
    pub fn new(max_buffers: usize) -> Self {
        Self {
            buffers: BTreeMap::new(),
            max_buffers,
            stats: Ipv6FragmentStats::default(),
        }
    }

    /// Get statistics
    pub fn stats(&self) -> &Ipv6FragmentStats {
        &self.stats
    }

    pub fn process_fragment(
        &mut self,
        src: Ipv6Address,
        dst: Ipv6Address,
        unfragmentable: Option<PacketPayload>,
        frag: &Ipv6FragmentHeader,
        frag_payload: PacketPayload,
        current_time: u64,
    ) -> (
        Result<Option<PacketPayload>, Ipv6ReassemblyError>,
        Vec<(Ipv6Address, Ipv6Address, PacketPayload, Option<[u8; 8]>)>,
    ) {
        let expired = self.evict_expired(current_time);
        self.stats.fragments_received = self.stats.fragments_received.saturating_add(1);

        let key = Ipv6FragmentKey::new(src, dst, frag.identification);
        if !self.buffers.contains_key(&key) {
            if self.buffers.len() >= self.max_buffers
                || self
                    .buffers
                    .keys()
                    .filter(|existing| existing.src == src)
                    .count()
                    >= Self::MAX_BUFFERS_PER_SOURCE
            {
                self.stats.dropped_limit = self.stats.dropped_limit.saturating_add(1);
                return (Ok(None), expired);
            }
            self.buffers
                .insert(key, Ipv6FragmentBuffer::new(current_time));
        }

        let add_result = {
            let Some(buffer) = self.buffers.get_mut(&key) else {
                return (Ok(None), expired);
            };
            buffer.add_fragment(unfragmentable, frag, frag_payload)
        };

        if let Err(error) = add_result {
            self.stats.dropped_invalid = self.stats.dropped_invalid.saturating_add(1);
            self.buffers.remove(&key);
            return (Err(error), expired);
        }

        let is_complete = self
            .buffers
            .get(&key)
            .map(Ipv6FragmentBuffer::is_complete)
            .unwrap_or(false);
        if !is_complete {
            return (Ok(None), expired);
        }

        let Some(buffer) = self.buffers.remove(&key) else {
            return (Ok(None), expired);
        };
        let reassembled = buffer.reassemble();
        if reassembled.is_some() {
            self.stats.reassembled = self.stats.reassembled.saturating_add(1);
        } else {
            self.stats.dropped_invalid = self.stats.dropped_invalid.saturating_add(1);
        }
        (Ok(reassembled), expired)
    }

    /// Process an incoming IPv6 packet that contains a fragment header.
    ///
    /// Returns (Result<reassembled_packet, error>, expired_buffers).
    /// Evict expired reassembly buffers.
    /// Returns a list of (src, dst, unfragmentable_part, fragment_header) for buffers that had the first fragment.
    pub fn evict_expired(
        &mut self,
        current_time: u64,
    ) -> Vec<(Ipv6Address, Ipv6Address, PacketPayload, Option<[u8; 8]>)> {
        let mut expired_with_first = Vec::new();
        let mut keys_to_remove = Vec::new();

        for (key, buf) in self.buffers.iter() {
            if buf.is_expired(current_time) {
                keys_to_remove.push(*key);
            }
        }

        for key in keys_to_remove {
            if let Some(buffer) = self.buffers.remove(&key) {
                if let Some(unfrag) = buffer.unfragmentable_part {
                    let mut quoted = unfrag;
                    if let Some(fragment_header) = buffer.first_frag_header {
                        if let Some(mut header_writer) = GeneratedPacketWriter::new(
                            fragment_header.len(),
                            DEFAULT_PACKET_HEADROOM,
                        ) {
                            if header_writer
                                .write_generated_bytes(&fragment_header)
                                .is_some()
                            {
                                if let Some(header_payload) = header_writer.finish() {
                                    append_payload(&mut quoted, header_payload);
                                }
                            }
                        }
                    } else if let Some(segment) = buffer
                        .segments
                        .into_iter()
                        .find(|segment| segment.offset == 0)
                    {
                        let Some(bounds) = crate::net::payload::OwnedPayloadBounds::checked(
                            &segment.payload,
                            0,
                            8,
                        ) else {
                            continue;
                        };
                        let Some(prefix) = bounds
                            .take_from(segment.payload)
                            .and_then(|window| window.into_payload().ok())
                        else {
                            continue;
                        };
                        append_payload(&mut quoted, prefix);
                    }
                    expired_with_first.push((key.src, key.dst, quoted, None));
                }
            }
            self.stats.timeouts += 1;
        }

        expired_with_first
    }

    /// Number of active reassembly buffers
    pub fn active_buffers(&self) -> usize {
        self.buffers.len()
    }
}
