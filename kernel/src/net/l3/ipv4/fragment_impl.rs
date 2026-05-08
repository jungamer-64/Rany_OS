// ============================================================================
// kernel/src/net/l3/ipv4/fragment_impl.rs - L3 / IPv4 / フラグメント実装
// ============================================================================

use super::*;
use crate::net::payload::{PacketPayloadView, append_payload};
use kernel_api::resource::net::PacketPayload;

// ============================================================================
// IP Fragment Reassembly (RFC 791)
// ============================================================================

/// Fragment reassembly key (identifies a unique datagram)
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FragmentKey {
    /// Source IP address
    pub src: Ipv4Address,
    /// Destination IP address
    pub dst: Ipv4Address,
    /// Identification field
    pub id: u16,
    /// Protocol
    pub protocol: u8,
}

impl FragmentKey {
    /// Create a new fragment key from packet header
    pub fn from_header(header: &Ipv4Header) -> Self {
        FragmentKey {
            src: header.source(),
            dst: header.destination(),
            id: header.identification(),
            protocol: header.protocol.into(),
        }
    }
}

/// A hole in the reassembly buffer (RFC 815 algorithm)
#[derive(Clone, Copy, Debug)]
pub(crate) struct FragmentHole {
    /// Start offset (bytes)
    first: u16,
    /// End offset (bytes, exclusive)
    last: u16,
}

/// Fragment reassembly buffer for a single datagram
struct FragmentSegment {
    offset: u16,
    payload: PacketPayload,
}

pub struct FragmentBuffer {
    /// List of holes (unfilled regions)
    holes: Vec<FragmentHole>,
    /// Total datagram length (known when last fragment received)
    total_len: Option<u16>,
    /// First fragment's full header packet.
    first_header: Option<PacketPayload>,
    /// Creation timestamp (for timeout)
    created_at: u64,
    /// Last update timestamp
    last_update: u64,
    /// Original fragment payload ownership chain used to rebuild a packet-backed result.
    segments: Vec<FragmentSegment>,
}

impl FragmentBuffer {
    fn take_payload_prefix(payload: PacketPayload, len: usize) -> PacketPayload {
        let mut remaining = len;
        let mut segments = Vec::new();
        for mut segment in payload.into_segments() {
            if remaining == 0 {
                break;
            }
            let take = segment.len().min(remaining);
            segment.set_len(take);
            segments.push(segment);
            remaining -= take;
        }

        match segments.len() {
            0 => PacketPayload::default(),
            1 => PacketPayload::single(segments.remove(0)),
            _ => PacketPayload::chain(kernel_api::resource::net::PacketChain::from_segments(
                segments,
            )),
        }
    }

    /// Maximum reassembled packet size (64KB - IP header)
    /// RFC 791 defines the maximum IP packet size as 65535 bytes.
    /// Since the header is at least 20 bytes, the max payload is 65515.
    pub const MAX_DATAGRAM_SIZE: usize = 65515;

    /// Maximum number of holes allowed in the reassembly buffer
    pub const MAX_HOLES: usize = 64;

    /// Fragment timeout in milliseconds (RFC 1122 recommends 60-120 seconds)
    pub const TIMEOUT_MS: u64 = 60_000;

    /// Create a new fragment buffer
    pub fn new(timestamp: u64) -> Self {
        FragmentBuffer {
            holes: vec![FragmentHole {
                first: 0,
                last: Self::MAX_DATAGRAM_SIZE as u16,
            }],
            total_len: None,
            first_header: None,
            created_at: timestamp,
            last_update: timestamp,
            segments: Vec::new(),
        }
    }

    /// Check if reassembly is complete
    pub fn is_complete(&self) -> bool {
        self.holes.is_empty() && self.total_len.is_some()
    }

    /// Check if the buffer has timed out
    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time.saturating_sub(self.created_at) > Self::TIMEOUT_MS
    }

    /// Add a fragment to the buffer (RFC 815 hole-filling algorithm)
    ///
    /// Returns true if the fragment was accepted, false if invalid/overlapping
    pub fn add_fragment(
        &mut self,
        header: &Ipv4Header,
        payload_packet: PacketPayload,
        current_time: u64,
    ) -> bool {
        let fragment_offset = (header.fragment_offset() as u32) * 8; // Convert to bytes
        let fragment_len = payload_packet.total_len() as u32;
        let fragment_end = fragment_offset + fragment_len;

        // Check for overflow
        if fragment_end > Self::MAX_DATAGRAM_SIZE as u32 {
            return false;
        }

        let fragment_offset = fragment_offset as u16;
        let fragment_end = fragment_end as u16;
        let fragment_len = fragment_len as u16;

        self.last_update = current_time;

        // SECURITY: Tiny Fragment を検出する（RFC 1858, RFC 3128）。
        // The first fragment (offset 0) must be large enough to contain the critical
        // parts of the transport header to allow for stateful inspection and filtering.
        if fragment_offset == 0 && header.more_fragments() {
            let min_len = match header.protocol() {
                super::IpProtocol::Tcp => 20, // TCP: must contain the entire 20-byte base header (RFC 3128)
                super::IpProtocol::Udp => 8,  // UDP: must contain at least the 8-byte header
                super::IpProtocol::Icmp => 8, // ICMP: must contain at least the 8-byte header
                _ => 8,
            };
            if fragment_len < min_len {
                log::warn!(
                    "[NET-IPV4] Tiny fragment (offset 0, protocol {:?}, len {}) detected, dropping datagram",
                    header.protocol(),
                    fragment_len
                );
                return false;
            }
        }

        // RFC 791: 8-octet multiple check for non-last fragments
        if header.more_fragments() && (fragment_len % 8 != 0) {
            log::warn!(
                "[NET-IPV4] Fragment length ({}) not a multiple of 8 while MF=1, dropping",
                fragment_len
            );
            return false;
        }

        // SECURITY: total length の一貫性を検証する（RFC 791）。
        if !header.more_fragments() {
            if let Some(existing_total) = self.total_len {
                if existing_total != fragment_end {
                    log::warn!(
                        "[NET-IPV4] Inconsistent total length in fragments: expected {}, got {}",
                        existing_total,
                        fragment_end
                    );
                    return false;
                }
            }
            self.total_len = Some(fragment_end);
        } else if let Some(total) = self.total_len {
            if fragment_end > total {
                log::warn!(
                    "[NET-IPV4] Fragment beyond end of datagram: {} > {}",
                    fragment_end,
                    total
                );
                return false;
            }
        }

        // first header storage is now handled in process_fragment for consistency

        // SECURITY: 重複 fragment を検出する。
        // We detect overlap by checking if the fragment range [offset, end)
        // covers any byte that is not currently in a hole.
        let mut covered_hole_bytes: u32 = 0;
        for hole in &self.holes {
            let intersection_start = fragment_offset.max(hole.first);
            let intersection_end = fragment_end.min(hole.last);
            if intersection_start < intersection_end {
                covered_hole_bytes += (intersection_end - intersection_start) as u32;
            }
        }

        if covered_hole_bytes == 0 {
            // Duplicate fragment - RFC 5722 (for IPv6) recommends dropping the entire
            // datagram to prevent IDS evasion attacks. We apply this to IPv4 for
            // enhanced security.
            log::warn!(
                "[NET-IPV4] Duplicate fragment detected at offset {}, dropping datagram per RFC 5722 policy",
                fragment_offset
            );
            return false;
        }

        if covered_hole_bytes < fragment_len as u32 {
            // Overlap detected (partially covers filled data and partially covers holes).
            // RFC 5722 (for IPv6) and general security best practices
            // recommend discarding the entire datagram to prevent IDS evasion.
            log::warn!(
                "[NET-IPV4] Overlapping fragment detected at offset {}, dropping datagram",
                fragment_offset
            );
            return false;
        }

        if fragment_len > 0 {
            self.segments.push(FragmentSegment {
                offset: fragment_offset,
                payload: payload_packet,
            });
        }

        // Update hole list (RFC 815 algorithm)
        self.update_holes(fragment_offset, fragment_end, header.more_fragments());

        // Check for hole list exhaustion attack
        if self.holes.len() > Self::MAX_HOLES {
            return false;
        }

        self.trim_holes_to_total();

        true
    }

    /// Store the first fragment header for later reassembly
    pub(super) fn store_first_header_if_needed(
        &mut self,
        header_packet: PacketPayload,
        fragment_offset: u16,
    ) {
        if fragment_offset == 0 && self.first_header.is_none() {
            self.first_header = Some(header_packet);
        }
    }

    /// RFC 815 hole-list update with a fragment range
    pub(super) fn update_holes(
        &mut self,
        fragment_offset: u16,
        fragment_end: u16,
        more_fragments: bool,
    ) {
        let mut new_holes = Vec::new();

        for hole in self.holes.drain(..) {
            if fragment_end <= hole.first || fragment_offset >= hole.last {
                new_holes.push(hole);
            } else {
                if fragment_offset > hole.first {
                    new_holes.push(FragmentHole {
                        first: hole.first,
                        last: fragment_offset,
                    });
                }
                if fragment_end < hole.last && more_fragments {
                    new_holes.push(FragmentHole {
                        first: fragment_end,
                        last: hole.last,
                    });
                }
            }
        }

        self.holes = new_holes;
    }

    /// Remove or clamp holes beyond the known total length
    pub(super) fn trim_holes_to_total(&mut self) {
        if let Some(total) = self.total_len {
            self.holes.retain(|h| h.first < total);
            for hole in &mut self.holes {
                if hole.last > total {
                    hole.last = total;
                }
            }
        }
    }

    /// Get the reassembled packet (only valid when is_complete() is true)
    /// Build the reassembled packet once complete
    pub fn get_reassembled(self) -> Option<PacketPayload> {
        if !self.is_complete() {
            return None;
        }

        let total_len = self.total_len? as usize;
        let mut header_payload = self.first_header?;
        let header_len = header_payload.total_len();

        // Check if reassembled length fits in IPv4 Total Length field (16 bits)
        if header_len + total_len > 65535 {
            log::warn!(
                "[NET-IPV4] Reassembled packet too large for u16 Total Length: {} bytes",
                header_len + total_len
            );
            return None;
        }

        let mut header_bytes = [0u8; 60];
        if header_len > header_bytes.len() {
            return None;
        }
        let mut copied = 0usize;
        PacketPayloadView::new(&header_payload).for_each_chunk(|chunk| {
            if copied == header_len {
                return;
            }
            let take = chunk.len().min(header_len - copied);
            header_bytes[copied..copied + take].copy_from_slice(&chunk[..take]);
            copied += take;
        });
        if copied != header_len {
            return None;
        }

        // Update header fields
        let packet_total_len = (header_len + total_len) as u16;
        header_bytes[2] = (packet_total_len >> 8) as u8;
        header_bytes[3] = (packet_total_len & 0xff) as u8;

        // Clear fragment flags/offset (keep DF if set, but actually reassembled packet shouldn't have MF or offset)
        header_bytes[6] &= 0x40; // Keep only DF flag, clear MF and high offset bits
        header_bytes[7] = 0; // Clear remaining offset bits

        // Recalculate header checksum
        header_bytes[10] = 0;
        header_bytes[11] = 0;
        let checksum = calculate_ip_checksum(&header_bytes[..header_len]);
        header_bytes[10] = (checksum >> 8) as u8;
        header_bytes[11] = (checksum & 0xff) as u8;

        if let Some(first_segment) = header_payload.segments_mut().first_mut() {
            let data = first_segment.data_mut();
            data[..header_len].copy_from_slice(&header_bytes[..header_len]);
        }

        let mut packet = header_payload;
        let mut segments = self.segments;
        segments.sort_unstable_by_key(|segment| segment.offset);
        for segment in segments {
            append_payload(&mut packet, segment.payload);
        }
        Some(packet)
    }
}

/// IP fragment reassembler
pub struct FragmentReassembler {
    /// Active fragment buffers, keyed by fragment key
    buffers: BTreeMap<FragmentKey, FragmentBuffer>,
    /// Maximum number of concurrent reassembly buffers
    max_buffers: usize,
    /// Statistics
    stats: FragmentStats,
}

/// Fragment reassembly statistics
#[derive(Debug, Default)]
pub struct FragmentStats {
    /// Fragments received
    pub fragments_received: u64,
    /// Datagrams successfully reassembled
    pub reassembled: u64,
    /// Reassembly timeouts
    pub timeouts: u64,
    /// Dropped due to buffer limit
    pub dropped_limit: u64,
    /// Dropped due to invalid fragment
    pub dropped_invalid: u64,
}

impl FragmentReassembler {
    /// Default maximum number of concurrent reassembly buffers
    pub const DEFAULT_MAX_BUFFERS: usize = 64;

    /// Maximum concurrent reassembly buffers from a single source address.
    /// Prevents a single attacker from monopolizing the entire buffer pool.
    const MAX_BUFFERS_PER_SOURCE: usize = 16;

    /// Create a new fragment reassembler
    pub fn new(max_buffers: usize) -> Self {
        FragmentReassembler {
            buffers: BTreeMap::new(),
            max_buffers,
            stats: FragmentStats::default(),
        }
    }

    /// Get statistics
    pub fn stats(&self) -> &FragmentStats {
        &self.stats
    }

    /// Process an incoming fragment
    ///
    /// Returns (reassembled_packet, expired_buffers)
    /// Evict expired reassembly buffers
    /// Returns a list of (src, full_header_plus_payload_prefix) for buffers that had the first fragment
    pub(crate) fn process_fragment(
        &mut self,
        header: &Ipv4Header,
        header_packet: PacketPayload,
        payload_packet: PacketPayload,
        current_time: u64,
    ) -> (Option<PacketPayload>, Vec<(Ipv4Address, PacketPayload)>) {
        let expired = self.evict_expired(current_time);
        self.stats.fragments_received = self.stats.fragments_received.saturating_add(1);

        let key = FragmentKey::from_header(header);
        if !self.buffers.contains_key(&key) {
            if self.buffers.len() >= self.max_buffers
                || self
                    .buffers
                    .keys()
                    .filter(|existing| existing.src == key.src)
                    .count()
                    >= Self::MAX_BUFFERS_PER_SOURCE
            {
                self.stats.dropped_limit = self.stats.dropped_limit.saturating_add(1);
                return (None, expired);
            }
            self.buffers.insert(key, FragmentBuffer::new(current_time));
        }

        let accepted = {
            let Some(buffer) = self.buffers.get_mut(&key) else {
                return (None, expired);
            };
            buffer.store_first_header_if_needed(header_packet, header.fragment_offset());
            buffer.add_fragment(header, payload_packet, current_time)
        };

        if !accepted {
            self.stats.dropped_invalid = self.stats.dropped_invalid.saturating_add(1);
            self.buffers.remove(&key);
            return (None, expired);
        }

        let is_complete = self
            .buffers
            .get(&key)
            .map(FragmentBuffer::is_complete)
            .unwrap_or(false);
        if !is_complete {
            return (None, expired);
        }

        let Some(buffer) = self.buffers.remove(&key) else {
            return (None, expired);
        };
        let reassembled = buffer.get_reassembled();
        if reassembled.is_some() {
            self.stats.reassembled = self.stats.reassembled.saturating_add(1);
        } else {
            self.stats.dropped_invalid = self.stats.dropped_invalid.saturating_add(1);
        }
        (reassembled, expired)
    }

    pub(super) fn evict_expired(&mut self, current_time: u64) -> Vec<(Ipv4Address, PacketPayload)> {
        let mut expired_with_first = Vec::new();
        let mut expired_keys = Vec::new();

        for (key, buf) in self.buffers.iter() {
            if buf.is_expired(current_time) {
                expired_keys.push(*key);
            }
        }

        for key in expired_keys {
            if let Some(buffer) = self.buffers.remove(&key) {
                if let Some(header) = buffer.first_header {
                    let mut quoted = header;
                    if let Some(segment) = buffer
                        .segments
                        .into_iter()
                        .find(|segment| segment.offset == 0)
                    {
                        let prefix = FragmentBuffer::take_payload_prefix(segment.payload, 8);
                        append_payload(&mut quoted, prefix);
                    }
                    expired_with_first.push((key.src, quoted));
                }
            }
            self.stats.timeouts += 1;
        }

        expired_with_first
    }

    /// Get the number of active reassembly buffers
    pub fn active_buffers(&self) -> usize {
        self.buffers.len()
    }
}

/// Calculate IP header checksum
pub(crate) fn calculate_ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    for i in (0..header.len()).step_by(2) {
        if i == 10 {
            continue; // Skip checksum field
        }
        let word = if i + 1 < header.len() {
            u16::from_be_bytes([header[i], header[i + 1]])
        } else {
            u16::from_be_bytes([header[i], 0])
        };
        sum += word as u32;
    }

    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}
