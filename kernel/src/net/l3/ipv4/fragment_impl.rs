use super::*;
use crate::net::datapath::mempool::PacketRef;
use crate::net::payload::{PacketPayloadBuilder, alloc_packet_with_headroom};
use kernel_api::resource::net::{PacketChain, PacketPayload};

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
    packet: PacketRef,
}

pub struct FragmentBuffer {
    /// Reassembled data buffer
    data: Vec<u8>,
    /// List of holes (unfilled regions)
    holes: Vec<FragmentHole>,
    /// Total datagram length (known when last fragment received)
    total_len: Option<u16>,
    /// First fragment's full header bytes (including options, up to 60 bytes)
    first_header: Option<[u8; 60]>,
    /// Length of the stored first header
    first_header_len: usize,
    /// First fragment's payload prefix (first 8 bytes for RFC 792 ICMP error)
    first_payload_prefix: Option<[u8; 8]>,
    /// Creation timestamp (for timeout)
    created_at: u64,
    /// Last update timestamp
    last_update: u64,
    /// Original fragment payload ownership chain used to rebuild a packet-backed result.
    segments: Vec<FragmentSegment>,
    /// Whether every fragment payload is still represented by packet-backed ownership.
    segments_complete: bool,
}

impl FragmentBuffer {
    fn packet_from_slice(data: &[u8]) -> Option<PacketRef> {
        if data.is_empty() {
            return None;
        }
        let mut packet = alloc_packet_with_headroom(data.len(), 0)?;
        packet.data_mut()[..data.len()].copy_from_slice(data);
        packet.set_len(data.len());
        Some(packet)
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
            data: Vec::new(),
            holes: vec![FragmentHole {
                first: 0,
                last: Self::MAX_DATAGRAM_SIZE as u16,
            }],
            total_len: None,
            first_header: None,
            first_header_len: 0,
            first_payload_prefix: None,
            created_at: timestamp,
            last_update: timestamp,
            segments: Vec::new(),
            segments_complete: true,
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
        payload: &[u8],
        payload_packet: Option<PacketRef>,
        current_time: u64,
    ) -> bool {
        let fragment_offset = (header.fragment_offset() as u32) * 8; // Convert to bytes
        let fragment_len = payload.len() as u32;
        let fragment_end = fragment_offset + fragment_len;

        // Check for overflow
        if fragment_end > Self::MAX_DATAGRAM_SIZE as u32 {
            return false;
        }

        let fragment_offset = fragment_offset as u16;
        let fragment_end = fragment_end as u16;
        let fragment_len = fragment_len as u16;

        self.last_update = current_time;

        // Capture first payload prefix for ICMP error (RFC 792)
        if fragment_offset == 0 && self.first_payload_prefix.is_none() {
            let mut prefix = [0u8; 8];
            let copy_len = payload.len().min(8);
            prefix[..copy_len].copy_from_slice(&payload[..copy_len]);
            self.first_payload_prefix = Some(prefix);
        }

        // Security: Check for 'Tiny Fragments' (RFC 1858, RFC 3128)
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

        // Security: Check for consistent total length (RFC 791)
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

        // Note: first header storage is now handled in process_fragment for consistency

        // Ensure buffer is large enough
        if self.data.len() < fragment_end as usize {
            self.data.resize(fragment_end as usize, 0);
        }

        // Security: Check for overlapping fragments.
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

        // Copy fragment data
        self.data[fragment_offset as usize..fragment_end as usize].copy_from_slice(payload);
        if fragment_len > 0 && self.segments_complete {
            let Some(packet) = payload_packet.or_else(|| Self::packet_from_slice(payload)) else {
                self.segments_complete = false;
                self.segments.clear();
                log::warn!(
                    "[NET-IPV4] Falling back to scratch-buffer reassembly for fragment at offset {}",
                    fragment_offset
                );
                self.update_holes(fragment_offset, fragment_end, header.more_fragments());
                if self.holes.len() > Self::MAX_HOLES {
                    return false;
                }
                self.trim_holes_to_total();
                return true;
            };
            self.segments.push(FragmentSegment {
                offset: fragment_offset,
                packet,
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
        header_data: &[u8],
        fragment_offset: u16,
    ) {
        if fragment_offset == 0 && self.first_header.is_none() {
            if header_data.len() > 60 {
                return;
            }
            let mut stored = [0u8; 60];
            stored[..header_data.len()].copy_from_slice(header_data);
            self.first_header = Some(stored);
            self.first_header_len = header_data.len();
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
        let header_storage = self.first_header.as_ref()?;
        let header_len = self.first_header_len;
        let header_data = &header_storage[..header_len];

        // Check if reassembled length fits in IPv4 Total Length field (16 bits)
        if header_len + total_len > 65535 {
            log::warn!(
                "[NET-IPV4] Reassembled packet too large for u16 Total Length: {} bytes",
                header_len + total_len
            );
            return None;
        }

        // Build complete packet: header + payload
        let mut packet = Vec::with_capacity(header_len + total_len);
        packet.extend_from_slice(header_data);
        packet.extend_from_slice(&self.data[..total_len]);

        // Update header fields
        let packet_total_len = (header_len + total_len) as u16;
        packet[2] = (packet_total_len >> 8) as u8;
        packet[3] = (packet_total_len & 0xff) as u8;

        // Clear fragment flags/offset (keep DF if set, but actually reassembled packet shouldn't have MF or offset)
        packet[6] &= 0x40; // Keep only DF flag, clear MF and high offset bits
        packet[7] = 0; // Clear remaining offset bits

        // Recalculate header checksum
        packet[10] = 0;
        packet[11] = 0;
        let checksum = calculate_ip_checksum(&packet[..header_len]);
        packet[10] = (checksum >> 8) as u8;
        packet[11] = (checksum & 0xff) as u8;

        let mut header_packet = Self::packet_from_slice(&packet[..header_len])?;
        header_packet.set_len(header_len);

        let mut chain = PacketChain::new();
        chain.push(header_packet);
        if !self.segments_complete || self.segments.is_empty() {
            if packet.len() > header_len {
                chain.push(Self::packet_from_slice(&packet[header_len..])?);
            }
        } else {
            let mut segments = self.segments;
            segments.sort_unstable_by_key(|segment| segment.offset);
            for segment in segments {
                chain.push(segment.packet);
            }
        }
        Some(PacketPayload::chain(chain))
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
#[derive(Debug, Default, Clone)]
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
    pub fn process_fragment(
        &mut self,
        header: &Ipv4Header,
        header_data: &[u8],
        payload: &[u8],
        payload_packet: Option<PacketRef>,
        current_time: u64,
    ) -> (Option<PacketPayload>, Vec<(Ipv4Address, PacketPayload)>) {
        self.stats.fragments_received += 1;

        let key = FragmentKey::from_header(header);
        let src = header.source();

        // Evict expired buffers
        let expired = self.evict_expired(current_time);

        // Check if we need to create a new buffer
        if !self.buffers.contains_key(&key) {
            // Check buffer limit
            if self.buffers.len() >= self.max_buffers {
                // Evict the oldest buffer to prevent Reassembly Buffer Exhaustion DoS
                let oldest = self
                    .buffers
                    .iter()
                    .min_by_key(|(_, buf)| buf.created_at)
                    .map(|(&k, _)| k);
                if let Some(oldest_key) = oldest {
                    self.buffers.remove(&oldest_key);
                } else {
                    self.stats.dropped_limit += 1;
                    return (None, expired);
                }
            }

            // Per-source limit: prevent a single source from monopolizing buffers (RFC 4963 / Best Practice)
            let source_count = self.buffers.keys().filter(|k| k.src == src).count();
            if source_count >= Self::MAX_BUFFERS_PER_SOURCE {
                log::warn!(
                    "[NET-IPV4] Fragment buffer per-source limit ({}) reached for source {:?}, dropping",
                    Self::MAX_BUFFERS_PER_SOURCE,
                    src
                );
                self.stats.dropped_limit += 1;
                return (None, expired);
            }

            self.buffers.insert(key, FragmentBuffer::new(current_time));
        }

        // Get the buffer and add fragment
        let buffer = match self.buffers.get_mut(&key) {
            Some(b) => b,
            None => return (None, expired),
        };

        // Capture first header for reassembly
        buffer.store_first_header_if_needed(header_data, header.fragment_offset());

        if !buffer.add_fragment(header, payload, payload_packet, current_time) {
            self.stats.dropped_invalid += 1;
            // Remove invalid buffer
            self.buffers.remove(&key);
            return (None, expired);
        }

        // Check if reassembly is complete
        let complete = buffer.is_complete();
        if complete {
            let result = self
                .buffers
                .remove(&key)
                .and_then(FragmentBuffer::get_reassembled);

            if result.is_some() {
                self.stats.reassembled += 1;
            }

            return (result, expired);
        }

        (None, expired)
    }

    /// Evict expired reassembly buffers
    /// Returns a list of (src, full_header_plus_payload_prefix) for buffers that had the first fragment
    pub(super) fn evict_expired(&mut self, current_time: u64) -> Vec<(Ipv4Address, PacketPayload)> {
        let mut expired_with_first = Vec::new();
        let mut expired_keys = Vec::new();

        for (key, buf) in self.buffers.iter() {
            if buf.is_expired(current_time) {
                if let Some(ref header) = buf.first_header {
                    // RFC 792: Include IP header + first 64 bits of data
                    let mut builder = PacketPayloadBuilder::new();
                    if builder
                        .push_bytes(&header[..buf.first_header_len])
                        .is_none()
                    {
                        expired_keys.push(*key);
                        continue;
                    }
                    if let Some(prefix) = buf.first_payload_prefix {
                        if builder.push_bytes(&prefix).is_none() {
                            expired_keys.push(*key);
                            continue;
                        }
                    }
                    expired_with_first.push((key.src, builder.build()));
                }
                expired_keys.push(*key);
            }
        }

        for key in expired_keys {
            self.buffers.remove(&key);
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
