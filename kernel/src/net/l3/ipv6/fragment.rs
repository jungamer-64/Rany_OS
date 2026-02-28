// ============================================================================
// kernel/src/net/ipv6/fragment.rs
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
pub struct Ipv6FragmentBuffer {
    /// Payload data (fragment payloads, without extension headers)
    data: Vec<u8>,
    /// Hole list (unfilled regions)
    holes: Vec<Hole>,
    /// Total payload length — known once the last fragment (M=0) arrives
    total_len: Option<u32>,
    /// Next Header value from the fragment header (upper-layer protocol)
    next_header: Option<u8>,
    /// Unfragmentable part (IPv6 fixed header + pre-fragment extension headers)
    /// captured from the first fragment (offset == 0).
    unfragmentable_part: Option<Vec<u8>>,
    /// Timestamp of first fragment arrival
    created_at: u64,
}

impl Ipv6FragmentBuffer {
    /// Maximum reassembled payload (just under 64 KB, accounting for headers)
    const MAX_PAYLOAD: usize = 65535;

    /// Maximum number of holes allowed in the reassembly buffer
    const MAX_HOLES: usize = 64;

    /// Timeout for reassembly (RFC 8200 recommends 60 seconds)
    const TIMEOUT_MS: u64 = 60_000;

    fn new(timestamp: u64) -> Self {
        Self {
            data: Vec::new(),
            holes: vec![Hole {
                first: 0,
                last: u32::MAX,
            }],
            total_len: None,
            next_header: None,
            unfragmentable_part: None,
            created_at: timestamp,
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
    ///
    /// Returns `true` if the fragment was successfully incorporated.
    fn add_fragment(
        &mut self,
        unfragmentable: &[u8],
        frag: &Ipv6FragmentHeader,
        payload: &[u8],
    ) -> bool {
        let offset = frag.offset_bytes();
        let payload_len = payload.len() as u32;
        let end = offset + payload_len;

        if end as usize > Self::MAX_PAYLOAD {
            return false;
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
        if covered_hole_bytes < payload_len {
            // Overlap detected with already received data
            return false;
        }

        // Record Next Header (should be consistent across fragments of same datagram)
        if self.next_header.is_none() {
            self.next_header = Some(frag.next_header);
        }

        // Capture unfragmentable part from the first fragment
        if frag.fragment_offset == 0 && self.unfragmentable_part.is_none() {
            self.unfragmentable_part = Some(unfragmentable.to_vec());
        }

        // Last fragment determines total length
        if !frag.more_fragments {
            self.total_len = Some(end);
        }

        // Grow data buffer if needed
        if (end as usize) > self.data.len() {
            self.data.resize(end as usize, 0);
        }

        // Copy payload into buffer
        self.data[offset as usize..end as usize].copy_from_slice(payload);

        // RFC 815 hole-list update
        self.update_holes(offset, end, frag.more_fragments);

        // Check for hole list exhaustion attack
        if self.holes.len() > Self::MAX_HOLES {
            return false;
        }

        self.trim_holes();

        true
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
    fn reassemble(&self) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }

        let total = self.total_len? as usize;
        let nh = self.next_header?;
        let unfrag = self.unfragmentable_part.as_ref()?;

        // Check if reassembled length fits in IPv6 Payload Length field (16 bits)
        // RFC 8200: Payload Length excludes the 40-byte fixed header.
        if (unfrag.len() + total).saturating_sub(40) > 65535 {
            log::warn!("[NET-IPV6] Reassembled packet too large for u16 Payload Length: {} bytes (Jumbo Payloads not supported)", unfrag.len() + total);
            return None;
        }

        // Build result: unfragmentable part + full payload
        let mut packet = Vec::with_capacity(unfrag.len() + total);
        packet.extend_from_slice(unfrag);
        packet.extend_from_slice(&self.data[..total]);

        // Patch the Next Header field.
        //
        // The unfragmentable part's last Next Header byte currently says "Fragment (44)".
        // We need to replace that with the actual next header from the fragment header.
        if unfrag.len() >= 40 {
            // Walk the extension header chain in the unfragmentable part
            let mut pos = 6; // Next Header offset in IPv6 fixed header
            let mut nh_value = unfrag[pos];

            // If the fixed header's Next Header is already 44, just patch it
            if nh_value == super::EXT_HEADER_FRAGMENT {
                if pos < packet.len() {
                    packet[pos] = nh;
                }
            } else {
                // Walk extension headers inside unfragmentable part
                let mut ext_offset = 40usize;
                // Security: limit iterations to prevent infinite loop on malformed headers
                for _ in 0..16 {
                    if ext_offset + 2 > unfrag.len() {
                        break;
                    }
                    
                    // Previous extension header's Next Header field is at 'pos'
                    // We need to update nh_value to the CURRENT extension header's Next Header
                    nh_value = unfrag[ext_offset];
                    
                    if nh_value == super::EXT_HEADER_FRAGMENT {
                        if ext_offset < packet.len() {
                            packet[ext_offset] = nh;
                        }
                        break;
                    }
                    
                    let ext_len = (unfrag[ext_offset + 1] as usize + 1) * 8;
                    if ext_len == 0 { break; } 
                    
                    ext_offset += ext_len;
                    if ext_offset >= unfrag.len() {
                        break;
                    }
                }
            }

            // Update Payload Length in the IPv6 header
            if packet.len() >= 6 {
                let payload_len = (packet.len().saturating_sub(40)) as u16;
                packet[4] = (payload_len >> 8) as u8;
                packet[5] = (payload_len & 0xff) as u8;
            }
        }

        Some(packet)
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
#[derive(Debug, Default, Clone)]
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

    /// Process an incoming IPv6 packet that contains a fragment header.
    ///
    /// - `unfragmentable`: the part of the original packet before the fragment header
    ///   (IPv6 fixed header + any pre-fragment extension headers).
    /// - `frag`: the parsed fragment header.
    /// - `payload`: the fragment payload (data after the fragment header).
    /// - `src`, `dst`: source and destination addresses (from the IPv6 fixed header).
    /// - `current_time`: monotonic timestamp in milliseconds.
    ///
    /// Returns `Some(reassembled_packet)` when the last fragment completes the datagram.
    pub fn process_fragment(
        &mut self,
        src: Ipv6Address,
        dst: Ipv6Address,
        unfragmentable: &[u8],
        frag: &Ipv6FragmentHeader,
        payload: &[u8],
        current_time: u64,
    ) -> Option<Vec<u8>> {
        self.stats.fragments_received += 1;

        let key = Ipv6FragmentKey::new(src, dst, frag.identification);

        // Lazy eviction of expired buffers
        self.evict_expired(current_time);

        // Ensure we have a buffer for this key
        if !self.buffers.contains_key(&key) {
            if self.buffers.len() >= self.max_buffers {
                self.stats.dropped_limit += 1;
                return None;
            }
            self.buffers.insert(key, Ipv6FragmentBuffer::new(current_time));
        }

        let buffer = self.buffers.get_mut(&key)?;

        if !buffer.add_fragment(unfragmentable, frag, payload) {
            self.stats.dropped_invalid += 1;
            self.buffers.remove(&key);
            return None;
        }

        if buffer.is_complete() {
            let result = buffer.reassemble();
            self.buffers.remove(&key);
            if result.is_some() {
                self.stats.reassembled += 1;
            }
            return result;
        }

        None
    }

    /// Evict expired reassembly buffers
    fn evict_expired(&mut self, current_time: u64) {
        let expired: Vec<_> = self
            .buffers
            .iter()
            .filter(|(_, buf)| buf.is_expired(current_time))
            .map(|(k, _)| *k)
            .collect();

        for key in expired {
            self.buffers.remove(&key);
            self.stats.timeouts += 1;
        }
    }

    /// Number of active reassembly buffers
    pub fn active_buffers(&self) -> usize {
        self.buffers.len()
    }
}
