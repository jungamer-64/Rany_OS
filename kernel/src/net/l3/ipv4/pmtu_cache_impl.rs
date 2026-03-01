use super::*;


impl PmtuCache {
    /// Default maximum entries
    pub const DEFAULT_MAX_ENTRIES: usize = 256;

    /// Create a new PMTU cache
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            max_entries,
            stats: PmtuStats::default(),
        }
    }

    /// Get statistics
    pub fn stats(&self) -> &PmtuStats {
        &self.stats
    }

    /// Get PMTU for a destination
    pub fn get(&mut self, dst: Ipv4Address, current_time: u64) -> u16 {
        if let Some(entry) = self.entries.get(&dst) {
            if !entry.is_expired(current_time) {
                self.stats.hits += 1;
                return entry.pmtu;
            }
        }
        self.stats.misses += 1;
        PmtuEntry::DEFAULT_MTU
    }

    /// Update PMTU for a destination (called when receiving ICMP Fragmentation Needed)
    pub fn update(&mut self, dst: Ipv4Address, new_mtu: u16, current_time: u64) {
        let clamped_mtu = new_mtu.clamp(PmtuEntry::MIN_MTU, PmtuEntry::MAX_MTU);

        if let Some(entry) = self.entries.get_mut(&dst) {
            if clamped_mtu < entry.pmtu {
                entry.pmtu = clamped_mtu;
                entry.updated_at = current_time;
                entry.next_probe = current_time + PmtuEntry::TIMEOUT_MS;
                self.stats.reductions += 1;
            }
        } else {
            // Evict oldest entry if at capacity
            if self.entries.len() >= self.max_entries {
                self.evict_oldest();
            }
            self.entries.insert(dst, PmtuEntry::new(clamped_mtu, current_time));
            self.stats.discoveries += 1;
        }
    }

    /// Probe for a larger MTU (called periodically)
    pub fn probe(&mut self, dst: Ipv4Address, current_time: u64) -> Option<u16> {
        if let Some(entry) = self.entries.get_mut(&dst) {
            if entry.should_probe(current_time) {
                // Try a larger MTU
                let probe_mtu = (entry.pmtu as u32 + 100).min(PmtuEntry::DEFAULT_MTU as u32) as u16;
                entry.next_probe = current_time + PmtuEntry::TIMEOUT_MS / 2;
                return Some(probe_mtu);
            }
        }
        None
    }

    /// Evict the oldest entry
    pub(super) fn evict_oldest(&mut self) {
        let oldest = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.updated_at)
            .map(|(k, _)| *k);
        if let Some(key) = oldest {
            self.entries.remove(&key);
        }
    }

    /// Evict expired entries
    pub fn evict_expired(&mut self, current_time: u64) {
        let expired: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, e)| e.is_expired(current_time))
            .map(|(k, _)| *k)
            .collect();
        for key in expired {
            self.entries.remove(&key);
        }
    }

    /// Get the number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

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
pub struct FragmentBuffer {
    /// Reassembled data buffer
    data: Vec<u8>,
    /// List of holes (unfilled regions)
    holes: Vec<FragmentHole>,
    /// Total datagram length (known when last fragment received)
    total_len: Option<u16>,
    /// First fragment's full header (including options, up to 60 bytes)
    first_header: Option<Vec<u8>>,
    /// Creation timestamp (for timeout)
    created_at: u64,
    /// Last update timestamp
    last_update: u64,
}

impl FragmentBuffer {
    /// Maximum reassembled packet size (64KB - IP header)
    /// RFC 791 defines the maximum IP packet size as 65535 bytes.
    /// Since the header is at least 20 bytes, the max payload is 65515.
    pub const MAX_DATAGRAM_SIZE: usize = 65515;

    /// Maximum number of holes allowed in the reassembly buffer
    pub const MAX_HOLES: usize = 64;

    /// Fragment timeout in milliseconds (RFC 791 recommends 15-60 seconds)
    pub const TIMEOUT_MS: u64 = 30_000;

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
            created_at: timestamp,
            last_update: timestamp,
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

        // Security: Check for consistent total length (RFC 791)
        if !header.more_fragments() {
            if let Some(existing_total) = self.total_len {
                if existing_total != fragment_end {
                    log::warn!("[NET-IPV4] Inconsistent total length in fragments: expected {}, got {}", existing_total, fragment_end);
                    return false;
                }
            }
            self.total_len = Some(fragment_end);
        } else if let Some(total) = self.total_len {
            if fragment_end > total {
                log::warn!("[NET-IPV4] Fragment beyond end of datagram: {} > {}", fragment_end, total);
                return false;
            }
        }

        // Note: first header storage is now handled in process_fragment for consistency

        // Ensure buffer is large enough
        if self.data.len() < fragment_end as usize {
            self.data.resize(fragment_end as usize, 0);
        }

        // Security: Check for inconsistent overlaps (RFC 1858 / RFC 3128)
        // If this fragment overlaps with data we already have, it MUST be identical.
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

        if covered_hole_bytes < fragment_len as u32 {
            // Potential overlap with existing data. Check consistency.
            // We only need to check bytes that are NOT in holes.
            for i in 0..fragment_len as usize {
                let pos = fragment_offset as usize + i;
                let is_in_hole = self.holes.iter().any(|h| pos >= h.first as usize && pos < h.last as usize);
                if !is_in_hole {
                    if pos < self.data.len() && self.data[pos] != payload[i] {
                        log::warn!("[NET-IPV4] Inconsistent fragment overlap at offset {}", pos);
                        return false;
                    }
                }
            }
        }

        // Copy fragment data
        self.data[fragment_offset as usize..fragment_end as usize].copy_from_slice(payload);

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
    pub(super) fn store_first_header_if_needed(&mut self, header_data: &[u8], fragment_offset: u16) {
        if fragment_offset == 0 && self.first_header.is_none() {
            self.first_header = Some(header_data.to_vec());
        }
    }

    /// RFC 815 hole-list update with a fragment range
    pub(super) fn update_holes(&mut self, fragment_offset: u16, fragment_end: u16, more_fragments: bool) {
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
    pub fn get_reassembled(&self) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }

        let total_len = self.total_len? as usize;
        let header_data = self.first_header.as_ref()?;
        let header_len = header_data.len();

        // Check if reassembled length fits in IPv4 Total Length field (16 bits)
        if header_len + total_len > 65535 {
            log::warn!("[NET-IPV4] Reassembled packet too large for u16 Total Length: {} bytes", header_len + total_len);
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
    /// Returns Some(reassembled_packet) if reassembly is complete
    /// Process an incoming IPv4 fragment
    pub fn process_fragment(
        &mut self,
        header: &Ipv4Header,
        header_data: &[u8],
        payload: &[u8],
        current_time: u64,
    ) -> Option<Vec<u8>> {
        self.stats.fragments_received += 1;

        let key = FragmentKey::from_header(header);

        // Evict expired buffers
        self.evict_expired(current_time);

        // Check if we need to create a new buffer
        if !self.buffers.contains_key(&key) {
            // Check buffer limit
            if self.buffers.len() >= self.max_buffers {
                // Evict the oldest buffer to prevent Reassembly Buffer Exhaustion DoS
                let oldest = self.buffers.iter()
                    .min_by_key(|(_, buf)| buf.created_at)
                    .map(|(&k, _)| k);
                if let Some(oldest_key) = oldest {
                    self.buffers.remove(&oldest_key);
                } else {
                    self.stats.dropped_limit += 1;
                    return None;
                }
            }

            self.buffers.insert(key, FragmentBuffer::new(current_time));
        }

        // Get the buffer and add fragment
        let buffer = self.buffers.get_mut(&key)?;

        // Capture first header for reassembly
        buffer.store_first_header_if_needed(header_data, header.fragment_offset());

        if !buffer.add_fragment(header, payload, current_time) {
            self.stats.dropped_invalid += 1;
            // Remove invalid buffer
            self.buffers.remove(&key);
            return None;
        }

        // Check if reassembly is complete
        if buffer.is_complete() {
            let result = buffer.get_reassembled();
            self.buffers.remove(&key);

            if result.is_some() {
                self.stats.reassembled += 1;
            }

            return result;
        }

        None
    }

    /// Evict expired reassembly buffers
    pub(super) fn evict_expired(&mut self, current_time: u64) {
        let expired_keys: Vec<_> = self
            .buffers
            .iter()
            .filter(|(_, buf)| buf.is_expired(current_time))
            .map(|(k, _)| *k)
            .collect();

        for key in expired_keys {
            self.buffers.remove(&key);
            self.stats.timeouts += 1;
        }
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

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// IPv4 packet processor
pub struct Ipv4Processor {
    /// Configuration
    config: Ipv4Config,
    /// Statistics
    stats: Ipv4Stats,
    /// Internal ID counter
    next_id: u16,
    /// ID generation secret (per-boot)
    id_secret: u16,
    /// Fragment reassembler
    reassembler: FragmentReassembler,
    /// Path MTU Discovery cache
    pmtu_cache: PmtuCache,
}

/// IPv4 statistics
#[derive(Debug, Default)]
pub struct Ipv4Stats {
    /// Packets received
    pub rx_packets: u64,
    /// Packets transmitted
    pub tx_packets: u64,
    /// Invalid packets
    pub rx_errors: u64,
    /// Dropped packets (not for us)
    pub rx_dropped: u64,
    /// Checksum errors
    pub checksum_errors: u64,
}

/// Result of IPv4 packet processing
pub enum Ipv4ProcessResult<'a> {
    /// ICMP packet with source address, destination address, and TTL
    Icmp(&'a [u8], Ipv4Address, Ipv4Address, u8),
    /// IGMP packet with source address and TTL
    Igmp(&'a [u8], Ipv4Address, u8),
    /// TCP packet
    Tcp(&'a [u8], Ipv4Address, Ipv4Address),
    /// UDP packet
    Udp(&'a [u8], Ipv4Address, Ipv4Address),
    /// Reassembled packet (owned data from fragment reassembly)
    Reassembled(Vec<u8>),
    /// Fragment received, reassembly in progress
    FragmentPending,
    /// Dropped
    Dropped,
    /// Error
    Error,
    /// Success (Consumed internally)
    Success,
}

impl Ipv4Processor {
    /// Create a new IPv4 processor
    pub fn new(config: Ipv4Config) -> Self {
        // Use cryptographically secure random for initial ID and secret
        let random_bytes = crate::net::security::tls::generate_random();
        let id_init = u16::from_be_bytes([random_bytes[0], random_bytes[1]]);
        let secret = u16::from_be_bytes([random_bytes[2], random_bytes[3]]);

        Ipv4Processor {
            config,
            stats: Ipv4Stats::default(),
            next_id: id_init,
            id_secret: secret,
            reassembler: FragmentReassembler::new(FragmentReassembler::DEFAULT_MAX_BUFFERS),
            pmtu_cache: PmtuCache::new(PmtuCache::DEFAULT_MAX_ENTRIES),
        }
    }

    /// Get configuration
    pub fn config(&self) -> &Ipv4Config {
        &self.config
    }

    /// Set configuration
    pub fn set_config(&mut self, config: Ipv4Config) {
        self.config = config;
    }

    /// Get statistics
    pub fn stats(&self) -> &Ipv4Stats {
        &self.stats
    }

    /// Get fragment reassembler statistics
    pub fn fragment_stats(&self) -> &FragmentStats {
        self.reassembler.stats()
    }

    /// Get PMTU cache statistics
    pub fn pmtu_stats(&self) -> &PmtuStats {
        self.pmtu_cache.stats()
    }

    /// Get Path MTU for a destination
    pub fn get_pmtu(&mut self, dst: Ipv4Address, current_time: u64) -> u16 {
        self.pmtu_cache.get(dst, current_time)
    }

    /// Update Path MTU (called when receiving ICMP Fragmentation Needed)
    pub fn update_pmtu(&mut self, dst: Ipv4Address, mtu: u16, current_time: u64) {
        self.pmtu_cache.update(dst, mtu, current_time);
    }

    /// Process an incoming IPv4 packet (without timestamp - for backwards compatibility)
    pub fn process<'a>(&mut self, data: &'a [u8]) -> Ipv4ProcessResult<'a> {
        // Use a default timestamp of 0 when not provided
        self.process_with_time(data, 0)
    }

    /// Process an incoming IPv4 packet with timestamp for fragment timeout handling
    pub fn process_with_time<'a>(&mut self, data: &'a [u8], current_time: u64) -> Ipv4ProcessResult<'a> {
        let packet = match Ipv4Packet::parse(data) {
            Some(p) => p,
            None => {
                self.stats.rx_errors += 1;
                return Ipv4ProcessResult::Error;
            }
        };

        // Verify checksum
        if !packet.verify_checksum() {
            self.stats.checksum_errors += 1;
            return Ipv4ProcessResult::Error;
        }

        // Check destination
        let dst = packet.destination();
        if !self.is_for_us(&dst) {
            self.stats.rx_dropped += 1;
            return Ipv4ProcessResult::Dropped;
        }

        self.stats.rx_packets += 1;

        let src = packet.source();
        
        // Security: Prevent Source IP spoofing (Martian packets)
        if src.is_broadcast() || src.is_multicast() || (src.is_loopback() && !self.config.address.is_loopback()) {
            self.stats.rx_dropped += 1;
            return Ipv4ProcessResult::Dropped;
        }

        let header = packet.header();

        // Check if this is a fragment
        let is_fragment = header.more_fragments() || header.fragment_offset() != 0;

        if is_fragment {
            // Handle fragmented packet
            let header_len = header.header_len();
            let header_data = &data[..header_len];
            let payload = packet.payload();
            if let Some(reassembled) = self.reassembler.process_fragment(header, header_data, payload, current_time) {
                // Reassembly complete - return the reassembled packet
                return Ipv4ProcessResult::Reassembled(reassembled);
            } else {
                // Still waiting for more fragments
                return Ipv4ProcessResult::FragmentPending;
            }
        }

        // Non-fragmented packet - process normally
        let payload = packet.payload();

        match packet.protocol() {
            IpProtocol::Icmp => Ipv4ProcessResult::Icmp(payload, src, dst, packet.ttl()),
            IpProtocol::Igmp => Ipv4ProcessResult::Igmp(payload, src, packet.ttl()),
            IpProtocol::Tcp => Ipv4ProcessResult::Tcp(payload, src, dst),
            IpProtocol::Udp => Ipv4ProcessResult::Udp(payload, src, dst),
            _ => Ipv4ProcessResult::Dropped,
        }
    }

    /// Check if a packet is for us
    pub(super) fn is_for_us(&self, addr: &Ipv4Address) -> bool {
        *addr == self.config.address
            || addr.is_broadcast()
            || *addr == self.config.broadcast_address()
    }

    /// Get next packet ID (unpredictable per-destination to prevent Idle Scan)
    pub fn next_id(&mut self, dst: Ipv4Address) -> u16 {
        // Increment global counter
        self.next_id = self.next_id.wrapping_add(1);
        
        // Compute per-destination scrambling using FNV-1a of (dst, secret)
        let mut hash: u32 = 0x811c9dc5;
        const FNV_PRIME: u32 = 0x01000193;
        
        for &byte in &dst.octets() {
            hash ^= byte as u32;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        for byte in self.id_secret.to_le_bytes() {
            hash ^= byte as u32;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        
        // Mix the global counter with the per-destination hash
        let scramble = (hash ^ (hash >> 16)) as u16;
        self.next_id.wrapping_add(scramble)
    }

    /// Build an IP packet for transmission
    pub fn build_packet<'a>(
        &mut self,
        buffer: &'a mut [u8],
        dst: Ipv4Address,
        protocol: IpProtocol,
    ) -> Option<Ipv4PacketMut<'a>> {
        let mut packet = Ipv4PacketMut::new(buffer)?;
        packet
            .init_header()
            .set_source(self.config.address)
            .set_destination(dst)
            .set_protocol(protocol)
            .set_identification(self.next_id(dst));
        Some(packet)
    }
}

/// Calculate IP pseudo-header checksum (for TCP/UDP)
pub fn pseudo_header_checksum(
    src: Ipv4Address,
    dst: Ipv4Address,
    protocol: IpProtocol,
    length: u16,
) -> u32 {
    let mut sum: u32 = 0;

    // Source address
    let src_bytes = src.as_bytes();
    sum += u16::from_be_bytes([src_bytes[0], src_bytes[1]]) as u32;
    sum += u16::from_be_bytes([src_bytes[2], src_bytes[3]]) as u32;

    // Destination address
    let dst_bytes = dst.as_bytes();
    sum += u16::from_be_bytes([dst_bytes[0], dst_bytes[1]]) as u32;
    sum += u16::from_be_bytes([dst_bytes[2], dst_bytes[3]]) as u32;

    // Protocol (zero-padded to 16 bits)
    sum += u8::from(protocol) as u32;

    // Length
    sum += length as u32;

    sum
}

/// Calculate checksum for a data buffer
pub fn data_checksum(data: &[u8], initial: u32) -> u16 {
    let mut sum = initial;

    // Sum 16-bit words
    for i in (0..data.len()).step_by(2) {
        let word = if i + 1 < data.len() {
            u16::from_be_bytes([data[i], data[i + 1]])
        } else {
            u16::from_be_bytes([data[i], 0])
        };
        sum += word as u32;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

