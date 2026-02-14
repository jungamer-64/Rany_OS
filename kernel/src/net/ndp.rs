// ============================================================================
// kernel/src/net/ndp.rs
// ============================================================================
//! Neighbor Discovery Protocol (NDP) for IPv6
//!
//! RFC 4861 compliant implementation.
//!
//! ## Features
//! - Neighbor Cache (replaces ARP for IPv6)
//! - Neighbor Solicitation / Neighbor Advertisement
//! - Router Solicitation (sending only)
//! - NDP option parsing (Source/Target Link-Layer Address, Prefix Info, MTU)

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::icmpv6::{Icmpv6Type, ICMPV6_HEADER_SIZE};
use super::ipv4::{IpProtocol, data_checksum};
use super::ipv6::{Ipv6Address, ipv6_pseudo_header_checksum};

// =====================================================
// NDP Constants
// =====================================================

/// Minimum Neighbor Solicitation size: ICMPv6 header (4) + reserved (4) + target (16) = 24
pub const NS_MIN_SIZE: usize = 24;

/// Minimum Neighbor Advertisement size: same as NS
pub const NA_MIN_SIZE: usize = 24;

/// Minimum Router Solicitation size: ICMPv6 header (4) + reserved (4) = 8
pub const RS_MIN_SIZE: usize = 8;

/// Reachable timeout (30 seconds default, RFC 4861 Section 6.3.2)
pub const REACHABLE_TIME_MS: u64 = 30_000;

/// Stale entry expiration (10 minutes)
pub const STALE_TIMEOUT_MS: u64 = 600_000;

/// Maximum entries in neighbor cache
pub const MAX_NEIGHBOR_ENTRIES: usize = 128;

// =====================================================
// NDP Option Types
// =====================================================

/// NDP option type codes (RFC 4861 Section 4.6)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NdpOptionType {
    /// Source Link-Layer Address
    SourceLinkLayerAddress = 1,
    /// Target Link-Layer Address
    TargetLinkLayerAddress = 2,
    /// Prefix Information
    PrefixInformation = 3,
    /// Redirected Header
    RedirectedHeader = 4,
    /// MTU
    Mtu = 5,
    /// Unknown option
    Unknown(u8),
}

impl From<u8> for NdpOptionType {
    fn from(value: u8) -> Self {
        match value {
            1 => NdpOptionType::SourceLinkLayerAddress,
            2 => NdpOptionType::TargetLinkLayerAddress,
            3 => NdpOptionType::PrefixInformation,
            4 => NdpOptionType::RedirectedHeader,
            5 => NdpOptionType::Mtu,
            other => NdpOptionType::Unknown(other),
        }
    }
}

// =====================================================
// NDP Option Parser
// =====================================================

/// Parsed NDP option
#[derive(Debug, Clone)]
pub enum NdpOption {
    /// Source/Target Link-Layer Address (6-byte MAC)
    LinkLayerAddress {
        option_type: NdpOptionType,
        mac: [u8; 6],
    },
    /// Prefix Information
    PrefixInfo {
        prefix_len: u8,
        on_link: bool,
        autonomous: bool,
        valid_lifetime: u32,
        preferred_lifetime: u32,
        prefix: Ipv6Address,
    },
    /// MTU option
    Mtu(u32),
}

/// Parse NDP options from the data following the fixed NDP message fields
pub fn parse_ndp_options(data: &[u8]) -> Vec<NdpOption> {
    let mut options = Vec::new();
    let mut offset = 0;

    while offset + 2 <= data.len() {
        let opt_type = NdpOptionType::from(data[offset]);
        let opt_len_units = data[offset + 1] as usize;

        // Length 0 is invalid — prevent infinite loop
        if opt_len_units == 0 {
            break;
        }

        let opt_len = opt_len_units * 8; // in bytes
        if offset + opt_len > data.len() {
            break;
        }

        let opt_data = &data[offset..offset + opt_len];

        match opt_type {
            NdpOptionType::SourceLinkLayerAddress | NdpOptionType::TargetLinkLayerAddress => {
                if opt_len >= 8 {
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(&opt_data[2..8]);
                    options.push(NdpOption::LinkLayerAddress {
                        option_type: opt_type,
                        mac,
                    });
                }
            }
            NdpOptionType::PrefixInformation => {
                if opt_len >= 32 {
                    let prefix_len = opt_data[2];
                    let flags = opt_data[3];
                    let on_link = (flags & 0x80) != 0;
                    let autonomous = (flags & 0x40) != 0;
                    let valid_lifetime = u32::from_be_bytes([
                        opt_data[4], opt_data[5], opt_data[6], opt_data[7],
                    ]);
                    let preferred_lifetime = u32::from_be_bytes([
                        opt_data[8], opt_data[9], opt_data[10], opt_data[11],
                    ]);
                    // Bytes 12-15: reserved
                    let mut prefix_bytes = [0u8; 16];
                    prefix_bytes.copy_from_slice(&opt_data[16..32]);
                    options.push(NdpOption::PrefixInfo {
                        prefix_len,
                        on_link,
                        autonomous,
                        valid_lifetime,
                        preferred_lifetime,
                        prefix: Ipv6Address::new(prefix_bytes),
                    });
                }
            }
            NdpOptionType::Mtu => {
                if opt_len >= 8 {
                    // Bytes 2-3: reserved
                    let mtu = u32::from_be_bytes([
                        opt_data[4], opt_data[5], opt_data[6], opt_data[7],
                    ]);
                    options.push(NdpOption::Mtu(mtu));
                }
            }
            _ => {
                // Skip unknown options
            }
        }

        offset += opt_len;
    }

    options
}

// =====================================================
// Neighbor State Machine
// =====================================================

/// Neighbor Cache entry state (RFC 4861 Section 7.3.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighborState {
    /// Address resolution in progress, MAC unknown
    Incomplete,
    /// Recently confirmed reachable
    Reachable,
    /// Reachability timer expired, but still usable
    Stale,
    /// Waiting before probing (traffic sent to neighbor)
    Delay,
    /// Actively probing (NS sent, waiting for NA)
    Probe,
}

/// Neighbor Cache entry
#[derive(Debug, Clone)]
pub struct NeighborEntry {
    /// IPv6 address
    pub ip: Ipv6Address,
    /// Link-layer (MAC) address
    pub mac: [u8; 6],
    /// Current NUD state
    pub state: NeighborState,
    /// Timestamp of last state change (milliseconds)
    pub timestamp: u64,
    /// Number of probes sent (for Incomplete/Probe states)
    pub probes_sent: u8,
}

impl NeighborEntry {
    /// Create a new entry in Incomplete state
    pub fn new_incomplete(ip: Ipv6Address, timestamp: u64) -> Self {
        Self {
            ip,
            mac: [0; 6],
            state: NeighborState::Incomplete,
            timestamp,
            probes_sent: 0,
        }
    }

    /// Create a new entry in Reachable state
    pub fn new_reachable(ip: Ipv6Address, mac: [u8; 6], timestamp: u64) -> Self {
        Self {
            ip,
            mac,
            state: NeighborState::Reachable,
            timestamp,
            probes_sent: 0,
        }
    }

    /// Check if this entry has a valid MAC address
    pub fn has_mac(&self) -> bool {
        self.state != NeighborState::Incomplete
    }
}

// =====================================================
// Neighbor Cache
// =====================================================

/// IPv6 Neighbor Cache (replaces ARP cache for IPv6)
pub struct NeighborCache {
    entries: BTreeMap<[u8; 16], NeighborEntry>,
}

impl NeighborCache {
    /// Create a new empty cache
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Lookup a neighbor by IPv6 address
    pub fn lookup(&self, ip: &Ipv6Address) -> Option<&NeighborEntry> {
        self.entries.get(ip.as_bytes())
    }

    /// Lookup a neighbor (mutable)
    pub fn lookup_mut(&mut self, ip: &Ipv6Address) -> Option<&mut NeighborEntry> {
        self.entries.get_mut(ip.as_bytes())
    }

    /// Insert or update an entry
    pub fn insert(&mut self, entry: NeighborEntry) {
        // Enforce max entries by removing oldest stale entry if needed
        if self.entries.len() >= MAX_NEIGHBOR_ENTRIES && !self.entries.contains_key(entry.ip.as_bytes()) {
            self.evict_one();
        }
        self.entries.insert(*entry.ip.as_bytes(), entry);
    }

    /// Remove an entry
    pub fn remove(&mut self, ip: &Ipv6Address) -> Option<NeighborEntry> {
        self.entries.remove(ip.as_bytes())
    }

    /// Update a neighbor's MAC address and set Reachable
    pub fn update_reachable(&mut self, ip: &Ipv6Address, mac: [u8; 6], timestamp: u64) {
        if let Some(entry) = self.entries.get_mut(ip.as_bytes()) {
            entry.mac = mac;
            entry.state = NeighborState::Reachable;
            entry.timestamp = timestamp;
            entry.probes_sent = 0;
        } else {
            self.insert(NeighborEntry::new_reachable(*ip, mac, timestamp));
        }
    }

    /// Transition Reachable entries to Stale after timeout
    pub fn expire_reachable(&mut self, current_time: u64) {
        for entry in self.entries.values_mut() {
            if entry.state == NeighborState::Reachable
                && current_time.saturating_sub(entry.timestamp) > REACHABLE_TIME_MS
            {
                entry.state = NeighborState::Stale;
            }
        }
    }

    /// Remove expired stale entries
    pub fn expire_old(&mut self, current_time: u64) {
        self.entries.retain(|_, entry| {
            if entry.state == NeighborState::Stale
                && current_time.saturating_sub(entry.timestamp) > STALE_TIMEOUT_MS
            {
                return false;
            }
            true
        });
    }

    /// Get number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all entries
    pub fn iter(&self) -> impl Iterator<Item = &NeighborEntry> {
        self.entries.values()
    }

    /// Evict one entry (prefer Stale, then oldest)
    fn evict_one(&mut self) {
        // Find a stale entry to evict
        let stale_key = self.entries.iter()
            .find(|(_, e)| e.state == NeighborState::Stale)
            .map(|(k, _)| *k);

        if let Some(key) = stale_key {
            self.entries.remove(&key);
            return;
        }

        // No stale entries — remove the first (oldest by BTreeMap key order)
        if let Some(key) = self.entries.keys().next().copied() {
            self.entries.remove(&key);
        }
    }
}

impl Default for NeighborCache {
    fn default() -> Self {
        Self::new()
    }
}

// =====================================================
// NDP Processor
// =====================================================

/// NDP processing result
#[derive(Debug)]
pub enum NdpResult {
    /// Send a Neighbor Advertisement in reply to NS
    SendNeighborAdvertisement {
        dst: Ipv6Address,
        target: Ipv6Address,
        our_mac: [u8; 6],
        solicited: bool,
    },
    /// Neighbor info learned (from NA or NS source)
    NeighborUpdated {
        ip: Ipv6Address,
        mac: [u8; 6],
    },
    /// Router Advertisement received (prefix/gateway info)
    RouterAdvertisement {
        router: Ipv6Address,
        router_mac: Option<[u8; 6]>,
        prefixes: Vec<NdpOption>,
    },
    /// Nothing to do
    None,
    /// Processing error
    Error,
}

/// NDP message processor
pub struct NdpProcessor {
    /// Neighbor cache
    cache: NeighborCache,
    /// Our link-local address
    our_link_local: Ipv6Address,
    /// Our MAC address
    our_mac: [u8; 6],
    /// Statistics
    stats: NdpStats,
}

/// NDP statistics
#[derive(Debug, Default)]
pub struct NdpStats {
    pub ns_received: AtomicU64,
    pub na_received: AtomicU64,
    pub rs_sent: AtomicU64,
    pub ra_received: AtomicU64,
    pub ns_sent: AtomicU64,
    pub na_sent: AtomicU64,
}

impl NdpProcessor {
    /// Create a new NDP processor
    pub fn new(our_link_local: Ipv6Address, our_mac: [u8; 6]) -> Self {
        Self {
            cache: NeighborCache::new(),
            our_link_local,
            our_mac,
            stats: NdpStats::default(),
        }
    }

    /// Get neighbor cache reference
    #[inline]
    pub fn cache(&self) -> &NeighborCache {
        &self.cache
    }

    /// Get mutable neighbor cache
    #[inline]
    pub fn cache_mut(&mut self) -> &mut NeighborCache {
        &mut self.cache
    }

    /// Get stats
    #[inline]
    pub fn stats(&self) -> &NdpStats {
        &self.stats
    }

    /// Process an NDP message (already validated as ICMPv6 NDP type)
    ///
    /// `data` includes the full ICMPv6 message (type, code, checksum, ...)
    pub fn process(
        &mut self,
        msg_type: Icmpv6Type,
        data: &[u8],
        src: Ipv6Address,
        dst: Ipv6Address,
        current_time: u64,
    ) -> NdpResult {
        match msg_type {
            Icmpv6Type::NeighborSolicitation => {
                self.process_ns(data, src, dst, current_time)
            }
            Icmpv6Type::NeighborAdvertisement => {
                self.process_na(data, src, dst, current_time)
            }
            Icmpv6Type::RouterAdvertisement => {
                self.process_ra(data, src, dst, current_time)
            }
            Icmpv6Type::RouterSolicitation => {
                // We don't process RS (we're not a router)
                NdpResult::None
            }
            _ => NdpResult::None,
        }
    }

    /// Process Neighbor Solicitation
    ///
    /// NS format: type(1) + code(1) + checksum(2) + reserved(4) + target(16) [+ options]
    fn process_ns(
        &mut self,
        data: &[u8],
        src: Ipv6Address,
        dst: Ipv6Address,
        current_time: u64,
    ) -> NdpResult {
        if data.len() < NS_MIN_SIZE {
            return NdpResult::Error;
        }

        self.stats.ns_received.fetch_add(1, Ordering::Relaxed);

        // Extract target address (bytes 8-23)
        let mut target_bytes = [0u8; 16];
        target_bytes.copy_from_slice(&data[8..24]);
        let target = Ipv6Address::new(target_bytes);

        // Check if this NS is for us
        if target != self.our_link_local {
            // TODO: also check global address
            return NdpResult::None;
        }

        // Parse options to get source link-layer address
        let options = if data.len() > NS_MIN_SIZE {
            parse_ndp_options(&data[NS_MIN_SIZE..])
        } else {
            Vec::new()
        };

        // Learn sender's MAC from Source Link-Layer Address option
        for opt in &options {
            if let NdpOption::LinkLayerAddress {
                option_type: NdpOptionType::SourceLinkLayerAddress,
                mac,
            } = opt
            {
                if !src.is_unspecified() {
                    self.cache.update_reachable(&src, *mac, current_time);
                }
            }
        }

        // Respond with Neighbor Advertisement
        NdpResult::SendNeighborAdvertisement {
            dst: src,
            target,
            our_mac: self.our_mac,
            solicited: !src.is_unspecified(),
        }
    }

    /// Process Neighbor Advertisement
    ///
    /// NA format: type(1) + code(1) + checksum(2) + flags(4) + target(16) [+ options]
    fn process_na(
        &mut self,
        data: &[u8],
        src: Ipv6Address,
        _dst: Ipv6Address,
        current_time: u64,
    ) -> NdpResult {
        if data.len() < NA_MIN_SIZE {
            return NdpResult::Error;
        }

        self.stats.na_received.fetch_add(1, Ordering::Relaxed);

        // Flags: R(1) + S(1) + O(1) + reserved(29) — byte 4
        let flags = data[4];
        let _router = (flags & 0x80) != 0;
        let _solicited = (flags & 0x40) != 0;
        let override_flag = (flags & 0x20) != 0;

        // Target address (bytes 8-23)
        let mut target_bytes = [0u8; 16];
        target_bytes.copy_from_slice(&data[8..24]);
        let target = Ipv6Address::new(target_bytes);

        // Parse options for Target Link-Layer Address
        let options = if data.len() > NA_MIN_SIZE {
            parse_ndp_options(&data[NA_MIN_SIZE..])
        } else {
            Vec::new()
        };

        let mut learned_mac = None;
        for opt in &options {
            if let NdpOption::LinkLayerAddress {
                option_type: NdpOptionType::TargetLinkLayerAddress,
                mac,
            } = opt
            {
                learned_mac = Some(*mac);
            }
        }

        // Update neighbor cache
        if let Some(mac) = learned_mac {
            // If override flag is set, or entry doesn't exist, update
            if override_flag || self.cache.lookup(&target).is_none() {
                self.cache.update_reachable(&target, mac, current_time);
            }

            return NdpResult::NeighborUpdated {
                ip: target,
                mac,
            };
        }

        NdpResult::None
    }

    /// Process Router Advertisement
    ///
    /// RA provides prefix info, gateway, and hop limit
    fn process_ra(
        &mut self,
        data: &[u8],
        src: Ipv6Address,
        _dst: Ipv6Address,
        current_time: u64,
    ) -> NdpResult {
        if data.len() < 16 {
            // RA minimum: type(1) + code(1) + checksum(2) + cur_hop_limit(1) +
            // flags(1) + router_lifetime(2) + reachable_time(4) + retrans_timer(4) = 16
            return NdpResult::Error;
        }

        self.stats.ra_received.fetch_add(1, Ordering::Relaxed);

        // Parse options
        let options = if data.len() > 16 {
            parse_ndp_options(&data[16..])
        } else {
            Vec::new()
        };

        // Extract router's MAC from Source Link-Layer Address option
        let mut router_mac = None;
        let mut prefix_options = Vec::new();
        for opt in options {
            match &opt {
                NdpOption::LinkLayerAddress {
                    option_type: NdpOptionType::SourceLinkLayerAddress,
                    mac,
                } => {
                    router_mac = Some(*mac);
                    // Update neighbor cache with router's MAC
                    self.cache.update_reachable(&src, *mac, current_time);
                }
                NdpOption::PrefixInfo { .. } | NdpOption::Mtu(_) => {
                    prefix_options.push(opt);
                }
                _ => {}
            }
        }

        NdpResult::RouterAdvertisement {
            router: src,
            router_mac,
            prefixes: prefix_options,
        }
    }

    /// Build a Neighbor Solicitation message
    ///
    /// Returns the ICMPv6 payload (caller wraps in IPv6)
    pub fn build_ns(
        src: &Ipv6Address,
        dst: &Ipv6Address,
        target: &Ipv6Address,
        src_mac: &[u8; 6],
    ) -> Vec<u8> {
        // NS: type(1) + code(1) + checksum(2) + reserved(4) + target(16) + SLLA option(8) = 32
        let total_len = 32;
        let mut msg = vec![0u8; total_len];

        msg[0] = u8::from(Icmpv6Type::NeighborSolicitation);
        msg[1] = 0; // code
        // Checksum placeholder: bytes 2-3
        // Reserved: bytes 4-7 (already 0)
        // Target address: bytes 8-23
        msg[8..24].copy_from_slice(target.as_bytes());

        // Source Link-Layer Address option
        msg[24] = 1; // type = Source Link-Layer Address
        msg[25] = 1; // length = 1 (in 8-byte units)
        msg[26..32].copy_from_slice(src_mac);

        // Compute checksum
        let pseudo = ipv6_pseudo_header_checksum(src, dst, IpProtocol::Icmpv6, total_len as u32);
        let cksum = data_checksum(&msg, pseudo);
        let cksum_bytes = cksum.to_be_bytes();
        msg[2] = cksum_bytes[0];
        msg[3] = cksum_bytes[1];

        msg
    }

    /// Build a Neighbor Advertisement message
    ///
    /// Returns the ICMPv6 payload
    pub fn build_na(
        src: &Ipv6Address,
        dst: &Ipv6Address,
        target: &Ipv6Address,
        our_mac: &[u8; 6],
        solicited: bool,
    ) -> Vec<u8> {
        // NA: type(1) + code(1) + checksum(2) + flags(4) + target(16) + TLLA option(8) = 32
        let total_len = 32;
        let mut msg = vec![0u8; total_len];

        msg[0] = u8::from(Icmpv6Type::NeighborAdvertisement);
        msg[1] = 0; // code
        // Checksum placeholder: bytes 2-3

        // Flags: R=0, S=solicited, O=1 (override)
        let mut flags: u8 = 0x20; // Override
        if solicited {
            flags |= 0x40; // Solicited
        }
        msg[4] = flags;
        // bytes 5-7: rest of flags field (0)

        // Target address: bytes 8-23
        msg[8..24].copy_from_slice(target.as_bytes());

        // Target Link-Layer Address option
        msg[24] = 2; // type = Target Link-Layer Address
        msg[25] = 1; // length = 1 (in 8-byte units)
        msg[26..32].copy_from_slice(our_mac);

        // Compute checksum
        let pseudo = ipv6_pseudo_header_checksum(src, dst, IpProtocol::Icmpv6, total_len as u32);
        let cksum = data_checksum(&msg, pseudo);
        let cksum_bytes = cksum.to_be_bytes();
        msg[2] = cksum_bytes[0];
        msg[3] = cksum_bytes[1];

        msg
    }

    /// Build a Router Solicitation message
    ///
    /// Sent to ff02::2 (all-routers) to solicit Router Advertisements
    pub fn build_rs(
        src: &Ipv6Address,
        src_mac: &[u8; 6],
    ) -> Vec<u8> {
        let dst = Ipv6Address::ALL_ROUTERS_LINK_LOCAL;
        // RS: type(1) + code(1) + checksum(2) + reserved(4) + SLLA option(8) = 16
        let total_len = 16;
        let mut msg = vec![0u8; total_len];

        msg[0] = u8::from(Icmpv6Type::RouterSolicitation);
        msg[1] = 0; // code
        // bytes 2-3: checksum placeholder
        // bytes 4-7: reserved

        // Source Link-Layer Address option
        msg[8] = 1;  // type = Source Link-Layer Address
        msg[9] = 1;  // length = 1 (in 8-byte units)
        msg[10..16].copy_from_slice(src_mac);

        // Compute checksum
        let pseudo = ipv6_pseudo_header_checksum(src, &dst, IpProtocol::Icmpv6, total_len as u32);
        let cksum = data_checksum(&msg, pseudo);
        let cksum_bytes = cksum.to_be_bytes();
        msg[2] = cksum_bytes[0];
        msg[3] = cksum_bytes[1];

        msg
    }

    /// Resolve an IPv6 address to MAC address
    ///
    /// Returns Some(mac) if entry is in Reachable/Stale/Delay/Probe state,
    /// None if Incomplete or not in cache.
    pub fn resolve(&self, ip: &Ipv6Address) -> Option<[u8; 6]> {
        // Multicast addresses map directly to MAC
        if ip.is_multicast() {
            return Some(ip.multicast_mac());
        }

        // Lookup in neighbor cache
        self.cache.lookup(ip).and_then(|entry| {
            if entry.has_mac() {
                Some(entry.mac)
            } else {
                None
            }
        })
    }

    /// Start resolution for a neighbor (create Incomplete entry)
    ///
    /// Returns the NS message to send (caller sends it)
    pub fn start_resolution(
        &mut self,
        target: &Ipv6Address,
        current_time: u64,
    ) -> Vec<u8> {
        // Create incomplete entry
        self.cache.insert(NeighborEntry::new_incomplete(*target, current_time));
        self.stats.ns_sent.fetch_add(1, Ordering::Relaxed);

        // Build NS targeting the solicited-node multicast address
        let sn_mcast = target.solicited_node();
        Self::build_ns(&self.our_link_local, &sn_mcast, target, &self.our_mac)
    }

    /// Run periodic maintenance (expire entries)
    pub fn tick(&mut self, current_time: u64) {
        self.cache.expire_reachable(current_time);
        self.cache.expire_old(current_time);
    }
}

// =====================================================
// Helper: Multicast MAC conversion
// =====================================================

/// Convert IPv6 multicast address to Ethernet multicast MAC
///
/// 33:33:xx:xx:xx:xx (last 4 bytes of IPv6 multicast address)
#[inline]
pub fn ipv6_multicast_to_mac(addr: &Ipv6Address) -> [u8; 6] {
    addr.multicast_mac()
}

// =====================================================
// Tests
// =====================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_neighbor_cache_basic() {
        let mut cache = NeighborCache::new();
        let ip = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

        assert!(cache.is_empty());

        cache.insert(NeighborEntry::new_reachable(ip, mac, 1000));
        assert_eq!(cache.len(), 1);

        let entry = cache.lookup(&ip).unwrap();
        assert_eq!(entry.mac, mac);
        assert_eq!(entry.state, NeighborState::Reachable);

        cache.remove(&ip);
        assert!(cache.is_empty());
    }

    #[test_case]
    fn test_neighbor_cache_update() {
        let mut cache = NeighborCache::new();
        let ip = Ipv6Address::LOOPBACK;

        // Insert incomplete
        cache.insert(NeighborEntry::new_incomplete(ip, 100));
        assert!(!cache.lookup(&ip).unwrap().has_mac());

        // Update to reachable
        let mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        cache.update_reachable(&ip, mac, 200);
        let entry = cache.lookup(&ip).unwrap();
        assert!(entry.has_mac());
        assert_eq!(entry.mac, mac);
        assert_eq!(entry.state, NeighborState::Reachable);
    }

    #[test_case]
    fn test_neighbor_cache_expiry() {
        let mut cache = NeighborCache::new();
        let ip = Ipv6Address::LOOPBACK;
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        cache.insert(NeighborEntry::new_reachable(ip, mac, 0));
        assert_eq!(cache.lookup(&ip).unwrap().state, NeighborState::Reachable);

        // Expire after reachable timeout
        cache.expire_reachable(REACHABLE_TIME_MS + 1);
        assert_eq!(cache.lookup(&ip).unwrap().state, NeighborState::Stale);

        // Expire after stale timeout
        cache.expire_old(STALE_TIMEOUT_MS + REACHABLE_TIME_MS + 2);
        assert!(cache.is_empty());
    }

    #[test_case]
    fn test_parse_slla_option() {
        // Source Link-Layer Address: type=1, len=1 (8 bytes), mac=52:54:00:12:34:56
        let data = [1, 1, 0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let options = parse_ndp_options(&data);
        assert_eq!(options.len(), 1);
        match &options[0] {
            NdpOption::LinkLayerAddress { option_type, mac } => {
                assert_eq!(*option_type, NdpOptionType::SourceLinkLayerAddress);
                assert_eq!(*mac, [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
            }
            _ => panic!("Expected LinkLayerAddress"),
        }
    }

    #[test_case]
    fn test_parse_prefix_info_option() {
        // Prefix Information: type=3, len=4 (32 bytes)
        let mut data = [0u8; 32];
        data[0] = 3;  // type
        data[1] = 4;  // length (4 * 8 = 32 bytes)
        data[2] = 64; // prefix length
        data[3] = 0xC0; // flags: on-link + autonomous
        data[4] = 0; data[5] = 0; data[6] = 0x0E; data[7] = 0x10; // valid lifetime = 3600
        data[8] = 0; data[9] = 0; data[10] = 0x07; data[11] = 0x08; // preferred lifetime = 1800
        // bytes 12-15: reserved
        // prefix: 2001:db8:: at bytes 16-31
        data[16] = 0x20; data[17] = 0x01;
        data[18] = 0x0d; data[19] = 0xb8;

        let options = parse_ndp_options(&data);
        assert_eq!(options.len(), 1);
        match &options[0] {
            NdpOption::PrefixInfo { prefix_len, on_link, autonomous, valid_lifetime, preferred_lifetime, prefix } => {
                assert_eq!(*prefix_len, 64);
                assert!(*on_link);
                assert!(*autonomous);
                assert_eq!(*valid_lifetime, 3600);
                assert_eq!(*preferred_lifetime, 1800);
                assert_eq!(prefix.as_bytes()[0], 0x20);
                assert_eq!(prefix.as_bytes()[1], 0x01);
            }
            _ => panic!("Expected PrefixInfo"),
        }
    }

    #[test_case]
    fn test_build_ns() {
        let src = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x50, 0x54, 0x00, 0xff, 0xfe, 0x12, 0x34, 0x56]);
        let target = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let dst = target.solicited_node();
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

        let msg = NdpProcessor::build_ns(&src, &dst, &target, &mac);
        assert_eq!(msg.len(), 32);
        assert_eq!(msg[0], u8::from(Icmpv6Type::NeighborSolicitation));
        // Target at bytes 8-23
        assert_eq!(&msg[8..24], target.as_bytes());
        // SLLA option at bytes 24-31
        assert_eq!(msg[24], 1); // type
        assert_eq!(msg[25], 1); // length
        assert_eq!(&msg[26..32], &mac);

        // Verify checksum
        let pseudo = ipv6_pseudo_header_checksum(&src, &dst, IpProtocol::Icmpv6, msg.len() as u32);
        let cksum = data_checksum(&msg, pseudo);
        assert_eq!(cksum, 0);
    }

    #[test_case]
    fn test_build_na() {
        let src = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let target = src;
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

        let msg = NdpProcessor::build_na(&src, &dst, &target, &mac, true);
        assert_eq!(msg.len(), 32);
        assert_eq!(msg[0], u8::from(Icmpv6Type::NeighborAdvertisement));
        // Flags: Solicited + Override = 0x60
        assert_eq!(msg[4] & 0x60, 0x60);
        // Target at bytes 8-23
        assert_eq!(&msg[8..24], target.as_bytes());

        // Verify checksum
        let pseudo = ipv6_pseudo_header_checksum(&src, &dst, IpProtocol::Icmpv6, msg.len() as u32);
        let cksum = data_checksum(&msg, pseudo);
        assert_eq!(cksum, 0);
    }

    #[test_case]
    fn test_build_rs() {
        let src = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

        let msg = NdpProcessor::build_rs(&src, &mac);
        assert_eq!(msg.len(), 16);
        assert_eq!(msg[0], u8::from(Icmpv6Type::RouterSolicitation));

        // Verify checksum
        let dst = Ipv6Address::ALL_ROUTERS_LINK_LOCAL;
        let pseudo = ipv6_pseudo_header_checksum(&src, &dst, IpProtocol::Icmpv6, msg.len() as u32);
        let cksum = data_checksum(&msg, pseudo);
        assert_eq!(cksum, 0);
    }

    #[test_case]
    fn test_multicast_mac() {
        let addr = Ipv6Address::ALL_NODES_LINK_LOCAL;
        let mac = ipv6_multicast_to_mac(&addr);
        assert_eq!(mac, [0x33, 0x33, 0x00, 0x00, 0x00, 0x01]);
    }

    #[test_case]
    fn test_resolve_multicast() {
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let proc = NdpProcessor::new(Ipv6Address::LOOPBACK, mac);

        let mcast = Ipv6Address::ALL_NODES_LINK_LOCAL;
        let resolved = proc.resolve(&mcast).unwrap();
        assert_eq!(resolved, [0x33, 0x33, 0x00, 0x00, 0x00, 0x01]);
    }

    #[test_case]
    fn test_ns_processing() {
        let our_mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let our_ip = Ipv6Address::from_eui64(&our_mac);
        let mut proc = NdpProcessor::new(our_ip, our_mac);

        let sender_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let sender_ip = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let dst = our_ip.solicited_node();

        // Build an NS targeting our address
        let ns = NdpProcessor::build_ns(&sender_ip, &dst, &our_ip, &sender_mac);

        let result = proc.process(
            Icmpv6Type::NeighborSolicitation,
            &ns,
            sender_ip,
            dst,
            1000,
        );

        match result {
            NdpResult::SendNeighborAdvertisement { dst, target, our_mac: na_mac, solicited } => {
                assert_eq!(dst, sender_ip);
                assert_eq!(target, our_ip);
                assert_eq!(na_mac, our_mac);
                assert!(solicited);
            }
            _ => panic!("Expected SendNeighborAdvertisement"),
        }

        // Sender should be learned in our cache
        let entry = proc.cache().lookup(&sender_ip).unwrap();
        assert_eq!(entry.mac, sender_mac);
        assert_eq!(entry.state, NeighborState::Reachable);
    }
}
