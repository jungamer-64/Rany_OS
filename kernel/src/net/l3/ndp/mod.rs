// ============================================================================
// kernel/src/net/l3/ndp/mod.rs
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


use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::icmpv6::Icmpv6Type;
use super::ipv4::{IpProtocol, data_checksum};
use super::ipv6::{Ipv6Address, ipv6_pseudo_header_checksum};

// =====================================================
// NDP Constants
// =====================================================

/// Minimum Neighbor Solicitation size: ICMPv6 header (4) + reserved (4) + target (16) = 24
pub(crate) mod processor_impl;
#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests;
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

/// Delay before first probe when Stale→Delay (RFC 4861 Section 7.3.3)
pub const DELAY_FIRST_PROBE_TIME_MS: u64 = 5_000;

/// Maximum unicast solicitations before declaring unreachable (RFC 4861)
pub const MAX_UNICAST_SOLICIT: u8 = 3;

/// Retransmit interval for unicast NS in Probe state (ms, RFC 4861)
pub const RETRANS_TIMER_MS: u64 = 1_000;

/// Maximum multicast solicitations for incomplete resolution (RFC 4861)
pub const MAX_MULTICAST_SOLICIT: u8 = 3;

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
    /// Recursive DNS Server (RFC 8106)
    RecursiveDnsServer = 25,
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
            25 => NdpOptionType::RecursiveDnsServer,
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
    /// Recursive DNS Server (RDNSS)
    RecursiveDnsServer {
        lifetime: u32,
        servers: Vec<Ipv6Address>,
    },
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
            NdpOptionType::RecursiveDnsServer => {
                if opt_len >= 24 {
                    // RFC 8106: Type(1), Length(1), Reserved(2), Lifetime(4), Addresses(Nx16)
                    let lifetime = u32::from_be_bytes([
                        opt_data[4], opt_data[5], opt_data[6], opt_data[7],
                    ]);
                    let mut servers = Vec::new();
                    let mut addr_offset = 8;
                    while addr_offset + 16 <= opt_len {
                        let mut addr_bytes = [0u8; 16];
                        addr_bytes.copy_from_slice(&opt_data[addr_offset..addr_offset + 16]);
                        servers.push(Ipv6Address::new(addr_bytes));
                        addr_offset += 16;
                    }
                    options.push(NdpOption::RecursiveDnsServer {
                        lifetime,
                        servers,
                    });
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

    /// Trigger NUD: Stale → Delay when traffic is sent to a Stale neighbor
    /// (RFC 4861 Section 7.3.3)
    /// Returns true if the entry exists and can be used (has a valid MAC)
    pub fn trigger_delay(&mut self, ip: &Ipv6Address, current_time: u64) -> bool {
        if let Some(entry) = self.entries.get_mut(ip.as_bytes()) {
            if entry.state == NeighborState::Stale {
                entry.state = NeighborState::Delay;
                entry.timestamp = current_time;
                entry.probes_sent = 0;
            }
            entry.has_mac()
        } else {
            false
        }
    }

    /// Process NUD timers — advances Delay→Probe, Probe retries, and
    /// removes entries that exceeded MAX_UNICAST_SOLICIT.
    /// Returns a list of IPv6 addresses that need a unicast NS probe.
    pub fn process_nud_timers(&mut self, current_time: u64) -> Vec<Ipv6Address> {
        let mut probe_targets = Vec::new();
        let mut dead_keys = Vec::new();

        for (key, entry) in self.entries.iter_mut() {
            match entry.state {
                NeighborState::Delay => {
                    // After DELAY_FIRST_PROBE_TIME, transition to Probe
                    if current_time.saturating_sub(entry.timestamp) >= DELAY_FIRST_PROBE_TIME_MS {
                        entry.state = NeighborState::Probe;
                        entry.timestamp = current_time;
                        entry.probes_sent = 1;
                        probe_targets.push(entry.ip);
                    }
                }
                NeighborState::Probe => {
                    // Retransmit NS at RETRANS_TIMER_MS intervals
                    if current_time.saturating_sub(entry.timestamp) >= RETRANS_TIMER_MS {
                        if entry.probes_sent >= MAX_UNICAST_SOLICIT {
                            // Unreachable — schedule removal
                            dead_keys.push(*key);
                        } else {
                            entry.probes_sent += 1;
                            entry.timestamp = current_time;
                            probe_targets.push(entry.ip);
                        }
                    }
                }
                NeighborState::Incomplete => {
                    // Timeout for multicast solicitation
                    if current_time.saturating_sub(entry.timestamp) >= RETRANS_TIMER_MS {
                        if entry.probes_sent >= MAX_MULTICAST_SOLICIT {
                            dead_keys.push(*key);
                        } else {
                            entry.probes_sent += 1;
                            entry.timestamp = current_time;
                            probe_targets.push(entry.ip);
                        }
                    }
                }
                _ => {}
            }
        }

        // Remove unreachable entries
        for key in dead_keys {
            self.entries.remove(&key);
        }

        probe_targets
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
    /// Send a Neighbor Advertisement to all-nodes multicast (for DAD defense, RFC 4862)
    SendNeighborAdvertisementMulticast {
        target: Ipv6Address,
        our_mac: [u8; 6],
    },
    /// Neighbor info learned (from NA or NS source)
    NeighborUpdated {
        ip: Ipv6Address,
        mac: [u8; 6],
    },
    /// Send a Neighbor Solicitation (e.g. for DAD)
    SendNeighborSolicitation {
        src: Ipv6Address,
        dst: Ipv6Address,
        target: Ipv6Address,
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
    pub(crate) our_link_local: Ipv6Address,
    /// Our global addresses (SLAAC / manual)
    pub(crate) global_addresses: Vec<Ipv6Address>,
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
