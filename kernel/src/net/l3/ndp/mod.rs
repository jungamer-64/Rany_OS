// ============================================================================
// kernel/src/net/l3/ndp/mod.rs - L3 / NDP モジュール
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
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::icmpv6::Icmpv6Type;
use super::ipv4::{IpProtocol, data_checksum};
use super::ipv6::{Ipv6Address, ipv6_pseudo_header_checksum};
use crate::net::payload::PacketPayloadView;
use kernel_api::resource::net::PacketPayload;

// =====================================================
// NDP Constants
// =====================================================

/// Minimum Neighbor Solicitation size: ICMPv6 header (4) + reserved (4) + target (16) = 24
pub(crate) mod processor_impl;
mod resolve_future;
pub use resolve_future::*;
#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests;
pub const NS_MIN_SIZE: usize = 24;

/// Minimum Neighbor Advertisement size: same as NS
pub const NA_MIN_SIZE: usize = 24;

/// Minimum Router Solicitation size: ICMPv6 header (4) + reserved (4) = 8

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
#[derive(Debug)]
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
    /// Recursive DNS Server (RDNSS)
    RecursiveDnsServer {
        lifetime: u32,
        servers: Vec<Ipv6Address>,
    },
}

// =====================================================
// Neighbor State Machine
// =====================================================

/// The requester can send now, wait for an outstanding solicitation, or
/// submit the first solicitation of a newly admitted resolution.
pub(crate) enum NeighborResolution {
    Resolved([u8; 6]),
    Pending,
    Probe(NeighborProbe),
}

pub(crate) struct NeighborProbe {
    pub(crate) source: Ipv6Address,
    pub(crate) destination: Ipv6Address,
    pub(crate) mac: [u8; 6],
    pub(crate) payload: PacketPayload,
}

#[derive(Clone, Copy)]
enum Solicitation {
    Resolve(Ipv6Address),
    Verify { target: Ipv6Address, mac: [u8; 6] },
}

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
#[derive(Debug)]
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

    /// Create a new entry in Stale state
    pub fn new_stale(ip: Ipv6Address, mac: [u8; 6], timestamp: u64) -> Self {
        Self {
            ip,
            mac,
            state: NeighborState::Stale,
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
        if self.entries.len() >= MAX_NEIGHBOR_ENTRIES
            && !self.entries.contains_key(entry.ip.as_bytes())
        {
            self.evict_one();
        }
        self.entries.insert(*entry.ip.as_bytes(), entry);
    }

    /// Remove an entry
    #[cfg(test)]
    fn remove(&mut self, ip: &Ipv6Address) -> Option<NeighborEntry> {
        self.entries.remove(ip.as_bytes())
    }

    /// Update a neighbor's MAC address and set Reachable (for solicited NA)
    pub fn update_reachable(&mut self, ip: &Ipv6Address, mac: [u8; 6], timestamp: u64) {
        if let Some(entry) = self.entries.get_mut(ip.as_bytes()) {
            entry.mac = mac;
            entry.state = NeighborState::Reachable;
            entry.timestamp = timestamp;
            entry.probes_sent = 0;
        } else {
            // RFC 4861 Section 7.2.5: SHOULD discard if not in cache.
            // But if we're here, process_na should have already checked.
            // We use new_reachable if forced.
            self.insert(NeighborEntry::new_reachable(*ip, mac, timestamp));
        }
    }

    /// Update a neighbor's MAC address and set Stale (for unsolicited info like NS SLLA or RA)
    pub fn update_stale(&mut self, ip: &Ipv6Address, mac: [u8; 6], timestamp: u64) {
        if let Some(entry) = self.entries.get_mut(ip.as_bytes()) {
            if entry.mac != mac {
                entry.mac = mac;
                entry.state = NeighborState::Stale;
                entry.timestamp = timestamp;
            }
        } else {
            self.insert(NeighborEntry::new_stale(*ip, mac, timestamp));
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
    fn mac_for_send(&mut self, ip: &Ipv6Address, current_time: u64) -> Option<[u8; 6]> {
        let entry = self.entries.get_mut(ip.as_bytes())?;
        if entry.state == NeighborState::Stale {
            entry.state = NeighborState::Delay;
            entry.timestamp = current_time;
            entry.probes_sent = 0;
        }
        entry.has_mac().then_some(entry.mac)
    }

    /// Process NUD timers — advances Delay→Probe, Probe retries, and
    /// removes entries that exceeded MAX_UNICAST_SOLICIT.
    /// Return due solicitations with the destination selected by neighbor state.
    fn process_nud_timers(&mut self, current_time: u64) -> Vec<Solicitation> {
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
                        probe_targets.push(Solicitation::Verify {
                            target: entry.ip,
                            mac: entry.mac,
                        });
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
                            probe_targets.push(Solicitation::Verify {
                                target: entry.ip,
                                mac: entry.mac,
                            });
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
                            probe_targets.push(Solicitation::Resolve(entry.ip));
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
    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if cache is empty
    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Evict one entry (prefer Stale, then oldest)
    fn evict_one(&mut self) {
        // Find a stale entry to evict
        let stale_key = self
            .entries
            .iter()
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
    NeighborUpdated { ip: Ipv6Address, mac: [u8; 6] },
    /// Router Advertisement received (prefix/gateway info)
    RouterAdvertisement {
        router: Ipv6Address,
        router_lifetime_secs: u16,
        prefixes: Vec<NdpOption>,
    },
    /// Redirect received (RFC 4861)
    Redirect {
        target: Ipv6Address,
        destination: Ipv6Address,
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
    addresses: crate::net::l3::ipv6::address_state::Ipv6AddressSet,
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
    pub ra_received: AtomicU64,
    pub ns_sent: AtomicU64,
}
