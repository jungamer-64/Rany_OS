// ============================================================================
// kernel/src/net/arp.rs
// ============================================================================
//! ARP (Address Resolution Protocol) Implementation for ExoRust
//!
//! This module implements ARP for IPv4-to-MAC address resolution
//! as part of the zero-copy networking stack.

use super::ethernet::MacAddress;
use super::ipv4::Ipv4Address;
use crate::sync::PoisonLock;
use core::sync::atomic::{AtomicU64, Ordering};

/// ARP hardware type
mod _split_1;
pub use _split_1::*;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ArpHardwareType {
    /// Ethernet (10 Mb)
    Ethernet = 1,
    /// Unknown
    Unknown(u16),
}

impl From<u16> for ArpHardwareType {
    fn from(value: u16) -> Self {
        match value {
            1 => ArpHardwareType::Ethernet,
            other => ArpHardwareType::Unknown(other),
        }
    }
}

impl From<ArpHardwareType> for u16 {
    fn from(value: ArpHardwareType) -> Self {
        match value {
            ArpHardwareType::Ethernet => 1,
            ArpHardwareType::Unknown(v) => v,
        }
    }
}

/// ARP operation code
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ArpOperation {
    /// ARP Request
    Request = 1,
    /// ARP Reply
    Reply = 2,
    /// Unknown
    Unknown(u16),
}

impl From<u16> for ArpOperation {
    fn from(value: u16) -> Self {
        match value {
            1 => ArpOperation::Request,
            2 => ArpOperation::Reply,
            other => ArpOperation::Unknown(other),
        }
    }
}

impl From<ArpOperation> for u16 {
    fn from(value: ArpOperation) -> Self {
        match value {
            ArpOperation::Request => 1,
            ArpOperation::Reply => 2,
            ArpOperation::Unknown(v) => v,
        }
    }
}

/// ARP packet header for IPv4 over Ethernet
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct ArpPacket {
    /// Hardware type (big-endian)
    pub hardware_type: [u8; 2],
    /// Protocol type (big-endian)
    pub protocol_type: [u8; 2],
    /// Hardware address length
    pub hardware_len: u8,
    /// Protocol address length
    pub protocol_len: u8,
    /// Operation (big-endian)
    pub operation: [u8; 2],
    /// Sender hardware address (MAC)
    pub sender_mac: [u8; 6],
    /// Sender protocol address (IPv4)
    pub sender_ip: [u8; 4],
    /// Target hardware address (MAC)
    pub target_mac: [u8; 6],
    /// Target protocol address (IPv4)
    pub target_ip: [u8; 4],
}

impl ArpPacket {
    /// Size of ARP packet (for IPv4 over Ethernet)
    pub const SIZE: usize = 28;

    /// Get hardware type
    pub fn hardware_type(&self) -> ArpHardwareType {
        ArpHardwareType::from(u16::from_be_bytes(self.hardware_type))
    }

    /// Set hardware type
    pub fn set_hardware_type(&mut self, htype: ArpHardwareType) {
        self.hardware_type = u16::to_be_bytes(htype.into());
    }

    /// Get protocol type (EtherType)
    pub fn protocol_type(&self) -> u16 {
        u16::from_be_bytes(self.protocol_type)
    }

    /// Set protocol type
    pub fn set_protocol_type(&mut self, ptype: u16) {
        self.protocol_type = ptype.to_be_bytes();
    }

    /// Get operation
    pub fn operation(&self) -> ArpOperation {
        ArpOperation::from(u16::from_be_bytes(self.operation))
    }

    /// Set operation
    pub fn set_operation(&mut self, op: ArpOperation) {
        self.operation = u16::to_be_bytes(op.into());
    }

    /// Get sender MAC address
    pub fn sender_mac(&self) -> MacAddress {
        MacAddress::new(self.sender_mac)
    }

    /// Set sender MAC address
    pub fn set_sender_mac(&mut self, mac: MacAddress) {
        self.sender_mac = *mac.as_bytes();
    }

    /// Get sender IP address
    pub fn sender_ip(&self) -> Ipv4Address {
        Ipv4Address::new(self.sender_ip)
    }

    /// Set sender IP address
    pub fn set_sender_ip(&mut self, ip: Ipv4Address) {
        self.sender_ip = *ip.as_bytes();
    }

    /// Get target MAC address
    pub fn target_mac(&self) -> MacAddress {
        MacAddress::new(self.target_mac)
    }

    /// Set target MAC address
    pub fn set_target_mac(&mut self, mac: MacAddress) {
        self.target_mac = *mac.as_bytes();
    }

    /// Get target IP address
    pub fn target_ip(&self) -> Ipv4Address {
        Ipv4Address::new(self.target_ip)
    }

    /// Set target IP address
    pub fn set_target_ip(&mut self, ip: Ipv4Address) {
        self.target_ip = *ip.as_bytes();
    }

    /// Initialize as ARP request
    pub fn init_request(
        &mut self,
        sender_mac: MacAddress,
        sender_ip: Ipv4Address,
        target_ip: Ipv4Address,
    ) {
        self.set_hardware_type(ArpHardwareType::Ethernet);
        self.set_protocol_type(0x0800); // IPv4
        self.hardware_len = 6;
        self.protocol_len = 4;
        self.set_operation(ArpOperation::Request);
        self.set_sender_mac(sender_mac);
        self.set_sender_ip(sender_ip);
        self.set_target_mac(MacAddress::ZERO);
        self.set_target_ip(target_ip);
    }

    /// Initialize as ARP reply
    pub fn init_reply(
        &mut self,
        sender_mac: MacAddress,
        sender_ip: Ipv4Address,
        target_mac: MacAddress,
        target_ip: Ipv4Address,
    ) {
        self.set_hardware_type(ArpHardwareType::Ethernet);
        self.set_protocol_type(0x0800); // IPv4
        self.hardware_len = 6;
        self.protocol_len = 4;
        self.set_operation(ArpOperation::Reply);
        self.set_sender_mac(sender_mac);
        self.set_sender_ip(sender_ip);
        self.set_target_mac(target_mac);
        self.set_target_ip(target_ip);
    }

    /// Validate ARP packet (IPv4 over Ethernet)
    pub fn is_valid(&self) -> bool {
        self.hardware_type() == ArpHardwareType::Ethernet
            && self.protocol_type() == 0x0800
            && self.hardware_len == 6
            && self.protocol_len == 4
    }
}

/// ARP cache entry
#[derive(Debug, Clone, Copy)]
pub struct ArpEntry {
    /// IP address
    pub ip: Ipv4Address,
    /// MAC address
    pub mac: MacAddress,
    /// Timestamp (ticks when entry was created/updated)
    pub timestamp: u64,
    /// Entry state
    pub state: ArpEntryState,
    /// Number of ARP requests sent for this entry
    pub request_count: u8,
    /// Timestamp of last ARP request sent
    pub last_request_time: u64,
}

/// ARP entry state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpEntryState {
    /// Entry is incomplete (waiting for reply)
    Incomplete,
    /// Entry is resolved and valid
    Resolved,
    /// Entry is stale (needs refresh)
    Stale,
}

impl ArpEntry {
    /// Create a new resolved entry
    pub fn new_resolved(ip: Ipv4Address, mac: MacAddress, timestamp: u64) -> Self {
        ArpEntry {
            ip,
            mac,
            timestamp,
            state: ArpEntryState::Resolved,
            request_count: 0,
            last_request_time: 0,
        }
    }

    /// Create a new incomplete entry
    pub fn new_incomplete(ip: Ipv4Address, timestamp: u64) -> Self {
        ArpEntry {
            ip,
            mac: MacAddress::ZERO,
            timestamp,
            state: ArpEntryState::Incomplete,
            request_count: 1,
            last_request_time: timestamp,
        }
    }

    /// Check if entry is expired
    pub fn is_expired(&self, current_time: u64, timeout: u64) -> bool {
        current_time.saturating_sub(self.timestamp) > timeout
    }
}

/// Maximum ARP cache size
const ARP_CACHE_SIZE: usize = 64;

/// ARP cache timeout (20 minutes in ticks, assuming 1000 ticks/sec)
const ARP_CACHE_TIMEOUT: u64 = 20 * 60 * 1000;

/// ARP incomplete entry timeout (3 seconds)
const ARP_INCOMPLETE_TIMEOUT: u64 = 3 * 1000;

/// Minimum interval between ARP requests for the same IP (1 second)
const ARP_REQUEST_INTERVAL: u64 = 1000;

/// Maximum number of ARP requests before giving up
const ARP_MAX_REQUESTS: u8 = 5;

/// ARP cache for IPv4-to-MAC resolution
pub struct ArpCache {
    /// Cache entries
    entries: PoisonLock<[Option<ArpEntry>; ARP_CACHE_SIZE]>,
    /// Statistics
    stats: ArpStats,
}

/// ARP statistics
pub struct ArpStats {
    /// Cache hits
    pub hits: AtomicU64,
    /// Cache misses
    pub misses: AtomicU64,
    /// Entries added
    pub entries_added: AtomicU64,
    /// Entries expired
    pub entries_expired: AtomicU64,
}

impl Default for ArpStats {
    fn default() -> Self {
        ArpStats {
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            entries_added: AtomicU64::new(0),
            entries_expired: AtomicU64::new(0),
        }
    }
}

impl ArpCache {
    /// Create a new ARP cache
    pub const fn new() -> Self {
        const NONE: Option<ArpEntry> = None;
        ArpCache {
            entries: PoisonLock::new([NONE; ARP_CACHE_SIZE]),
            stats: ArpStats {
                hits: AtomicU64::new(0),
                misses: AtomicU64::new(0),
                entries_added: AtomicU64::new(0),
                entries_expired: AtomicU64::new(0),
            },
        }
    }

    /// Look up a MAC address by IP
    pub fn lookup(&self, ip: Ipv4Address, current_time: u64) -> Option<MacAddress> {
        let entries_guard = match self.entries.lock() {
            Ok(g) => g,
            Err(_) => {
                log::error!("[NET] ARP cache lock poisoned - lookup returns None");
                self.stats.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };

        for entry in entries_guard.iter().flatten() {
            if entry.ip == ip {
                if entry.state == ArpEntryState::Resolved {
                    if !entry.is_expired(current_time, ARP_CACHE_TIMEOUT) {
                        self.stats.hits.fetch_add(1, Ordering::Relaxed);
                        return Some(entry.mac);
                    }
                }
            }
        }

        self.stats.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Insert or update an ARP entry
    pub fn insert(&self, ip: Ipv4Address, mac: MacAddress, current_time: u64) {
        let mut entries = match self.entries.lock() {
            Ok(g) => g,
            Err(_) => {
                log::error!("[NET] ARP cache lock poisoned - insert ignored");
                return;
            }
        };

        // Look for existing entry or empty slot
        let mut empty_slot = None;
        let mut oldest_slot = None;
        let mut oldest_time = u64::MAX;

        for (i, entry) in entries.iter_mut().enumerate() {
            match entry {
                Some(e) if e.ip == ip => {
                    // Update existing entry
                    e.mac = mac;
                    e.timestamp = current_time;
                    e.state = ArpEntryState::Resolved;
                    return;
                }
                None if empty_slot.is_none() => {
                    empty_slot = Some(i);
                }
                Some(e) => {
                    if e.timestamp < oldest_time {
                        oldest_time = e.timestamp;
                        oldest_slot = Some(i);
                    }
                }
                _ => {}
            }
        }

        // Insert in empty slot or replace oldest
        let slot = empty_slot.or(oldest_slot);
        if let Some(i) = slot {
            entries[i] = Some(ArpEntry::new_resolved(ip, mac, current_time));
            self.stats.entries_added.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Mark an entry as incomplete (ARP request sent)
    pub fn mark_incomplete(&self, ip: Ipv4Address, current_time: u64) {
        let mut entries = match self.entries.lock() {
            Ok(g) => g,
            Err(_) => {
                log::error!("[NET] ARP cache lock poisoned - mark_incomplete ignored");
                return;
            }
        };

        // Look for existing entry
        for entry in entries.iter_mut().flatten() {
            if entry.ip == ip {
                entry.state = ArpEntryState::Incomplete;
                entry.timestamp = current_time;
                return;
            }
        }

        // Find empty slot or oldest entry
        if let Some(i) = Self::find_available_slot(&entries) {
            entries[i] = Some(ArpEntry::new_incomplete(ip, current_time));
        }
    }

    /// Find an empty slot, or the oldest slot as fallback.
    fn find_available_slot(entries: &[Option<ArpEntry>; ARP_CACHE_SIZE]) -> Option<usize> {
        let mut empty_slot = None;
        let mut oldest_slot = None;
        let mut oldest_time = u64::MAX;

        for (i, entry) in entries.iter().enumerate() {
            match entry {
                None if empty_slot.is_none() => {
                    empty_slot = Some(i);
                }
                Some(e) if e.timestamp < oldest_time => {
                    oldest_time = e.timestamp;
                    oldest_slot = Some(i);
                }
                _ => {}
            }
        }

        empty_slot.or(oldest_slot)
    }

    /// Check if we have a pending request for an IP
    pub fn is_pending(&self, ip: Ipv4Address, current_time: u64) -> bool {
        let entries_guard = match self.entries.lock() {
            Ok(g) => g,
            Err(_) => {
                log::error!("[NET] ARP cache lock poisoned - is_pending returns false");
                return false;
            }
        };

        for entry in entries_guard.iter().flatten() {
            if entry.ip == ip && entry.state == ArpEntryState::Incomplete {
                return !entry.is_expired(current_time, ARP_INCOMPLETE_TIMEOUT);
            }
        }

        false
    }

    /// Remove an entry
    pub fn remove(&self, ip: Ipv4Address) {
        let mut entries = match self.entries.lock() {
            Ok(g) => g,
            Err(_) => {
                log::error!("[NET] ARP cache lock poisoned - remove ignored");
                return;
            }
        };

        for entry in entries.iter_mut() {
            if let Some(e) = entry {
                if e.ip == ip {
                    *entry = None;
                    return;
                }
            }
        }
    }

    /// Expire old entries
    pub fn expire_old(&self, current_time: u64) {
        let mut entries = match self.entries.lock() {
            Ok(g) => g,
            Err(_) => {
                log::error!("[NET] ARP cache lock poisoned - expire_old ignored");
                return;
            }
        };

        for entry in entries.iter_mut() {
            if let Some(e) = entry {
                let timeout = if e.state == ArpEntryState::Incomplete {
                    ARP_INCOMPLETE_TIMEOUT
                } else {
                    ARP_CACHE_TIMEOUT
                };

                if e.is_expired(current_time, timeout) {
                    *entry = None;
                    self.stats.entries_expired.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Get statistics
    pub fn stats(&self) -> (u64, u64, u64, u64) {
        (
            self.stats.hits.load(Ordering::Relaxed),
            self.stats.misses.load(Ordering::Relaxed),
            self.stats.entries_added.load(Ordering::Relaxed),
            self.stats.entries_expired.load(Ordering::Relaxed),
        )
    }

    /// Check whether an ARP request should be sent for the given IP.
    /// Implements rate limiting to prevent ARP storms.
    pub fn should_send_request(&self, ip: Ipv4Address, current_time: u64) -> bool {
        let mut entries = match self.entries.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };

        for entry in entries.iter_mut() {
            if let Some(e) = entry {
                if e.ip == ip && e.state == ArpEntryState::Incomplete {
                    // Rate limit: check interval and max attempts
                    if e.request_count >= ARP_MAX_REQUESTS {
                        return false;
                    }
                    if current_time.saturating_sub(e.last_request_time) < ARP_REQUEST_INTERVAL {
                        return false;
                    }
                    // Update rate limit state
                    e.request_count = e.request_count.saturating_add(1);
                    e.last_request_time = current_time;
                    return true;
                }
            }
        }

        // No existing entry - allow the request (caller should create Incomplete entry)
        true
    }

    /// Get all entries (for debugging)
    pub fn all_entries(&self) -> alloc::vec::Vec<ArpEntry> {
        match self.entries.lock() {
            Ok(entries) => entries.iter().filter_map(|e| *e).collect(),
            Err(_) => {
                log::error!("[NET] ARP cache lock poisoned - all_entries returns empty");
                alloc::vec::Vec::new()
            }
        }
    }
}

extern crate alloc;

/// ARP processor for handling ARP packets
pub struct ArpProcessor {
    /// Local MAC address
    local_mac: MacAddress,
    /// Local IP address
    local_ip: Ipv4Address,
    /// ARP cache
    cache: ArpCache,
}

/// Result of ARP processing
pub enum ArpResult {
    /// Need to send an ARP reply
    SendReply {
        target_mac: MacAddress,
        target_ip: Ipv4Address,
    },
    /// Cache was updated
    CacheUpdated,
    /// Packet was ignored
    Ignored,
    /// Invalid packet
    Invalid,
}
