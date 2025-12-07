//! ARP (Address Resolution Protocol) Implementation for ExoRust
//!
//! This module implements ARP for IPv4-to-MAC address resolution
//! as part of the zero-copy networking stack.

use super::ethernet::MacAddress;
use super::ipv4::Ipv4Address;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

/// ARP hardware type
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
        }
    }

    /// Create a new incomplete entry
    pub fn new_incomplete(ip: Ipv4Address, timestamp: u64) -> Self {
        ArpEntry {
            ip,
            mac: MacAddress::ZERO,
            timestamp,
            state: ArpEntryState::Incomplete,
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

/// ARP cache for IPv4-to-MAC resolution
pub struct ArpCache {
    /// Cache entries
    entries: Mutex<[Option<ArpEntry>; ARP_CACHE_SIZE]>,
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
            entries: Mutex::new([NONE; ARP_CACHE_SIZE]),
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
        let entries = self.entries.lock();

        for entry in entries.iter().flatten() {
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
        let mut entries = self.entries.lock();

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
        let mut entries = self.entries.lock();

        // Look for existing entry
        for entry in entries.iter_mut().flatten() {
            if entry.ip == ip {
                entry.state = ArpEntryState::Incomplete;
                entry.timestamp = current_time;
                return;
            }
        }

        // Find empty slot or oldest entry
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

        if let Some(i) = empty_slot.or(oldest_slot) {
            entries[i] = Some(ArpEntry::new_incomplete(ip, current_time));
        }
    }

    /// Check if we have a pending request for an IP
    pub fn is_pending(&self, ip: Ipv4Address, current_time: u64) -> bool {
        let entries = self.entries.lock();

        for entry in entries.iter().flatten() {
            if entry.ip == ip && entry.state == ArpEntryState::Incomplete {
                return !entry.is_expired(current_time, ARP_INCOMPLETE_TIMEOUT);
            }
        }

        false
    }

    /// Remove an entry
    pub fn remove(&self, ip: Ipv4Address) {
        let mut entries = self.entries.lock();

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
        let mut entries = self.entries.lock();

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

    /// Get all entries (for debugging)
    pub fn all_entries(&self) -> alloc::vec::Vec<ArpEntry> {
        let entries = self.entries.lock();
        entries.iter().filter_map(|e| *e).collect()
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

impl ArpProcessor {
    /// Create a new ARP processor
    pub fn new(local_mac: MacAddress, local_ip: Ipv4Address) -> Self {
        ArpProcessor {
            local_mac,
            local_ip,
            cache: ArpCache::new(),
        }
    }

    /// Get the ARP cache
    pub fn cache(&self) -> &ArpCache {
        &self.cache
    }

    /// Set local addresses
    pub fn set_local(&mut self, mac: MacAddress, ip: Ipv4Address) {
        self.local_mac = mac;
        self.local_ip = ip;
    }

    /// Process an incoming ARP packet
    pub fn process(&self, data: &[u8], current_time: u64) -> ArpResult {
        if data.len() < ArpPacket::SIZE {
            return ArpResult::Invalid;
        }

        // SAFETY: We checked the length
        let packet = unsafe { &*(data.as_ptr() as *const ArpPacket) };

        if !packet.is_valid() {
            return ArpResult::Invalid;
        }

        let sender_mac = packet.sender_mac();
        let sender_ip = packet.sender_ip();
        let target_ip = packet.target_ip();

        // Update cache with sender info (opportunistic update)
        if !sender_ip.is_any() && !sender_mac.is_broadcast() {
            self.cache.insert(sender_ip, sender_mac, current_time);
        }

        match packet.operation() {
            ArpOperation::Request => {
                // Is this request for us?
                if target_ip == self.local_ip {
                    ArpResult::SendReply {
                        target_mac: sender_mac,
                        target_ip: sender_ip,
                    }
                } else {
                    ArpResult::Ignored
                }
            }
            ArpOperation::Reply => {
                // We already updated the cache above
                ArpResult::CacheUpdated
            }
            _ => ArpResult::Ignored,
        }
    }

    /// Build an ARP request packet
    pub fn build_request(&self, buffer: &mut [u8], target_ip: Ipv4Address) -> Option<usize> {
        if buffer.len() < ArpPacket::SIZE {
            return None;
        }

        // SAFETY: Buffer is large enough
        let packet = unsafe { &mut *(buffer.as_mut_ptr() as *mut ArpPacket) };

        packet.init_request(self.local_mac, self.local_ip, target_ip);
        Some(ArpPacket::SIZE)
    }

    /// Build an ARP reply packet
    pub fn build_reply(
        &self,
        buffer: &mut [u8],
        target_mac: MacAddress,
        target_ip: Ipv4Address,
    ) -> Option<usize> {
        if buffer.len() < ArpPacket::SIZE {
            return None;
        }

        // SAFETY: Buffer is large enough
        let packet = unsafe { &mut *(buffer.as_mut_ptr() as *mut ArpPacket) };

        packet.init_reply(self.local_mac, self.local_ip, target_mac, target_ip);
        Some(ArpPacket::SIZE)
    }

    /// Resolve an IP address to MAC (from cache)
    pub fn resolve(&self, ip: Ipv4Address, current_time: u64) -> Option<MacAddress> {
        // Broadcast IP -> broadcast MAC
        if ip.is_broadcast() {
            return Some(MacAddress::BROADCAST);
        }

        self.cache.lookup(ip, current_time)
    }

    /// Check if we need to send an ARP request
    pub fn needs_request(&self, ip: Ipv4Address, current_time: u64) -> bool {
        self.cache.lookup(ip, current_time).is_none() && !self.cache.is_pending(ip, current_time)
    }

    /// Mark that we're waiting for a reply
    pub fn request_sent(&self, ip: Ipv4Address, current_time: u64) {
        self.cache.mark_incomplete(ip, current_time);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arp_cache() {
        let cache = ArpCache::new();
        let ip = Ipv4Address::from_octets(192, 168, 1, 1);
        let mac = MacAddress::from_octets(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);

        // Initially empty
        assert!(cache.lookup(ip, 0).is_none());

        // Insert and lookup
        cache.insert(ip, mac, 100);
        assert_eq!(cache.lookup(ip, 100), Some(mac));

        // Expired entry
        assert!(cache.lookup(ip, ARP_CACHE_TIMEOUT + 200).is_none());
    }

    #[test]
    fn test_arp_packet() {
        let mut buffer = [0u8; ArpPacket::SIZE];
        let packet = unsafe { &mut *(buffer.as_mut_ptr() as *mut ArpPacket) };

        let sender_mac = MacAddress::from_octets(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let sender_ip = Ipv4Address::from_octets(192, 168, 1, 1);
        let target_ip = Ipv4Address::from_octets(192, 168, 1, 2);

        packet.init_request(sender_mac, sender_ip, target_ip);

        assert!(packet.is_valid());
        assert_eq!(packet.operation(), ArpOperation::Request);
        assert_eq!(packet.sender_mac(), sender_mac);
        assert_eq!(packet.sender_ip(), sender_ip);
        assert_eq!(packet.target_ip(), target_ip);
    }
}
