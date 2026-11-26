// ============================================================================
// kernel/src/net/l3/ipv4/pmtu_impl.rs - L3 / IPv4 / PMTU実装
// ============================================================================

use super::*;

impl PmtuEntry {
    /// Default MTU (standard Ethernet)
    pub const DEFAULT_MTU: u16 = 1500;
    /// Minimum MTU (RFC 791)
    pub const MIN_MTU: u16 = 68;
    /// Maximum MTU
    pub const MAX_MTU: u16 = 65535;
    /// Cache entry timeout in milliseconds (10 minutes, RFC 1191)
    pub const TIMEOUT_MS: u64 = 600_000;

    /// Create a new PMTU entry
    pub fn new(pmtu: u16, timestamp: u64) -> Self {
        Self {
            pmtu: pmtu.clamp(Self::MIN_MTU, Self::MAX_MTU),
            updated_at: timestamp,
        }
    }

    /// Check if the entry has expired
    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time.saturating_sub(self.updated_at) > Self::TIMEOUT_MS
    }

    /// RFC 1191: Get the next smaller MTU from the plateau list.
    /// Used when a router doesn't provide the next-hop MTU in ICMP.
    pub fn get_next_plateau(current_mtu: u16) -> u16 {
        // RFC 1191 Section 4: "A host MUST use the next smaller MTU from the following list"
        // List is recommended: 65535, 32000, 17914, 8166, 4352, 2048, 1492, 1006, 508, 296, 68.
        const PLATEAUS: &[u16] = &[
            65535, 32000, 17914, 8166, 4352, 2048, 1500, 1492, 1006, 576, 508, 296, 68,
        ];

        for &p in PLATEAUS {
            if p < current_mtu {
                return p;
            }
        }
        Self::MIN_MTU
    }
}

impl PmtuCache {
    /// Default maximum entries
    pub const DEFAULT_MAX_ENTRIES: usize = 256;

    /// Create a new PMTU cache
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            max_entries,
        }
    }

    /// Get PMTU for a destination
    pub fn get(&mut self, dst: Ipv4Address, current_time: u64) -> u16 {
        if let Some(entry) = self.entries.get(&dst)
            && !entry.is_expired(current_time)
        {
            return entry.pmtu;
        }
        PmtuEntry::DEFAULT_MTU
    }

    /// Update PMTU for a destination (called when receiving ICMP Fragmentation Needed)
    pub fn update(&mut self, dst: Ipv4Address, new_mtu: u16, current_time: u64) {
        let clamped_mtu = new_mtu.clamp(PmtuEntry::MIN_MTU, PmtuEntry::MAX_MTU);

        if let Some(entry) = self.entries.get_mut(&dst) {
            if clamped_mtu < entry.pmtu {
                entry.pmtu = clamped_mtu;
                entry.updated_at = current_time;
            }
        } else {
            // Evict oldest entry if at capacity
            if self.entries.len() >= self.max_entries {
                self.evict_oldest();
            }
            self.entries
                .insert(dst, PmtuEntry::new(clamped_mtu, current_time));
        }
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
}
