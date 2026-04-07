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
            next_probe: timestamp + Self::TIMEOUT_MS,
        }
    }

    /// Check if the entry has expired
    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time.saturating_sub(self.updated_at) > Self::TIMEOUT_MS
    }

    /// Check if we should probe for a larger MTU
    pub fn should_probe(&self, current_time: u64) -> bool {
        current_time >= self.next_probe && self.pmtu < Self::DEFAULT_MTU
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
            self.entries
                .insert(dst, PmtuEntry::new(clamped_mtu, current_time));
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
