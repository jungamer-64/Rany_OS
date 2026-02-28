// ============================================================================
// kernel/src/io/iommu/vendors/intel/controller/context_cache.rs
// ============================================================================

//! IOMMU context entry cache
//!
//! This module provides a small 2‑way set‑associative cache for
//! *context entries* (device ID → context table entry mapping) used by the
//! Intel IOMMU controller logic.  It has no relationship to the DMA/IOVA
//! translation path, despite the previous location under `dma/`.
//!
//! The cache is primarily intended to avoid repeated page‑table walks when
//! looking up a device's context entry during domain attach/detach and other
//! controller operations.

use crate::io::iommu::vendors::intel::tables::ContextEntry;

// ============================================================================
// Context Cache Entry
// ============================================================================

/// Context Cache Entry
#[derive(Clone, Copy)]
struct ContextCacheEntry {
    /// Requester ID (BDF)
    requester_id: u16,
    /// Cached context entry
    entry: ContextEntry,
    /// Last access timestamp (for LRU)
    last_access: u64,
    /// Valid flag
    valid: bool,
}

impl Default for ContextCacheEntry {
    fn default() -> Self {
        Self {
            requester_id: 0,
            entry: ContextEntry::default(),
            last_access: 0,
            valid: false,
        }
    }
}

// ============================================================================
// Context Cache (2-Way Set Associative)
// ============================================================================

/// Context Cache with 2-way set associative design and LRU eviction
///
/// Caches frequently accessed context entries to avoid repeated
/// page table walks for context table lookups.
///
/// ## Design
/// - 32 sets × 2 ways = 64 total entries
/// - Each set can hold 2 entries that hash to the same index
/// - LRU eviction within each set when both ways are valid
pub struct ContextCache {
    /// Cache entries: [SETS][WAYS]
    entries: [[ContextCacheEntry; Self::WAYS]; Self::SETS],
    /// Current timestamp for LRU
    timestamp: u64,
    /// Cache hits
    hits: u64,
    /// Cache misses
    misses: u64,
    /// Evictions (replacement of valid entry)
    evictions: u64,
}

impl ContextCache {
    /// Number of cache sets
    const SETS: usize = 32;
    /// Number of ways per set (associativity)
    const WAYS: usize = 2;

    /// Create a new context cache
    pub const fn new() -> Self {
        const DEFAULT: ContextCacheEntry = ContextCacheEntry {
            requester_id: 0,
            entry: ContextEntry { lo: 0, hi: 0 },
            last_access: 0,
            valid: false,
        };
        Self {
            entries: [[DEFAULT; Self::WAYS]; Self::SETS],
            timestamp: 0,
            hits: 0,
            misses: 0,
            evictions: 0,
        }
    }

    /// Hash function for requester ID to determine set index
    #[inline]
    fn set_index(requester_id: u16) -> usize {
        (requester_id as usize) % Self::SETS
    }

    /// Lookup a context entry
    pub fn lookup(&mut self, requester_id: u16) -> Option<ContextEntry> {
        self.timestamp += 1;
        let set_idx = Self::set_index(requester_id);

        // Search all ways in this set
        for way in 0..Self::WAYS {
            let entry = &mut self.entries[set_idx][way];
            if entry.valid && entry.requester_id == requester_id {
                entry.last_access = self.timestamp;
                self.hits += 1;
                return Some(entry.entry);
            }
        }

        self.misses += 1;
        None
    }

    /// Insert a context entry (with LRU eviction within the set)
    pub fn insert(&mut self, requester_id: u16, entry: ContextEntry) {
        self.timestamp += 1;
        let set_idx = Self::set_index(requester_id);

        // First pass: look for existing entry with same requester_id (update)
        for way in 0..Self::WAYS {
            if self.entries[set_idx][way].valid
                && self.entries[set_idx][way].requester_id == requester_id
            {
                self.entries[set_idx][way] = ContextCacheEntry {
                    requester_id,
                    entry,
                    last_access: self.timestamp,
                    valid: true,
                };
                return;
            }
        }

        // Second pass: look for invalid (empty) slot
        for way in 0..Self::WAYS {
            if !self.entries[set_idx][way].valid {
                self.entries[set_idx][way] = ContextCacheEntry {
                    requester_id,
                    entry,
                    last_access: self.timestamp,
                    valid: true,
                };
                return;
            }
        }

        // Third pass: evict LRU entry (all ways are valid)
        let mut lru_way = 0;
        let mut lru_time = self.entries[set_idx][0].last_access;
        for way in 1..Self::WAYS {
            if self.entries[set_idx][way].last_access < lru_time {
                lru_time = self.entries[set_idx][way].last_access;
                lru_way = way;
            }
        }

        self.evictions += 1;
        self.entries[set_idx][lru_way] = ContextCacheEntry {
            requester_id,
            entry,
            last_access: self.timestamp,
            valid: true,
        };
    }

    /// Invalidate a specific entry
    pub fn invalidate(&mut self, requester_id: u16) {
        let set_idx = Self::set_index(requester_id);
        for way in 0..Self::WAYS {
            if self.entries[set_idx][way].requester_id == requester_id {
                self.entries[set_idx][way].valid = false;
            }
        }
    }

    /// Invalidate all entries
    pub fn invalidate_all(&mut self) {
        for set in &mut self.entries {
            for entry in set {
                entry.valid = false;
            }
        }
    }

    /// Get cache statistics (hits, misses)
    pub fn stats(&self) -> (u64, u64) {
        (self.hits, self.misses)
    }

    /// Get extended cache statistics (hits, misses, evictions)
    pub fn stats_extended(&self) -> (u64, u64, u64) {
        (self.hits, self.misses, self.evictions)
    }
}

impl Default for ContextCache {
    fn default() -> Self {
        Self::new()
    }
}
