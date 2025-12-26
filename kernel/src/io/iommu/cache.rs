// ============================================================================
// kernel/src/io/iommu/cache.rs - Context Cache
// ============================================================================
//! IOMMU Context Cache
//!
//! Provides a context cache with LRU-like eviction for optimizing repeated
//! context table lookups.

use super::tables::ContextEntry;

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
// Context Cache
// ============================================================================

/// Context Cache with LRU eviction
///
/// Caches frequently accessed context entries to avoid repeated
/// page table walks for context table lookups.
pub struct ContextCache {
    /// Cache entries (fixed size for simplicity)
    entries: [ContextCacheEntry; Self::CACHE_SIZE],
    /// Current timestamp for LRU
    timestamp: u64,
    /// Cache hits
    hits: u64,
    /// Cache misses
    misses: u64,
}

impl ContextCache {
    /// Cache size (power of 2 for fast modulo)
    const CACHE_SIZE: usize = 64;

    /// Create a new context cache
    pub const fn new() -> Self {
        const DEFAULT: ContextCacheEntry = ContextCacheEntry {
            requester_id: 0,
            entry: ContextEntry { lo: 0, hi: 0 },
            last_access: 0,
            valid: false,
        };
        Self {
            entries: [DEFAULT; Self::CACHE_SIZE],
            timestamp: 0,
            hits: 0,
            misses: 0,
        }
    }

    /// Hash function for requester ID
    fn hash(requester_id: u16) -> usize {
        (requester_id as usize) % Self::CACHE_SIZE
    }

    /// Lookup a context entry
    pub fn lookup(&mut self, requester_id: u16) -> Option<ContextEntry> {
        self.timestamp += 1;
        let idx = Self::hash(requester_id);

        if self.entries[idx].valid && self.entries[idx].requester_id == requester_id {
            self.entries[idx].last_access = self.timestamp;
            self.hits += 1;
            Some(self.entries[idx].entry)
        } else {
            self.misses += 1;
            None
        }
    }

    /// Insert a context entry
    pub fn insert(&mut self, requester_id: u16, entry: ContextEntry) {
        self.timestamp += 1;
        let idx = Self::hash(requester_id);

        self.entries[idx] = ContextCacheEntry {
            requester_id,
            entry,
            last_access: self.timestamp,
            valid: true,
        };
    }

    /// Invalidate a specific entry
    pub fn invalidate(&mut self, requester_id: u16) {
        let idx = Self::hash(requester_id);
        if self.entries[idx].requester_id == requester_id {
            self.entries[idx].valid = false;
        }
    }

    /// Invalidate all entries
    pub fn invalidate_all(&mut self) {
        for entry in &mut self.entries {
            entry.valid = false;
        }
    }

    /// Get cache statistics
    pub fn stats(&self) -> (u64, u64) {
        (self.hits, self.misses)
    }
}

impl Default for ContextCache {
    fn default() -> Self {
        Self::new()
    }
}
