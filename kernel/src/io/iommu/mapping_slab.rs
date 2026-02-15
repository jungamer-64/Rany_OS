// ============================================================================
// kernel/src/io/iommu/mapping_slab.rs
// ============================================================================
//! Allocation-Free DMA Mapping Management
//!
//! This module provides `MappingSlab`, a pre-allocated pool of mapping slots
//! that eliminates heap allocation during map/unmap operations.
//!
//! # Design Rationale
//!
//! The original `BTreeMap<u64, DmaMapping>` implementation suffered from:
//! - Heap allocation on every insert/remove
//! - Poor cache locality due to pointer chasing
//! - O(log n) overhead with large constant factors
//!
//! This implementation uses:
//! - **Slab Allocator**: Pre-allocated fixed-size slots
//! - **Open-Addressing Hash Table**: O(1) average lookup by IOVA
//! - **Intrusive Doubly-Linked List**: O(1) iteration for domain cleanup
//!
//! # Memory Layout
//!
//! ```text
//! MappingSlab
//! ├── slots: [MappingSlot; CAPACITY]     // Pre-allocated slots
//! ├── hash_buckets: [SlotIndex; BUCKETS] // Hash table for IOVA lookup
//! ├── free_head: SlotIndex               // Free list head
//! └── stats: SlabStats                   // Utilization metrics
//! ```
//!
//! # Thread Safety
//!
//! This structure is NOT thread-safe by itself. It must be protected by
//! the `DomainShard`'s `PoisonLock`.

use alloc::boxed::Box;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::types::DmaMapping;

// ============================================================================
// Configuration
// ============================================================================

/// Maximum number of mappings per shard.
/// Should be power of 2 for efficient hash computation.
pub const SLAB_CAPACITY: usize = 512;

/// Number of hash buckets (should be ~2x capacity for good load factor).
const HASH_BUCKETS: usize = 1024;

/// Invalid slot index sentinel.
const INVALID_INDEX: u16 = u16::MAX;

// ============================================================================
// Slot Types
// ============================================================================

/// A single mapping slot in the slab.
#[repr(C)]
pub struct MappingSlot {
    /// The actual mapping data.
    pub mapping: DmaMapping,
    
    /// Next slot in the intrusive list (free list or active list).
    /// INVALID_INDEX means end of list.
    next: u16,
    
    /// Previous slot in the active list (for O(1) removal).
    /// INVALID_INDEX means head of list.
    prev: u16,
    
    /// Index in the hash collision chain.
    /// INVALID_INDEX means end of chain.
    hash_next: u16,
    
    /// Slot state flag.
    flags: SlotFlags,
}

bitflags::bitflags! {
    /// Slot state flags.
    #[derive(Debug, Clone, Copy, Default)]
    struct SlotFlags: u8 {
        /// Slot is currently in use.
        const IN_USE = 0b0001;
        /// Slot is part of a super-page mapping.
        const SUPERPAGE = 0b0010;
    }
}

impl MappingSlot {
    /// Create a new empty slot.
    const fn new() -> Self {
        Self {
            mapping: DmaMapping {
                iova: 0,
                phys: 0,
                size: 0,
                read: false,
                write: false,
                domain_id_placeholder: 0,
            },
            next: INVALID_INDEX,
            prev: INVALID_INDEX,
            hash_next: INVALID_INDEX,
            flags: SlotFlags::empty(),
        }
    }
    
    /// Check if slot is in use.
    #[inline]
    pub fn is_used(&self) -> bool {
        self.flags.contains(SlotFlags::IN_USE)
    }
}

// ============================================================================
// Slab Statistics
// ============================================================================

/// Runtime statistics for monitoring slab utilization.
#[derive(Default)]
pub struct SlabStats {
    /// Current number of active mappings.
    pub active: AtomicU32,
    /// Total insertions since creation.
    pub total_inserts: AtomicU64,
    /// Total removals since creation.
    pub total_removes: AtomicU64,
    /// Hash collision count (for tuning).
    pub hash_collisions: AtomicU64,
    /// High watermark of active mappings.
    pub high_watermark: AtomicU32,
}

impl SlabStats {
    fn record_insert(&self) {
        let current = self.active.fetch_add(1, Ordering::Relaxed) + 1;
        self.total_inserts.fetch_add(1, Ordering::Relaxed);
        
        // Update high watermark
        let mut hw = self.high_watermark.load(Ordering::Relaxed);
        while current > hw {
            match self.high_watermark.compare_exchange_weak(
                hw,
                current,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(x) => hw = x,
            }
        }
    }
    
    fn record_remove(&self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
        self.total_removes.fetch_add(1, Ordering::Relaxed);
    }
    
    fn record_collision(&self) {
        self.hash_collisions.fetch_add(1, Ordering::Relaxed);
    }
}

// ============================================================================
// Mapping Slab
// ============================================================================

/// Pre-allocated slab for DMA mappings.
///
/// Provides O(1) average insert/lookup/remove operations without
/// heap allocation during hot paths.
pub struct MappingSlab {
    /// Pre-allocated slot array.
    slots: Box<[MappingSlot; SLAB_CAPACITY]>,
    
    /// Hash table buckets (index into slots, INVALID_INDEX = empty).
    hash_buckets: Box<[u16; HASH_BUCKETS]>,
    
    /// Free list head index.
    free_head: u16,
    
    /// Active list head index (for iteration).
    active_head: u16,
    
    /// Runtime statistics.
    pub stats: SlabStats,
}

impl MappingSlab {
    /// Create a new slab with all slots in the free list.
    pub fn new() -> Self {
        // Initialize slots array
        let slots: Box<[MappingSlot; SLAB_CAPACITY]> = {
            // Use vec for initialization, then convert
            let mut v = alloc::vec::Vec::with_capacity(SLAB_CAPACITY);
            for i in 0..SLAB_CAPACITY {
                let mut slot = MappingSlot::new();
                // Link to next free slot
                slot.next = if i + 1 < SLAB_CAPACITY {
                    (i + 1) as u16
                } else {
                    INVALID_INDEX
                };
                v.push(slot);
            }
            v.try_into().unwrap_or_else(|_| {
                panic!("MappingSlab: vec size mismatch");
            })
        };
        
        // Initialize hash buckets to empty
        let hash_buckets: Box<[u16; HASH_BUCKETS]> = {
            let v = alloc::vec![INVALID_INDEX; HASH_BUCKETS];
            v.try_into().unwrap_or_else(|_| {
                panic!("MappingSlab: hash bucket size mismatch");
            })
        };
        
        Self {
            slots,
            hash_buckets,
            free_head: 0,
            active_head: INVALID_INDEX,
            stats: SlabStats::default(),
        }
    }
    
    /// Compute hash bucket index for an IOVA.
    #[inline]
    fn hash_iova(iova: u64) -> usize {
        // FNV-1a style mixing for better distribution
        let mut h = iova;
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51afd7ed558ccd);
        h ^= h >> 33;
        (h as usize) & (HASH_BUCKETS - 1)
    }
    
    /// Insert a new mapping. Returns slot index on success.
    ///
    /// # Errors
    ///
    /// Returns `Err(DmaMapping)` if slab is full or IOVA already exists.
    pub fn insert(&mut self, mapping: DmaMapping) -> Result<u16, DmaMapping> {
        // Check if IOVA already mapped
        if self.lookup(mapping.iova).is_some() {
            return Err(mapping);
        }
        
        // Allocate slot from free list
        let slot_idx = self.free_head;
        if slot_idx == INVALID_INDEX {
            return Err(mapping); // Slab full
        }
        
        // Save iova before moving mapping
        let iova = mapping.iova;
        
        // Get free_head's next before modifying
        let next_free = self.slots[slot_idx as usize].next;
        self.free_head = next_free;
        
        // Update active list head's prev if exists
        let old_head = self.active_head;
        if old_head != INVALID_INDEX {
            self.slots[old_head as usize].prev = slot_idx;
        }
        
        // Insert into hash table
        let bucket = Self::hash_iova(iova);
        let existing = self.hash_buckets[bucket];
        if existing != INVALID_INDEX {
            self.stats.record_collision();
        }
        self.hash_buckets[bucket] = slot_idx;
        
        // Initialize slot (after all other modifications)
        let slot = &mut self.slots[slot_idx as usize];
        slot.mapping = mapping;
        slot.flags = SlotFlags::IN_USE;
        slot.prev = INVALID_INDEX;
        slot.next = old_head;
        slot.hash_next = existing;
        
        // Update active head
        self.active_head = slot_idx;
        
        self.stats.record_insert();
        Ok(slot_idx)
    }
    
    /// Look up a mapping by IOVA.
    pub fn lookup(&self, iova: u64) -> Option<&DmaMapping> {
        let bucket = Self::hash_iova(iova);
        let mut idx = self.hash_buckets[bucket];
        
        while idx != INVALID_INDEX {
            let slot = &self.slots[idx as usize];
            if slot.mapping.iova == iova && slot.is_used() {
                return Some(&slot.mapping);
            }
            idx = slot.hash_next;
        }
        
        None
    }
    
    /// Look up a mapping by IOVA (mutable).
    pub fn lookup_mut(&mut self, iova: u64) -> Option<&mut DmaMapping> {
        let bucket = Self::hash_iova(iova);
        let mut idx = self.hash_buckets[bucket];
        
        while idx != INVALID_INDEX {
            let slot = &self.slots[idx as usize];
            if slot.mapping.iova == iova && slot.is_used() {
                // Safe because we have &mut self
                return Some(&mut self.slots[idx as usize].mapping);
            }
            idx = slot.hash_next;
        }
        
        None
    }
    
    /// Remove a mapping by IOVA. Returns the mapping if found.
    pub fn remove(&mut self, iova: u64) -> Option<DmaMapping> {
        let bucket = Self::hash_iova(iova);
        
        // Find in hash chain
        let mut prev_hash_idx = INVALID_INDEX;
        let mut idx = self.hash_buckets[bucket];
        
        while idx != INVALID_INDEX {
            let slot = &self.slots[idx as usize];
            if slot.mapping.iova == iova && slot.is_used() {
                break;
            }
            prev_hash_idx = idx;
            idx = slot.hash_next;
        }
        
        if idx == INVALID_INDEX {
            return None; // Not found
        }
        
        // Extract all needed values before any mutation
        let mapping = self.slots[idx as usize].mapping.clone();
        let hash_next = self.slots[idx as usize].hash_next;
        let prev = self.slots[idx as usize].prev;
        let next = self.slots[idx as usize].next;
        
        // Remove from hash chain
        if prev_hash_idx == INVALID_INDEX {
            self.hash_buckets[bucket] = hash_next;
        } else {
            self.slots[prev_hash_idx as usize].hash_next = hash_next;
        }
        
        // Remove from active list
        if prev != INVALID_INDEX {
            self.slots[prev as usize].next = next;
        } else {
            self.active_head = next;
        }
        
        if next != INVALID_INDEX {
            self.slots[next as usize].prev = prev;
        }
        
        // Return slot to free list
        let slot = &mut self.slots[idx as usize];
        slot.flags = SlotFlags::empty();
        slot.next = self.free_head;
        slot.prev = INVALID_INDEX;
        slot.hash_next = INVALID_INDEX;
        self.free_head = idx;
        
        self.stats.record_remove();
        Some(mapping)
    }
    
    /// Check if a mapping overlaps with an existing one.
    pub fn overlaps(&self, iova: u64, size: u64) -> bool {
        let end = iova.saturating_add(size);
        
        // Check all active mappings (could be optimized with range tree)
        let mut idx = self.active_head;
        while idx != INVALID_INDEX {
            let slot = &self.slots[idx as usize];
            let mapping = &slot.mapping;
            let m_end = mapping.iova.saturating_add(mapping.size);
            
            // Check for overlap
            if iova < m_end && end > mapping.iova {
                return true;
            }
            
            idx = slot.next;
        }
        
        false
    }
    
    /// Iterate over all active mappings.
    pub fn iter(&self) -> MappingSlabIter<'_> {
        MappingSlabIter {
            slab: self,
            current: self.active_head,
        }
    }
    
    /// Number of active mappings.
    #[inline]
    pub fn len(&self) -> usize {
        self.stats.active.load(Ordering::Relaxed) as usize
    }
    
    /// Check if slab is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    
    /// Check if slab is full.
    #[inline]
    pub fn is_full(&self) -> bool {
        self.free_head == INVALID_INDEX
    }
    
    /// Available slots remaining.
    #[inline]
    pub fn available(&self) -> usize {
        SLAB_CAPACITY - self.len()
    }
    
    /// Drain all mappings, returning them as a Vec.
    /// Used for domain cleanup.
    pub fn drain(&mut self) -> alloc::vec::Vec<DmaMapping> {
        let mut result = alloc::vec::Vec::with_capacity(self.len());
        
        while self.active_head != INVALID_INDEX {
            let idx = self.active_head;
            
            // Extract values before modifying
            let mapping = self.slots[idx as usize].mapping.clone();
            let iova = mapping.iova;
            let next_active = self.slots[idx as usize].next;
            
            result.push(mapping);
            
            // Remove from hash table
            let bucket = Self::hash_iova(iova);
            self.remove_from_hash_chain(bucket, idx);
            
            // Move to free list
            self.active_head = next_active;
            let slot = &mut self.slots[idx as usize];
            slot.flags = SlotFlags::empty();
            slot.next = self.free_head;
            slot.prev = INVALID_INDEX;
            self.free_head = idx;
        }
        
        self.stats.active.store(0, Ordering::Relaxed);
        result
    }
    
    /// Helper to remove a slot from its hash chain.
    fn remove_from_hash_chain(&mut self, bucket: usize, target_idx: u16) {
        let mut prev_idx = INVALID_INDEX;
        let mut idx = self.hash_buckets[bucket];
        
        while idx != INVALID_INDEX && idx != target_idx {
            prev_idx = idx;
            idx = self.slots[idx as usize].hash_next;
        }
        
        if idx == target_idx {
            let next = self.slots[idx as usize].hash_next;
            if prev_idx == INVALID_INDEX {
                self.hash_buckets[bucket] = next;
            } else {
                self.slots[prev_idx as usize].hash_next = next;
            }
        }
    }
}

impl Default for MappingSlab {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "qemu-test-export")]
pub fn qemu_smoke_insert_lookup_remove() -> bool {
    let mut slab = MappingSlab::new();

    let mapping = DmaMapping {
        iova: 0x1000,
        phys: 0x2000,
        size: 0x1000,
        read: true,
        write: false,
        domain_id_placeholder: 0,
    };

    if slab.insert(mapping).is_err() {
        return false;
    }
    if slab.len() != 1 {
        return false;
    }
    match slab.lookup(0x1000) {
        Some(found) if found.phys == 0x2000 => {}
        _ => return false,
    }
    if slab.remove(0x1000).is_none() {
        return false;
    }
    slab.len() == 0
}

#[cfg(feature = "qemu-test-export")]
pub fn qemu_smoke_overlap_detection() -> bool {
    let mut slab = MappingSlab::new();

    let mapping = DmaMapping {
        iova: 0x1000,
        phys: 0x2000,
        size: 0x2000,
        read: true,
        write: true,
        domain_id_placeholder: 0,
    };

    if slab.insert(mapping).is_err() {
        return false;
    }

    slab.overlaps(0x1500, 0x1000)
        && slab.overlaps(0x0800, 0x1000)
        && !slab.overlaps(0x3000, 0x1000)
        && !slab.overlaps(0x0000, 0x1000)
}

// ============================================================================
// Iterator
// ============================================================================

/// Iterator over active mappings in a slab.
pub struct MappingSlabIter<'a> {
    slab: &'a MappingSlab,
    current: u16,
}

impl<'a> Iterator for MappingSlabIter<'a> {
    type Item = &'a DmaMapping;
    
    fn next(&mut self) -> Option<Self::Item> {
        if self.current == INVALID_INDEX {
            return None;
        }
        
        let slot = &self.slab.slots[self.current as usize];
        self.current = slot.next;
        Some(&slot.mapping)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test_case]
    fn test_insert_lookup_remove() {
        let mut slab = MappingSlab::new();
        
        let mapping = DmaMapping {
            iova: 0x1000,
            phys: 0x2000,
            size: 0x1000,
            read: true,
            write: false,
            domain_id_placeholder: 0,
        };
        
        assert!(slab.insert(mapping.clone()).is_ok());
        assert_eq!(slab.len(), 1);
        
        let found = slab.lookup(0x1000);
        assert!(found.is_some());
        assert_eq!(found.unwrap().phys, 0x2000);
        
        let removed = slab.remove(0x1000);
        assert!(removed.is_some());
        assert_eq!(slab.len(), 0);
    }
    
    #[test_case]
    fn test_overlap_detection() {
        let mut slab = MappingSlab::new();
        
        let mapping = DmaMapping {
            iova: 0x1000,
            phys: 0x2000,
            size: 0x2000,
            read: true,
            write: true,
            domain_id_placeholder: 0,
        };
        
        slab.insert(mapping).unwrap();
        
        // Should overlap
        assert!(slab.overlaps(0x1500, 0x1000));
        assert!(slab.overlaps(0x0800, 0x1000));
        
        // Should not overlap
        assert!(!slab.overlaps(0x3000, 0x1000));
        assert!(!slab.overlaps(0x0000, 0x1000));
    }
}

