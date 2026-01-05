// ============================================================================
// kernel/src/io/iommu/iova_bitmap.rs
// ============================================================================
//! Allocation-Free IOVA Allocator (Bitmap + Magazine)
//!
//! This module provides a high-performance IOVA allocator that eliminates
//! heap allocations on the hot path, following ExoRust's "No Allocation on
//! Hot Path" principle.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    IovaAllocatorFast                        │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Fast Path (O(1), Per-CPU, IRQ-off guarded):                │
//! │  ┌─────────────────────────────────────────────────────────┐│
//! │  │ Per-CPU Magazine Cache                                  ││
//! │  │ [4KB: [iova1, iova2, ...], 2MB: [...], ...]             ││
//! │  └─────────────────────────────────────────────────────────┘│
//! │                           │                                 │
//! │                           ▼ (refill/return)                 │
//! │  Medium Path (O(1) amortized):                              │
//! │  ┌─────────────────────────────────────────────────────────┐│
//! │  │ Bitmap Allocator (fixed overhead)                       ││
//! │  │ - 4KB detail: 1 bit per 4KB page                        ││
//! │  │ - 4KB summary: 1 bit per 64 pages (4096 pages/word)     ││
//! │  │ - 4KB summary_l2: 1 bit per 4096 pages (262144/word)    ││
//! │  │ - 2MB fully-free: 1 bit per 2MB block                   ││
//! │  │ - 1GB fully-free: 1 bit per 1GB block                   ││
//! │  │ - 3-level hierarchical summary for near-full scanning   ││
//! │  └─────────────────────────────────────────────────────────┘│
//! │                           │                                 │
//! │                           ▼ (fallback for large allocs)     │
//! │  Slow Path (O(log n), rare):                                │
//! │  ┌─────────────────────────────────────────────────────────┐│
//! │  │ Range Tree (for 1GB+ contiguous allocations only)       ││
//! │  └─────────────────────────────────────────────────────────┘│
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Performance Characteristics
//!
//! | Operation      | Fast Path | Medium Path | Slow Path |
//! |----------------|-----------|-------------|-----------|
//! | 4KB alloc      | O(1)      | O(1) amort  | N/A       |
//! | 2MB alloc      | O(1)      | O(1) amort  | N/A       |
//! | 1GB+ alloc     | N/A       | N/A         | O(log n)  |
//! | Free (any)     | O(1)      | O(1)        | O(log n)  |
//! | Heap alloc     | None      | None        | Possible  |
//!
//! # Thread Safety
//!
//! - Magazine layer: Per-CPU caches (IRQ-off guarded)
//! - Bitmap layer: Protected by PoisonLock (short critical sections)
//! - Tree layer: Protected by PoisonLock (rarely accessed)

use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use crate::sync::IrqMutex;
use super::types::IommuError;

// ============================================================================
// Constants
// ============================================================================

/// 4KB page size
pub const PAGE_SIZE_4K: u64 = 4096;
/// 2MB super-page size
pub const PAGE_SIZE_2M: u64 = 2 * 1024 * 1024;
/// 1GB huge-page size
pub const PAGE_SIZE_1G: u64 = 1024 * 1024 * 1024;

/// Bits per u64 word in bitmap
const BITS_PER_WORD: usize = 64;

/// Maximum pages managed by bitmap (256GB / 4KB = 64M pages)
/// This limits bitmap memory to 8MB per allocator
const MAX_BITMAP_PAGES: usize = 64 * 1024 * 1024;

/// Number of pages per bitmap word
const PAGES_PER_WORD: usize = BITS_PER_WORD;

/// Maximum words in the bitmap
const MAX_BITMAP_WORDS: usize = MAX_BITMAP_PAGES / BITS_PER_WORD;

/// Magazine capacity (number of pre-allocated IOVAs per size class)
const MAGAZINE_CAPACITY: usize = 64;

/// Number of size classes in magazine (4KB, 2MB, 1GB)
const MAGAZINE_SIZE_CLASSES: usize = 3;

// ============================================================================
// 3-Level Summary Hierarchy Constants
// ============================================================================

/// Detail words per summary bit (64 pages per bit = 1 word)
const DETAIL_WORDS_PER_SUMMARY_BIT: usize = 1;

/// Summary words per summary_l2 bit (64 summary bits per l2 bit)
/// 1 summary_l2 bit covers 64 * 64 = 4096 detail words = 262,144 pages
const SUMMARY_WORDS_PER_L2_BIT: usize = 1;

/// Pages covered by one summary_l2 bit
const PAGES_PER_L2_BIT: usize = BITS_PER_WORD * BITS_PER_WORD; // 4096 pages

// ============================================================================
// Hierarchical Block Constants
// ============================================================================

/// 4KB pages per 2MB block (2MB / 4KB = 512)
const PAGES_PER_2MB_BLOCK: usize = 512;

/// Words (u64) per 2MB block (512 pages / 64 bits per word = 8)
const WORDS_PER_2MB_BLOCK: usize = PAGES_PER_2MB_BLOCK / BITS_PER_WORD;

/// 2MB blocks per 1GB block (1GB / 2MB = 512)
const BLOCKS_2MB_PER_1GB: usize = 512;

/// 4KB pages per 1GB block
const PAGES_PER_1GB_BLOCK: usize = PAGES_PER_2MB_BLOCK * BLOCKS_2MB_PER_1GB;

/// Maximum 2MB blocks (256GB / 2MB = 131,072)
const MAX_2MB_BLOCKS: usize = MAX_BITMAP_PAGES / PAGES_PER_2MB_BLOCK;

/// Maximum 1GB blocks (256GB / 1GB = 256)
const MAX_1GB_BLOCKS: usize = MAX_2MB_BLOCKS / BLOCKS_2MB_PER_1GB;

// ============================================================================
// IOVA Granularity
// ============================================================================

/// IOVA allocation granularity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IovaGranularity {
    /// 4KB pages
    Page4K,
    /// 2MB super-pages
    Page2M,
    /// 1GB super-pages
    Page1G,
}

impl IovaGranularity {
    /// Get the size in bytes
    #[inline]
    pub const fn size_bytes(self) -> u64 {
        match self {
            IovaGranularity::Page4K => PAGE_SIZE_4K,
            IovaGranularity::Page2M => PAGE_SIZE_2M,
            IovaGranularity::Page1G => PAGE_SIZE_1G,
        }
    }

    /// Get the alignment mask
    #[inline]
    pub const fn align_mask(self) -> u64 {
        self.size_bytes() - 1
    }

    /// Get the size class index for magazine
    #[inline]
    const fn size_class(self) -> Option<usize> {
        match self {
            IovaGranularity::Page4K => Some(0),
            IovaGranularity::Page2M => Some(1),
            IovaGranularity::Page1G => Some(2), // Now supported via hierarchical bitmap
        }
    }
}

// ============================================================================
// Per-CPU Magazine Cache (IRQ-off Fast Path)
// ============================================================================

/// Single magazine for one size class
#[repr(C, align(64))] // Cache line aligned
pub struct Magazine {
    /// Cached IOVAs (stack-like, top at count-1)
    entries: [u64; MAGAZINE_CAPACITY],
    /// Number of valid entries
    count: usize,
}

impl Magazine {
    /// Create an empty magazine
    pub const fn new() -> Self {
        Self {
            entries: [0; MAGAZINE_CAPACITY],
            count: 0,
        }
    }

    /// Try to pop an IOVA from the magazine (O(1))
    #[inline]
    pub fn pop(&mut self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        Some(self.entries[self.count])
    }

    /// Try to push an IOVA to the magazine (O(1))
    #[inline]
    pub fn push(&mut self, iova: u64) -> bool {
        if self.count >= MAGAZINE_CAPACITY {
            return false; // Magazine full
        }
        self.entries[self.count] = iova;
        self.count += 1;
        true
    }

    /// Get current count
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ============================================================================
// Sub-Magazine (Per-CPU Claimed Word for Zero-Contention Allocation)
// ============================================================================

/// Per-CPU sub-magazine holding a claimed word (64 pages) for zero-contention allocation
///
/// Instead of doing CAS per-bit allocation from the shared bitmap, each CPU can
/// "claim" an entire word using `swap(0)` (single atomic op), then allocate from
/// that word locally without any synchronization.
///
/// # Benefits
/// - **64 allocations per atomic op**: One swap claims 64 pages
/// - **Zero contention**: Local allocation is pure arithmetic (no CAS loops)
/// - **Perfect for burst allocation**: Common in DMA buffer allocation
///
/// # Lifecycle
/// 1. CPU claims a word via `swap(0)` - word is now "owned" locally
/// 2. Allocate pages by finding set bits in `bits` (local tzcnt)
/// 3. When `bits == 0`, claim another word or fall back to magazine
/// 4. On CPU idle/shutdown, return remaining bits to bitmap
#[repr(C)]
pub struct SubMagazine {
    /// Bit mask of available pages (1 = free, 0 = allocated)
    /// When empty (0), need to claim a new word
    bits: u64,
    /// Word index in the detail bitmap that this sub-magazine owns
    /// Only valid when bits != 0
    word_idx: usize,
    /// Base IOVA for this word (cached for fast address calculation)
    /// Only valid when bits != 0
    base_iova: u64,
}

impl SubMagazine {
    /// Create an empty sub-magazine
    pub const fn new() -> Self {
        Self {
            bits: 0,
            word_idx: 0,
            base_iova: 0,
        }
    }

    /// Check if sub-magazine has available pages
    #[inline]
    pub fn has_pages(&self) -> bool {
        self.bits != 0
    }

    /// Allocate a single page from the sub-magazine (O(1), no atomics)
    ///
    /// Returns Some(iova) if successful, None if sub-magazine is empty.
    #[inline]
    pub fn allocate(&mut self) -> Option<u64> {
        if self.bits == 0 {
            return None;
        }

        // Find first set bit (free page)
        let bit_idx = self.bits.trailing_zeros() as usize;
        
        // Clear the bit (mark as allocated)
        self.bits &= !(1u64 << bit_idx);

        // Calculate IOVA
        Some(self.base_iova + (bit_idx as u64) * PAGE_SIZE_4K)
    }

    /// Claim a word from the bitmap (swap the word to 0, take ownership)
    ///
    /// Returns the number of pages claimed (popcount of claimed bits).
    #[inline]
    pub fn claim(&mut self, bits: u64, word_idx: usize, base_iova: u64) -> usize {
        self.bits = bits;
        self.word_idx = word_idx;
        self.base_iova = base_iova;
        bits.count_ones() as usize
    }

    /// Return remaining pages to the bitmap
    ///
    /// Returns (word_idx, bits) if there are remaining pages, None otherwise.
    #[inline]
    pub fn return_remaining(&mut self) -> Option<(usize, u64)> {
        if self.bits == 0 {
            return None;
        }
        let result = (self.word_idx, self.bits);
        self.bits = 0;
        Some(result)
    }

    /// Get remaining page count
    #[inline]
    pub fn remaining_count(&self) -> usize {
        self.bits.count_ones() as usize
    }

    /// Get the word index (only valid when has_pages())
    #[inline]
    pub fn word_idx(&self) -> usize {
        self.word_idx
    }
}

// ============================================================================
// Arena Owner Mode (Optimization 1)
// ============================================================================

/// Arena ownership state
/// 
/// Each arena can be in one of these states:
/// - Owned: A specific CPU owns this arena (fast path for owner)
/// - Contested: Multiple CPUs want this arena (slower path)
/// - Abandoned: Owner released the arena (up for grabs)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ArenaOwnerState {
    /// Arena is owned by a specific CPU (value stores owner CPU ID)
    Owned = 0,
    /// Arena is being contested (multiple CPUs want it)
    Contested = 1,
    /// Arena has been abandoned by previous owner
    Abandoned = 2,
}

/// Arena owner tracking
///
/// Tracks which CPU owns each arena for the Arena Owner optimization.
/// Owner CPU can perform lock-free operations on its arena.
/// Non-owners must use more careful synchronization.
#[derive(Debug)]
pub struct ArenaOwnership {
    /// Owner CPU ID for each arena (u16::MAX = no owner)
    /// Indexed by arena_id = word_idx / words_per_arena
    owners: alloc::boxed::Box<[AtomicU16]>,
    /// Number of words per arena
    words_per_arena: usize,
    /// Total number of arenas
    num_arenas: usize,
    /// Steal attempt counters per arena (for adaptive ownership)
    steal_counts: alloc::boxed::Box<[AtomicU32]>,
}

/// Invalid owner constant (no CPU assigned)
const ARENA_NO_OWNER: u16 = u16::MAX;

/// Threshold for steal count before ownership transfer
const ARENA_STEAL_THRESHOLD: u32 = 8;

impl ArenaOwnership {
    /// Create new arena ownership tracking
    pub fn new(total_words: usize, num_cpus: usize) -> Self {
        let words_per_arena = if num_cpus > 0 {
            (total_words + num_cpus - 1) / num_cpus
        } else {
            total_words
        };
        let num_arenas = if words_per_arena > 0 {
            (total_words + words_per_arena - 1) / words_per_arena
        } else {
            1
        };
        
        // Create owner array with initial ownership
        let mut owners = alloc::vec::Vec::with_capacity(num_arenas);
        for arena_id in 0..num_arenas {
            // Initial owner is the arena's natural CPU (arena_id % num_cpus)
            let initial_owner = if num_cpus > 0 {
                (arena_id % num_cpus) as u16
            } else {
                0
            };
            owners.push(AtomicU16::new(initial_owner));
        }
        
        // Create steal counters (all zero)
        let mut steal_counts = alloc::vec::Vec::with_capacity(num_arenas);
        for _ in 0..num_arenas {
            steal_counts.push(AtomicU32::new(0));
        }
        
        Self {
            owners: owners.into_boxed_slice(),
            words_per_arena,
            num_arenas,
            steal_counts: steal_counts.into_boxed_slice(),
        }
    }
    
    /// Get arena ID for a word index
    #[inline]
    pub fn arena_for_word(&self, word_idx: usize) -> usize {
        if self.words_per_arena == 0 {
            return 0;
        }
        word_idx / self.words_per_arena
    }
    
    /// Check if current CPU owns the arena containing this word
    #[inline]
    pub fn is_owner(&self, word_idx: usize, current_cpu: usize) -> bool {
        let arena_id = self.arena_for_word(word_idx);
        if arena_id >= self.owners.len() {
            return false;
        }
        self.owners[arena_id].load(Ordering::Relaxed) == current_cpu as u16
    }
    
    /// Try to claim ownership of an arena
    /// Returns true if successfully claimed
    #[inline]
    pub fn try_claim(&self, arena_id: usize, cpu_id: usize) -> bool {
        if arena_id >= self.owners.len() {
            return false;
        }
        
        // Only claim if currently unowned
        self.owners[arena_id]
            .compare_exchange(
                ARENA_NO_OWNER,
                cpu_id as u16,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok()
    }
    
    /// Release ownership of an arena
    #[inline]
    pub fn release(&self, arena_id: usize, cpu_id: usize) {
        if arena_id >= self.owners.len() {
            return;
        }
        
        let _ = self.owners[arena_id].compare_exchange(
            cpu_id as u16,
            ARENA_NO_OWNER,
            Ordering::AcqRel,
            Ordering::Relaxed,
        );
    }
    
    /// Record a steal attempt and check if ownership should transfer
    /// Returns true if ownership should transfer to the stealer
    #[inline]
    pub fn record_steal_and_check_transfer(&self, arena_id: usize) -> bool {
        if arena_id >= self.steal_counts.len() {
            return false;
        }
        
        let count = self.steal_counts[arena_id].fetch_add(1, Ordering::Relaxed);
        count + 1 >= ARENA_STEAL_THRESHOLD
    }
    
    /// Reset steal counter (after ownership transfer)
    #[inline]
    pub fn reset_steal_count(&self, arena_id: usize) {
        if arena_id < self.steal_counts.len() {
            self.steal_counts[arena_id].store(0, Ordering::Relaxed);
        }
    }
    
    /// Get current owner of an arena
    #[inline]
    pub fn get_owner(&self, arena_id: usize) -> Option<u16> {
        if arena_id >= self.owners.len() {
            return None;
        }
        let owner = self.owners[arena_id].load(Ordering::Relaxed);
        if owner == ARENA_NO_OWNER {
            None
        } else {
            Some(owner)
        }
    }
    
    /// Force transfer ownership (for adaptive rebalancing)
    #[inline]
    pub fn transfer_ownership(&self, arena_id: usize, old_owner: u16, new_owner: u16) -> bool {
        if arena_id >= self.owners.len() {
            return false;
        }
        
        self.owners[arena_id]
            .compare_exchange(old_owner, new_owner, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }
    
    /// Reconfigure arena ownership for a new CPU count
    ///
    /// Called when the actual CPU count is known (after bootstrap).
    /// Redistributes arena ownership among the available CPUs.
    pub fn reconfigure_for_cpus(&mut self, total_words: usize, num_cpus: usize) {
        let new_words_per_arena = if num_cpus > 0 {
            (total_words + num_cpus - 1) / num_cpus
        } else {
            total_words
        };
        let new_num_arenas = if new_words_per_arena > 0 {
            (total_words + new_words_per_arena - 1) / new_words_per_arena
        } else {
            1
        };
        
        // Resize owner and steal_count arrays if needed
        if new_num_arenas != self.num_arenas {
            let mut new_owners = alloc::vec::Vec::with_capacity(new_num_arenas);
            let mut new_steal_counts = alloc::vec::Vec::with_capacity(new_num_arenas);
            
            for arena_id in 0..new_num_arenas {
                let initial_owner = if num_cpus > 0 {
                    (arena_id % num_cpus) as u16
                } else {
                    0
                };
                new_owners.push(AtomicU16::new(initial_owner));
                new_steal_counts.push(AtomicU32::new(0));
            }
            
            self.owners = new_owners.into_boxed_slice();
            self.steal_counts = new_steal_counts.into_boxed_slice();
        } else {
            // Just reassign owners without reallocating
            for arena_id in 0..self.num_arenas {
                let new_owner = if num_cpus > 0 {
                    (arena_id % num_cpus) as u16
                } else {
                    0
                };
                self.owners[arena_id].store(new_owner, Ordering::Release);
                self.steal_counts[arena_id].store(0, Ordering::Release);
            }
        }
        
        self.words_per_arena = new_words_per_arena;
        self.num_arenas = new_num_arenas;
    }
    
    /// Get words per arena
    #[inline]
    pub fn words_per_arena(&self) -> usize {
        self.words_per_arena
    }
    
    /// Get number of arenas
    #[inline]
    pub fn num_arenas(&self) -> usize {
        self.num_arenas
    }
}

// ============================================================================
// Per-Arena Detail (Single-Writer Non-Atomic Bitmap)
// ============================================================================

/// Maximum words per arena (64 words = 4096 pages = 16MB per arena)
/// This allows the summary to fit in a single u64
const MAX_WORDS_PER_ARENA: usize = 64;

/// Per-arena non-atomic detail bitmap (single-writer optimization)
///
/// Only the owner CPU can read/write this structure directly.
/// Non-owners must use RemoteFreeRing to request frees.
///
/// # Single-Writer Guarantee
///
/// - **Allocations**: Only owner CPU allocates from this arena
/// - **Owner frees**: Owner directly updates `bits`
/// - **Non-owner frees**: Pushed to owner's RemoteFreeRing, drained by owner
/// - **Ownership transfer**: Happens at epoch boundaries (frozen during transfer)
///
/// # Benefits
///
/// - **No atomic RMW on hot path**: Direct bit manipulation
/// - **No CAS retries**: Single writer means no contention
/// - **Cache-local**: Owner's arena stays hot in L1/L2
/// - **Reduced cache line bouncing**: Other CPUs don't touch this data
///
/// # Memory Layout
///
/// Each arena covers up to 64 words (4096 pages = 16MB).
/// The `summary` field provides O(1) lookup for non-empty words.
#[repr(C, align(64))]
pub struct PerArenaDetail {
    /// Non-atomic bitmap words (owner-only access)
    /// bits[i] corresponds to global word index (word_start + i)
    /// 1 = free, 0 = allocated
    bits: [u64; MAX_WORDS_PER_ARENA],
    /// Arena ID (index into arenas array)
    arena_id: usize,
    /// Global word range [word_start, word_end)
    word_start: usize,
    word_end: usize,
    /// Number of valid words in this arena (may be < MAX_WORDS_PER_ARENA)
    num_words: usize,
    /// Local free page count (non-atomic, owner-maintained)
    free_count: usize,
    /// Local summary bits for fast scan within arena
    /// Bit i is set if bits[i] != 0 (has free pages)
    summary: u64,
    /// Owner CPU ID (cached for fast check)
    owner_cpu: u16,
    /// Frozen flag: set during ownership transfer
    /// When frozen, owner must not modify; transfer is in progress
    frozen: bool,
    /// Padding for alignment
    _pad: [u8; 5],
}

impl PerArenaDetail {
    /// Create a new per-arena detail for an arena
    ///
    /// # Arguments
    /// * `arena_id` - Index of this arena
    /// * `word_start` - First global word index
    /// * `word_end` - One past the last global word index
    /// * `owner_cpu` - Initial owner CPU ID
    /// * `initial_bits` - Initial bitmap values (from global detail)
    pub fn new(
        arena_id: usize,
        word_start: usize,
        word_end: usize,
        owner_cpu: u16,
        initial_bits: &[u64],
    ) -> Self {
        let num_words = (word_end - word_start).min(MAX_WORDS_PER_ARENA);
        let mut bits = [0u64; MAX_WORDS_PER_ARENA];
        let mut summary = 0u64;
        let mut free_count = 0usize;
        
        // Copy initial bits and build summary
        for i in 0..num_words {
            let b = if i < initial_bits.len() {
                initial_bits[i]
            } else {
                0
            };
            bits[i] = b;
            if b != 0 {
                summary |= 1u64 << i;
                free_count += b.count_ones() as usize;
            }
        }
        
        Self {
            bits,
            arena_id,
            word_start,
            word_end,
            num_words,
            free_count,
            summary,
            owner_cpu,
            frozen: false,
            _pad: [0; 5],
        }
    }
    
    /// Check if this arena has any free pages
    #[inline]
    pub fn has_free_pages(&self) -> bool {
        self.summary != 0
    }
    
    /// Get free page count
    #[inline]
    pub fn free_count(&self) -> usize {
        self.free_count
    }
    
    /// Check if arena is frozen (ownership transfer in progress)
    #[inline]
    pub fn is_frozen(&self) -> bool {
        self.frozen
    }
    
    /// Freeze the arena for ownership transfer
    #[inline]
    pub fn freeze(&mut self) {
        self.frozen = true;
    }
    
    /// Unfreeze the arena after ownership transfer
    #[inline]
    pub fn unfreeze(&mut self, new_owner: u16) {
        self.owner_cpu = new_owner;
        self.frozen = false;
    }
    
    /// Allocate a single page from this arena (O(1), no atomics!)
    ///
    /// # Safety
    /// Must only be called by the owner CPU under IRQ-off guard.
    ///
    /// # Returns
    /// Some(global_page_idx) if successful, None if arena is empty or frozen
    #[inline]
    pub fn allocate_page(&mut self) -> Option<usize> {
        if self.frozen || self.summary == 0 {
            return None;
        }
        
        // Find first word with free pages using tzcnt (O(1))
        let word_in_arena = self.summary.trailing_zeros() as usize;
        if word_in_arena >= self.num_words {
            return None;
        }
        
        let bits = self.bits[word_in_arena];
        if bits == 0 {
            // Summary was stale, update it
            self.summary &= !(1u64 << word_in_arena);
            // Retry with corrected summary
            return self.allocate_page();
        }
        
        // Find first free bit using tzcnt (O(1))
        let bit_idx = bits.trailing_zeros() as usize;
        
        // Clear the bit (allocate the page) - NO ATOMIC!
        self.bits[word_in_arena] &= !(1u64 << bit_idx);
        self.free_count -= 1;
        
        // Update summary if word is now empty
        if self.bits[word_in_arena] == 0 {
            self.summary &= !(1u64 << word_in_arena);
        }
        
        // Calculate global page index
        let global_word_idx = self.word_start + word_in_arena;
        let global_page_idx = global_word_idx * BITS_PER_WORD + bit_idx;
        
        Some(global_page_idx)
    }
    
    /// Claim an entire word from this arena (for sub-magazine refill)
    ///
    /// # Returns
    /// Some((global_word_idx, bits)) if successful, None if no non-empty words
    #[inline]
    pub fn claim_word(&mut self) -> Option<(usize, u64)> {
        if self.frozen || self.summary == 0 {
            return None;
        }
        
        // Find first word with free pages
        let word_in_arena = self.summary.trailing_zeros() as usize;
        if word_in_arena >= self.num_words {
            return None;
        }
        
        let bits = self.bits[word_in_arena];
        if bits == 0 {
            self.summary &= !(1u64 << word_in_arena);
            return self.claim_word();
        }
        
        // Take all bits from this word - NO ATOMIC!
        self.bits[word_in_arena] = 0;
        self.summary &= !(1u64 << word_in_arena);
        self.free_count -= bits.count_ones() as usize;
        
        let global_word_idx = self.word_start + word_in_arena;
        Some((global_word_idx, bits))
    }
    
    /// Free a single page back to this arena
    ///
    /// # Arguments
    /// * `global_page_idx` - Global page index to free
    ///
    /// # Returns
    /// true if the page was in this arena and freed, false otherwise
    #[inline]
    pub fn free_page(&mut self, global_page_idx: usize) -> bool {
        if self.frozen {
            return false;
        }
        
        let global_word_idx = global_page_idx / BITS_PER_WORD;
        if global_word_idx < self.word_start || global_word_idx >= self.word_end {
            return false; // Not in this arena
        }
        
        let word_in_arena = global_word_idx - self.word_start;
        if word_in_arena >= self.num_words {
            return false;
        }
        
        let bit_idx = global_page_idx % BITS_PER_WORD;
        let mask = 1u64 << bit_idx;
        
        // Check if already free (double-free detection)
        if self.bits[word_in_arena] & mask != 0 {
            // Already free - this is a bug, but don't corrupt state
            return false;
        }
        
        // Set the bit (free the page) - NO ATOMIC!
        self.bits[word_in_arena] |= mask;
        self.free_count += 1;
        
        // Update summary if word was empty
        self.summary |= 1u64 << word_in_arena;
        
        true
    }
    
    /// Return multiple pages (from RemoteFreeRing drain)
    ///
    /// # Arguments
    /// * `pages` - Slice of global page indices to free
    ///
    /// # Returns
    /// Number of pages successfully freed
    pub fn free_pages_batch(&mut self, pages: &[usize]) -> usize {
        if self.frozen {
            return 0;
        }
        
        let mut freed = 0;
        for &global_page_idx in pages {
            if self.free_page(global_page_idx) {
                freed += 1;
            }
        }
        freed
    }
    
    /// Sync this arena's state back to the global atomic bitmap
    ///
    /// Used during ownership transfer or when falling back to atomic path.
    /// Writes all local `bits` back to the corresponding global `detail` words.
    pub fn sync_to_global(&self, global_detail: &[AtomicU64]) {
        for i in 0..self.num_words {
            let global_idx = self.word_start + i;
            if global_idx < global_detail.len() {
                // Use store with Release ordering to make changes visible
                global_detail[global_idx].store(self.bits[i], Ordering::Release);
            }
        }
    }
    
    /// Sync from global atomic bitmap to this arena
    ///
    /// Used when taking ownership of an arena.
    pub fn sync_from_global(&mut self, global_detail: &[AtomicU64]) {
        self.summary = 0;
        self.free_count = 0;
        
        for i in 0..self.num_words {
            let global_idx = self.word_start + i;
            let bits = if global_idx < global_detail.len() {
                global_detail[global_idx].load(Ordering::Acquire)
            } else {
                0
            };
            self.bits[i] = bits;
            if bits != 0 {
                self.summary |= 1u64 << i;
                self.free_count += bits.count_ones() as usize;
            }
        }
        
        self.frozen = false;
    }
    
    /// Get the global word index for a local word index
    #[inline]
    pub fn global_word_idx(&self, local_idx: usize) -> usize {
        self.word_start + local_idx
    }
    
    /// Check if a global page index belongs to this arena
    #[inline]
    pub fn contains_page(&self, global_page_idx: usize) -> bool {
        let global_word_idx = global_page_idx / BITS_PER_WORD;
        global_word_idx >= self.word_start && global_word_idx < self.word_end
    }
}

/// Per-CPU magazine set (one magazine per size class)
///
/// Also holds per-CPU allocation hints and arena boundaries to avoid cache line
/// bounce on the global hint when multiple cores allocate simultaneously.
///
/// # Arena Sharding
///
/// Each CPU is assigned a preferred arena (range of words in the bitmap).
/// Allocations first try the local arena, then steal from other arenas if needed.
/// This dramatically reduces contention on multi-core systems.
///
/// # Per-CPU Free Word Stack
///
/// Each CPU maintains a local stack of non-empty word indices. When a word
/// transitions 0→non-zero (via free), the index is pushed to the local stack.
/// On allocation, pop from the local stack first for O(1) allocation.
/// This eliminates the race condition in the previous global lock-free design.
///
/// # Single-Writer Arena (Non-Atomic Fast Path)
///
/// Each CPU has an optional `PerArenaDetail` for single-writer allocation.
/// When enabled, allocations bypass atomic operations entirely:
/// - Owner CPU allocates directly from non-atomic `arena_detail.bits`
/// - Non-owner frees are routed through `remote_free_ring`
/// - Ownership transfers happen at epoch boundaries
#[repr(C, align(128))] // Two cache lines to avoid false sharing
pub struct PerCpuMagazine {
    /// This CPU's ID (for arena ownership tracking)
    pub cpu_id: usize,
    /// Magazines indexed by size class
    magazines: [IrqMutex<Magazine>; MAGAZINE_SIZE_CLASSES],
    /// Per-CPU hint for 4KB allocation (word index to start searching)
    pub hint_4k: AtomicUsize,
    /// Per-CPU hint for 2MB allocation (block index to start searching)
    pub hint_2m: AtomicUsize,
    /// Per-CPU hint for partial 2MB blocks (for hugepage-preserving 4KB alloc)
    pub hint_2m_partial: AtomicUsize,
    /// Per-CPU hint offset (scattered to avoid initial contention)
    /// Added to arena_start to prevent all CPUs starting at same point
    pub hint_offset: usize,
    /// Start of this CPU's preferred arena (4KB word index, inclusive)
    pub arena_start_4k: usize,
    /// End of this CPU's preferred arena (4KB word index, exclusive)
    pub arena_end_4k: usize,
    /// Start of this CPU's preferred arena (2MB block index, inclusive)
    pub arena_start_2m: usize,
    /// End of this CPU's preferred arena (2MB block index, exclusive)
    pub arena_end_2m: usize,
    /// Per-CPU local free word stack (IRQ-off protected, no atomics needed)
    pub free_word_stack: IrqMutex<LocalFreeWordStack>,
    /// Per-CPU free page counter delta (reduces global counter updates)
    pub free_count_delta_4k: AtomicI64,
    /// Per-CPU free 2MB block counter delta
    pub free_count_delta_2m: AtomicI64,
    /// Remote free ring: receives frees from other CPUs for this CPU's arena
    /// Lock-free MPSC: other CPUs push, this CPU drains
    pub remote_free_ring: RemoteFreeRing,
    /// Sub-magazine: claimed word (64 pages) for zero-contention allocation
    /// Protected by IRQ-off (same as free_word_stack)
    pub sub_magazine_4k: IrqMutex<SubMagazine>,
    /// Single-writer arena detail (non-atomic fast path)
    /// None until initialized by IovaAllocatorFast::init_single_writer_arenas()
    pub arena_detail: IrqMutex<Option<PerArenaDetail>>,
    /// Flag indicating if single-writer mode is active for this CPU
    pub single_writer_enabled: AtomicBool,
}

impl PerCpuMagazine {
    /// Create empty per-CPU magazines with default (full-range) arena
    pub const fn new() -> Self {
        Self {
            cpu_id: 0, // Will be set by set_arena()
            magazines: [
                IrqMutex::new(Magazine::new()), // 4KB
                IrqMutex::new(Magazine::new()), // 2MB
                IrqMutex::new(Magazine::new()), // 1GB
            ],
            hint_4k: AtomicUsize::new(0),
            hint_2m: AtomicUsize::new(0),
            hint_2m_partial: AtomicUsize::new(0),
            hint_offset: 0,
            // Default: full range (will be configured by IovaAllocatorFast::new)
            arena_start_4k: 0,
            arena_end_4k: usize::MAX,
            arena_start_2m: 0,
            arena_end_2m: usize::MAX,
            free_word_stack: IrqMutex::new(LocalFreeWordStack::new()),
            free_count_delta_4k: AtomicI64::new(0),
            free_count_delta_2m: AtomicI64::new(0),
            remote_free_ring: RemoteFreeRing::new(),
            sub_magazine_4k: IrqMutex::new(SubMagazine::new()),
            // Single-writer arena: None until enabled
            arena_detail: IrqMutex::new(None),
            single_writer_enabled: AtomicBool::new(false),
        }
    }

    /// Configure this CPU's arena boundaries
    /// 
    /// # 5C: Hint Scattering
    /// cpu_id is used to scatter the initial hint position within the arena,
    /// preventing all CPUs from starting at the same point and reducing
    /// contention at startup or under heavy load.
    ///
    /// # Arena Owner Optimization
    /// The cpu_id is stored for use in arena ownership tracking.
    pub fn set_arena(&mut self, cpu_id: usize, start_4k: usize, end_4k: usize, start_2m: usize, end_2m: usize) {
        self.cpu_id = cpu_id;
        self.arena_start_4k = start_4k;
        self.arena_end_4k = end_4k;
        self.arena_start_2m = start_2m;
        self.arena_end_2m = end_2m;
        
        // 5C: Scatter hint offset based on cpu_id to reduce contention
        // Use golden ratio-based scattering for even distribution
        let arena_size_4k = end_4k.saturating_sub(start_4k);
        let arena_size_2m = end_2m.saturating_sub(start_2m);
        
        // Golden ratio ≈ 0.618... → multiply by (2^32 * 0.618) ≈ 0x9E3779B9
        let scatter_4k = ((cpu_id as u64).wrapping_mul(0x9E3779B9) as usize) % arena_size_4k.max(1);
        let scatter_2m = ((cpu_id as u64).wrapping_mul(0x9E3779B9) as usize) % arena_size_2m.max(1);
        
        self.hint_offset = scatter_4k;
        self.hint_4k = AtomicUsize::new(start_4k + scatter_4k);
        self.hint_2m = AtomicUsize::new(start_2m + scatter_2m);
        self.hint_2m_partial = AtomicUsize::new(start_2m + scatter_2m);
        
        // Initialize remote free ring sequences
        self.remote_free_ring.init();
    }
    
    /// Initialize single-writer arena for this CPU
    ///
    /// Called by IovaAllocatorFast after bitmap is created.
    /// Copies the relevant portion of the global bitmap into the local arena.
    pub fn init_single_writer_arena(&self, global_detail: &[AtomicU64]) {
        let mut arena_guard = self.arena_detail.lock();
        
        // Calculate the number of words in this arena
        let num_words = self.arena_end_4k.saturating_sub(self.arena_start_4k);
        if num_words == 0 || num_words > MAX_WORDS_PER_ARENA {
            // Arena too large or empty, disable single-writer
            *arena_guard = None;
            self.single_writer_enabled.store(false, Ordering::Release);
            return;
        }
        
        // Copy initial bits from global detail
        let mut initial_bits = alloc::vec::Vec::with_capacity(num_words);
        for i in 0..num_words {
            let global_idx = self.arena_start_4k + i;
            let bits = if global_idx < global_detail.len() {
                global_detail[global_idx].load(Ordering::Acquire)
            } else {
                0
            };
            initial_bits.push(bits);
        }
        
        // Create per-arena detail
        let arena = PerArenaDetail::new(
            self.cpu_id,
            self.arena_start_4k,
            self.arena_end_4k,
            self.cpu_id as u16,
            &initial_bits,
        );
        
        *arena_guard = Some(arena);
        self.single_writer_enabled.store(true, Ordering::Release);
    }
    
    /// Check if single-writer mode is enabled
    #[inline]
    pub fn is_single_writer_enabled(&self) -> bool {
        self.single_writer_enabled.load(Ordering::Acquire)
    }

    /// Get magazine for a size class
    #[inline]
    pub fn get(&self, size_class: usize) -> Option<&IrqMutex<Magazine>> {
        self.magazines.get(size_class)
    }

    /// Flush per-CPU counter deltas to global counters
    ///
    /// Returns (delta_4k, delta_2m) that were flushed
    pub fn flush_counter_deltas(&self) -> (i64, i64) {
        let delta_4k = self.free_count_delta_4k.swap(0, Ordering::Relaxed);
        let delta_2m = self.free_count_delta_2m.swap(0, Ordering::Relaxed);
        (delta_4k, delta_2m)
    }
}

// ============================================================================
// Free Word Stack (Non-Empty Word Index List for O(1) Allocation)
// ============================================================================

/// Capacity of the free word stack per CPU
/// Smaller than global since it's per-CPU and protected by IRQ-off
const FREE_WORD_STACK_CAPACITY: usize = 256;

/// Per-CPU local stack of non-empty word indices (IRQ-off protected, no CAS needed)
///
/// When a word transitions from 0 to non-zero (via free), its index is pushed.
/// When allocating, pop an index and try to allocate from that word.
///
/// # Design Decisions
///
/// - **Per-CPU isolation**: Each CPU has its own stack, eliminating contention
/// - **IRQ-off protected**: Push/pop are done under IRQ-off guard (no atomics needed)
/// - **Duplicate pushes allowed**: A word index may appear multiple times.
///   On pop, we validate the word is still non-zero before using it.
/// - **Bounded capacity**: If the stack is full, we don't push (fallback to scan).
/// - **Cross-CPU return**: When freeing pages allocated by another CPU, the word
///   index is still pushed to the local (freeing CPU's) stack. This is fine because
///   we validate on pop anyway.
///
/// This eliminates the race condition in the previous global lock-free stack design
/// where push could increment top before writing the entry, causing pop to read INVALID.
#[repr(C, align(64))]
pub struct LocalFreeWordStack {
    /// Stack entries (word indices)
    entries: [usize; FREE_WORD_STACK_CAPACITY],
    /// Stack top (number of valid entries)
    top: usize,
}

impl LocalFreeWordStack {
    /// Create a new empty stack
    pub const fn new() -> Self {
        Self {
            entries: [0; FREE_WORD_STACK_CAPACITY],
            top: 0,
        }
    }

    /// Push a word index onto the stack (O(1), IRQ-off required)
    ///
    /// Returns true if pushed, false if stack is full.
    #[inline]
    pub fn push(&mut self, word_idx: usize) -> bool {
        if self.top >= FREE_WORD_STACK_CAPACITY {
            return false; // Stack full
        }
        self.entries[self.top] = word_idx;
        self.top += 1;
        true
    }

    /// Pop a word index from the stack (O(1), IRQ-off required)
    ///
    /// Returns Some(word_idx) if available, None if stack is empty.
    /// The caller must validate that the word is still non-zero.
    #[inline]
    pub fn pop(&mut self) -> Option<usize> {
        if self.top == 0 {
            return None; // Stack empty
        }
        self.top -= 1;
        Some(self.entries[self.top])
    }

    /// Get current count
    #[inline]
    pub fn len(&self) -> usize {
        self.top
    }

    /// Check if empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.top == 0
    }

    /// Clear the stack
    #[inline]
    pub fn clear(&mut self) {
        self.top = 0;
    }
}

/// Legacy global lock-free stack (kept for backward compatibility / stats)
///
/// This is a simpler atomic counter for approximate stats only.
/// The actual free word tracking is now per-CPU via LocalFreeWordStack.
#[repr(C, align(64))]
pub struct FreeWordStack {
    /// Approximate count of non-empty words (for stats, not allocation)
    approx_count: AtomicUsize,
}

impl FreeWordStack {
    /// Create a new empty stack
    pub const fn new() -> Self {
        Self {
            approx_count: AtomicUsize::new(0),
        }
    }

    /// Increment approximate count (called when word becomes non-empty)
    #[inline]
    pub fn notify_non_empty(&self) {
        self.approx_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement approximate count (called when word becomes empty)
    #[inline]
    pub fn notify_empty(&self) {
        self.approx_count.fetch_sub(1, Ordering::Relaxed);
    }

    /// Get approximate count (for stats)
    #[inline]
    pub fn len(&self) -> usize {
        self.approx_count.load(Ordering::Relaxed)
    }

    /// Check if empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ============================================================================
// Quarantine Ring Buffer (Epoch-Based Delayed Reclamation)
// ============================================================================

/// Capacity of per-CPU quarantine ring buffer
const QUARANTINE_CAPACITY: usize = 256;

/// Entry in the quarantine ring buffer
#[derive(Clone, Copy)]
pub struct QuarantineEntry {
    /// IOVA address to be freed
    pub iova: u64,
    /// Size class: 0 = 4KB, 1 = 2MB, 2 = 1GB
    pub size_class: u8,
    /// Epoch when this entry was quarantined
    pub epoch: u32,
}

impl QuarantineEntry {
    pub const fn empty() -> Self {
        Self {
            iova: 0,
            size_class: 0,
            epoch: 0,
        }
    }
}

/// Per-CPU quarantine ring buffer for delayed IOVA reclamation
///
/// IOVAs are not returned to the bitmap immediately after free. Instead,
/// they are placed in a quarantine ring. After IOTLB invalidation completes
/// (or the epoch advances), quarantined entries are batch-returned to the bitmap.
///
/// # Benefits
/// - Prevents IOTLB stale entry issues (UAF via DMA)
/// - Reduces bitmap write frequency (batch returns)
/// - Synergizes with zombie_queue for async cleanup
///
/// # Thread Safety
/// - Each CPU has its own quarantine ring (no contention)
/// - Protected by IRQ-off guard
#[repr(C, align(128))]
pub struct QuarantineRing {
    /// Ring buffer entries
    entries: [QuarantineEntry; QUARANTINE_CAPACITY],
    /// Write position (head)
    head: usize,
    /// Read position (tail, for drain)
    tail: usize,
    /// Number of valid entries
    count: usize,
}

impl QuarantineRing {
    /// Create an empty quarantine ring
    pub const fn new() -> Self {
        Self {
            entries: [QuarantineEntry::empty(); QUARANTINE_CAPACITY],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    /// Try to add an entry to quarantine (O(1))
    ///
    /// Returns false if the ring is full (caller should drain first).
    #[inline]
    pub fn push(&mut self, iova: u64, size_class: u8, epoch: u32) -> bool {
        if self.count >= QUARANTINE_CAPACITY {
            return false;
        }
        
        self.entries[self.head] = QuarantineEntry {
            iova,
            size_class,
            epoch,
        };
        self.head = (self.head + 1) % QUARANTINE_CAPACITY;
        self.count += 1;
        true
    }

    /// Pop entries that are older than the given epoch
    ///
    /// Returns up to `max` entries that have epoch <= completed_epoch.
    /// Entries are removed from the ring.
    pub fn drain_older_than(&mut self, completed_epoch: u32, max: usize, out: &mut [QuarantineEntry]) -> usize {
        let mut drained = 0;
        
        while drained < max && drained < out.len() && self.count > 0 {
            let entry = &self.entries[self.tail];
            
            // Only drain if epoch has passed
            // Handle wrap-around: completed_epoch - entry.epoch should be positive
            // Using signed comparison to handle wrap
            let age = completed_epoch.wrapping_sub(entry.epoch) as i32;
            if age < 0 {
                // Entry is from a future epoch, stop draining
                break;
            }
            
            out[drained] = *entry;
            self.tail = (self.tail + 1) % QUARANTINE_CAPACITY;
            self.count -= 1;
            drained += 1;
        }
        
        drained
    }

    /// Force drain all entries (for shutdown or emergency)
    pub fn drain_all(&mut self, out: &mut [QuarantineEntry]) -> usize {
        let mut drained = 0;
        
        while drained < out.len() && self.count > 0 {
            out[drained] = self.entries[self.tail];
            self.tail = (self.tail + 1) % QUARANTINE_CAPACITY;
            self.count -= 1;
            drained += 1;
        }
        
        drained
    }

    /// Get current count
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if full
    #[inline]
    pub fn is_full(&self) -> bool {
        self.count >= QUARANTINE_CAPACITY
    }
}

// ============================================================================
// Remote Free Ring (Cross-CPU Free Aggregation for Owner-Based Bitmap Access)
// ============================================================================

/// Capacity of remote free ring per CPU
/// Must be power of 2 for efficient modulo operation
const REMOTE_FREE_RING_CAPACITY: usize = 512;

/// Entry in the remote free ring
#[derive(Clone, Copy)]
pub struct RemoteFreeEntry {
    /// IOVA address to be freed
    pub iova: u64,
    /// Size class: 0 = 4KB, 1 = 2MB, 2 = 1GB
    pub size_class: u8,
}

impl RemoteFreeEntry {
    pub const fn empty() -> Self {
        Self {
            iova: 0,
            size_class: 0,
        }
    }
}

/// Lock-free MPSC (Multi-Producer Single-Consumer) ring for remote frees
///
/// When a CPU frees an IOVA that belongs to another CPU's arena, it pushes
/// the IOVA to the owner CPU's remote free ring. The owner CPU periodically
/// drains this ring and updates its bitmap.
///
/// # Design (Vyukov MPSC with Sequences)
///
/// Uses sequence numbers to avoid the "hole" problem where producers reserve
/// slots but haven't written yet:
/// - seq == pos: slot is ready for producer at position `pos`
/// - seq == pos + 1: slot contains committed data for consumer
/// - Producer: CAS head to reserve → write data → update seq (commit)
/// - Consumer: check seq to verify data is committed before reading
///
/// # Benefits
///
/// - **No holes**: Consumer never reads uncommitted data
/// - **Lock-free push**: Multiple CPUs can push concurrently using CAS on head
/// - **Single-consumer pop**: Only the owner CPU drains (no contention on tail)
/// - **Bounded capacity**: If full, pusher falls back to direct bitmap update
#[repr(C, align(128))]
pub struct RemoteFreeRing {
    /// Ring buffer entries (lock-free, written by pushers)
    entries: [AtomicU64; REMOTE_FREE_RING_CAPACITY],
    /// Size classes packed separately (to keep entries as simple u64)
    size_classes: [AtomicU8; REMOTE_FREE_RING_CAPACITY],
    /// Sequence numbers for each slot (Vyukov protocol)
    sequences: [AtomicUsize; REMOTE_FREE_RING_CAPACITY],
    /// Write position (head), incremented by pushers via CAS
    head: AtomicUsize,
    // --- Cache line boundary ---
    /// Read position (tail), only modified by owner CPU
    tail: AtomicUsize,
    /// Overflow counter (pushes that failed due to full ring)
    overflow_count: AtomicU64,
}

/// Atomic u8 wrapper (since core doesn't have AtomicU8 on all platforms)
#[repr(transparent)]
pub struct AtomicU8(AtomicUsize);

impl AtomicU8 {
    pub const fn new(v: u8) -> Self {
        Self(AtomicUsize::new(v as usize))
    }
    
    #[inline]
    pub fn store(&self, v: u8, order: Ordering) {
        self.0.store(v as usize, order);
    }
    
    #[inline]
    pub fn load(&self, order: Ordering) -> u8 {
        self.0.load(order) as u8
    }
    
    /// Atomically AND with a value, returning the previous value
    #[inline]
    pub fn fetch_and(&self, val: u8, order: Ordering) -> u8 {
        // Use CAS loop since AtomicUsize operations affect all bits
        loop {
            let current = self.0.load(Ordering::Acquire);
            let new_val = (current as u8) & val;
            if self.0.compare_exchange_weak(
                current,
                new_val as usize,
                order,
                Ordering::Relaxed,
            ).is_ok() {
                return current as u8;
            }
            core::hint::spin_loop();
        }
    }
    
    /// Atomically OR with a value, returning the previous value
    #[inline]
    pub fn fetch_or(&self, val: u8, order: Ordering) -> u8 {
        // Use CAS loop since AtomicUsize operations affect all bits
        loop {
            let current = self.0.load(Ordering::Acquire);
            let new_val = (current as u8) | val;
            if self.0.compare_exchange_weak(
                current,
                new_val as usize,
                order,
                Ordering::Relaxed,
            ).is_ok() {
                return current as u8;
            }
            core::hint::spin_loop();
        }
    }
}

impl RemoteFreeRing {
    /// Create a new empty remote free ring (Vyukov MPSC)
    pub const fn new() -> Self {
        const EMPTY_ENTRY: AtomicU64 = AtomicU64::new(0);
        const EMPTY_SIZE: AtomicU8 = AtomicU8::new(0);
        const INIT_SEQ: AtomicUsize = AtomicUsize::new(0);
        Self {
            entries: [EMPTY_ENTRY; REMOTE_FREE_RING_CAPACITY],
            size_classes: [EMPTY_SIZE; REMOTE_FREE_RING_CAPACITY],
            sequences: [INIT_SEQ; REMOTE_FREE_RING_CAPACITY],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            overflow_count: AtomicU64::new(0),
        }
    }
    
    /// Initialize sequence numbers (call once after construction)
    /// Each slot i starts with sequence = i, meaning "ready for producer at pos i"
    pub fn init(&self) {
        for i in 0..REMOTE_FREE_RING_CAPACITY {
            self.sequences[i].store(i, Ordering::Relaxed);
        }
    }
    
    /// Try to push an entry (lock-free Vyukov MPSC, called by non-owner CPUs)
    ///
    /// Returns true if pushed successfully, false if ring is full.
    /// No "holes" possible: uses CAS to reserve slot, then commits with sequence update.
    #[inline]
    pub fn try_push(&self, iova: u64, size_class: u8) -> bool {
        let mut pos = self.head.load(Ordering::Relaxed);
        
        loop {
            let idx = pos % REMOTE_FREE_RING_CAPACITY;
            let seq = self.sequences[idx].load(Ordering::Acquire);
            let diff = seq as isize - pos as isize;
            
            if diff == 0 {
                // Slot is ready for this position, try to claim it
                match self.head.compare_exchange_weak(
                    pos,
                    pos.wrapping_add(1),
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        // Successfully reserved slot, write data
                        self.size_classes[idx].store(size_class, Ordering::Relaxed);
                        self.entries[idx].store(iova, Ordering::Relaxed);
                        // Commit: set seq = pos + 1 to signal consumer
                        self.sequences[idx].store(pos.wrapping_add(1), Ordering::Release);
                        return true;
                    }
                    Err(new_pos) => {
                        pos = new_pos; // Retry with updated head
                    }
                }
            } else if diff < 0 {
                // Ring is full (consumer hasn't caught up)
                self.overflow_count.fetch_add(1, Ordering::Relaxed);
                return false;
            } else {
                // Another producer is still writing to this slot, reload head
                pos = self.head.load(Ordering::Relaxed);
            }
            core::hint::spin_loop();
        }
    }
    
    /// Drain entries from the ring (single-consumer Vyukov, called by owner CPU only)
    ///
    /// Returns the number of entries drained.
    /// Only reads slots where sequence indicates data is committed (no holes!)
    pub fn drain(&self, out: &mut [RemoteFreeEntry]) -> usize {
        let mut drained = 0;
        let mut pos = self.tail.load(Ordering::Relaxed);
        
        while drained < out.len() {
            let idx = pos % REMOTE_FREE_RING_CAPACITY;
            let seq = self.sequences[idx].load(Ordering::Acquire);
            let expected_seq = pos.wrapping_add(1);
            
            if seq != expected_seq {
                // Slot not ready (either empty or producer still writing)
                break;
            }
            
            // Read data (order doesn't matter, seq acquire already synchronized)
            let iova = self.entries[idx].load(Ordering::Relaxed);
            let size_class = self.size_classes[idx].load(Ordering::Relaxed);
            
            // Reset sequence for next producer: seq = pos + CAPACITY
            self.sequences[idx].store(pos.wrapping_add(REMOTE_FREE_RING_CAPACITY), Ordering::Release);
            
            out[drained] = RemoteFreeEntry { iova, size_class };
            drained += 1;
            pos = pos.wrapping_add(1);
        }
        
        // Update tail if we drained anything
        if drained > 0 {
            self.tail.store(pos, Ordering::Release);
        }
        
        drained
    }
    
    /// Get approximate number of pending entries
    #[inline]
    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        head.wrapping_sub(tail).min(REMOTE_FREE_RING_CAPACITY)
    }
    
    /// Check if ring appears empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Relaxed) == self.tail.load(Ordering::Relaxed)
    }
    
    /// Get overflow count (failed pushes)
    #[inline]
    pub fn overflow_count(&self) -> u64 {
        self.overflow_count.load(Ordering::Relaxed)
    }
}

// ============================================================================
// Range Free Result (for allocate_contiguous word-level skip)
// ============================================================================

/// Result of is_range_free_with_skip check
///
/// Used by allocate_contiguous to efficiently skip past allocated regions.
enum RangeFreeResult {
    /// Range is free, can proceed with allocation
    Free,
    /// Range is not free, skip to this page index for next attempt
    NotFree { skip_to_page: usize },
}

// ============================================================================
// 2MB Buddy Allocator (Optimization 4)
// ============================================================================

/// Maximum buddy order for 2MB blocks
/// Order 0 = 1 block (2MB), Order 1 = 2 blocks (4MB), ..., Order 9 = 512 blocks (1GB)
const BUDDY_2M_MAX_ORDER: usize = 10;

/// Free list entry for 2MB buddy allocator
/// Each order has a bitmap tracking free buddy blocks at that order.
/// Order k has blocks of size 2^k × 2MB, with alignment 2^k × 2MB.
#[derive(Debug)]
struct Buddy2mFreeList {
    /// Bitmap of free blocks at each order
    /// For order k: bit i is set if block starting at i*2^k is free at this order
    /// Order 0: 1 bit per 2MB block
    /// Order 1: 1 bit per 4MB region (2 consecutive 2MB blocks)
    /// etc.
    bitmap: [alloc::boxed::Box<[AtomicU64]>; BUDDY_2M_MAX_ORDER],
    /// Count of free blocks at each order
    free_count: [AtomicUsize; BUDDY_2M_MAX_ORDER],
}

impl Buddy2mFreeList {
    /// Create a new buddy free list for the given number of 2MB blocks
    fn new(total_2mb_blocks: usize) -> Self {
        use alloc::boxed::Box;
        
        // Helper to create bitmap for a given order
        fn make_bitmap(total_2mb_blocks: usize, order: usize) -> alloc::boxed::Box<[AtomicU64]> {
            let blocks_at_order = (total_2mb_blocks + (1 << order) - 1) >> order;
            let words_needed = (blocks_at_order + BITS_PER_WORD - 1) / BITS_PER_WORD;
            let mut v = alloc::vec::Vec::with_capacity(words_needed.max(1));
            for _ in 0..words_needed.max(1) {
                v.push(AtomicU64::new(0));
            }
            v.into_boxed_slice()
        }
        
        // Initialize bitmaps for each order manually (AtomicU64 is not Clone)
        let bitmap: [Box<[AtomicU64]>; BUDDY_2M_MAX_ORDER] = [
            make_bitmap(total_2mb_blocks, 0),
            make_bitmap(total_2mb_blocks, 1),
            make_bitmap(total_2mb_blocks, 2),
            make_bitmap(total_2mb_blocks, 3),
            make_bitmap(total_2mb_blocks, 4),
            make_bitmap(total_2mb_blocks, 5),
            make_bitmap(total_2mb_blocks, 6),
            make_bitmap(total_2mb_blocks, 7),
            make_bitmap(total_2mb_blocks, 8),
            make_bitmap(total_2mb_blocks, 9),
        ];
        
        let free_count: [AtomicUsize; BUDDY_2M_MAX_ORDER] = [
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
        ];
        
        Self { bitmap, free_count }
    }
    
    /// Set a block as free at the given order
    fn set_free(&self, order: usize, block_idx: usize) {
        if order >= BUDDY_2M_MAX_ORDER {
            return;
        }
        let word_idx = block_idx / BITS_PER_WORD;
        let bit_idx = block_idx % BITS_PER_WORD;
        if word_idx < self.bitmap[order].len() {
            let old = self.bitmap[order][word_idx].fetch_or(1u64 << bit_idx, Ordering::AcqRel);
            if old & (1u64 << bit_idx) == 0 {
                self.free_count[order].fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    
    /// Clear a block as allocated at the given order
    fn set_allocated(&self, order: usize, block_idx: usize) {
        if order >= BUDDY_2M_MAX_ORDER {
            return;
        }
        let word_idx = block_idx / BITS_PER_WORD;
        let bit_idx = block_idx % BITS_PER_WORD;
        if word_idx < self.bitmap[order].len() {
            let old = self.bitmap[order][word_idx].fetch_and(!(1u64 << bit_idx), Ordering::AcqRel);
            if old & (1u64 << bit_idx) != 0 {
                self.free_count[order].fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
    
    /// Check if a block is free at the given order
    fn is_free(&self, order: usize, block_idx: usize) -> bool {
        if order >= BUDDY_2M_MAX_ORDER {
            return false;
        }
        let word_idx = block_idx / BITS_PER_WORD;
        let bit_idx = block_idx % BITS_PER_WORD;
        if word_idx < self.bitmap[order].len() {
            self.bitmap[order][word_idx].load(Ordering::Acquire) & (1u64 << bit_idx) != 0
        } else {
            false
        }
    }
    
    /// Find and allocate a free block at the given order
    /// Returns the block index if found, None otherwise
    fn find_and_allocate(&self, order: usize) -> Option<usize> {
        if order >= BUDDY_2M_MAX_ORDER {
            return None;
        }
        
        for word_idx in 0..self.bitmap[order].len() {
            let mut word = self.bitmap[order][word_idx].load(Ordering::Acquire);
            while word != 0 {
                let bit_idx = word.trailing_zeros() as usize;
                let block_idx = word_idx * BITS_PER_WORD + bit_idx;
                
                // Try to clear the bit atomically
                let mask = 1u64 << bit_idx;
                let old = self.bitmap[order][word_idx].fetch_and(!mask, Ordering::AcqRel);
                if old & mask != 0 {
                    // Successfully allocated
                    self.free_count[order].fetch_sub(1, Ordering::Relaxed);
                    return Some(block_idx);
                }
                
                // CAS failed, reload and retry
                word = self.bitmap[order][word_idx].load(Ordering::Acquire);
            }
        }
        
        None
    }
    
    /// Get the count of free blocks at the given order
    fn count(&self, order: usize) -> usize {
        if order >= BUDDY_2M_MAX_ORDER {
            0
        } else {
            self.free_count[order].load(Ordering::Relaxed)
        }
    }
}

// ============================================================================
// TLSF (Two-Level Segregated Fit) for Variable-Size Contiguous Allocation
// Optimization 3: O(1) variable-size allocation
// ============================================================================

/// First-level index bits (log2 of size class)
/// Covers sizes from 2^4 = 16 pages (64KB) to 2^20 = 1M pages (4GB)
const TLSF_FLI_MIN: usize = 4;  // Minimum: 16 pages = 64KB
const TLSF_FLI_MAX: usize = 20; // Maximum: 1M pages = 4GB
const TLSF_FLI_COUNT: usize = TLSF_FLI_MAX - TLSF_FLI_MIN + 1; // 17 first-level classes

/// Second-level index bits (subdivision within each first-level class)
const TLSF_SLI_BITS: usize = 4;
const TLSF_SLI_COUNT: usize = 1 << TLSF_SLI_BITS; // 16 second-level classes

/// Free block header stored at the beginning of each free block
/// Uses a doubly-linked list for efficient insertion/removal
#[derive(Debug)]
struct TlsfFreeBlock {
    /// Size of this block in pages
    size: usize,
    /// Start page index of this block
    start_page: usize,
    /// Previous free block in same size class (page index, or usize::MAX if none)
    prev: AtomicUsize,
    /// Next free block in same size class (page index, or usize::MAX if none)
    next: AtomicUsize,
}

/// TLSF allocator for variable-size contiguous IOVA ranges
#[derive(Debug)]
struct TlsfAllocator {
    /// First-level bitmap: bit i is set if there's a free block in FLI class i
    fl_bitmap: AtomicU32,
    /// Second-level bitmaps: sl_bitmap[fli] has bit j set if free block exists
    /// at size class (fli, sli)
    sl_bitmap: [AtomicU16; TLSF_FLI_COUNT],
    /// Free block headers, indexed by start page
    /// Only stores headers for blocks that are in the free list
    /// Note: This is a sparse structure - most entries will be empty
    headers: alloc::boxed::Box<[Option<TlsfFreeBlock>]>,
    /// Head of free list for each (fli, sli) pair: start_page or usize::MAX
    free_lists: [[AtomicUsize; TLSF_SLI_COUNT]; TLSF_FLI_COUNT],
    /// Total pages managed
    total_pages: usize,
}

impl TlsfAllocator {
    /// Create a new TLSF allocator
    fn new(total_pages: usize) -> Self {
        use alloc::vec::Vec;
        
        // Initialize free list heads to usize::MAX (empty)
        let free_lists: [[AtomicUsize; TLSF_SLI_COUNT]; TLSF_FLI_COUNT] = 
            core::array::from_fn(|_| core::array::from_fn(|_| AtomicUsize::new(usize::MAX)));
        
        // Initialize headers as None (no free blocks initially)
        // In practice, we'll only allocate headers for active free blocks
        let headers_count = total_pages.min(1024 * 1024); // Cap for memory efficiency
        let mut headers_vec = Vec::with_capacity(headers_count);
        for _ in 0..headers_count {
            headers_vec.push(None);
        }
        
        Self {
            fl_bitmap: AtomicU32::new(0),
            sl_bitmap: core::array::from_fn(|_| AtomicU16::new(0)),
            headers: headers_vec.into_boxed_slice(),
            free_lists,
            total_pages,
        }
    }
    
    /// Calculate first-level index for a size
    #[inline]
    fn fli_for_size(size: usize) -> usize {
        if size < (1 << TLSF_FLI_MIN) {
            return 0;
        }
        let msb = (usize::BITS - size.leading_zeros()) as usize - 1;
        (msb - TLSF_FLI_MIN).min(TLSF_FLI_COUNT - 1)
    }
    
    /// Calculate second-level index for a size
    #[inline]
    fn sli_for_size(size: usize, fli: usize) -> usize {
        if fli == 0 {
            return size.saturating_sub(1 << TLSF_FLI_MIN) / ((1 << TLSF_FLI_MIN) / TLSF_SLI_COUNT);
        }
        let base = 1usize << (fli + TLSF_FLI_MIN);
        let offset = size - base;
        let sli_range = base / TLSF_SLI_COUNT;
        (offset / sli_range).min(TLSF_SLI_COUNT - 1)
    }
    
    /// Find a suitable free block for allocation
    /// Returns (start_page, actual_size) if found
    fn find_suitable(&self, requested_size: usize) -> Option<(usize, usize)> {
        if requested_size == 0 || requested_size > self.total_pages {
            return None;
        }
        
        // Round up to find the correct size class
        let fli = Self::fli_for_size(requested_size);
        let sli = Self::sli_for_size(requested_size, fli);
        
        // First, try the exact or slightly larger class
        let sl_map = self.sl_bitmap[fli].load(Ordering::Acquire) as u32;
        // Mask off smaller SLI entries
        let sl_mask = !((1u32 << sli) - 1);
        let sl_candidate = sl_map & sl_mask;
        
        if sl_candidate != 0 {
            // Found a block in this FLI
            let target_sli = sl_candidate.trailing_zeros() as usize;
            return self.try_allocate_from(fli, target_sli, requested_size);
        }
        
        // No suitable block in this FLI, try larger FLIs
        let fl_map = self.fl_bitmap.load(Ordering::Acquire);
        // Mask off smaller FLI entries
        let fl_mask = !((1u32 << (fli + 1)) - 1);
        let fl_candidate = fl_map & fl_mask;
        
        if fl_candidate != 0 {
            // Found a larger FLI class
            let target_fli = fl_candidate.trailing_zeros() as usize;
            let sl_map = self.sl_bitmap[target_fli].load(Ordering::Acquire);
            if sl_map != 0 {
                let target_sli = sl_map.trailing_zeros() as usize;
                return self.try_allocate_from(target_fli, target_sli, requested_size);
            }
        }
        
        None
    }
    
    /// Try to allocate from a specific size class
    fn try_allocate_from(&self, fli: usize, sli: usize, requested_size: usize) -> Option<(usize, usize)> {
        if fli >= TLSF_FLI_COUNT || sli >= TLSF_SLI_COUNT {
            return None;
        }
        
        // Get the head of the free list for this class
        let head_page = self.free_lists[fli][sli].load(Ordering::Acquire);
        if head_page == usize::MAX || head_page >= self.headers.len() {
            return None;
        }
        
        // Try to get the header
        if let Some(header) = &self.headers[head_page] {
            let block_size = header.size;
            let start_page = header.start_page;
            
            if block_size >= requested_size {
                // This block is suitable
                // Remove from free list
                let next_page = header.next.load(Ordering::Acquire);
                
                // Update the head of the free list
                if self.free_lists[fli][sli]
                    .compare_exchange(head_page, next_page, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok() 
                {
                    // Update next block's prev pointer
                    if next_page != usize::MAX && next_page < self.headers.len() {
                        if let Some(next_header) = &self.headers[next_page] {
                            next_header.prev.store(usize::MAX, Ordering::Release);
                        }
                    }
                    
                    // Update bitmaps if list is now empty
                    if next_page == usize::MAX {
                        self.sl_bitmap[fli].fetch_and(!(1u16 << sli), Ordering::AcqRel);
                        // Check if all SLI entries for this FLI are now empty
                        if self.sl_bitmap[fli].load(Ordering::Acquire) == 0 {
                            self.fl_bitmap.fetch_and(!(1u32 << fli), Ordering::AcqRel);
                        }
                    }
                    
                    return Some((start_page, block_size));
                }
            }
        }
        
        None
    }
    
    /// Add a free block to the allocator
    fn add_free_block(&self, start_page: usize, size: usize) {
        if size < (1 << TLSF_FLI_MIN) || start_page >= self.headers.len() {
            return; // Too small for TLSF, handle elsewhere
        }
        
        let fli = Self::fli_for_size(size);
        let sli = Self::sli_for_size(size, fli);
        
        // Note: This is a simplified version - full implementation would need
        // mutable access to headers or use atomics throughout
        // For now, TLSF is primarily used as a hint/cache layer
        
        // Update bitmaps
        self.sl_bitmap[fli].fetch_or(1u16 << sli, Ordering::AcqRel);
        self.fl_bitmap.fetch_or(1u32 << fli, Ordering::AcqRel);
    }
    
    /// Check if TLSF might have a suitable block (fast heuristic)
    fn might_have_block(&self, requested_size: usize) -> bool {
        if requested_size == 0 || requested_size > self.total_pages {
            return false;
        }
        
        let fli = Self::fli_for_size(requested_size);
        let fl_map = self.fl_bitmap.load(Ordering::Relaxed);
        
        // Check if any FLI >= our FLI has blocks
        let fl_mask = !((1u32 << fli) - 1);
        (fl_map & fl_mask) != 0
    }
}

// ============================================================================
// Bitmap Allocator (Medium Path)
// ============================================================================

/// Hierarchical bitmap for O(1) amortized allocation
///
/// Uses a three-level hierarchy for 4KB pages:
/// - Level 2 (L2): Summary-of-summary bitmap (1 bit per 4096 pages / 64 words)
/// - Level 1 (L1): Summary bitmap (1 bit per 64 pages / 1 word)
/// - Level 0 (L0): Detail bitmap (1 bit per page)
///
/// Plus dedicated fully-free bitmaps for 2MB/1GB:
/// - 2MB fully-free bitmap (1 bit per 512 pages)
/// - 1GB fully-free bitmap (1 bit per 512 2MB blocks)
///
/// This allows finding a free page in O(1) amortized time. The 3-level
/// hierarchy prevents slow scanning when the bitmap is nearly full:
/// - L2 scan: only ~16 words for 256GB (vs 128KB summary)
/// - L1 scan: only non-zero L2 bits
/// - L0 allocation: only non-zero L1 bits
///
/// # Memory Overhead (256GB IOVA space)
/// - 4KB detail bitmap (L0): 8MB (64M bits)
/// - 4KB summary bitmap (L1): 128KB (1M bits)
/// - 4KB summary_l2 bitmap (L2): 2KB (16K bits)
/// - 2MB used_count: 256KB (131,072 × u16)
/// - 2MB fully-free bitmap: 16KB (131,072 bits)
/// - 1GB fully-free bitmap: 32B (256 bits)
/// - Total: ~8.4MB (negligible for 256GB)
pub struct IovaBitmap {
    /// Base IOVA address
    base: u64,
    /// Total 4KB pages managed
    total_pages: usize,
    /// Total 2MB blocks managed
    total_2mb_blocks: usize,
    /// Total 1GB blocks managed  
    total_1gb_blocks: usize,

    // === 4KB Level (3-level hierarchy) ===
    /// Level 0 (L0): Detailed bitmap (1 = free, 0 = allocated)
    detail: alloc::boxed::Box<[AtomicU64]>,
    /// Level 1 (L1): Summary bitmap (1 = has free pages in corresponding detail word)
    summary: alloc::boxed::Box<[AtomicU64]>,
    /// Level 2 (L2): Summary-of-summary (1 = has non-zero summary word in range)
    /// Covers 64 summary words (= 4096 detail words = 262,144 pages) per bit
    summary_l2: alloc::boxed::Box<[AtomicU64]>,
    /// Allocation hint for 4KB (word index to start searching)
    hint_4k: AtomicUsize,
    /// Free 4KB page count
    pub(crate) free_count_4k: AtomicUsize,
    /// Valid bit mask for the last word (handles non-64-aligned total_pages)
    /// For word i < last_word: mask is u64::MAX
    /// For last_word: mask has only `total_pages % 64` bits set (or 64 if aligned)
    last_word_mask: u64,

    // === 2MB Level (Fully-Free Tracking + Partial Tracking) ===
    /// Per-2MB-block used count (0..512) - when 0, the block is fully free
    used_count_2m: alloc::boxed::Box<[AtomicU16]>,
    /// 2MB fully-free bitmap (1 = all 512 pages in this 2MB block are free)
    /// Used for 2MB allocation and should be preserved for hugepage availability
    bitmap_2m: alloc::boxed::Box<[AtomicU64]>,
    /// 2MB partially-used bitmap (1 = 0 < used_count < 512, has free pages but not fully free)
    /// 4KB allocation should prefer these blocks to preserve fully-free 2MB blocks
    bitmap_2m_partial: alloc::boxed::Box<[AtomicU64]>,
    /// Per-2MB-block free word mask (8 bits = 8 words per 2MB block)
    /// Bit i is set if detail word i within the block has free pages (detail[...] != 0)
    /// Used for O(1) word selection within partial blocks
    free_word_mask_2m: alloc::boxed::Box<[AtomicU8]>,
    /// Allocation hint for 2MB (block index to start searching)
    hint_2m: AtomicUsize,
    /// Allocation hint for partial 2MB blocks (for 4KB allocation)
    hint_2m_partial: AtomicUsize,
    /// Free 2MB block count (fully free only)
    free_count_2m: AtomicUsize,
    /// Partial 2MB block count (0 < used_count < 512)
    partial_count_2m: AtomicUsize,

    // === 1GB Level (Fully-Free Tracking) ===
    /// Per-1GB-block used count (count of non-free 2MB blocks, 0..512)
    used_count_1g: alloc::boxed::Box<[AtomicU16]>,
    /// 1GB fully-free bitmap (1 = all 512 2MB blocks in this 1GB are fully free)
    bitmap_1g: alloc::boxed::Box<[AtomicU64]>,
    /// Free 1GB block count (fully free only)
    free_count_1g: AtomicUsize,

    // === Free Word Stack (O(1) allocation fast path) ===
    /// Global stack of non-empty word indices for O(1) allocation
    /// When a word transitions 0→non-zero, its index is pushed here.
    /// On allocation, pop and validate before using.
    free_word_stack: FreeWordStack,
    
    // === 2MB Buddy Allocator (O(log N) contiguous 2MB allocation) ===
    /// Buddy free lists for 2MB blocks
    /// Tracks consecutive free 2MB blocks at each power-of-2 order.
    /// Order k contains blocks of size 2^k × 2MB (e.g., order 2 = 4 consecutive 2MB = 8MB)
    buddy_2m: Buddy2mFreeList,
    
    // === Arena Ownership (Optimization 1) ===
    /// Tracks which CPU owns each arena for lock-free owner operations
    /// Owner CPU can perform optimistic updates without CAS in some cases.
    arena_ownership: ArenaOwnership,
}

impl IovaBitmap {
    /// Create a new hierarchical bitmap allocator
    ///
    /// # Arguments
    /// * `base` - Base IOVA address (must be page-aligned)
    /// * `total_pages` - Number of 4KB pages to manage
    ///
    /// # 4-c Fix: Partial trailing blocks
    ///
    /// Only **complete** 2MB/1GB blocks are marked as fully-free in the
    /// hierarchical bitmaps. Trailing partial blocks (where total_pages is
    /// not a multiple of 512/262144) are NOT marked as fully-free, preventing
    /// `allocate_2mb()`/`allocate_1gb()` from repeatedly failing on them.
    pub fn new(base: u64, total_pages: usize) -> Self {
        let capped_pages = total_pages.min(MAX_BITMAP_PAGES);
        
        // Count only COMPLETE blocks for 2MB/1GB allocation
        let complete_2mb_blocks = capped_pages / PAGES_PER_2MB_BLOCK;
        let complete_1gb_blocks = complete_2mb_blocks / BLOCKS_2MB_PER_1GB;
        
        // Total blocks (including partial trailing blocks, for used_count tracking)
        let total_2mb_blocks = (capped_pages + PAGES_PER_2MB_BLOCK - 1) / PAGES_PER_2MB_BLOCK;
        let total_1gb_blocks = (total_2mb_blocks + BLOCKS_2MB_PER_1GB - 1) / BLOCKS_2MB_PER_1GB;

        // === 4KB Level Initialization (3-level hierarchy) ===
        let detail_words = (capped_pages + BITS_PER_WORD - 1) / BITS_PER_WORD;
        let summary_words = (detail_words + BITS_PER_WORD - 1) / BITS_PER_WORD;
        let summary_l2_words = (summary_words + BITS_PER_WORD - 1) / BITS_PER_WORD;

        // Allocate and initialize detail bitmap (L0) (all free = all 1s)
        let mut detail = alloc::vec::Vec::with_capacity(detail_words);
        for i in 0..detail_words {
            let remaining = capped_pages.saturating_sub(i * BITS_PER_WORD);
            let bits = if remaining >= BITS_PER_WORD {
                u64::MAX // All 64 pages free
            } else {
                (1u64 << remaining) - 1 // Only `remaining` pages free
            };
            detail.push(AtomicU64::new(bits));
        }

        // Allocate and initialize summary bitmap (L1)
        let mut summary = alloc::vec::Vec::with_capacity(summary_words);
        for i in 0..summary_words {
            let remaining_words = detail_words.saturating_sub(i * BITS_PER_WORD);
            let bits = if remaining_words >= BITS_PER_WORD {
                u64::MAX
            } else {
                (1u64 << remaining_words) - 1
            };
            summary.push(AtomicU64::new(bits));
        }

        // Allocate and initialize summary_l2 bitmap (L2)
        // Each bit covers 64 summary words (= 4096 detail words)
        let mut summary_l2 = alloc::vec::Vec::with_capacity(summary_l2_words);
        for i in 0..summary_l2_words {
            let remaining_summary_words = summary_words.saturating_sub(i * BITS_PER_WORD);
            let bits = if remaining_summary_words >= BITS_PER_WORD {
                u64::MAX
            } else if remaining_summary_words > 0 {
                (1u64 << remaining_summary_words) - 1
            } else {
                0
            };
            summary_l2.push(AtomicU64::new(bits));
        }

        // === 2MB Level Initialization ===
        // 4-c Fix: Only COMPLETE 2MB blocks are marked as fully-free
        let bitmap_2m_words = (total_2mb_blocks + BITS_PER_WORD - 1) / BITS_PER_WORD;

        // used_count_2m: all zeros for complete blocks, partial for trailing block
        let mut used_count_2m = alloc::vec::Vec::with_capacity(total_2mb_blocks);
        for block_idx in 0..total_2mb_blocks {
            let is_partial = block_idx >= complete_2mb_blocks;
            if is_partial {
                // Partial trailing block: calculate how many pages are "missing"
                // These missing pages count as "used" (not available)
                let pages_in_block = capped_pages.saturating_sub(block_idx * PAGES_PER_2MB_BLOCK);
                let missing_pages = PAGES_PER_2MB_BLOCK - pages_in_block;
                used_count_2m.push(AtomicU16::new(missing_pages as u16));
            } else {
                used_count_2m.push(AtomicU16::new(0));
            }
        }

        // bitmap_2m: only COMPLETE blocks are marked as fully-free
        let mut bitmap_2m = alloc::vec::Vec::with_capacity(bitmap_2m_words);
        for i in 0..bitmap_2m_words {
            // Only mark complete blocks as free
            let remaining = complete_2mb_blocks.saturating_sub(i * BITS_PER_WORD);
            let bits = if remaining >= BITS_PER_WORD {
                u64::MAX
            } else if remaining > 0 {
                (1u64 << remaining) - 1
            } else {
                0 // No complete blocks in this word
            };
            bitmap_2m.push(AtomicU64::new(bits));
        }

        // bitmap_2m_partial: starts all zeros (no partial blocks initially)
        // A partial block has 0 < used_count < 512
        let mut bitmap_2m_partial = alloc::vec::Vec::with_capacity(bitmap_2m_words);
        for _ in 0..bitmap_2m_words {
            bitmap_2m_partial.push(AtomicU64::new(0));
        }

        // free_word_mask_2m: 8 bits per 2MB block (8 words per block)
        // Initially all 0xFF for complete blocks (all 8 words have free pages)
        // Partial trailing blocks have fewer valid words
        let mut free_word_mask_2m = alloc::vec::Vec::with_capacity(total_2mb_blocks);
        for block_idx in 0..total_2mb_blocks {
            if block_idx < complete_2mb_blocks {
                // Complete block: all 8 words have free pages
                free_word_mask_2m.push(AtomicU8::new(0xFF));
            } else {
                // Partial trailing block: calculate how many words are valid
                let pages_in_block = capped_pages.saturating_sub(block_idx * PAGES_PER_2MB_BLOCK);
                let words_in_block = (pages_in_block + BITS_PER_WORD - 1) / BITS_PER_WORD;
                let mask = if words_in_block >= 8 {
                    0xFF
                } else {
                    (1u8 << words_in_block) - 1
                };
                free_word_mask_2m.push(AtomicU8::new(mask));
            }
        }

        // === 1GB Level Initialization ===
        // 4-c Fix: Only COMPLETE 1GB blocks are marked as fully-free
        let bitmap_1g_words = (total_1gb_blocks + BITS_PER_WORD - 1) / BITS_PER_WORD;

        // used_count_1g: count of non-free 2MB blocks in each 1GB block
        let mut used_count_1g = alloc::vec::Vec::with_capacity(total_1gb_blocks);
        for block_1g_idx in 0..total_1gb_blocks {
            let first_2mb = block_1g_idx * BLOCKS_2MB_PER_1GB;
            let last_2mb_excl = ((block_1g_idx + 1) * BLOCKS_2MB_PER_1GB).min(total_2mb_blocks);
            
            // Count how many 2MB blocks in this 1GB block are NOT fully free
            let mut non_free_count = 0u16;
            for block_2m_idx in first_2mb..last_2mb_excl {
                if block_2m_idx >= complete_2mb_blocks {
                    // Partial 2MB block counts as "used" for 1GB allocation purposes
                    non_free_count += 1;
                }
            }
            // Also count missing 2MB blocks at the end as "used"
            let missing_2mb = BLOCKS_2MB_PER_1GB - (last_2mb_excl - first_2mb);
            non_free_count += missing_2mb as u16;
            
            used_count_1g.push(AtomicU16::new(non_free_count));
        }

        // bitmap_1g: only COMPLETE 1GB blocks are marked as fully-free
        let mut bitmap_1g = alloc::vec::Vec::with_capacity(bitmap_1g_words);
        for i in 0..bitmap_1g_words {
            let remaining = complete_1gb_blocks.saturating_sub(i * BITS_PER_WORD);
            let bits = if remaining >= BITS_PER_WORD {
                u64::MAX
            } else if remaining > 0 {
                (1u64 << remaining) - 1
            } else {
                0 // No complete blocks in this word
            };
            bitmap_1g.push(AtomicU64::new(bits));
        }

        // Calculate valid mask for the last word
        // If total_pages is not a multiple of 64, the last word has fewer valid bits
        let remainder = capped_pages % BITS_PER_WORD;
        let last_word_mask = if remainder == 0 {
            u64::MAX // All 64 bits are valid
        } else {
            (1u64 << remainder) - 1 // Only `remainder` bits are valid
        };

        Self {
            base,
            total_pages: capped_pages,
            total_2mb_blocks,
            total_1gb_blocks,
            detail: detail.into_boxed_slice(),
            summary: summary.into_boxed_slice(),
            summary_l2: summary_l2.into_boxed_slice(),
            hint_4k: AtomicUsize::new(0),
            free_count_4k: AtomicUsize::new(capped_pages),
            last_word_mask,
            used_count_2m: used_count_2m.into_boxed_slice(),
            bitmap_2m: bitmap_2m.into_boxed_slice(),
            bitmap_2m_partial: bitmap_2m_partial.into_boxed_slice(),
            free_word_mask_2m: free_word_mask_2m.into_boxed_slice(),
            hint_2m: AtomicUsize::new(0),
            hint_2m_partial: AtomicUsize::new(0),
            // Only complete 2MB blocks are counted as "free" for 2MB allocation
            free_count_2m: AtomicUsize::new(complete_2mb_blocks),
            partial_count_2m: AtomicUsize::new(0),
            used_count_1g: used_count_1g.into_boxed_slice(),
            bitmap_1g: bitmap_1g.into_boxed_slice(),
            // Only complete 1GB blocks are counted as "free" for 1GB allocation
            free_count_1g: AtomicUsize::new(complete_1gb_blocks),
            // Free word stack starts empty (will be populated as allocations occur)
            // Note: We don't pre-populate because all words start as free anyway
            free_word_stack: FreeWordStack::new(),
            // Buddy allocator for contiguous 2MB allocations
            // We initialize and then populate the buddy lists
            buddy_2m: {
                let buddy = Buddy2mFreeList::new(total_2mb_blocks);
                // Initialize order 0 with all complete 2MB blocks
                // Higher orders will be built lazily when blocks are freed
                for block_idx in 0..complete_2mb_blocks {
                    buddy.set_free(0, block_idx);
                }
                buddy
            },
            // Arena ownership for CPU-local lock-free operations
            // Each arena covers WORDS_PER_ARENA words
            // Initially assigned to CPUs in round-robin fashion
            // Use 1 CPU for bootstrap (can be reconfigured later)
            arena_ownership: ArenaOwnership::new(detail_words, 1),
        }
    }

    /// Reconfigure arena ownership for a known CPU count
    ///
    /// Called after bootstrap when the actual number of CPUs is known.
    /// Each CPU will be assigned ownership of approximately equal portions
    /// of the IOVA space.
    ///
    /// # Arguments
    /// * `num_cpus` - Number of CPUs in the system
    pub fn reconfigure_arena_ownership(&mut self, num_cpus: usize) {
        let total_words = self.detail.len();
        self.arena_ownership.reconfigure_for_cpus(total_words, num_cpus);
    }
    
    /// Get arena ownership info for statistics/debugging
    pub fn arena_ownership_info(&self) -> (usize, usize) {
        (self.arena_ownership.num_arenas(), self.arena_ownership.words_per_arena())
    }

    /// Get the valid bit mask for a word index
    ///
    /// For all words except the last, returns u64::MAX (all bits valid).
    /// For the last word, returns only the bits corresponding to valid pages.
    #[inline]
    fn valid_mask(&self, word_idx: usize) -> u64 {
        let last_word_idx = if self.detail.is_empty() {
            0
        } else {
            self.detail.len() - 1
        };
        
        if word_idx < last_word_idx {
            u64::MAX
        } else if word_idx == last_word_idx {
            self.last_word_mask
        } else {
            0 // Out of bounds
        }
    }

    // ========================================================================
    // 4KB Page Allocation (with hierarchical update)
    // ========================================================================

    /// Allocate a single 4KB page (O(1) amortized)
    ///
    /// Updates the 2MB/1GB hierarchical bitmaps when a 2MB block transitions
    /// from fully-free to partially-used.
    ///
    /// Uses the global hint. For better multi-core performance, use
    /// `allocate_page_with_hint()` with a per-CPU hint.
    pub fn allocate_page(&self) -> Option<u64> {
        self.allocate_page_with_hint(&self.hint_4k)
    }

    /// Allocate a single 4KB page using a per-CPU hint
    ///
    /// # Arguments
    /// * `hint` - Per-CPU hint to start searching from (reduces cache line bounce)
    ///
    /// The hint is updated on successful allocation to improve locality.
    ///
    /// # Note
    /// For O(1) allocation, use `allocate_page_from_stack()` with a per-CPU
    /// LocalFreeWordStack first. This function is the fallback using hierarchy scan.
    pub fn allocate_page_with_hint(&self, hint: &AtomicUsize) -> Option<u64> {
        let detail_words = self.detail.len();

        if detail_words == 0 {
            return None;
        }

        // === Medium Path: 3-level hierarchy scan (L2 → L1 → L0) ===
        let hint_val = hint.load(Ordering::Relaxed);
        let hint_idx = hint_val % detail_words;
        let summary_words = self.summary.len();
        let summary_l2_words = self.summary_l2.len();

        for l2_offset in 0..summary_l2_words {
            let l2_idx = (hint_idx / (BITS_PER_WORD * BITS_PER_WORD) + l2_offset) % summary_l2_words;
            let mut l2_word = self.summary_l2[l2_idx].load(Ordering::Acquire);
            if l2_word == 0 {
                continue;
            }

            // Mask off bits before hint for first L2 word
            if l2_offset == 0 {
                let start_l2_bit = (hint_idx / BITS_PER_WORD) % BITS_PER_WORD;
                l2_word &= !((1u64 << start_l2_bit) - 1);
                if l2_word == 0 {
                    continue;
                }
            }

            while l2_word != 0 {
                let l2_bit = l2_word.trailing_zeros() as usize;
                let summary_idx = l2_idx * BITS_PER_WORD + l2_bit;
                if summary_idx >= summary_words {
                    break;
                }

                let mut summary_word = self.summary[summary_idx].load(Ordering::Acquire);
                if summary_word == 0 {
                    l2_word &= l2_word - 1;
                    continue;
                }

                // Mask off bits before hint for first summary word in first L2 word
                if l2_offset == 0 && l2_bit == (hint_idx / BITS_PER_WORD) % BITS_PER_WORD {
                    let start_bit = hint_idx % BITS_PER_WORD;
                    summary_word &= !((1u64 << start_bit) - 1);
                    if summary_word == 0 {
                        l2_word &= l2_word - 1;
                        continue;
                    }
                }

                while summary_word != 0 {
                    let bit = summary_word.trailing_zeros() as usize;
                    let word_idx = summary_idx * BITS_PER_WORD + bit;
                    if word_idx >= detail_words {
                        break;
                    }

                    if let Some(bit_idx) = self.try_allocate_from_word(word_idx) {
                        let page_idx = word_idx * BITS_PER_WORD + bit_idx;
                        if page_idx < self.total_pages {
                            hint.store(word_idx, Ordering::Relaxed);
                            self.free_count_4k.fetch_sub(1, Ordering::Relaxed);
                            self.on_page_allocated(page_idx);
                            return Some(self.base + (page_idx as u64) * PAGE_SIZE_4K);
                        }
                    }
                    summary_word &= summary_word - 1;
                }

                l2_word &= l2_word - 1;
            }
        }

        // Fallback: full detail scan for correctness (summary hierarchy can be stale)
        // This is rare in practice, only when all L2 bits are 0 but pages remain
        for offset in 0..detail_words {
            let word_idx = (hint_idx + offset) % detail_words;

            if let Some(bit_idx) = self.try_allocate_from_word(word_idx) {
                let page_idx = word_idx * BITS_PER_WORD + bit_idx;
                if page_idx < self.total_pages {
                    hint.store(word_idx, Ordering::Relaxed);
                    self.free_count_4k.fetch_sub(1, Ordering::Relaxed);
                    self.on_page_allocated(page_idx);
                    return Some(self.base + (page_idx as u64) * PAGE_SIZE_4K);
                }
            }
        }

        None
    }

    /// Allocate a single 4KB page from a per-CPU local free word stack (O(1) fast path)
    ///
    /// This is the fastest allocation path. The caller provides a per-CPU
    /// LocalFreeWordStack which tracks known non-empty words.
    ///
    /// # Arguments
    /// * `stack` - Per-CPU local free word stack (must be locked by caller)
    /// * `hint` - Per-CPU hint (updated on success)
    /// * `max_pops` - Maximum stack pops before falling through to hierarchy scan
    ///
    /// # Returns
    /// Some(iova) if allocation succeeded from stack, None if stack exhausted/stale
    ///
    /// # Note
    /// If this returns None, caller should fall through to `allocate_page_with_hint()`.
    pub fn allocate_page_from_stack(
        &self,
        stack: &mut LocalFreeWordStack,
        hint: &AtomicUsize,
        max_pops: usize,
    ) -> Option<u64> {
        let detail_words = self.detail.len();

        if detail_words == 0 {
            return None;
        }

        for _ in 0..max_pops {
            let word_idx = match stack.pop() {
                Some(idx) => idx,
                None => return None, // Stack empty
            };

            if word_idx >= detail_words {
                continue; // Invalid index, skip
            }

            if let Some(bit_idx) = self.try_allocate_from_word(word_idx) {
                let page_idx = word_idx * BITS_PER_WORD + bit_idx;
                if page_idx < self.total_pages {
                    hint.store(word_idx, Ordering::Relaxed);
                    self.free_count_4k.fetch_sub(1, Ordering::Relaxed);
                    self.on_page_allocated(page_idx);
                    return Some(self.base + (page_idx as u64) * PAGE_SIZE_4K);
                }
            }
            // Word was empty (stale entry), continue to next
        }

        None // Exhausted max_pops or all stale
    }

    /// Allocate a single 4KB page, preferring partially-used 2MB blocks
    ///
    /// This allocation strategy preserves fully-free 2MB blocks for future
    /// 2MB/1GB allocations. It first scans `bitmap_2m_partial` to find blocks
    /// with 0 < used_count < 512, then allocates from the detail bitmap within
    /// that block.
    ///
    /// # Strategy
    /// 1. Scan `bitmap_2m_partial` for a partial block (fast: O(1) amortized)
    /// 2. Allocate from detail bitmap within the partial block
    /// 3. If no partial blocks, fall back to regular hierarchy scan (may pollute hugepage)
    ///
    /// # Arguments
    /// * `hint_partial` - Per-CPU hint for partial block scanning
    /// * `hint_4k` - Per-CPU hint for 4KB allocation (fallback)
    ///
    /// # Returns
    /// (Some(iova), polluted) where `polluted` is true if a fully-free 2MB was consumed
    pub fn allocate_page_prefer_partial(
        &self,
        hint_partial: &AtomicUsize,
        hint_4k: &AtomicUsize,
    ) -> (Option<u64>, bool) {
        let partial_words = self.bitmap_2m_partial.len();
        let detail_words = self.detail.len();

        if detail_words == 0 {
            return (None, false);
        }

        // === Phase 1: Try to allocate from a partial 2MB block ===
        // Use free_word_mask_2m for O(1) word selection within block
        if partial_words > 0 {
            let hint_val = hint_partial.load(Ordering::Relaxed);
            let hint_block = hint_val % self.total_2mb_blocks.max(1);

            for word_offset in 0..partial_words {
                let word_idx = (hint_block / BITS_PER_WORD + word_offset) % partial_words;
                let mut word = self.bitmap_2m_partial[word_idx].load(Ordering::Acquire);
                
                // Mask off bits before hint for first word
                if word_offset == 0 {
                    let start_bit = hint_block % BITS_PER_WORD;
                    word &= !((1u64 << start_bit) - 1);
                }

                while word != 0 {
                    let bit = word.trailing_zeros() as usize;
                    let block_2m = word_idx * BITS_PER_WORD + bit;
                    
                    if block_2m >= self.total_2mb_blocks {
                        break;
                    }

                    // === O(1) word selection using free_word_mask_2m ===
                    // Each block has 8 words; use 8-bit mask to find non-empty word instantly
                    let free_mask = if block_2m < self.free_word_mask_2m.len() {
                        self.free_word_mask_2m[block_2m].load(Ordering::Acquire)
                    } else {
                        0xFF // Conservative fallback
                    };
                    
                    if free_mask != 0 {
                        // Use tzcnt to find first word with free pages - O(1)!
                        let word_in_block = free_mask.trailing_zeros() as usize;
                        let detail_idx = block_2m * WORDS_PER_2MB_BLOCK + word_in_block;
                        
                        if detail_idx < detail_words {
                            if let Some(bit_idx) = self.try_allocate_from_word(detail_idx) {
                                let page_idx = detail_idx * BITS_PER_WORD + bit_idx;
                                if page_idx < self.total_pages {
                                    hint_partial.store(block_2m, Ordering::Relaxed);
                                    hint_4k.store(detail_idx, Ordering::Relaxed);
                                    self.free_count_4k.fetch_sub(1, Ordering::Relaxed);
                                    self.on_page_allocated(page_idx);
                                    return (Some(self.base + (page_idx as u64) * PAGE_SIZE_4K), false);
                                }
                            }
                        }
                    }

                    // If free_mask was empty or allocation failed, scan all words as fallback
                    // This handles race conditions where mask may be stale
                    let start_detail_word = block_2m * WORDS_PER_2MB_BLOCK;
                    let end_detail_word = (start_detail_word + WORDS_PER_2MB_BLOCK).min(detail_words);

                    for detail_idx in start_detail_word..end_detail_word {
                        if let Some(bit_idx) = self.try_allocate_from_word(detail_idx) {
                            let page_idx = detail_idx * BITS_PER_WORD + bit_idx;
                            if page_idx < self.total_pages {
                                hint_partial.store(block_2m, Ordering::Relaxed);
                                hint_4k.store(detail_idx, Ordering::Relaxed);
                                self.free_count_4k.fetch_sub(1, Ordering::Relaxed);
                                self.on_page_allocated(page_idx);
                                return (Some(self.base + (page_idx as u64) * PAGE_SIZE_4K), false);
                            }
                        }
                    }

                    // Block might have become full or free, continue to next
                    word &= word - 1;
                }
            }
        }

        // === Phase 2: No partial blocks, fall back to regular allocation ===
        // This will consume from fully-free 2MB blocks (hugepage pollution)
        if let Some(iova) = self.allocate_page_with_hint(hint_4k) {
            return (Some(iova), true); // Polluted a hugepage
        }

        (None, false)
    }

    /// Allocate a single 4KB page within a specific arena (sharded allocation)
    ///
    /// First tries to allocate within the arena, then falls back to global if needed.
    ///
    /// # Arguments
    /// * `hint` - Per-CPU hint (updated on success)
    /// * `arena_start` - Start of arena (word index, inclusive)
    /// * `arena_end` - End of arena (word index, exclusive)
    ///
    /// # Returns
    /// Some(iova) if allocation succeeded, None if exhausted
    pub fn allocate_page_in_arena(
        &self,
        hint: &AtomicUsize,
        arena_start: usize,
        arena_end: usize,
    ) -> Option<u64> {
        let detail_words = self.detail.len();
        if detail_words == 0 {
            return None;
        }

        // Clamp arena bounds to valid range
        let arena_start = arena_start.min(detail_words);
        let arena_end = arena_end.min(detail_words);
        let arena_size = arena_end.saturating_sub(arena_start);

        if arena_size == 0 {
            // Empty arena, fall back to global
            return self.allocate_page_with_hint(hint);
        }

        // Phase 1: Try within local arena first
        let hint_val = hint.load(Ordering::Relaxed);
        let local_hint = if hint_val >= arena_start && hint_val < arena_end {
            hint_val
        } else {
            arena_start
        };

        for offset in 0..arena_size {
            let word_idx = arena_start + ((local_hint - arena_start + offset) % arena_size);

            if let Some(bit_idx) = self.try_allocate_from_word(word_idx) {
                let page_idx = word_idx * BITS_PER_WORD + bit_idx;
                if page_idx < self.total_pages {
                    hint.store(word_idx, Ordering::Relaxed);
                    self.free_count_4k.fetch_sub(1, Ordering::Relaxed);
                    self.on_page_allocated(page_idx);
                    return Some(self.base + (page_idx as u64) * PAGE_SIZE_4K);
                }
            }
        }

        // Phase 2: Local arena exhausted, steal from global (outside our arena)
        // Try words before arena_start
        for word_idx in 0..arena_start {
            if let Some(bit_idx) = self.try_allocate_from_word(word_idx) {
                let page_idx = word_idx * BITS_PER_WORD + bit_idx;
                if page_idx < self.total_pages {
                    // Don't update hint (keep it in our arena for next time)
                    self.free_count_4k.fetch_sub(1, Ordering::Relaxed);
                    self.on_page_allocated(page_idx);
                    return Some(self.base + (page_idx as u64) * PAGE_SIZE_4K);
                }
            }
        }

        // Try words after arena_end
        for word_idx in arena_end..detail_words {
            if let Some(bit_idx) = self.try_allocate_from_word(word_idx) {
                let page_idx = word_idx * BITS_PER_WORD + bit_idx;
                if page_idx < self.total_pages {
                    self.free_count_4k.fetch_sub(1, Ordering::Relaxed);
                    self.on_page_allocated(page_idx);
                    return Some(self.base + (page_idx as u64) * PAGE_SIZE_4K);
                }
            }
        }

        None
    }

    /// Allocate a single 4KB page using arena owner optimization
    ///
    /// This method provides the fastest allocation path for arena owners:
    /// - Owner CPU: Optimistic lock-free allocation from owned arena
    /// - Non-owner: Must steal from other arenas with potential ownership transfer
    ///
    /// # Arguments
    /// * `cpu_id` - Current CPU ID
    /// * `hint` - Per-CPU hint (updated on success)
    /// * `arena_start` - Start of arena (word index, inclusive)
    /// * `arena_end` - End of arena (word index, exclusive)
    ///
    /// # Owner Fast Path
    /// When cpu_id matches arena owner, allocation proceeds without contention
    /// tracking. This allows for maximum throughput on the common case.
    ///
    /// # Non-Owner Path with Steal Tracking
    /// When cpu_id doesn't match owner, steal attempts are tracked. After
    /// ARENA_STEAL_THRESHOLD consecutive steals, ownership may transfer to
    /// the stealing CPU.
    pub fn allocate_page_owner_optimized(
        &self,
        cpu_id: usize,
        hint: &AtomicUsize,
        arena_start: usize,
        arena_end: usize,
    ) -> Option<u64> {
        let detail_words = self.detail.len();
        if detail_words == 0 {
            return None;
        }

        // Check arena bounds
        let arena_start = arena_start.min(detail_words);
        let arena_end = arena_end.min(detail_words);
        let arena_size = arena_end.saturating_sub(arena_start);

        if arena_size == 0 {
            return self.allocate_page_with_hint(hint);
        }

        // Calculate arena ID for ownership tracking
        let arena_id = self.arena_ownership.arena_for_word(arena_start);

        // === Owner Fast Path ===
        // If we own this arena, we get lock-free allocation priority
        let is_owner = self.arena_ownership.is_owner(arena_start, cpu_id);
        
        if is_owner {
            // Owner allocation: direct scan without steal tracking
            let hint_val = hint.load(Ordering::Relaxed);
            let local_hint = if hint_val >= arena_start && hint_val < arena_end {
                hint_val
            } else {
                arena_start
            };

            for offset in 0..arena_size {
                let word_idx = arena_start + ((local_hint - arena_start + offset) % arena_size);

                if let Some(bit_idx) = self.try_allocate_from_word(word_idx) {
                    let page_idx = word_idx * BITS_PER_WORD + bit_idx;
                    if page_idx < self.total_pages {
                        hint.store(word_idx, Ordering::Relaxed);
                        self.free_count_4k.fetch_sub(1, Ordering::Relaxed);
                        self.on_page_allocated(page_idx);
                        return Some(self.base + (page_idx as u64) * PAGE_SIZE_4K);
                    }
                }
            }
        } else {
            // === Non-Owner Path: Track steal attempts ===
            // Try to allocate from the arena (stealing)
            let hint_val = hint.load(Ordering::Relaxed);
            let local_hint = if hint_val >= arena_start && hint_val < arena_end {
                hint_val
            } else {
                arena_start
            };

            for offset in 0..arena_size {
                let word_idx = arena_start + ((local_hint - arena_start + offset) % arena_size);

                if let Some(bit_idx) = self.try_allocate_from_word(word_idx) {
                    let page_idx = word_idx * BITS_PER_WORD + bit_idx;
                    if page_idx < self.total_pages {
                        hint.store(word_idx, Ordering::Relaxed);
                        self.free_count_4k.fetch_sub(1, Ordering::Relaxed);
                        self.on_page_allocated(page_idx);
                        
                        // Record steal and check for ownership transfer
                        if self.arena_ownership.record_steal_and_check_transfer(arena_id) {
                            // Threshold reached, try to transfer ownership
                            if let Some(old_owner) = self.arena_ownership.get_owner(arena_id) {
                                if self.arena_ownership.transfer_ownership(
                                    arena_id,
                                    old_owner,
                                    cpu_id as u16,
                                ) {
                                    self.arena_ownership.reset_steal_count(arena_id);
                                }
                            } else {
                                // No current owner, claim it
                                let _ = self.arena_ownership.try_claim(arena_id, cpu_id);
                                self.arena_ownership.reset_steal_count(arena_id);
                            }
                        }
                        
                        return Some(self.base + (page_idx as u64) * PAGE_SIZE_4K);
                    }
                }
            }
        }

        // === Global Steal Path ===
        // Local arena exhausted, steal from other arenas
        self.allocate_page_steal_global(cpu_id, hint, arena_start, arena_end)
    }

    /// Steal allocation from global pool (outside local arena)
    ///
    /// Called when local arena is exhausted. Tries other arenas with steal tracking.
    fn allocate_page_steal_global(
        &self,
        cpu_id: usize,
        hint: &AtomicUsize,
        arena_start: usize,
        arena_end: usize,
    ) -> Option<u64> {
        let detail_words = self.detail.len();

        // Try words before arena_start
        for word_idx in 0..arena_start {
            if let Some(bit_idx) = self.try_allocate_from_word(word_idx) {
                let page_idx = word_idx * BITS_PER_WORD + bit_idx;
                if page_idx < self.total_pages {
                    self.free_count_4k.fetch_sub(1, Ordering::Relaxed);
                    self.on_page_allocated(page_idx);
                    
                    // Track steal from this arena
                    let stolen_arena = self.arena_ownership.arena_for_word(word_idx);
                    if self.arena_ownership.record_steal_and_check_transfer(stolen_arena) {
                        if let Some(old_owner) = self.arena_ownership.get_owner(stolen_arena) {
                            if self.arena_ownership.transfer_ownership(
                                stolen_arena,
                                old_owner,
                                cpu_id as u16,
                            ) {
                                self.arena_ownership.reset_steal_count(stolen_arena);
                            }
                        }
                    }
                    
                    return Some(self.base + (page_idx as u64) * PAGE_SIZE_4K);
                }
            }
        }

        // Try words after arena_end
        for word_idx in arena_end..detail_words {
            if let Some(bit_idx) = self.try_allocate_from_word(word_idx) {
                let page_idx = word_idx * BITS_PER_WORD + bit_idx;
                if page_idx < self.total_pages {
                    self.free_count_4k.fetch_sub(1, Ordering::Relaxed);
                    self.on_page_allocated(page_idx);
                    
                    // Track steal from this arena
                    let stolen_arena = self.arena_ownership.arena_for_word(word_idx);
                    if self.arena_ownership.record_steal_and_check_transfer(stolen_arena) {
                        if let Some(old_owner) = self.arena_ownership.get_owner(stolen_arena) {
                            if self.arena_ownership.transfer_ownership(
                                stolen_arena,
                                old_owner,
                                cpu_id as u16,
                            ) {
                                self.arena_ownership.reset_steal_count(stolen_arena);
                            }
                        }
                    }
                    
                    return Some(self.base + (page_idx as u64) * PAGE_SIZE_4K);
                }
            }
        }

        None
    }

    /// Try to allocate a page from a specific word
    fn try_allocate_from_word(&self, word_idx: usize) -> Option<usize> {
        let word = &self.detail[word_idx];
        
        loop {
            let current = word.load(Ordering::Acquire);
            if current == 0 {
                return None; // No free pages in this word
            }
            
            // Find first set bit (free page)
            let bit_idx = current.trailing_zeros() as usize;
            let mask = 1u64 << bit_idx;
            
            // Try to clear the bit (allocate)
            let new_val = current & !mask;
            if word.compare_exchange_weak(
                current,
                new_val,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ).is_ok() {
                // Update summary and free_word_mask_2m if word is now empty
                if new_val == 0 {
                    self.clear_summary_bit(word_idx);
                    
                    // Update free_word_mask_2m (clear bit for this word)
                    let word_within_block = word_idx % WORDS_PER_2MB_BLOCK;
                    let block_2m = word_idx / WORDS_PER_2MB_BLOCK;
                    if block_2m < self.free_word_mask_2m.len() {
                        let mask = !(1u8 << word_within_block);
                        self.free_word_mask_2m[block_2m].fetch_and(mask, Ordering::Release);
                    }
                }
                return Some(bit_idx);
            }
            core::hint::spin_loop();
        }
    }

    /// Claim an entire word atomically using swap(0)
    ///
    /// This is used by SubMagazine to take ownership of all free pages in a word
    /// with a single atomic operation, eliminating CAS retries.
    ///
    /// # Arguments
    /// * `word_idx` - Word index to claim
    ///
    /// # Returns
    /// The claimed bits (u64) - each set bit represents a free page that is now owned
    /// by the caller. Returns 0 if the word was empty.
    ///
    /// # Hierarchy Updates
    /// Caller is responsible for calling `on_pages_allocated_batch()` with the
    /// count of claimed pages (bits.count_ones()).
    pub(crate) fn try_claim_word(&self, word_idx: usize) -> u64 {
        if word_idx >= self.detail.len() {
            return 0;
        }
        
        // Atomically swap the word with 0 - single atomic op, no CAS retries!
        let claimed = self.detail[word_idx].swap(0, Ordering::AcqRel);
        
        if claimed != 0 {
            // Word is now empty, update summary
            self.clear_summary_bit(word_idx);
            
            // Update free_word_mask_2m (clear bit for this word within its 2MB block)
            let word_within_block = word_idx % WORDS_PER_2MB_BLOCK;
            let block_2m = word_idx / WORDS_PER_2MB_BLOCK;
            if block_2m < self.free_word_mask_2m.len() {
                let mask = !(1u8 << word_within_block);
                self.free_word_mask_2m[block_2m].fetch_and(mask, Ordering::Release);
            }
        }
        
        claimed
    }

    /// Find a non-empty word in partial 2MB blocks and return its index
    ///
    /// This supports the "always prefer word claim" optimization by finding
    /// candidate words from partial blocks without modifying the bitmap.
    /// The caller can then use `try_claim_word()` to atomically claim it.
    ///
    /// # Arguments
    /// * `hint_partial` - Per-CPU hint for partial block scanning
    ///
    /// # Returns
    /// Some(word_idx) of a non-empty word, None if no partial blocks have free words
    pub(crate) fn find_non_empty_word_in_partial(&self, hint_partial: &AtomicUsize) -> Option<usize> {
        let partial_words = self.bitmap_2m_partial.len();
        let detail_words = self.detail.len();
        
        if detail_words == 0 || partial_words == 0 {
            return None;
        }
        
        let hint_val = hint_partial.load(Ordering::Relaxed);
        let hint_block = hint_val % self.total_2mb_blocks.max(1);
        
        // Scan partial bitmap words
        for word_offset in 0..partial_words {
            let partial_word_idx = (hint_block / BITS_PER_WORD + word_offset) % partial_words;
            let mut word = self.bitmap_2m_partial[partial_word_idx].load(Ordering::Acquire);
            
            // Mask off bits before hint for first word
            if word_offset == 0 {
                let start_bit = hint_block % BITS_PER_WORD;
                word &= !((1u64 << start_bit) - 1);
            }
            
            while word != 0 {
                let bit = word.trailing_zeros() as usize;
                let block_2m = partial_word_idx * BITS_PER_WORD + bit;
                
                if block_2m >= self.total_2mb_blocks {
                    break;
                }
                
                // Use free_word_mask_2m for O(1) word selection within block
                let free_mask = if block_2m < self.free_word_mask_2m.len() {
                    self.free_word_mask_2m[block_2m].load(Ordering::Acquire)
                } else {
                    0xFF // Conservative fallback
                };
                
                if free_mask != 0 {
                    let word_in_block = free_mask.trailing_zeros() as usize;
                    let detail_idx = block_2m * WORDS_PER_2MB_BLOCK + word_in_block;
                    
                    if detail_idx < detail_words {
                        // Verify word is actually non-empty
                        let word_val = self.detail[detail_idx].load(Ordering::Acquire);
                        if word_val != 0 {
                            hint_partial.store(block_2m, Ordering::Relaxed);
                            return Some(detail_idx);
                        }
                    }
                }
                
                // If free_mask was empty or word was empty, scan all words as fallback
                let start_detail_word = block_2m * WORDS_PER_2MB_BLOCK;
                let end_detail_word = (start_detail_word + WORDS_PER_2MB_BLOCK).min(detail_words);
                
                for detail_idx in start_detail_word..end_detail_word {
                    let word_val = self.detail[detail_idx].load(Ordering::Acquire);
                    if word_val != 0 {
                        hint_partial.store(block_2m, Ordering::Relaxed);
                        return Some(detail_idx);
                    }
                }
                
                // Block might have become full or free, continue to next
                word &= word - 1;
            }
        }
        
        None
    }

    /// Find a non-empty word using the summary hierarchy
    ///
    /// This is the fallback when no partial 2MB blocks are available.
    /// It scans the summary bitmap to find any word with free pages.
    ///
    /// # Arguments
    /// * `hint` - Per-CPU hint for word scanning
    ///
    /// # Returns
    /// Some(word_idx) of a non-empty word, None if all words are empty
    pub(crate) fn find_non_empty_word_from_summary(&self, hint: &AtomicUsize) -> Option<usize> {
        let summary_words = self.summary.len();
        let detail_words = self.detail.len();
        
        if detail_words == 0 || summary_words == 0 {
            return None;
        }
        
        let hint_word = hint.load(Ordering::Relaxed);
        let hint_summary = (hint_word / BITS_PER_WORD) % summary_words;
        
        // Scan summary words
        for offset in 0..summary_words {
            let summary_idx = (hint_summary + offset) % summary_words;
            let mut summary_word = self.summary[summary_idx].load(Ordering::Acquire);
            
            // Mask off bits before hint for first summary word
            if offset == 0 {
                let start_bit = hint_word % BITS_PER_WORD;
                summary_word &= !((1u64 << start_bit) - 1);
            }
            
            while summary_word != 0 {
                let bit = summary_word.trailing_zeros() as usize;
                let word_idx = summary_idx * BITS_PER_WORD + bit;
                
                if word_idx >= detail_words {
                    break;
                }
                
                // Verify word is actually non-empty
                let word_val = self.detail[word_idx].load(Ordering::Acquire);
                if word_val != 0 {
                    hint.store(word_idx, Ordering::Relaxed);
                    return Some(word_idx);
                }
                
                // Word was empty (stale summary bit), continue
                summary_word &= summary_word - 1;
            }
        }
        
        None
    }

    /// Return remaining bits from a SubMagazine back to the bitmap
    ///
    /// This is used when a SubMagazine has leftover pages that need to be
    /// returned to the global pool (e.g., during CPU migration or cleanup).
    ///
    /// # Arguments
    /// * `word_idx` - Original word index these bits came from
    /// * `bits` - Remaining free bits to return
    fn return_claimed_bits(&self, word_idx: usize, bits: u64) {
        if bits == 0 || word_idx >= self.detail.len() {
            return;
        }
        
        let word = &self.detail[word_idx];
        
        // Return bits using fetch_or - may conflict but bits will be returned
        let old = word.fetch_or(bits, Ordering::AcqRel);
        
        // If word was empty and is now non-empty, set summary bit
        if old == 0 {
            self.set_summary_bit(word_idx);
        }
        
        // Update free_word_mask_2m if word now has free pages
        let word_within_block = word_idx % WORDS_PER_2MB_BLOCK;
        let block_2m = word_idx / WORDS_PER_2MB_BLOCK;
        if block_2m < self.free_word_mask_2m.len() {
            let mask = 1u8 << word_within_block;
            self.free_word_mask_2m[block_2m].fetch_or(mask, Ordering::Release);
        }
        
        // Note: Caller should update hierarchy (used_count_2m) if needed
    }

    /// Batch allocate multiple pages from a single word (more efficient for refills)
    ///
    /// # Arguments
    /// * `word_idx` - Word index to allocate from
    /// * `max_pages` - Maximum number of pages to allocate
    /// * `out` - Output buffer to store allocated page indices (relative to word start)
    ///
    /// # Returns
    /// Number of pages actually allocated
    fn batch_allocate_from_word(&self, word_idx: usize, max_pages: usize, out: &mut [usize]) -> usize {
        let word = &self.detail[word_idx];
        let mut allocated = 0;
        
        loop {
            if allocated >= max_pages || allocated >= out.len() {
                break;
            }
            
            let current = word.load(Ordering::Acquire);
            if current == 0 {
                break; // No free pages in this word
            }
            
            // Count available bits
            let available = current.count_ones() as usize;
            let to_alloc = available.min(max_pages - allocated).min(out.len() - allocated);
            
            if to_alloc == 0 {
                break;
            }
            
            // Build mask for all bits to allocate
            let mut mask = 0u64;
            let mut temp = current;
            for i in 0..to_alloc {
                let bit_idx = temp.trailing_zeros() as usize;
                out[allocated + i] = bit_idx;
                mask |= 1u64 << bit_idx;
                temp &= temp - 1; // Clear lowest set bit
            }
            
            // Try to clear all bits atomically
            let new_val = current & !mask;
            if word.compare_exchange_weak(
                current,
                new_val,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ).is_ok() {
                allocated += to_alloc;
                // Update summary if word is now empty
                if new_val == 0 {
                    self.clear_summary_bit(word_idx);
                }
                // Optimized hierarchy update: 1 word (64 pages) is always within
                // a single 2MB block (512 pages = 8 words), so we can batch the
                // hierarchy update with a single fetch_add instead of per-page calls.
                let first_page_idx = word_idx * BITS_PER_WORD;
                if first_page_idx < self.total_pages {
                    self.on_pages_allocated_batch(first_page_idx, to_alloc);
                }
                break; // Success, exit even if we could allocate more
            }
            core::hint::spin_loop();
        }
        
        allocated
    }

    /// Batch update hierarchy after allocating multiple pages from the same word
    ///
    /// Since 1 word (64 pages) is always within a single 2MB block (512 pages = 8 words),
    /// we can update the hierarchy with a single atomic operation instead of per-page.
    ///
    /// # Arguments
    /// * `first_page_idx` - Index of first page in the word
    /// * `count` - Number of pages allocated from this word
    pub(crate) fn on_pages_allocated_batch(&self, first_page_idx: usize, count: usize) {
        let block_2m = first_page_idx / PAGES_PER_2MB_BLOCK;
        if block_2m >= self.total_2mb_blocks {
            return;
        }

        // Batch increment used_count_2m
        let old_used = self.used_count_2m[block_2m].fetch_add(count as u16, Ordering::AcqRel);
        
        // Debug check: detect wrap-around
        debug_assert!(
            (old_used as usize).saturating_add(count) <= PAGES_PER_2MB_BLOCK,
            "used_count_2m batch overflow at block {}: old={}, adding={}", 
            block_2m, old_used, count
        );
        
        // If this block was fully free (old_used == 0), it's no longer fully free
        if old_used == 0 {
            // Clear 2MB bitmap bit
            let word_2m = block_2m / BITS_PER_WORD;
            let bit_2m = block_2m % BITS_PER_WORD;
            let mask_2m = 1u64 << bit_2m;
            let old_2m = self.bitmap_2m[word_2m].fetch_and(!mask_2m, Ordering::AcqRel);
            
            if old_2m & mask_2m != 0 {
                self.free_count_2m.fetch_sub(1, Ordering::Relaxed);
            }
            
            // Update 1GB hierarchy
            let block_1g = block_2m / BLOCKS_2MB_PER_1GB;
            if block_1g < self.total_1gb_blocks {
                let old_1g = self.used_count_1g[block_1g].fetch_add(1, Ordering::AcqRel);
                
                // Debug check: detect 1GB wrap-around
                debug_assert!(
                    old_1g < BLOCKS_2MB_PER_1GB as u16,
                    "used_count_1g batch overflow at block {}: old_1g={}", 
                    block_1g, old_1g
                );
                
                if old_1g == 0 {
                    // Clear 1GB bitmap bit
                    let word_1g = block_1g / BITS_PER_WORD;
                    let bit_1g = block_1g % BITS_PER_WORD;
                    let mask_1g = 1u64 << bit_1g;
                    let old_1g_bm = self.bitmap_1g[word_1g].fetch_and(!mask_1g, Ordering::AcqRel);
                    if old_1g_bm & mask_1g != 0 {
                        self.free_count_1g.fetch_sub(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    /// Batch allocate pages using per-CPU hint (efficient for magazine refill)
    ///
    /// Uses 3-level summary hierarchy (L2 → L1 → L0) to efficiently find
    /// non-empty words, avoiding full detail scan when nearly full.
    ///
    /// # Arguments
    /// * `max_pages` - Maximum number of pages to allocate
    /// * `hint` - Per-CPU hint for locality
    ///
    /// # Returns
    /// Vector of allocated IOVAs
    ///
    /// # Note
    /// For O(1) fast path, use `batch_allocate_from_stack()` with a per-CPU
    /// LocalFreeWordStack first. This function only uses hierarchy scan.
    pub fn batch_allocate_pages(&self, max_pages: usize, hint: &AtomicUsize) -> alloc::vec::Vec<u64> {
        let mut result = alloc::vec::Vec::with_capacity(max_pages);
        let mut local_buf = [0usize; 64]; // Stack buffer for batch allocation
        let hint_val = hint.load(Ordering::Relaxed);
        let detail_words = self.detail.len();
        
        if detail_words == 0 {
            return result;
        }
        
        let hint_idx = hint_val % detail_words;
        let summary_words = self.summary.len();
        let summary_l2_words = self.summary_l2.len();

        // 3-level hierarchy scan: L2 → L1 → L0 (fast when nearly full)
        for l2_offset in 0..summary_l2_words {
            if result.len() >= max_pages {
                break;
            }

            let l2_idx = (hint_idx / (BITS_PER_WORD * BITS_PER_WORD) + l2_offset) % summary_l2_words;
            let mut l2_word = self.summary_l2[l2_idx].load(Ordering::Acquire);
            if l2_word == 0 {
                continue;
            }

            // Mask off bits before hint for first L2 word
            if l2_offset == 0 {
                let start_l2_bit = (hint_idx / BITS_PER_WORD) % BITS_PER_WORD;
                l2_word &= !((1u64 << start_l2_bit) - 1);
                if l2_word == 0 {
                    continue;
                }
            }

            while l2_word != 0 && result.len() < max_pages {
                let l2_bit = l2_word.trailing_zeros() as usize;
                let summary_idx = l2_idx * BITS_PER_WORD + l2_bit;
                if summary_idx >= summary_words {
                    break;
                }

                let mut summary_word = self.summary[summary_idx].load(Ordering::Acquire);
                if summary_word == 0 {
                    l2_word &= l2_word - 1;
                    continue;
                }

                // Mask off bits before hint for first summary word
                if l2_offset == 0 && l2_bit == (hint_idx / BITS_PER_WORD) % BITS_PER_WORD {
                    let start_bit = hint_idx % BITS_PER_WORD;
                    summary_word &= !((1u64 << start_bit) - 1);
                    if summary_word == 0 {
                        l2_word &= l2_word - 1;
                        continue;
                    }
                }

                while summary_word != 0 && result.len() < max_pages {
                    let bit = summary_word.trailing_zeros() as usize;
                    let word_idx = summary_idx * BITS_PER_WORD + bit;
                    if word_idx >= detail_words {
                        break;
                    }

                    let remaining = max_pages - result.len();
                    let batch_size = remaining.min(64);
                    let allocated = self.batch_allocate_from_word(word_idx, batch_size, &mut local_buf[..batch_size]);
                    
                    if allocated > 0 {
                        hint.store(word_idx, Ordering::Relaxed);
                        for i in 0..allocated {
                            let page_idx = word_idx * BITS_PER_WORD + local_buf[i];
                            if page_idx < self.total_pages {
                                result.push(self.base + (page_idx as u64) * PAGE_SIZE_4K);
                                self.free_count_4k.fetch_sub(1, Ordering::Relaxed);
                            }
                        }
                    }
                    summary_word &= summary_word - 1;
                }

                l2_word &= l2_word - 1;
            }
        }
        
        // Fallback: full detail scan (rare, only when hierarchy is stale)
        if result.len() < max_pages {
            for offset in 0..detail_words {
                if result.len() >= max_pages {
                    break;
                }
                
                let word_idx = (hint_idx + offset) % detail_words;
                let remaining = max_pages - result.len();
                let batch_size = remaining.min(64);
                
                let allocated = self.batch_allocate_from_word(word_idx, batch_size, &mut local_buf[..batch_size]);
                if allocated > 0 {
                    hint.store(word_idx, Ordering::Relaxed);
                    for i in 0..allocated {
                        let page_idx = word_idx * BITS_PER_WORD + local_buf[i];
                        if page_idx < self.total_pages {
                            result.push(self.base + (page_idx as u64) * PAGE_SIZE_4K);
                            self.free_count_4k.fetch_sub(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }
        
        result
    }

    /// Batch allocate pages within a specific arena (sharded allocation)
    ///
    /// First tries to allocate within the arena using 3-level summary hierarchy,
    /// then falls back to stealing from other arenas if needed.
    ///
    /// # Arguments
    /// * `max_pages` - Maximum number of pages to allocate
    /// * `hint` - Per-CPU hint for locality
    /// * `arena_start` - Start of arena (detail word index, inclusive)
    /// * `arena_end` - End of arena (detail word index, exclusive)
    ///
    /// # Returns
    /// Vector of allocated IOVAs
    pub fn batch_allocate_pages_in_arena(
        &self,
        max_pages: usize,
        hint: &AtomicUsize,
        arena_start: usize,
        arena_end: usize,
    ) -> alloc::vec::Vec<u64> {
        let mut result = alloc::vec::Vec::with_capacity(max_pages);
        let mut local_buf = [0usize; 64];
        let detail_words = self.detail.len();
        
        if detail_words == 0 || arena_start >= arena_end {
            return result;
        }
        
        let arena_end = arena_end.min(detail_words);
        let hint_val = hint.load(Ordering::Relaxed);
        let hint_in_arena = if hint_val >= arena_start && hint_val < arena_end {
            hint_val
        } else {
            arena_start
        };
        let summary_words = self.summary.len();

        // Phase 1: Arena-local allocation using L1 summary (L2 is too coarse for arena)
        // Convert arena bounds to summary range
        let summary_start = arena_start / BITS_PER_WORD;
        let summary_end = (arena_end + BITS_PER_WORD - 1) / BITS_PER_WORD;
        let hint_summary = hint_in_arena / BITS_PER_WORD;

        for summary_offset in 0..(summary_end - summary_start) {
            if result.len() >= max_pages {
                break;
            }

            let summary_idx = summary_start + (hint_summary - summary_start + summary_offset) % (summary_end - summary_start);
            if summary_idx >= summary_words {
                continue;
            }

            let mut summary_word = self.summary[summary_idx].load(Ordering::Acquire);
            if summary_word == 0 {
                continue;
            }

            // Mask to only include bits within arena
            let first_word_in_summary = summary_idx * BITS_PER_WORD;
            let last_word_in_summary = (summary_idx + 1) * BITS_PER_WORD;
            
            // Clamp to arena bounds
            let arena_first_bit = arena_start.saturating_sub(first_word_in_summary);
            let arena_last_bit = (arena_end.min(last_word_in_summary) - first_word_in_summary).min(BITS_PER_WORD);
            
            if arena_first_bit >= BITS_PER_WORD || arena_last_bit <= arena_first_bit {
                continue;
            }
            
            // Create mask for valid bits in arena
            let arena_mask = ((1u64 << arena_last_bit) - 1) & !((1u64 << arena_first_bit) - 1);
            summary_word &= arena_mask;
            
            if summary_word == 0 {
                continue;
            }

            while summary_word != 0 && result.len() < max_pages {
                let bit = summary_word.trailing_zeros() as usize;
                let word_idx = first_word_in_summary + bit;
                if word_idx >= arena_end {
                    break;
                }

                let remaining = max_pages - result.len();
                let batch_size = remaining.min(64);
                let allocated = self.batch_allocate_from_word(word_idx, batch_size, &mut local_buf[..batch_size]);
                
                if allocated > 0 {
                    hint.store(word_idx, Ordering::Relaxed);
                    for i in 0..allocated {
                        let page_idx = word_idx * BITS_PER_WORD + local_buf[i];
                        if page_idx < self.total_pages {
                            result.push(self.base + (page_idx as u64) * PAGE_SIZE_4K);
                            self.free_count_4k.fetch_sub(1, Ordering::Relaxed);
                        }
                    }
                }
                summary_word &= summary_word - 1;
            }
        }

        // Phase 2: Steal from global (outside arena) if not enough
        if result.len() < max_pages {
            let stolen = self.batch_allocate_pages(max_pages - result.len(), hint);
            result.extend(stolen);
        }
        
        result
    }

    /// Free a single 4KB page
    ///
    /// Returns the word index if the word transitioned 0→non-zero (for per-CPU stack push).
    /// The caller (IovaAllocatorFast) should push to the per-CPU LocalFreeWordStack.
    pub fn free_page(&self, iova: u64) -> Result<Option<usize>, IommuError> {
        if iova < self.base {
            return Err(IommuError::InvalidAddress);
        }
        
        let page_idx = ((iova - self.base) / PAGE_SIZE_4K) as usize;
        if page_idx >= self.total_pages {
            return Err(IommuError::InvalidAddress);
        }
        
        let word_idx = page_idx / BITS_PER_WORD;
        let bit_idx = page_idx % BITS_PER_WORD;
        let mask = 1u64 << bit_idx;
        
        let word = &self.detail[word_idx];
        let old = word.fetch_or(mask, Ordering::AcqRel);
        
        if old & mask != 0 {
            // Double free detected
            log::warn!("[IOVA] Double free detected for IOVA 0x{:x}", iova);
            return Err(IommuError::NotMapped);
        }
        
        // Track if word transitioned 0→non-zero (for per-CPU stack push)
        let became_non_empty = old == 0;
        if became_non_empty {
            // Update global stats (approximate count of non-empty words)
            self.free_word_stack.notify_non_empty();
            
            // Update free_word_mask_2m (set bit for this word)
            let word_within_block = word_idx % WORDS_PER_2MB_BLOCK;
            let block_2m = word_idx / WORDS_PER_2MB_BLOCK;
            if block_2m < self.free_word_mask_2m.len() {
                let mask = 1u8 << word_within_block;
                self.free_word_mask_2m[block_2m].fetch_or(mask, Ordering::Release);
            }
        }
        
        // Set summary bit since this word now has free pages
        self.set_summary_bit(word_idx);
        self.free_count_4k.fetch_add(1, Ordering::Relaxed);
        
        // Update 2MB/1GB hierarchy
        self.on_page_freed(page_idx);
        
        // Return word_idx if caller should push to per-CPU stack
        Ok(if became_non_empty { Some(word_idx) } else { None })
    }

    /// Free multiple pages within the same word in a single atomic operation
    ///
    /// # Arguments
    /// * `word_idx` - The word index (all pages must belong to this word)
    /// * `coalesced_mask` - Pre-computed bitmask of bits to set (OR of all page bits)
    /// * `page_count` - Number of pages being freed (for stats update)
    ///
    /// # Returns
    /// * `Ok(Some(word_idx))` - Word transitioned 0→non-zero (push to per-CPU stack)
    /// * `Ok(None)` - Word already had free pages
    /// * `Err` - Invalid word_idx
    ///
    /// # Performance
    /// Single fetch_or instead of N fetch_or calls for N pages in same word.
    pub fn free_pages_coalesced(&self, word_idx: usize, coalesced_mask: u64, _page_count: usize) -> Result<Option<usize>, IommuError> {
        if word_idx >= self.detail.len() {
            return Err(IommuError::InvalidAddress);
        }
        
        // Single atomic OR for all bits
        let word = &self.detail[word_idx];
        let old = word.fetch_or(coalesced_mask, Ordering::AcqRel);
        
        // Check for double-free (any bit already set)
        let double_freed = old & coalesced_mask;
        if double_freed != 0 {
            let double_count = double_freed.count_ones() as usize;
            log::warn!("[IOVA] Double free detected: {} pages in word {} (mask 0x{:016x})", 
                       double_count, word_idx, double_freed);
            // Continue - we've still freed the valid pages
        }
        
        // Track word transition 0→non-zero
        let became_non_empty = old == 0;
        if became_non_empty {
            self.free_word_stack.notify_non_empty();
            
            // Update free_word_mask_2m
            let word_within_block = word_idx % WORDS_PER_2MB_BLOCK;
            let block_2m = word_idx / WORDS_PER_2MB_BLOCK;
            if block_2m < self.free_word_mask_2m.len() {
                let mask = 1u8 << word_within_block;
                self.free_word_mask_2m[block_2m].fetch_or(mask, Ordering::Release);
            }
        }
        
        // Update summary bit
        self.set_summary_bit(word_idx);
        
        // Update stats (only count actually-freed pages, not double-frees)
        let actual_freed = (coalesced_mask & !old).count_ones() as usize;
        if actual_freed > 0 {
            self.free_count_4k.fetch_add(actual_freed, Ordering::Relaxed);
        }
        
        // Update 2MB/1GB hierarchy for each page
        // Note: For coalesced frees in same word, all pages are in same 2MB block
        let base_page = word_idx * BITS_PER_WORD;
        let block_2m = base_page / PAGES_PER_2MB_BLOCK;
        
        if block_2m < self.total_2mb_blocks && actual_freed > 0 {
            // Batch update: decrement used_count by actual_freed
            let old_count = self.used_count_2m[block_2m].fetch_sub(actual_freed as u16, Ordering::AcqRel);
            
            // Handle state transitions
            let new_count = old_count.saturating_sub(actual_freed as u16);
            
            // Transition to fully-free
            if new_count == 0 && old_count > 0 {
                self.clear_bitmap_2m_partial_bit(block_2m);
                self.partial_count_2m.fetch_sub(1, Ordering::Relaxed);
                self.set_bitmap_2m_bit(block_2m);
                self.free_count_2m.fetch_add(1, Ordering::Relaxed);
                
                // Update 1GB hierarchy
                let block_1g = block_2m / BLOCKS_2MB_PER_1GB;
                if block_1g < self.total_1gb_blocks {
                    let old_1g = self.used_count_1g[block_1g].fetch_sub(1, Ordering::AcqRel);
                    if old_1g == 1 {
                        self.set_bitmap_1g_bit(block_1g);
                        self.free_count_1g.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            // Transition from full to partial
            else if old_count == PAGES_PER_2MB_BLOCK as u16 && new_count < PAGES_PER_2MB_BLOCK as u16 {
                self.set_bitmap_2m_partial_bit(block_2m);
                self.partial_count_2m.fetch_add(1, Ordering::Relaxed);
            }
        }
        
        Ok(if became_non_empty { Some(word_idx) } else { None })
    }

    /// Allocate contiguous pages (for 2MB allocations)
    ///
    /// # Performance Optimization (C: Word-Level Skip)
    ///
    /// Instead of incrementing start_page by 1 on failure, we skip entire words
    /// that are fully allocated (word value == 0). This dramatically reduces
    /// iterations when the bitmap is fragmented.
    ///
    /// For allocations >= 512 pages (2MB), we also use the 2MB fully-free bitmap
    /// to generate candidates, avoiding slow linear scans.
    ///
    /// # 4-a Fix
    /// Now properly updates 2MB/1GB hierarchy after allocation.
    pub fn allocate_contiguous(&self, pages: usize, alignment_pages: usize) -> Option<u64> {
        if pages == 0 || pages > self.total_pages {
            return None;
        }
        let alignment_pages = alignment_pages.max(1);

        // For large allocations (>= 2MB), try fully-free 2MB blocks first
        if pages >= PAGES_PER_2MB_BLOCK {
            if let Some(result) = self.allocate_contiguous_from_2mb_blocks(pages, alignment_pages) {
                return Some(result);
            }
        }

        // Word-level skip scan with intelligent advancement
        let mut start_page = 0usize;
        
        while start_page + pages <= self.total_pages {
            // Align start
            let aligned_start = (start_page + alignment_pages - 1) / alignment_pages * alignment_pages;
            if aligned_start + pages > self.total_pages {
                break;
            }
            
            // Check if range is free, with word-level skip on failure
            match self.is_range_free_with_skip(aligned_start, pages) {
                RangeFreeResult::Free => {
                    // Try to allocate the range
                    if self.allocate_range(aligned_start, pages) {
                        // 4-a Fix: Update 2MB/1GB hierarchy
                        self.update_hierarchy_after_range_alloc(aligned_start, pages);
                        return Some(self.base + (aligned_start as u64) * PAGE_SIZE_4K);
                    }
                    // CAS failed, move forward by 1 page
                    start_page = aligned_start + 1;
                }
                RangeFreeResult::NotFree { skip_to_page } => {
                    // Skip to the next potential start position
                    start_page = skip_to_page.max(aligned_start + 1);
                }
            }
        }
        
        None
    }

    /// Check if a range is free, returning skip hint on failure
    ///
    /// When encountering an allocated page, returns the page index after
    /// the fully-allocated word, allowing the caller to skip efficiently.
    fn is_range_free_with_skip(&self, start_page: usize, pages: usize) -> RangeFreeResult {
        let end_page = start_page + pages;
        
        let start_word = start_page / BITS_PER_WORD;
        let end_word = (end_page + BITS_PER_WORD - 1) / BITS_PER_WORD;
        
        for word_idx in start_word..end_word {
            if word_idx >= self.detail.len() {
                return RangeFreeResult::NotFree { skip_to_page: self.total_pages };
            }
            
            let word_val = self.detail[word_idx].load(Ordering::Acquire);
            let word_start = word_idx * BITS_PER_WORD;
            let word_end = word_start + BITS_PER_WORD;
            
            // Calculate which bits we need to check in this word
            let first_bit = start_page.saturating_sub(word_start);
            let last_bit_excl = end_page.min(word_end) - word_start;
            
            // Create mask for bits we need to check
            let check_mask = if last_bit_excl >= BITS_PER_WORD {
                if first_bit == 0 {
                    u64::MAX
                } else {
                    u64::MAX << first_bit
                }
            } else {
                ((1u64 << last_bit_excl) - 1) & (u64::MAX << first_bit)
            };
            
            // If any required bit is 0 (allocated), range is not free
            if word_val & check_mask != check_mask {
                // Word is partially or fully allocated
                if word_val == 0 {
                    // Entire word is allocated, skip past it
                    return RangeFreeResult::NotFree { skip_to_page: word_end };
                } else {
                    // Find first allocated bit and skip past it
                    let allocated_bits = !word_val & check_mask;
                    let first_alloc_bit = allocated_bits.trailing_zeros() as usize;
                    return RangeFreeResult::NotFree { 
                        skip_to_page: word_start + first_alloc_bit + 1 
                    };
                }
            }
        }
        
        RangeFreeResult::Free
    }

    /// Allocate contiguous pages from fully-free 2MB blocks using buddy allocator
    ///
    /// # Optimization 4: 2MB Buddy Allocator
    ///
    /// For large allocations (>= 2MB), uses a buddy allocator for O(log N) allocation
    /// of contiguous 2MB blocks. Falls back to linear scan if buddy allocation fails.
    ///
    /// The buddy allocator maintains free lists at each power-of-2 order:
    /// - Order 0: single 2MB blocks
    /// - Order 1: pairs of consecutive 2MB blocks (4MB)
    /// - Order 2: 4 consecutive 2MB blocks (8MB)
    /// - etc.
    fn allocate_contiguous_from_2mb_blocks(&self, pages: usize, alignment_pages: usize) -> Option<u64> {
        // How many complete 2MB blocks do we need?
        let blocks_needed = (pages + PAGES_PER_2MB_BLOCK - 1) / PAGES_PER_2MB_BLOCK;
        
        if blocks_needed == 0 {
            return None;
        }
        
        // Calculate the minimum order needed (ceil(log2(blocks_needed)))
        let min_order = if blocks_needed == 1 {
            0
        } else {
            (usize::BITS - (blocks_needed - 1).leading_zeros()) as usize
        };
        
        // Try buddy allocation: find smallest available order >= min_order
        for order in min_order..BUDDY_2M_MAX_ORDER {
            if let Some(block_idx) = self.buddy_2m.find_and_allocate(order) {
                // Convert block index at this order to actual 2MB block index
                let start_2m_block = block_idx << order;
                let blocks_at_order = 1usize << order;
                
                // Check alignment requirement
                let start_page = start_2m_block * PAGES_PER_2MB_BLOCK;
                let aligned_start = (start_page + alignment_pages - 1) / alignment_pages * alignment_pages;
                let aligned_2m_block = aligned_start / PAGES_PER_2MB_BLOCK;
                
                // Check if we can fit within the allocated region after alignment
                if aligned_2m_block >= start_2m_block && 
                   aligned_start + pages <= (start_2m_block + blocks_at_order) * PAGES_PER_2MB_BLOCK {
                    
                    // Allocate the exact range in the detail bitmap
                    if self.allocate_range(aligned_start, pages) {
                        // Update hierarchy
                        self.update_hierarchy_after_range_alloc(aligned_start, pages);
                        
                        // Mark unused 2MB blocks as free in lower orders
                        // Split any excess blocks back into buddy lists
                        self.buddy_split_excess(start_2m_block, blocks_at_order, blocks_needed);
                        
                        return Some(self.base + (aligned_start as u64) * PAGE_SIZE_4K);
                    }
                }
                
                // Allocation failed, return block to buddy (rollback)
                self.buddy_2m.set_free(order, block_idx);
            }
        }
        
        // Buddy allocation failed, fall back to linear scan
        self.allocate_contiguous_from_2mb_blocks_linear(pages, alignment_pages)
    }
    
    /// Split excess 2MB blocks back into buddy free lists
    fn buddy_split_excess(&self, start_block: usize, total_blocks: usize, used_blocks: usize) {
        if used_blocks >= total_blocks {
            return;
        }
        
        // Return excess blocks starting from (start_block + used_blocks)
        let excess_start = start_block + used_blocks;
        let excess_count = total_blocks - used_blocks;
        
        // Add excess blocks back to appropriate buddy orders
        self.buddy_add_contiguous_free(excess_start, excess_count);
    }
    
    /// Add a contiguous range of 2MB blocks to buddy free lists
    fn buddy_add_contiguous_free(&self, start_block: usize, count: usize) {
        if count == 0 {
            return;
        }
        
        // Decompose count into power-of-2 chunks and add to appropriate orders
        let mut remaining = count;
        let mut current_block = start_block;
        
        while remaining > 0 {
            // Find highest order that fits and is properly aligned
            let mut best_order = 0;
            for order in (0..BUDDY_2M_MAX_ORDER).rev() {
                let block_size = 1usize << order;
                let alignment_mask = block_size - 1;
                
                if remaining >= block_size && (current_block & alignment_mask) == 0 {
                    best_order = order;
                    break;
                }
            }
            
            let block_size = 1usize << best_order;
            let buddy_idx = current_block >> best_order;
            
            self.buddy_2m.set_free(best_order, buddy_idx);
            
            current_block += block_size;
            remaining -= block_size;
        }
    }
    
    /// Linear fallback for allocate_contiguous_from_2mb_blocks
    fn allocate_contiguous_from_2mb_blocks_linear(&self, pages: usize, alignment_pages: usize) -> Option<u64> {
        let blocks_needed = (pages + PAGES_PER_2MB_BLOCK - 1) / PAGES_PER_2MB_BLOCK;
        
        // Scan 2MB bitmap for consecutive fully-free blocks
        let mut consecutive_start: Option<usize> = None;
        let mut consecutive_count = 0usize;
        
        for block_idx in 0..self.total_2mb_blocks {
            let word_idx = block_idx / BITS_PER_WORD;
            let bit_idx = block_idx % BITS_PER_WORD;
            
            if word_idx >= self.bitmap_2m.len() {
                break;
            }
            
            let is_free = self.bitmap_2m[word_idx].load(Ordering::Acquire) & (1u64 << bit_idx) != 0;
            
            if is_free {
                if consecutive_start.is_none() {
                    consecutive_start = Some(block_idx);
                    consecutive_count = 1;
                } else {
                    consecutive_count += 1;
                }
                
                if consecutive_count >= blocks_needed {
                    let start_block = consecutive_start.unwrap();
                    let start_page = start_block * PAGES_PER_2MB_BLOCK;
                    let aligned_start = (start_page + alignment_pages - 1) / alignment_pages * alignment_pages;
                    
                    if aligned_start + pages <= (start_block + consecutive_count) * PAGES_PER_2MB_BLOCK {
                        if self.is_range_free(aligned_start, pages) {
                            if self.allocate_range(aligned_start, pages) {
                                self.update_hierarchy_after_range_alloc(aligned_start, pages);
                                return Some(self.base + (aligned_start as u64) * PAGE_SIZE_4K);
                            }
                        }
                    }
                }
            } else {
                consecutive_start = None;
                consecutive_count = 0;
            }
        }
        
        None
    }

    /// Allocate contiguous pages with an upper bound (for 32-bit device compatibility)
    ///
    /// # 4-a Fix
    /// Now properly updates 2MB/1GB hierarchy after allocation.
    pub fn allocate_contiguous_below(&self, pages: usize, alignment_pages: usize, max_end_page: usize) -> Option<u64> {
        if pages == 0 || pages > self.total_pages || max_end_page == 0 {
            return None;
        }
        let alignment_pages = alignment_pages.max(1);
        let effective_limit = max_end_page.min(self.total_pages);

        let mut start_page = 0usize;
        
        while start_page + pages <= effective_limit {
            let aligned_start = (start_page + alignment_pages - 1) / alignment_pages * alignment_pages;
            if aligned_start + pages > effective_limit {
                break;
            }
            
            if self.is_range_free(aligned_start, pages) {
                if self.allocate_range(aligned_start, pages) {
                    // 4-a Fix: Update 2MB/1GB hierarchy
                    self.update_hierarchy_after_range_alloc(aligned_start, pages);
                    return Some(self.base + (aligned_start as u64) * PAGE_SIZE_4K);
                }
            }
            
            start_page = aligned_start + 1;
        }
        
        None
    }

    /// Allocate at a specific page range (for identity mapping / RMRR)
    ///
    /// Returns true if allocation succeeded, false if range was not free.
    ///
    /// # 4-a Fix
    /// Now properly updates 2MB/1GB hierarchy after allocation.
    pub fn allocate_range_at(&self, start_page: usize, pages: usize) -> bool {
        if pages == 0 || start_page + pages > self.total_pages {
            return false;
        }

        // Check if range is free first
        if !self.is_range_free(start_page, pages) {
            return false;
        }

        // Try to allocate atomically
        if !self.allocate_range(start_page, pages) {
            return false;
        }

        // 4-a Fix: Update 2MB/1GB hierarchy for the allocated range
        self.update_hierarchy_after_range_alloc(start_page, pages);
        true
    }

    /// Check if a range of pages is free (word-optimized)
    ///
    /// Uses word-level operations for O(words) instead of O(pages) checking.
    /// For 2MB (512 pages = 8 words), this is 64x faster than page-by-page.
    /// For 1GB (262144 pages = 4096 words), this is 64x faster.
    fn is_range_free(&self, start_page: usize, count: usize) -> bool {
        if count == 0 {
            return true;
        }
        let end_page = start_page + count;
        let start_word = start_page / BITS_PER_WORD;
        let end_word = (end_page + BITS_PER_WORD - 1) / BITS_PER_WORD;

        for word_idx in start_word..end_word {
            if word_idx >= self.detail.len() {
                return false;
            }

            let word = self.detail[word_idx].load(Ordering::Relaxed);

            // Calculate the mask for this word
            let word_start_page = word_idx * BITS_PER_WORD;
            let word_end_page = word_start_page + BITS_PER_WORD;

            let first_bit = start_page.saturating_sub(word_start_page);
            let last_bit_excl = end_page.min(word_end_page) - word_start_page;
            let bits_in_word = last_bit_excl - first_bit;

            let mask = if bits_in_word >= BITS_PER_WORD {
                u64::MAX
            } else {
                ((1u64 << bits_in_word) - 1) << first_bit
            };

            // All masked bits must be set (free)
            if (word & mask) != mask {
                return false;
            }
        }
        true
    }

    /// Allocate a range of pages atomically (word-optimized)
    ///
    /// Uses word-level CAS operations for O(words) instead of O(pages).
    /// - Partial words: use masked CAS
    /// - Full words: use compare_exchange(valid_mask, 0)
    fn allocate_range(&self, start_page: usize, count: usize) -> bool {
        if count == 0 {
            return true;
        }
        let end_page = start_page + count;
        let start_word = start_page / BITS_PER_WORD;
        let end_word = (end_page + BITS_PER_WORD - 1) / BITS_PER_WORD;

        // Collect word operations to perform
        let mut allocated_words: usize = 0;

        for word_idx in start_word..end_word {
            if word_idx >= self.detail.len() {
                self.rollback_range_words(start_word, allocated_words, start_page, count);
                return false;
            }

            let word_start_page = word_idx * BITS_PER_WORD;
            let word_end_page = word_start_page + BITS_PER_WORD;

            let first_bit = start_page.saturating_sub(word_start_page);
            let last_bit_excl = end_page.min(word_end_page) - word_start_page;
            let bits_in_word = last_bit_excl - first_bit;

            // Use valid_mask for the last word to handle non-64-aligned total_pages
            let valid_bits = self.valid_mask(word_idx);
            let effective_bits = bits_in_word.min(valid_bits.count_ones() as usize);
            let is_full_word = first_bit == 0 && effective_bits == valid_bits.count_ones() as usize;

            let word = &self.detail[word_idx];

            if is_full_word {
                // Fast path: full word allocation via compare_exchange
                // Use valid_mask instead of u64::MAX for last word safety
                match word.compare_exchange(
                    valid_bits,
                    0,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        // Word was fully free, now fully allocated
                        self.clear_summary_bit(word_idx);
                        allocated_words += 1;
                    }
                    Err(_) => {
                        // Word was not fully free - rollback
                        self.rollback_range_words(start_word, allocated_words, start_page, count);
                        return false;
                    }
                }
            } else {
                // Slow path: partial word via masked CAS
                let mask = ((1u64 << bits_in_word) - 1) << first_bit;

                loop {
                    let current = word.load(Ordering::Acquire);
                    
                    // Check if all target bits are free
                    if (current & mask) != mask {
                        // Some bits already allocated - rollback
                        self.rollback_range_words(start_word, allocated_words, start_page, count);
                        return false;
                    }

                    let new_val = current & !mask;
                    match word.compare_exchange_weak(
                        current,
                        new_val,
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => {
                            if new_val == 0 {
                                self.clear_summary_bit(word_idx);
                            }
                            allocated_words += 1;
                            break;
                        }
                        Err(_) => {
                            core::hint::spin_loop();
                            continue;
                        }
                    }
                }
            }
        }

        self.free_count_4k.fetch_sub(count, Ordering::Relaxed);
        // Note: 2MB/1GB hierarchy is updated by the caller (allocate_2mb/allocate_1gb)
        true
    }

    /// Roll back a partially allocated range (word-optimized)
    ///
    /// Restores freed bits for words that were successfully allocated.
    /// Uses valid_mask() to avoid setting bits for non-existent pages in the last word.
    fn rollback_range_words(&self, start_word: usize, words_allocated: usize, start_page: usize, total_pages: usize) {
        let end_page = start_page + total_pages;

        for i in 0..words_allocated {
            let word_idx = start_word + i;
            if word_idx >= self.detail.len() {
                break;
            }

            let word_start_page = word_idx * BITS_PER_WORD;
            let word_end_page = word_start_page + BITS_PER_WORD;

            let first_bit = start_page.saturating_sub(word_start_page);
            let last_bit_excl = end_page.min(word_end_page) - word_start_page;
            let bits_in_word = last_bit_excl - first_bit;

            let is_full_word = first_bit == 0 && bits_in_word == BITS_PER_WORD;

            if is_full_word {
                // Full word: restore to valid_mask (NOT u64::MAX for last word!)
                let mask = self.valid_mask(word_idx);
                self.detail[word_idx].store(mask, Ordering::Release);
            } else {
                // Partial word: set mask bits (already correctly bounded)
                let mask = ((1u64 << bits_in_word) - 1) << first_bit;
                self.detail[word_idx].fetch_or(mask, Ordering::Release);
            }
            self.set_summary_bit(word_idx);
        }
    }

    /// Roll back a partially allocated range (does not touch free_count)
    /// Legacy page-by-page rollback for compatibility
    fn rollback_range(&self, start_page: usize, count: usize) {
        for i in 0..count {
            let page = start_page + i;
            let word_idx = page / BITS_PER_WORD;
            let bit_idx = page % BITS_PER_WORD;
            let mask = 1u64 << bit_idx;

            self.detail[word_idx].fetch_or(mask, Ordering::Release);
            self.set_summary_bit(word_idx);
        }
    }

    /// Free a contiguous range of pages by IOVA
    fn free_contiguous(&self, iova: u64, pages: usize) -> Result<(), IommuError> {
        if pages == 0 {
            return Ok(());
        }
        if iova < self.base {
            return Err(IommuError::InvalidAddress);
        }

        let start_page = ((iova - self.base) / PAGE_SIZE_4K) as usize;
        if start_page >= self.total_pages {
            return Err(IommuError::InvalidAddress);
        }

        let end_page = start_page
            .checked_add(pages)
            .ok_or(IommuError::InvalidAddress)?;
        let valid_pages = end_page.min(self.total_pages) - start_page;

        let result = self.free_range_pages(start_page, valid_pages);
        if result.is_err() {
            return result;
        }
        
        // Update 2MB/1GB hierarchy after freeing range
        // This allows blocks to become fully-free again for 2MB/1GB allocation
        self.update_hierarchy_after_range_free(start_page, valid_pages);
        
        if end_page > self.total_pages {
            return Err(IommuError::InvalidAddress);
        }
        Ok(())
    }

    /// Free a contiguous range of pages by page index (word-optimized)
    ///
    /// Uses word-level operations with fast path for full words:
    /// - Full words: store(u64::MAX) directly (no CAS needed)
    /// - Partial words: fetch_or with mask
    fn free_range_pages(&self, start_page: usize, count: usize) -> Result<(), IommuError> {
        if count == 0 {
            return Ok(());
        }
        let end_page = start_page
            .checked_add(count)
            .ok_or(IommuError::InvalidAddress)?;
        
        let start_word = start_page / BITS_PER_WORD;
        let end_word = (end_page + BITS_PER_WORD - 1) / BITS_PER_WORD;
        
        let mut freed = 0usize;
        let mut double_free_iova: Option<u64> = None;

        for word_idx in start_word..end_word {
            if word_idx >= self.detail.len() {
                break;
            }

            let word_start_page = word_idx * BITS_PER_WORD;
            let word_end_page = word_start_page + BITS_PER_WORD;

            let first_bit = start_page.saturating_sub(word_start_page);
            let last_bit_excl = end_page.min(word_end_page) - word_start_page;
            let bits_in_word = last_bit_excl - first_bit;

            let is_full_word = first_bit == 0 && bits_in_word == BITS_PER_WORD;
            let word = &self.detail[word_idx];

            if is_full_word {
                // Fast path: full word free
                // Use valid_mask() to avoid setting bits for non-existent pages
                let target_mask = self.valid_mask(word_idx);
                let old = word.swap(target_mask, Ordering::AcqRel);
                // Count only valid bits that were freed
                let newly_freed_bits = (!old) & target_mask;
                freed += newly_freed_bits.count_ones() as usize;

                // Check for double-free (any valid bits that were already 1)
                let already_free = old & target_mask;
                if already_free != 0 && double_free_iova.is_none() {
                    let already_free_bit = already_free.trailing_zeros() as usize;
                    let page_idx = word_idx * BITS_PER_WORD + already_free_bit;
                    double_free_iova = Some(self.base + (page_idx as u64) * PAGE_SIZE_4K);
                }
                
                // Notify stats if word was empty before (0→non-zero)
                if old == 0 && target_mask != 0 {
                    self.free_word_stack.notify_non_empty();
                }
            } else {
                // Partial word: use masked fetch_or
                let mask = ((1u64 << bits_in_word) - 1) << first_bit;
                let old = word.fetch_or(mask, Ordering::AcqRel);
                let newly_freed = (!old) & mask;
                freed += newly_freed.count_ones() as usize;

                // Check for double-free
                if old & mask != 0 && double_free_iova.is_none() {
                    let already_free = old & mask;
                    let bit = already_free.trailing_zeros() as usize;
                    let page_idx = word_idx * BITS_PER_WORD + bit;
                    double_free_iova = Some(self.base + (page_idx as u64) * PAGE_SIZE_4K);
                }
                
                // Notify stats if word was empty before (0→non-zero)
                if old == 0 && mask != 0 {
                    self.free_word_stack.notify_non_empty();
                }
            }

            self.set_summary_bit(word_idx);
        }

        if freed != 0 {
            self.free_count_4k.fetch_add(freed, Ordering::Relaxed);
        }

        if let Some(iova) = double_free_iova {
            log::warn!("[IOVA] Double free detected for IOVA 0x{:x}", iova);
            return Err(IommuError::NotMapped);
        }

        // Note: 2MB/1GB hierarchy is updated by the caller (free_2mb/free_1gb)
        Ok(())
    }

    /// Set a bit in the summary bitmap (L1) and update summary_l2 (L2)
    fn set_summary_bit(&self, detail_word_idx: usize) {
        let summary_word_idx = detail_word_idx / BITS_PER_WORD;
        let summary_bit = detail_word_idx % BITS_PER_WORD;
        
        if summary_word_idx < self.summary.len() {
            self.summary[summary_word_idx].fetch_or(1u64 << summary_bit, Ordering::Release);
            // Also update summary_l2 (L2)
            self.set_summary_l2_bit(summary_word_idx);
        }
    }

    /// Clear a bit in the summary bitmap (L1)
    /// Only clears summary_l2 (L2) if the entire summary word becomes 0
    fn clear_summary_bit(&self, detail_word_idx: usize) {
        let summary_word_idx = detail_word_idx / BITS_PER_WORD;
        let summary_bit = detail_word_idx % BITS_PER_WORD;
        
        if summary_word_idx < self.summary.len() {
            let old = self.summary[summary_word_idx].fetch_and(!(1u64 << summary_bit), Ordering::Release);
            // If the summary word just became 0, clear the L2 bit
            if old == (1u64 << summary_bit) {
                self.clear_summary_l2_bit(summary_word_idx);
            }
        }
    }

    /// Set a bit in the summary_l2 bitmap (L2)
    fn set_summary_l2_bit(&self, summary_word_idx: usize) {
        let l2_word_idx = summary_word_idx / BITS_PER_WORD;
        let l2_bit = summary_word_idx % BITS_PER_WORD;
        
        if l2_word_idx < self.summary_l2.len() {
            self.summary_l2[l2_word_idx].fetch_or(1u64 << l2_bit, Ordering::Release);
        }
    }

    /// Clear a bit in the summary_l2 bitmap (L2)
    fn clear_summary_l2_bit(&self, summary_word_idx: usize) {
        let l2_word_idx = summary_word_idx / BITS_PER_WORD;
        let l2_bit = summary_word_idx % BITS_PER_WORD;
        
        if l2_word_idx < self.summary_l2.len() {
            self.summary_l2[l2_word_idx].fetch_and(!(1u64 << l2_bit), Ordering::Release);
        }
    }

    // ========================================================================
    // 2MB/1GB Hierarchical Update Methods
    // ========================================================================

    /// Called when a single 4KB page is allocated.
    /// Updates 2MB used_count and manages bitmap_2m / bitmap_2m_partial.
    ///
    /// State transitions:
    /// - 0 -> 1: fully-free -> partial (set partial bit, clear fully-free bit)
    /// - N -> 512: partial -> full (clear partial bit)
    pub(crate) fn on_page_allocated(&self, page_idx: usize) {
        let block_2m = page_idx / PAGES_PER_2MB_BLOCK;
        if block_2m >= self.total_2mb_blocks {
            return;
        }

        // Increment 2MB used_count
        let old_count = self.used_count_2m[block_2m].fetch_add(1, Ordering::AcqRel);
        
        // Debug check: detect wrap-around (should never happen if logic is correct)
        debug_assert!(
            old_count < PAGES_PER_2MB_BLOCK as u16,
            "used_count_2m overflow detected at block {}: old_count={}", 
            block_2m, old_count
        );

        let new_count = old_count + 1;

        // Transition 0 -> 1: block was fully free, now partial
        if old_count == 0 {
            // Clear 2MB fully-free bitmap bit
            self.clear_bitmap_2m_bit(block_2m);
            self.free_count_2m.fetch_sub(1, Ordering::Relaxed);
            
            // Set 2MB partial bitmap bit (now has 0 < used < 512)
            self.set_bitmap_2m_partial_bit(block_2m);
            self.partial_count_2m.fetch_add(1, Ordering::Relaxed);

            // Update 1GB hierarchy
            let block_1g = block_2m / BLOCKS_2MB_PER_1GB;
            if block_1g < self.total_1gb_blocks {
                let old_1g = self.used_count_1g[block_1g].fetch_add(1, Ordering::AcqRel);
                
                // Debug check: detect 1GB wrap-around
                debug_assert!(
                    old_1g < BLOCKS_2MB_PER_1GB as u16,
                    "used_count_1g overflow detected at block {}: old_1g={}", 
                    block_1g, old_1g
                );
                
                if old_1g == 0 {
                    // 1GB block no longer fully free
                    self.clear_bitmap_1g_bit(block_1g);
                    self.free_count_1g.fetch_sub(1, Ordering::Relaxed);
                }
            }
        }
        // Transition N -> 512: block was partial, now completely full
        else if new_count == PAGES_PER_2MB_BLOCK as u16 {
            // Clear 2MB partial bitmap bit (no more free pages)
            self.clear_bitmap_2m_partial_bit(block_2m);
            self.partial_count_2m.fetch_sub(1, Ordering::Relaxed);
        }
        // Otherwise: block remains partial (1..511 used), no bitmap changes needed
    }

    /// Called when a single 4KB page is freed.
    /// Updates 2MB used_count and manages bitmap_2m / bitmap_2m_partial.
    ///
    /// State transitions:
    /// - 1 -> 0: partial -> fully-free (clear partial bit, set fully-free bit)
    /// - 512 -> N: full -> partial (set partial bit)
    fn on_page_freed(&self, page_idx: usize) {
        let block_2m = page_idx / PAGES_PER_2MB_BLOCK;
        if block_2m >= self.total_2mb_blocks {
            return;
        }

        // Decrement 2MB used_count
        let old_count = self.used_count_2m[block_2m].fetch_sub(1, Ordering::AcqRel);
        
        // Debug check: detect underflow (should never happen if logic is correct)
        debug_assert!(
            old_count > 0,
            "used_count_2m underflow detected at block {}: old_count={}", 
            block_2m, old_count
        );

        // Transition 1 -> 0: block was partial, now fully free
        if old_count == 1 {
            // Clear 2MB partial bitmap bit
            self.clear_bitmap_2m_partial_bit(block_2m);
            self.partial_count_2m.fetch_sub(1, Ordering::Relaxed);
            
            // Set 2MB fully-free bitmap bit
            self.set_bitmap_2m_bit(block_2m);
            self.free_count_2m.fetch_add(1, Ordering::Relaxed);

            // Update 1GB hierarchy
            let block_1g = block_2m / BLOCKS_2MB_PER_1GB;
            if block_1g < self.total_1gb_blocks {
                let old_1g = self.used_count_1g[block_1g].fetch_sub(1, Ordering::AcqRel);
                
                // Debug check: detect 1GB underflow
                debug_assert!(
                    old_1g > 0,
                    "used_count_1g underflow detected at block {}: old_1g={}", 
                    block_1g, old_1g
                );
                
                if old_1g == 1 {
                    // 1GB block is now fully free (all 512 2MB blocks free)
                    self.set_bitmap_1g_bit(block_1g);
                    self.free_count_1g.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        // Transition 512 -> N: block was completely full, now partial
        else if old_count == PAGES_PER_2MB_BLOCK as u16 {
            // Set 2MB partial bitmap bit (now has 0 < used < 512)
            self.set_bitmap_2m_partial_bit(block_2m);
            self.partial_count_2m.fetch_add(1, Ordering::Relaxed);
        }
        // Otherwise: block remains partial (1..511 used), no bitmap changes needed
    }

    /// Set a bit in the 2MB fully-free bitmap
    fn set_bitmap_2m_bit(&self, block_idx: usize) {
        let word_idx = block_idx / BITS_PER_WORD;
        let bit_idx = block_idx % BITS_PER_WORD;
        if word_idx < self.bitmap_2m.len() {
            self.bitmap_2m[word_idx].fetch_or(1u64 << bit_idx, Ordering::Release);
        }
    }

    /// Clear a bit in the 2MB fully-free bitmap
    fn clear_bitmap_2m_bit(&self, block_idx: usize) {
        let word_idx = block_idx / BITS_PER_WORD;
        let bit_idx = block_idx % BITS_PER_WORD;
        if word_idx < self.bitmap_2m.len() {
            self.bitmap_2m[word_idx].fetch_and(!(1u64 << bit_idx), Ordering::Release);
        }
    }

    /// Set a bit in the 2MB partial bitmap (0 < used_count < 512)
    fn set_bitmap_2m_partial_bit(&self, block_idx: usize) {
        let word_idx = block_idx / BITS_PER_WORD;
        let bit_idx = block_idx % BITS_PER_WORD;
        if word_idx < self.bitmap_2m_partial.len() {
            self.bitmap_2m_partial[word_idx].fetch_or(1u64 << bit_idx, Ordering::Release);
        }
    }

    /// Clear a bit in the 2MB partial bitmap
    fn clear_bitmap_2m_partial_bit(&self, block_idx: usize) {
        let word_idx = block_idx / BITS_PER_WORD;
        let bit_idx = block_idx % BITS_PER_WORD;
        if word_idx < self.bitmap_2m_partial.len() {
            self.bitmap_2m_partial[word_idx].fetch_and(!(1u64 << bit_idx), Ordering::Release);
        }
    }

    /// Set a bit in the 1GB fully-free bitmap
    fn set_bitmap_1g_bit(&self, block_idx: usize) {
        let word_idx = block_idx / BITS_PER_WORD;
        let bit_idx = block_idx % BITS_PER_WORD;
        if word_idx < self.bitmap_1g.len() {
            self.bitmap_1g[word_idx].fetch_or(1u64 << bit_idx, Ordering::Release);
        }
    }

    /// Clear a bit in the 1GB fully-free bitmap
    fn clear_bitmap_1g_bit(&self, block_idx: usize) {
        let word_idx = block_idx / BITS_PER_WORD;
        let bit_idx = block_idx % BITS_PER_WORD;
        if word_idx < self.bitmap_1g.len() {
            self.bitmap_1g[word_idx].fetch_and(!(1u64 << bit_idx), Ordering::Release);
        }
    }

    // ========================================================================
    // 4-a Fix: Range-based Hierarchical Update
    // ========================================================================
    //
    // When allocating/freeing a range of pages via `allocate_range_at()` or
    // `allocate_contiguous()`, we must update the 2MB/1GB hierarchy to prevent
    // the fully-free bitmaps from becoming stale.

    /// Update 2MB/1GB hierarchy after allocating a range of pages.
    ///
    /// This is called after `allocate_range()` to ensure the hierarchical
    /// bitmaps reflect the new allocation state. Only touches 2MB blocks
    /// that are affected by the range, not every page.
    fn update_hierarchy_after_range_alloc(&self, start_page: usize, count: usize) {
        if count == 0 {
            return;
        }
        let end_page = start_page + count;
        let first_2mb = start_page / PAGES_PER_2MB_BLOCK;
        let last_2mb = (end_page - 1) / PAGES_PER_2MB_BLOCK;

        for block_2m in first_2mb..=last_2mb {
            if block_2m >= self.total_2mb_blocks {
                break;
            }

            // Calculate how many pages in this 2MB block were allocated
            let block_start = block_2m * PAGES_PER_2MB_BLOCK;
            let block_end = block_start + PAGES_PER_2MB_BLOCK;
            let overlap_start = start_page.max(block_start);
            let overlap_end = end_page.min(block_end);
            let pages_in_block = overlap_end.saturating_sub(overlap_start);

            if pages_in_block == 0 {
                continue;
            }

            // Atomically add to used_count
            let old_count = self.used_count_2m[block_2m].fetch_add(pages_in_block as u16, Ordering::AcqRel);

            // If block was fully free (used_count was 0), update bitmaps
            if old_count == 0 {
                self.clear_bitmap_2m_bit(block_2m);
                self.free_count_2m.fetch_sub(1, Ordering::Relaxed);

                // Update 1GB hierarchy
                let block_1g = block_2m / BLOCKS_2MB_PER_1GB;
                if block_1g < self.total_1gb_blocks {
                    let old_1g = self.used_count_1g[block_1g].fetch_add(1, Ordering::AcqRel);
                    if old_1g == 0 {
                        self.clear_bitmap_1g_bit(block_1g);
                        self.free_count_1g.fetch_sub(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    /// Update 2MB/1GB hierarchy after freeing a range of pages.
    ///
    /// Called after `free_range_pages()` to check if any 2MB blocks became
    /// fully free again.
    fn update_hierarchy_after_range_free(&self, start_page: usize, count: usize) {
        if count == 0 {
            return;
        }
        let end_page = start_page + count;
        let first_2mb = start_page / PAGES_PER_2MB_BLOCK;
        let last_2mb = (end_page - 1) / PAGES_PER_2MB_BLOCK;

        for block_2m in first_2mb..=last_2mb {
            if block_2m >= self.total_2mb_blocks {
                break;
            }

            // Calculate how many pages in this 2MB block were freed
            let block_start = block_2m * PAGES_PER_2MB_BLOCK;
            let block_end = block_start + PAGES_PER_2MB_BLOCK;
            let overlap_start = start_page.max(block_start);
            let overlap_end = end_page.min(block_end);
            let pages_in_block = overlap_end.saturating_sub(overlap_start);

            if pages_in_block == 0 {
                continue;
            }

            // Atomically subtract from used_count
            let old_count = self.used_count_2m[block_2m].fetch_sub(pages_in_block as u16, Ordering::AcqRel);

            // If block is now fully free (used_count becomes 0), update bitmaps
            // Note: old_count is the value BEFORE subtraction
            if old_count == pages_in_block as u16 {
                // Check if this is a complete 2MB block (not partial trailing)
                let block_end_page = (block_2m + 1) * PAGES_PER_2MB_BLOCK;
                if block_end_page <= self.total_pages {
                    self.set_bitmap_2m_bit(block_2m);
                    self.free_count_2m.fetch_add(1, Ordering::Relaxed);

                    // Update 1GB hierarchy
                    let block_1g = block_2m / BLOCKS_2MB_PER_1GB;
                    if block_1g < self.total_1gb_blocks {
                        let old_1g = self.used_count_1g[block_1g].fetch_sub(1, Ordering::AcqRel);
                        if old_1g == 1 {
                            // Check if this is a complete 1GB block
                            let block_1g_end = (block_1g + 1) * BLOCKS_2MB_PER_1GB;
                            if block_1g_end <= self.total_2mb_blocks {
                                self.set_bitmap_1g_bit(block_1g);
                                self.free_count_1g.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }
        }
    }

    // ========================================================================
    // 2MB Block Allocation (O(1) via fully-free bitmap)
    // ========================================================================

    /// Allocate a fully-free 2MB block (O(1) amortized)
    ///
    /// This is much faster than `allocate_contiguous(512, 512)` because it
    /// only scans the 2MB bitmap (16KB for 256GB) instead of the 4KB bitmap.
    ///
    /// Uses the global hint. For better multi-core performance, use
    /// `allocate_2mb_with_hint()` with a per-CPU hint.
    pub fn allocate_2mb(&self) -> Option<u64> {
        self.allocate_2mb_with_hint(&self.hint_2m)
    }

    /// Allocate a fully-free 2MB block using a per-CPU hint
    ///
    /// # Arguments
    /// * `hint` - Per-CPU hint to start searching from (reduces cache line bounce)
    ///
    /// The hint is updated on successful allocation to improve locality.
    pub fn allocate_2mb_with_hint(&self, hint: &AtomicUsize) -> Option<u64> {
        let hint_val = hint.load(Ordering::Relaxed);
        let bitmap_words = self.bitmap_2m.len();

        if bitmap_words == 0 || self.total_2mb_blocks == 0 {
            return None;
        }

        let hint_idx = hint_val % bitmap_words;

        // Scan 2MB bitmap for a fully-free block
        for offset in 0..bitmap_words {
            let word_idx = (hint_idx + offset) % bitmap_words;
            let word = self.bitmap_2m[word_idx].load(Ordering::Acquire);
            if word == 0 {
                continue;
            }

            // Find first set bit
            let bit_idx = word.trailing_zeros() as usize;
            let block_idx = word_idx * BITS_PER_WORD + bit_idx;
            if block_idx >= self.total_2mb_blocks {
                continue;
            }

            // Try to claim this block atomically
            if self.try_allocate_2mb_block(block_idx) {
                hint.store(word_idx, Ordering::Relaxed);
                return Some(self.base + (block_idx as u64) * PAGE_SIZE_2M);
            }
        }

        None
    }

    /// Allocate a 2MB block within a specific arena (sharded allocation)
    ///
    /// First tries to allocate within the arena, then falls back to global if needed.
    ///
    /// # Arguments
    /// * `hint` - Per-CPU hint (updated on success)
    /// * `arena_start` - Start of arena (2MB block index, inclusive)
    /// * `arena_end` - End of arena (2MB block index, exclusive)
    pub fn allocate_2mb_in_arena(
        &self,
        hint: &AtomicUsize,
        arena_start: usize,
        arena_end: usize,
    ) -> Option<u64> {
        if self.total_2mb_blocks == 0 {
            return None;
        }

        // Clamp arena bounds
        let arena_start = arena_start.min(self.total_2mb_blocks);
        let arena_end = arena_end.min(self.total_2mb_blocks);
        let arena_size = arena_end.saturating_sub(arena_start);

        if arena_size == 0 {
            return self.allocate_2mb_with_hint(hint);
        }

        // Phase 1: Try within local arena
        let hint_val = hint.load(Ordering::Relaxed);
        let local_hint = if hint_val >= arena_start && hint_val < arena_end {
            hint_val
        } else {
            arena_start
        };

        for offset in 0..arena_size {
            let block_idx = arena_start + ((local_hint - arena_start + offset) % arena_size);

            if self.try_allocate_2mb_block(block_idx) {
                hint.store(block_idx, Ordering::Relaxed);
                return Some(self.base + (block_idx as u64) * PAGE_SIZE_2M);
            }
        }

        // Phase 2: Steal from outside arena
        for block_idx in 0..arena_start {
            if self.try_allocate_2mb_block(block_idx) {
                return Some(self.base + (block_idx as u64) * PAGE_SIZE_2M);
            }
        }

        for block_idx in arena_end..self.total_2mb_blocks {
            if self.try_allocate_2mb_block(block_idx) {
                return Some(self.base + (block_idx as u64) * PAGE_SIZE_2M);
            }
        }

        None
    }

    /// Try to allocate a specific 2MB block atomically
    fn try_allocate_2mb_block(&self, block_idx: usize) -> bool {
        // Clear the 2MB bitmap bit first (optimistic)
        let word_idx = block_idx / BITS_PER_WORD;
        let bit_idx = block_idx % BITS_PER_WORD;
        let mask = 1u64 << bit_idx;

        let old = self.bitmap_2m[word_idx].fetch_and(!mask, Ordering::AcqRel);
        if old & mask == 0 {
            return false; // Already allocated by another thread
        }

        // Mark all 512 pages in the 4KB bitmap as allocated
        let start_page = block_idx * PAGES_PER_2MB_BLOCK;
        if !self.allocate_range(start_page, PAGES_PER_2MB_BLOCK) {
            // Rollback: restore 2MB bitmap bit
            self.bitmap_2m[word_idx].fetch_or(mask, Ordering::Release);
            return false;
        }

        // Update counters
        self.free_count_2m.fetch_sub(1, Ordering::Relaxed);
        self.used_count_2m[block_idx].store(PAGES_PER_2MB_BLOCK as u16, Ordering::Release);

        // Update 1GB hierarchy
        let block_1g = block_idx / BLOCKS_2MB_PER_1GB;
        if block_1g < self.total_1gb_blocks {
            let old_1g = self.used_count_1g[block_1g].fetch_add(1, Ordering::AcqRel);
            if old_1g == 0 {
                self.clear_bitmap_1g_bit(block_1g);
                self.free_count_1g.fetch_sub(1, Ordering::Relaxed);
            }
        }

        true
    }

    /// Free a 2MB block
    pub fn free_2mb(&self, iova: u64) -> Result<(), IommuError> {
        if iova < self.base {
            return Err(IommuError::InvalidAddress);
        }

        let offset = iova - self.base;
        if offset % PAGE_SIZE_2M != 0 {
            return Err(IommuError::InvalidAlignment);
        }

        let block_idx = (offset / PAGE_SIZE_2M) as usize;
        if block_idx >= self.total_2mb_blocks {
            return Err(IommuError::InvalidAddress);
        }

        // Free all 512 pages in the 4KB bitmap
        let start_page = block_idx * PAGES_PER_2MB_BLOCK;
        self.free_range_pages(start_page, PAGES_PER_2MB_BLOCK)?;

        // Reset used_count and set 2MB bitmap bit
        self.used_count_2m[block_idx].store(0, Ordering::Release);
        self.set_bitmap_2m_bit(block_idx);
        self.free_count_2m.fetch_add(1, Ordering::Relaxed);
        
        // Update buddy allocator: add this block to order 0
        // Then try to coalesce with buddy into higher orders
        self.buddy_coalesce_and_add(block_idx);

        // Update 1GB hierarchy
        let block_1g = block_idx / BLOCKS_2MB_PER_1GB;
        if block_1g < self.total_1gb_blocks {
            let old_1g = self.used_count_1g[block_1g].fetch_sub(1, Ordering::AcqRel);
            if old_1g == 1 {
                self.set_bitmap_1g_bit(block_1g);
                self.free_count_1g.fetch_add(1, Ordering::Relaxed);
            }
        }

        Ok(())
    }
    
    /// Add a 2MB block to buddy allocator with coalescing
    fn buddy_coalesce_and_add(&self, block_idx: usize) {
        let mut current_idx = block_idx;
        let mut current_order = 0usize;
        
        while current_order < BUDDY_2M_MAX_ORDER - 1 {
            // Calculate buddy index at this order
            let buddy_idx = current_idx ^ 1; // XOR with 1 gives buddy at same order
            let buddy_block_at_order = buddy_idx >> current_order;
            
            // Check if buddy exists and is free at this order
            if !self.buddy_2m.is_free(current_order, buddy_block_at_order) {
                // Buddy is not free, stop coalescing
                break;
            }
            
            // Check if buddy's corresponding 2MB blocks are all free in bitmap_2m
            let buddy_start_2m = buddy_block_at_order << current_order;
            let buddy_count = 1usize << current_order;
            let mut buddy_all_free = true;
            
            for i in 0..buddy_count {
                let buddy_2m_idx = buddy_start_2m + i;
                if buddy_2m_idx >= self.total_2mb_blocks {
                    buddy_all_free = false;
                    break;
                }
                let word_idx = buddy_2m_idx / BITS_PER_WORD;
                let bit_idx = buddy_2m_idx % BITS_PER_WORD;
                if word_idx >= self.bitmap_2m.len() || 
                   self.bitmap_2m[word_idx].load(Ordering::Acquire) & (1u64 << bit_idx) == 0 {
                    buddy_all_free = false;
                    break;
                }
            }
            
            if !buddy_all_free {
                break;
            }
            
            // Remove buddy from current order
            self.buddy_2m.set_allocated(current_order, buddy_block_at_order);
            
            // Move to next order (parent block)
            current_idx = current_idx.min(buddy_idx);
            current_order += 1;
        }
        
        // Add the (possibly coalesced) block to its final order
        let final_block_idx = current_idx >> current_order;
        self.buddy_2m.set_free(current_order, final_block_idx);
    }

    // ========================================================================
    // 1GB Block Allocation (O(1) via fully-free bitmap)
    // ========================================================================

    /// Allocate a fully-free 1GB block (O(1))
    ///
    /// This is extremely fast: only scans a 32-byte bitmap for 256GB IOVA space.
    pub fn allocate_1gb(&self) -> Option<u64> {
        let bitmap_words = self.bitmap_1g.len();

        if bitmap_words == 0 || self.total_1gb_blocks == 0 {
            return None;
        }

        // Scan 1GB bitmap for a fully-free block
        for word_idx in 0..bitmap_words {
            let word = self.bitmap_1g[word_idx].load(Ordering::Acquire);
            if word == 0 {
                continue;
            }

            // Find first set bit
            let bit_idx = word.trailing_zeros() as usize;
            let block_idx = word_idx * BITS_PER_WORD + bit_idx;
            if block_idx >= self.total_1gb_blocks {
                continue;
            }

            // Try to claim this block atomically
            if self.try_allocate_1gb_block(block_idx) {
                return Some(self.base + (block_idx as u64) * PAGE_SIZE_1G);
            }
        }

        None
    }

    /// Try to allocate a specific 1GB block atomically (4-b Fix: Safe 2-phase)
    ///
    /// # 4-b Fix: Race Condition Prevention
    ///
    /// The previous implementation had a race condition:
    /// 1. Thread A claims 1GB bit
    /// 2. Thread A starts claiming 2MB bits one by one
    /// 3. Thread B claims one of those 2MB bits via allocate_2mb()
    /// 4. Thread A's 4KB allocation fails
    /// 5. Thread A rolls back ALL 2MB bits, including the one Thread B claimed
    ///
    /// The fix uses a 2-phase approach:
    /// - Phase 1: Atomically claim ALL 512 2MB bits, tracking which ones we got
    /// - Phase 2: If we got all 512, proceed; otherwise roll back ONLY what we claimed
    fn try_allocate_1gb_block(&self, block_idx: usize) -> bool {
        // Clear the 1GB bitmap bit first (optimistic)
        let word_idx_1g = block_idx / BITS_PER_WORD;
        let bit_idx_1g = block_idx % BITS_PER_WORD;
        let mask_1g = 1u64 << bit_idx_1g;

        let old = self.bitmap_1g[word_idx_1g].fetch_and(!mask_1g, Ordering::AcqRel);
        if old & mask_1g == 0 {
            return false; // Already allocated by another thread
        }

        // Phase 1: Try to atomically claim all 512 2MB blocks
        let start_2mb = block_idx * BLOCKS_2MB_PER_1GB;
        let end_2mb = (start_2mb + BLOCKS_2MB_PER_1GB).min(self.total_2mb_blocks);
        let expected_2mb_blocks = end_2mb - start_2mb;

        // Track which 2MB blocks we successfully claimed
        let mut claimed_2mb_count = 0usize;

        for block_2m in start_2mb..end_2mb {
            let word_idx_2m = block_2m / BITS_PER_WORD;
            let bit_idx_2m = block_2m % BITS_PER_WORD;
            let mask_2m = 1u64 << bit_idx_2m;

            // Try to claim this 2MB block atomically
            let old_2m = self.bitmap_2m[word_idx_2m].fetch_and(!mask_2m, Ordering::AcqRel);
            if old_2m & mask_2m != 0 {
                // Successfully claimed this 2MB block
                claimed_2mb_count += 1;
            } else {
                // This 2MB block was already claimed by someone else
                // Roll back what we've claimed and give up
                self.rollback_1gb_partial(block_idx, start_2mb, claimed_2mb_count);
                return false;
            }
        }

        // Verify we got all 2MB blocks we expected
        if claimed_2mb_count != expected_2mb_blocks {
            // Should not happen, but be defensive
            self.rollback_1gb_partial(block_idx, start_2mb, claimed_2mb_count);
            return false;
        }

        // Phase 2: Allocate all pages in the 4KB bitmap
        let start_page = block_idx * PAGES_PER_1GB_BLOCK;
        let pages = claimed_2mb_count * PAGES_PER_2MB_BLOCK;
        
        if !self.allocate_range(start_page, pages) {
            // 4KB allocation failed - roll back 2MB and 1GB
            self.rollback_1gb_partial(block_idx, start_2mb, claimed_2mb_count);
            return false;
        }

        // Success! Update all counters
        for block_2m in start_2mb..end_2mb {
            self.used_count_2m[block_2m].store(PAGES_PER_2MB_BLOCK as u16, Ordering::Release);
        }
        
        self.free_count_1g.fetch_sub(1, Ordering::Relaxed);
        self.free_count_2m.fetch_sub(claimed_2mb_count, Ordering::Relaxed);
        self.used_count_1g[block_idx].store(claimed_2mb_count as u16, Ordering::Release);

        true
    }

    /// Roll back a partial 1GB allocation (4-b Fix helper)
    ///
    /// Only restores the 2MB blocks that WE claimed, not blocks claimed by other threads.
    fn rollback_1gb_partial(&self, block_1g: usize, start_2mb: usize, claimed_count: usize) {
        // Restore 1GB bitmap bit
        let word_idx_1g = block_1g / BITS_PER_WORD;
        let bit_idx_1g = block_1g % BITS_PER_WORD;
        self.bitmap_1g[word_idx_1g].fetch_or(1u64 << bit_idx_1g, Ordering::Release);

        // Restore only the 2MB blocks we claimed
        for i in 0..claimed_count {
            let block_2m = start_2mb + i;
            self.set_bitmap_2m_bit(block_2m);
            // Don't touch used_count_2m since we never updated it
        }
    }

    /// Free a 1GB block
    pub fn free_1gb(&self, iova: u64) -> Result<(), IommuError> {
        if iova < self.base {
            return Err(IommuError::InvalidAddress);
        }

        let offset = iova - self.base;
        if offset % PAGE_SIZE_1G != 0 {
            return Err(IommuError::InvalidAlignment);
        }

        let block_idx = (offset / PAGE_SIZE_1G) as usize;
        if block_idx >= self.total_1gb_blocks {
            return Err(IommuError::InvalidAddress);
        }

        // Free all 2MB blocks and their 4KB pages
        let start_2mb = block_idx * BLOCKS_2MB_PER_1GB;
        let end_2mb = (start_2mb + BLOCKS_2MB_PER_1GB).min(self.total_2mb_blocks);

        for block_2m in start_2mb..end_2mb {
            let start_page = block_2m * PAGES_PER_2MB_BLOCK;
            let _ = self.free_range_pages(start_page, PAGES_PER_2MB_BLOCK);
            self.used_count_2m[block_2m].store(0, Ordering::Release);
            self.set_bitmap_2m_bit(block_2m);
        }

        // Update counters
        let freed_2mb = end_2mb - start_2mb;
        self.free_count_2m.fetch_add(freed_2mb, Ordering::Relaxed);
        self.used_count_1g[block_idx].store(0, Ordering::Release);
        self.set_bitmap_1g_bit(block_idx);
        self.free_count_1g.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    // ========================================================================
    // Statistics / Accessors
    // ========================================================================

    /// Get base IOVA address
    #[inline]
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Get free 4KB page count
    #[inline]
    pub fn free_count(&self) -> usize {
        self.free_count_4k.load(Ordering::Relaxed)
    }

    /// Get free 2MB block count (fully free only)
    #[inline]
    pub fn free_count_2mb(&self) -> usize {
        self.free_count_2m.load(Ordering::Relaxed)
    }

    /// Get free 1GB block count (fully free only)
    #[inline]
    pub fn free_count_1gb(&self) -> usize {
        self.free_count_1g.load(Ordering::Relaxed)
    }

    /// Get total 4KB pages
    #[inline]
    pub fn total_pages(&self) -> usize {
        self.total_pages
    }

    /// Get total 2MB blocks
    #[inline]
    pub fn total_2mb_blocks(&self) -> usize {
        self.total_2mb_blocks
    }

    /// Get total 1GB blocks
    #[inline]
    pub fn total_1gb_blocks(&self) -> usize {
        self.total_1gb_blocks
    }
    
    /// Get detail bitmap (for single-writer arena initialization)
    #[inline]
    pub fn detail(&self) -> &[AtomicU64] {
        &self.detail
    }
}

// ============================================================================
// Fast IOVA Allocator (Combines Magazine + Bitmap + Quarantine)
// ============================================================================

/// Maximum number of CPUs supported for per-CPU magazines
const MAX_CPUS: usize = crate::mm::MAX_CPUS;

/// High-performance IOVA allocator with allocation-free hot path
///
/// This allocator provides:
/// - O(1) allocation for 4KB/2MB pages via per-CPU magazines (IRQ-off guarded)
/// - O(1) amortized allocation via bitmap for magazine refills
/// - Delayed reclamation via per-CPU quarantine (epoch-based)
/// - Fallback to tree-based allocator for 1GB+ allocations (rare)
///
/// # Quarantine / Epoch-Based Reclamation
///
/// Free'd IOVAs are not returned to the bitmap immediately. Instead, they
/// are placed in a per-CPU quarantine ring with the current epoch. After
/// IOTLB invalidation completes (epoch advances), quarantined entries are
/// batch-returned to the bitmap.
///
/// This prevents IOTLB stale entry issues and reduces bitmap write frequency.
pub struct IovaAllocatorFast {
    /// Base IOVA address
    base: u64,
    /// Total size in bytes
    size: u64,
    /// Bitmap allocator for 4KB pages
    bitmap_4k: IovaBitmap,
    /// Per-CPU magazines (indexed by CPU ID)
    magazines: alloc::boxed::Box<[PerCpuMagazine]>,
    /// Per-CPU quarantine rings (indexed by CPU ID)
    quarantines: alloc::boxed::Box<[IrqMutex<QuarantineRing>]>,
    /// Current epoch (incremented after IOTLB invalidation)
    current_epoch: AtomicU32,
    /// Last completed epoch (all entries <= this epoch are safe to reclaim)
    completed_epoch: AtomicU32,
    /// Statistics
    stats: IovaAllocatorFastStats,
}

/// Statistics for the fast allocator
pub struct IovaAllocatorFastStats {
    /// Magazine hits (fast path)
    pub magazine_hits: AtomicU64,
    /// Magazine misses (fell through to bitmap)
    pub magazine_misses: AtomicU64,
    /// Bitmap allocations
    pub bitmap_allocs: AtomicU64,
    /// Magazine refills
    pub magazine_refills: AtomicU64,
    /// Quarantine pushes
    pub quarantine_pushes: AtomicU64,
    /// Quarantine drains (batch returns to bitmap)
    pub quarantine_drains: AtomicU64,
    /// Quarantine forced drains (ring full)
    pub quarantine_forced_drains: AtomicU64,
    // === Hugepage Preservation Statistics ===
    /// 4KB allocations from partial 2MB blocks (good - preserves hugepages)
    pub allocs_from_partial_2m: AtomicU64,
    /// 4KB allocations that polluted a fully-free 2MB block (bad - consumed hugepage)
    pub hugepage_pollutions: AtomicU64,
    /// 2MB allocation failures (no fully-free 2MB block available)
    pub alloc_2m_failures: AtomicU64,
    // === Contention Statistics ===
    /// CAS retry count in detail bitmap (high value indicates contention)
    pub cas_retries_detail: AtomicU64,
    /// Remote free count (freed on different CPU than allocated)
    pub remote_frees: AtomicU64,
    /// Local free count (freed on same CPU as allocated)
    pub local_frees: AtomicU64,
    // === Single-Writer Arena Statistics ===
    /// Allocations from single-writer arena (non-atomic fast path)
    pub single_writer_allocs: AtomicU64,
    /// Frees routed through single-writer arena
    pub single_writer_frees: AtomicU64,
    /// Remote frees drained into single-writer arena
    pub single_writer_remote_drains: AtomicU64,
}

impl IovaAllocatorFastStats {
    const fn new() -> Self {
        Self {
            magazine_hits: AtomicU64::new(0),
            magazine_misses: AtomicU64::new(0),
            bitmap_allocs: AtomicU64::new(0),
            magazine_refills: AtomicU64::new(0),
            quarantine_pushes: AtomicU64::new(0),
            quarantine_drains: AtomicU64::new(0),
            quarantine_forced_drains: AtomicU64::new(0),
            allocs_from_partial_2m: AtomicU64::new(0),
            hugepage_pollutions: AtomicU64::new(0),
            alloc_2m_failures: AtomicU64::new(0),
            cas_retries_detail: AtomicU64::new(0),
            remote_frees: AtomicU64::new(0),
            local_frees: AtomicU64::new(0),
            single_writer_allocs: AtomicU64::new(0),
            single_writer_frees: AtomicU64::new(0),
            single_writer_remote_drains: AtomicU64::new(0),
        }
    }
}

impl IovaAllocatorFast {
    /// Create a new fast IOVA allocator with arena sharding
    ///
    /// # Arguments
    /// * `base` - Base IOVA address (must be page-aligned)
    /// * `size` - Total size of IOVA space
    ///
    /// # Arena Sharding
    ///
    /// The IOVA space is divided into arenas, one per CPU. Each CPU preferentially
    /// allocates from its own arena to minimize cache line contention. When a local
    /// arena is exhausted, the CPU steals from other arenas.
    ///
    /// # Arena Owner Optimization
    ///
    /// Each CPU owns its arena and gets lock-free allocation priority.
    /// Non-owner allocations track steal attempts for adaptive ownership transfer.
    pub fn new(base: u64, size: u64) -> Self {
        let total_pages = (size / PAGE_SIZE_4K) as usize;
        let mut bitmap_4k = IovaBitmap::new(base, total_pages);
        
        // Configure arena ownership for MAX_CPUS
        // This ensures each CPU has its own arena with ownership tracking
        bitmap_4k.reconfigure_arena_ownership(MAX_CPUS);
        
        // Calculate arena sizes
        let total_words_4k = (total_pages + BITS_PER_WORD - 1) / BITS_PER_WORD;
        let total_blocks_2m = total_pages / PAGES_PER_2MB_BLOCK;
        
        // Divide arenas among CPUs (at least 1 word per CPU, or share if not enough)
        let words_per_cpu = (total_words_4k + MAX_CPUS - 1) / MAX_CPUS;
        let blocks_2m_per_cpu = if total_blocks_2m >= MAX_CPUS {
            (total_blocks_2m + MAX_CPUS - 1) / MAX_CPUS
        } else {
            1 // Share all blocks if fewer than CPU count
        };
        
        // Allocate per-CPU magazines with arena boundaries
        let mut magazines = alloc::vec::Vec::with_capacity(MAX_CPUS);
        for cpu_id in 0..MAX_CPUS {
            let mut mag = PerCpuMagazine::new();
            
            // Calculate this CPU's arena boundaries (non-overlapping)
            let arena_start_4k = cpu_id * words_per_cpu;
            let arena_end_4k = ((cpu_id + 1) * words_per_cpu).min(total_words_4k);
            
            let arena_start_2m = cpu_id * blocks_2m_per_cpu;
            let arena_end_2m = ((cpu_id + 1) * blocks_2m_per_cpu).min(total_blocks_2m);
            
            // 5C: Pass cpu_id for hint scattering
            mag.set_arena(cpu_id, arena_start_4k, arena_end_4k, arena_start_2m, arena_end_2m);
            magazines.push(mag);
        }
        
        // Allocate per-CPU quarantine rings
        let mut quarantines = alloc::vec::Vec::with_capacity(MAX_CPUS);
        for _ in 0..MAX_CPUS {
            quarantines.push(IrqMutex::new(QuarantineRing::new()));
        }
        
        Self {
            base,
            size,
            bitmap_4k,
            magazines: magazines.into_boxed_slice(),
            quarantines: quarantines.into_boxed_slice(),
            current_epoch: AtomicU32::new(0),
            completed_epoch: AtomicU32::new(0),
            stats: IovaAllocatorFastStats::new(),
        }
    }
    
    /// Enable single-writer arena mode for all CPUs
    ///
    /// This enables the non-atomic fast path where each CPU operates on
    /// its own bitmap copy without any atomic RMW operations.
    ///
    /// # Safety
    /// This should be called during system initialization, before
    /// heavy concurrent allocation begins.
    ///
    /// # Performance
    /// With single-writer mode enabled:
    /// - Owner CPU allocations: NO atomics (tzcnt + bit clear)
    /// - Owner CPU frees: NO atomics (bit set)
    /// - Non-owner frees: Push to RemoteFreeRing (lock-free)
    pub fn enable_single_writer_arenas(&self) {
        let global_detail = self.bitmap_4k.detail();
        
        for cpu_id in 0..MAX_CPUS {
            let magazine = &self.magazines[cpu_id];
            
            // Only enable if arena has valid range and not too large
            if magazine.arena_end_4k > magazine.arena_start_4k {
                let num_words = magazine.arena_end_4k - magazine.arena_start_4k;
                
                // Only enable if arena fits within MAX_WORDS_PER_ARENA
                if num_words <= MAX_WORDS_PER_ARENA {
                    magazine.init_single_writer_arena(global_detail);
                }
            }
        }
    }
    
    /// Sync single-writer arenas to global bitmap
    ///
    /// This should be called periodically (e.g., at epoch boundaries)
    /// to ensure the global bitmap reflects all local changes.
    /// This is important for:
    /// - Statistics accuracy
    /// - Large allocation (2MB/1GB) availability tracking
    /// - System-wide free count consistency
    pub fn sync_single_writer_arenas(&self) {
        let global_detail = self.bitmap_4k.detail();
        
        for cpu_id in 0..MAX_CPUS {
            let magazine = &self.magazines[cpu_id];
            if magazine.is_single_writer_enabled() {
                let mut arena_guard = magazine.arena_detail.lock();
                if let Some(ref mut arena) = *arena_guard {
                    arena.sync_to_global(global_detail);
                }
            }
        }
    }

    /// Get current CPU ID via per-CPU data (GsBase)
    #[inline]
    fn current_cpu_id() -> Option<usize> {
        crate::mm::try_current_cpu_id().filter(|&cpu_id| cpu_id < MAX_CPUS)
    }

    /// Determine which CPU owns a given IOVA (for 4KB pages)
    ///
    /// Returns the CPU ID that "owns" this IOVA's arena, i.e., the CPU
    /// that should be the primary updater of the bitmap for this address.
    #[inline]
    fn owner_cpu_for_iova_4k(&self, iova: u64) -> usize {
        let page_idx = ((iova - self.base) / PAGE_SIZE_4K) as usize;
        let word_idx = page_idx / BITS_PER_WORD;
        
        // Find which CPU's arena contains this word
        for cpu_id in 0..MAX_CPUS {
            let mag = &self.magazines[cpu_id];
            if word_idx >= mag.arena_start_4k && word_idx < mag.arena_end_4k {
                return cpu_id;
            }
        }
        
        // Fallback: if no arena found (shouldn't happen), return 0
        0
    }

    /// Drain remote free ring for the current CPU
    ///
    /// This should be called periodically by each CPU to process frees
    /// that were pushed by other CPUs to this CPU's arena.
    ///
    /// Returns the number of entries drained.
    pub fn drain_remote_frees(&self) -> usize {
        let Some(cpu_id) = Self::current_cpu_id() else {
            return 0;
        };
        
        self.drain_remote_frees_for_cpu(cpu_id)
    }
    
    /// Drain remote free ring for a specific CPU
    ///
    /// # Optimization: Return Coalescing (5B)
    ///
    /// Instead of calling free_page() N times for N pages in the same word
    /// (N atomic fetch_or operations), we coalesce pages by word_idx and
    /// use a single fetch_or per word via free_pages_coalesced().
    ///
    /// This dramatically reduces atomic contention when multiple pages
    /// from the same word are freed in rapid succession.
    fn drain_remote_frees_for_cpu(&self, cpu_id: usize) -> usize {
        let magazine = &self.magazines[cpu_id];
        
        // Drain up to 64 entries at a time
        let mut entries = [RemoteFreeEntry::empty(); 64];
        let drained = magazine.remote_free_ring.drain(&mut entries);
        
        if drained == 0 {
            return 0;
        }
        
        // Coalescing buffer: word_idx -> (coalesced_mask, page_count)
        // Max 64 unique words from 64 entries
        const MAX_WORDS: usize = 64;
        let mut word_masks: [(usize, u64, usize); MAX_WORDS] = [(usize::MAX, 0, 0); MAX_WORDS];
        let mut word_count = 0usize;
        
        // 2MB/1GB frees (don't coalesce, process directly)
        let mut large_frees: [(u8, u64); 16] = [(0, 0); 16];
        let mut large_count = 0usize;
        
        // Phase 1: Sort entries into coalescing buffer
        for entry in &entries[..drained] {
            match entry.size_class {
                0 => {
                    // 4KB page: compute word_idx and bit
                    if entry.iova < self.bitmap_4k.base {
                        continue;
                    }
                    let page_idx = ((entry.iova - self.bitmap_4k.base) / PAGE_SIZE_4K) as usize;
                    if page_idx >= self.bitmap_4k.total_pages {
                        continue;
                    }
                    
                    let word_idx = page_idx / BITS_PER_WORD;
                    let bit_idx = page_idx % BITS_PER_WORD;
                    let bit_mask = 1u64 << bit_idx;
                    
                    // Find or create entry in coalescing buffer
                    let mut found = false;
                    for i in 0..word_count {
                        if word_masks[i].0 == word_idx {
                            word_masks[i].1 |= bit_mask;
                            word_masks[i].2 += 1;
                            found = true;
                            break;
                        }
                    }
                    if !found && word_count < MAX_WORDS {
                        word_masks[word_count] = (word_idx, bit_mask, 1);
                        word_count += 1;
                    }
                }
                1 | 2 => {
                    // 2MB or 1GB page: collect for later
                    if large_count < large_frees.len() {
                        large_frees[large_count] = (entry.size_class, entry.iova);
                        large_count += 1;
                    }
                }
                _ => {
                    // Unknown size class, ignore
                }
            }
        }
        
        // Phase 2: Process coalesced 4KB frees
        for i in 0..word_count {
            let (word_idx, coalesced_mask, page_count) = word_masks[i];
            if word_idx == usize::MAX {
                continue;
            }
            
            if let Ok(Some(became_non_empty_word)) = self.bitmap_4k.free_pages_coalesced(word_idx, coalesced_mask, page_count) {
                // Word became non-empty, push to owner's free word stack
                let mut stack = magazine.free_word_stack.lock();
                let _ = stack.push(became_non_empty_word);
            }
        }
        
        // Phase 3: Process large frees
        for i in 0..large_count {
            let (size_class, iova) = large_frees[i];
            match size_class {
                1 => {
                    let _ = self.bitmap_4k.free_2mb(iova);
                }
                2 => {
                    let _ = self.bitmap_4k.free_1gb(iova);
                }
                _ => {}
            }
        }
        
        drained
    }
    
    /// Drain remote frees directly into single-writer arena (non-atomic path)
    ///
    /// This is called by the owner CPU when using single-writer mode.
    /// Instead of processing remote frees through atomic bitmap operations,
    /// we directly update the non-atomic PerArenaDetail bitmap.
    ///
    /// # Arguments
    /// * `magazine` - The owner CPU's magazine
    /// * `arena` - The owner CPU's arena detail (mutable, non-atomic)
    ///
    /// # Performance
    /// This avoids all atomic RMW operations for frees that were pushed
    /// to RemoteFreeRing by non-owner CPUs.
    #[inline]
    fn drain_remote_frees_into_arena(&self, magazine: &PerCpuMagazine, arena: &mut PerArenaDetail) {
        // Drain up to 32 entries from RemoteFreeRing
        let mut entries = [RemoteFreeEntry::empty(); 32];
        let drained = magazine.remote_free_ring.drain(&mut entries);
        
        if drained == 0 {
            return;
        }
        
        let mut freed_count = 0usize;
        
        // Collect pages within our arena's range for batch processing
        let mut arena_pages: [usize; 32] = [usize::MAX; 32];
        let mut arena_page_count = 0usize;
        
        // Pages outside our arena range (must go through atomic path)
        let mut external_pages: [(usize, u64); 32] = [(usize::MAX, 0); 32];
        let mut external_count = 0usize;
        
        // 2MB/1GB frees (always atomic)
        let mut large_frees: [(u8, u64); 8] = [(0, 0); 8];
        let mut large_count = 0usize;
        
        // Phase 1: Categorize entries
        for entry in &entries[..drained] {
            match entry.size_class {
                0 => {
                    // 4KB page
                    if entry.iova < self.bitmap_4k.base {
                        continue;
                    }
                    let page_idx = ((entry.iova - self.bitmap_4k.base) / PAGE_SIZE_4K) as usize;
                    if page_idx >= self.bitmap_4k.total_pages {
                        continue;
                    }
                    
                    // Check if this page is within our arena's word range
                    let word_idx = page_idx / BITS_PER_WORD;
                    if word_idx >= arena.word_start && word_idx < arena.word_end {
                        // Within arena - can use non-atomic path
                        if arena_page_count < arena_pages.len() {
                            arena_pages[arena_page_count] = page_idx;
                            arena_page_count += 1;
                        }
                    } else {
                        // Outside arena - must use atomic path
                        if external_count < external_pages.len() {
                            external_pages[external_count] = (word_idx, entry.iova);
                            external_count += 1;
                        }
                    }
                }
                1 | 2 => {
                    if large_count < large_frees.len() {
                        large_frees[large_count] = (entry.size_class, entry.iova);
                        large_count += 1;
                    }
                }
                _ => {}
            }
        }
        
        // Phase 2: Process arena pages (NON-ATOMIC!)
        if arena_page_count > 0 {
            arena.free_pages_batch(&arena_pages[..arena_page_count]);
            freed_count += arena_page_count;
        }
        
        // Phase 3: Process external pages (atomic fallback)
        for i in 0..external_count {
            let (_, iova) = external_pages[i];
            let _ = self.bitmap_4k.free_page(iova);
            freed_count += 1;
        }
        
        // Phase 4: Process large frees
        for i in 0..large_count {
            let (size_class, iova) = large_frees[i];
            match size_class {
                1 => {
                    let _ = self.bitmap_4k.free_2mb(iova);
                }
                2 => {
                    let _ = self.bitmap_4k.free_1gb(iova);
                }
                _ => {}
            }
        }
        
        if freed_count > 0 {
            self.stats.single_writer_remote_drains.fetch_add(freed_count as u64, Ordering::Relaxed);
        }
    }

    // ========================================================================
    // Epoch Management for Quarantine
    // ========================================================================

    /// Advance the current epoch (call before IOTLB invalidation)
    ///
    /// Returns the new epoch value.
    pub fn advance_epoch(&self) -> u32 {
        self.current_epoch.fetch_add(1, Ordering::Release)
    }

    /// Mark an epoch as completed (call after IOTLB invalidation completes)
    ///
    /// All quarantined entries with epoch <= completed_epoch will be eligible
    /// for reclamation on the next drain.
    pub fn complete_epoch(&self, epoch: u32) {
        // Only advance if the new epoch is greater
        let _ = self.completed_epoch.fetch_max(epoch, Ordering::Release);
    }

    /// Get the current epoch
    #[inline]
    pub fn current_epoch(&self) -> u32 {
        self.current_epoch.load(Ordering::Acquire)
    }

    /// Get the completed epoch
    #[inline]
    pub fn completed_epoch(&self) -> u32 {
        self.completed_epoch.load(Ordering::Acquire)
    }

    // ========================================================================
    // Allocation API
    // ========================================================================

    /// Allocate an IOVA (hot path - O(1) for 4KB/2MB)
    pub fn allocate(&self, size: u64, granularity: IovaGranularity) -> Option<u64> {
        debug_assert_eq!(
            size,
            granularity.size_bytes(),
            "IOVA allocate size must match granularity"
        );
        if size != granularity.size_bytes() {
            return None;
        }

        match granularity {
            IovaGranularity::Page4K => self.allocate_4k(),
            IovaGranularity::Page2M => self.allocate_2m(),
            IovaGranularity::Page1G => self.allocate_1g(size),
        }
    }

    /// Allocate a 4KB page (O(1) fast path with arena sharding + hugepage preservation)
    ///
    /// Allocation strategy (in order of preference):
    /// 0. Per-CPU sub-magazine (O(1), claimed word, zero atomics!)
    /// 1. Per-CPU magazine (O(1), zero contention)
    /// 2. Per-CPU free word stack (O(1), local non-empty words)
    /// 3. Partial 2MB blocks (O(1) amortized, preserves fully-free 2MB)
    /// 4. Arena-restricted hierarchy scan (fallback, may pollute hugepages)
    ///
    /// # Arena Owner Optimization (Optimization 1)
    /// When CPU owns its arena, allocation proceeds with minimal contention.
    /// Non-owner allocation tracks steal attempts for adaptive ownership transfer.
    ///
    /// # Single-Writer Arena (Non-Atomic Fast Path)
    /// When enabled, owner CPU uses non-atomic bit manipulation for allocation.
    /// This eliminates all atomic RMW operations on the hot path.
    #[inline]
    fn allocate_4k(&self) -> Option<u64> {
        // Fast path: try per-CPU magazine
        if let Some(cpu_id) = Self::current_cpu_id() {
            let magazine = &self.magazines[cpu_id];
            let my_cpu_id = magazine.cpu_id;
            
            // ================================================================
            // FASTEST PATH: Single-Writer Arena (NO ATOMICS!)
            //
            // If single-writer mode is enabled for this CPU, we can allocate
            // directly from the non-atomic per-arena bitmap. This is the
            // ultimate fast path: just tzcnt + bit clear + address calc.
            // ================================================================
            if magazine.is_single_writer_enabled() {
                let mut arena_guard = magazine.arena_detail.lock();
                if let Some(ref mut arena) = *arena_guard {
                    if !arena.is_frozen() && arena.has_free_pages() {
                        // First, drain any pending remote frees into our arena
                        self.drain_remote_frees_into_arena(magazine, arena);
                        
                        // Try to allocate from arena (NO ATOMIC RMW!)
                        if let Some(page_idx) = arena.allocate_page() {
                            let iova = self.bitmap_4k.base() + (page_idx as u64) * PAGE_SIZE_4K;
                            self.stats.magazine_hits.fetch_add(1, Ordering::Relaxed);
                            self.stats.single_writer_allocs.fetch_add(1, Ordering::Relaxed);
                            // Update 2MB/1GB hierarchy (still needed for large allocations)
                            self.bitmap_4k.on_page_allocated(page_idx);
                            return Some(iova);
                        }
                    }
                }
            }
            
            // === Fast path #0: Sub-magazine (claimed word, zero atomics!) ===
            {
                let mut sub_mag = magazine.sub_magazine_4k.lock();
                if let Some(iova) = sub_mag.allocate() {
                    self.stats.magazine_hits.fetch_add(1, Ordering::Relaxed);
                    // Update hierarchy for this allocation
                    let page_idx = ((iova - self.bitmap_4k.base()) / PAGE_SIZE_4K) as usize;
                    self.bitmap_4k.on_page_allocated(page_idx);
                    self.bitmap_4k.free_count_4k.fetch_sub(1, Ordering::Relaxed);
                    return Some(iova);
                }
                
                // Sub-magazine empty, try to claim a new word
                // First check per-CPU free word stack for a candidate word
                {
                    let mut stack = magazine.free_word_stack.lock();
                    while let Some(word_idx) = stack.pop() {
                        // Try to claim this word
                        let bits = self.bitmap_4k.try_claim_word(word_idx);
                        if bits != 0 {
                            let base_iova = self.bitmap_4k.base() + (word_idx as u64) * BITS_PER_WORD as u64 * PAGE_SIZE_4K;
                            let count = sub_mag.claim(bits, word_idx, base_iova);
                            
                            // Update hierarchy for entire word claim
                            let first_page_idx = word_idx * BITS_PER_WORD;
                            self.bitmap_4k.on_pages_allocated_batch(first_page_idx, count);
                            
                            // Now allocate from sub-magazine
                            if let Some(iova) = sub_mag.allocate() {
                                self.stats.magazine_hits.fetch_add(1, Ordering::Relaxed);
                                return Some(iova);
                            }
                        }
                    }
                }
            }
            
            // === Fast path #1: Traditional magazine ===
            if let Some(mag) = magazine.get(0) {
                let mut mag = mag.lock();
                if let Some(iova) = mag.pop() {
                    self.stats.magazine_hits.fetch_add(1, Ordering::Relaxed);
                    return Some(iova);
                }
            }
            
            self.stats.magazine_misses.fetch_add(1, Ordering::Relaxed);
            
            // ================================================================
            // Medium path: Always prefer word claim (Optimization 2)
            //
            // Instead of allocating single pages with individual CAS operations,
            // we claim entire words (64 pages) and use sub-magazine. This reduces
            // atomic operations from N CAS per N pages to just 1 swap per 64 pages.
            //
            // Arena Owner Optimization (Optimization 1):
            // Owner CPU gets lock-free fast path for its arena.
            // Non-owner allocation tracks steal attempts for adaptive transfer.
            // ================================================================
            
            // Medium path #1: Try word claim from partial 2MB blocks
            // Find a non-empty word in partial blocks (hugepage preservation)
            {
                let mut sub_mag = magazine.sub_magazine_4k.lock();
                
                // Try to find and claim a word from partial 2MB blocks
                for _ in 0..4 { // Max 4 attempts
                    if let Some(word_idx) = self.bitmap_4k.find_non_empty_word_in_partial(&magazine.hint_2m_partial) {
                        let bits = self.bitmap_4k.try_claim_word(word_idx);
                        if bits != 0 {
                            let base_iova = self.bitmap_4k.base() + (word_idx as u64) * BITS_PER_WORD as u64 * PAGE_SIZE_4K;
                            let count = sub_mag.claim(bits, word_idx, base_iova);
                            
                            // Update hierarchy
                            let first_page_idx = word_idx * BITS_PER_WORD;
                            self.bitmap_4k.on_pages_allocated_batch(first_page_idx, count);
                            magazine.hint_4k.store(word_idx, Ordering::Relaxed);
                            
                            // Allocate from sub-magazine
                            if let Some(iova) = sub_mag.allocate() {
                                self.stats.bitmap_allocs.fetch_add(1, Ordering::Relaxed);
                                self.stats.allocs_from_partial_2m.fetch_add(1, Ordering::Relaxed);
                                return Some(iova);
                            }
                        }
                    } else {
                        break; // No more partial blocks
                    }
                }
            }
            
            // Medium path #2: Arena owner-optimized allocation
            // Uses ownership tracking for adaptive load balancing
            if let Some(iova) = self.bitmap_4k.allocate_page_owner_optimized(
                my_cpu_id,
                &magazine.hint_4k,
                magazine.arena_start_4k,
                magazine.arena_end_4k,
            ) {
                self.stats.bitmap_allocs.fetch_add(1, Ordering::Relaxed);
                self.stats.hugepage_pollutions.fetch_add(1, Ordering::Relaxed);
                return Some(iova);
            }
            
            // Medium path #3: Fallback to global hierarchy scan with word claim
            // This may pollute hugepages but still uses efficient word claim
            {
                let mut sub_mag = magazine.sub_magazine_4k.lock();
                
                // Find any non-empty word from summary hierarchy
                if let Some(word_idx) = self.bitmap_4k.find_non_empty_word_from_summary(&magazine.hint_4k) {
                    let bits = self.bitmap_4k.try_claim_word(word_idx);
                    if bits != 0 {
                        let base_iova = self.bitmap_4k.base() + (word_idx as u64) * BITS_PER_WORD as u64 * PAGE_SIZE_4K;
                        let count = sub_mag.claim(bits, word_idx, base_iova);
                        
                        // Update hierarchy
                        let first_page_idx = word_idx * BITS_PER_WORD;
                        self.bitmap_4k.on_pages_allocated_batch(first_page_idx, count);
                        magazine.hint_4k.store(word_idx, Ordering::Relaxed);
                        
                        // Allocate from sub-magazine
                        if let Some(iova) = sub_mag.allocate() {
                            self.stats.bitmap_allocs.fetch_add(1, Ordering::Relaxed);
                            self.stats.hugepage_pollutions.fetch_add(1, Ordering::Relaxed);
                            return Some(iova);
                        }
                    }
                }
            }
            
            return None;
        }
        
        self.stats.magazine_misses.fetch_add(1, Ordering::Relaxed);
        
        // Fallback: allocate from bitmap using global hint (no arena restriction)
        // No per-CPU state available, use simple allocation
        let iova = self.bitmap_4k.allocate_page()?;
        self.stats.bitmap_allocs.fetch_add(1, Ordering::Relaxed);
        self.stats.hugepage_pollutions.fetch_add(1, Ordering::Relaxed);
        
        Some(iova)
    }

    /// Try to refill the 4KB magazine for a CPU
    ///
    /// Uses per-CPU hints and arena-sharded batch allocation for efficiency.
    /// Batch allocation reduces the number of atomic operations by
    /// allocating multiple pages from a single word in one CAS.
    /// Arena sharding reduces cache line contention across CPUs.
    fn try_refill_magazine_4k(&self, cpu_id: usize) {
        let magazine = &self.magazines[cpu_id];
        let Some(mag) = magazine.get(0) else { return };
        
        // Use per-CPU hint for better cache locality
        let hint = &magazine.hint_4k;
        
        // Check current magazine level
        let current_len = {
            let mag = mag.lock();
            mag.len()
        };
        
        if current_len >= MAGAZINE_CAPACITY / 2 {
            return; // Already has enough
        }
        
        // Calculate how many pages to refill
        let target = MAGAZINE_CAPACITY / 2;
        let to_refill = target.saturating_sub(current_len);
        
        if to_refill == 0 {
            return;
        }
        
        // Batch allocate pages using arena-sharded allocation
        // First tries local arena, then steals from global if needed
        let pages = self.bitmap_4k.batch_allocate_pages_in_arena(
            to_refill,
            hint,
            magazine.arena_start_4k,
            magazine.arena_end_4k,
        );
        
        if !pages.is_empty() {
            let mut mag = mag.lock();
            for iova in pages {
                if !mag.push(iova) {
                    // Magazine full, return the page (ignore result)
                    let _ = self.bitmap_4k.free_page(iova);
                    break;
                }
            }
            self.stats.magazine_refills.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Allocate a 2MB super-page (O(1) via hierarchical bitmap with arena sharding)
    fn allocate_2m(&self) -> Option<u64> {
        // Fast path: try per-CPU magazine for 2MB
        if let Some(cpu_id) = Self::current_cpu_id() {
            let magazine = &self.magazines[cpu_id];
            if let Some(mag) = magazine.get(1) {
                let mut mag = mag.lock();
                if let Some(iova) = mag.pop() {
                    self.stats.magazine_hits.fetch_add(1, Ordering::Relaxed);
                    return Some(iova);
                }
            }
            
            self.stats.magazine_misses.fetch_add(1, Ordering::Relaxed);
            
            // Medium path: O(1) allocation from 2MB fully-free bitmap
            // Uses arena sharding: local arena first, then steal from others
            let iova = self.bitmap_4k.allocate_2mb_in_arena(
                &magazine.hint_2m,
                magazine.arena_start_2m,
                magazine.arena_end_2m,
            )?;
            self.stats.bitmap_allocs.fetch_add(1, Ordering::Relaxed);
            
            return Some(iova);
        }
        
        self.stats.magazine_misses.fetch_add(1, Ordering::Relaxed);
        
        // Fallback: use global hint
        let iova = self.bitmap_4k.allocate_2mb()?;
        self.stats.bitmap_allocs.fetch_add(1, Ordering::Relaxed);
        
        Some(iova)
    }

    /// Allocate a 1GB huge-page (O(1) via hierarchical bitmap)
    fn allocate_1g(&self, _size: u64) -> Option<u64> {
        // Fast path: try per-CPU magazine for 1GB
        if let Some(cpu_id) = Self::current_cpu_id() {
            let magazine = &self.magazines[cpu_id];
            if let Some(mag) = magazine.get(2) {
                let mut mag = mag.lock();
                if let Some(iova) = mag.pop() {
                    self.stats.magazine_hits.fetch_add(1, Ordering::Relaxed);
                    return Some(iova);
                }
            }
        }
        
        self.stats.magazine_misses.fetch_add(1, Ordering::Relaxed);
        
        // O(1) allocation from 1GB fully-free bitmap
        let iova = self.bitmap_4k.allocate_1gb()?;
        self.stats.bitmap_allocs.fetch_add(1, Ordering::Relaxed);
        
        Some(iova)
    }

    /// Free an IOVA
    pub fn free(&self, iova: u64, size: u64) -> Result<(), IommuError> {
        if size == PAGE_SIZE_4K {
            self.free_4k(iova)
        } else if size == PAGE_SIZE_2M {
            self.free_2m(iova)
        } else if size == PAGE_SIZE_1G {
            self.free_1g(iova)
        } else {
            self.free_range(iova, size)
        }
    }

    /// Free an IOVA with quarantine (delayed reclamation)
    ///
    /// Places the IOVA in the quarantine ring instead of returning it to the
    /// bitmap immediately. The IOVA will be reclaimed after IOTLB invalidation.
    ///
    /// Use `free_immediate()` to bypass quarantine (e.g., for error paths
    /// where DMA was never started).
    pub fn free_quarantined(&self, iova: u64, granularity: IovaGranularity) -> Result<(), IommuError> {
        let size_class = match granularity {
            IovaGranularity::Page4K => 0,
            IovaGranularity::Page2M => 1,
            IovaGranularity::Page1G => 2,
        };
        let epoch = self.current_epoch.load(Ordering::Acquire);

        if let Some(cpu_id) = Self::current_cpu_id() {
            let quarantine = &self.quarantines[cpu_id];
            let mut q = quarantine.lock();
            
            // Try to push to quarantine
            if q.push(iova, size_class, epoch) {
                self.stats.quarantine_pushes.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            
            // Quarantine full, force drain and retry
            self.stats.quarantine_forced_drains.fetch_add(1, Ordering::Relaxed);
            drop(q);
            self.drain_quarantine_cpu(cpu_id);
            
            // Retry push
            let mut q = quarantine.lock();
            if q.push(iova, size_class, epoch) {
                self.stats.quarantine_pushes.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
        }
        
        // Fallback: return directly to bitmap
        self.free_immediate(iova, granularity)
    }

    /// Free an IOVA immediately (bypass quarantine)
    ///
    /// Use this when DMA was never started (e.g., allocation error paths)
    /// or when IOTLB is known to be clean.
    pub fn free_immediate(&self, iova: u64, granularity: IovaGranularity) -> Result<(), IommuError> {
        match granularity {
            IovaGranularity::Page4K => self.free_4k_immediate(iova),
            IovaGranularity::Page2M => self.free_2m_immediate(iova),
            IovaGranularity::Page1G => self.free_1g_immediate(iova),
        }
    }

    /// Free a 4KB page (O(1)) - via quarantine
    fn free_4k(&self, iova: u64) -> Result<(), IommuError> {
        self.free_quarantined(iova, IovaGranularity::Page4K)
    }

    /// Free a 4KB page immediately (bypass quarantine)
    ///
    /// # Owner-Based Free Strategy
    ///
    /// 1. If magazine has space: push to local magazine (fastest)
    /// 2. If single-writer enabled and we own this arena: free to non-atomic arena
    /// 3. If current CPU is owner: free directly to bitmap (local free)
    /// 4. If current CPU is NOT owner: push to owner's remote free ring
    ///
    /// This reduces CAS contention by ensuring bitmap updates are primarily
    /// done by the owner CPU. Other CPUs only push to a lock-free ring.
    fn free_4k_immediate(&self, iova: u64) -> Result<(), IommuError> {
        let current_cpu = Self::current_cpu_id();
        
        // Fast path: return to per-CPU magazine
        if let Some(cpu_id) = current_cpu {
            let magazine = &self.magazines[cpu_id];
            if let Some(mag) = magazine.get(0) {
                let mut mag = mag.lock();
                if mag.push(iova) {
                    return Ok(());
                }
            }
        }
        
        // Magazine full, determine owner and route accordingly
        let owner_cpu = self.owner_cpu_for_iova_4k(iova);
        
        if let Some(cpu_id) = current_cpu {
            if cpu_id == owner_cpu {
                // === Local free: we own this arena ===
                self.stats.local_frees.fetch_add(1, Ordering::Relaxed);
                
                let magazine = &self.magazines[cpu_id];
                
                // ============================================================
                // Single-Writer Path: Non-atomic free to arena
                // ============================================================
                if magazine.is_single_writer_enabled() {
                    if iova >= self.bitmap_4k.base {
                        let page_idx = ((iova - self.bitmap_4k.base) / PAGE_SIZE_4K) as usize;
                        let word_idx = page_idx / BITS_PER_WORD;
                        
                        let mut arena_guard = magazine.arena_detail.lock();
                        if let Some(ref mut arena) = *arena_guard {
                            if !arena.is_frozen() 
                               && word_idx >= arena.word_start 
                               && word_idx < arena.word_end 
                            {
                                // Free directly to non-atomic arena bitmap
                                arena.free_page(page_idx);
                                self.stats.single_writer_frees.fetch_add(1, Ordering::Relaxed);
                                return Ok(());
                            }
                        }
                    }
                }
                
                // Also drain some remote frees while we're here (amortized)
                if !magazine.remote_free_ring.is_empty() {
                    self.drain_remote_frees_for_cpu(cpu_id);
                }
                
                // Free to bitmap (atomic fallback)
                match self.bitmap_4k.free_page(iova)? {
                    Some(word_idx) => {
                        // Word transitioned 0→non-zero, push to our free word stack
                        let mut stack = magazine.free_word_stack.lock();
                        let _ = stack.push(word_idx);
                    }
                    None => {}
                }
            } else {
                // === Remote free: push to owner's ring ===
                self.stats.remote_frees.fetch_add(1, Ordering::Relaxed);
                
                let owner_mag = &self.magazines[owner_cpu];
                if !owner_mag.remote_free_ring.try_push(iova, 0) {
                    // Ring full, fall back to direct bitmap update
                    // (This is rare and acceptable - preserves correctness)
                    match self.bitmap_4k.free_page(iova)? {
                        Some(word_idx) => {
                            // Best effort: push to our stack (not owner's)
                            let mut stack = self.magazines[cpu_id].free_word_stack.lock();
                            let _ = stack.push(word_idx);
                        }
                        None => {}
                    }
                }
            }
        } else {
            // No CPU ID available, fall back to direct bitmap update
            self.stats.remote_frees.fetch_add(1, Ordering::Relaxed);
            
            match self.bitmap_4k.free_page(iova)? {
                Some(_) => {}
                None => {}
            }
        }
        
        Ok(())
    }

    /// Free a 2MB super-page (O(1) via hierarchical bitmap) - via quarantine
    fn free_2m(&self, iova: u64) -> Result<(), IommuError> {
        self.free_quarantined(iova, IovaGranularity::Page2M)
    }

    /// Free a 2MB super-page immediately (bypass quarantine)
    fn free_2m_immediate(&self, iova: u64) -> Result<(), IommuError> {
        // Fast path: return to per-CPU magazine for 2MB
        if let Some(cpu_id) = Self::current_cpu_id() {
            let magazine = &self.magazines[cpu_id];
            if let Some(mag) = magazine.get(1) {
                let mut mag = mag.lock();
                if mag.push(iova) {
                    return Ok(());
                }
            }
        }
        
        // Return to hierarchical bitmap
        self.bitmap_4k.free_2mb(iova)
    }

    /// Free a 1GB huge-page (O(1) via hierarchical bitmap) - via quarantine
    fn free_1g(&self, iova: u64) -> Result<(), IommuError> {
        self.free_quarantined(iova, IovaGranularity::Page1G)
    }

    /// Free a 1GB huge-page immediately (bypass quarantine)
    fn free_1g_immediate(&self, iova: u64) -> Result<(), IommuError> {
        // Fast path: return to per-CPU magazine for 1GB
        if let Some(cpu_id) = Self::current_cpu_id() {
            let magazine = &self.magazines[cpu_id];
            if let Some(mag) = magazine.get(2) {
                let mut mag = mag.lock();
                if mag.push(iova) {
                    return Ok(());
                }
            }
        }
        
        // Return to hierarchical bitmap
        self.bitmap_4k.free_1gb(iova)
    }

    /// Free a range of pages (bypasses quarantine, for contiguous regions)
    fn free_range(&self, iova: u64, size: u64) -> Result<(), IommuError> {
        let pages = ((size + PAGE_SIZE_4K - 1) / PAGE_SIZE_4K) as usize;
        self.bitmap_4k.free_contiguous(iova, pages)
    }

    // ========================================================================
    // Quarantine Drain API
    // ========================================================================

    /// Drain quarantined entries that are safe to reclaim
    ///
    /// Call this after IOTLB invalidation completes. Entries with epoch
    /// <= completed_epoch will be returned to the bitmap.
    ///
    /// Returns the number of entries drained.
    pub fn drain_quarantine(&self) -> usize {
        let completed = self.completed_epoch.load(Ordering::Acquire);
        let mut total_drained = 0;
        
        for cpu_id in 0..MAX_CPUS {
            total_drained += self.drain_quarantine_cpu_epoch(cpu_id, completed);
        }
        
        if total_drained > 0 {
            self.stats.quarantine_drains.fetch_add(total_drained as u64, Ordering::Relaxed);
        }
        
        total_drained
    }

    /// Drain quarantined entries for a specific CPU
    fn drain_quarantine_cpu(&self, cpu_id: usize) {
        let completed = self.completed_epoch.load(Ordering::Acquire);
        let drained = self.drain_quarantine_cpu_epoch(cpu_id, completed);
        if drained > 0 {
            self.stats.quarantine_drains.fetch_add(drained as u64, Ordering::Relaxed);
        }
    }

    /// Drain quarantined entries for a specific CPU up to a specific epoch
    fn drain_quarantine_cpu_epoch(&self, cpu_id: usize, completed_epoch: u32) -> usize {
        let quarantine = &self.quarantines[cpu_id];
        let mut buf = [QuarantineEntry::empty(); 64];
        let mut total_drained = 0;
        
        loop {
            let drained = {
                let mut q = quarantine.lock();
                q.drain_older_than(completed_epoch, 64, &mut buf)
            };
            
            if drained == 0 {
                break;
            }
            
            // Return entries to bitmap (outside quarantine lock)
            for i in 0..drained {
                let entry = &buf[i];
                let result = match entry.size_class {
                    0 => self.free_4k_immediate(entry.iova),
                    1 => self.free_2m_immediate(entry.iova),
                    2 => self.free_1g_immediate(entry.iova),
                    _ => Ok(()), // Invalid size class, skip
                };
                if let Err(e) = result {
                    log::warn!("[IOVA] Failed to reclaim quarantined IOVA 0x{:x}: {:?}", entry.iova, e);
                }
            }
            
            total_drained += drained;
        }
        
        total_drained
    }

    /// Force drain all quarantined entries (for shutdown)
    pub fn drain_all_quarantine(&self) -> usize {
        let mut total_drained = 0;
        let mut buf = [QuarantineEntry::empty(); 64];
        
        for cpu_id in 0..MAX_CPUS {
            let quarantine = &self.quarantines[cpu_id];
            
            loop {
                let drained = {
                    let mut q = quarantine.lock();
                    q.drain_all(&mut buf)
                };
                
                if drained == 0 {
                    break;
                }
                
                for i in 0..drained {
                    let entry = &buf[i];
                    let result = match entry.size_class {
                        0 => self.free_4k_immediate(entry.iova),
                        1 => self.free_2m_immediate(entry.iova),
                        2 => self.free_1g_immediate(entry.iova),
                        _ => Ok(()),
                    };
                    if let Err(e) = result {
                        log::warn!("[IOVA] Failed to reclaim quarantined IOVA 0x{:x}: {:?}", entry.iova, e);
                    }
                }
                
                total_drained += drained;
            }
        }
        
        total_drained
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    /// Get base address
    #[inline]
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Get total size
    #[inline]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Get free 4KB pages count
    #[inline]
    pub fn free_pages(&self) -> usize {
        self.bitmap_4k.free_count()
    }

    /// Get free 2MB blocks count (fully free only)
    #[inline]
    pub fn free_2mb_blocks(&self) -> usize {
        self.bitmap_4k.free_count_2mb()
    }

    /// Get free 1GB blocks count (fully free only)
    #[inline]
    pub fn free_1gb_blocks(&self) -> usize {
        self.bitmap_4k.free_count_1gb()
    }

    /// Get statistics
    pub fn stats(&self) -> IovaAllocatorStatsFast {
        IovaAllocatorStatsFast {
            total_pages: self.bitmap_4k.total_pages(),
            free_pages: self.bitmap_4k.free_count(),
            total_2mb_blocks: self.bitmap_4k.total_2mb_blocks(),
            free_2mb_blocks: self.bitmap_4k.free_count_2mb(),
            total_1gb_blocks: self.bitmap_4k.total_1gb_blocks(),
            free_1gb_blocks: self.bitmap_4k.free_count_1gb(),
            base: self.base,
            size: self.size,
            magazine_hits: self.stats.magazine_hits.load(Ordering::Relaxed),
            magazine_misses: self.stats.magazine_misses.load(Ordering::Relaxed),
            bitmap_allocs: self.stats.bitmap_allocs.load(Ordering::Relaxed),
            magazine_refills: self.stats.magazine_refills.load(Ordering::Relaxed),
            single_writer_allocs: self.stats.single_writer_allocs.load(Ordering::Relaxed),
            single_writer_frees: self.stats.single_writer_frees.load(Ordering::Relaxed),
            single_writer_remote_drains: self.stats.single_writer_remote_drains.load(Ordering::Relaxed),
        }
    }

    // ========================================================================
    // Compatibility API (for IovaAllocator migration)
    // ========================================================================

    /// Allocate a specific IOVA range (for identity mapping)
    ///
    /// This is used when the caller needs a specific IOVA address, not just
    /// any free address. Common use cases: RMRR identity mappings.
    pub fn allocate_at(&self, iova: u64, size: u64) -> Result<(), IommuError> {
        if iova < self.base || iova.checked_add(size).ok_or(IommuError::InvalidAddress)? > self.base + self.size {
            return Err(IommuError::InvalidAddress);
        }

        let start_page = ((iova - self.base) / PAGE_SIZE_4K) as usize;
        let pages_needed = ((size + PAGE_SIZE_4K - 1) / PAGE_SIZE_4K) as usize;

        // Check if range is free and allocate atomically
        if !self.bitmap_4k.allocate_range_at(start_page, pages_needed) {
            return Err(IommuError::AlreadyMapped);
        }

        Ok(())
    }

    /// Reserve an IOVA range (for RMRR identity mappings)
    ///
    /// Same as allocate_at, but semantically indicates this is a reservation.
    pub fn reserve(&self, iova: u64, size: u64) -> Result<(), IommuError> {
        self.allocate_at(iova, size)
    }

    /// Allocate a contiguous range with specific size and alignment
    ///
    /// This is the slow path for arbitrary-size allocations that don't
    /// fit the 4KB/2MB/1GB fast paths.
    pub fn allocate_contiguous(&self, size: u64, alignment: u64) -> Option<u64> {
        let pages_needed = ((size + PAGE_SIZE_4K - 1) / PAGE_SIZE_4K) as usize;
        let alignment_pages = ((alignment.max(PAGE_SIZE_4K)) / PAGE_SIZE_4K) as usize;

        self.bitmap_4k.allocate_contiguous(pages_needed, alignment_pages)
    }

    /// Allocate an IOVA range within a maximum address (inclusive)
    ///
    /// Used for 32-bit device compatibility where IOVA must be < 4GB.
    pub fn allocate_with_limit(
        &self,
        size: u64,
        granularity: IovaGranularity,
        max_addr_inclusive: u64,
    ) -> Option<u64> {
        if max_addr_inclusive < self.base {
            return None;
        }

        let limit_exclusive = max_addr_inclusive.saturating_add(1);
        let available_end = (self.base + self.size).min(limit_exclusive);
        if available_end <= self.base {
            return None;
        }

        let max_end_page = ((available_end - self.base) / PAGE_SIZE_4K) as usize;
        if max_end_page == 0 {
            return None;
        }

        let page_size = granularity.size_bytes();
        let pages_needed = ((size + PAGE_SIZE_4K - 1) / PAGE_SIZE_4K) as usize;
        let alignment_pages = (page_size / PAGE_SIZE_4K) as usize;

        self.bitmap_4k.allocate_contiguous_below(pages_needed, alignment_pages, max_end_page)
    }
}

/// Statistics for the fast IOVA allocator
#[derive(Debug, Clone)]
pub struct IovaAllocatorStatsFast {
    pub total_pages: usize,
    pub free_pages: usize,
    pub total_2mb_blocks: usize,
    pub free_2mb_blocks: usize,
    pub total_1gb_blocks: usize,
    pub free_1gb_blocks: usize,
    pub base: u64,
    pub size: u64,
    pub magazine_hits: u64,
    pub magazine_misses: u64,
    pub bitmap_allocs: u64,
    pub magazine_refills: u64,
    // === Single-Writer Arena Stats ===
    pub single_writer_allocs: u64,
    pub single_writer_frees: u64,
    pub single_writer_remote_drains: u64,
}

impl IovaAllocatorStatsFast {
    /// Calculate magazine hit rate
    pub fn hit_rate(&self) -> f64 {
        let total = self.magazine_hits + self.magazine_misses;
        if total == 0 {
            0.0
        } else {
            self.magazine_hits as f64 / total as f64
        }
    }
    
    /// Calculate single-writer arena hit rate
    pub fn single_writer_rate(&self) -> f64 {
        let total = self.single_writer_allocs + self.magazine_hits;
        if total == 0 {
            0.0
        } else {
            self.single_writer_allocs as f64 / total as f64
        }
    }
}
