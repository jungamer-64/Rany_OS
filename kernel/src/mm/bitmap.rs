// ============================================================================
// src/mm/bitmap.rs - Hierarchical Bitmap Allocator
// IOVA_MM_MIGRATION_PLAN Phase 1.2: HierarchicalBitmap / HugePageBitmap
//
// 3-Level hierarchical bitmap for O(1) free-slot search using tzcnt/popcnt.
// Can be used for both IOVA allocation and physical frame allocation.
//
// Architecture:
//   Level 2 (L2): 1 bit per 4096 units (summary of summary)
//   Level 1 (L1): 1 bit per 64 units (summary)
//   Level 0 (L0): 1 bit per unit (detail)
//
// Bit semantics: 1 = free, 0 = allocated
// ============================================================================
#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Bits per word (u64)
mod _split_1;
use _split_1::*;
const BITS_PER_WORD: usize = 64;

/// Units covered per L1 summary bit (= bits per detail word)
const UNITS_PER_L1_BIT: usize = BITS_PER_WORD;

/// Units covered per L2 summary bit (= 64 L1 bits = 4096 units)
const UNITS_PER_L2_BIT: usize = BITS_PER_WORD * BITS_PER_WORD;

// ============================================================================
// HierarchicalBitmap - Core 3-Level Bitmap
// ============================================================================

/// 3-Level Hierarchical Bitmap for O(1) free-slot allocation
///
/// This structure maintains a bitmap with three levels of summary:
/// - **Level 0 (detail)**: 1 bit per unit (free=1, allocated=0)
/// - **Level 1 (summary)**: 1 bit per 64 units (1 if any free in detail word)
/// - **Level 2 (summary_l2)**: 1 bit per 4096 units (1 if any free in L1 word)
///
/// # Performance
/// - `allocate_one()`: O(1) using tzcnt to find first free bit
/// - `mark_allocated()`: O(1) with atomic compare-exchange
/// - `mark_free()`: O(1) with atomic operations
///
/// # Thread Safety
/// All operations are lock-free using atomic operations.
/// Summary levels are maintained conservatively (may have false positives).
#[repr(C)]
pub struct HierarchicalBitmap {
    /// Level 0: Detail bitmap (1 bit per unit)
    detail: Box<[AtomicU64]>,
    /// Level 1: Summary bitmap (1 bit per 64 units)
    summary: Box<[AtomicU64]>,
    /// Level 2: Summary of summary (1 bit per 4096 units)
    summary_l2: Box<[AtomicU64]>,
    /// Total number of units managed
    total_units: usize,
    /// Number of detail words
    detail_words: usize,
    /// Number of summary words
    summary_words: usize,
    /// Free count (may be slightly stale due to concurrent access)
    free_count: AtomicUsize,
    /// Valid bit mask for the last detail word
    last_word_mask: u64,
    /// Allocation hint (detail word index to start searching)
    pub(crate) hint: AtomicUsize,
}

impl HierarchicalBitmap {
    /// Create a new hierarchical bitmap
    ///
    /// # Arguments
    /// * `total_units` - Number of units to manage (e.g., pages)
    ///
    /// # Panics
    /// Panics if `total_units` is 0
    pub fn new(total_units: usize) -> Self {
        assert!(total_units > 0, "HierarchicalBitmap: total_units must be > 0");

        let detail_words = (total_units + BITS_PER_WORD - 1) / BITS_PER_WORD;
        let summary_words = (detail_words + BITS_PER_WORD - 1) / BITS_PER_WORD;
        let summary_l2_words = (summary_words + BITS_PER_WORD - 1) / BITS_PER_WORD;

        // Calculate last word mask
        let last_bits = total_units % BITS_PER_WORD;
        let last_word_mask = if last_bits == 0 {
            u64::MAX
        } else {
            (1u64 << last_bits) - 1
        };

        // Initialize detail bitmap (all free = all 1s)
        let mut detail = Vec::with_capacity(detail_words);
        for i in 0..detail_words {
            let remaining = total_units.saturating_sub(i * BITS_PER_WORD);
            let bits = if remaining >= BITS_PER_WORD {
                u64::MAX
            } else {
                (1u64 << remaining) - 1
            };
            detail.push(AtomicU64::new(bits));
        }

        // Initialize summary bitmap (all have free = all 1s)
        let mut summary = Vec::with_capacity(summary_words);
        for i in 0..summary_words {
            let remaining_words = detail_words.saturating_sub(i * BITS_PER_WORD);
            let bits = if remaining_words >= BITS_PER_WORD {
                u64::MAX
            } else {
                (1u64 << remaining_words) - 1
            };
            summary.push(AtomicU64::new(bits));
        }

        // Initialize summary_l2 bitmap
        let mut summary_l2 = Vec::with_capacity(summary_l2_words);
        for i in 0..summary_l2_words {
            let remaining_words = summary_words.saturating_sub(i * BITS_PER_WORD);
            let bits = if remaining_words >= BITS_PER_WORD {
                u64::MAX
            } else {
                (1u64 << remaining_words) - 1
            };
            summary_l2.push(AtomicU64::new(bits));
        }

        Self {
            detail: detail.into_boxed_slice(),
            summary: summary.into_boxed_slice(),
            summary_l2: summary_l2.into_boxed_slice(),
            total_units,
            detail_words,
            summary_words,
            free_count: AtomicUsize::new(total_units),
            last_word_mask,
            hint: AtomicUsize::new(0),
        }
    }

    /// Get total number of units
    #[inline]
    pub fn total_units(&self) -> usize {
        self.total_units
    }

    /// Get current free count (may be slightly stale)
    #[inline]
    pub fn free_count(&self) -> usize {
        self.free_count.load(Ordering::Relaxed)
    }

    /// Check if the bitmap is empty (all allocated)
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.free_count() == 0
    }

    /// Check if the bitmap is full (all free)
    #[inline]
    pub fn is_full(&self) -> bool {
        self.free_count() == self.total_units
    }

    /// Get valid mask for a given word index
    #[inline]
    pub fn valid_mask(&self, word_idx: usize) -> u64 {
        if word_idx + 1 == self.detail_words {
            self.last_word_mask
        } else {
            u64::MAX
        }
    }

    /// Allocate a single unit using O(1) tzcnt search
    ///
    /// Returns the index of the allocated unit, or `None` if no free units.
    pub fn allocate_one(&self) -> Option<usize> {
        // Start from hint for better locality
        let hint = self.hint.load(Ordering::Relaxed) % self.summary_l2.len().max(1);

        // Search L2 starting from hint
        for l2_offset in 0..self.summary_l2.len() {
            let l2_idx = (hint + l2_offset) % self.summary_l2.len();
            let l2_word = self.summary_l2[l2_idx].load(Ordering::Acquire);
            if l2_word == 0 {
                continue;
            }

            // Found non-zero L2 word, search L1 within it
            let l1_start = l2_idx * BITS_PER_WORD;
            let l1_end = (l1_start + BITS_PER_WORD).min(self.summary.len());

            for l1_idx in l1_start..l1_end {
                let l1_word = self.summary[l1_idx].load(Ordering::Acquire);
                if l1_word == 0 {
                    continue;
                }

                // Found non-zero L1 word, search detail within it
                let l1_bit = l1_word.trailing_zeros() as usize;
                let detail_idx = l1_idx * BITS_PER_WORD + l1_bit;
                if detail_idx >= self.detail.len() {
                    continue;
                }

                // Try to allocate from this detail word
                if let Some(unit_idx) = self.try_allocate_from_word(detail_idx) {
                    // Update hint for next allocation
                    self.hint.store(l2_idx, Ordering::Relaxed);
                    return Some(unit_idx);
                }
            }
        }

        None
    }

    /// L1ブロック内でlimit未満の空きユニットを検索する
    fn scan_l1_for_free_below(&self, l1_idx: usize, limit_idx: usize) -> Option<usize> {
        let l1_word = self.summary[l1_idx].load(Ordering::Acquire);
        if l1_word == 0 {
            return None;
        }

        let l1_bit = l1_word.trailing_zeros() as usize;
        let detail_idx = l1_idx * BITS_PER_WORD + l1_bit;

        if detail_idx * BITS_PER_WORD >= limit_idx {
            return None;
        }

        if detail_idx >= self.detail.len() {
            return None;
        }

        if let Some(unit_idx) = self.try_allocate_from_word(detail_idx) {
            if unit_idx < limit_idx {
                return Some(unit_idx);
            }
        }
        None
    }

    /// Allocate a single unit below a specific limit index
    ///
    /// Searches from 0 up to limit, ensuring the allocated index is specificially < limit.
    pub fn allocate_one_below(&self, limit_idx: usize) -> Option<usize> {
        // Linear scan from 0 to ensure finding first fit below limit
        let l2_limit = (limit_idx + UNITS_PER_L2_BIT - 1) / UNITS_PER_L2_BIT;
        let l2_scan_end = l2_limit.min(self.summary_l2.len());

        for l2_idx in 0..l2_scan_end {
            let l2_word = self.summary_l2[l2_idx].load(Ordering::Acquire);
            if l2_word == 0 {
                continue;
            }

            let l1_start = l2_idx * BITS_PER_WORD;
            let l1_end = (l1_start + BITS_PER_WORD).min(self.summary.len());

            for l1_idx in l1_start..l1_end {
                // Check if this L1 block starts beyond limit
                if l1_idx * UNITS_PER_L1_BIT >= limit_idx {
                    return None;
                }

                if let Some(unit_idx) = self.scan_l1_for_free_below(l1_idx, limit_idx) {
                    return Some(unit_idx);
                }
            }
        }

        None
    }

    /// Try to allocate a unit from a specific detail word
    ///
    /// This is public to allow HugePageBitmap to use it for targeted allocation.
    pub fn try_allocate_from_word(&self, word_idx: usize) -> Option<usize> {
        let valid_mask = self.valid_mask(word_idx);

        loop {
            let word = self.detail[word_idx].load(Ordering::Acquire);
            let available = word & valid_mask;
            if available == 0 {
                return None;
            }

            // Find first free bit
            let bit_idx = available.trailing_zeros() as usize;
            let bit_mask = 1u64 << bit_idx;

            // Try to atomically clear the bit
            match self.detail[word_idx].compare_exchange_weak(
                word,
                word & !bit_mask,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    // Successfully allocated
                    let unit_idx = word_idx * BITS_PER_WORD + bit_idx;

                    // Update summary if word became empty
                    if (word & !bit_mask) == 0 {
                        self.clear_summary_bit(word_idx);
                    }

                    // Decrement free count
                    self.free_count.fetch_sub(1, Ordering::Relaxed);

                    return Some(unit_idx);
                }
                Err(_) => {
                    // CAS failed, retry
                    core::hint::spin_loop();
                }
            }
        }
    }

    /// Mark a unit as allocated (returns true if it was free)
    pub fn mark_allocated(&self, index: usize) -> bool {
        if index >= self.total_units {
            return false;
        }

        let word_idx = index / BITS_PER_WORD;
        let bit_idx = index % BITS_PER_WORD;
        let bit_mask = 1u64 << bit_idx;

        loop {
            let word = self.detail[word_idx].load(Ordering::Acquire);
            if (word & bit_mask) == 0 {
                // Already allocated
                return false;
            }

            match self.detail[word_idx].compare_exchange_weak(
                word,
                word & !bit_mask,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    // Update summary if word became empty
                    if (word & !bit_mask) == 0 {
                        self.clear_summary_bit(word_idx);
                    }
                    self.free_count.fetch_sub(1, Ordering::Relaxed);
                    return true;
                }
                Err(_) => {
                    core::hint::spin_loop();
                }
            }
        }
    }

    /// Mark a unit as free (returns true if it was allocated)
    pub fn mark_free(&self, index: usize) -> bool {
        if index >= self.total_units {
            return false;
        }

        let word_idx = index / BITS_PER_WORD;
        let bit_idx = index % BITS_PER_WORD;
        let bit_mask = 1u64 << bit_idx;

        loop {
            let word = self.detail[word_idx].load(Ordering::Acquire);
            if (word & bit_mask) != 0 {
                // Already free
                return false;
            }

            match self.detail[word_idx].compare_exchange_weak(
                word,
                word | bit_mask,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    // Update summary if word became non-empty
                    if word == 0 {
                        self.set_summary_bit(word_idx);
                    }
                    self.free_count.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
                Err(_) => {
                    core::hint::spin_loop();
                }
            }
        }
    }

    /// Mark a range of units as allocated
    /// 
    /// # Arguments
    /// * `start` - Starting index
    /// * `count` - Number of units to mark
    /// 
    /// # Returns
    /// Number of units that were actually marked (were free before)
    pub fn mark_allocated_range(&self, start: usize, count: usize) -> usize {
        if count == 0 {
            return 0;
        }
        
        let end = (start + count).min(self.total_units);
        let mut marked = 0;
        
        for index in start..end {
            if self.mark_allocated(index) {
                marked += 1;
            }
        }
        
        marked
    }

    /// Check if a unit is free
    #[inline]
    pub fn is_free(&self, index: usize) -> bool {
        if index >= self.total_units {
            return false;
        }
        let word_idx = index / BITS_PER_WORD;
        let bit_idx = index % BITS_PER_WORD;
        let word = self.detail[word_idx].load(Ordering::Acquire);
        (word & (1u64 << bit_idx)) != 0
    }

    /// Check if a range of units is free
    pub fn is_range_free(&self, start: usize, count: usize) -> bool {
        if count == 0 {
            return true;
        }
        if start + count > self.total_units {
            return false;
        }

        let end = start + count;
        let start_word = start / BITS_PER_WORD;
        let end_word = (end + BITS_PER_WORD - 1) / BITS_PER_WORD;

        for word_idx in start_word..end_word {
            let word = self.detail[word_idx].load(Ordering::Acquire);

            // Calculate which bits in this word we need to check
            let word_start_unit = word_idx * BITS_PER_WORD;
            let check_start = start.max(word_start_unit) - word_start_unit;
            let check_end = end.min(word_start_unit + BITS_PER_WORD) - word_start_unit;

            // Create mask for bits we need to check
            let check_mask = if check_end == BITS_PER_WORD {
                u64::MAX << check_start
            } else {
                ((1u64 << check_end) - 1) & (u64::MAX << check_start)
            };

            // All checked bits must be 1 (free)
            if (word & check_mask) != check_mask {
                return false;
            }
        }

        true
    }

    /// Try to claim an entire word (64 units) atomically
    ///
    /// Returns the previous value of the word (bits that were free).
    /// The word is cleared to 0 (all allocated).
    pub fn try_claim_word(&self, word_idx: usize) -> u64 {
        if word_idx >= self.detail.len() {
            return 0;
        }

        let valid_mask = self.valid_mask(word_idx);
        let claimed = self.detail[word_idx].swap(0, Ordering::AcqRel) & valid_mask;

        if claimed != 0 {
            // Update summary
            self.clear_summary_bit(word_idx);
            // Update free count
            let freed_count = claimed.count_ones() as usize;
            self.free_count.fetch_sub(freed_count, Ordering::Relaxed);
        }

        claimed
    }

    /// Return a claimed word (restore bits to free state)
    pub fn return_word(&self, word_idx: usize, bits: u64) {
        if word_idx >= self.detail.len() || bits == 0 {
            return;
        }

        let valid_bits = bits & self.valid_mask(word_idx);
        if valid_bits == 0 {
            return;
        }

        let old = self.detail[word_idx].fetch_or(valid_bits, Ordering::AcqRel);

        // Update summary if word was empty
        if old == 0 {
            self.set_summary_bit(word_idx);
        }

        // Update free count
        let new_free = valid_bits.count_ones() as usize;
        self.free_count.fetch_add(new_free, Ordering::Relaxed);
    }

    /// Access raw detail bitmap (for single-writer arena sync)
    #[inline]
    pub fn detail(&self) -> &[AtomicU64] {
        &self.detail
    }

    /// Access raw summary bitmap
    #[inline]
    pub fn summary(&self) -> &[AtomicU64] {
        &self.summary
    }

    /// Access raw L2 summary bitmap
    #[inline]
    pub fn summary_l2(&self) -> &[AtomicU64] {
        &self.summary_l2
    }

    // ========================================================================
    // Private: Summary maintenance
    // ========================================================================

    /// Clear summary bit when a detail word becomes empty
    fn clear_summary_bit(&self, detail_word_idx: usize) {
        let l1_idx = detail_word_idx / BITS_PER_WORD;
        let l1_bit = detail_word_idx % BITS_PER_WORD;
        let l1_mask = 1u64 << l1_bit;

        let old_l1 = self.summary[l1_idx].fetch_and(!l1_mask, Ordering::AcqRel);

        // If L1 word became empty, clear L2 bit
        if (old_l1 & !l1_mask) == 0 {
            let l2_idx = l1_idx / BITS_PER_WORD;
            let l2_bit = l1_idx % BITS_PER_WORD;
            let l2_mask = 1u64 << l2_bit;
            self.summary_l2[l2_idx].fetch_and(!l2_mask, Ordering::AcqRel);
        }
    }

    /// Set summary bit when a detail word becomes non-empty
    fn set_summary_bit(&self, detail_word_idx: usize) {
        let l1_idx = detail_word_idx / BITS_PER_WORD;
        let l1_bit = detail_word_idx % BITS_PER_WORD;
        let l1_mask = 1u64 << l1_bit;

        let old_l1 = self.summary[l1_idx].fetch_or(l1_mask, Ordering::AcqRel);

        // If L1 word was empty, set L2 bit
        if old_l1 == 0 {
            let l2_idx = l1_idx / BITS_PER_WORD;
            let l2_bit = l1_idx % BITS_PER_WORD;
            let l2_mask = 1u64 << l2_bit;
            self.summary_l2[l2_idx].fetch_or(l2_mask, Ordering::AcqRel);
        }
    }
}

// ============================================================================
// HugePageBitmap - Extended Bitmap with 2MB/1GB Tracking
// ============================================================================

use core::sync::atomic::AtomicU16;
use super::atomic_utils::AtomicU8;

/// Pages per 2MB block (2MB / 4KB = 512)
pub const PAGES_PER_2MB: usize = 512;

/// Blocks per 1GB (1GB / 2MB = 512)
pub const BLOCKS_2MB_PER_1GB: usize = 512;

/// Words per 2MB block (512 pages / 64 bits = 8)
pub const WORDS_PER_2MB: usize = PAGES_PER_2MB / BITS_PER_WORD;

/// HugePage-aware Hierarchical Bitmap
///
/// Extends `HierarchicalBitmap` with 2MB and 1GB tracking for efficient
/// huge page allocation while preserving 4KB granularity.
///
/// # Features
/// - **2MB fully-free tracking**: Bitmap indicating which 2MB blocks are completely free
/// - **1GB fully-free tracking**: Bitmap indicating which 1GB blocks are completely free
/// - **Partial 2MB tracking**: Identifies blocks that have some free pages (for 4KB alloc)
/// - **Demotion tracking**: Marks 2MB blocks that should not be promoted back to hugepage
/// - **Free word mask**: Per-2MB-block mask for O(1) word selection
///
/// # Usage
/// ```ignore
/// let bitmap = HugePageBitmap::new(1 << 20); // 4GB (1M pages)
///
/// // 2MB allocation
/// if let Some(block_2m) = bitmap.allocate_2m() {
///     // Got a fully-free 2MB block
/// }
///
/// // 4KB allocation (prefers partial blocks to preserve hugepages)
/// if let Some(page) = bitmap.allocate_4k_from_partial() {
///     // Allocated from partial block
/// }
/// ```
#[repr(C)]
pub struct HugePageBitmap {
    /// Base 4KB hierarchical bitmap
    base: HierarchicalBitmap,
    
    // === 2MB Level ===
    /// Per-2MB-block used count (0..512)
    /// When 0, the block is fully free
    used_count_2m: Box<[AtomicU16]>,
    /// 2MB fully-free bitmap (1 = all 512 pages free)
    bitmap_2m: Box<[AtomicU64]>,
    /// 2MB partial bitmap (1 = 0 < used < 512, has some free pages)
    bitmap_2m_partial: Box<[AtomicU64]>,
    /// Demoted 2MB bitmap (1 = block is demoted, won't be promoted)
    demoted_2m: Box<[AtomicU64]>,
    /// Per-2MB free word mask (8 bits for 8 words per 2MB)
    free_word_mask_2m: Box<[AtomicU8]>,
    /// Total 2MB blocks
    total_2m_blocks: usize,
    /// Free 2MB block count (fully free only)
    free_count_2m: AtomicUsize,
    /// Partial 2MB block count
    partial_count_2m: AtomicUsize,
    /// Demoted 2MB block count
    demoted_count_2m: AtomicUsize,
    /// Allocation hint for 2MB
    hint_2m: AtomicUsize,
    /// Allocation hint for partial 2MB (for 4KB allocation)
    hint_2m_partial: AtomicUsize,
    
    // === 1GB Level ===
    /// Per-1GB-block used count (count of non-free 2MB blocks, 0..512)
    used_count_1g: Box<[AtomicU16]>,
    /// 1GB fully-free bitmap (1 = all 512 2MB blocks free)
    bitmap_1g: Box<[AtomicU64]>,
    /// Total 1GB blocks
    total_1g_blocks: usize,
    /// Free 1GB block count
    free_count_1g: AtomicUsize,
}
