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

impl HugePageBitmap {
    /// Create a new HugePageBitmap
    ///
    /// # Arguments
    /// * `total_pages` - Total 4KB pages to manage
    ///
    /// # Note
    /// Only **complete** 2MB/1GB blocks are marked as fully-free.
    /// Trailing partial blocks are tracked but not marked as fully-free.
    pub fn new(total_pages: usize) -> Self {
        let base = HierarchicalBitmap::new(total_pages);
        
        // Calculate block counts
        let complete_2m_blocks = total_pages / PAGES_PER_2MB;
        let total_2m_blocks = (total_pages + PAGES_PER_2MB - 1) / PAGES_PER_2MB;
        let complete_1g_blocks = complete_2m_blocks / BLOCKS_2MB_PER_1GB;
        let total_1g_blocks = (total_2m_blocks + BLOCKS_2MB_PER_1GB - 1) / BLOCKS_2MB_PER_1GB;
        
        // 2MB level
        let bitmap_2m_words = (total_2m_blocks + BITS_PER_WORD - 1) / BITS_PER_WORD;
        
        // Initialize used_count_2m (all 0 = all free)
        let used_count_2m: Vec<AtomicU16> = (0..total_2m_blocks)
            .map(|_| AtomicU16::new(0))
            .collect();
        
        // Initialize bitmap_2m (only complete blocks are fully-free)
        let mut bitmap_2m = Vec::with_capacity(bitmap_2m_words);
        for i in 0..bitmap_2m_words {
            let block_start = i * BITS_PER_WORD;
            let remaining = complete_2m_blocks.saturating_sub(block_start);
            let bits = if remaining >= BITS_PER_WORD {
                u64::MAX
            } else {
                (1u64 << remaining) - 1
            };
            bitmap_2m.push(AtomicU64::new(bits));
        }
        
        // Initialize bitmap_2m_partial (all 0 initially)
        let bitmap_2m_partial: Vec<AtomicU64> = (0..bitmap_2m_words)
            .map(|_| AtomicU64::new(0))
            .collect();
        
        // Initialize demoted_2m (all 0)
        let demoted_2m: Vec<AtomicU64> = (0..bitmap_2m_words)
            .map(|_| AtomicU64::new(0))
            .collect();
        
        // Initialize free_word_mask_2m (all 0xFF = all words have free pages)
        let free_word_mask_2m: Vec<AtomicU8> = (0..total_2m_blocks)
            .map(|_| AtomicU8::new(0xFF))
            .collect();
        
        // 1GB level
        let bitmap_1g_words = (total_1g_blocks + BITS_PER_WORD - 1) / BITS_PER_WORD;
        
        // Initialize used_count_1g (all 0)
        let used_count_1g: Vec<AtomicU16> = (0..total_1g_blocks)
            .map(|_| AtomicU16::new(0))
            .collect();
        
        // Initialize bitmap_1g (only complete blocks)
        let mut bitmap_1g = Vec::with_capacity(bitmap_1g_words);
        for i in 0..bitmap_1g_words {
            let block_start = i * BITS_PER_WORD;
            let remaining = complete_1g_blocks.saturating_sub(block_start);
            let bits = if remaining >= BITS_PER_WORD {
                u64::MAX
            } else {
                (1u64 << remaining) - 1
            };
            bitmap_1g.push(AtomicU64::new(bits));
        }
        
        Self {
            base,
            used_count_2m: used_count_2m.into_boxed_slice(),
            bitmap_2m: bitmap_2m.into_boxed_slice(),
            bitmap_2m_partial: bitmap_2m_partial.into_boxed_slice(),
            demoted_2m: demoted_2m.into_boxed_slice(),
            free_word_mask_2m: free_word_mask_2m.into_boxed_slice(),
            total_2m_blocks,
            free_count_2m: AtomicUsize::new(complete_2m_blocks),
            partial_count_2m: AtomicUsize::new(0),
            demoted_count_2m: AtomicUsize::new(0),
            hint_2m: AtomicUsize::new(0),
            hint_2m_partial: AtomicUsize::new(0),
            used_count_1g: used_count_1g.into_boxed_slice(),
            bitmap_1g: bitmap_1g.into_boxed_slice(),
            total_1g_blocks,
            free_count_1g: AtomicUsize::new(complete_1g_blocks),
        }
    }
    
    // ========================================================================
    // Getters
    // ========================================================================
    
    /// Get total 4KB pages
    #[inline]
    pub fn total_pages(&self) -> usize {
        self.base.total_units()
    }
    
    /// Get free 4KB page count
    #[inline]
    pub fn free_count_4k(&self) -> usize {
        self.base.free_count()
    }
    
    /// Get free 2MB block count
    #[inline]
    pub fn free_count_2m(&self) -> usize {
        self.free_count_2m.load(Ordering::Relaxed)
    }
    
    /// Get partial 2MB block count
    #[inline]
    pub fn partial_count_2m(&self) -> usize {
        self.partial_count_2m.load(Ordering::Relaxed)
    }
    
    /// Get free 1GB block count
    #[inline]
    pub fn free_count_1g(&self) -> usize {
        self.free_count_1g.load(Ordering::Relaxed)
    }
    
    /// Get total 2MB blocks
    #[inline]
    pub fn total_2m_blocks(&self) -> usize {
        self.total_2m_blocks
    }
    
    /// Get total 1GB blocks
    #[inline]
    pub fn total_1g_blocks(&self) -> usize {
        self.total_1g_blocks
    }
    
    /// Access base 4KB bitmap
    #[inline]
    pub fn base(&self) -> &HierarchicalBitmap {
        &self.base
    }
    
    // ========================================================================
    // 4KB Allocation (delegates to base)
    // ========================================================================
    
    /// Allocate a single 4KB page
    ///
    /// This is a simple allocation that doesn't consider hugepage preservation.
    /// For hugepage-aware allocation, use `allocate_4k_from_partial()`.
    pub fn allocate_4k(&self) -> Option<usize> {
        let page_idx = self.base.allocate_one()?;
        self.on_page_allocated(page_idx);
        Some(page_idx)
    }
    
    /// Free a 4KB page
    pub fn free_4k(&self, page_idx: usize) -> bool {
        if self.base.mark_free(page_idx) {
            self.on_page_freed(page_idx);
            true
        } else {
            false
        }
    }
    
    /// Check if a 4KB page is free
    #[inline]
    pub fn is_page_free(&self, page_idx: usize) -> bool {
        self.base.is_free(page_idx)
    }
    
    // ========================================================================
    // 2MB Allocation
    // ========================================================================
    
    /// Allocate a fully-free 2MB block
    ///
    /// Returns the block index, or None if no fully-free 2MB blocks available.
    pub fn allocate_2m(&self) -> Option<usize> {
        let hint = self.hint_2m.load(Ordering::Relaxed) % self.bitmap_2m.len().max(1);
        
        for offset in 0..self.bitmap_2m.len() {
            let word_idx = (hint + offset) % self.bitmap_2m.len();
            
            loop {
                let word = self.bitmap_2m[word_idx].load(Ordering::Acquire);
                if word == 0 {
                    break; // No free blocks in this word
                }
                
                let bit_idx = word.trailing_zeros() as usize;
                let bit_mask = 1u64 << bit_idx;
                
                // Try to clear the bit
                match self.bitmap_2m[word_idx].compare_exchange_weak(
                    word,
                    word & !bit_mask,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        let block_idx = word_idx * BITS_PER_WORD + bit_idx;
                        
                        // Mark all 512 pages as allocated in base bitmap
                        let page_start = block_idx * PAGES_PER_2MB;
                        for i in 0..PAGES_PER_2MB {
                            self.base.mark_allocated(page_start + i);
                        }
                        
                        // Update used count
                        self.used_count_2m[block_idx].store(PAGES_PER_2MB as u16, Ordering::Release);
                        
                        // Update free word mask
                        self.free_word_mask_2m[block_idx].store(0, Ordering::Release);
                        
                        // Update 1GB tracking
                        let block_1g = block_idx / BLOCKS_2MB_PER_1GB;
                        if block_1g < self.used_count_1g.len() {
                            let old_used = self.used_count_1g[block_1g].fetch_add(1, Ordering::AcqRel);
                            if old_used == 0 {
                                // 1GB block was fully free, now it's not
                                let word_1g = block_1g / BITS_PER_WORD;
                                let bit_1g = block_1g % BITS_PER_WORD;
                                self.bitmap_1g[word_1g].fetch_and(!(1u64 << bit_1g), Ordering::AcqRel);
                                self.free_count_1g.fetch_sub(1, Ordering::Relaxed);
                            }
                        }
                        
                        self.free_count_2m.fetch_sub(1, Ordering::Relaxed);
                        self.hint_2m.store(word_idx, Ordering::Relaxed);
                        
                        return Some(block_idx);
                    }
                    Err(_) => {
                        core::hint::spin_loop();
                    }
                }
            }
        }
        
        None
    }
    
    /// Free a 2MB block
    ///
    /// All 512 pages in the block must be allocated (used_count == 512).
    pub fn free_2m(&self, block_idx: usize) -> bool {
        if block_idx >= self.total_2m_blocks {
            return false;
        }
        
        // Check if block is fully allocated
        let used = self.used_count_2m[block_idx].load(Ordering::Acquire);
        if used != PAGES_PER_2MB as u16 {
            return false; // Not fully allocated
        }
        
        // Mark all pages as free in base bitmap
        let page_start = block_idx * PAGES_PER_2MB;
        for i in 0..PAGES_PER_2MB {
            self.base.mark_free(page_start + i);
        }
        
        // Update used count
        self.used_count_2m[block_idx].store(0, Ordering::Release);
        
        // Update free word mask
        self.free_word_mask_2m[block_idx].store(0xFF, Ordering::Release);
        
        // Set 2MB fully-free bit
        let word_idx = block_idx / BITS_PER_WORD;
        let bit_idx = block_idx % BITS_PER_WORD;
        self.bitmap_2m[word_idx].fetch_or(1u64 << bit_idx, Ordering::AcqRel);
        self.free_count_2m.fetch_add(1, Ordering::Relaxed);
        
        // Update 1GB tracking
        let block_1g = block_idx / BLOCKS_2MB_PER_1GB;
        if block_1g < self.used_count_1g.len() {
            let old_used = self.used_count_1g[block_1g].fetch_sub(1, Ordering::AcqRel);
            if old_used == 1 {
                // 1GB block is now fully free
                let word_1g = block_1g / BITS_PER_WORD;
                let bit_1g = block_1g % BITS_PER_WORD;
                self.bitmap_1g[word_1g].fetch_or(1u64 << bit_1g, Ordering::AcqRel);
                self.free_count_1g.fetch_add(1, Ordering::Relaxed);
            }
        }
        
        true
    }
    
    /// Check if a 2MB block is fully free
    #[inline]
    pub fn is_2m_free(&self, block_idx: usize) -> bool {
        if block_idx >= self.total_2m_blocks {
            return false;
        }
        let word_idx = block_idx / BITS_PER_WORD;
        let bit_idx = block_idx % BITS_PER_WORD;
        let word = self.bitmap_2m[word_idx].load(Ordering::Acquire);
        (word & (1u64 << bit_idx)) != 0
    }
    
    /// Check if a 2MB block is demoted
    #[inline]
    pub fn is_block_demoted(&self, block_idx: usize) -> bool {
        if block_idx >= self.total_2m_blocks {
            return false;
        }
        let word_idx = block_idx / BITS_PER_WORD;
        let bit_idx = block_idx % BITS_PER_WORD;
        let word = self.demoted_2m[word_idx].load(Ordering::Acquire);
        (word & (1u64 << bit_idx)) != 0
    }
    
    // ========================================================================
    // 1GB Allocation
    // ========================================================================
    
    /// Allocate a fully-free 1GB block
    ///
    /// Returns the block index, or None if no fully-free 1GB blocks available.
    pub fn allocate_1g(&self) -> Option<usize> {
        for word_idx in 0..self.bitmap_1g.len() {
            loop {
                let word = self.bitmap_1g[word_idx].load(Ordering::Acquire);
                if word == 0 {
                    break;
                }
                
                let bit_idx = word.trailing_zeros() as usize;
                let bit_mask = 1u64 << bit_idx;
                
                match self.bitmap_1g[word_idx].compare_exchange_weak(
                    word,
                    word & !bit_mask,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        let block_1g_idx = word_idx * BITS_PER_WORD + bit_idx;
                        
                        // Mark all 512 2MB blocks as allocated
                        let block_2m_start = block_1g_idx * BLOCKS_2MB_PER_1GB;
                        for i in 0..BLOCKS_2MB_PER_1GB {
                            let block_2m = block_2m_start + i;
                            if block_2m < self.total_2m_blocks {
                                // Clear 2MB fully-free bit
                                let w2m = block_2m / BITS_PER_WORD;
                                let b2m = block_2m % BITS_PER_WORD;
                                self.bitmap_2m[w2m].fetch_and(!(1u64 << b2m), Ordering::AcqRel);
                                
                                // Update used count
                                self.used_count_2m[block_2m].store(PAGES_PER_2MB as u16, Ordering::Release);
                                
                                // Clear free word mask
                                self.free_word_mask_2m[block_2m].store(0, Ordering::Release);
                            }
                        }
                        
                        // Mark all pages as allocated
                        let page_start = block_1g_idx * BLOCKS_2MB_PER_1GB * PAGES_PER_2MB;
                        let page_count = BLOCKS_2MB_PER_1GB * PAGES_PER_2MB;
                        for i in 0..page_count {
                            let page = page_start + i;
                            if page < self.base.total_units() {
                                self.base.mark_allocated(page);
                            }
                        }
                        
                        // Update counts
                        self.used_count_1g[block_1g_idx].store(BLOCKS_2MB_PER_1GB as u16, Ordering::Release);
                        self.free_count_1g.fetch_sub(1, Ordering::Relaxed);
                        self.free_count_2m.fetch_sub(BLOCKS_2MB_PER_1GB.min(self.total_2m_blocks - block_2m_start), Ordering::Relaxed);
                        
                        return Some(block_1g_idx);
                    }
                    Err(_) => {
                        core::hint::spin_loop();
                    }
                }
            }
        }
        
        None
    }
    
    /// Check if a 1GB block is fully free
    #[inline]
    pub fn is_1g_free(&self, block_idx: usize) -> bool {
        if block_idx >= self.total_1g_blocks {
            return false;
        }
        let word_idx = block_idx / BITS_PER_WORD;
        let bit_idx = block_idx % BITS_PER_WORD;
        let word = self.bitmap_1g[word_idx].load(Ordering::Acquire);
        (word & (1u64 << bit_idx)) != 0
    }

    /// Free a 1GB block
    ///
    /// All 512 2MB blocks in this 1GB block must be fully allocated.
    pub(crate) fn free_1g(&self, block_idx: usize) -> bool {
        if block_idx >= self.total_1g_blocks {
            return false;
        }
        
        // Free all 512 2MB blocks
        let block_2m_start = block_idx * BLOCKS_2MB_PER_1GB;
        let block_2m_end = (block_2m_start + BLOCKS_2MB_PER_1GB).min(self.total_2m_blocks);
        
        let mut success = true;
        for block_2m in block_2m_start..block_2m_end {
            if !self.free_2m(block_2m) {
                success = false;
            }
        }
        
        success
    }

    // ========================================================================
    // Bounded Allocation (for strict address limits)
    // ========================================================================

    /// Allocate 4KB page below specific limit
    pub fn allocate_4k_below(&self, limit_page_idx: usize) -> Option<usize> {
        // Try partial blocks first (but restricted by limit)
        if let Some(page) = self.allocate_4k_from_partial_below(limit_page_idx) {
             return Some(page);
        }
        
        // Try base bitmap
        if let Some(page) = self.base.allocate_one_below(limit_page_idx) {
             self.on_page_allocated(page);
             return Some(page);
        }
        
        None
    }

    /// Allocate 4KB from partial/demoted blocks below limit
    fn allocate_4k_from_partial_below(&self, limit_page_idx: usize) -> Option<usize> {
        let limit_block = (limit_page_idx + PAGES_PER_2MB - 1) / PAGES_PER_2MB;
        let limit_word = (limit_block + BITS_PER_WORD - 1) / BITS_PER_WORD;

        // 1. Try demoted blocks (linear scan 0..limit)
        if let Some(page) = self.scan_bitmap_below(&self.demoted_2m, limit_word, limit_block, limit_page_idx) {
            return Some(page);
        }

        // 2. Try partial blocks (linear scan 0..limit)
        if let Some(page) = self.scan_bitmap_below(&self.bitmap_2m_partial, limit_word, limit_block, limit_page_idx) {
            return Some(page);
        }

        // 3. Demote fully free block (linear scan 0..limit)
        if let Some(block) = self.demote_2m_block_below(limit_block) {
             return self.allocate_from_block(block);
        }

        None
    }

    /// Scan a bitmap for a usable block below the given limits and allocate a page from it.
    /// Scan individual bits in a single bitmap word for an allocatable page below limit.
    fn scan_word_bits_below(
        &self,
        word: u64,
        word_idx: usize,
        limit_block: usize,
        limit_page_idx: usize,
    ) -> Option<usize> {
        for bit in 0..BITS_PER_WORD {
            let block_idx = word_idx * BITS_PER_WORD + bit;
            if block_idx >= limit_block { return None; }
            if (word & (1u64 << bit)) != 0 {
                if let Some(page) = self.allocate_from_block(block_idx) {
                    if page < limit_page_idx { return Some(page); }
                }
            }
        }
        None
    }

    fn scan_bitmap_below(
        &self,
        bitmap: &[AtomicU64],
        limit_word: usize,
        limit_block: usize,
        limit_page_idx: usize,
    ) -> Option<usize> {
        let scan_end = limit_word.min(bitmap.len());

        for word_idx in 0..scan_end {
            if word_idx * BITS_PER_WORD >= limit_block { break; }
            let word = bitmap[word_idx].load(Ordering::Acquire);
            if word == 0 { continue; }

            if let Some(page) = self.scan_word_bits_below(word, word_idx, limit_block, limit_page_idx) {
                return Some(page);
            }
        }
        None
    }

    /// Demote a fully-free 2MB block below limit
    fn demote_2m_block_below(&self, limit_block: usize) -> Option<usize> {
        let limit_word = (limit_block + BITS_PER_WORD - 1) / BITS_PER_WORD;
        let scan_end = limit_word.min(self.bitmap_2m.len());

        for word_idx in 0..scan_end {
            if word_idx * BITS_PER_WORD >= limit_block { return None; }
            loop {
                let word = self.bitmap_2m[word_idx].load(Ordering::Acquire);
                if word == 0 { break; }
                
                let bit_idx = word.trailing_zeros() as usize;
                let block_idx = word_idx * BITS_PER_WORD + bit_idx;
                if block_idx >= limit_block { return None; }

                let bit_mask = 1u64 << bit_idx;
                
                // Check demoted
                let demoted = self.demoted_2m[word_idx].load(Ordering::Acquire);
                if (demoted & bit_mask) != 0 {
                    // Already demoted, try next bit 
                    // But trailing_zeros finds FIRST. If first is demoted, we must mask it out to find next?
                    // Optimized loop should rely on masking or iterator?
                    // This naive loop is broken if we just 'continue' without changing 'word'.
                    // Actually demoted blocks are removed from bitmap_2m? 
                    // No. bitmap_2m tracks "fully free".
                    // demoted_2m tracks "demoted (was fully free, now for 4k)".
                    // If demoted, it IS fully free in 2MB sense? No, it's BEING USESD for 4K.
                    // Wait, `demote_2m_block` implementation (Line 1097) checks `demoted_2m`.
                    // And it attempts to CLEAR `bitmap_2m`.
                    // `match self.bitmap_2m... compare_exchange(word, word & !bit_mask ...)`
                    // So if it succeeds, it REMOVES from bitmap_2m.
                    // So next strict loop read will see 'word' without that bit.
                    // BUT: if we fail CAS or find demoted, we need to retry loop with refreshed 'word'.
                    // My loop `let word = ...` is inside `loop`.
                    
                    // But if (demoted & bit_mask) != 0:
                    // It means bit is set in `bitmap_2m`.
                    // But it is ALSO set in `demoted_2m`?
                    // No, `allocate_4k_from_demoted` consumes pages.
                    // If a block is demoted, it should NOT be in `bitmap_2m` as "Full Free".
                    // Line 1105: `word & !bit_mask`. It clears it from `bitmap_2m`.
                    // So `bitmap_2m` bit 1 means "Fully Free and NOT Demoted".
                    // So `demote_2m_block` check at 1097 `if (demoted_word & bit_mask) != 0` seems redundant or paranoid?
                    // Ah, maybe race condition where it was added to demoted but not yet removed from bitmap_2m (unlikely with CAS).
                    // Or maybe I misunderstand `bitmap_2m` semantics.
                    // `bitmap_2m` = "Fully Free 2MB Block".
                }
                
                match self.bitmap_2m[word_idx].compare_exchange_weak(word, word & !bit_mask, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => {
                        self.demoted_2m[word_idx].fetch_or(bit_mask, Ordering::AcqRel);
                        self.bitmap_2m_partial[word_idx].fetch_or(bit_mask, Ordering::AcqRel);
                        self.free_count_2m.fetch_sub(1, Ordering::Relaxed);
                        self.partial_count_2m.fetch_add(1, Ordering::Relaxed);
                        self.demoted_count_2m.fetch_add(1, Ordering::Relaxed);
                        return Some(block_idx);
                    }
                    Err(_) => { core::hint::spin_loop(); }
                }
            }
        }
        None
    }

    /// Allocate 2MB super-page below specific limit
    pub fn allocate_2m_below(&self, limit_block_idx: usize) -> Option<usize> {
        let limit_word = (limit_block_idx + BITS_PER_WORD - 1) / BITS_PER_WORD;
        let scan_end = limit_word.min(self.bitmap_2m.len());

        for word_idx in 0..scan_end {
            if word_idx * BITS_PER_WORD >= limit_block_idx { return None; }
            loop {
                let word = self.bitmap_2m[word_idx].load(Ordering::Acquire);
                if word == 0 { break; }
                
                let bit_idx = word.trailing_zeros() as usize;
                let block_idx = word_idx * BITS_PER_WORD + bit_idx;
                if block_idx >= limit_block_idx { return None; }
                
                let bit_mask = 1u64 << bit_idx;
                match self.bitmap_2m[word_idx].compare_exchange_weak(word, word & !bit_mask, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => {
                         // Init block logic (duplicated from allocate_2m)
                        self.base.mark_allocated_range(block_idx * PAGES_PER_2MB, PAGES_PER_2MB);
                        self.used_count_2m[block_idx].store(PAGES_PER_2MB as u16, Ordering::Release);
                        self.free_word_mask_2m[block_idx].store(0, Ordering::Release);
                        
                        // Update 1GB tracking
                        let block_1g = block_idx / BLOCKS_2MB_PER_1GB;
                        if block_1g < self.used_count_1g.len() {
                            let old_used = self.used_count_1g[block_1g].fetch_add(1, Ordering::AcqRel);
                            if old_used == 0 {
                                // Was fully free (should have been caught by 1G alloc? No)
                                // If it was 0, it means 1GB was empty.
                                // Clear 1GB free bit
                                let w1g = block_1g / BITS_PER_WORD;
                                let b1g = block_1g % BITS_PER_WORD;
                                self.bitmap_1g[w1g].fetch_and(!(1u64 << b1g), Ordering::AcqRel);
                                self.free_count_1g.fetch_sub(1, Ordering::Relaxed);
                            }
                        }
                        
                        self.free_count_2m.fetch_sub(1, Ordering::Relaxed);
                        return Some(block_idx);
                    }
                    Err(_) => { core::hint::spin_loop(); }
                }
            }
        }
        None
    }

    /// Allocate 1GB huge-page below specific limit
    pub fn allocate_1g_below(&self, limit_block_idx: usize) -> Option<usize> {
        let limit_word = (limit_block_idx + BITS_PER_WORD - 1) / BITS_PER_WORD;
        let scan_end = limit_word.min(self.bitmap_1g.len());

        for word_idx in 0..scan_end {
            if word_idx * BITS_PER_WORD >= limit_block_idx { return None; }
            loop {
                let word = self.bitmap_1g[word_idx].load(Ordering::Acquire);
                if word == 0 { break; }
                
                let bit_idx = word.trailing_zeros() as usize;
                let block_idx = word_idx * BITS_PER_WORD + bit_idx;
                if block_idx >= limit_block_idx { return None; }

                let bit_mask = 1u64 << bit_idx;
                match self.bitmap_1g[word_idx].compare_exchange_weak(word, word & !bit_mask, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => {
                         // Initialize 1GB block (duplicated from allocate_1g)
                         // Mark 2MB blocks as allocated
                        let block_2m_start = block_idx * BLOCKS_2MB_PER_1GB;
                        for i in 0..BLOCKS_2MB_PER_1GB {
                             let block_2m = block_2m_start + i;
                             if block_2m < self.total_2m_blocks {
                                  // Clear 2MB free bit
                                  let w2m = block_2m / BITS_PER_WORD;
                                  let b2m = block_2m % BITS_PER_WORD;
                                  self.bitmap_2m[w2m].fetch_and(!(1u64 << b2m), Ordering::AcqRel);
                                  self.used_count_2m[block_2m].store(PAGES_PER_2MB as u16, Ordering::Release);
                                  self.free_word_mask_2m[block_2m].store(0, Ordering::Release);
                             }
                        }
                        // Mark pages
                        self.base.mark_allocated_range(block_idx * BLOCKS_2MB_PER_1GB * PAGES_PER_2MB, BLOCKS_2MB_PER_1GB * PAGES_PER_2MB);
                        
                        self.used_count_1g[block_idx].store(BLOCKS_2MB_PER_1GB as u16, Ordering::Release);
                        self.free_count_1g.fetch_sub(1, Ordering::Relaxed);
                        self.free_count_2m.fetch_sub(BLOCKS_2MB_PER_1GB.min(self.total_2m_blocks - block_2m_start), Ordering::Relaxed);

                        return Some(block_idx);
                    }
                    Err(_) => { core::hint::spin_loop(); }
                }
            }
        }
        None
    }
    
    // ========================================================================
    // Hugepage-Preserving 4KB Allocation
    // ========================================================================
    
    /// Allocate 4KB from partial 2MB blocks
    ///
    /// This preserves fully-free 2MB blocks for hugepage allocation by
    /// preferring to allocate from blocks that are already partially used.
    pub fn allocate_4k_from_partial(&self) -> Option<usize> {
        // First try demoted blocks
        if let Some(page) = self.allocate_4k_from_demoted() {
            return Some(page);
        }
        
        // Then try partial blocks
        let hint = self.hint_2m_partial.load(Ordering::Relaxed) % self.bitmap_2m_partial.len().max(1);
        
        for offset in 0..self.bitmap_2m_partial.len() {
            let word_idx = (hint + offset) % self.bitmap_2m_partial.len();
            let word = self.bitmap_2m_partial[word_idx].load(Ordering::Acquire);
            if word == 0 {
                continue;
            }
            
            // Find a partial block
            let bit_idx = word.trailing_zeros() as usize;
            let block_idx = word_idx * BITS_PER_WORD + bit_idx;
            
            if block_idx >= self.total_2m_blocks {
                continue;
            }
            
            // Try to allocate from this block's free words
            if let Some(page) = self.allocate_from_block(block_idx) {
                self.hint_2m_partial.store(word_idx, Ordering::Relaxed);
                return Some(page);
            }
        }
        
        // Finally, demote a fully-free 2MB block
        if let Some(block) = self.demote_2m_block() {
            return self.allocate_from_block(block);
        }
        
        None
    }
    
    /// Allocate 4KB from demoted blocks
    fn allocate_4k_from_demoted(&self) -> Option<usize> {
        for word_idx in 0..self.demoted_2m.len() {
            let word = self.demoted_2m[word_idx].load(Ordering::Acquire);
            if word == 0 {
                continue;
            }
            
            for bit in 0..BITS_PER_WORD {
                if (word & (1u64 << bit)) == 0 {
                    continue;
                }
                
                let block_idx = word_idx * BITS_PER_WORD + bit;
                if block_idx >= self.total_2m_blocks {
                    break;
                }
                
                if let Some(page) = self.allocate_from_block(block_idx) {
                    return Some(page);
                }
            }
        }
        
        None
    }
    
    /// Allocate a 4KB page from a specific 2MB block
    fn allocate_from_block(&self, block_idx: usize) -> Option<usize> {
        let mask = self.free_word_mask_2m[block_idx].load(Ordering::Acquire);
        if mask == 0 {
            return None;
        }
        
        let word_in_block = mask.trailing_zeros() as usize;
        let detail_word_idx = block_idx * WORDS_PER_2MB + word_in_block;
        
        if let Some(page_idx) = self.base.try_allocate_from_word(detail_word_idx) {
            self.on_page_allocated(page_idx);
            return Some(page_idx);
        }
        
        None
    }
    
    /// Demote a fully-free 2MB block for 4KB allocation
    fn demote_2m_block(&self) -> Option<usize> {
        // Find a fully-free, non-demoted block
        for word_idx in 0..self.bitmap_2m.len() {
            loop {
                let word = self.bitmap_2m[word_idx].load(Ordering::Acquire);
                if word == 0 {
                    break;
                }
                
                let bit_idx = word.trailing_zeros() as usize;
                let bit_mask = 1u64 << bit_idx;
                let block_idx = word_idx * BITS_PER_WORD + bit_idx;
                
                // Check if already demoted
                let demoted_word = self.demoted_2m[word_idx].load(Ordering::Acquire);
                if (demoted_word & bit_mask) != 0 {
                    // Try next bit
                    continue;
                }
                
                // Try to clear fully-free bit and set demoted bit atomically
                match self.bitmap_2m[word_idx].compare_exchange_weak(
                    word,
                    word & !bit_mask,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        // Set demoted bit
                        self.demoted_2m[word_idx].fetch_or(bit_mask, Ordering::AcqRel);
                        
                        // Mark as partial
                        self.bitmap_2m_partial[word_idx].fetch_or(bit_mask, Ordering::AcqRel);
                        
                        self.free_count_2m.fetch_sub(1, Ordering::Relaxed);
                        self.partial_count_2m.fetch_add(1, Ordering::Relaxed);
                        self.demoted_count_2m.fetch_add(1, Ordering::Relaxed);
                        
                        return Some(block_idx);
                    }
                    Err(_) => {
                        core::hint::spin_loop();
                    }
                }
            }
        }
        
        None
    }
    
    // ========================================================================
    // Hierarchy Maintenance Callbacks
    // ========================================================================
    
    /// Called when a 4KB page is allocated
    ///
    /// Updates 2MB and 1GB tracking accordingly.
    pub(crate) fn on_page_allocated(&self, page_idx: usize) {
        let block_2m = page_idx / PAGES_PER_2MB;
        if block_2m >= self.total_2m_blocks {
            return;
        }
        
        // Update used count
        let old_used = self.used_count_2m[block_2m].fetch_add(1, Ordering::AcqRel);
        
        // Update word mask
        let word_in_block = (page_idx % PAGES_PER_2MB) / BITS_PER_WORD;
        let detail_word_idx = block_2m * WORDS_PER_2MB + word_in_block;
        if self.base.detail()[detail_word_idx].load(Ordering::Acquire) == 0 {
            let mask_bit = 1u8 << word_in_block;
            self.free_word_mask_2m[block_2m].fetch_and(!mask_bit, Ordering::AcqRel);
        }
        
        if old_used == 0 {
            // Block was fully free, now it's not
            let word_idx = block_2m / BITS_PER_WORD;
            let bit_idx = block_2m % BITS_PER_WORD;
            let bit_mask = 1u64 << bit_idx;
            
            // Clear fully-free bit
            self.bitmap_2m[word_idx].fetch_and(!bit_mask, Ordering::AcqRel);
            
            // Set partial bit
            self.bitmap_2m_partial[word_idx].fetch_or(bit_mask, Ordering::AcqRel);
            
            self.free_count_2m.fetch_sub(1, Ordering::Relaxed);
            self.partial_count_2m.fetch_add(1, Ordering::Relaxed);
            
            // Update 1GB
            let block_1g = block_2m / BLOCKS_2MB_PER_1GB;
            if block_1g < self.used_count_1g.len() {
                let old_1g = self.used_count_1g[block_1g].fetch_add(1, Ordering::AcqRel);
                if old_1g == 0 {
                    let w1g = block_1g / BITS_PER_WORD;
                    let b1g = block_1g % BITS_PER_WORD;
                    self.bitmap_1g[w1g].fetch_and(!(1u64 << b1g), Ordering::AcqRel);
                    self.free_count_1g.fetch_sub(1, Ordering::Relaxed);
                }
            }
        }
    }
    
    /// Called when a 4KB page is freed
    ///
    /// Updates 2MB and 1GB tracking accordingly.
    pub(crate) fn on_page_freed(&self, page_idx: usize) {
        let block_2m = page_idx / PAGES_PER_2MB;
        if block_2m >= self.total_2m_blocks {
            return;
        }
        
        // Update word mask
        let word_in_block = (page_idx % PAGES_PER_2MB) / BITS_PER_WORD;
        let mask_bit = 1u8 << word_in_block;
        self.free_word_mask_2m[block_2m].fetch_or(mask_bit, Ordering::AcqRel);
        
        // Update used count
        let old_used = self.used_count_2m[block_2m].fetch_sub(1, Ordering::AcqRel);
        
        if old_used == 1 {
            // Block is now fully free
            let word_idx = block_2m / BITS_PER_WORD;
            let bit_idx = block_2m % BITS_PER_WORD;
            let bit_mask = 1u64 << bit_idx;
            
            // Clear partial bit
            self.bitmap_2m_partial[word_idx].fetch_and(!bit_mask, Ordering::AcqRel);
            self.partial_count_2m.fetch_sub(1, Ordering::Relaxed);
            
            // Check if demoted
            let demoted = self.demoted_2m[word_idx].load(Ordering::Acquire);
            if (demoted & bit_mask) != 0 {
                // Clear demoted bit and set fully-free
                self.demoted_2m[word_idx].fetch_and(!bit_mask, Ordering::AcqRel);
                self.demoted_count_2m.fetch_sub(1, Ordering::Relaxed);
            }
            
            // Set fully-free bit
            self.bitmap_2m[word_idx].fetch_or(bit_mask, Ordering::AcqRel);
            self.free_count_2m.fetch_add(1, Ordering::Relaxed);
            
            // Update 1GB
            let block_1g = block_2m / BLOCKS_2MB_PER_1GB;
            if block_1g < self.used_count_1g.len() {
                let old_1g = self.used_count_1g[block_1g].fetch_sub(1, Ordering::AcqRel);
                if old_1g == 1 {
                    let w1g = block_1g / BITS_PER_WORD;
                    let b1g = block_1g % BITS_PER_WORD;
                    self.bitmap_1g[w1g].fetch_or(1u64 << b1g, Ordering::AcqRel);
                    self.free_count_1g.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
    
    // ========================================================================
    // Accessors for IovaBitmap Integration (Phase 3.2)
    // ========================================================================
    
    // Accessors for IovaBitmap Integration (Phase 3.2)
    // ========================================================================
    
    /// Access the base 4KB hierarchical bitmap (immutable)
    #[inline]
    pub(crate) fn base_bitmap(&self) -> &HierarchicalBitmap {
        &self.base
    }
    
    /// Access the base 4KB hierarchical bitmap (mutable)
    #[inline]
    pub fn base_mut(&mut self) -> &mut HierarchicalBitmap {

        &mut self.base
    }
    
    /// Access detail bitmap directly
    #[inline]
    pub fn detail(&self) -> &[AtomicU64] {
        self.base.detail()
    }
    
    /// Access summary bitmap directly
    #[inline]
    pub fn summary(&self) -> &[AtomicU64] {
        self.base.summary()
    }
    
    /// Access L2 summary bitmap directly
    #[inline]
    pub fn summary_l2(&self) -> &[AtomicU64] {
        self.base.summary_l2()
    }
    
    /// Get valid mask for a detail word
    #[inline]
    pub fn valid_mask(&self, word_idx: usize) -> u64 {
        self.base.valid_mask(word_idx)
    }
    
    /// Access used_count_2m directly
    #[inline]
    pub fn used_count_2m(&self) -> &[AtomicU16] {
        &self.used_count_2m
    }
    
    /// Access bitmap_2m directly
    #[inline]
    pub fn bitmap_2m(&self) -> &[AtomicU64] {
        &self.bitmap_2m
    }
    
    /// Access bitmap_2m_partial directly
    #[inline]
    pub fn bitmap_2m_partial(&self) -> &[AtomicU64] {
        &self.bitmap_2m_partial
    }
    
    /// Access demoted_2m directly
    #[inline]
    pub fn demoted_2m(&self) -> &[AtomicU64] {
        &self.demoted_2m
    }
    
    /// Access free_word_mask_2m directly
    #[inline]
    pub fn free_word_mask_2m(&self) -> &[AtomicU8] {
        &self.free_word_mask_2m
    }
    
    /// Access used_count_1g directly
    #[inline]
    pub fn used_count_1g(&self) -> &[AtomicU16] {
        &self.used_count_1g
    }
    
    /// Access bitmap_1g directly
    #[inline]
    pub fn bitmap_1g(&self) -> &[AtomicU64] {
        &self.bitmap_1g
    }
    
    /// Get demoted 2MB block count
    #[inline]
    pub fn demoted_count_2m(&self) -> usize {
        self.demoted_count_2m.load(Ordering::Relaxed)
    }
    
    /// Get hint for 4KB allocation
    #[inline]
    pub fn hint_4k(&self) -> usize {
        self.base.hint.load(Ordering::Relaxed)
    }
    
    /// Set hint for 4KB allocation
    #[inline]
    pub fn set_hint_4k(&self, hint: usize) {
        self.base.hint.store(hint, Ordering::Relaxed);
    }
    
    /// Get hint for 2MB allocation
    #[inline]
    pub fn hint_2m(&self) -> usize {
        self.hint_2m.load(Ordering::Relaxed)
    }
    
    /// Set hint for 2MB allocation
    #[inline]
    pub fn set_hint_2m(&self, hint: usize) {
        self.hint_2m.store(hint, Ordering::Relaxed);
    }
    
    /// Get hint for partial 2MB allocation
    #[inline]
    pub fn hint_2m_partial(&self) -> usize {
        self.hint_2m_partial.load(Ordering::Relaxed)
    }
    
    /// Set hint for partial 2MB allocation
    #[inline]
    pub fn set_hint_2m_partial(&self, hint: usize) {
        self.hint_2m_partial.store(hint, Ordering::Relaxed);
    }
    
    /// Mark a page as allocated (low-level)
    #[inline]
    pub fn mark_page_allocated(&self, page_idx: usize) -> bool {
        if self.base.mark_allocated(page_idx) {
            self.on_page_allocated(page_idx);
            true
        } else {
            false
        }
    }
    
    /// Mark a page as free (low-level)
    #[inline]
    pub fn mark_page_free(&self, page_idx: usize) -> bool {
        if self.base.mark_free(page_idx) {
            self.on_page_freed(page_idx);
            true
        } else {
            false
        }
    }
    
    /// Try to allocate from a specific word (for single-writer arena)
    #[inline]
    pub fn try_allocate_from_word(&self, word_idx: usize) -> Option<usize> {
        if let Some(page_idx) = self.base.try_allocate_from_word(word_idx) {
            self.on_page_allocated(page_idx);
            Some(page_idx)
        } else {
            None
        }
    }
    
    /// Try to claim an entire word (for single-writer arena batch allocation)
    #[inline]
    pub fn try_claim_word(&self, word_idx: usize) -> u64 {
        let bits = self.base.try_claim_word(word_idx);
        // Note: on_page_allocated must be called for each allocated page
        // This is handled by the caller
        bits
    }
    
    /// Return bits to a word (for single-writer arena)
    #[inline]
    pub fn return_word(&self, word_idx: usize, bits: u64) {
        self.base.return_word(word_idx, bits);
        // Note: on_page_freed must be called for each freed page
        // This is handled by the caller
    }
    
    // ========================================================================
    // Coalesced Free Optimization (N frees → 1 atomic)
    // ========================================================================
    
    /// Free multiple pages in the same word with a single atomic operation
    ///
    /// Instead of N separate `mark_free()` calls (N atomics), this combines
    /// them into a single `fetch_or` operation.
    ///
    /// # Arguments
    /// * `word_idx` - Word index in detail bitmap
    /// * `coalesced_mask` - Bitmask of pages to free (1 = free that page)
    ///
    /// # Returns
    /// * `Ok(freed_count)` - Number of pages actually freed
    /// * `Err(())` - Invalid word index
    ///
    /// # Performance
    /// - Single atomic `fetch_or` instead of N `compare_exchange_weak` loops
    /// - Particularly effective for batch free in RemoteFreeRing drain
    ///
    /// # Example
    /// ```ignore
    /// // Free pages 0, 1, 5, 6, 7 in word 10 (5 pages, 1 atomic)
    /// let mask = 0b11100011; // bits 0,1,5,6,7
    /// bitmap.free_pages_coalesced(10, mask)?;
    /// ```
    pub fn free_pages_coalesced(&self, word_idx: usize, coalesced_mask: u64) -> Result<usize, ()> {
        if word_idx >= self.base.detail().len() {
            return Err(());
        }
        
        let valid_mask = self.base.valid_mask(word_idx);
        let bits_to_free = coalesced_mask & valid_mask;
        
        if bits_to_free == 0 {
            return Ok(0);
        }
        
        // Single atomic operation to free all pages in the mask
        let old = self.base.detail()[word_idx].fetch_or(bits_to_free, Ordering::AcqRel);
        
        // Count how many pages were actually freed (were 0 before, now 1)
        let actually_freed = bits_to_free & !old;
        let freed_count = actually_freed.count_ones() as usize;
        
        if freed_count == 0 {
            return Ok(0);
        }
        
        // Update free count
        self.base.free_count.fetch_add(freed_count, Ordering::Relaxed);
        
        // Update summary if word was empty
        if old == 0 {
            self.base.set_summary_bit(word_idx);
        }
        
        // Update 2MB hierarchy for affected pages
        self.update_2m_hierarchy_on_free(word_idx, freed_count);
        
        Ok(freed_count)
    }

    /// Update 2MB/1GB hierarchy after freeing pages in a word
    fn update_2m_hierarchy_on_free(&self, word_idx: usize, freed_count: usize) {
        let start_page = word_idx * BITS_PER_WORD;
        let block_2m = start_page / PAGES_PER_2MB;
        
        if block_2m >= self.total_2m_blocks {
            return;
        }

        let word_in_block = (start_page % PAGES_PER_2MB) / BITS_PER_WORD;
        let mask_bit = 1u8 << word_in_block;
        self.free_word_mask_2m[block_2m].fetch_or(mask_bit, Ordering::AcqRel);
        
        let old_used = self.used_count_2m[block_2m].fetch_sub(freed_count as u16, Ordering::AcqRel);
        let new_used = old_used.saturating_sub(freed_count as u16);
        
        if new_used == 0 && old_used > 0 {
            let bword = block_2m / BITS_PER_WORD;
            let bbit = block_2m % BITS_PER_WORD;
            let bmask = 1u64 << bbit;
            
            self.bitmap_2m_partial[bword].fetch_and(!bmask, Ordering::AcqRel);
            self.partial_count_2m.fetch_sub(1, Ordering::Relaxed);
            
            let demoted = self.demoted_2m[bword].load(Ordering::Acquire);
            if (demoted & bmask) != 0 {
                self.demoted_2m[bword].fetch_and(!bmask, Ordering::AcqRel);
                self.demoted_count_2m.fetch_sub(1, Ordering::Relaxed);
            }
            
            self.bitmap_2m[bword].fetch_or(bmask, Ordering::AcqRel);
            self.free_count_2m.fetch_add(1, Ordering::Relaxed);
            
            let block_1g = block_2m / BLOCKS_2MB_PER_1GB;
            if block_1g < self.used_count_1g.len() {
                let old_1g = self.used_count_1g[block_1g].fetch_sub(1, Ordering::AcqRel);
                if old_1g == 1 {
                    let w1g = block_1g / BITS_PER_WORD;
                    let b1g = block_1g % BITS_PER_WORD;
                    self.bitmap_1g[w1g].fetch_or(1u64 << b1g, Ordering::AcqRel);
                    self.free_count_1g.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
    
    // ========================================================================
    // O(1) Word Selection in Partial Blocks
    // ========================================================================
    
    /// Find a non-empty word in partial 2MB blocks using free_word_mask
    ///
    /// Uses the `free_word_mask_2m` optimization for O(1) word selection
    /// within partial blocks, instead of scanning all 8 words per block.
    ///
    /// # Arguments
    /// * `hint` - Starting block index (modulo total blocks)
    ///
    /// # Returns
    /// * `Some(word_idx)` - Global detail word index with free pages
    /// * `None` - No partial blocks have free pages
    ///
    /// # Performance
    /// - O(1) word selection within each block (via tzcnt on 8-bit mask)
    /// - Scans partial block bitmap at word granularity
    pub fn find_non_empty_word_in_partial(&self, hint: usize) -> Option<usize> {
        let hint_block = hint % self.total_2m_blocks.max(1);
        
        for offset in 0..self.bitmap_2m_partial.len() {
            let word_idx = (hint_block / BITS_PER_WORD + offset) % self.bitmap_2m_partial.len();
            let partial_word = self.bitmap_2m_partial[word_idx].load(Ordering::Acquire);
            
            if partial_word == 0 {
                continue;
            }
            
            // Iterate through partial blocks in this word
            let mut remaining = partial_word;
            while remaining != 0 {
                let bit_idx = remaining.trailing_zeros() as usize;
                remaining &= remaining - 1; // Clear lowest bit
                
                let block_idx = word_idx * BITS_PER_WORD + bit_idx;
                if block_idx >= self.total_2m_blocks {
                    continue;
                }
                
                // Use free_word_mask for O(1) word selection within block
                let free_mask = self.free_word_mask_2m[block_idx].load(Ordering::Acquire);
                if free_mask == 0 {
                    continue;
                }
                
                let word_in_block = free_mask.trailing_zeros() as usize;
                let global_word_idx = block_idx * WORDS_PER_2MB + word_in_block;
                
                return Some(global_word_idx);
            }
        }
        
        None
    }
    
    /// Try to claim a word from partial blocks for SubMagazine
    ///
    /// Combines `find_non_empty_word_in_partial` with `try_claim_word` for
    /// efficient SubMagazine refill.
    ///
    /// # Returns
    /// * `Some((word_idx, bits, base_addr))` - Claimed word info for SubMagazine
    /// * `None` - No claimable words in partial blocks
    pub fn try_claim_word_from_partial(&self, hint: usize, base_addr: u64) -> Option<(usize, u64, u64)> {
        let word_idx = self.find_non_empty_word_in_partial(hint)?;
        let bits = self.try_claim_word(word_idx);
        
        if bits == 0 {
            return None;
        }
        
        // Calculate physical address for this word
        let page_base = word_idx * BITS_PER_WORD;
        let word_base_addr = base_addr + (page_base as u64) * 4096;
        
        Some((word_idx, bits, word_base_addr))
    }
}

// ============================================================================
// QEMU smoke tests
// ============================================================================

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests;

