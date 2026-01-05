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
//! │  │ - 4KB bitmap: 1 bit per 4KB page                        ││
//! │  │ - 2MB bitmap: 1 bit per 2MB region                      ││
//! │  │ - Hierarchical summary for fast scanning                ││
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

use core::sync::atomic::{AtomicU16, AtomicU64, AtomicUsize, Ordering};
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
// Hierarchical Block Constants
// ============================================================================

/// 4KB pages per 2MB block (2MB / 4KB = 512)
const PAGES_PER_2MB_BLOCK: usize = 512;

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

/// Per-CPU magazine set (one magazine per size class)
///
/// Also holds per-CPU allocation hints to avoid cache line bounce
/// on the global hint when multiple cores allocate simultaneously.
#[repr(C, align(128))] // Two cache lines to avoid false sharing
pub struct PerCpuMagazine {
    /// Magazines indexed by size class
    magazines: [IrqMutex<Magazine>; MAGAZINE_SIZE_CLASSES],
    /// Per-CPU hint for 4KB allocation (word index to start searching)
    pub hint_4k: AtomicUsize,
    /// Per-CPU hint for 2MB allocation (block index to start searching)
    pub hint_2m: AtomicUsize,
}

impl PerCpuMagazine {
    /// Create empty per-CPU magazines
    pub const fn new() -> Self {
        Self {
            magazines: [
                IrqMutex::new(Magazine::new()), // 4KB
                IrqMutex::new(Magazine::new()), // 2MB
                IrqMutex::new(Magazine::new()), // 1GB
            ],
            hint_4k: AtomicUsize::new(0),
            hint_2m: AtomicUsize::new(0),
        }
    }

    /// Get magazine for a size class
    #[inline]
    pub fn get(&self, size_class: usize) -> Option<&IrqMutex<Magazine>> {
        self.magazines.get(size_class)
    }
}

// ============================================================================
// Bitmap Allocator (Medium Path)
// ============================================================================

/// Hierarchical bitmap for O(1) amortized allocation
///
/// Uses a two-level hierarchy:
/// - Level 0: Summary bitmap (1 bit per 64 pages)
/// - Level 1: Detail bitmap (1 bit per page)
/// - Level 2: 2MB fully-free bitmap (1 bit per 512 pages)
/// - Level 3: 1GB fully-free bitmap (1 bit per 512 2MB blocks)
///
/// This allows finding a free page in O(1) amortized time by first
/// checking the summary level. For 2MB/1GB allocations, the dedicated
/// fully-free bitmaps provide O(1) allocation without linear scanning.
///
/// # Memory Overhead (256GB IOVA space)
/// - 4KB detail bitmap: 8MB (64M bits)
/// - 4KB summary bitmap: 128KB
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

    // === 4KB Level ===
    /// Level 1: Detailed bitmap (1 = free, 0 = allocated)
    detail: alloc::boxed::Box<[AtomicU64]>,
    /// Level 0: Summary bitmap (1 = has free pages in corresponding detail word)
    summary: alloc::boxed::Box<[AtomicU64]>,
    /// Allocation hint for 4KB (word index to start searching)
    hint_4k: AtomicUsize,
    /// Free 4KB page count
    free_count_4k: AtomicUsize,
    /// Valid bit mask for the last word (handles non-64-aligned total_pages)
    /// For word i < last_word: mask is u64::MAX
    /// For last_word: mask has only `total_pages % 64` bits set (or 64 if aligned)
    last_word_mask: u64,

    // === 2MB Level (Fully-Free Tracking) ===
    /// Per-2MB-block used count (0..512) - when 0, the block is fully free
    used_count_2m: alloc::boxed::Box<[AtomicU16]>,
    /// 2MB fully-free bitmap (1 = all 512 pages in this 2MB block are free)
    bitmap_2m: alloc::boxed::Box<[AtomicU64]>,
    /// Allocation hint for 2MB (block index to start searching)
    hint_2m: AtomicUsize,
    /// Free 2MB block count (fully free only)
    free_count_2m: AtomicUsize,

    // === 1GB Level (Fully-Free Tracking) ===
    /// Per-1GB-block used count (count of non-free 2MB blocks, 0..512)
    used_count_1g: alloc::boxed::Box<[AtomicU16]>,
    /// 1GB fully-free bitmap (1 = all 512 2MB blocks in this 1GB are fully free)
    bitmap_1g: alloc::boxed::Box<[AtomicU64]>,
    /// Free 1GB block count (fully free only)
    free_count_1g: AtomicUsize,
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

        // === 4KB Level Initialization ===
        let detail_words = (capped_pages + BITS_PER_WORD - 1) / BITS_PER_WORD;
        let summary_words = (detail_words + BITS_PER_WORD - 1) / BITS_PER_WORD;

        // Allocate and initialize detail bitmap (all free = all 1s)
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

        // Allocate and initialize summary bitmap
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
            hint_4k: AtomicUsize::new(0),
            free_count_4k: AtomicUsize::new(capped_pages),
            last_word_mask,
            used_count_2m: used_count_2m.into_boxed_slice(),
            bitmap_2m: bitmap_2m.into_boxed_slice(),
            hint_2m: AtomicUsize::new(0),
            // Only complete 2MB blocks are counted as "free" for 2MB allocation
            free_count_2m: AtomicUsize::new(complete_2mb_blocks),
            used_count_1g: used_count_1g.into_boxed_slice(),
            bitmap_1g: bitmap_1g.into_boxed_slice(),
            // Only complete 1GB blocks are counted as "free" for 1GB allocation
            free_count_1g: AtomicUsize::new(complete_1gb_blocks),
        }
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
    pub fn allocate_page_with_hint(&self, hint: &AtomicUsize) -> Option<u64> {
        let hint_val = hint.load(Ordering::Relaxed);
        let detail_words = self.detail.len();

        if detail_words == 0 {
            return None;
        }

        let hint_idx = hint_val % detail_words;
        let summary_words = self.summary.len();

        // Summary-first scan (fast when nearly full)
        for summary_offset in 0..summary_words {
            let summary_idx = (hint_idx / BITS_PER_WORD + summary_offset) % summary_words;
            let mut summary_word = self.summary[summary_idx].load(Ordering::Acquire);
            if summary_word == 0 {
                continue;
            }

            if summary_offset == 0 {
                let start_bit = hint_idx % BITS_PER_WORD;
                summary_word &= !((1u64 << start_bit) - 1);
                if summary_word == 0 {
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
                        // Update 2MB/1GB hierarchy
                        self.on_page_allocated(page_idx);
                        return Some(self.base + (page_idx as u64) * PAGE_SIZE_4K);
                    }
                }
                // Note: Do NOT clear summary bit here on failure.
                // Summary bit is only cleared when the word transitions to 0 via CAS
                // inside try_allocate_from_word(). This prevents races where another
                // CPU frees a page and sets the summary bit, only to have it cleared
                // immediately by this thread.

                summary_word &= summary_word - 1;
            }
        }

        // Fallback: full detail scan for correctness (summary can be stale)
        for offset in 0..detail_words {
            let word_idx = (hint_idx + offset) % detail_words;

            if let Some(bit_idx) = self.try_allocate_from_word(word_idx) {
                let page_idx = word_idx * BITS_PER_WORD + bit_idx;
                if page_idx < self.total_pages {
                    hint.store(word_idx, Ordering::Relaxed);
                    self.free_count_4k.fetch_sub(1, Ordering::Relaxed);
                    // Update 2MB/1GB hierarchy
                    self.on_page_allocated(page_idx);
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
                // Update summary if word is now empty
                if new_val == 0 {
                    self.clear_summary_bit(word_idx);
                }
                return Some(bit_idx);
            }
            core::hint::spin_loop();
        }
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
    fn on_pages_allocated_batch(&self, first_page_idx: usize, count: usize) {
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
    /// # Arguments
    /// * `max_pages` - Maximum number of pages to allocate
    /// * `hint` - Per-CPU hint for locality
    ///
    /// # Returns
    /// Vector of allocated IOVAs
    pub fn batch_allocate_pages(&self, max_pages: usize, hint: &AtomicUsize) -> alloc::vec::Vec<u64> {
        let mut result = alloc::vec::Vec::with_capacity(max_pages);
        let mut local_buf = [0usize; 64]; // Stack buffer for batch allocation
        let hint_val = hint.load(Ordering::Relaxed);
        let detail_words = self.detail.len();
        
        if detail_words == 0 {
            return result;
        }
        
        let hint_idx = hint_val % detail_words;
        
        // Scan through words starting from hint
        for offset in 0..detail_words {
            if result.len() >= max_pages {
                break;
            }
            
            let word_idx = (hint_idx + offset) % detail_words;
            let remaining = max_pages - result.len();
            let batch_size = remaining.min(64);
            
            let allocated = self.batch_allocate_from_word(word_idx, batch_size, &mut local_buf[..batch_size]);
            if allocated > 0 {
                // Update hint to this word for next allocation
                hint.store(word_idx, Ordering::Relaxed);
                
                // Convert to IOVAs
                for i in 0..allocated {
                    let page_idx = word_idx * BITS_PER_WORD + local_buf[i];
                    if page_idx < self.total_pages {
                        result.push(self.base + (page_idx as u64) * PAGE_SIZE_4K);
                        self.free_count_4k.fetch_sub(1, Ordering::Relaxed);
                    }
                }
            }
        }
        
        result
    }

    /// Free a single 4KB page
    pub fn free_page(&self, iova: u64) -> Result<(), IommuError> {
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
        
        // Set summary bit since this word now has free pages
        self.set_summary_bit(word_idx);
        self.free_count_4k.fetch_add(1, Ordering::Relaxed);
        
        // Update 2MB/1GB hierarchy
        self.on_page_freed(page_idx);
        
        Ok(())
    }

    /// Allocate contiguous pages (for 2MB allocations)
    ///
    /// # 4-a Fix
    /// Now properly updates 2MB/1GB hierarchy after allocation.
    pub fn allocate_contiguous(&self, pages: usize, alignment_pages: usize) -> Option<u64> {
        if pages == 0 || pages > self.total_pages {
            return None;
        }
        let alignment_pages = alignment_pages.max(1);

        // For large allocations, scan the bitmap linearly
        let mut start_page = 0usize;
        
        while start_page + pages <= self.total_pages {
            // Align start
            let aligned_start = (start_page + alignment_pages - 1) / alignment_pages * alignment_pages;
            if aligned_start + pages > self.total_pages {
                break;
            }
            
            // Check if range is free
            if self.is_range_free(aligned_start, pages) {
                // Try to allocate the range
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

    /// Set a bit in the summary bitmap
    fn set_summary_bit(&self, detail_word_idx: usize) {
        let summary_word_idx = detail_word_idx / BITS_PER_WORD;
        let summary_bit = detail_word_idx % BITS_PER_WORD;
        
        if summary_word_idx < self.summary.len() {
            self.summary[summary_word_idx].fetch_or(1u64 << summary_bit, Ordering::Release);
        }
    }

    /// Clear a bit in the summary bitmap
    fn clear_summary_bit(&self, detail_word_idx: usize) {
        let summary_word_idx = detail_word_idx / BITS_PER_WORD;
        let summary_bit = detail_word_idx % BITS_PER_WORD;
        
        if summary_word_idx < self.summary.len() {
            self.summary[summary_word_idx].fetch_and(!(1u64 << summary_bit), Ordering::Release);
        }
    }

    // ========================================================================
    // 2MB/1GB Hierarchical Update Methods
    // ========================================================================

    /// Called when a single 4KB page is allocated.
    /// Updates 2MB used_count and clears 2MB/1GB bitmap bits if needed.
    fn on_page_allocated(&self, page_idx: usize) {
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

        // Transition 0 -> 1: block is no longer fully free
        if old_count == 0 {
            // Clear 2MB bitmap bit
            self.clear_bitmap_2m_bit(block_2m);
            self.free_count_2m.fetch_sub(1, Ordering::Relaxed);

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
    }

    /// Called when a single 4KB page is freed.
    /// Updates 2MB used_count and sets 2MB/1GB bitmap bits if block becomes fully free.
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

        // Transition 1 -> 0: block is now fully free
        if old_count == 1 {
            // Set 2MB bitmap bit
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
    // Statistics
    // ========================================================================

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
}

// ============================================================================
// Fast IOVA Allocator (Combines Magazine + Bitmap)
// ============================================================================

/// Maximum number of CPUs supported for per-CPU magazines
const MAX_CPUS: usize = crate::mm::MAX_CPUS;

/// High-performance IOVA allocator with allocation-free hot path
///
/// This allocator provides:
/// - O(1) allocation for 4KB/2MB pages via per-CPU magazines (IRQ-off guarded)
/// - O(1) amortized allocation via bitmap for magazine refills
/// - Fallback to tree-based allocator for 1GB+ allocations (rare)
pub struct IovaAllocatorFast {
    /// Base IOVA address
    base: u64,
    /// Total size in bytes
    size: u64,
    /// Bitmap allocator for 4KB pages
    bitmap_4k: IovaBitmap,
    /// Per-CPU magazines (indexed by CPU ID)
    magazines: alloc::boxed::Box<[PerCpuMagazine]>,
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
}

impl IovaAllocatorFastStats {
    const fn new() -> Self {
        Self {
            magazine_hits: AtomicU64::new(0),
            magazine_misses: AtomicU64::new(0),
            bitmap_allocs: AtomicU64::new(0),
            magazine_refills: AtomicU64::new(0),
        }
    }
}

impl IovaAllocatorFast {
    /// Create a new fast IOVA allocator
    ///
    /// # Arguments
    /// * `base` - Base IOVA address (must be page-aligned)
    /// * `size` - Total size of IOVA space
    pub fn new(base: u64, size: u64) -> Self {
        let total_pages = (size / PAGE_SIZE_4K) as usize;
        let bitmap_4k = IovaBitmap::new(base, total_pages);
        
        // Allocate per-CPU magazines
        let mut magazines = alloc::vec::Vec::with_capacity(MAX_CPUS);
        for _ in 0..MAX_CPUS {
            magazines.push(PerCpuMagazine::new());
        }
        
        Self {
            base,
            size,
            bitmap_4k,
            magazines: magazines.into_boxed_slice(),
            stats: IovaAllocatorFastStats::new(),
        }
    }

    /// Get current CPU ID via per-CPU data (GsBase)
    #[inline]
    fn current_cpu_id() -> Option<usize> {
        crate::mm::try_current_cpu_id().filter(|&cpu_id| cpu_id < MAX_CPUS)
    }

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

    /// Allocate a 4KB page (O(1) fast path)
    #[inline]
    fn allocate_4k(&self) -> Option<u64> {
        // Fast path: try per-CPU magazine
        if let Some(cpu_id) = Self::current_cpu_id() {
            let magazine = &self.magazines[cpu_id];
            if let Some(mag) = magazine.get(0) {
                let mut mag = mag.lock();
                if let Some(iova) = mag.pop() {
                    self.stats.magazine_hits.fetch_add(1, Ordering::Relaxed);
                    return Some(iova);
                }
            }
            
            self.stats.magazine_misses.fetch_add(1, Ordering::Relaxed);
            
            // Medium path: allocate from bitmap using per-CPU hint
            let hint = &magazine.hint_4k;
            let iova = self.bitmap_4k.allocate_page_with_hint(hint)?;
            self.stats.bitmap_allocs.fetch_add(1, Ordering::Relaxed);
            
            // Try to refill magazine while we're here
            self.try_refill_magazine_4k(cpu_id);
            
            return Some(iova);
        }
        
        self.stats.magazine_misses.fetch_add(1, Ordering::Relaxed);
        
        // Fallback: allocate from bitmap using global hint
        let iova = self.bitmap_4k.allocate_page()?;
        self.stats.bitmap_allocs.fetch_add(1, Ordering::Relaxed);
        
        Some(iova)
    }

    /// Try to refill the 4KB magazine for a CPU
    ///
    /// Uses per-CPU hints and batch allocation for efficiency.
    /// Batch allocation reduces the number of atomic operations by
    /// allocating multiple pages from a single word in one CAS.
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
        
        // Batch allocate pages (more efficient than one-by-one)
        let pages = self.bitmap_4k.batch_allocate_pages(to_refill, hint);
        
        if !pages.is_empty() {
            let mut mag = mag.lock();
            for iova in pages {
                if !mag.push(iova) {
                    // Magazine full, return the page
                    let _ = self.bitmap_4k.free_page(iova);
                    break;
                }
            }
            self.stats.magazine_refills.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Allocate a 2MB super-page (O(1) via hierarchical bitmap)
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
            // Use per-CPU hint for better cache locality
            let hint = &magazine.hint_2m;
            let iova = self.bitmap_4k.allocate_2mb_with_hint(hint)?;
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

    /// Free a 4KB page (O(1))
    fn free_4k(&self, iova: u64) -> Result<(), IommuError> {
        // Fast path: return to per-CPU magazine
        if let Some(cpu_id) = Self::current_cpu_id() {
            let magazine = &self.magazines[cpu_id];
            if let Some(mag) = magazine.get(0) {
                let mut mag = mag.lock();
                if mag.push(iova) {
                    return Ok(());
                }
            }
        }
        
        // Magazine full, return to bitmap
        self.bitmap_4k.free_page(iova)
    }

    /// Free a 2MB super-page (O(1) via hierarchical bitmap)
    fn free_2m(&self, iova: u64) -> Result<(), IommuError> {
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

    /// Free a 1GB huge-page (O(1) via hierarchical bitmap)
    fn free_1g(&self, iova: u64) -> Result<(), IommuError> {
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

    /// Free a range of pages
    fn free_range(&self, iova: u64, size: u64) -> Result<(), IommuError> {
        let pages = ((size + PAGE_SIZE_4K - 1) / PAGE_SIZE_4K) as usize;
        self.bitmap_4k.free_contiguous(iova, pages)
    }

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
}
