// ============================================================================
// kernel/src/mm/fast_allocator.rs - High-Performance Bitmap Allocator
// ============================================================================
//!
//! Generic high-performance bitmap allocator for physical memory and IOVA.
//!
//! # Overview
//!
//! This module provides a fast, scalable bitmap allocator that combines:
//! - **Per-CPU Magazine Caching**: O(1) allocation from local cache
//! - **Single-Writer Arenas**: Non-atomic allocation for owner CPU
//! - **Hierarchical Bitmap**: 3-level summary for O(1) free slot discovery
//! - **Sub-Magazine (Claimed Word)**: 64 allocations per atomic operation
//! - **Arena Sharding**: Reduces cache line contention between CPUs
//!
//! # Usage
//!
//! ```ignore
//! let allocator = FastBitmapAllocator::new(0x1000_0000, 1 << 30); // 1GB
//! 
//! // Allocate 4KB page
//! if let Some(addr) = allocator.allocate_4k() {
//!     // Use addr...
//!     allocator.free_4k(addr);
//! }
//! ```
//!
//! # Performance
//!
//! | Operation | Path | Cost |
//! |-----------|------|------|
//! | allocate_4k | Sub-magazine | O(1), NO atomics |
//! | allocate_4k | Magazine | O(1), 1 atomic |
//! | allocate_4k | Single-writer arena | O(1), NO atomics |
//! | allocate_4k | Bitmap fallback | O(log N), few atomics |
//! | free_4k (local) | Magazine | O(1), 1 atomic |
//! | free_4k (remote) | RemoteFreeRing | O(1), lock-free push |

#![allow(dead_code)]

extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::sync::IrqMutex;
use super::bitmap::HugePageBitmap;
use super::magazine::{Magazine, DEFAULT_MAGAZINE_CAPACITY};
use super::arena::{PerArenaDetail, ArenaOwnership, MAX_WORDS_PER_ARENA};
use super::remote_free::RemoteFreeRing;
use super::frame_magazine::{SubFrameMagazine, LocalFreeWordStack};

// ============================================================================
// Constants
// ============================================================================

/// 4KB page size
pub const PAGE_SIZE_4K: u64 = 4096;
/// 2MB super-page size
pub const PAGE_SIZE_2M: u64 = 2 * 1024 * 1024;
/// 1GB huge-page size
pub const PAGE_SIZE_1G: u64 = 1024 * 1024 * 1024;

/// Bits per u64 word
const BITS_PER_WORD: usize = 64;

/// Pages per 2MB block
const PAGES_PER_2MB_BLOCK: usize = 512;

/// Maximum CPUs supported
pub const MAX_CPUS: usize = crate::mm::MAX_CPUS;

/// Magazine size classes
const MAGAZINE_SIZE_CLASSES: usize = 3; // 4KB, 2MB, 1GB

// ============================================================================
// PageGranularity
// ============================================================================

/// Page size granularity for allocation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageGranularity {
    /// 4KB pages
    Page4K,
    /// 2MB super-pages
    Page2M,
    /// 1GB huge-pages
    Page1G,
}

impl PageGranularity {
    /// Get the size in bytes
    #[inline]
    pub const fn size_bytes(self) -> u64 {
        match self {
            PageGranularity::Page4K => PAGE_SIZE_4K,
            PageGranularity::Page2M => PAGE_SIZE_2M,
            PageGranularity::Page1G => PAGE_SIZE_1G,
        }
    }

    /// Get the alignment mask
    #[inline]
    pub const fn align_mask(self) -> u64 {
        self.size_bytes() - 1
    }

    /// Get the size class index for magazine
    #[inline]
    pub const fn size_class(self) -> usize {
        match self {
            PageGranularity::Page4K => 0,
            PageGranularity::Page2M => 1,
            PageGranularity::Page1G => 2,
        }
    }
}

// ============================================================================
// FastMagazine (IOVA-style magazine with u64 entries)
// ============================================================================

/// Magazine entry type (address)
type FastMagazineEntry = u64;

/// Fast magazine for address caching (not PhysFrame)
pub type FastMagazine = Magazine<FastMagazineEntry, DEFAULT_MAGAZINE_CAPACITY>;

// ============================================================================
// PerCpuFastMagazine
// ============================================================================

/// Per-CPU magazine set for fast allocator
#[repr(C, align(128))] // Two cache lines to avoid false sharing
pub struct PerCpuFastMagazine {
    /// CPU ID for this magazine set
    pub cpu_id: usize,
    /// Magazines indexed by size class (4KB, 2MB, 1GB)
    magazines: [IrqMutex<FastMagazine>; MAGAZINE_SIZE_CLASSES],
    /// Per-CPU hint for 4KB allocation (word index)
    pub hint_4k: AtomicUsize,
    /// Per-CPU hint for 2MB allocation (block index)
    pub hint_2m: AtomicUsize,
    /// Start of this CPU's preferred arena (4KB word index, inclusive)
    pub arena_start_4k: usize,
    /// End of this CPU's preferred arena (4KB word index, exclusive)
    pub arena_end_4k: usize,
    /// Start of this CPU's preferred arena (2MB block index, inclusive)
    pub arena_start_2m: usize,
    /// End of this CPU's preferred arena (2MB block index, exclusive)
    pub arena_end_2m: usize,
    /// Per-CPU free word stack for O(1) allocation
    pub free_word_stack: IrqMutex<LocalFreeWordStack>,
    /// Per-CPU free page counter delta
    pub free_count_delta_4k: AtomicI64,
    /// Remote free ring: receives frees from other CPUs
    pub remote_free_ring: RemoteFreeRing,
    /// Sub-magazine for claimed word optimization
    pub sub_magazine_4k: IrqMutex<SubFrameMagazine>,
    /// Single-writer arena detail
    pub arena_detail: IrqMutex<Option<PerArenaDetail>>,
    /// Single-writer mode enabled flag
    pub single_writer_enabled: AtomicBool,
}

impl PerCpuFastMagazine {
    /// Create new per-CPU magazine set
    pub const fn new() -> Self {
        Self {
            cpu_id: 0,
            magazines: [
                IrqMutex::new(FastMagazine::new()),
                IrqMutex::new(FastMagazine::new()),
                IrqMutex::new(FastMagazine::new()),
            ],
            hint_4k: AtomicUsize::new(0),
            hint_2m: AtomicUsize::new(0),
            arena_start_4k: 0,
            arena_end_4k: usize::MAX,
            arena_start_2m: 0,
            arena_end_2m: usize::MAX,
            free_word_stack: IrqMutex::new(LocalFreeWordStack::new()),
            free_count_delta_4k: AtomicI64::new(0),
            remote_free_ring: RemoteFreeRing::new(),
            sub_magazine_4k: IrqMutex::new(SubFrameMagazine::new()),
            arena_detail: IrqMutex::new(None),
            single_writer_enabled: AtomicBool::new(false),
        }
    }

    /// Configure arena boundaries
    pub fn set_arena(
        &mut self,
        cpu_id: usize,
        start_4k: usize,
        end_4k: usize,
        start_2m: usize,
        end_2m: usize,
    ) {
        self.cpu_id = cpu_id;
        self.arena_start_4k = start_4k;
        self.arena_end_4k = end_4k;
        self.arena_start_2m = start_2m;
        self.arena_end_2m = end_2m;

        // Scatter hint based on cpu_id (golden ratio)
        let arena_size_4k = end_4k.saturating_sub(start_4k);
        let scatter = ((cpu_id as u64).wrapping_mul(0x9E3779B9) as usize) % arena_size_4k.max(1);
        self.hint_4k = AtomicUsize::new(start_4k + scatter);

        let arena_size_2m = end_2m.saturating_sub(start_2m);
        let scatter_2m = ((cpu_id as u64).wrapping_mul(0x9E3779B9) as usize) % arena_size_2m.max(1);
        self.hint_2m = AtomicUsize::new(start_2m + scatter_2m);

        self.remote_free_ring.init();
    }

    /// Get magazine for a size class
    #[inline]
    pub fn get_magazine(&self, size_class: usize) -> Option<&IrqMutex<FastMagazine>> {
        self.magazines.get(size_class)
    }

    /// Check if single-writer mode is enabled
    #[inline]
    pub fn is_single_writer_enabled(&self) -> bool {
        self.single_writer_enabled.load(Ordering::Acquire)
    }

    /// Initialize single-writer arena
    pub fn init_single_writer_arena(&self, global_detail: &[AtomicU64]) {
        let word_start = self.arena_start_4k;
        let word_end = self.arena_end_4k;
        
        if word_end <= word_start {
            return;
        }

        // Collect initial bits for first window
        let num_words = (word_end - word_start).min(MAX_WORDS_PER_ARENA);
        let mut initial_bits = Vec::with_capacity(num_words);
        for i in 0..num_words {
            let global_idx = word_start + i;
            let bits = if global_idx < global_detail.len() {
                global_detail[global_idx].load(Ordering::Acquire)
            } else {
                0
            };
            initial_bits.push(bits);
        }

        let arena = PerArenaDetail::new(
            self.cpu_id,
            word_start,
            word_end,
            self.cpu_id as u16,
            &initial_bits,
        );

        *self.arena_detail.lock() = Some(arena);
        self.single_writer_enabled.store(true, Ordering::Release);
    }
}

impl Default for PerCpuFastMagazine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// FastAllocatorStats
// ============================================================================

/// Statistics for the fast allocator
pub struct FastAllocatorStats {
    /// Magazine hits (fast path)
    pub magazine_hits: AtomicU64,
    /// Magazine misses (fell through to bitmap)
    pub magazine_misses: AtomicU64,
    /// Bitmap allocations
    pub bitmap_allocs: AtomicU64,
    /// Magazine refills
    pub magazine_refills: AtomicU64,
    /// Sub-magazine claims
    pub sub_magazine_claims: AtomicU64,
    /// Single-writer allocations
    pub single_writer_allocs: AtomicU64,
    /// Single-writer frees
    pub single_writer_frees: AtomicU64,
    /// Remote frees drained
    pub remote_frees_drained: AtomicU64,
    /// 4KB allocations from partial 2MB
    pub allocs_from_partial_2m: AtomicU64,
    /// Hugepage pollutions (4KB alloc from fully-free 2MB)
    pub hugepage_pollutions: AtomicU64,
}

impl FastAllocatorStats {
    const fn new() -> Self {
        Self {
            magazine_hits: AtomicU64::new(0),
            magazine_misses: AtomicU64::new(0),
            bitmap_allocs: AtomicU64::new(0),
            magazine_refills: AtomicU64::new(0),
            sub_magazine_claims: AtomicU64::new(0),
            single_writer_allocs: AtomicU64::new(0),
            single_writer_frees: AtomicU64::new(0),
            remote_frees_drained: AtomicU64::new(0),
            allocs_from_partial_2m: AtomicU64::new(0),
            hugepage_pollutions: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// FastBitmapAllocator
// ============================================================================

/// High-performance bitmap allocator
///
/// Combines per-CPU magazines, single-writer arenas, and hierarchical bitmap
/// for extremely fast allocation with minimal contention.
pub struct FastBitmapAllocator {
    /// Base address
    base: u64,
    /// Total size in bytes
    size: u64,
    /// Hierarchical bitmap for 4KB/2MB/1GB tracking
    bitmap: HugePageBitmap,
    /// Per-CPU magazines
    magazines: Box<[PerCpuFastMagazine]>,
    /// Arena ownership tracking
    arena_ownership: ArenaOwnership,
    /// Statistics
    stats: FastAllocatorStats,
}

impl FastBitmapAllocator {
    /// Create a new fast bitmap allocator
    pub fn new(base: u64, size: u64) -> Self {
        let total_pages = (size / PAGE_SIZE_4K) as usize;
        let bitmap = HugePageBitmap::new(total_pages);

        // Calculate arena sizes
        let total_words_4k = (total_pages + BITS_PER_WORD - 1) / BITS_PER_WORD;
        let total_blocks_2m = total_pages / PAGES_PER_2MB_BLOCK;

        let words_per_cpu = (total_words_4k + MAX_CPUS - 1) / MAX_CPUS;
        let blocks_2m_per_cpu = if total_blocks_2m >= MAX_CPUS {
            (total_blocks_2m + MAX_CPUS - 1) / MAX_CPUS
        } else {
            1
        };

        // Create per-CPU magazines
        let mut magazines = Vec::with_capacity(MAX_CPUS);
        for cpu_id in 0..MAX_CPUS {
            let mut mag = PerCpuFastMagazine::new();

            let arena_start_4k = cpu_id * words_per_cpu;
            let arena_end_4k = ((cpu_id + 1) * words_per_cpu).min(total_words_4k);

            let arena_start_2m = cpu_id * blocks_2m_per_cpu;
            let arena_end_2m = ((cpu_id + 1) * blocks_2m_per_cpu).min(total_blocks_2m);

            mag.set_arena(cpu_id, arena_start_4k, arena_end_4k, arena_start_2m, arena_end_2m);
            magazines.push(mag);
        }

        let arena_ownership = ArenaOwnership::new(total_words_4k, MAX_CPUS);

        Self {
            base,
            size,
            bitmap,
            magazines: magazines.into_boxed_slice(),
            arena_ownership,
            stats: FastAllocatorStats::new(),
        }
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

    /// Get current CPU ID
    #[inline]
    fn current_cpu_id() -> Option<usize> {
        crate::mm::per_cpu::try_current_cpu_id().filter(|&cpu_id| cpu_id < MAX_CPUS)
    }

    // ========================================================================
    // Single-Writer Arena Management
    // ========================================================================

    /// Enable single-writer arena mode
    pub fn enable_single_writer_arenas(&self) {
        let global_detail = self.bitmap.detail();

        for cpu_id in 0..MAX_CPUS {
            let magazine = &self.magazines[cpu_id];

            if magazine.arena_end_4k > magazine.arena_start_4k {
                let num_words = magazine.arena_end_4k - magazine.arena_start_4k;

                // Only enable if arena fits or use windowing
                if num_words <= MAX_WORDS_PER_ARENA * 4 {
                    magazine.init_single_writer_arena(global_detail);
                }
            }
        }
    }

    /// Sync single-writer arenas to global bitmap
    pub fn sync_single_writer_arenas(&self) {
        let global_detail = self.bitmap.detail();

        for cpu_id in 0..MAX_CPUS {
            let magazine = &self.magazines[cpu_id];
            if magazine.is_single_writer_enabled() {
                let arena_guard = magazine.arena_detail.lock();
                if let Some(ref arena) = *arena_guard {
                    arena.sync_to_global(global_detail);
                }
            }
        }
    }

    // ========================================================================
    // 4KB Allocation
    // ========================================================================

    /// Allocate a 4KB page
    #[inline]
    pub fn allocate_4k(&self) -> Option<u64> {
        // Fast path: try per-CPU optimizations
        if let Some(cpu_id) = Self::current_cpu_id() {
            let magazine = &self.magazines[cpu_id];

            // === FASTEST: Single-writer arena (NO ATOMICS!) ===
            if magazine.is_single_writer_enabled() {
                let mut arena_guard = magazine.arena_detail.lock();
                if let Some(ref mut arena) = *arena_guard {
                    if !arena.is_frozen() {
                        if let Some(page_idx) = arena.allocate_page() {
                            let addr = self.base + (page_idx as u64) * PAGE_SIZE_4K;
                            self.stats.single_writer_allocs.fetch_add(1, Ordering::Relaxed);
                            return Some(addr);
                        }

                        // Try window reload for large arenas
                        if arena.is_windowed() && arena.has_next_window() {
                            let global_detail = self.bitmap.detail();
                            if arena.reload_next_window(global_detail) {
                                if let Some(page_idx) = arena.allocate_page() {
                                    let addr = self.base + (page_idx as u64) * PAGE_SIZE_4K;
                                    self.stats.single_writer_allocs.fetch_add(1, Ordering::Relaxed);
                                    return Some(addr);
                                }
                            }
                        }
                    }
                }
            }

            // === FAST #0: Sub-magazine (claimed word) ===
            {
                let mut sub_mag = magazine.sub_magazine_4k.lock();
                if sub_mag.has_frames() {
                    if let Some(frame) = sub_mag.allocate() {
                        let addr = frame.start_address().as_u64();
                        self.stats.magazine_hits.fetch_add(1, Ordering::Relaxed);
                        return Some(addr);
                    }
                }
            }

            // === FAST #1: Magazine ===
            if let Some(mag_lock) = magazine.get_magazine(0) {
                let mut mag = mag_lock.lock();
                if let Some(addr) = mag.pop() {
                    self.stats.magazine_hits.fetch_add(1, Ordering::Relaxed);
                    return Some(addr);
                }
            }
        }

        // Slow path: bitmap allocation
        self.allocate_4k_from_bitmap()
    }

    /// Allocate from bitmap (slow path)
    fn allocate_4k_from_bitmap(&self) -> Option<u64> {
        // Try partial 2MB blocks first (hugepage preservation)
        if let Some(page_idx) = self.bitmap.allocate_4k_from_partial() {
            let addr = self.base + (page_idx as u64) * PAGE_SIZE_4K;
            self.stats.bitmap_allocs.fetch_add(1, Ordering::Relaxed);
            self.stats.allocs_from_partial_2m.fetch_add(1, Ordering::Relaxed);
            return Some(addr);
        }

        // Fallback: use base hierarchical bitmap
        if let Some(page_idx) = self.bitmap.base_bitmap().allocate_one() {
            let addr = self.base + (page_idx as u64) * PAGE_SIZE_4K;
            self.stats.bitmap_allocs.fetch_add(1, Ordering::Relaxed);
            self.stats.hugepage_pollutions.fetch_add(1, Ordering::Relaxed);
            // Update 2MB hierarchy
            self.bitmap.on_page_allocated(page_idx);
            return Some(addr);
        }

        self.stats.magazine_misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    // ========================================================================
    // 2MB/1GB Allocation
    // ========================================================================

    /// Allocate a 2MB super-page
    pub fn allocate_2m(&self) -> Option<u64> {
        // Try magazine first
        if let Some(cpu_id) = Self::current_cpu_id() {
            let magazine = &self.magazines[cpu_id];
            if let Some(mag_lock) = magazine.get_magazine(1) {
                let mut mag = mag_lock.lock();
                if let Some(addr) = mag.pop() {
                    self.stats.magazine_hits.fetch_add(1, Ordering::Relaxed);
                    return Some(addr);
                }
            }
        }

        // Bitmap fallback
        if let Some(block_idx) = self.bitmap.allocate_2m() {
            let addr = self.base + (block_idx as u64) * PAGE_SIZE_2M;
            self.stats.bitmap_allocs.fetch_add(1, Ordering::Relaxed);
            return Some(addr);
        }

        None
    }

    /// Allocate a 1GB huge-page
    pub fn allocate_1g(&self) -> Option<u64> {
        if let Some(block_idx) = self.bitmap.allocate_1g() {
            let addr = self.base + (block_idx as u64) * PAGE_SIZE_1G;
            self.stats.bitmap_allocs.fetch_add(1, Ordering::Relaxed);
            return Some(addr);
        }
        None
    }

    // ========================================================================
    // Bounded Allocation
    // ========================================================================

    /// Allocate 4KB page below limit
    pub fn allocate_4k_below(&self, limit: u64) -> Option<u64> {
        if limit >= self.base + self.size {
            return self.allocate_4k();
        }
        if limit <= self.base { return None; }
        
        // Strict limit: bypass magazine
        let limit_idx = ((limit - self.base) / PAGE_SIZE_4K) as usize;
        
        if let Some(idx) = self.bitmap.allocate_4k_below(limit_idx) {
             let addr = self.base + (idx as u64) * PAGE_SIZE_4K;
             self.stats.bitmap_allocs.fetch_add(1, Ordering::Relaxed);
             Some(addr)
        } else {
             None
        }
    }

    /// Allocate 2MB page below limit
    pub fn allocate_2m_below(&self, limit: u64) -> Option<u64> {
        if limit >= self.base + self.size {
            return self.allocate_2m();
        }
        if limit <= self.base { return None; }

        let limit_idx = ((limit - self.base) / PAGE_SIZE_2M) as usize;
        if let Some(idx) = self.bitmap.allocate_2m_below(limit_idx) {
             let addr = self.base + (idx as u64) * PAGE_SIZE_2M;
             self.stats.bitmap_allocs.fetch_add(1, Ordering::Relaxed);
             Some(addr)
        } else {
             None
        }
    }

    /// Allocate 1GB page below limit
    pub fn allocate_1g_below(&self, limit: u64) -> Option<u64> {
         if limit >= self.base + self.size {
            return self.allocate_1g();
         }
         if limit <= self.base { return None; }

         let limit_idx = ((limit - self.base) / PAGE_SIZE_1G) as usize;
         if let Some(idx) = self.bitmap.allocate_1g_below(limit_idx) {
             let addr = self.base + (idx as u64) * PAGE_SIZE_1G;
             self.stats.bitmap_allocs.fetch_add(1, Ordering::Relaxed);
             Some(addr)
         } else {
             None
         }
    }

    // ========================================================================
    // Free Operations
    // ========================================================================

    /// Free a 4KB page
    pub fn free_4k(&self, addr: u64) -> bool {
        if addr < self.base || addr >= self.base + self.size {
            return false;
        }

        let page_idx = ((addr - self.base) / PAGE_SIZE_4K) as usize;

        // Try local magazine first
        if let Some(cpu_id) = Self::current_cpu_id() {
            let magazine = &self.magazines[cpu_id];

            // Check if in single-writer arena
            if magazine.is_single_writer_enabled() {
                let mut arena_guard = magazine.arena_detail.lock();
                if let Some(ref mut arena) = *arena_guard {
                    if arena.in_current_window(page_idx) && !arena.is_frozen() {
                        if arena.free_page(page_idx) {
                            self.stats.single_writer_frees.fetch_add(1, Ordering::Relaxed);
                            return true;
                        }
                    }
                }
            }

            // Try magazine
            if let Some(mag_lock) = magazine.get_magazine(0) {
                let mut mag = mag_lock.lock();
                if !mag.is_full() {
                    if mag.push(addr) {
                        return true;
                    }
                }
            }
        }

        // Fallback: direct bitmap free
        self.bitmap.free_4k(page_idx)
    }

    /// Free a 2MB super-page
    pub fn free_2m(&self, addr: u64) -> bool {
        if addr < self.base || addr >= self.base + self.size {
            return false;
        }

        let block_idx = ((addr - self.base) / PAGE_SIZE_2M) as usize;

        // Try magazine first
        if let Some(cpu_id) = Self::current_cpu_id() {
            let magazine = &self.magazines[cpu_id];
            if let Some(mag_lock) = magazine.get_magazine(1) {
                let mut mag = mag_lock.lock();
                if !mag.is_full() {
                    if mag.push(addr) {
                        return true;
                    }
                }
            }
        }

        self.bitmap.free_2m(block_idx)
    }

    /// Free a 1GB huge-page
    pub fn free_1g(&self, addr: u64) -> bool {
        if addr < self.base || addr >= self.base + self.size {
            return false;
        }

        let block_idx = ((addr - self.base) / PAGE_SIZE_1G) as usize;
        self.bitmap.free_1g(block_idx)
    }

    // ========================================================================
    // Remote Free Draining
    // ========================================================================

    /// Drain remote free ring for current CPU
    pub fn drain_remote_frees(&self) -> usize {
        let Some(cpu_id) = Self::current_cpu_id() else {
            return 0;
        };

        self.drain_remote_frees_for_cpu(cpu_id)
    }

    /// Drain remote free ring for a specific CPU
    fn drain_remote_frees_for_cpu(&self, cpu_id: usize) -> usize {
        let magazine = &self.magazines[cpu_id];
        let mut drained = 0;

        // Drain entries from remote free ring using closure
        let base = self.base;
        let bitmap = &self.bitmap;
        
        drained = magazine.remote_free_ring.drain_with(64, |entry| {
            let page_idx = ((entry.addr - base) / PAGE_SIZE_4K) as usize;
            let _ = bitmap.free_4k(page_idx);
        });

        if drained > 0 {
            self.stats.remote_frees_drained.fetch_add(drained as u64, Ordering::Relaxed);
        }

        drained
    }

    // ========================================================================
    // Statistics
    // ========================================================================

    /// Get free count for 4KB pages
    #[inline]
    pub fn free_count(&self) -> usize {
        self.bitmap.free_count_4k()
    }

    /// Get free count for 2MB blocks
    #[inline]
    pub fn free_count_2m(&self) -> usize {
        self.bitmap.free_count_2m()
    }

    /// Get free count for 1GB blocks
    #[inline]
    pub fn free_count_1g(&self) -> usize {
        self.bitmap.free_count_1g()
    }

    /// Get total pages
    #[inline]
    pub fn total_pages(&self) -> usize {
        self.bitmap.total_pages()
    }

    /// Get statistics
    pub fn stats(&self) -> &FastAllocatorStats {
        &self.stats
    }

    /// Get access to bitmap for advanced operations
    #[inline]
    pub fn bitmap(&self) -> &HugePageBitmap {
        &self.bitmap
    }

    /// Reconfigure arenas for specific CPU list (NUMA-aware)
    pub fn reconfigure_for_cpu_ids(&mut self, cpu_ids: &[usize]) {
        let total_pages = self.bitmap.total_pages();
        let total_words_4k = (total_pages + BITS_PER_WORD - 1) / BITS_PER_WORD;
        let total_blocks_2m = total_pages / PAGES_PER_2MB_BLOCK;

        let num_cpus = cpu_ids.len().max(1);
        let words_per_cpu = (total_words_4k + num_cpus - 1) / num_cpus;
        let blocks_2m_per_cpu = if total_blocks_2m >= num_cpus {
            (total_blocks_2m + num_cpus - 1) / num_cpus
        } else {
            1
        };

        for (idx, &cpu_id) in cpu_ids.iter().enumerate() {
            if cpu_id < MAX_CPUS {
                let arena_start_4k = (idx * words_per_cpu).min(total_words_4k);
                let arena_end_4k = ((idx + 1) * words_per_cpu).min(total_words_4k);

                let arena_start_2m = (idx * blocks_2m_per_cpu).min(total_blocks_2m);
                let arena_end_2m = ((idx + 1) * blocks_2m_per_cpu).min(total_blocks_2m);

                let mag = &mut self.magazines[cpu_id];
                mag.set_arena(cpu_id, arena_start_4k, arena_end_4k, arena_start_2m, arena_end_2m);
                mag.single_writer_enabled.store(false, Ordering::Release);
                *mag.arena_detail.lock() = None;
            }
        }

        self.arena_ownership.reconfigure_for_cpu_list(total_words_4k, cpu_ids);
    }

    // ========================================================================
    // Reserve/Contiguous Allocation (PMM compatibility)
    // ========================================================================

    /// Reserve a range of addresses (mark as allocated)
    ///
    /// Used for marking memory holes, reserved regions, etc.
    pub fn reserve(&self, start: u64, size: u64) -> Result<(), ()> {
        if start < self.base || size == 0 {
            return Err(());
        }

        let end = start.saturating_add(size);
        if end > self.base + self.size {
            return Err(());
        }

        let start_page = ((start - self.base) / PAGE_SIZE_4K) as usize;
        let end_page = ((end - self.base) / PAGE_SIZE_4K) as usize;

        for page_idx in start_page..end_page {
            self.bitmap.base_bitmap().mark_allocated(page_idx);
            self.bitmap.on_page_allocated(page_idx);
        }

        Ok(())
    }

    /// Allocate contiguous pages
    ///
    /// Returns the start address if successful.
    pub fn allocate_contiguous(&self, size: u64, align: u64) -> Option<u64> {
        if size == 0 || align == 0 {
            return None;
        }

        let pages_needed = ((size + PAGE_SIZE_4K - 1) / PAGE_SIZE_4K) as usize;
        let align_pages = ((align + PAGE_SIZE_4K - 1) / PAGE_SIZE_4K) as usize;
        let total_pages = self.bitmap.total_pages();

        // Simple linear scan for contiguous free pages
        let mut start_page = 0;
        while start_page < total_pages {
            // Align start
            if start_page % align_pages != 0 {
                start_page = ((start_page / align_pages) + 1) * align_pages;
                continue;
            }

            if start_page + pages_needed > total_pages {
                break;
            }

            // Check if range is free
            let base_bitmap = self.bitmap.base_bitmap();
            if base_bitmap.is_range_free(start_page, pages_needed) {
                // Allocate all pages
                let mut success = true;
                for i in 0..pages_needed {
                    if !base_bitmap.mark_allocated(start_page + i) {
                        success = false;
                        // Rollback
                        for j in 0..i {
                            base_bitmap.mark_free(start_page + j);
                        }
                        break;
                    }
                    self.bitmap.on_page_allocated(start_page + i);
                }

                if success {
                    let addr = self.base + (start_page as u64) * PAGE_SIZE_4K;
                    self.stats.bitmap_allocs.fetch_add(1, Ordering::Relaxed);
                    return Some(addr);
                }
            }

            start_page += 1;
        }

        None
    }

    /// Free immediately (without quarantine)
    pub fn free_immediate(&self, addr: u64, granularity: PageGranularity) -> Result<(), ()> {
        match granularity {
            PageGranularity::Page4K => {
                if self.free_4k(addr) { Ok(()) } else { Err(()) }
            }
            PageGranularity::Page2M => {
                if self.free_2m(addr) { Ok(()) } else { Err(()) }
            }
            PageGranularity::Page1G => {
                if self.free_1g(addr) { Ok(()) } else { Err(()) }
            }
        }
    }

    /// Free a range of pages immediately
    pub fn free_range_immediate(&self, start: u64, size: u64) -> Result<(), ()> {
        if start < self.base || size == 0 {
            return Err(());
        }

        let end = start.saturating_add(size);
        if end > self.base + self.size {
            return Err(());
        }

        let start_page = ((start - self.base) / PAGE_SIZE_4K) as usize;
        let end_page = ((end - self.base) / PAGE_SIZE_4K) as usize;

        for page_idx in start_page..end_page {
            self.bitmap.free_4k(page_idx);
        }

        Ok(())
    }

    /// Get PMM-compatible stats (free_pages, total_pages)
    pub fn pmm_stats(&self) -> (u64, usize) {
        (self.free_count() as u64, self.total_pages())
    }
}
