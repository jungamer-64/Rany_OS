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
use crate::mm::bitmap::HugePageBitmap;
use crate::mm::cache::magazine::{Magazine, DEFAULT_MAGAZINE_CAPACITY};
use crate::mm::cache::arena::{PerArenaDetail, ArenaOwnership, MAX_WORDS_PER_ARENA};
use crate::mm::remote_free::RemoteFreeRing;
use super::frame_magazine::{SubFrameMagazine, LocalFreeWordStack};

// ============================================================================
// Constants
// ============================================================================

// Page size constants - re-exported from types.rs (as u64)
pub use crate::mm::types::{PAGE_SIZE_4K as PAGE_SIZE_4K_USIZE, PAGE_SIZE_2M as PAGE_SIZE_2M_USIZE, PAGE_SIZE_1G as PAGE_SIZE_1G_USIZE};

/// 4KB page size (u64 for address arithmetic)
mod impl_core;
pub const PAGE_SIZE_4K: u64 = PAGE_SIZE_4K_USIZE as u64;
/// 2MB super-page size (u64 for address arithmetic)
pub const PAGE_SIZE_2M: u64 = PAGE_SIZE_2M_USIZE as u64;
/// 1GB huge-page size (u64 for address arithmetic)
pub const PAGE_SIZE_1G: u64 = PAGE_SIZE_1G_USIZE as u64;

/// Bits per u64 word
const BITS_PER_WORD: usize = 64;

/// Pages per 2MB block
const PAGES_PER_2MB_BLOCK: usize = 512;

/// Maximum CPUs supported
#[cfg(feature = "qemu-test-export")]
pub const MAX_CPUS: usize = 1;
#[cfg(not(feature = "qemu-test-export"))]
pub const MAX_CPUS: usize = crate::per_cpu::MAX_CPUS;

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

    /// From size class index
    #[inline]
    pub const fn from_size_class(idx: u8) -> Self {
        match idx {
            0 => PageGranularity::Page4K,
            1 => PageGranularity::Page2M,
            2 => PageGranularity::Page1G,
            _ => PageGranularity::Page4K,
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
#[derive(Debug)]
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
        crate::io::log::early_print("[FAST_ALLOC] init_single_writer_arena: cpu=");
        crate::io::log::early_print_dec(self.cpu_id as u64);
        crate::io::log::early_print(" num_words=");
        crate::io::log::early_print_dec(num_words as u64);
        crate::io::log::early_print("\n");

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
        crate::io::log::early_print("[FAST_ALLOC] init_single_writer_arena: initial_bits done, len=");
        crate::io::log::early_print_dec(initial_bits.len() as u64);
        crate::io::log::early_print("\n");

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
#[derive(Debug)]
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
#[derive(Debug)]
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
