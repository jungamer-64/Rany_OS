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
//! - **Hierarchical Bitmap**: 3-level summary for O(1) free slot discovery
//! - **Stable CPU Cache Slots**: Dynamically provisioned by logical CPU ID
//!
//! # Usage
//!
//! ```ignore
//! let allocator = FastBitmapAllocator::new(
//!     0x1000_0000,
//!     1 << 30,
//!     LocalCachePolicy::PerCpu,
//! ); // 1GB
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
//! | allocate_4k | Magazine | O(1), 1 atomic |
//! | allocate_4k | Bitmap fallback | O(log N), few atomics |
//! | free_4k (local) | Magazine | O(1), 1 atomic |
//! | CPU offline | Magazine drain | O(cached pages) |
extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::cpu::{CpuId, CpuSet};
use crate::loader::type_id::{SemVer, TypeHash, TypeIdHash, const_hash};
use crate::mm::bitmap::HugePageBitmap;
use crate::mm::cache::magazine::{DEFAULT_MAGAZINE_CAPACITY, Magazine};
use crate::sync::poison_lock::{IrqPoisonLock, PoisonLock};

// ============================================================================
// Constants
// ============================================================================

// Page size constants - re-exported from types.rs (as u64)
pub use crate::mm::types::{
    PAGE_SIZE_1G as PAGE_SIZE_1G_USIZE, PAGE_SIZE_2M as PAGE_SIZE_2M_USIZE,
    PAGE_SIZE_4K as PAGE_SIZE_4K_USIZE,
};

/// 4KB page size (u64 for address arithmetic)
mod impl_core;
pub const PAGE_SIZE_4K: u64 = PAGE_SIZE_4K_USIZE as u64;
/// 2MB super-page size (u64 for address arithmetic)
pub const PAGE_SIZE_2M: u64 = PAGE_SIZE_2M_USIZE as u64;
/// 1GB huge-page size (u64 for address arithmetic)
pub const PAGE_SIZE_1G: u64 = PAGE_SIZE_1G_USIZE as u64;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalCachePolicy {
    PerCpu,
    SharedBitmap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuCacheProvisionError {
    Allocation,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CpuMagazineDrain {
    pub page_4k: usize,
    pub page_2m: usize,
    pub page_1g: usize,
}

impl CpuMagazineDrain {
    pub const fn total(self) -> usize {
        self.page_4k + self.page_2m + self.page_1g
    }

    pub fn merge(&mut self, other: Self) {
        self.page_4k = self.page_4k.saturating_add(other.page_4k);
        self.page_2m = self.page_2m.saturating_add(other.page_2m);
        self.page_1g = self.page_1g.saturating_add(other.page_1g);
    }
}

// ============================================================================
// PerCpuFastMagazine
// ============================================================================

/// Per-CPU magazine set for fast allocator
#[repr(C, align(128))] // Two cache lines to avoid false sharing
#[derive(Debug)]
pub struct PerCpuFastMagazine {
    /// CPU ID for this magazine set
    pub cpu_id: CpuId,
    /// Magazines indexed by size class (4KB, 2MB, 1GB)
    magazines: [IrqPoisonLock<FastMagazine>; MAGAZINE_SIZE_CLASSES],
}

impl PerCpuFastMagazine {
    /// Create new per-CPU magazine set
    pub const fn new(cpu_id: CpuId) -> Self {
        Self {
            cpu_id,
            magazines: [
                IrqPoisonLock::new(FastMagazine::new()),
                IrqPoisonLock::new(FastMagazine::new()),
                IrqPoisonLock::new(FastMagazine::new()),
            ],
        }
    }

    /// Get magazine for a size class
    #[inline]
    pub fn get_magazine(&self, size_class: usize) -> Option<&IrqPoisonLock<FastMagazine>> {
        self.magazines.get(size_class)
    }
}

impl TypeIdHash for PerCpuFastMagazine {
    fn type_id_hash() -> TypeHash {
        const_hash(b"PerCpuFastMagazine:v3:typed_cpu_id,magazines")
    }

    fn type_name() -> &'static str {
        "PerCpuFastMagazine"
    }

    fn type_version() -> SemVer {
        SemVer::new(3, 0, 0)
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
    /// Stable per-CPU magazines, grown under a topology lock.
    magazines: IrqPoisonLock<Vec<Arc<PerCpuFastMagazine>>>,
    /// Serializes topology growth without holding the magazine registry across
    /// allocations backed by this allocator.
    provision_lock: PoisonLock<()>,
    cache_policy: LocalCachePolicy,
    /// Statistics
    stats: FastAllocatorStats,
}

impl TypeIdHash for FastBitmapAllocator {
    fn type_id_hash() -> TypeHash {
        const_hash(b"FastBitmapAllocator:v2:base,size,bitmap,magazines,provision_lock,cache_policy")
    }

    fn type_name() -> &'static str {
        "FastBitmapAllocator"
    }

    fn type_version() -> SemVer {
        SemVer::new(2, 0, 0)
    }
}
