// ============================================================================
// src/mm/exchange_heap.rs - Exchange Heap for Zero-Copy IPC
// 設計書 5.3: 線形型と交換ヒープ（RedLeaf OS参照）
//
// v0.3.0: linked_list_allocator から内蔵Buddy Allocatorへ移行
// v0.4.0: Segregated Free Lists (区分フリーリスト) 導入
//         - O(n) First-Fit から O(1) サイズクラス探索へ
//         - IPCの頻繁な割り当て/解放のボトルネックを解消
// v0.5.0: Per-CPU Caching 導入
//         - ロック競合を削減
//         - IPCホットパスでのスケーラビリティ向上
// v0.6.0: Victim Cache (Work-Stealing) 導入
//         - Per-CPU cache miss時に隣接CPUからスティール
//         - グローバルロックへのフォールバック頻度削減
// ============================================================================
use crate::sync::{IrqMutex, PoisonLock};
use alloc::alloc::{GlobalAlloc, Layout};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// Per-CPU Caching Constants
// ============================================================================

mod stats_and_compat;
pub use stats_and_compat::*;

/// Per-CPU cache capacity (number of cached blocks per size class)
const PER_CPU_CACHE_CAPACITY: usize = 32;

/// Number of size classes to cache per-CPU (small allocations only)
/// Classes 0-5: 8B, 16B, 32B, 64B, 128B, 256B
const CACHED_SIZE_CLASSES: usize = 6;

// ============================================================================
// Per-CPU Exchange Cache
// ============================================================================

/// Per-CPU cached block entry
struct CachedBlock {
    addr: usize,
    size: usize,
}

/// Per-CPU cache for small allocations
#[repr(C, align(128))] // Cache line aligned to avoid false sharing
struct PerCpuExchangeCache {
    /// Cached blocks indexed by size class
    caches: [[Option<CachedBlock>; PER_CPU_CACHE_CAPACITY]; CACHED_SIZE_CLASSES],
    /// Number of cached blocks per class
    counts: [usize; CACHED_SIZE_CLASSES],
    /// Statistics: cache hits
    cache_hits: AtomicU64,
    /// Statistics: cache misses
    cache_misses: AtomicU64,
    /// Statistics: steal attempts
    steal_attempts: AtomicU64,
    /// Statistics: steal successes
    steal_successes: AtomicU64,
}

impl PerCpuExchangeCache {
    const fn new() -> Self {
        const EMPTY_BLOCK: Option<CachedBlock> = None;
        const EMPTY_CACHE: [Option<CachedBlock>; PER_CPU_CACHE_CAPACITY] =
            [EMPTY_BLOCK; PER_CPU_CACHE_CAPACITY];
        Self {
            caches: [EMPTY_CACHE; CACHED_SIZE_CLASSES],
            counts: [0; CACHED_SIZE_CLASSES],
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            steal_attempts: AtomicU64::new(0),
            steal_successes: AtomicU64::new(0),
        }
    }

    /// Try to allocate from cache
    #[inline]
    fn try_alloc(&mut self, size_class: usize) -> Option<(usize, usize)> {
        if size_class >= CACHED_SIZE_CLASSES {
            return None;
        }

        let count = self.counts[size_class];
        if count == 0 {
            self.cache_misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        let idx = count - 1;
        if let Some(block) = self.caches[size_class][idx].take() {
            self.counts[size_class] = idx;
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Some((block.addr, block.size));
        }

        None
    }

    /// Try to cache a freed block
    #[inline]
    fn try_cache(&mut self, addr: usize, size: usize, size_class: usize) -> bool {
        if size_class >= CACHED_SIZE_CLASSES {
            return false;
        }

        let count = self.counts[size_class];
        if count >= PER_CPU_CACHE_CAPACITY {
            return false;
        }

        self.caches[size_class][count] = Some(CachedBlock { addr, size });
        self.counts[size_class] = count + 1;
        true
    }

    /// Try to steal one block from this cache (called by victim)
    ///
    /// Returns Some((addr, size)) if a block was available to steal.
    /// This is called by other CPUs when their local cache is empty.
    #[inline]
    fn try_steal_one(&mut self, size_class: usize) -> Option<(usize, usize)> {
        if size_class >= CACHED_SIZE_CLASSES {
            return None;
        }

        let count = self.counts[size_class];
        // Only steal if victim has more than half capacity (avoid thrashing)
        if count <= PER_CPU_CACHE_CAPACITY / 2 {
            return None;
        }

        let idx = count - 1;
        if let Some(block) = self.caches[size_class][idx].take() {
            self.counts[size_class] = idx;
            return Some((block.addr, block.size));
        }

        None
    }
}

/// CPU cache entries have stable addresses while the registry grows for newly
/// discovered firmware slots.
type ExchangeCacheSnapshot = Arc<[Arc<IrqMutex<PerCpuExchangeCache>>]>;

