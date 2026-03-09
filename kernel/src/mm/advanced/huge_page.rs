// ============================================================================
// src/mm/huge_page.rs - Huge Page Direct Allocation with Direct Compaction
// ============================================================================
#![allow(dead_code)]

use crate::sync::PoisonLock;
use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use x86_64::structures::paging::PhysFrame;

// types.rs から共通定数をインポート
use crate::mm::types::{
    HUGE_PAGE_ORDER_1GB, HUGE_PAGE_ORDER_2MB, HUGE_PAGE_SIZE_1GB, HUGE_PAGE_SIZE_2MB,
};

// ============================================================================
// CPU Feature Detection
// ============================================================================

/// 1GB Huge Page機能が検出されたか
static HUGE_PAGE_1G_AVAILABLE: AtomicBool = AtomicBool::new(false);

/// 1GBページサポートを検出
pub fn detect_1g_page_support() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::__cpuid;
        let result = __cpuid(0x80000001);
        let supported = (result.edx & (1 << 26)) != 0;
        HUGE_PAGE_1G_AVAILABLE.store(supported, Ordering::Release);
        supported
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// 1GBページがサポートされているかチェック
#[inline]
pub fn is_1g_page_supported() -> bool {
    HUGE_PAGE_1G_AVAILABLE.load(Ordering::Acquire)
}

// ============================================================================
// Configuration
// ============================================================================

pub const INITIAL_POOL_SIZE: usize = 64;
pub const MAX_POOL_SIZE: usize = 256;
pub const POOL_LOW_WATERMARK: usize = 16;
pub const MAX_NUMA_NODES: usize = 8;

// ============================================================================
// Huge Page Types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HugePageSize {
    Size2MB = 0,
    Size1GB = 1,
}

impl HugePageSize {
    pub const fn size_bytes(self) -> usize {
        match self {
            Self::Size2MB => HUGE_PAGE_SIZE_2MB,
            Self::Size1GB => HUGE_PAGE_SIZE_1GB,
        }
    }

    pub const fn order(self) -> usize {
        match self {
            Self::Size2MB => HUGE_PAGE_ORDER_2MB,
            Self::Size1GB => HUGE_PAGE_ORDER_1GB,
        }
    }

    pub fn effective_size(self) -> HugePageSize {
        match self {
            Self::Size1GB if !is_1g_page_supported() => Self::Size2MB,
            other => other,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HugePageEntry {
    pub frame: PhysFrame,
    pub size: HugePageSize,
    pub numa_node: u8,
    pub alloc_time: u64,
}

impl HugePageEntry {
    pub fn new(frame: PhysFrame, size: HugePageSize, numa_node: u8) -> Self {
        Self {
            frame,
            size,
            numa_node,
            alloc_time: crate::time::current_time_ns(),
        }
    }
}

// ============================================================================
// Allocation Result
// ============================================================================

#[derive(Debug)]
pub enum HugePageAllocResult {
    Success(HugePageEntry),
    PoolHit(HugePageEntry),
    CompactionSuccess(HugePageEntry),
    Failed(HugePageAllocError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HugePageAllocError {
    OutOfMemory,
    CompactionFailed,
    UnsupportedSize,
    InvalidNumaNode,
    AlignmentError,
}

// ============================================================================
// Huge Page Pool
// ============================================================================

pub struct HugePagePool {
    free_2mb: VecDeque<PhysFrame>,
    free_1gb: VecDeque<PhysFrame>,
    numa_node: u8,
    alloc_success: u64,
    pool_hits: u64,
    compaction_success: u64,
    alloc_failed: u64,
}

impl HugePagePool {
    pub const fn new(numa_node: u8) -> Self {
        Self {
            free_2mb: VecDeque::new(),
            free_1gb: VecDeque::new(),
            numa_node,
            alloc_success: 0,
            pool_hits: 0,
            compaction_success: 0,
            alloc_failed: 0,
        }
    }

    fn try_get_2mb(&mut self) -> Option<PhysFrame> {
        self.free_2mb.pop_front()
    }

    fn try_get_1gb(&mut self) -> Option<PhysFrame> {
        self.free_1gb.pop_front()
    }

    fn put_2mb(&mut self, frame: PhysFrame) {
        if self.free_2mb.len() < MAX_POOL_SIZE {
            self.free_2mb.push_back(frame);
        }
    }

    fn put_1gb(&mut self, frame: PhysFrame) {
        if self.free_1gb.len() < MAX_POOL_SIZE {
            self.free_1gb.push_back(frame);
        }
    }

    pub fn pool_size(&self, size: HugePageSize) -> usize {
        match size {
            HugePageSize::Size2MB => self.free_2mb.len(),
            HugePageSize::Size1GB => self.free_1gb.len(),
        }
    }

    pub fn needs_refill(&self, size: HugePageSize) -> bool {
        self.pool_size(size) <= POOL_LOW_WATERMARK
    }
}

// ============================================================================
// Huge Page Allocator
// ============================================================================

pub struct HugePageAllocator {
    pools: [PoisonLock<HugePagePool>; MAX_NUMA_NODES],
    compaction_in_progress: AtomicU64,
    stats: HugePageGlobalStats,
}

pub struct HugePageGlobalStats {
    pub total_requests: AtomicU64,
    pub buddy_allocations: AtomicU64,
    pub compaction_runs: AtomicU64,
    pub fallback_to_small: AtomicU64,
}

impl HugePageAllocator {
    pub const fn new() -> Self {
        const EMPTY_POOL: PoisonLock<HugePagePool> = PoisonLock::new(HugePagePool::new(0));
        // Note: Individual initialization would be better but array initializers are limited for non-copy types
        // In practice, we'll fix up the node IDs if necessary or just use the index.
        Self {
            pools: [
                PoisonLock::new(HugePagePool::new(0)),
                PoisonLock::new(HugePagePool::new(1)),
                PoisonLock::new(HugePagePool::new(2)),
                PoisonLock::new(HugePagePool::new(3)),
                PoisonLock::new(HugePagePool::new(4)),
                PoisonLock::new(HugePagePool::new(5)),
                PoisonLock::new(HugePagePool::new(6)),
                PoisonLock::new(HugePagePool::new(7)),
            ],
            compaction_in_progress: AtomicU64::new(0),
            stats: HugePageGlobalStats {
                total_requests: AtomicU64::new(0),
                buddy_allocations: AtomicU64::new(0),
                compaction_runs: AtomicU64::new(0),
                fallback_to_small: AtomicU64::new(0),
            },
        }
    }

    pub fn allocate(
        &self,
        size: HugePageSize,
        numa_node: usize,
        allow_compaction: bool,
    ) -> HugePageAllocResult {
        if numa_node >= MAX_NUMA_NODES {
            return HugePageAllocResult::Failed(HugePageAllocError::InvalidNumaNode);
        }

        self.stats.total_requests.fetch_add(1, Ordering::Relaxed);

        {
            let mut pool = self.pools[numa_node]
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let frame_opt = match size {
                HugePageSize::Size2MB => pool.try_get_2mb(),
                HugePageSize::Size1GB => pool.try_get_1gb(),
            };

            if let Some(frame) = frame_opt {
                pool.pool_hits += 1;
                pool.alloc_success += 1;
                let entry = HugePageEntry::new(frame, size, numa_node as u8);
                return HugePageAllocResult::PoolHit(entry);
            }
        }

        if let Some(frame) = self.try_allocate_from_buddy(size, numa_node) {
            self.stats.buddy_allocations.fetch_add(1, Ordering::Relaxed);
            let entry = HugePageEntry::new(frame, size, numa_node as u8);
            return HugePageAllocResult::Success(entry);
        }

        if allow_compaction {
            if let Some(frame) = self.try_allocate_with_compaction(size, numa_node) {
                let entry = HugePageEntry::new(frame, size, numa_node as u8);
                return HugePageAllocResult::CompactionSuccess(entry);
            }
        }

        {
            let mut pool = self.pools[numa_node]
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            pool.alloc_failed += 1;
        }

        HugePageAllocResult::Failed(HugePageAllocError::OutOfMemory)
    }

    fn try_allocate_from_buddy(&self, _size: HugePageSize, _numa_node: usize) -> Option<PhysFrame> {
        None
    }

    fn try_allocate_with_compaction(
        &self,
        size: HugePageSize,
        numa_node: usize,
    ) -> Option<PhysFrame> {
        let node_bit = 1u64 << numa_node;
        let prev = self
            .compaction_in_progress
            .fetch_or(node_bit, Ordering::AcqRel);
        if prev & node_bit != 0 {
            return None;
        }

        self.stats.compaction_runs.fetch_add(1, Ordering::Relaxed);
        let result = self.run_direct_compaction(size, numa_node);
        self.compaction_in_progress
            .fetch_and(!node_bit, Ordering::Release);

        if result {
            self.try_allocate_from_buddy(size, numa_node)
        } else {
            None
        }
    }

    fn run_direct_compaction(&self, _size: HugePageSize, _numa_node: usize) -> bool {
        false
    }

    pub fn free(&self, entry: HugePageEntry) {
        let numa_node = entry.numa_node as usize;
        if numa_node >= MAX_NUMA_NODES {
            return;
        }

        let mut pool = self.pools[numa_node]
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match entry.size {
            HugePageSize::Size2MB => pool.put_2mb(entry.frame),
            HugePageSize::Size1GB => pool.put_1gb(entry.frame),
        }
    }

    pub fn refill_pool(&self, numa_node: usize, size: HugePageSize, count: usize) -> usize {
        if numa_node >= MAX_NUMA_NODES {
            return 0;
        }

        let mut filled = 0;
        for _ in 0..count {
            if let Some(frame) = self.try_allocate_from_buddy(size, numa_node) {
                let mut pool = self.pools[numa_node]
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                match size {
                    HugePageSize::Size2MB => pool.put_2mb(frame),
                    HugePageSize::Size1GB => pool.put_1gb(frame),
                }
                filled += 1;
            } else {
                break;
            }
        }
        filled
    }

    pub fn pool_stats(&self, numa_node: usize) -> Option<HugePagePoolStats> {
        if numa_node >= MAX_NUMA_NODES {
            return None;
        }

        let pool = self.pools[numa_node]
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        Some(HugePagePoolStats {
            free_2mb: pool.free_2mb.len(),
            free_1gb: pool.free_1gb.len(),
            alloc_success: pool.alloc_success,
            pool_hits: pool.pool_hits,
            compaction_success: pool.compaction_success,
            alloc_failed: pool.alloc_failed,
        })
    }
}

#[derive(Debug, Clone)]
pub struct HugePagePoolStats {
    pub free_2mb: usize,
    pub free_1gb: usize,
    pub alloc_success: u64,
    pub pool_hits: u64,
    pub compaction_success: u64,
    pub alloc_failed: u64,
}

pub static HUGE_PAGE_ALLOCATOR: HugePageAllocator = HugePageAllocator::new();

pub fn allocate_huge_page_2mb(numa_node: usize) -> HugePageAllocResult {
    HUGE_PAGE_ALLOCATOR.allocate(HugePageSize::Size2MB, numa_node, true)
}

pub fn allocate_huge_page_1gb(numa_node: usize) -> HugePageAllocResult {
    HUGE_PAGE_ALLOCATOR.allocate(HugePageSize::Size1GB, numa_node, true)
}

pub fn free_huge_page(entry: HugePageEntry) {
    HUGE_PAGE_ALLOCATOR.free(entry);
}

pub fn allocate_huge_page_2mb_fast(numa_node: usize) -> HugePageAllocResult {
    HUGE_PAGE_ALLOCATOR.allocate(HugePageSize::Size2MB, numa_node, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_huge_page_sizes() {
        assert_eq!(HugePageSize::Size2MB.size_bytes(), 2 * 1024 * 1024);
        assert_eq!(HugePageSize::Size1GB.size_bytes(), 1024 * 1024 * 1024);
        assert_eq!(HugePageSize::Size2MB.order(), 9);
        assert_eq!(HugePageSize::Size1GB.order(), 18);
    }

    #[test_case]
    fn test_pool_new() {
        let pool = HugePagePool::new(0);
        assert_eq!(pool.numa_node, 0);
        assert_eq!(pool.pool_size(HugePageSize::Size2MB), 0);
        assert_eq!(pool.pool_size(HugePageSize::Size1GB), 0);
    }

    #[test_case]
    fn test_pool_needs_refill() {
        let pool = HugePagePool::new(0);
        assert!(pool.needs_refill(HugePageSize::Size2MB));
    }
}
