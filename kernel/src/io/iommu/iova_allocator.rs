// ============================================================================
// kernel/src/io/iommu/iova_allocator.rs
// ============================================================================
//! IOVA Allocator (I/O Virtual Address Allocator)
//!
//! Manages I/O Virtual Address space for DMA mappings.
//! Supports 4KB, 2MB, and 1GB granularity allocations.
//! Uses O(log n) tree-based allocation with automatic coalescing.

use super::types::IommuError;
use alloc::collections::{BTreeMap, BTreeSet};

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
    pub const fn size_bytes(self) -> u64 {
        match self {
            IovaGranularity::Page4K => 4 * 1024,
            IovaGranularity::Page2M => 2 * 1024 * 1024,
            IovaGranularity::Page1G => 1024 * 1024 * 1024,
        }
    }

    /// Get the alignment mask
    pub const fn align_mask(self) -> u64 {
        self.size_bytes() - 1
    }
}

/// Standard 4KB page size (public for other IOMMU modules)
pub const PAGE_SIZE_4K: u64 = 4096;

/// IOVA range for tracking allocations
#[derive(Debug, Clone)]
pub struct IovaRange {
    /// Start address
    pub start: u64,
    /// Size in bytes
    pub size: u64,
}

// ============================================================================
// Free Range Tree for O(log n) IOVA Allocation
// ============================================================================

/// Free range tracking structure using BTreeMap for O(log n) operations
///
/// Maintains two indexes:
/// - `by_start`: Maps start_page to contiguous free page count (for coalescing)
/// - `by_size`: Sorted set of (size, start_page) for best-fit allocation
#[derive(Debug, Clone)]
pub struct FreeRangeTree {
    /// Map: start_page -> contiguous free pages
    by_start: BTreeMap<usize, usize>,
    /// Set: (size, start_page) for size-ordered queries
    by_size: BTreeSet<(usize, usize)>,
}

impl FreeRangeTree {
    /// Create a new free range tree with a single initial range
    pub fn new(total_pages: usize) -> Self {
        let mut by_start = BTreeMap::new();
        let mut by_size = BTreeSet::new();

        if total_pages > 0 {
            by_start.insert(0, total_pages);
            by_size.insert((total_pages, 0));
        }

        Self { by_start, by_size }
    }

    /// Find a free range with at least `pages_needed` pages and proper alignment
    /// Returns (start_page, actual_size) or None
    pub fn find_free_range(
        &self,
        pages_needed: usize,
        alignment_pages: usize,
    ) -> Option<(usize, usize)> {
        // Find the smallest range that fits (best-fit)
        for &(size, start) in self.by_size.range((pages_needed, 0)..) {
            // Check alignment
            let aligned_start = (start + alignment_pages - 1) / alignment_pages * alignment_pages;
            let offset = aligned_start - start;

            if size >= pages_needed + offset {
                return Some((aligned_start, size));
            }
        }
        None
    }

    /// Find a free range with at least `pages_needed` pages and proper alignment,
    /// bounded by an exclusive end page.
    pub fn find_free_range_below(
        &self,
        pages_needed: usize,
        alignment_pages: usize,
        max_end_page: usize,
    ) -> Option<(usize, usize)> {
        if max_end_page == 0 {
            return None;
        }

        for &(size, start) in self.by_size.range((pages_needed, 0)..) {
            let aligned_start = (start + alignment_pages - 1) / alignment_pages * alignment_pages;
            let offset = aligned_start - start;
            let end = aligned_start.saturating_add(pages_needed);

            if size >= pages_needed + offset && end <= max_end_page {
                return Some((aligned_start, size));
            }
        }

        None
    }

    /// Allocate a range of pages starting at `start_page` with `count` pages
    /// Splits the containing free range as needed
    pub fn allocate(&mut self, start_page: usize, count: usize) -> bool {
        // Find the range containing this allocation
        // Look for ranges that start at or before start_page
        let containing = self.by_start.range(..=start_page).next_back();

        if let Some((&range_start, &range_size)) = containing {
            let range_end = range_start + range_size;
            let alloc_end = start_page + count;

            // Check if target range is fully within this free range
            if start_page >= range_start && alloc_end <= range_end {
                // Remove the old range
                self.by_start.remove(&range_start);
                self.by_size.remove(&(range_size, range_start));

                // Add prefix range if any
                if start_page > range_start {
                    let prefix_size = start_page - range_start;
                    self.by_start.insert(range_start, prefix_size);
                    self.by_size.insert((prefix_size, range_start));
                }

                // Add suffix range if any
                if alloc_end < range_end {
                    let suffix_size = range_end - alloc_end;
                    self.by_start.insert(alloc_end, suffix_size);
                    self.by_size.insert((suffix_size, alloc_end));
                }

                return true;
            }
        }
        false
    }

    /// Free a range of pages, coalescing with adjacent free ranges
    pub fn free(&mut self, start_page: usize, count: usize) {
        let mut new_start = start_page;
        let mut new_size = count;

        // Check for preceding free range to coalesce
        if let Some((&prev_start, &prev_size)) = self.by_start.range(..start_page).next_back() {
            if prev_start + prev_size == start_page {
                // Coalesce with preceding range
                self.by_start.remove(&prev_start);
                self.by_size.remove(&(prev_size, prev_start));
                new_start = prev_start;
                new_size += prev_size;
            }
        }

        // Check for following free range to coalesce
        let end_page = new_start + new_size;
        if let Some((&next_start, &next_size)) = self.by_start.range(end_page..).next() {
            if next_start == end_page {
                // Coalesce with following range
                self.by_start.remove(&next_start);
                self.by_size.remove(&(next_size, next_start));
                new_size += next_size;
            }
        }

        // Insert the coalesced range
        self.by_start.insert(new_start, new_size);
        self.by_size.insert((new_size, new_start));
    }

    /// Get total free pages
    pub fn total_free(&self) -> usize {
        self.by_start.values().sum()
    }

    /// Get number of free ranges
    pub fn range_count(&self) -> usize {
        self.by_start.len()
    }

    /// Get the largest contiguous free range in pages
    pub fn largest_free(&self) -> usize {
        self.by_size
            .iter()
            .next_back()
            .map(|(size, _)| *size)
            .unwrap_or(0)
    }
}

/// IOVA Allocator using tree-based free range tracking
///
/// Manages I/O Virtual Address space for DMA mappings.
/// Supports 4KB, 2MB, and 1GB granularity allocations.
/// Uses O(log n) tree-based allocation with automatic coalescing.
pub struct IovaAllocator {
    /// Base address of the IOVA space
    base: u64,
    /// Total size of the IOVA space
    size: u64,
    /// Number of 4KB pages managed
    total_pages: usize,
    /// Number of free 4KB pages
    free_pages: usize,
    /// Next allocation hint (for fast sequential allocation)
    next_hint: usize,
    /// Free range tree for O(log n) allocation
    free_ranges: FreeRangeTree,
}

impl IovaAllocator {
    /// 4KB page size
    const PAGE_SIZE_4K: u64 = 4096;

    /// Create a new IOVA allocator
    ///
    /// # Arguments
    /// * `base` - Base address of the IOVA space (should be page-aligned)
    /// * `size` - Total size of the IOVA space
    pub fn new(base: u64, size: u64) -> Self {
        let total_pages = (size / Self::PAGE_SIZE_4K) as usize;

        // Initialize free range tree with entire space as one free range
        let free_ranges = FreeRangeTree::new(total_pages);

        Self {
            base,
            size,
            total_pages,
            free_pages: total_pages,
            next_hint: 0,
            free_ranges,
        }
    }

    /// Get base address
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Get total size
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Get free pages count
    pub fn free_pages(&self) -> usize {
        self.free_pages
    }

    /// Allocate an IOVA range
    ///
    /// Returns the allocated IOVA address, or None if allocation fails.
    /// Uses O(log n) tree-based allocation with best-fit.
    pub fn allocate(&mut self, size: u64, granularity: IovaGranularity) -> Option<u64> {
        let page_size = granularity.size_bytes();
        let pages_needed = ((size + Self::PAGE_SIZE_4K - 1) / Self::PAGE_SIZE_4K) as usize;
        let alignment_pages = (page_size / Self::PAGE_SIZE_4K) as usize;

        // Use tree-based allocation (O(log n))
        let (start_page, _) = self
            .free_ranges
            .find_free_range(pages_needed, alignment_pages)?;

        // Allocate from tree (splits the range)
        self.free_ranges.allocate(start_page, pages_needed);

        self.free_pages = self.free_pages.saturating_sub(pages_needed);

        // Update hint for next allocation
        self.next_hint = start_page + pages_needed;

        Some(self.base + (start_page as u64) * Self::PAGE_SIZE_4K)
    }

    /// Allocate an IOVA range within a maximum address (inclusive).
    pub fn allocate_with_limit(
        &mut self,
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

        let max_end_page = ((available_end - self.base) / Self::PAGE_SIZE_4K) as usize;
        if max_end_page == 0 {
            return None;
        }

        let page_size = granularity.size_bytes();
        let pages_needed = ((size + Self::PAGE_SIZE_4K - 1) / Self::PAGE_SIZE_4K) as usize;
        let alignment_pages = (page_size / Self::PAGE_SIZE_4K) as usize;

        let (start_page, _) = self
            .free_ranges
            .find_free_range_below(pages_needed, alignment_pages, max_end_page)?;

        self.free_ranges.allocate(start_page, pages_needed);
        self.free_pages = self.free_pages.saturating_sub(pages_needed);
        self.next_hint = start_page + pages_needed;

        Some(self.base + (start_page as u64) * Self::PAGE_SIZE_4K)
    }

    /// Allocate a specific IOVA range (for identity mapping)
    pub fn allocate_at(&mut self, iova: u64, size: u64) -> Result<(), IommuError> {
        if iova < self.base || iova + size > self.base + self.size {
            return Err(IommuError::InvalidAddress);
        }

        let start_page = ((iova - self.base) / Self::PAGE_SIZE_4K) as usize;
        let pages_needed = ((size + Self::PAGE_SIZE_4K - 1) / Self::PAGE_SIZE_4K) as usize;

        // Use tree to allocate (will fail if not free)
        if !self.free_ranges.allocate(start_page, pages_needed) {
            return Err(IommuError::AlreadyMapped);
        }

        self.free_pages = self.free_pages.saturating_sub(pages_needed);
        Ok(())
    }

    /// Free an IOVA range with automatic coalescing
    pub fn free(&mut self, iova: u64, size: u64) -> Result<(), IommuError> {
        if iova < self.base || iova + size > self.base + self.size {
            return Err(IommuError::InvalidAddress);
        }

        let start_page = ((iova - self.base) / Self::PAGE_SIZE_4K) as usize;
        let pages_count = ((size + Self::PAGE_SIZE_4K - 1) / Self::PAGE_SIZE_4K) as usize;

        // Free in tree (with automatic coalescing)
        self.free_ranges.free(start_page, pages_count);

        self.free_pages = self.free_pages.saturating_add(pages_count);

        // Update hint to freed range for potential reuse
        if start_page < self.next_hint {
            self.next_hint = start_page;
        }

        Ok(())
    }

    /// Reserve an IOVA range (for RMRR identity mappings)
    pub fn reserve(&mut self, iova: u64, size: u64) -> Result<(), IommuError> {
        if iova < self.base || iova + size > self.base + self.size {
            return Err(IommuError::InvalidAddress);
        }

        let start_page = ((iova - self.base) / Self::PAGE_SIZE_4K) as usize;
        let pages_needed = ((size + Self::PAGE_SIZE_4K - 1) / Self::PAGE_SIZE_4K) as usize;

        // Use tree to allocate (will fail if not free)
        if !self.free_ranges.allocate(start_page, pages_needed) {
            return Err(IommuError::AlreadyMapped);
        }

        self.free_pages = self.free_pages.saturating_sub(pages_needed);
        Ok(())
    }

    /// Allocate a contiguous range with specific size requirements
    pub fn allocate_contiguous(&mut self, size: u64, alignment: u64) -> Option<u64> {
        let pages_needed = ((size + Self::PAGE_SIZE_4K - 1) / Self::PAGE_SIZE_4K) as usize;
        let alignment_pages = ((alignment.max(Self::PAGE_SIZE_4K)) / Self::PAGE_SIZE_4K) as usize;

        // Use tree-based allocation (O(log n))
        let (start_page, _) = self
            .free_ranges
            .find_free_range(pages_needed, alignment_pages)?;

        // Allocate from tree
        self.free_ranges.allocate(start_page, pages_needed);

        self.free_pages = self.free_pages.saturating_sub(pages_needed);

        // Update hint
        self.next_hint = start_page + pages_needed;

        Some(self.base + (start_page as u64) * Self::PAGE_SIZE_4K)
    }

    /// Get basic statistics
    pub fn stats(&self) -> IovaAllocatorStats {
        IovaAllocatorStats {
            total_pages: self.total_pages,
            free_pages: self.free_pages,
            allocated_pages: self.total_pages - self.free_pages,
            base: self.base,
            size: self.size,
        }
    }

    /// Get detailed statistics including fragmentation
    pub fn stats_detailed(&self) -> IovaAllocatorStatsDetailed {
        let free_ranges = self.free_ranges.range_count();
        let fragmentation = if self.free_pages > 0 {
            (free_ranges as f32) / (self.free_pages as f32 / 64.0).max(1.0)
        } else {
            0.0
        };

        IovaAllocatorStatsDetailed {
            total_pages: self.total_pages,
            free_pages: self.free_pages,
            allocated_pages: self.total_pages - self.free_pages,
            base: self.base,
            size: self.size,
            free_ranges,
            fragmentation,
            largest_free_range: self.free_ranges.largest_free(),
        }
    }
}

/// IOVA allocator statistics
#[derive(Debug, Clone)]
pub struct IovaAllocatorStats {
    pub total_pages: usize,
    pub free_pages: usize,
    pub allocated_pages: usize,
    pub base: u64,
    pub size: u64,
}

/// Detailed IOVA allocator statistics
#[derive(Debug, Clone)]
pub struct IovaAllocatorStatsDetailed {
    pub total_pages: usize,
    pub free_pages: usize,
    pub allocated_pages: usize,
    pub base: u64,
    pub size: u64,
    /// Number of distinct free ranges
    pub free_ranges: usize,
    /// Fragmentation ratio (higher = more fragmented)
    pub fragmentation: f32,
    /// Largest contiguous free range in pages
    pub largest_free_range: usize,
}
