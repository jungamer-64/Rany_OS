// ============================================================================
// kernel/src/io/iommu/page_table_pool.rs - NUMA-Aware Page Table Recycling
// ============================================================================
//!
//! # Page Table Pool
//!
//! NUMA-local recycling pool for IOMMU page tables.
//!
//! ## Design Principles
//!
//! 1. **Acquire-time zeroing** - Pages are zeroed on acquire, not release
//! 2. **Exact node tracking** - `PooledPt.node` = actual allocation node
//! 3. **No realloc** - `release()` never exceeds capacity
//! 4. **Lock ordering** - Always acquire domain lock BEFORE pool lock
//!
//! ## Performance
//!
//! - Reduces allocation overhead for short-lived page tables
//! - Maintains NUMA locality for better memory access latency
//! - Statistics for tuning (hit/miss/evict)
//!

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::sync::IrqMutex;

use super::tables::{PT_ENTRIES, SlPte};
use super::types::IommuError;

// ============================================================================
// PooledPt - Owned page table with NUMA node
// ============================================================================

/// A page table acquired from the pool
///
/// Contains the actual NUMA node where the page was allocated.
/// This prevents cross-node mixing on release.
pub struct PooledPt {
    /// Virtual pointer to the page table (512 entries)
    pub ptr: NonNull<SlPte>,
    /// Physical address of the page table
    pub phys: u64,
    /// Actual NUMA node where this page was allocated
    pub node: usize,
    /// Layout for deallocation
    layout: alloc::alloc::Layout,
}

// SAFETY: The pointer is to heap-allocated memory with no aliasing
unsafe impl Send for PooledPt {}
unsafe impl Sync for PooledPt {}

impl PooledPt {
    /// Create a new PooledPt
    ///
    /// Used by PageTableScope::Drop to reconstruct for pool release.
    pub fn new(ptr: NonNull<SlPte>, phys: u64, node: usize) -> Self {
        // Layout for a single page table (4KB, 4KB-aligned)
        let layout =
            alloc::alloc::Layout::from_size_align(PT_ENTRIES * core::mem::size_of::<SlPte>(), 4096)
                .expect("Page table layout should be valid");

        Self {
            ptr,
            phys,
            node,
            layout,
        }
    }
}

// ============================================================================
// PoolStats - Statistics for tuning
// ============================================================================

/// Pool statistics for monitoring and tuning
#[derive(Debug, Clone, Copy)]
pub struct PoolStats {
    /// Cache hits (reused from pool)
    pub hits: u64,
    /// Cache misses (fresh allocation)
    pub misses: u64,
    /// Evictions (pool full, had to dealloc)
    pub evicts: u64,
}

// ============================================================================
// PageTablePool - NUMA-aware recycling pool
// ============================================================================

/// NUMA-aware page table recycling pool
///
/// # Lock Ordering
///
/// **ALWAYS acquire `IommuDomain` lock BEFORE `PageTablePool` lock.**
///
/// This prevents deadlocks when domain operations need page tables.
///
/// # Zero-Allocation Guarantee
///
/// - `release()` never reallocates (capacity checked before push)
/// - All vectors are pre-allocated with `with_capacity(max_per_node)`
pub struct PageTablePool {
    /// Per-NUMA-node pools of recycled page tables
    pools: Vec<IrqMutex<Vec<PooledPt>>>,
    /// Maximum tables to cache per node
    max_per_node: usize,
    /// Statistics
    hits: AtomicU64,
    misses: AtomicU64,
    evicts: AtomicU64,
}

impl PageTablePool {
    /// Create a new page table pool
    ///
    /// # Arguments
    /// * `num_nodes` - Number of NUMA nodes in the system
    /// * `max_per_node` - Maximum page tables to cache per node
    pub fn new(num_nodes: usize, max_per_node: usize) -> Arc<Self> {
        let mut pools = Vec::with_capacity(num_nodes);
        for _ in 0..num_nodes {
            // Pre-allocate to avoid realloc on push
            pools.push(IrqMutex::new(Vec::with_capacity(max_per_node)));
        }

        Arc::new(Self {
            pools,
            max_per_node,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evicts: AtomicU64::new(0),
        })
    }

    /// Acquire a zeroed page table, preferring the given NUMA node
    ///
    /// # Zero Guarantee
    ///
    /// The returned page table is ALWAYS zeroed:
    /// - From pool: zeroed on acquire (before return)
    /// - Fresh allocation: zeroed by allocator
    ///
    /// # Arguments
    /// * `node_hint` - Preferred NUMA node (clamped to valid range)
    pub fn acquire(&self, node_hint: Option<usize>) -> Result<PooledPt, IommuError> {
        let node = node_hint
            .unwrap_or(0)
            .min(self.pools.len().saturating_sub(1));
        let mut pool = self.pools[node].lock();

        if let Some(pt) = pool.pop() {
            // CRITICAL: Zero the page table before returning (security + correctness)
            // Old PTEs from previous domain could leak information or cause faults
            unsafe {
                core::ptr::write_bytes(pt.ptr.as_ptr(), 0, PT_ENTRIES);
            }
            self.hits.fetch_add(1, Ordering::Relaxed);
            Ok(pt)
        } else {
            drop(pool); // Release lock before allocation
            self.misses.fetch_add(1, Ordering::Relaxed);
            Self::alloc_fresh(node)
        }
    }

    /// Release a page table back to the pool
    ///
    /// If the pool is full for this node, the page is deallocated instead.
    ///
    /// # Zero-Allocation Guarantee
    ///
    /// This method NEVER reallocates because:
    /// - Vector capacity is pre-allocated in `new()`
    /// - We check `len() < max_per_node` before push
    pub fn release(&self, pt: PooledPt) {
        let mut pool = self.pools[pt.node].lock();

        // NEVER exceed capacity to avoid realloc
        if pool.len() < self.max_per_node {
            pool.push(pt);
        } else {
            drop(pool); // Release lock before dealloc
            self.evicts.fetch_add(1, Ordering::Relaxed);
            Self::dealloc(pt);
        }
    }

    /// Get current statistics
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evicts: self.evicts.load(Ordering::Relaxed),
        }
    }

    /// Get the number of NUMA nodes
    pub fn num_nodes(&self) -> usize {
        self.pools.len()
    }

    /// Get current cached count for a node
    pub fn cached_count(&self, node: usize) -> usize {
        if node < self.pools.len() {
            self.pools[node].lock().len()
        } else {
            0
        }
    }

    // ========================================================================
    // Private allocation helpers
    // ========================================================================

    /// Allocate a fresh page table on the given NUMA node
    fn alloc_fresh(node: usize) -> Result<PooledPt, IommuError> {
        let layout =
            alloc::alloc::Layout::from_size_align(PT_ENTRIES * core::mem::size_of::<SlPte>(), 4096)
                .map_err(|_| IommuError::HardwareError)?;

        // Allocate zeroed page on the specified NUMA node
        let ptr = crate::mm::numa::allocate_zeroed_on_node(layout, Some(node))
            .ok_or(IommuError::OutOfMemory)?;

        // Get physical address
        let phys = super::tables::virt_ptr_to_phys(ptr.as_ptr())?;

        // Note: The allocator may have fallen back to a different node.
        // In a real NUMA-aware allocator, we would query the actual node.
        // For now, we trust the hint as the actual node.
        // TODO: Query actual allocation node when allocator supports it.
        let actual_node = node;

        Ok(PooledPt::new(ptr.cast(), phys, actual_node))
    }

    /// Deallocate a page table
    fn dealloc(pt: PooledPt) {
        // Use the matching dealloc function for allocate_zeroed_on_node
        crate::mm::numa::deallocate_on_node(pt.ptr.cast(), pt.layout, Some(pt.node));
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_basic() {
        let pool = PageTablePool::new(2, 4);

        // Acquire should work
        let pt = pool.acquire(Some(0)).expect("acquire failed");
        assert!(pt.phys != 0);

        // Release and re-acquire should hit cache
        pool.release(pt);
        let _pt2 = pool.acquire(Some(0)).expect("acquire failed");

        let stats = pool.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1); // First acquire was a miss
    }
}
