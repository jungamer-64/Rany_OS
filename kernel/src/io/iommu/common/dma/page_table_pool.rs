// ============================================================================
// kernel/src/io/iommu/common/dma/page_table_pool.rs - NUMA-Aware Page Table Recycling
// ============================================================================

//!
//! # Page Table Pool
//!
//! NUMA-local recycling pool for IOMMU page tables.
//!
//! ## Design Principles
//!
//! 1. **Acquire-time zeroing** - Pages are zeroed on acquire, not release
//! 2. **Exact node tracking** - the retained PMM owner determines cache placement
//! 3. **No realloc** - `release()` never exceeds capacity
//! 4. **Lock ordering** - Always acquire domain lock BEFORE pool lock
//!
//! ## Performance
//!
//! - Reduces allocation overhead for short-lived page tables
//! - Maintains NUMA locality for better memory access latency
//! - Statistics for tuning (hit/miss/evict)
//!

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::sync::IrqMutex;

use crate::io::iommu::common::tables::{PT_ENTRIES, SlPte};
use crate::io::iommu::types::IommuError;

// ============================================================================
// Page Table Reference Count Registry
// ============================================================================

/// Global registry entry for a page table
#[derive(Debug)]
struct PageTableRegistryEntry {
    ref_count: u16,
    active: Option<PooledPt>,
}

/// Global registry mapping page table physical addresses to their metadata.
/// Metadata and the published owner share one registry entry. Address lookup
/// cannot reconstruct a release capability.
static PAGE_TABLE_REGISTRY: spin::Once<IrqMutex<BTreeMap<u64, PageTableRegistryEntry>>> =
    spin::Once::new();

/// Get or initialize the page table registry
fn page_table_registry() -> &'static IrqMutex<BTreeMap<u64, PageTableRegistryEntry>> {
    PAGE_TABLE_REGISTRY.call_once(|| IrqMutex::new(BTreeMap::new()))
}

/// Register a page table's metadata in the global registry
pub(in crate::io::iommu) fn register_page_table(phys: u64) {
    let mut registry = page_table_registry().lock();
    registry.entry(phys).or_insert(PageTableRegistryEntry {
        ref_count: 0,
        active: None,
    });
    // Drop the registry lock BEFORE calling register_protected_page
    // to avoid nested IrqMutex acquisition which can deadlock.
    drop(registry);

    // Security: Mark the page table as protected from DMA
    crate::io::iommu::runtime::security::register_protected_page(phys);
}

/// Unregister a page table's metadata from the global registry
pub(in crate::io::iommu) fn unregister_page_table(phys: u64) {
    let mut registry = page_table_registry().lock();
    assert!(
        registry
            .get(&phys)
            .is_none_or(|entry| entry.active.is_none()),
        "active table owner must be detached before unregister"
    );
    registry.remove(&phys);
    drop(registry);

    // Security: Unregister from DMA protection
    crate::io::iommu::runtime::security::unregister_protected_page(phys);
}

/// Increment reference count for a page table
/// Returns the new count
pub fn inc_ref(phys: u64) -> u16 {
    let mut registry = page_table_registry().lock();
    if let Some(entry) = registry.get_mut(&phys) {
        entry.ref_count += 1;
        return entry.ref_count;
    }
    0
}

/// Decrement reference count for a page table
/// Returns true if count reached zero (table can be reclaimed)
pub fn dec_ref(phys: u64) -> bool {
    let mut registry = page_table_registry().lock();
    if let Some(entry) = registry.get_mut(&phys) {
        if entry.ref_count > 0 {
            entry.ref_count -= 1;
            return entry.ref_count == 0;
        }
    }
    false
}

/// Get current reference count for a page table
pub fn get_ref_count(phys: u64) -> u16 {
    let registry = page_table_registry().lock();
    registry.get(&phys).map(|e| e.ref_count).unwrap_or(0)
}

// ============================================================================
// PooledPt - Owned page table with NUMA node
// ============================================================================

/// A page table acquired from the pool
///
/// Contains the actual NUMA node where the page was allocated.
/// This prevents cross-node mixing on release.
#[derive(Debug)]
pub struct PooledPt {
    /// Virtual pointer to the page table (512 entries)
    ptr: NonNull<SlPte>,
    /// Physical address of the page table
    phys: u64,
    /// Actual NUMA node where this page was allocated
    node: usize,
    backing: Option<crate::mm::phys::frame_allocator::PhysicalAllocation>,
}

// SAFETY: this non-Clone owner retains a unique unpublished or retired table;
// pointer observation alone never reconstructs or releases its PMM allocation.
unsafe impl Send for PooledPt {}
unsafe impl Sync for PooledPt {}

impl PooledPt {
    /// Observe the table without delegating allocation release authority.
    pub fn ptr(&self) -> NonNull<SlPte> {
        self.ptr
    }
    pub fn phys(&self) -> u64 {
        self.phys
    }
    pub fn node(&self) -> usize {
        self.node
    }
    fn from_backing(backing: crate::mm::phys::frame_allocator::PhysicalAllocation) -> Self {
        let phys = backing.as_u64();
        let node = backing.node().as_usize();
        let pointer =
            crate::mm::virt::mapping::phys_to_virt(backing.start_address()).as_u64() as *mut SlPte;
        // SAFETY: admitted nonzero RAM and retained HHDM cover an aligned 4KiB table.
        let ptr = unsafe { NonNull::new_unchecked(pointer) };
        Self {
            ptr,
            phys,
            node,
            backing: Some(backing),
        }
    }
}

impl Drop for PooledPt {
    fn drop(&mut self) {
        unregister_page_table(self.phys);
        if let Some(backing) = self.backing.take() {
            backing.release();
        }
    }
}

/// Publish the existing owner into the registry; metadata cannot mint ownership.
pub(in crate::io::iommu) fn publish_table(table: PooledPt) {
    let mut registry = page_table_registry().lock();
    let entry = registry
        .get_mut(&table.phys)
        .expect("table was admitted before publication");
    assert!(entry.active.is_none(), "one active owner per table");
    entry.active = Some(table);
}

/// An unlinked table retains RAM and DMA protection until translation completion.
#[derive(Debug)]
pub(in crate::io::iommu) struct QuarantinedPt(core::mem::ManuallyDrop<PooledPt>);
impl QuarantinedPt {
    /// # Safety
    /// Every parent reference is detached under the domain's paging lock. An
    /// allocator admission alone is insufficient to prove hardware retirement.
    pub(in crate::io::iommu) unsafe fn from_unlinked(table: PooledPt) -> Self {
        Self(core::mem::ManuallyDrop::new(table))
    }
    /// # Safety
    /// A domain paging-structure invalidation, including ATS device translation
    /// caches, began after detachment and has completed. No parent/DMA user remains.
    pub(in crate::io::iommu) unsafe fn complete_after_invalidation(self) -> PooledPt {
        core::mem::ManuallyDrop::into_inner(self.0)
    }
}

/// Separate queues preserve the invalidation boundary. Failure keeps the
/// captured cohort intact for retry; later detachments stay queued for a later
/// invalidation and cannot be reclaimed by an earlier completion.
#[derive(Debug, Default)]
pub(in crate::io::iommu) struct TableRetirement {
    queued: Vec<QuarantinedPt>,
    captured: Vec<QuarantinedPt>,
}
impl TableRetirement {
    /// Transfer every detached table into one completion owner's cohort. The
    /// paging lock excludes detachment while ownership leaves this registry.
    pub(in crate::io::iommu) fn take_pending(&mut self) -> DetachedTables {
        DetachedTables {
            queued: core::mem::take(&mut self.queued),
            captured: core::mem::take(&mut self.captured),
        }
    }
    pub(in crate::io::iommu) fn has_pending(&self) -> bool {
        !self.queued.is_empty() || !self.captured.is_empty()
    }
    pub(in crate::io::iommu) fn reserve(&mut self, count: usize) -> Result<(), IommuError> {
        self.queued
            .try_reserve(count)
            .map_err(|_| IommuError::MetadataAllocation)
    }
    pub(in crate::io::iommu) fn push(&mut self, table: QuarantinedPt) {
        assert!(
            self.queued.len() < self.queued.capacity(),
            "retirement admitted before detachment"
        );
        self.queued.push(table);
    }
    /// Caller holds the paging lock so no scope's rollback admission is live.
    pub(in crate::io::iommu) fn capture(&mut self) -> bool {
        if self.captured.is_empty() {
            core::mem::swap(&mut self.queued, &mut self.captured);
        }
        !self.captured.is_empty()
    }
    /// # Safety
    /// The invalidation begun after capture has completed for the owning domain,
    /// including paging-structure caches and ATS device TLBs. No cancellation,
    /// timeout, submission acknowledgement, or older flush is completion proof.
    pub(in crate::io::iommu) unsafe fn take_completed(&mut self) -> Vec<QuarantinedPt> {
        core::mem::take(&mut self.captured)
    }
}

/// Tables detached before one range owner's hardware synchronization begins.
/// A concurrent flush cannot release these owners, or add later detachments.
#[derive(Debug)]
pub(in crate::io::iommu) struct DetachedTables {
    queued: Vec<QuarantinedPt>,
    captured: Vec<QuarantinedPt>,
}
impl DetachedTables {
    pub(in crate::io::iommu) fn is_empty(&self) -> bool {
        self.queued.is_empty() && self.captured.is_empty()
    }
    /// # Safety
    /// The owning domain's paging-structure and ATS invalidation began after
    /// this cohort was detached and has completed, including DMA read/write drain.
    pub(in crate::io::iommu) unsafe fn release(self, pool: &PageTablePool) {
        for table in self.queued.into_iter().chain(self.captured) {
            pool.release(unsafe { table.complete_after_invalidation() });
        }
    }
}

/// Consume the unique active owner once; repeated address observations return None.
/// # Safety
/// The domain owns this table and has removed all parent references under its
/// paging lock. The result must remain quarantined through IOTLB completion.
pub(in crate::io::iommu) unsafe fn take_unlinked_table(phys: u64) -> Option<QuarantinedPt> {
    let table = page_table_registry().lock().get_mut(&phys)?.active.take()?;
    // SAFETY: caller established detachment; this transition does not reuse RAM.
    Some(unsafe { QuarantinedPt::from_unlinked(table) })
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
/// **ALWAYS acquire `IommuDomain` shard lock(s) BEFORE `PageTablePool` lock.**
///
/// This prevents deadlocks when domain operations need page tables.
///
/// # Zero-Allocation Guarantee
///
/// - `release()` never reallocates (capacity checked before push)
/// - All vectors are pre-allocated with `with_capacity(max_per_node)`
#[derive(Debug)]
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

    /// Acquire a zeroed table only on the explicitly requested node.
    /// Without an explicit node, allocation follows the PMM locality policy.
    ///
    /// # Zero Guarantee
    ///
    /// The returned page table is ALWAYS zeroed:
    /// - From pool: zeroed on acquire (before return)
    /// - Fresh allocation: zeroed by allocator
    ///
    /// # Arguments
    /// * `node_hint` - Exact NUMA node, or the current CPU's allocation policy
    pub fn acquire(&self, node_hint: Option<usize>) -> Result<PooledPt, IommuError> {
        let node = node_hint.unwrap_or_else(crate::mm::numa::topology::current_node);
        let pool = self.pools.get(node).ok_or(IommuError::InvalidAddress)?;
        let mut pool = pool.lock();

        if let Some(pt) = pool.pop() {
            // CRITICAL: Zero the page table before returning (security + correctness)
            // Old PTEs from previous domain could leak information or cause faults
            // SAFETY: an unpublished or completed owner exclusively retains this table.
            unsafe {
                core::ptr::write_bytes(pt.ptr.as_ptr(), 0, PT_ENTRIES);
            }
            self.hits.fetch_add(1, Ordering::Relaxed);
            Ok(pt)
        } else {
            drop(pool); // Release lock before allocation
            self.misses.fetch_add(1, Ordering::Relaxed);
            Self::alloc_fresh(node_hint)
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
        let Some(node_pool) = self.pools.get(pt.node) else {
            log::error!(
                "[IOMMU] rejecting page-table cache placement on absent NUMA node {}",
                pt.node
            );
            self.evicts.fetch_add(1, Ordering::Relaxed);
            Self::dealloc(pt);
            return;
        };

        let mut pool = node_pool.lock();

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
    fn alloc_fresh(node: Option<usize>) -> Result<PooledPt, IommuError> {
        let backing = if let Some(node) = node {
            let node = u8::try_from(node).map_err(|_| IommuError::InvalidAddress)?;
            crate::mm::phys::frame_allocator::alloc_contiguous_frames_aligned_on_node(
                crate::mm::types::NumaNodeId::new(node),
                1,
                4096,
            )
        } else {
            crate::mm::phys::frame_allocator::alloc_frame()
        }
        .map_err(|error| match error {
            crate::mm::phys::frame_allocator::FrameAllocError::InvalidNode => {
                IommuError::InvalidAddress
            }
            crate::mm::phys::frame_allocator::FrameAllocError::Uninitialized => {
                IommuError::NotInitialized
            }
            _ => IommuError::OutOfMemory,
        })?;
        let table = PooledPt::from_backing(backing);
        // SAFETY: a new unpublished physical owner exclusively retains this table.
        unsafe { core::ptr::write_bytes(table.ptr.as_ptr(), 0, PT_ENTRIES) };
        register_page_table(table.phys);
        Ok(table)
    }

    fn dealloc(pt: PooledPt) {
        drop(pt);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
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

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn explicit_invalid_node_does_not_fall_back() {
        let pool = PageTablePool::new(1, 4);
        assert_eq!(
            pool.acquire(Some(1)).unwrap_err(),
            IommuError::InvalidAddress
        );
        assert_eq!(pool.stats().misses, 0);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn captured_retirement_does_not_include_newer_unlinks() {
        let pool = PageTablePool::new(1, 4);
        let first = pool.acquire(Some(0)).unwrap();
        let first_phys = first.phys();
        let second = pool.acquire(Some(0)).unwrap();
        let second_phys = second.phys();
        publish_table(first);
        publish_table(second);
        let mut pending = TableRetirement::default();
        pending.reserve(2).unwrap();
        // SAFETY: these fixtures are never published to a hardware parent.
        pending.push(unsafe { take_unlinked_table(first_phys) }.unwrap());
        assert!(unsafe { take_unlinked_table(first_phys) }.is_none());
        assert!(pending.capture());
        pending.reserve(1).unwrap();
        pending.push(unsafe { take_unlinked_table(second_phys) }.unwrap());
        assert_eq!(pool.cached_count(0), 0);
        // A failed flush keeps exactly the original cohort for its retry.
        assert!(pending.capture());
        assert_eq!(pending.captured.len(), 1);
        assert_eq!(pending.queued.len(), 1);
        // SAFETY: the fixture has no hardware users; completion covers the first capture.
        for table in unsafe { pending.take_completed() } {
            pool.release(unsafe { table.complete_after_invalidation() });
        }
        assert_eq!(pool.cached_count(0), 1);
        assert!(pending.has_pending());
        assert!(pending.capture());
        for table in unsafe { pending.take_completed() } {
            pool.release(unsafe { table.complete_after_invalidation() });
        }
        assert_eq!(pool.cached_count(0), 2);
        assert!(!pending.has_pending());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn attached_rollback_waits_for_retirement_and_reuse_is_zeroed() {
        use crate::io::iommu::common::tables::PageTableScope;
        use crate::io::iommu::types::PteFormat;
        let pool = PageTablePool::new(1, 4);
        let pending = crate::sync::PoisonLock::new(TableRetirement::default());
        let mut parent = SlPte::new();
        let phys;
        {
            let mut scope = PageTableScope::new_with_pool(pool.clone(), Some(0), &pending).unwrap();
            phys = scope.phys();
            // SAFETY: the parent remains exclusive on this stack through rollback;
            // the scope owns all writable entries and is never installed in hardware.
            unsafe {
                scope.ptr().write(SlPte::mapping(0x123000, true, true));
                scope.attach_to_parent(&mut parent, 0, PteFormat::Intel, 1);
            }
            assert!(parent.is_present());
        }
        assert!(!parent.is_present());
        assert_eq!(pool.cached_count(0), 0);
        let unrelated = pool.acquire(Some(0)).unwrap();
        assert_ne!(unrelated.phys(), phys);
        let completed = {
            let mut pending = pending.lock().unwrap();
            assert!(pending.capture());
            // SAFETY: this retained stack parent was never reachable by hardware.
            unsafe { pending.take_completed() }
        };
        for table in completed {
            pool.release(unsafe { table.complete_after_invalidation() });
        }
        let reused = pool.acquire(Some(0)).unwrap();
        assert_eq!(reused.phys(), phys);
        for index in 0..PT_ENTRIES {
            // SAFETY: the exclusive owner covers all 512 entries.
            assert!(!unsafe { *reused.ptr().as_ptr().add(index) }.is_present());
        }
    }
}
