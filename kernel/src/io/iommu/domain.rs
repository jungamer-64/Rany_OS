// ============================================================================
// kernel/src/io/iommu/domain.rs
// ============================================================================
use super::interface::IommuHardwareContext;
use super::mapping_slab::MappingSlab;
use super::page_table_pool::{
    dec_ref, get_ref_count, inc_ref, register_page_table, unregister_page_table,
};
use super::quarantine::QuarantineQueue;
use super::tables::{
    PT_ENTRIES, PT_LEVELS, PageTableScope, SlPte, phys_to_virt_usize, virt_ptr_to_phys,
};
use super::types::{DmaMapping, IommuDomainType, IommuError, PteFormat};
use crate::io::iommu::amd::tables::AmdPte;
use crate::io::iommu::security::{SecurityEvent, SecurityNotifier};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use bitflags::bitflags;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use crate::sync::{PoisonLock, PoisonLockGuard};
use spin::{Once, RwLock};
mod domain_impl;

// ============================================================================
// Invalidation Request Pattern
// ============================================================================
//
// DESIGN: domain側は InvalidateRequest を生成するだけで、実際の IOTLB invalidation は
// controller側で行う。これにより循環依存を回避し、オブジェクト安全性を確保する。
//
// CONVENTION: controller.process_invalidations() は「最後に wait 1回」を保証。
// 個別の request に wait フラグはない。呼び出し側が wait を忘れる事故を防ぐ。

/// IOTLB Invalidation Request
///
/// domain側で生成され、controller側の `process_invalidations()` で処理される。
/// controller は cap/ecap に応じて最適な descriptor に変換する。
#[derive(Debug, Clone)]
pub struct InvalidateRequest {
    /// Domain ID for this invalidation
    pub domain_id: u16,
    /// Kind of invalidation
    pub kind: InvalidateKind,
    /// Optional flags for advanced features
    pub flags: InvalidateFlags,
}

/// Kind of IOTLB invalidation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidateKind {
    /// Invalidate a specific page range
    Pages {
        /// Start IOVA of the range
        start_iova: u64,
        /// Size in bytes (will be aligned to page size)
        bytes: u64,
    },
    /// Invalidate entire domain
    Domain,
    /// Global invalidation (all domains)
    Global,
    /// Context cache invalidation for device
    Context {
        /// Source ID (bus << 8 | devfn)
        source_id: u16,
    },
    /// Interrupt Entry Cache invalidation
    Iec {
        /// Global (true) or indexed (false with index)
        global: bool,
        /// Index for non-global invalidation
        index: u16,
    },
    /// PASID-based IOTLB invalidation (Scalable Mode)
    PasidIotlb {
        /// Target PASID
        pasid: u32,
    },
    /// PASID cache invalidation (Scalable Mode)
    PasidCache {
        /// Target PASID (None = domain-wide)
        pasid: Option<u32>,
    },
}

bitflags! {
    /// Flags for invalidation request (extensibility for future VT-d features)
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct InvalidateFlags: u32 {
        /// Drain reads before completing
        const DRAIN_READ = 1 << 0;
        /// Drain writes before completing
        const DRAIN_WRITE = 1 << 1;
        /// ATS-aware invalidation (Device-TLB)
        const ATS_AWARE = 1 << 2;
        /// Request is part of a batch (optimization hint)
        const BATCHED = 1 << 3;
        /// Reserved for future use
        const _RESERVED = 0;
    }
}

impl InvalidateRequest {
    /// Create a page invalidation request
    #[inline]
    pub fn pages(domain_id: u16, start_iova: u64, bytes: u64) -> Self {
        Self {
            domain_id,
            kind: InvalidateKind::Pages { start_iova, bytes },
            flags: InvalidateFlags::empty(),
        }
    }

    /// Create a domain invalidation request
    #[inline]
    pub fn domain(domain_id: u16) -> Self {
        Self {
            domain_id,
            kind: InvalidateKind::Domain,
            flags: InvalidateFlags::empty(),
        }
    }

    /// Create a global invalidation request
    #[inline]
    pub fn global() -> Self {
        Self {
            domain_id: 0,
            kind: InvalidateKind::Global,
            flags: InvalidateFlags::empty(),
        }
    }

    /// Create a context cache invalidation request
    #[inline]
    pub fn context(domain_id: u16, source_id: u16) -> Self {
        Self {
            domain_id,
            kind: InvalidateKind::Context { source_id },
            flags: InvalidateFlags::empty(),
        }
    }

    /// Add ATS-aware flag
    #[inline]
    pub fn with_ats(mut self) -> Self {
        self.flags |= InvalidateFlags::ATS_AWARE;
        self
    }

    /// Add drain flags
    #[inline]
    pub fn with_drain(mut self) -> Self {
        self.flags |= InvalidateFlags::DRAIN_READ | InvalidateFlags::DRAIN_WRITE;
        self
    }

    /// Create a PASID-based IOTLB invalidation request (Scalable Mode)
    #[inline]
    pub fn pasid_iotlb(domain_id: u16, pasid: u32) -> Self {
        Self {
            domain_id,
            kind: InvalidateKind::PasidIotlb { pasid },
            flags: InvalidateFlags::empty(),
        }
    }

    /// Create a PASID cache invalidation request (Scalable Mode)
    #[inline]
    pub fn pasid_cache(domain_id: u16, pasid: Option<u32>) -> Self {
        Self {
            domain_id,
            kind: InvalidateKind::PasidCache { pasid },
            flags: InvalidateFlags::empty(),
        }
    }
}

// ============================================================================
// IommuInvalidator Trait
// ============================================================================

/// Trait for processing IOTLB invalidation requests
///
/// This trait decouples `IommuDomain` operations from the hardware-specific
/// invalidation logic in `IommuController`. It enables:
///
/// - **Loose coupling**: Domain doesn't need to know about controller internals
/// - **Testability**: Allows mocking invalidation for unit tests
/// - **Future flexibility**: Async invalidation, batching, etc.
///
/// # Convention
///
/// `process_invalidations()` guarantees a single wait at the end of all
/// invalidation descriptors. Individual requests do not have wait flags.
///
/// # Example
///
/// ```ignore
/// // In domain operations:
/// let request = InvalidateRequest::pages(domain_id, iova, size);
/// invalidator.process_invalidations(&[request])?;
///
/// // Or for batched operations:
/// let requests = vec![
///     InvalidateRequest::pages(domain_id, iova1, size1),
///     InvalidateRequest::pages(domain_id, iova2, size2),
/// ];
/// invalidator.process_invalidations(&requests)?;
/// ```
pub trait IommuInvalidator: Send + Sync {
    /// Process a batch of invalidation requests synchronously
    ///
    /// All requests are processed, then a single wait is performed.
    fn process_invalidations(&self, requests: &[InvalidateRequest]) -> Result<(), IommuError>;

    /// Process a single invalidation request synchronously (convenience)
    fn invalidate(&self, request: InvalidateRequest) -> Result<(), IommuError> {
        self.process_invalidations(&[request])
    }

    /// Process a single invalidation request asynchronously
    ///
    /// Returns when the IOTLB invalidation is done. The default implementation
    /// delegates to the synchronous path.
    fn invalidate_async(&self, request: InvalidateRequest) -> impl Future<Output = Result<(), IommuError>> + Send {
        async move { self.invalidate(request) }
    }
}

/// No-op invalidator for contexts where IOTLB invalidation is unnecessary.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopInvalidator;

impl IommuInvalidator for NoopInvalidator {
    fn process_invalidations(&self, _requests: &[InvalidateRequest]) -> Result<(), IommuError> {
        Ok(())
    }
}

/// IOMMU Domain (address space for devices)
///
/// Each domain owns sharded locks for mapping metadata/page tables, allowing
/// parallel map/unmap operations across domains and across shard boundaries.
///
/// # Performance Considerations: BTreeMap vs Slab Allocator
///
/// The current implementation uses `BTreeMap<u64, DmaMapping>` for tracking mappings.
/// This has the following characteristics:
///
/// | Operation     | Current (BTreeMap) | Target (Slab+Intrusive) |
/// |---------------|--------------------|-----------------------------|
/// | Insert        | O(log n) + alloc   | O(1), allocation-free       |
/// | Remove        | O(log n)           | O(1)                        |
/// | Lookup        | O(log n)           | O(1) via handle             |
/// | Memory        | Heap per entry     | Pre-allocated slab          |
///
/// ## Why BTreeMap is Problematic for High-Throughput I/O
///
/// 1. **Heap Allocation**: Every `map()` allocates a `BTreeMap` node on the heap.
///    For 100Gbps networking with 1500-byte packets, this is ~8M allocations/sec.
///
/// 2. **Pointer Chasing**: Tree traversal causes cache misses, especially under
///    memory pressure where nodes are not cache-local.
///
/// 3. **Lock Contention**: Even with sharding, the BTreeMap lock must be held
///    during the entire insertion/removal operation.
///
/// ## Migration Plan to Intrusive Data Structures
///
/// **Phase 1**: Add `DmaMappingSlot` slab allocator (fixed-size, per-NUMA).
/// ```text
/// struct DmaMappingSlot {
///     iova: u64,
///     phys: u64,
///     size: u64,
///     domain_link: IntrusiveListLink,  // For domain's active list
///     device_link: IntrusiveListLink,  // For device's mapping list
///     flags: DmaMappingFlags,
///     ref_count: AtomicU32,
/// }
/// ```
///
/// **Phase 2**: Replace `DmaHandle`'s IOVA lookup with direct slot pointer.
/// ```text
/// struct DmaHandle<T> {
///     slot: *mut DmaMappingSlot,  // Direct reference, no tree lookup
///     rref: Option<RRef<T>>,
///     // ...
/// }
/// ```
///
/// **Phase 3**: Use intrusive linked lists per domain shard.
/// ```text
/// struct DomainShard {
///     active_mappings: IntrusiveList<DmaMappingSlot>,  // O(1) insert/remove
///     mapping_count: usize,
/// }
/// ```
///
/// ## Interim Optimization: Segregated Free Lists for Common Sizes
///
/// Until the full migration, add fast paths for common allocation sizes:
/// ```text
/// const FAST_PATH_SIZES: [u64; 3] = [4096, 65536, 2097152];  // 4KB, 64KB, 2MB
/// ```
///
/// This reduces tree pressure for the most common DMA buffer sizes.
const DOMAIN_SHARD_COUNT: usize = 64;
const PML4_ENTRIES_PER_SHARD: usize = PT_ENTRIES / DOMAIN_SHARD_COUNT;

// ============================================================================
// DMA Resource Registry (Phase 8: Leak Prevention - Slab-Based)
// ============================================================================

/// Maximum entries in the DMA resource registry slab.
/// Power of 2 for efficient hash computation.
const REGISTRY_SLAB_CAPACITY: usize = 512;

/// Number of hash buckets for registry lookups.
const REGISTRY_HASH_BUCKETS: usize = 1024;

/// Invalid slot index sentinel.
const REGISTRY_INVALID_INDEX: u16 = u16::MAX;

/// Entry in the DMA resource registry tracking an active DmaHandle.
///
/// This is stored in a per-domain registry to enable force-unmap on
/// domain destruction, preventing resource leaks in SAS environments.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct DmaRegistryEntry {
    /// IOVA address of this mapping
    pub iova: u64,
    /// Physical address
    pub phys: u64,
    /// Size in bytes
    pub size: u64,
    /// Whether this entry has been unmapped (tombstone for lazy cleanup)
    pub unmapped: bool,
}

/// Slot in the DMA resource registry slab.
#[derive(Clone, Copy)]
#[repr(C)]
struct RegistrySlot {
    /// Entry data (valid if in_use is true)
    entry: DmaRegistryEntry,
    /// Next slot in free list or hash chain
    next: u16,
    /// Slot is in use
    in_use: bool,
}

impl RegistrySlot {
    const fn empty() -> Self {
        Self {
            entry: DmaRegistryEntry {
                iova: 0,
                phys: 0,
                size: 0,
                unmapped: false,
            },
            next: REGISTRY_INVALID_INDEX,
            in_use: false,
        }
    }
}

/// DMA Resource Registry for tracking active DmaHandles.
///
/// Enables two critical features:
/// 1. **Leak Prevention**: Domain destruction force-unmaps all entries
/// 2. **Resource Accounting**: Track total DMA memory per domain
///
/// # Thread Safety
///
/// The registry is protected by `PoisonLock` with shard-level granularity
/// to reduce contention. Each shard corresponds to a range of IOVAs.
///
/// # Performance (Slab-Based Implementation)
///
/// | Operation     | Complexity       | Heap Alloc |
/// |---------------|------------------|------------|
/// | Insert        | O(1) avg         | None       |
/// | Remove        | O(1) avg         | None       |
/// | Lookup        | O(1) avg         | None       |
/// | Force unmap   | O(n) linear      | None       |
///
/// This eliminates the BTreeMap heap allocation bottleneck for 100Gbps+ I/O.
pub struct DmaResourceRegistry {
    /// Pre-allocated slots (no heap allocation on map/unmap)
    slots: PoisonLock<Box<[RegistrySlot]>>,
    /// Hash buckets for O(1) IOVA lookup
    hash_buckets: PoisonLock<Box<[u16]>>,
    /// Head of free slot list
    free_head: PoisonLock<u16>,
    /// Total active mappings count
    active_count: AtomicU64,
    /// Total mapped bytes
    total_bytes: AtomicU64,
}

impl DmaResourceRegistry {
    /// Create a new empty registry with pre-allocated slab
    pub fn new() -> Self {
        // Initialize slots with free list using Vec to avoid stack overflow
        let mut slots_vec = Vec::with_capacity(REGISTRY_SLAB_CAPACITY);
        for i in 0..REGISTRY_SLAB_CAPACITY {
            let mut slot = RegistrySlot::empty();
            if i < REGISTRY_SLAB_CAPACITY - 1 {
                slot.next = (i + 1) as u16;
            } else {
                slot.next = REGISTRY_INVALID_INDEX;
            }
            slots_vec.push(slot);
        }
        let slots = slots_vec.into_boxed_slice();

        // Initialize hash buckets to empty
        let mut buckets_vec = Vec::with_capacity(REGISTRY_HASH_BUCKETS);
        for _ in 0..REGISTRY_HASH_BUCKETS {
            buckets_vec.push(REGISTRY_INVALID_INDEX);
        }
        let hash_buckets = buckets_vec.into_boxed_slice();

        Self {
            slots: PoisonLock::new(slots),
            hash_buckets: PoisonLock::new(hash_buckets),
            free_head: PoisonLock::new(0),
            active_count: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
        }
    }

    /// Hash function for IOVA to bucket index
    #[inline]
    fn hash_iova(iova: u64) -> usize {
        // Use upper bits for better distribution (IOVA is page-aligned)
        ((iova >> 12) as usize) % REGISTRY_HASH_BUCKETS
    }

    /// Register a new DMA mapping
    ///
    /// Called when a DmaHandle is created for this domain.
    /// O(1) average time, no heap allocation.
    pub fn register(&self, iova: u64, phys: u64, size: u64) -> Result<(), IommuError> {
        // Allocate slot from free list
        let mut free_guard = self.free_head.lock().map_err(|_| {
            log::error!("[IOMMU] DMA registry free_head lock poisoned");
            IommuError::Poisoned
        })?;

        let slot_idx = *free_guard;
        if slot_idx == REGISTRY_INVALID_INDEX {
            log::error!("[IOMMU] DMA registry slab exhausted (cap={})", REGISTRY_SLAB_CAPACITY);
            return Err(IommuError::OutOfMemory);
        }

        let mut slots_guard = self.slots.lock().map_err(|_| {
            log::error!("[IOMMU] DMA registry slots lock poisoned");
            IommuError::Poisoned
        })?;

        // Update free list head
        *free_guard = slots_guard[slot_idx as usize].next;

        // Initialize slot
        let slot = &mut slots_guard[slot_idx as usize];
        slot.entry = DmaRegistryEntry {
            iova,
            phys,
            size,
            unmapped: false,
        };
        slot.in_use = true;
        slot.next = REGISTRY_INVALID_INDEX;

        drop(slots_guard);
        drop(free_guard);

        // Insert into hash chain
        let bucket = Self::hash_iova(iova);
        let mut buckets_guard = self.hash_buckets.lock().map_err(|_| {
            log::error!("[IOMMU] DMA registry hash lock poisoned");
            IommuError::Poisoned
        })?;

        let mut slots_guard = self.slots.lock().map_err(|_| {
            log::error!("[IOMMU] DMA registry slots lock poisoned");
            IommuError::Poisoned
        })?;

        // Prepend to bucket's chain
        slots_guard[slot_idx as usize].next = buckets_guard[bucket];
        buckets_guard[bucket] = slot_idx;

        self.active_count.fetch_add(1, Ordering::Relaxed);
        self.total_bytes.fetch_add(size, Ordering::Relaxed);

        Ok(())
    }

    /// Unregister a DMA mapping
    ///
    /// Called when a DmaHandle is successfully unmapped.
    /// O(1) average time.
    pub fn unregister(&self, iova: u64) -> Result<Option<DmaRegistryEntry>, IommuError> {
        let bucket = Self::hash_iova(iova);

        let mut buckets_guard = self.hash_buckets.lock().map_err(|_| IommuError::Poisoned)?;
        let mut slots_guard = self.slots.lock().map_err(|_| IommuError::Poisoned)?;

        // Search hash chain
        let mut prev_idx = REGISTRY_INVALID_INDEX;
        let mut curr_idx = buckets_guard[bucket];

        while curr_idx != REGISTRY_INVALID_INDEX {
            let slot = &slots_guard[curr_idx as usize];
            if slot.in_use && slot.entry.iova == iova {
                // Found - remove from hash chain
                let entry = slot.entry;
                let next_idx = slot.next;

                if prev_idx == REGISTRY_INVALID_INDEX {
                    buckets_guard[bucket] = next_idx;
                } else {
                    slots_guard[prev_idx as usize].next = next_idx;
                }

                // Clear slot and return to free list
                slots_guard[curr_idx as usize].in_use = false;
                slots_guard[curr_idx as usize].entry = DmaRegistryEntry {
                    iova: 0,
                    phys: 0,
                    size: 0,
                    unmapped: false,
                };

                drop(buckets_guard);
                drop(slots_guard);

                // Return to free list
                let mut free_guard = self.free_head.lock().map_err(|_| IommuError::Poisoned)?;
                let mut slots_guard = self.slots.lock().map_err(|_| IommuError::Poisoned)?;
                slots_guard[curr_idx as usize].next = *free_guard;
                *free_guard = curr_idx;

                self.active_count.fetch_sub(1, Ordering::Relaxed);
                self.total_bytes.fetch_sub(entry.size, Ordering::Relaxed);

                return Ok(Some(entry));
            }
            prev_idx = curr_idx;
            curr_idx = slot.next;
        }

        Ok(None)
    }

    /// Mark an entry as unmapped (lazy tombstone for batch cleanup)
    pub fn mark_unmapped(&self, iova: u64) -> Result<bool, IommuError> {
        let bucket = Self::hash_iova(iova);

        let buckets_guard = self.hash_buckets.lock().map_err(|_| IommuError::Poisoned)?;
        let mut slots_guard = self.slots.lock().map_err(|_| IommuError::Poisoned)?;

        let mut curr_idx = buckets_guard[bucket];
        while curr_idx != REGISTRY_INVALID_INDEX {
            let slot = &mut slots_guard[curr_idx as usize];
            if slot.in_use && slot.entry.iova == iova {
                slot.entry.unmapped = true;
                return Ok(true);
            }
            curr_idx = slot.next;
        }

        Ok(false)
    }

    /// Get count of active (non-unmapped) entries
    #[inline]
    pub fn active_count(&self) -> u64 {
        self.active_count.load(Ordering::Relaxed)
    }

    /// Get total mapped bytes
    #[inline]
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes.load(Ordering::Relaxed)
    }

    /// Drain all entries for force-unmap on domain destruction
    ///
    /// Returns all entries that need to be force-unmapped.
    /// After this call, the registry is empty.
    /// Acquire all three locks needed by drain_all.
    fn lock_all_for_drain(
        &self,
    ) -> Result<(
        crate::sync::PoisonLockGuard<'_, Box<[RegistrySlot]>>,
        crate::sync::PoisonLockGuard<'_, Box<[u16]>>,
        crate::sync::PoisonLockGuard<'_, u16>,
    ), IommuError> {
        let slots_guard = self.slots.lock().map_err(|_| IommuError::Poisoned)?;
        let buckets_guard = self.hash_buckets.lock().map_err(|_| IommuError::Poisoned)?;
        let free_guard = self.free_head.lock().map_err(|_| IommuError::Poisoned)?;
        Ok((slots_guard, buckets_guard, free_guard))
    }

    pub fn drain_all(&self) -> Result<Vec<DmaRegistryEntry>, IommuError> {
        let (mut slots_guard, mut buckets_guard, mut free_guard) = self.lock_all_for_drain()?;

        let mut entries = Vec::new();

        // Scan all slots and collect active entries
        for i in 0..REGISTRY_SLAB_CAPACITY {
            let slot = &mut slots_guard[i];
            if slot.in_use && !slot.entry.unmapped {
                entries.push(slot.entry);
            }
            // Reset slot
            slot.in_use = false;
            slot.entry = DmaRegistryEntry {
                iova: 0,
                phys: 0,
                size: 0,
                unmapped: false,
            };
            slot.next = if i < REGISTRY_SLAB_CAPACITY - 1 {
                (i + 1) as u16
            } else {
                REGISTRY_INVALID_INDEX
            };
        }

        // Reset hash buckets
        for bucket in buckets_guard.iter_mut() {
            *bucket = REGISTRY_INVALID_INDEX;
        }

        // Reset free list
        *free_guard = 0;

        self.active_count.store(0, Ordering::Relaxed);
        self.total_bytes.store(0, Ordering::Relaxed);

        Ok(entries)
    }

    /// Check if an IOVA is registered
    pub fn contains(&self, iova: u64) -> bool {
        let bucket = Self::hash_iova(iova);

        let Ok(buckets_guard) = self.hash_buckets.lock() else {
            return false;
        };
        let Ok(slots_guard) = self.slots.lock() else {
            return false;
        };

        let mut curr_idx = buckets_guard[bucket];
        while curr_idx != REGISTRY_INVALID_INDEX {
            let slot = &slots_guard[curr_idx as usize];
            if slot.in_use && slot.entry.iova == iova {
                return true;
            }
            curr_idx = slot.next;
        }

        false
    }
}

impl Default for DmaResourceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Shard for domain-local mapping metadata.
///
/// Shard of DMA mappings for lock striping.
///
/// # Design
///
/// Uses pre-allocated Slab + intrusive list for O(1) insert/lookup/remove.
/// No heap allocation on hot path (map/unmap).
///
/// See [MappingSlab] documentation for implementation details.
struct DomainShard {
    mappings: MappingSlab,
}

impl DomainShard {
    fn new() -> Self {
        Self {
            mappings: MappingSlab::new(),
        }
    }
}

pub struct IommuDomain {
    /// Domain Type
    pub(crate) domain_type: IommuDomainType,
    /// Domain ID
    pub(crate) id: u16,
    /// Second-level page table root (PML4)
    pub(crate) page_table: *mut SlPte,
    /// Second-level page table root physical address
    pub(crate) page_table_phys: u64,
    /// Mapped regions
    shards: Box<[PoisonLock<DomainShard>]>,
    /// Total mapped size
    mapped_size: AtomicU64,
    /// Optional NUMA node affinity for this domain's data structures
    numa_node: RwLock<Option<usize>>,
    /// Support for 2MB super-pages
    pub(crate) supports_2mb: bool,
    /// Support for 1GB super-pages
    pub(crate) supports_1gb: bool,
    /// Maximum address width (in bits) supported for IOVA/physical addresses
    pub(crate) max_addr_bits: u8,
    /// Quarantine queue for zero-allocation IOTLB invalidation (Phase 5)
    quarantine: Arc<QuarantineQueue>,
    /// Reused buffer for flush invalidations (avoid per-flush allocations)
    flush_requests: PoisonLock<Vec<InvalidateRequest>>,
    /// Phase 6: Page table recycling pool (shared with controller)
    page_table_pool: Arc<super::page_table_pool::PageTablePool>,
    /// PTE format (Intel or AMD)
    pte_format: PteFormat,
    /// Optional security notifier for fatal domain errors
    security_notifier: Once<Arc<dyn SecurityNotifier>>,
    /// Fatal error flag; once set, the domain rejects new map/unmap operations.
    poisoned: AtomicBool,
    /// Per-Domain IOVA Allocator (Phase 7: Scalability Improvement)
    ///
    /// **Now required for all domains.** Each domain uses its own IOVA space
    /// to eliminate lock contention between devices in different domains.
    ///
    /// Uses `IovaAllocatorFast` - a bitmap-based allocator with per-CPU magazine
    /// caching for O(1) allocation/free of common 4KB/2MB pages.
    ///
    /// # Benefits
    ///
    /// - Zero lock contention between domains (per-CPU magazines)
    /// - O(1) allocation/free for 4KB and 2MB pages
    /// - Full 48-bit IOVA space per domain for ASLR
    /// - Per-domain resource accounting
    /// - 32-bit devices don't compete for low addresses
    per_domain_iova: super::IovaAllocatorFast,
    /// DMA Resource Registry (Phase 8: Leak Prevention)
    ///
    /// Tracks all active DmaHandles belonging to this domain.
    /// Enables force-unmap on domain destruction to prevent resource leaks.
    ///
    /// # Usage
    ///
    /// - `register()`: Called when DmaHandle is created
    /// - `unregister()`: Called when DmaHandle is unmapped
    /// - `drain_all()`: Called on domain destruction for force-unmap
    dma_registry: DmaResourceRegistry,
}
