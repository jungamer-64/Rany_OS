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

unsafe impl Send for IommuDomain {}
unsafe impl Sync for IommuDomain {}

impl IommuDomain {
    /// Create a new domain
    ///
    /// # Arguments
    /// * `id` - Domain ID
    /// * `numa_node` - Optional NUMA node affinity
    /// * `supports_2mb` - Hardware supports 2MB super pages
    /// * `supports_1gb` - Hardware supports 1GB super pages
    /// * `max_addr_bits` - Maximum supported address width (bits)
    /// * `domain_type` - Domain type (Strict, Passthrough, etc.)
    /// * `page_table_pool` - Shared page table pool for recycling
    pub fn new(
        id: u16,
        numa_node: Option<usize>,
        supports_2mb: bool,
        supports_1gb: bool,
        max_addr_bits: u8,
        domain_type: IommuDomainType,
        page_table_pool: Arc<super::page_table_pool::PageTablePool>,
        pte_format: PteFormat,
    ) -> Self {
        // Allocate page table on the preferred NUMA node when possible.
        // For Passthrough, we still allocate it to simplify logic (or we could skip it)
        // But the hardware won't use it if we set TT=Passthrough.
        // Let's allocate it to avoid null pointer checks elsewhere, or make it Option.
        // For now: Allocate it.
        let layout =
            alloc::alloc::Layout::from_size_align(PT_ENTRIES * core::mem::size_of::<SlPte>(), 4096)
                .expect("Invalid layout for page table");

        let page_table = crate::mm::numa::allocate_zeroed_on_node(layout, numa_node)
            .expect("Failed to allocate IOMMU page table")
            .as_ptr() as *mut SlPte;

        let root_phys = virt_ptr_to_phys(page_table as *const u8)
            .expect("Failed to get root page table physical address");
        register_page_table(root_phys);

        debug_assert_eq!(PT_ENTRIES % DOMAIN_SHARD_COUNT, 0);
        debug_assert!(PML4_ENTRIES_PER_SHARD > 0);
        let mut shards = Vec::with_capacity(DOMAIN_SHARD_COUNT);
        for _ in 0..DOMAIN_SHARD_COUNT {
            shards.push(PoisonLock::new(DomainShard::new()));
        }

        let (default_iova_base, default_iova_size) = if cfg!(feature = "qemu-test-export") {
            // Keep qemu migration suites deterministic under their fixed bump allocator.
            (0x1_0000_0000, 0x1000_0000) // 4GB base, 256MB window
        } else {
            (0x1_0000_0000, 0x8_0000_0000) // 4GB base, 32GB window
        };
        let per_domain_iova = super::IovaAllocatorFast::new(default_iova_base, default_iova_size);

        Self {
            id,
            domain_type,
            page_table,
            shards: shards.into_boxed_slice(),
            mapped_size: AtomicU64::new(0),
            numa_node: RwLock::new(numa_node),
            supports_2mb,
            supports_1gb,
            max_addr_bits: max_addr_bits.clamp(1, 64),
            quarantine: QuarantineQueue::new(),
            // Pre-allocate flush buffer to avoid dynamic allocation in critical path.
            // CRITICAL: This capacity must never be exceeded. The quarantine's
            // drain_pending_invalidations() asserts this in debug builds.
            flush_requests: PoisonLock::new(Vec::with_capacity(
                super::quarantine::INVALIDATION_CAPACITY,
            )),
            page_table_pool,
            pte_format,
            security_notifier: Once::new(),
            poisoned: AtomicBool::new(false),
            // Per-domain IOVA allocator: Default 256GB space starting at 4GB
            // Avoids low addresses (reserved for 32-bit legacy devices) and
            // provides ample space for typical workloads.
            // Uses bitmap-based IovaAllocatorFast with O(1) magazine allocation.
            per_domain_iova,
            dma_registry: DmaResourceRegistry::new(),
        }
    }

    /// Create a new domain with per-domain IOVA allocator
    ///
    /// This constructor creates a domain with its own dedicated IOVA space,
    /// eliminating lock contention with other domains.
    ///
    /// # Arguments
    /// * `id` - Domain ID
    /// * `numa_node` - Optional NUMA node affinity
    /// * `supports_2mb` - Hardware supports 2MB super pages
    /// * `supports_1gb` - Hardware supports 1GB super pages
    /// * `max_addr_bits` - Maximum supported address width (bits)
    /// * `domain_type` - Domain type (Strict, Passthrough, etc.)
    /// * `page_table_pool` - Shared page table pool for recycling
    /// * `pte_format` - PTE format (Intel or AMD)
    /// * `iova_base` - Base address for this domain's IOVA space
    /// * `iova_size` - Size of this domain's IOVA space
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Create domain with 512GB IOVA space starting at 4GB
    /// let domain = IommuDomain::new_with_iova(
    ///     domain_id,
    ///     Some(numa_node),
    ///     true, true, 48,
    ///     IommuDomainType::Strict,
    ///     pool.clone(),
    ///     PteFormat::Intel,
    ///     4 * 1024 * 1024 * 1024,       // 4GB base
    ///     512 * 1024 * 1024 * 1024,     // 512GB size
    /// );
    /// ```
    pub fn new_with_iova(
        id: u16,
        numa_node: Option<usize>,
        supports_2mb: bool,
        supports_1gb: bool,
        max_addr_bits: u8,
        domain_type: IommuDomainType,
        page_table_pool: Arc<super::page_table_pool::PageTablePool>,
        pte_format: PteFormat,
        iova_base: u64,
        iova_size: u64,
    ) -> Self {
        let mut domain = Self::new(
            id,
            numa_node,
            supports_2mb,
            supports_1gb,
            max_addr_bits,
            domain_type,
            page_table_pool,
            pte_format,
        );

        // Override with custom IOVA range
        domain.per_domain_iova = super::IovaAllocatorFast::new(iova_base, iova_size);

        log::debug!(
            "[IOMMU] Domain {} initialized with custom IOVA: base=0x{:x}, size=0x{:x}",
            id,
            iova_base,
            iova_size
        );

        domain
    }

    /// Allocate IOVA from this domain's allocator.
    ///
    /// Uses IovaAllocatorFast with O(1) per-CPU magazine allocation.
    /// All domains have their own IOVA allocator, eliminating lock contention.
    #[inline]
    pub fn allocate_iova(&self, size: u64) -> Result<u64, super::types::IommuError> {
        use super::IovaGranularity;
        
        // IovaAllocatorFast is internally lock-free for common paths
        self.per_domain_iova
            .allocate(size, IovaGranularity::Page4K)
            .ok_or(super::types::IommuError::OutOfIova)
    }

    /// Free IOVA back to this domain's allocator.
    ///
    /// Uses IovaAllocatorFast with O(1) per-CPU magazine deallocation.
    #[inline]
    pub fn free_iova(&self, iova: u64, size: u64) -> Result<(), super::types::IommuError> {
        // IovaAllocatorFast is internally lock-free for common paths
        self.per_domain_iova.free(iova, size)
    }

    /// Check if this domain has a per-domain IOVA allocator.
    /// Always returns true now that per-domain IOVA is mandatory.
    #[inline]
    pub fn has_per_domain_iova(&self) -> bool {
        true
    }

    // ========================================================================
    // Phase 8: DMA Resource Registry (Leak Prevention)
    // ========================================================================

    /// Register a DMA mapping in this domain's resource registry
    ///
    /// Called when a DmaHandle is created for this domain.
    pub fn register_dma_mapping(&self, iova: u64, phys: u64, size: u64) -> Result<(), IommuError> {
        self.dma_registry.register(iova, phys, size)
    }

    /// Unregister a DMA mapping from this domain's resource registry
    ///
    /// Called when a DmaHandle is successfully unmapped.
    pub fn unregister_dma_mapping(&self, iova: u64) -> Result<Option<DmaRegistryEntry>, IommuError> {
        self.dma_registry.unregister(iova)
    }

    /// Get the count of active DMA mappings in this domain
    #[inline]
    pub fn active_dma_count(&self) -> u64 {
        self.dma_registry.active_count()
    }

    /// Get the total bytes of active DMA mappings in this domain
    #[inline]
    pub fn active_dma_bytes(&self) -> u64 {
        self.dma_registry.total_bytes()
    }

    /// Force unmap all active DMA mappings
    ///
    /// This is called during domain destruction to prevent resource leaks.
    /// Returns the list of entries that were force-unmapped.
    ///
    /// # Warning
    ///
    /// This is a destructive operation that invalidates all DmaHandles
    /// belonging to this domain. Only call during domain teardown.
    pub fn force_unmap_all_dma(&self) -> Result<Vec<DmaRegistryEntry>, IommuError> {
        let entries = self.dma_registry.drain_all()?;

        if !entries.is_empty() {
            log::warn!(
                "[IOMMU] Domain {}: Force-unmapping {} leaked DMA mappings ({} bytes)",
                self.id,
                entries.len(),
                entries.iter().map(|e| e.size).sum::<u64>()
            );
        }

        Ok(entries)
    }

    /// Check if a specific IOVA is registered in this domain
    pub fn is_dma_registered(&self, iova: u64) -> bool {
        self.dma_registry.contains(iova)
    }

    /// Get domain ID
    pub fn id(&self) -> u16 {
        self.id
    }

    /// Get domain type
    pub fn domain_type(&self) -> IommuDomainType {
        self.domain_type
    }

    /// Get page table physical address
    pub fn page_table_addr(&self) -> u64 {
        self.page_table as u64
    }

    /// Get optional NUMA node affinity for this domain
    pub fn numa_node(&self) -> Option<usize> {
        *self.numa_node.read()
    }

    /// Set domain NUMA affinity hint
    pub fn set_numa_node(&self, numa_node: Option<usize>) {
        *self.numa_node.write() = numa_node;
    }

    /// Attach a security notifier for fatal domain errors (best-effort, one-time).
    pub(crate) fn set_security_notifier(&self, notifier: Arc<dyn SecurityNotifier>) -> bool {
        let mut set = false;
        self.security_notifier.call_once(|| {
            set = true;
            notifier
        });
        set
    }

    fn notify_security(&self, event: SecurityEvent) {
        if let Some(notifier) = self.security_notifier.get() {
            notifier.notify(event);
        }
    }

    // ========================================================================
    // Phase 5: Quarantine Queue Support
    // ========================================================================

    /// Get the quarantine queue for zero-allocation IOTLB invalidation
    pub fn quarantine_queue(&self) -> Arc<QuarantineQueue> {
        self.quarantine.clone()
    }

    /// Clear page table mapping only (without freeing IOVA)
    ///
    /// Used by `try_unmap_lazy()` to clear PTEs before IOTLB invalidation.
    /// IOVA will be freed later when the invalidation batch completes.
    ///
    /// # Safety
    /// The caller must ensure the IOVA range will be freed after IOTLB invalidation.
    /// Verify domain is not poisoned, look up the mapping, and lock shards.
    fn verify_and_lock_for_clear(
        &self,
        iova: u64,
        size: u64,
    ) -> Result<(DmaMapping, Vec<crate::sync::PoisonLockGuard<'_, DomainShard>>), IommuError> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(IommuError::Poisoned);
        }
        let (start_shard, end_shard) = self.shard_range(iova, size)?;
        let guards = self.lock_shards(start_shard, end_shard)?;
        let mapping = guards[0]
            .mappings
            .lookup(iova)
            .cloned()
            .ok_or(IommuError::NotMapped)?;
        if mapping.size != size {
            return Err(IommuError::NotMapped);
        }
        Ok((mapping, guards))
    }

    pub fn clear_mapping_only(&self, iova: u64, size: u64) -> Result<(), IommuError> {
        let (_mapping, mut guards) = self.verify_and_lock_for_clear(iova, size)?;

        for guard in guards.iter_mut() {
            guard.mappings.remove(iova);
        }

        if self.domain_type != IommuDomainType::Passthrough {
            self.unmap_range(iova, size)?;
        }

        self.mapped_size.fetch_sub(size, Ordering::Relaxed);

        Ok(())
    }

    /// Flush pending IOTLB invalidations and reap completed quarantine entries
    ///
    /// This method:
    /// 1. Drains pending invalidation requests from the quarantine queue
    /// 2. Processes them through the IOMMU invalidator
    /// 3. Increments the completed batch ID
    /// 4. Reaps completed entries (drops abandoned, wakes waiters)
    /// 5. Frees IOVAs for completed entries
    ///
    /// Call this periodically or when the quarantine queue is full.
    ///
    /// # Context
    ///
    /// Must be called from thread/executor context. This path allocates and
    /// drops RRef raw parts via the quarantine reap.
    pub fn flush<I: IommuInvalidator>(
        &self,
        invalidator: &I,
        context: &dyn IommuHardwareContext,
    ) -> Result<(), IommuError> {
        // Drain pending invalidations (Round 9: returns DrainResult)
        let mut requests = self
            .flush_requests
            .lock()
            .map_err(|_| IommuError::Poisoned)?;
        let drained_batch = match self.quarantine.drain_pending_invalidations(&mut requests) {
            super::quarantine::DrainResult::NoWork { .. } => return Ok(()),
            super::quarantine::DrainResult::NotReady { batch: _ } => {
                // Round 9 Safety: Reserved slots pending.
                // We MUST NOT issue invalidations or reap, as that would
                // advance the batch prematurely or leave valid PTEs behind.
                // We can optionally log this or return a special error if needed,
                // but for now we just skip the flush.
                return Ok(());
            }
            super::quarantine::DrainResult::Drained { batch } => batch,
            super::quarantine::DrainResult::Poisoned { .. } => return Err(IommuError::Poisoned),
        };

        // Skip if nothing to flush (double check, though NoWork covers this)
        if requests.is_empty() {
            return Ok(());
        }

        // Process all invalidation requests in a single batch
        if let Err(err) = invalidator.process_invalidations(requests.as_slice()) {
            return Err(err);
        }
        requests.clear();

        // Reap and process completed entries for this batch
        self.quarantine.reap_completed(drained_batch, context);

        Ok(())
    }

    fn within_addr_width(&self, addr: u64, size: u64) -> bool {
        if self.max_addr_bits >= 64 {
            return true;
        }

        let limit = 1u128 << self.max_addr_bits;
        let end = match addr.checked_add(size) {
            Some(end) => end,
            None => return false,
        };

        (addr as u128) < limit && (end as u128) <= limit
    }

    fn shard_for_iova(iova: u64) -> usize {
        let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
        pml4_idx / PML4_ENTRIES_PER_SHARD
    }

    fn shard_range(&self, iova: u64, size: u64) -> Result<(usize, usize), IommuError> {
        if size == 0 {
            return Err(IommuError::InvalidAlignment);
        }
        let end = iova.checked_add(size).ok_or(IommuError::InvalidAddress)?;
        let last = end.saturating_sub(1);
        let start = Self::shard_for_iova(iova);
        let end = Self::shard_for_iova(last);
        Ok((start, end))
    }

    fn lock_shards(
        &self,
        start: usize,
        end: usize,
    ) -> Result<Vec<PoisonLockGuard<'_, DomainShard>>, IommuError> {
        let mut guards = Vec::with_capacity(end.saturating_sub(start) + 1);
        for idx in start..=end {
            let guard = self.shards[idx].lock().map_err(|_| IommuError::Poisoned)?;
            guards.push(guard);
        }
        Ok(guards)
    }

    /// Check if a new mapping overlaps with existing mappings.
    ///
    /// Uses `MappingSlab::overlaps()` for O(n) scan through active mappings.
    /// This is acceptable because:
    /// - Typical domain has few concurrent mappings (< 100)
    /// - Called only during map() validation, not on hot path
    fn mapping_overlaps(mappings: &MappingSlab, iova: u64, size: u64) -> bool {
        mappings.overlaps(iova, size)
    }

    /// Validate alignment, address width, and poison state for a map operation.
    fn validate_map_args(&self, iova: u64, phys: u64, size: u64) -> Result<(), IommuError> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(IommuError::Poisoned);
        }

        if iova & 0xFFF != 0 || phys & 0xFFF != 0 || size & 0xFFF != 0 {
            return Err(IommuError::InvalidAlignment);
        }

        if !self.within_addr_width(iova, size) || !self.within_addr_width(phys, size) {
            return Err(IommuError::InvalidAddress);
        }

        Ok(())
    }

    /// Check that no existing mapping overlaps the given range across all shards.
    fn check_no_overlap(
        guards: &[PoisonLockGuard<'_, DomainShard>],
        iova: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        for guard in guards.iter() {
            if Self::mapping_overlaps(&guard.mappings, iova, size) {
                return Err(IommuError::AlreadyMapped);
            }
        }
        Ok(())
    }

    /// Check whether a 1GB huge page can be used for the current mapping position.
    fn can_use_1gb_page(&self, iova: u64, phys: u64, remaining: u64) -> bool {
        const SIZE_1GB: u64 = 1024 * 1024 * 1024;
        self.supports_1gb
            && remaining >= SIZE_1GB
            && iova % SIZE_1GB == 0
            && phys % SIZE_1GB == 0
            && (phys as u64 & 0x3FFF_FFFF) == 0
    }

    /// Check whether a 2MB huge page can be used for the current mapping position.
    fn can_use_2mb_page(&self, iova: u64, phys: u64, remaining: u64) -> bool {
        const SIZE_2MB: u64 = 2 * 1024 * 1024;
        self.supports_2mb
            && remaining >= SIZE_2MB
            && iova % SIZE_2MB == 0
            && phys % SIZE_2MB == 0
    }

    /// Attempt to map pages at the best available page size (1GB > 2MB > 4KB).
    ///
    /// Returns the number of bytes successfully mapped in this chunk.
    fn map_next_chunk(
        &self,
        iova: u64,
        phys: u64,
        remaining: u64,
        read: bool,
        write: bool,
    ) -> Result<u64, IommuError> {
        const SIZE_1GB: u64 = 1024 * 1024 * 1024;
        const SIZE_2MB: u64 = 2 * 1024 * 1024;
        const SIZE_4KB: u64 = 4096;

        if self.can_use_1gb_page(iova, phys, remaining) {
            unsafe { self.map_page_1gb(iova, phys, read, write) }?;
            return Ok(SIZE_1GB);
        }

        if self.can_use_2mb_page(iova, phys, remaining) {
            unsafe { self.map_page_2mb(iova, phys, read, write) }?;
            return Ok(SIZE_2MB);
        }

        let pages_remaining = (remaining / SIZE_4KB) as usize;
        let pt_idx = ((iova >> 12) & 0x1FF) as usize;
        let pages_in_pt = core::cmp::min(pages_remaining, PT_ENTRIES - pt_idx);
        let pages_mapped = self.map_range_4k(iova, phys, pages_in_pt, read, write)?;
        Ok((pages_mapped as u64) * SIZE_4KB)
    }

    /// Rollback previously mapped pages and return the appropriate error.
    ///
    /// If rollback itself fails, the domain is poisoned.
    fn rollback_mapping(&self, start_iova: u64, mapped_len: u64, error: IommuError) -> IommuError {
        if mapped_len > 0 {
            if let Err(rollback_err) = self.unmap_range(start_iova, mapped_len) {
                log::error!(
                    "[IommuDomain] rollback failed after map error: {:?} (rollback: {:?})",
                    error,
                    rollback_err
                );
                self.poison();
                return IommuError::Poisoned;
            }
        }
        error
    }

    /// Map all pages in the given range transactionally.
    ///
    /// If any page mapping fails, all successfully mapped pages are rolled back.
    fn map_pages_transactional(
        &self,
        iova: u64,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        let mut current_iova = iova;
        let mut current_phys = phys;
        let mut remaining = size;
        let mut mapped_len: u64 = 0;

        while remaining > 0 {
            match self.map_next_chunk(current_iova, current_phys, remaining, read, write) {
                Ok(bytes) => {
                    current_iova += bytes;
                    current_phys += bytes;
                    remaining -= bytes;
                    mapped_len += bytes;
                }
                Err(e) => {
                    return Err(self.rollback_mapping(iova, mapped_len, e));
                }
            }
        }

        Ok(())
    }

    /// Map a DMA region
    ///
    /// This function is transactional: if any page mapping fails, all successfully
    /// mapped pages are rolled back before returning the error.
    pub fn map(
        &self,
        iova: u64,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        self.validate_map_args(iova, phys, size)?;

        let (start_shard, end_shard) = self.shard_range(iova, size)?;
        let mut guards = self.lock_shards(start_shard, end_shard)?;

        Self::check_no_overlap(&guards, iova, size)?;

        if self.domain_type != IommuDomainType::Passthrough {
            self.map_pages_transactional(iova, phys, size, read, write)?;
        }

        let mapping = DmaMapping {
            iova,
            phys,
            size,
            read,
            write,
            domain_id_placeholder: self.id,
        };
        for guard in guards.iter_mut() {
            // Note: insert may fail if slab is full (SLAB_CAPACITY exhausted).
            // In production, consider returning IommuError::OutOfResources.
            let _ = guard.mappings.insert(mapping.clone());
        }

        self.mapped_size.fetch_add(size, Ordering::Relaxed);

        Ok(())
    }

    /// Unmap a 2MB super-page (for rollback)
    fn unmap_super_page_2mb(&self, iova: u64) -> Result<(), IommuError> {
        let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
        let pdp_idx = ((iova >> 30) & 0x1FF) as usize;
        let pd_idx = ((iova >> 21) & 0x1FF) as usize;

        let layout =
            alloc::alloc::Layout::from_size_align(PT_ENTRIES * core::mem::size_of::<SlPte>(), 4096)
                .unwrap();

        unsafe {
            let pml4_entry = self.page_table.add(pml4_idx);
            if !(*pml4_entry).is_present() {
                return Err(IommuError::NotMapped);
            }
            let pdp_table = (*pml4_entry).phys_addr() as *mut SlPte;
            let pdp_phys = (*pml4_entry).phys_addr();

            let pdp_entry = pdp_table.add(pdp_idx);
            if !(*pdp_entry).is_present() {
                return Err(IommuError::NotMapped);
            }
            let pd_table = (*pdp_entry).phys_addr() as *mut SlPte;
            let pd_phys = (*pdp_entry).phys_addr();

            let pd_entry = pd_table.add(pd_idx);
            if !(*pd_entry).is_present() || !(*pd_entry).is_super_page(self.pte_format) {
                return Err(IommuError::NotMapped);
            }

            // Clear the entry
            *pd_entry = SlPte::new();

            // Decrement PD count
            if dec_ref(pd_phys) {
                // Free PD
                *pdp_entry = SlPte::new();
                alloc::alloc::dealloc(pd_table as *mut u8, layout);
                unregister_page_table(pd_phys);

                // Decrement PDP count
                if dec_ref(pdp_phys) {
                    // Free PDP
                    *pml4_entry = SlPte::new();
                    alloc::alloc::dealloc(pdp_table as *mut u8, layout);
                    unregister_page_table(pdp_phys);

                    // Decrement PML4 count (root)
                    let pml4_phys = virt_ptr_to_phys(self.page_table as *const u8)?;
                    dec_ref(pml4_phys);
                }
            }
        }
        Ok(())
    }

    /// Unmap a 1GB super-page (for rollback)
    fn unmap_super_page_1gb(&self, iova: u64) -> Result<(), IommuError> {
        let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
        let pdp_idx = ((iova >> 30) & 0x1FF) as usize;

        let layout =
            alloc::alloc::Layout::from_size_align(PT_ENTRIES * core::mem::size_of::<SlPte>(), 4096)
                .unwrap();

        unsafe {
            let pml4_entry = self.page_table.add(pml4_idx);
            if !(*pml4_entry).is_present() {
                return Err(IommuError::NotMapped);
            }
            let pdp_table = (*pml4_entry).phys_addr() as *mut SlPte;
            let pdp_phys = (*pml4_entry).phys_addr();

            let pdp_entry = pdp_table.add(pdp_idx);
            if !(*pdp_entry).is_present() || !(*pdp_entry).is_super_page(self.pte_format) {
                return Err(IommuError::NotMapped);
            }

            // Clear the entry
            *pdp_entry = SlPte::new();

            // Decrement PDP count
            if dec_ref(pdp_phys) {
                // Free PDP
                *pml4_entry = SlPte::new();
                alloc::alloc::dealloc(pdp_table as *mut u8, layout);
                unregister_page_table(pdp_phys);

                // Decrement PML4 count (root)
                let pml4_phys = virt_ptr_to_phys(self.page_table as *const u8)?;
                dec_ref(pml4_phys);
            }
        }
        Ok(())
    }

    /// Map a region with identity mapping (IOVA = Physical Address)
    ///
    /// # Security Warning
    ///
    /// Identity mapping bypasses IOMMU protection and should only be used
    /// for RMRR (Reserved Memory Region Reporting) regions or early boot.
    ///
    /// This function is only available when:
    /// - `feature = "unsafe_iommu_bypass"` is enabled, OR
    /// - `debug_assertions` are enabled (debug builds)
    ///
    /// In production builds, use `map()` with explicit IOVA allocation instead.
    #[cfg(any(feature = "unsafe_iommu_bypass", debug_assertions))]
    pub fn map_identity(
        &self,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        log::warn!(
            "[IOMMU][SECURITY] Identity mapping {:#x}+{:#x} - bypassing protection!",
            phys, size
        );
        self.map(phys, phys, size, read, write)
    }

    /// Map a region with identity mapping - DISABLED in production builds.
    ///
    /// This stub exists to provide a clear compile-time error when identity
    /// mapping is attempted in production builds without the bypass feature.
    #[cfg(not(any(feature = "unsafe_iommu_bypass", debug_assertions)))]
    #[allow(unused_variables)]
    pub fn map_identity(
        &self,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        log::error!(
            "[IOMMU][SECURITY] Identity mapping rejected - enable 'unsafe_iommu_bypass' feature"
        );
        Err(IommuError::NotSupported)
    }

    /// Map a contiguous run of 4KB pages within a single PT.
    fn map_range_4k(
        &self,
        iova: u64,
        phys: u64,
        pages: usize,
        read: bool,
        write: bool,
    ) -> Result<usize, IommuError> {
        const SIZE_4KB: u64 = 4096;

        if pages == 0 {
            return Ok(0);
        }

        let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
        let pdp_idx = ((iova >> 30) & 0x1FF) as usize;
        let pd_idx = ((iova >> 21) & 0x1FF) as usize;
        let pt_idx = ((iova >> 12) & 0x1FF) as usize;

        unsafe {
            let (pt_table, pt_phys, mut newly_allocated) =
                self.ensure_page_tables_4k(pml4_idx, pdp_idx, pd_idx)?;

            let pages_in_pt = core::cmp::min(pages, PT_ENTRIES - pt_idx);

            if newly_allocated[2].is_none() {
                Self::check_pt_no_conflicts(pt_table, pt_idx, pages_in_pt)?;
            }

            Self::write_pt_entries_4k(
                pt_table, pt_idx, phys, pages_in_pt,
                read, write, self.pte_format,
            );

            for scope in newly_allocated.iter_mut().flatten() {
                scope.commit();
            }

            for _ in 0..pages_in_pt {
                inc_ref(pt_phys);
            }

            Ok(pages_in_pt)
        }
    }

    /// Ensure an intermediate page table exists at the given index.
    ///
    /// If the entry is not present, allocate a new page table and attach it.
    /// If `check_super_page` is true and the entry is a super page, return `AlreadyMapped`.
    /// Returns the child table pointer, its physical address, and an optional scope.
    unsafe fn ensure_intermediate_table(
        &self,
        parent_table: *mut SlPte,
        parent_phys: u64,
        idx: usize,
        level: u8,
        check_super_page: bool,
    ) -> Result<(*mut SlPte, u64, Option<PageTableScope>), IommuError> {
        let entry = parent_table.add(idx);
        if (*entry).is_present() {
            if check_super_page && (*entry).is_super_page(self.pte_format) {
                return Err(IommuError::AlreadyMapped);
            }
            let child = (*entry).phys_addr() as *mut SlPte;
            let phys = (*entry).phys_addr();
            Ok((child, phys, None))
        } else {
            let mut scope = self.allocate_page_table()?;
            scope.attach_to_parent(entry, parent_phys, self.pte_format, level);
            let child = (*entry).phys_addr() as *mut SlPte;
            let phys = (*entry).phys_addr();
            Ok((child, phys, Some(scope)))
        }
    }

    /// Walk 3 levels (PML4→PDP→PD) and ensure each intermediate table exists.
    ///
    /// Returns the PT base pointer, PT physical address, and any newly allocated scopes.
    unsafe fn ensure_page_tables_4k(
        &self,
        pml4_idx: usize,
        pdp_idx: usize,
        pd_idx: usize,
    ) -> Result<(*mut SlPte, u64, [Option<PageTableScope>; 3]), IommuError> {
        let mut newly_allocated: [Option<PageTableScope>; 3] = [None, None, None];

        let pml4_phys = virt_ptr_to_phys(self.page_table as *const u8)?;

        let (pdp_table, pdp_phys, scope0) =
            self.ensure_intermediate_table(self.page_table, pml4_phys, pml4_idx, 3, false)?;
        newly_allocated[0] = scope0;

        let (pd_table, pd_phys, scope1) =
            self.ensure_intermediate_table(pdp_table, pdp_phys, pdp_idx, 2, true)?;
        newly_allocated[1] = scope1;

        let (pt_table, pt_phys, scope2) =
            self.ensure_intermediate_table(pd_table, pd_phys, pd_idx, 1, true)?;
        newly_allocated[2] = scope2;

        Ok((pt_table, pt_phys, newly_allocated))
    }

    /// Check that no existing PT entries in the target range are present.
    unsafe fn check_pt_no_conflicts(
        pt_table: *mut SlPte,
        pt_idx: usize,
        count: usize,
    ) -> Result<(), IommuError> {
        for idx in 0..count {
            let pt_entry = pt_table.add(pt_idx + idx);
            if (*pt_entry).is_present() {
                return Err(IommuError::AlreadyMapped);
            }
        }
        Ok(())
    }

    /// Write 4KB page table entries for the given range.
    unsafe fn write_pt_entries_4k(
        pt_table: *mut SlPte,
        pt_idx: usize,
        phys: u64,
        count: usize,
        read: bool,
        write: bool,
        pte_format: PteFormat,
    ) {
        const SIZE_4KB: u64 = 4096;
        for idx in 0..count {
            let pt_entry = pt_table.add(pt_idx + idx);
            let entry_phys = phys + (idx as u64 * SIZE_4KB);
            match pte_format {
                PteFormat::Intel => {
                    *pt_entry = SlPte::mapping(entry_phys, read, write);
                }
                PteFormat::Amd => {
                    let amd_pte = AmdPte::mapping(entry_phys, read, write, 0);
                    *pt_entry = SlPte(amd_pte.0);
                }
            }
        }
    }

    /// Map a single page using 4-level page table walking
    /// Intel VT-d uses: PML4 -> PDP -> PD -> PT (same as x86-64 paging)
    ///
    /// On error, any newly allocated page tables are deallocated to prevent leaks.
    fn map_page(
        &self,
        iova: u64,
        phys: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
        let pdp_idx = ((iova >> 30) & 0x1FF) as usize;
        let pd_idx = ((iova >> 21) & 0x1FF) as usize;
        let pt_idx = ((iova >> 12) & 0x1FF) as usize;

        let mut newly_allocated: [Option<PageTableScope>; 3] = [None, None, None];

        unsafe {
            let pml4_phys = virt_ptr_to_phys(self.page_table as *const u8)?;

            // Level 4: PML4 -> PDP
            let pml4_entry = self.page_table.add(pml4_idx);
            newly_allocated[0] = self.ensure_pdp_table(pml4_entry, pml4_phys)?;
            let pdp_table = (*pml4_entry).phys_addr() as *mut SlPte;
            let pdp_phys = (*pml4_entry).phys_addr();

            // Level 3: PDP -> PD
            let pdp_entry = pdp_table.add(pdp_idx);
            newly_allocated[1] = self.ensure_pd_table(pdp_entry, pdp_phys)?;
            let pd_table = (*pdp_entry).phys_addr() as *mut SlPte;
            let pd_phys = (*pdp_entry).phys_addr();

            // Level 2: PD -> PT
            let pd_entry = pd_table.add(pd_idx);
            newly_allocated[2] = self.ensure_pt_table(pd_entry, pd_phys)?;
            let pt_table = (*pd_entry).phys_addr() as *mut SlPte;
            let pt_phys = (*pd_entry).phys_addr();

            // Level 1: PT -> Page
            let pt_entry = pt_table.add(pt_idx);
            if (*pt_entry).is_present() {
                return Err(IommuError::AlreadyMapped);
            }

            match self.pte_format {
                PteFormat::Intel => {
                    *pt_entry = SlPte::mapping(phys, read, write);
                }
                PteFormat::Amd => {
                    let amd_pte = AmdPte::mapping(phys, read, write, 0);
                    *pt_entry = SlPte(amd_pte.0);
                }
            }

            inc_ref(pt_phys);

            Self::commit_allocated_tables(&mut newly_allocated);
        }

        Ok(())
    }

    /// 新規割り当て済みページテーブルをコミットする
    fn commit_allocated_tables(tables: &mut [Option<PageTableScope>]) {
        for slot in tables.iter_mut() {
            if let Some(scope) = slot {
                scope.commit();
            }
        }
    }

    /// Allocate a zeroed page table from the pool (Phase 6)
    ///
    /// Uses the domain's page table pool for NUMA-aware recycling.
    /// Falls back to direct allocation if pool is not available.
    fn allocate_page_table(&self) -> Result<PageTableScope, IommuError> {
        PageTableScope::new_with_pool(self.page_table_pool.clone(), self.numa_node())
    }

    /// Ensure a PDP table exists for the given PML4 entry, allocating if needed.
    unsafe fn ensure_pdp_table(
        &self,
        pml4_entry: *mut SlPte,
        pml4_phys: u64,
    ) -> Result<Option<PageTableScope>, IommuError> {
        if (*pml4_entry).is_present() {
            return Ok(None);
        }
        let mut pdp_scope = self.allocate_page_table()?;
        pdp_scope.attach_to_parent(pml4_entry, pml4_phys, self.pte_format, 3);
        Ok(Some(pdp_scope))
    }

    /// Ensure a PD table exists for the given PDP entry, allocating if needed.
    /// Returns Err(AlreadyMapped) if a 1GB super-page already exists.
    unsafe fn ensure_pd_table(
        &self,
        pdp_entry: *mut SlPte,
        pdp_phys: u64,
    ) -> Result<Option<PageTableScope>, IommuError> {
        if (*pdp_entry).is_present() {
            if (*pdp_entry).is_super_page(self.pte_format) {
                return Err(IommuError::AlreadyMapped);
            }
            return Ok(None);
        }
        let mut pd_scope = self.allocate_page_table()?;
        pd_scope.attach_to_parent(pdp_entry, pdp_phys, self.pte_format, 2);
        Ok(Some(pd_scope))
    }

    /// Ensure a PT (Level 1) table exists for the given PD entry, allocating if needed.
    unsafe fn ensure_pt_table(
        &self,
        pd_entry: *mut SlPte,
        pd_phys: u64,
    ) -> Result<Option<PageTableScope>, IommuError> {
        if (*pd_entry).is_present() {
            return Ok(None);
        }
        let mut pt_scope = self.allocate_page_table()?;
        pt_scope.attach_to_parent(pd_entry, pd_phys, self.pte_format, 1);
        Ok(Some(pt_scope))
    }

    /// Map a 2MB super-page
    ///
    /// Uses 3-level page table walking (PML4 -> PDP -> PD) and sets super-page at PD level.
    /// Both iova and phys must be 2MB-aligned.
    ///
    /// On error, any newly allocated page tables are deallocated to prevent leaks.
    pub unsafe fn map_page_2mb(
        &self,
        iova: u64,
        phys: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        const SIZE_2MB: u64 = 2 * 1024 * 1024;

        if iova % SIZE_2MB != 0 || phys % SIZE_2MB != 0 {
            return Err(IommuError::InvalidAddress);
        }

        let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
        let pdp_idx = ((iova >> 30) & 0x1FF) as usize;
        let pd_idx = ((iova >> 21) & 0x1FF) as usize;

        let mut newly_allocated: [Option<PageTableScope>; 2] = [None, None];

        let pml4_table = self.page_table;
        let pml4_entry = unsafe { pml4_table.add(pml4_idx) };
        let pml4_phys = virt_ptr_to_phys(pml4_table as *const u8)?;

        newly_allocated[0] = unsafe { self.ensure_pdp_table(pml4_entry, pml4_phys)? };

        let pdp_table = (unsafe { *pml4_entry }).phys_addr() as *mut SlPte;
        let pdp_entry = unsafe { pdp_table.add(pdp_idx) };
        let pdp_phys = (unsafe { *pml4_entry }).phys_addr();

        newly_allocated[1] = unsafe { self.ensure_pd_table(pdp_entry, pdp_phys)? };

        let pd_table = (unsafe { *pdp_entry }).phys_addr() as *mut SlPte;
        let pd_entry = unsafe { pd_table.add(pd_idx) };
        let pd_phys = (unsafe { *pdp_entry }).phys_addr();

        if (unsafe { *pd_entry }).is_present() {
            return Err(IommuError::AlreadyMapped);
        }

        // Create 2MB super-page entry
        match self.pte_format {
            PteFormat::Intel => unsafe { *pd_entry = SlPte::super_page_2mb(phys, read, write) },
            PteFormat::Amd => {
                let amd_pte = AmdPte::mapping(phys, read, write, 0);
                unsafe { *pd_entry = SlPte(amd_pte.0) };
            }
        }
        inc_ref(pd_phys);

        Self::commit_allocated_tables(&mut newly_allocated);

        Ok(())
    }

    unsafe fn ensure_pdp_for_super_page(
        &self,
        pml4_entry: *mut SlPte,
        pml4_phys: u64,
    ) -> Result<Option<PageTableScope>, IommuError> {
        if !(unsafe { *pml4_entry }).is_present() {
            let mut pdp_scope = self.allocate_page_table()?;
            pdp_scope.attach_to_parent(pml4_entry, pml4_phys, self.pte_format, 3);
            Ok(Some(pdp_scope))
        } else if (unsafe { *pml4_entry }).is_super_page(self.pte_format) {
            Err(IommuError::AlreadyMapped)
        } else {
            Ok(None)
        }
    }

    /// Map a 1GB super-page
    ///
    /// Uses 2-level page table walking (PML4 -> PDP) and sets super-page at PDP level.
    /// Both iova and phys must be 1GB-aligned.
    ///
    /// On error, any newly allocated page tables are deallocated to prevent leaks.
    pub unsafe fn map_page_1gb(
        &self,
        iova: u64,
        phys: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        const SIZE_1GB: u64 = 1024 * 1024 * 1024;

        if iova % SIZE_1GB != 0 || phys % SIZE_1GB != 0 {
            return Err(IommuError::InvalidAddress);
        }

        // Calculate indices
        let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
        let pdp_idx = ((iova >> 30) & 0x1FF) as usize;

        // Track newly allocated PDP table for rollback via RAII
        let mut newly_allocated_pdp: Option<PageTableScope> = None;

        let pml4_table = self.page_table;
        let pml4_entry = unsafe { pml4_table.add(pml4_idx) };
        let pml4_phys = virt_ptr_to_phys(pml4_table as *const u8)?;
        newly_allocated_pdp = unsafe { self.ensure_pdp_for_super_page(pml4_entry, pml4_phys)? };

        let pdp_table = (unsafe { *pml4_entry }).phys_addr() as *mut SlPte;
        let pdp_entry = unsafe { pdp_table.add(pdp_idx) };
        let pdp_phys = (unsafe { *pml4_entry }).phys_addr();

        // Check if already mapped
        if (unsafe { *pdp_entry }).is_present() {
            // If a mapping already exists, let RAII (PageTableScope Drop) roll back any
            // newly allocated page tables and return an error.
            return Err(IommuError::AlreadyMapped);
        }

        // Create 1GB super-page entry
        match self.pte_format {
            PteFormat::Intel => unsafe { *pdp_entry = SlPte::super_page_1gb(phys, read, write) },
            PteFormat::Amd => {
                // For AMD, 1GB page is at Level 3 (PDP). Next Level field (9-11) should be 0.
                let amd_pte = AmdPte::mapping(phys, read, write, 0);
                unsafe { *pdp_entry = SlPte(amd_pte.0) };
            }
        }
        // Increment PDP count
        inc_ref(pdp_phys);

        // Commit newly allocated PDP if any
        if let Some(scope) = newly_allocated_pdp.as_mut() {
            scope.commit();
        }

        Ok(())
    }

    /// 複数シャードのガードを取得する
    fn acquire_shard_guards<'a>(
        &'a self,
        start_shard: usize,
        end_shard: usize,
        first_guard: crate::sync::PoisonLockGuard<'a, DomainShard>,
    ) -> Result<Vec<crate::sync::PoisonLockGuard<'a, DomainShard>>, IommuError> {
        let mut guards = Vec::with_capacity(end_shard.saturating_sub(start_shard) + 1);
        guards.push(first_guard);
        for idx in (start_shard + 1)..=end_shard {
            let guard = self.shards[idx].lock().map_err(|_| IommuError::Poisoned)?;
            guards.push(guard);
        }
        Ok(guards)
    }

    /// Unmap a DMA region
    pub fn unmap(&self, iova: u64) -> Result<DmaMapping, IommuError> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(IommuError::Poisoned);
        }

        let start_shard = Self::shard_for_iova(iova);
        let guard = self.shards[start_shard]
            .lock()
            .map_err(|_| IommuError::Poisoned)?;
        let mapping = guard
            .mappings
            .lookup(iova)
            .cloned()
            .ok_or(IommuError::NotMapped)?;
        let (_, end_shard) = self.shard_range(iova, mapping.size)?;

        let mut guards = self.acquire_shard_guards(start_shard, end_shard, guard)?;

        for guard in guards.iter_mut() {
            guard.mappings.remove(iova);
        }

        if self.domain_type != IommuDomainType::Passthrough {
            self.unmap_range(iova, mapping.size)?;
        }

        self.mapped_size
            .fetch_sub(mapping.size, Ordering::Relaxed);

        Ok(mapping)
    }

    /// Unmap a range using super-page aware traversal.
    fn unmap_range(&self, iova: u64, size: u64) -> Result<(), IommuError> {
        let mut current = iova;
        let mut remaining = size;
        const SIZE_4KB: u64 = 4096;

        while remaining > 0 {
            if let Some(unmapped) = self.try_unmap_superpage(current)? {
                if unmapped > remaining {
                    return Err(IommuError::InvalidAlignment);
                }
                current += unmapped;
                remaining -= unmapped;
                continue;
            }

            let pages_remaining = (remaining / SIZE_4KB) as usize;
            let pt_idx = ((current >> 12) & 0x1FF) as usize;
            let pages_in_pt = core::cmp::min(pages_remaining, PT_ENTRIES - pt_idx);
            let pages_unmapped = self.unmap_range_4k(current, pages_in_pt)?;
            let unmapped_bytes = (pages_unmapped as u64) * SIZE_4KB;
            if unmapped_bytes > remaining {
                return Err(IommuError::InvalidAlignment);
            }
            current += unmapped_bytes;
            remaining -= unmapped_bytes;
        }

        Ok(())
    }

    fn try_unmap_superpage(&self, iova: u64) -> Result<Option<u64>, IommuError> {
        const SIZE_1GB: u64 = 1024 * 1024 * 1024;
        const SIZE_2MB: u64 = 2 * 1024 * 1024;

        let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
        let pdp_idx = ((iova >> 30) & 0x1FF) as usize;
        let pd_idx = ((iova >> 21) & 0x1FF) as usize;

        unsafe {
            let pml4_entry = self.page_table.add(pml4_idx);
            if !(*pml4_entry).is_present() {
                return Err(IommuError::NotMapped);
            }
            let pdp_table = (*pml4_entry).phys_addr() as *mut SlPte;

            let pdp_entry = pdp_table.add(pdp_idx);
            if !(*pdp_entry).is_present() {
                return Err(IommuError::NotMapped);
            }
            if (*pdp_entry).is_super_page(self.pte_format) {
                self.unmap_super_page_1gb(iova)?;
                return Ok(Some(SIZE_1GB));
            }

            let pd_table = (*pdp_entry).phys_addr() as *mut SlPte;
            let pd_entry = pd_table.add(pd_idx);
            if !(*pd_entry).is_present() {
                return Err(IommuError::NotMapped);
            }
            if (*pd_entry).is_super_page(self.pte_format) {
                self.unmap_super_page_2mb(iova)?;
                return Ok(Some(SIZE_2MB));
            }
        }

        Ok(None)
    }

    /// Cascade-cleanup empty page tables after all 4K entries in a PT are removed.
    unsafe fn cleanup_empty_page_tables_4k(
        &self,
        pml4_entry: *mut SlPte,
        pdp_entry: *mut SlPte,
        pdp_table: *mut SlPte,
        pdp_phys: u64,
        pd_entry: *mut SlPte,
        pd_table: *mut SlPte,
        pd_phys: u64,
        pt_table: *mut SlPte,
        pt_phys: u64,
        layout: alloc::alloc::Layout,
    ) {
        if get_ref_count(pt_phys) != 0 {
            return;
        }
        *pd_entry = SlPte::new();
        alloc::alloc::dealloc(pt_table as *mut u8, layout);
        unregister_page_table(pt_phys);

        if !dec_ref(pd_phys) {
            return;
        }
        *pdp_entry = SlPte::new();
        alloc::alloc::dealloc(pd_table as *mut u8, layout);
        unregister_page_table(pd_phys);

        if !dec_ref(pdp_phys) {
            return;
        }
        *pml4_entry = SlPte::new();
        alloc::alloc::dealloc(pdp_table as *mut u8, layout);
        unregister_page_table(pdp_phys);

        let pml4_phys = virt_ptr_to_phys(self.page_table as *const u8)
            .expect("Failed to get pml4 phys");
        dec_ref(pml4_phys);
    }

    fn verify_pt_entries_present(
        pt_table: *mut SlPte,
        pt_idx: usize,
        count: usize,
    ) -> Result<(), IommuError> {
        for idx in 0..count {
            let pt_entry = unsafe { pt_table.add(pt_idx + idx) };
            if !unsafe { (*pt_entry) }.is_present() {
                return Err(IommuError::NotMapped);
            }
        }
        Ok(())
    }

    /// Unmap a contiguous run of 4KB entries within a single PT.
    fn unmap_range_4k(&self, iova: u64, pages: usize) -> Result<usize, IommuError> {
        if pages == 0 {
            return Ok(0);
        }

        let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
        let pdp_idx = ((iova >> 30) & 0x1FF) as usize;
        let pd_idx = ((iova >> 21) & 0x1FF) as usize;
        let pt_idx = ((iova >> 12) & 0x1FF) as usize;
        let pages_in_pt = core::cmp::min(pages, PT_ENTRIES - pt_idx);

        let layout =
            alloc::alloc::Layout::from_size_align(PT_ENTRIES * core::mem::size_of::<SlPte>(), 4096)
                .unwrap();

        unsafe {
            let pml4_entry = self.page_table.add(pml4_idx);
            if !(*pml4_entry).is_present() {
                return Err(IommuError::NotMapped);
            }
            let pdp_table = (*pml4_entry).phys_addr() as *mut SlPte;
            let pdp_phys = (*pml4_entry).phys_addr();

            let pdp_entry = pdp_table.add(pdp_idx);
            if !(*pdp_entry).is_present() {
                return Err(IommuError::NotMapped);
            }
            if (*pdp_entry).is_super_page(self.pte_format) {
                return Err(IommuError::InvalidAlignment);
            }
            let pd_table = (*pdp_entry).phys_addr() as *mut SlPte;
            let pd_phys = (*pdp_entry).phys_addr();

            let pd_entry = pd_table.add(pd_idx);
            if !(*pd_entry).is_present() {
                return Err(IommuError::NotMapped);
            }
            if (*pd_entry).is_super_page(self.pte_format) {
                return Err(IommuError::InvalidAlignment);
            }
            let pt_table = (*pd_entry).phys_addr() as *mut SlPte;
            let pt_phys = (*pd_entry).phys_addr();

            Self::verify_pt_entries_present(pt_table, pt_idx, pages_in_pt)?;

            for idx in 0..pages_in_pt {
                let pt_entry = pt_table.add(pt_idx + idx);
                *pt_entry = SlPte::new();
                let _ = dec_ref(pt_phys);
            }

            self.cleanup_empty_page_tables_4k(
                pml4_entry, pdp_entry, pdp_table, pdp_phys,
                pd_entry, pd_table, pd_phys,
                pt_table, pt_phys, layout,
            );
        }

        Ok(pages_in_pt)
    }

    /// Unmap a single entry at `iova` and return the unmapped size.
    #[allow(dead_code)]
    fn unmap_entry(&self, iova: u64) -> Result<u64, IommuError> {
        const SIZE_1GB: u64 = 1024 * 1024 * 1024;
        const SIZE_2MB: u64 = 2 * 1024 * 1024;
        const SIZE_4KB: u64 = 4096;

        let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
        let pdp_idx = ((iova >> 30) & 0x1FF) as usize;
        let pd_idx = ((iova >> 21) & 0x1FF) as usize;

        unsafe {
            let pml4_entry = self.page_table.add(pml4_idx);
            if !(*pml4_entry).is_present() {
                return Err(IommuError::NotMapped);
            }
            let pdp_table = (*pml4_entry).phys_addr() as *mut SlPte;

            let pdp_entry = pdp_table.add(pdp_idx);
            if !(*pdp_entry).is_present() {
                return Err(IommuError::NotMapped);
            }
            if (*pdp_entry).is_super_page(self.pte_format) {
                self.unmap_super_page_1gb(iova)?;
                return Ok(SIZE_1GB);
            }

            let pd_table = (*pdp_entry).phys_addr() as *mut SlPte;
            let pd_entry = pd_table.add(pd_idx);
            if !(*pd_entry).is_present() {
                return Err(IommuError::NotMapped);
            }
            if (*pd_entry).is_super_page(self.pte_format) {
                self.unmap_super_page_2mb(iova)?;
                return Ok(SIZE_2MB);
            }
        }

        self.unmap_page(iova)?;
        Ok(SIZE_4KB)
    }

    /// Unmap a single page using 4-level page table walking
    ///
    /// Also reclaims empty page tables (PT, PD, PDP) to prevent memory accumulation
    /// from sparse mappings.
    #[allow(unused_assignments)]
    fn unmap_page(&self, iova: u64) -> Result<(), IommuError> {
        // Extract indices for each level
        let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
        let pdp_idx = ((iova >> 30) & 0x1FF) as usize;
        let pd_idx = ((iova >> 21) & 0x1FF) as usize;
        let pt_idx = ((iova >> 12) & 0x1FF) as usize;

        let layout =
            alloc::alloc::Layout::from_size_align(PT_ENTRIES * core::mem::size_of::<SlPte>(), 4096)
                .unwrap();

        unsafe {
            // Walk down to PT
            let pml4_entry = self.page_table.add(pml4_idx);
            if !(*pml4_entry).is_present() {
                return Err(IommuError::NotMapped);
            }
            let pdp_table = (*pml4_entry).phys_addr() as *mut SlPte;
            let pdp_phys = (*pml4_entry).phys_addr();

            let pdp_entry = pdp_table.add(pdp_idx);
            if !(*pdp_entry).is_present() {
                return Err(IommuError::NotMapped);
            }
            let pd_table = (*pdp_entry).phys_addr() as *mut SlPte;
            let pd_phys = (*pdp_entry).phys_addr();

            let pd_entry = pd_table.add(pd_idx);
            if !(*pd_entry).is_present() {
                return Err(IommuError::NotMapped);
            }
            let pt_table = (*pd_entry).phys_addr() as *mut SlPte;
            let pt_phys = (*pd_entry).phys_addr();

            let pt_entry = pt_table.add(pt_idx);
            if !(*pt_entry).is_present() {
                return Err(IommuError::NotMapped);
            }
            *pt_entry = SlPte::new(); // Clear entry

            // Decrement PT count
            if dec_ref(pt_phys) {
                // Free PT
                *pd_entry = SlPte::new();
                alloc::alloc::dealloc(pt_table as *mut u8, layout);
                unregister_page_table(pt_phys);

                // Decrement PD count
                if dec_ref(pd_phys) {
                    // Free PD
                    *pdp_entry = SlPte::new();
                    alloc::alloc::dealloc(pd_table as *mut u8, layout);
                    unregister_page_table(pd_phys);

                    // Decrement PDP count
                    if dec_ref(pdp_phys) {
                        // Free PDP
                        *pml4_entry = SlPte::new();
                        alloc::alloc::dealloc(pdp_table as *mut u8, layout);
                        unregister_page_table(pdp_phys);

                        // Decrement PML4 count (root)
                        let pml4_phys = virt_ptr_to_phys(self.page_table as *const u8)
                            .expect("Failed to get pml4 phys");
                        dec_ref(pml4_phys);
                    }
                }
            }
        }

        Ok(())
    }

    /// Get total mapped size
    pub fn mapped_size(&self) -> u64 {
        self.mapped_size.load(Ordering::Relaxed)
    }

    fn poison(&self) {
        if !self.poisoned.swap(true, Ordering::AcqRel) {
            self.notify_security(SecurityEvent::QuarantinePoisoned { domain_id: self.id });
            log::error!(
                "[IommuDomain] domain {} poisoned due to rollback failure",
                self.id
            );
        }
    }

    /// Lookup a mapping by its IOVA base.
    pub fn mapping(&self, iova: u64) -> Option<DmaMapping> {
        let shard = Self::shard_for_iova(iova);
        let guard = match self.shards[shard].lock() {
            Ok(guard) => guard,
            Err(_) => return None,
        };
        guard.mappings.lookup(iova).cloned()
    }

    /// Get a snapshot of all mappings (deduplicated across shards).
    /// Returns mappings sorted by IOVA address.
    pub fn mappings_snapshot(&self) -> Vec<DmaMapping> {
        let mut snapshot = Vec::new();
        for shard in self.shards.iter() {
            let guard = match shard.lock() {
                Ok(guard) => guard,
                Err(_) => continue,
            };
            for mapping in guard.mappings.iter() {
                // Deduplicate by IOVA (only add if not already present)
                if !snapshot.iter().any(|m: &DmaMapping| m.iova == mapping.iova) {
                    snapshot.push(mapping.clone());
                }
            }
        }
        // Sort by IOVA for consistent ordering
        snapshot.sort_by_key(|m| m.iova);
        snapshot
    }

    #[cfg(test)]
    pub fn drop_mapping_for_test(&self, iova: u64) -> Option<DmaMapping> {
        let mapping = self.mapping(iova)?;
        let (start_shard, end_shard) = self.shard_range(iova, mapping.size).ok()?;
        let mut guards = self.lock_shards(start_shard, end_shard).ok()?;
        for guard in guards.iter_mut() {
            guard.mappings.remove(iova);
        }
        self.mapped_size
            .fetch_sub(mapping.size, Ordering::Relaxed);
        Some(mapping)
    }

    // =========================================================================
    // DmaHandle Integration
    // =========================================================================

    /// Map an RRef for DMA access
    ///
    /// This method:
    /// 1. Gets the physical address from the RRef
    /// 2. Allocates an IOVA from the hardware context
    /// 3. Creates page table mappings
    /// 4. Returns a DmaHandle that tracks ownership
    ///
    /// # Arguments
    /// * `rref` - The RRef to map (consumed)
    /// * `context` - The IOMMU context for IOVA allocation
    /// * `direction` - DMA transfer direction
    ///
    /// # Errors
    /// Returns `MapError<T>` containing the original RRef on failure.
    pub fn map_buffer<T>(
        &self,
        rref: crate::ipc::RRef<T>,
        context: &dyn IommuHardwareContext,
        direction: super::dma_handle::DmaDirection,
    ) -> Result<super::dma_handle::DmaHandle<T>, super::dma_handle::MapError<T>> {
        use super::dma_handle::{DmaHandle, MapError, MapErrorKind, MappingKind};
        use x86_64::VirtAddr;

        // Get physical address from RRef's virtual pointer
        let virt_ptr = &*rref as *const T as u64;
        let virt_addr = VirtAddr::new(virt_ptr);
        let phys_addr = crate::mm::mapping::virt_to_phys(virt_addr);
        let phys = phys_addr.as_u64();

        let size = core::mem::size_of::<T>() as u64;

        // Page-align the size (round up)
        let aligned_size = (size + 4095) & !4095;
        if aligned_size == 0 {
            return Err(MapError::new(rref, MapErrorKind::InvalidAlignment));
        }

        // Allocate IOVA from domain's per-domain allocator (Phase 7)
        // This eliminates lock contention between domains for 100Gbps+ I/O
        let iova = match self.allocate_iova(aligned_size) {
            Ok(addr) => addr,
            Err(e) => return Err(MapError::new(rref, MapErrorKind::IommuError(e))),
        };
        let _ = context; // context kept for API compatibility but not used for IOVA

        // Determine permissions from direction
        let (read, write) = match direction {
            super::dma_handle::DmaDirection::ToDevice => (true, false),
            super::dma_handle::DmaDirection::FromDevice => (false, true),
            super::dma_handle::DmaDirection::Bidirectional => (true, true),
        };

        // Create page table mappings
        if let Err(e) = self.map(iova, phys, aligned_size, read, write) {
            // Mapping failed - free IOVA back to domain allocator and return error with RRef
            let _ = self.free_iova(iova, aligned_size);
            return Err(MapError::new(rref, MapErrorKind::IommuError(e)));
        }

        // Success - create DmaHandle
        Ok(DmaHandle::new(
            rref,
            iova,
            phys,
            size,
            self.id,
            direction,
            MappingKind::Domain,
        ))
    }

    /// Unmap a DMA buffer and return the RRef
    ///
    /// This method:
    /// 1. Removes page table mappings
    /// 2. Invalidates IOTLB (via IommuInvalidator)
    /// 3. Frees the IOVA
    /// 4. Returns the RRef to the caller
    ///
    /// # Arguments
    /// * `handle` - The DmaHandle to unmap (consumed)
    /// * `context` - The IOMMU context for IOVA deallocation
    /// * `invalidator` - Invalidator for IOTLB flush
    ///
    /// # Errors
    /// Returns `UnmapError<T>` containing the handle on failure.
    pub fn unmap_buffer<T, I: IommuInvalidator>(
        &self,
        mut handle: super::dma_handle::DmaHandle<T>,
        context: &dyn IommuHardwareContext,
        invalidator: &I,
    ) -> Result<crate::ipc::RRef<T>, super::dma_handle::UnmapError<T>> {
        use super::dma_handle::{UnmapError, UnmapErrorKind};

        let iova = handle.iova();
        let size = handle.size();

        // Page-align the size (round up)
        let aligned_size = (size + 4095) & !4095;

        // Unmap from page tables
        if let Err(e) = self.unmap(iova) {
            return Err(UnmapError::new(handle, UnmapErrorKind::IommuError(e)));
        }

        // Invalidate IOTLB
        let req = InvalidateRequest::pages(self.id, iova, aligned_size);
        if let Err(e) = invalidator.invalidate(req) {
            // IOTLB invalidation failed - this is critical!
            // We can't return the RRef because device may still access it
            return Err(UnmapError::new(handle, UnmapErrorKind::IommuError(e)));
        }

        // Free IOVA back to domain's per-domain allocator
        if let Err(e) = self.free_iova(iova, aligned_size) {
            // IOVA free failed - log but continue since mapping is already removed
            log::warn!("[IommuDomain] IOVA free failed for 0x{:x}: {:?}", iova, e);
        }
        let _ = context; // context kept for API compatibility

        // Take the RRef from the handle (marks it as unmapped)
        match handle.take_rref() {
            Some(rref) => Ok(rref),
            None => Err(UnmapError::new(handle, UnmapErrorKind::InvalidIova)),
        }
    }

    /// Unmap a DMA buffer asynchronously and return the RRef
    ///
    /// This method:
    /// 1. Removes page table mappings (sync)
    /// 2. Initiates async IOTLB invalidation
    /// 3. Awaits completion
    /// 4. Frees the IOVA
    /// 5. Returns the RRef to the caller
    ///
    /// # Arguments
    /// * `handle` - The DmaHandle to unmap (consumed)
    /// * `context` - The IOMMU context for IOVA deallocation
    /// * `invalidator` - Invalidator for async IOTLB flush
    ///
    /// # Returns
    /// A future that resolves to `Result<RRef<T>, UnmapError<T>>`
    pub async fn unmap_buffer_async<T, I: IommuInvalidator + Sync>(
        &self,
        mut handle: super::dma_handle::DmaHandle<T>,
        context: &dyn IommuHardwareContext,
        invalidator: &I,
    ) -> Result<crate::ipc::RRef<T>, super::dma_handle::UnmapError<T>> {
        use super::dma_handle::{UnmapError, UnmapErrorKind};

        let iova = handle.iova();
        let size = handle.size();
        let domain_id = self.id;

        // Page-align the size (round up)
        let aligned_size = (size + 4095) & !4095;

        // Unmap from page tables (sync)
        if let Err(e) = self.unmap(iova) {
            return Err(UnmapError::new(handle, UnmapErrorKind::IommuError(e)));
        }

        // Invalidate IOTLB asynchronously
        let req = InvalidateRequest::pages(domain_id, iova, aligned_size);
        if let Err(e) = invalidator.invalidate_async(req).await {
            // IOTLB invalidation failed - critical!
            // We can't return the RRef because device may still access it
            return Err(UnmapError::new(handle, UnmapErrorKind::IommuError(e)));
        }

        // Free IOVA
        if let Err(e) = context.free_iova(iova, aligned_size) {
            log::warn!("[IommuDomain] IOVA free failed for 0x{:x}: {:?}", iova, e);
        }

        // Take the RRef from the handle (marks it as unmapped)
        match handle.take_rref() {
            Some(rref) => Ok(rref),
            None => Err(UnmapError::new(handle, UnmapErrorKind::InvalidIova)),
        }
    }

    /// Find the next child page table entry starting from `start_idx`.
    ///
    /// Returns `(child_ptr, child_level, next_idx_after_child)` or `None` if no child found.
    unsafe fn find_next_child_table(
        table_ptr: *mut SlPte,
        level: usize,
        start_idx: usize,
        pte_format: PteFormat,
    ) -> Option<(*mut SlPte, usize, usize)> {
        let mut idx = start_idx;
        while idx < PT_ENTRIES {
            let pte = unsafe { *table_ptr.add(idx) };
            idx += 1;

            if !pte.is_present() {
                continue;
            }

            // Skip super pages (2MB at level 2, 1GB at level 3)
            if (level == 3 || level == 2) && pte.is_super_page(pte_format) {
                continue;
            }

            let child_phys = pte.phys_addr();
            let child_ptr = phys_to_virt_usize(child_phys) as *mut SlPte;
            return Some((child_ptr, level - 1, idx));
        }
        None
    }

    /// Iteratively deallocate all page tables using an explicit stack.
    ///
    /// This implementation avoids recursion entirely by using a fixed-size
    /// explicit stack. The stack size is bounded by the maximum page table
    /// depth (PT_LEVELS) multiplied by the fan-out (PT_ENTRIES), but in practice
    /// we process tables level-by-level to keep stack usage minimal.
    ///
    /// # Design
    ///
    /// Uses post-order traversal: children are freed before parents.
    /// The algorithm:
    /// 1. Push root table with level info
    /// 2. For each table, push all child tables (non-super-page entries)
    /// 3. When a table has no more children to process, free it
    ///
    /// # Safety
    /// - The domain must not be in use by hardware (IOMMU disabled or domain detached)
    unsafe fn deallocate_page_tables_iterative(&mut self) { unsafe {
        let layout =
            alloc::alloc::Layout::from_size_align(PT_ENTRIES * core::mem::size_of::<SlPte>(), 4096)
                .expect("invalid page table layout");

        /// Stack entry for iterative page table traversal.
        /// Using a fixed-size array avoids heap allocation during Drop.
        #[derive(Clone, Copy)]
        struct StackEntry {
            table_ptr: *mut SlPte,
            level: usize,
            next_idx: usize, // Next child index to process
        }

        // Maximum stack depth: one entry per level, plus entries being processed
        // PT_LEVELS is typically 4, so 16 entries is more than enough for worst case
        const MAX_STACK_DEPTH: usize = 16;
        let mut stack: [StackEntry; MAX_STACK_DEPTH] = [StackEntry {
            table_ptr: core::ptr::null_mut(),
            level: 0,
            next_idx: 0,
        }; MAX_STACK_DEPTH];
        // Push root table
        stack[0] = StackEntry {
            table_ptr: self.page_table,
            level: PT_LEVELS,
            next_idx: 0,
        };
        let mut stack_top: usize = 1;

        while stack_top > 0 {
            let entry_idx = stack_top - 1;

            // Copy current entry values to avoid borrow conflicts
            let table_ptr = stack[entry_idx].table_ptr;
            let level = stack[entry_idx].level;
            let mut next_idx = stack[entry_idx].next_idx;

            // Leaf level (level 1) or all children processed - free this table
            if level <= 1 || next_idx >= PT_ENTRIES {
                stack_top -= 1;

                // Unregister and deallocate the table
                if let Ok(phys) = virt_ptr_to_phys(table_ptr as *const u8) {
                    unregister_page_table(phys);
                }
                alloc::alloc::dealloc(table_ptr as *mut u8, layout);
                continue;
            }

            // Find next child table to process
            match Self::find_next_child_table(table_ptr, level, next_idx, self.pte_format) {
                Some((child_ptr, child_level, updated_next_idx)) => {
                    stack[entry_idx].next_idx = updated_next_idx;
                    if stack_top < MAX_STACK_DEPTH {
                        stack[stack_top] = StackEntry {
                            table_ptr: child_ptr,
                            level: child_level,
                            next_idx: 0,
                        };
                        stack_top += 1;
                    } else {
                        log::error!(
                            "[IommuDomain] Page table deallocation stack overflow at level {}",
                            level
                        );
                    }
                }
                None => {
                    stack[entry_idx].next_idx = PT_ENTRIES;
                }
            }
        }
    }}

    /// Legacy recursive deallocation - kept for reference but not used.
    #[allow(dead_code)]
    unsafe fn deallocate_page_tables_recursive(&mut self) { unsafe {
        // Delegate to the iterative version
        self.deallocate_page_tables_iterative();
    }}
}

impl Drop for IommuDomain {
    fn drop(&mut self) {
        if !self.page_table.is_null() {
            unsafe {
                self.deallocate_page_tables_iterative();
            }
        }
    }
}
