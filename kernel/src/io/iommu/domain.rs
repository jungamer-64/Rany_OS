// ============================================================================
// kernel/src/io/iommu/domain.rs
// ============================================================================
use super::controller::iova::IovaManager; // For allocate_iova/free_iova on IommuController
use super::quarantine::QuarantineQueue;
use super::tables::{PT_ENTRIES, PageTableScope, SlPte, phys_to_virt_usize, virt_ptr_to_phys};
use super::types::{DmaMapping, IommuDomainType, IommuError};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use bitflags::bitflags;

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
pub trait IommuInvalidator {
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
    /// Returns a future that completes when the IOTLB invalidation is done.
    /// The default implementation blocks synchronously.
    fn invalidate_async<'a>(
        &'a self,
        request: InvalidateRequest,
    ) -> core::pin::Pin<
        alloc::boxed::Box<dyn core::future::Future<Output = Result<(), IommuError>> + Send + 'a>,
    >
    where
        Self: Sync,
    {
        // Default: just wrap the sync version
        let result = self.invalidate(request);
        alloc::boxed::Box::pin(async move { result })
    }
}

/// IOMMU Domain (address space for devices)
///
/// Each domain has its own Mutex in the global IOMMU_DOMAINS registry,
/// allowing parallel map/unmap operations across different domains.
pub struct IommuDomain {
    /// Domain Type
    pub(crate) domain_type: IommuDomainType,
    /// Domain ID
    pub(crate) id: u16,
    /// Second-level page table root (PML4)
    pub(crate) page_table: *mut SlPte,
    /// Mapped regions
    pub(crate) mappings: BTreeMap<u64, DmaMapping>,
    /// Total mapped size
    pub(crate) mapped_size: u64,
    /// Optional NUMA node affinity for this domain's data structures
    pub(crate) numa_node: Option<usize>,
    /// Support for 2MB super-pages
    pub(crate) supports_2mb: bool,
    /// Support for 1GB super-pages
    pub(crate) supports_1gb: bool,
    /// Reference counts for page tables (Physical Address -> Active Entry Count)
    /// Used to avoid O(N) scanning during unmap and recursive deallocation cleanup.
    ///
    /// # Performance Note
    /// Uses BTreeMap for O(log n) lookup. For ~64K entries, this is ~16 comparisons.
    /// For extreme performance requirements (millions of mappings), consider:
    /// - Intrusive reference counting embedded in page table metadata
    /// - Hash map with pre-sized capacity
    /// Current implementation is acceptable for typical IOMMU workloads.
    pub(crate) page_table_counts: BTreeMap<u64, u16>,
    /// Quarantine queue for zero-allocation IOTLB invalidation (Phase 5)
    quarantine: Arc<QuarantineQueue>,
    /// Phase 6: Page table recycling pool (shared with controller)
    page_table_pool: Arc<super::page_table_pool::PageTablePool>,
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
    /// * `domain_type` - Domain type (Strict, Passthrough, etc.)
    /// * `page_table_pool` - Shared page table pool for recycling
    pub fn new(
        id: u16,
        numa_node: Option<usize>,
        supports_2mb: bool,
        supports_1gb: bool,
        domain_type: IommuDomainType,
        page_table_pool: Arc<super::page_table_pool::PageTablePool>,
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

        // Initialize page_table_counts with root table
        let mut page_table_counts = BTreeMap::new();
        let root_phys = virt_ptr_to_phys(page_table as *const u8)
            .expect("Failed to get root page table physical address");
        page_table_counts.insert(root_phys, 0);

        Self {
            id,
            domain_type,
            page_table,
            mappings: BTreeMap::new(),
            mapped_size: 0,
            numa_node,
            supports_2mb,
            supports_1gb,
            page_table_counts,
            quarantine: QuarantineQueue::new(),
            page_table_pool,
        }
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
        self.numa_node
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
    pub fn clear_mapping_only(&mut self, iova: u64, size: u64) -> Result<(), IommuError> {
        // Remove the mapping from our tracking
        let mapping = self.mappings.remove(&iova).ok_or(IommuError::NotMapped)?;

        // Verify size matches
        if mapping.size != size {
            // Put it back if size mismatch
            self.mappings.insert(iova, mapping);
            return Err(IommuError::NotMapped);
        }

        // Clear the page table entries using existing unmap_page method
        let num_pages = size / 4096;
        for i in 0..num_pages {
            let page_iova = iova + i * 4096;
            self.unmap_page(page_iova)?;
        }

        // Update stats
        self.mapped_size = self.mapped_size.saturating_sub(size);

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
    pub fn flush(
        &self,
        invalidator: &dyn IommuInvalidator,
        controller: &super::IommuController,
    ) -> Result<(), IommuError> {
        // Drain pending invalidations (Round 9: returns DrainResult)
        let (drained_batch, requests) = match self.quarantine.drain_pending_invalidations() {
            super::quarantine::DrainResult::NoWork { .. } => return Ok(()),
            super::quarantine::DrainResult::NotReady { batch } => {
                // Round 9 Safety: Reserved slots pending.
                // We MUST NOT issue invalidations or reap, as that would
                // advance the batch prematurely or leave valid PTEs behind.
                // We can optionally log this or return a special error if needed,
                // but for now we just skip the flush.
                return Ok(());
            }
            super::quarantine::DrainResult::Drained { batch, requests } => (batch, requests),
            super::quarantine::DrainResult::Poisoned { .. } => return Err(IommuError::Poisoned),
        };

        // Skip if nothing to flush (double check, though NoWork covers this)
        if requests.is_empty() {
            return Ok(());
        }

        // Process all invalidation requests
        for req in requests {
            invalidator.invalidate(req)?;
        }

        // Reap and process completed entries for this batch
        self.quarantine.reap_completed(drained_batch, controller);

        Ok(())
    }

    /// Map a DMA region
    pub fn map(
        &mut self,
        iova: u64,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        if self.domain_type == IommuDomainType::Passthrough {
            // Passthrough means identity, so map calls are effectively no-ops or identity checks
            // We just return OK.
            // Ideally we could verify iova == phys, but sometimes map is called to *create* the mapping.
            // In PT, it's already there.
            return Ok(());
        }
        // Validate alignment
        if iova & 0xFFF != 0 || phys & 0xFFF != 0 || size & 0xFFF != 0 {
            return Err(IommuError::InvalidAlignment);
        }

        // Check for overlapping mappings
        for (existing_iova, mapping) in &self.mappings {
            let existing_end = existing_iova + mapping.size;
            let new_end = iova + size;

            if iova < existing_end && new_end > *existing_iova {
                return Err(IommuError::AlreadyMapped);
            }
        }

        // Create page table entries using largest possible page sizes
        let mut current_iova = iova;
        let mut current_phys = phys;
        let mut remaining = size;

        const SIZE_1GB: u64 = 1024 * 1024 * 1024;
        const SIZE_2MB: u64 = 2 * 1024 * 1024;
        const SIZE_4KB: u64 = 4096;

        while remaining > 0 {
            // Try 1GB page
            if self.supports_1gb
                && remaining >= SIZE_1GB
                && current_iova % SIZE_1GB == 0
                && current_phys % SIZE_1GB == 0
                && (current_phys as u64 & 0x3FFF_FFFF) == 0
            // Extra alignment check for 1GB
            {
                unsafe { self.map_page_1gb(current_iova, current_phys, read, write) }?;
                current_iova += SIZE_1GB;
                current_phys += SIZE_1GB;
                remaining -= SIZE_1GB;
                continue;
            }

            // Try 2MB page
            if self.supports_2mb
                && remaining >= SIZE_2MB
                && current_iova % SIZE_2MB == 0
                && current_phys % SIZE_2MB == 0
            {
                unsafe { self.map_page_2mb(current_iova, current_phys, read, write) }?;
                current_iova += SIZE_2MB;
                current_phys += SIZE_2MB;
                remaining -= SIZE_2MB;
                continue;
            }

            // Fallback to 4KB page
            self.map_page(current_iova, current_phys, read, write)?;
            current_iova += SIZE_4KB;
            current_phys += SIZE_4KB;
            remaining -= SIZE_4KB;
        }

        // Record mapping
        self.mappings.insert(
            iova,
            DmaMapping {
                iova,
                phys,
                size,
                read,
                write,
                domain_id_placeholder: self.id,
            },
        );

        self.mapped_size += size;

        Ok(())
    }

    /// Map a region with identity mapping (IOVA = Physical Address)
    pub fn map_identity(
        &mut self,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        self.map(phys, phys, size, read, write)
    }

    /// Map a single page using 4-level page table walking
    /// Intel VT-d uses: PML4 -> PDP -> PD -> PT (same as x86-64 paging)
    ///
    /// On error, any newly allocated page tables are deallocated to prevent leaks.
    fn map_page(
        &mut self,
        iova: u64,
        phys: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        // Extract indices for each level
        let pml4_idx = ((iova >> 39) & 0x1FF) as usize; // Bits 47:39
        let pdp_idx = ((iova >> 30) & 0x1FF) as usize; // Bits 38:30
        let pd_idx = ((iova >> 21) & 0x1FF) as usize; // Bits 29:21
        let pt_idx = ((iova >> 12) & 0x1FF) as usize; // Bits 20:12

        // Track newly allocated page tables for rollback via RAII
        // Index 0: PDP, 1: PD, 2: PT (order of allocation)
        let mut newly_allocated: [Option<PageTableScope>; 3] = [None, None, None];

        // self.page_table is the PML4 root
        unsafe {
            // Get pml4 physical address for counting
            let pml4_phys = virt_ptr_to_phys(self.page_table as *const u8)?;

            // Level 4: PML4 -> PDP
            let pml4_entry = self.page_table.add(pml4_idx);
            if !(*pml4_entry).is_present() {
                // Allocate PDP table on the domain's preferred NUMA node when available
                let mut pdp_scope = match self.allocate_page_table() {
                    Ok(s) => s,
                    Err(e) => return Err(e),
                };

                // Attach to parent (writes parent entry)
                pdp_scope.attach_to_parent(pml4_entry, pml4_phys);

                newly_allocated[0] = Some(pdp_scope);
            }
            let pdp_table = (*pml4_entry).phys_addr() as *mut SlPte;
            let pdp_phys = (*pml4_entry).phys_addr();

            // Level 3: PDP -> PD
            let pdp_entry = pdp_table.add(pdp_idx);
            if !(*pdp_entry).is_present() {
                // Allocate PD table on the domain's preferred NUMA node when available
                let mut pd_scope = match self.allocate_page_table() {
                    Ok(s) => s,
                    Err(e) => return Err(e),
                };

                pd_scope.attach_to_parent(pdp_entry, pdp_phys);
                newly_allocated[1] = Some(pd_scope);
            }
            let pd_table = (*pdp_entry).phys_addr() as *mut SlPte;
            let pd_phys = (*pdp_entry).phys_addr();

            // Level 2: PD -> PT
            let pd_entry = pd_table.add(pd_idx);
            if !(*pd_entry).is_present() {
                // Allocate PT on the domain's preferred NUMA node when available
                let mut pt_scope = match self.allocate_page_table() {
                    Ok(s) => s,
                    Err(e) => return Err(e),
                };

                pt_scope.attach_to_parent(pd_entry, pd_phys);
                newly_allocated[2] = Some(pt_scope);
            }
            let pt_table = (*pd_entry).phys_addr() as *mut SlPte;
            let pt_phys = (*pd_entry).phys_addr();

            // Level 1: PT -> Page
            let pt_entry = pt_table.add(pt_idx);
            if (*pt_entry).is_present() {
                return Err(IommuError::AlreadyMapped);
            }

            *pt_entry = SlPte::mapping(phys, read, write);

            // Increment PT count
            *self.page_table_counts.entry(pt_phys).or_default() += 1;

            // Commit newly allocated page tables into accounting
            for slot in newly_allocated.iter_mut() {
                if let Some(scope) = slot {
                    scope.commit(&mut self.page_table_counts);
                }
            }
        }

        Ok(())
    }
    /// Allocate a zeroed page table from the pool (Phase 6)
    ///
    /// Uses the domain's page table pool for NUMA-aware recycling.
    /// Falls back to direct allocation if pool is not available.
    fn allocate_page_table(&self) -> Result<PageTableScope, IommuError> {
        PageTableScope::new_with_pool(self.page_table_pool.clone(), self.numa_node)
    }

    /// Map a 2MB super-page
    ///
    /// Uses 3-level page table walking (PML4 -> PDP -> PD) and sets super-page at PD level.
    /// Both iova and phys must be 2MB-aligned.
    ///
    /// On error, any newly allocated page tables are deallocated to prevent leaks.
    pub unsafe fn map_page_2mb(
        &mut self,
        iova: u64,
        phys: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        const SIZE_2MB: u64 = 2 * 1024 * 1024;

        if iova % SIZE_2MB != 0 || phys % SIZE_2MB != 0 {
            return Err(IommuError::InvalidAddress);
        }

        // Calculate indices for 4-level paging (but stop at PD level for 2MB pages)
        let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
        let pdp_idx = ((iova >> 30) & 0x1FF) as usize;
        let pd_idx = ((iova >> 21) & 0x1FF) as usize;

        // Track newly allocated page tables for rollback via RAII
        // Index 0: PDP, 1: PD
        let mut newly_allocated: [Option<PageTableScope>; 2] = [None, None];

        let pml4_table = self.page_table;
        let pml4_entry = unsafe { pml4_table.add(pml4_idx) };

        // Ensure PDP exists
        if !(unsafe { *pml4_entry }).is_present() {
            let mut pdp_scope = match self.allocate_page_table() {
                Ok(s) => s,
                Err(e) => return Err(e),
            };

            // Attach to parent (writes PML4 entry)
            let pml4_phys = virt_ptr_to_phys(pml4_table as *const u8)?;

            pdp_scope.attach_to_parent(pml4_entry, pml4_phys);
            newly_allocated[0] = Some(pdp_scope);
        }

        let pdp_table = (unsafe { *pml4_entry }).phys_addr() as *mut SlPte;
        let pdp_entry = unsafe { pdp_table.add(pdp_idx) };
        let pdp_phys = (unsafe { *pml4_entry }).phys_addr();

        // Ensure PD exists
        if !(unsafe { *pdp_entry }).is_present() {
            let mut pd_scope = match self.allocate_page_table() {
                Ok(s) => s,
                Err(e) => return Err(e),
            };

            pd_scope.attach_to_parent(pdp_entry, pdp_phys);
            newly_allocated[1] = Some(pd_scope);
        } else if (unsafe { *pdp_entry }).is_super_page() {
            // Already a 1GB super-page at this level
            return Err(IommuError::AlreadyMapped);
        }

        let pd_table = (unsafe { *pdp_entry }).phys_addr() as *mut SlPte;
        let pd_entry = unsafe { pd_table.add(pd_idx) };
        let pd_phys = (unsafe { *pdp_entry }).phys_addr();

        // Check if already mapped
        if (unsafe { *pd_entry }).is_present() {
            // If a mapping already exists, let RAII (PageTableScope Drop) roll back any
            // newly allocated page tables and return an error.
            return Err(IommuError::AlreadyMapped);
        }

        // Create 2MB super-page entry
        unsafe { *pd_entry = SlPte::super_page_2mb(phys, read, write) };
        // Increment PD count (valid entry)
        *self.page_table_counts.entry(pd_phys).or_default() += 1;

        // Commit any newly allocated page tables into accounting
        for slot in newly_allocated.iter_mut() {
            if let Some(scope) = slot {
                scope.commit(&mut self.page_table_counts);
            }
        }

        Ok(())
    }

    /// Map a 1GB super-page
    ///
    /// Uses 2-level page table walking (PML4 -> PDP) and sets super-page at PDP level.
    /// Both iova and phys must be 1GB-aligned.
    ///
    /// On error, any newly allocated page tables are deallocated to prevent leaks.
    pub unsafe fn map_page_1gb(
        &mut self,
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

        // Ensure PDP exists
        if !(unsafe { *pml4_entry }).is_present() {
            let mut pdp_scope = match self.allocate_page_table() {
                Ok(s) => s,
                Err(e) => {
                    return Err(e);
                }
            };

            // Attach to parent (writes PML4 entry)
            let pml4_phys = virt_ptr_to_phys(pml4_table as *const u8)?;

            pdp_scope.attach_to_parent(pml4_entry, pml4_phys);
            newly_allocated_pdp = Some(pdp_scope);
        }

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
        unsafe { *pdp_entry = SlPte::super_page_1gb(phys, read, write) };
        // Increment PDP count
        *self.page_table_counts.entry(pdp_phys).or_default() += 1;

        // Commit newly allocated PDP if any
        if let Some(scope) = newly_allocated_pdp.as_mut() {
            scope.commit(&mut self.page_table_counts);
        }

        Ok(())
    }

    /// Unmap a DMA region
    pub fn unmap(&mut self, iova: u64) -> Result<DmaMapping, IommuError> {
        let mapping = self.mappings.remove(&iova).ok_or(IommuError::NotMapped)?;

        // Clear page table entries
        let num_pages = mapping.size / 4096;
        for i in 0..num_pages {
            let page_iova = iova + i * 4096;
            self.unmap_page(page_iova)?;
        }

        self.mapped_size -= mapping.size;

        Ok(mapping)
    }

    /// Unmap a single page using 4-level page table walking
    ///
    /// Also reclaims empty page tables (PT, PD, PDP) to prevent memory accumulation
    /// from sparse mappings.
    fn unmap_page(&mut self, iova: u64) -> Result<(), IommuError> {
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
            if let Some(count) = self.page_table_counts.get_mut(&pt_phys) {
                *count -= 1;
                if *count == 0 {
                    // Free PT
                    *pd_entry = SlPte::new();
                    alloc::alloc::dealloc(pt_table as *mut u8, layout);
                    self.page_table_counts.remove(&pt_phys);

                    // Decrement PD count
                    if let Some(pd_count) = self.page_table_counts.get_mut(&pd_phys) {
                        *pd_count -= 1;
                        if *pd_count == 0 {
                            // Free PD
                            *pdp_entry = SlPte::new();
                            alloc::alloc::dealloc(pd_table as *mut u8, layout);
                            self.page_table_counts.remove(&pd_phys);

                            // Decrement PDP count
                            if let Some(pdp_count) = self.page_table_counts.get_mut(&pdp_phys) {
                                *pdp_count -= 1;
                                if *pdp_count == 0 {
                                    // Free PDP
                                    *pml4_entry = SlPte::new();
                                    alloc::alloc::dealloc(pdp_table as *mut u8, layout);
                                    self.page_table_counts.remove(&pdp_phys);

                                    // Decrement PML4 count (root)
                                    let pml4_phys = virt_ptr_to_phys(self.page_table as *const u8)
                                        .expect("Failed to get pml4 phys");
                                    if let Some(pml4_count) =
                                        self.page_table_counts.get_mut(&pml4_phys)
                                    {
                                        *pml4_count -= 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Get total mapped size
    pub fn mapped_size(&self) -> u64 {
        self.mapped_size
    }

    /// Get all mappings
    pub fn mappings(&self) -> &BTreeMap<u64, DmaMapping> {
        &self.mappings
    }

    // =========================================================================
    // DmaHandle Integration
    // =========================================================================

    /// Map an RRef for DMA access
    ///
    /// This method:
    /// 1. Gets the physical address from the RRef
    /// 2. Allocates an IOVA from the controller
    /// 3. Creates page table mappings
    /// 4. Returns a DmaHandle that tracks ownership
    ///
    /// # Arguments
    /// * `rref` - The RRef to map (consumed)
    /// * `controller` - The IOMMU controller for IOVA allocation
    /// * `direction` - DMA transfer direction
    ///
    /// # Errors
    /// Returns `MapError<T>` containing the original RRef on failure.
    pub fn map_buffer<T>(
        &mut self,
        rref: crate::ipc::RRef<T>,
        controller: &super::IommuController,
        direction: super::dma_handle::DmaDirection,
    ) -> Result<super::dma_handle::DmaHandle<T>, super::dma_handle::MapError<T>> {
        use super::dma_handle::{DmaHandle, MapError, MapErrorKind};
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

        // Allocate IOVA from controller
        let iova = match controller.allocate_iova(aligned_size) {
            Ok(addr) => addr,
            Err(e) => return Err(MapError::new(rref, MapErrorKind::IommuError(e))),
        };

        // Determine permissions from direction
        let (read, write) = match direction {
            super::dma_handle::DmaDirection::ToDevice => (true, false),
            super::dma_handle::DmaDirection::FromDevice => (false, true),
            super::dma_handle::DmaDirection::Bidirectional => (true, true),
        };

        // Create page table mappings
        if let Err(e) = self.map(iova, phys, aligned_size, read, write) {
            // Mapping failed - free IOVA and return error with RRef
            let _ = controller.free_iova(iova, aligned_size);
            return Err(MapError::new(rref, MapErrorKind::IommuError(e)));
        }

        // Success - create DmaHandle
        Ok(DmaHandle::new(rref, iova, phys, size, self.id, direction))
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
    /// * `controller` - The IOMMU controller for IOVA deallocation
    /// * `invalidator` - Optional invalidator for IOTLB flush
    ///
    /// # Errors
    /// Returns `UnmapError<T>` containing the handle on failure.
    pub fn unmap_buffer<T>(
        &mut self,
        mut handle: super::dma_handle::DmaHandle<T>,
        controller: &super::IommuController,
        invalidator: Option<&dyn IommuInvalidator>,
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

        // Invalidate IOTLB if invalidator provided
        if let Some(inv) = invalidator {
            let req = InvalidateRequest::pages(self.id, iova, aligned_size);
            if let Err(e) = inv.invalidate(req) {
                // IOTLB invalidation failed - this is critical!
                // We can't return the RRef because device may still access it
                return Err(UnmapError::new(handle, UnmapErrorKind::IommuError(e)));
            }
        }

        // Free IOVA
        if let Err(e) = controller.free_iova(iova, aligned_size) {
            // IOVA free failed - log but continue since mapping is already removed
            log::warn!("[IommuDomain] IOVA free failed for 0x{:x}: {:?}", iova, e);
        }

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
    /// * `controller` - The IOMMU controller for IOVA deallocation
    /// * `invalidator` - Invalidator for async IOTLB flush
    ///
    /// # Returns
    /// A future that resolves to `Result<RRef<T>, UnmapError<T>>`
    pub async fn unmap_buffer_async<T>(
        &mut self,
        mut handle: super::dma_handle::DmaHandle<T>,
        controller: &super::IommuController,
        invalidator: &(dyn IommuInvalidator + Sync),
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
        if let Err(e) = controller.free_iova(iova, aligned_size) {
            log::warn!("[IommuDomain] IOVA free failed for 0x{:x}: {:?}", iova, e);
        }

        // Take the RRef from the handle (marks it as unmapped)
        match handle.take_rref() {
            Some(rref) => Ok(rref),
            None => Err(UnmapError::new(handle, UnmapErrorKind::InvalidIova)),
        }
    }

    /// Recursively deallocate all page tables under the given table (iterative version)
    ///
    /// Note: This now relies on `page_table_counts` (BTreeMap) to know which pages are allocated tables.
    /// This avoids tree walking and stack overflow risks entirely.
    /// It effectively becomes "free all tables tracked by this domain".
    ///
    /// # Safety
    /// - The domain must not be in use by hardware (IOMMU disabled or domain detached)
    unsafe fn deallocate_page_tables_iterative(&mut self) {
        // Free all tables tracked in the counts map
        // We iterate keys (Physical Addresses), convert to Virtual, and dealloc.
        // Since we are destroying the domain, we just free everything.
        // We must be careful not to double free if logic is flawed, but map guarantees uniqueness.
        // Also, we skip the root table if it's managed by IommuDomain itself (which it is).
        // Wait, `IommuDomain::new` allocates `page_table`. `Drop` (or callers) should free it.
        // If we free everything in `page_table_counts`, we free the root too.
        // Callers must be aware.

        let layout =
            alloc::alloc::Layout::from_size_align(PT_ENTRIES * core::mem::size_of::<SlPte>(), 4096)
                .expect("invalid page table layout");

        for &phys_addr in self.page_table_counts.keys() {
            let virt_addr = phys_to_virt_usize(phys_addr) as u64;

            let ptr = virt_addr as *mut u8;
            // Don't free the root table if `IommuDomain` logic expects to free it separately?
            // `IommuDomain` stores `page_table` pointer.
            // If we free it here, `IommuDomain` should not free it again.
            // `IommuDomain` struct doesn't implement Drop yet, but usually `deallocate_page_table_recursive` was called manually.

            unsafe {
                alloc::alloc::dealloc(ptr, layout);
            }
        }
        self.page_table_counts.clear();
    }
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
