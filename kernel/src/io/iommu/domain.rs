// ============================================================================
// kernel/src/io/iommu/domain.rs
// ============================================================================
use super::interface::IommuHardwareContext;
use super::page_table_pool::{dec_ref, inc_ref, register_page_table, unregister_page_table};
use super::quarantine::QuarantineQueue;
use super::tables::{
    PT_ENTRIES, PT_LEVELS, PageTableScope, SlPte, phys_to_virt_usize, virt_ptr_to_phys,
};
use super::types::{DmaMapping, IommuDomainType, IommuError, PteFormat};
use crate::io::iommu::amd::tables::AmdPte;
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
    async fn invalidate_async(&self, request: InvalidateRequest) -> Result<(), IommuError> {
        self.invalidate(request)
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
    /// Maximum address width (in bits) supported for IOVA/physical addresses
    pub(crate) max_addr_bits: u8,
    /// Quarantine queue for zero-allocation IOTLB invalidation (Phase 5)
    quarantine: Arc<QuarantineQueue>,
    /// Reused buffer for flush invalidations (avoid per-flush allocations)
    flush_requests: Vec<InvalidateRequest>,
    /// Phase 6: Page table recycling pool (shared with controller)
    page_table_pool: Arc<super::page_table_pool::PageTablePool>,
    /// PTE format (Intel or AMD)
    pte_format: PteFormat,
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

        Self {
            id,
            domain_type,
            page_table,
            mappings: BTreeMap::new(),
            mapped_size: 0,
            numa_node,
            supports_2mb,
            supports_1gb,
            max_addr_bits: max_addr_bits.clamp(1, 64),
            quarantine: QuarantineQueue::new(),
            flush_requests: Vec::with_capacity(super::quarantine::INVALIDATION_CAPACITY),
            page_table_pool,
            pte_format,
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

        if self.domain_type != IommuDomainType::Passthrough {
            self.unmap_range(iova, size)?;
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
    ///
    /// # Context
    ///
    /// Must be called from thread/executor context. This path allocates and
    /// drops RRef raw parts via the quarantine reap.
    pub fn flush<I: IommuInvalidator>(
        &mut self,
        invalidator: &I,
        context: &dyn IommuHardwareContext,
    ) -> Result<(), IommuError> {
        // Drain pending invalidations (Round 9: returns DrainResult)
        let requests = &mut self.flush_requests;
        let drained_batch = match self.quarantine.drain_pending_invalidations(requests) {
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

        // Process all invalidation requests
        for req in requests.drain(..) {
            invalidator.invalidate(req)?;
        }

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

    /// Map a DMA region
    ///
    /// This function is transactional: if any page mapping fails, all successfully
    /// mapped pages are rolled back before returning the error.
    pub fn map(
        &mut self,
        iova: u64,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        if self.domain_type == IommuDomainType::Passthrough {
            // Passthrough means identity, so map calls are page-table no-ops.
            // We still track mappings for ownership/unmap bookkeeping.
        }
        // Validate alignment
        if iova & 0xFFF != 0 || phys & 0xFFF != 0 || size & 0xFFF != 0 {
            return Err(IommuError::InvalidAlignment);
        }

        if !self.within_addr_width(iova, size) || !self.within_addr_width(phys, size) {
            return Err(IommuError::InvalidAddress);
        }

        // Check for overlapping mappings using range queries (O(log n))
        let new_end = iova.checked_add(size).ok_or(IommuError::InvalidAddress)?;
        if let Some((&existing_iova, mapping)) = self.mappings.range(..=iova).next_back() {
            if existing_iova + mapping.size > iova {
                return Err(IommuError::AlreadyMapped);
            }
        }
        if let Some((&existing_iova, _)) = self.mappings.range(iova..).next() {
            if existing_iova < new_end {
                return Err(IommuError::AlreadyMapped);
            }
        }

        if self.domain_type == IommuDomainType::Passthrough {
            // Track mapping even in passthrough domains.
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
            return Ok(());
        }

        // Create page table entries using largest possible page sizes
        let mut current_iova = iova;
        let mut current_phys = phys;
        let mut remaining = size;

        const SIZE_1GB: u64 = 1024 * 1024 * 1024;
        const SIZE_2MB: u64 = 2 * 1024 * 1024;
        const SIZE_4KB: u64 = 4096;

        // Track total bytes successfully mapped for rollback on error
        let start_iova = iova;
        let mut mapped_len: u64 = 0;

        while remaining > 0 {
            // Try 1GB page
            if self.supports_1gb
                && remaining >= SIZE_1GB
                && current_iova % SIZE_1GB == 0
                && current_phys % SIZE_1GB == 0
                && (current_phys as u64 & 0x3FFF_FFFF) == 0
            // Extra alignment check for 1GB
            {
                match unsafe { self.map_page_1gb(current_iova, current_phys, read, write) } {
                    Ok(()) => {
                        current_iova += SIZE_1GB;
                        current_phys += SIZE_1GB;
                        remaining -= SIZE_1GB;
                        mapped_len += SIZE_1GB;
                        continue;
                    }
                    Err(e) => {
                        // Rollback all successfully mapped pages
                        if mapped_len > 0 {
                            if let Err(rollback_err) = self.unmap_range(start_iova, mapped_len) {
                                log::error!(
                                    "[IommuDomain] rollback failed after map error: {:?} (rollback: {:?})",
                                    e,
                                    rollback_err
                                );
                                return Err(rollback_err);
                            }
                        }
                        return Err(e);
                    }
                }
            }

            // Try 2MB page
            if self.supports_2mb
                && remaining >= SIZE_2MB
                && current_iova % SIZE_2MB == 0
                && current_phys % SIZE_2MB == 0
            {
                match unsafe { self.map_page_2mb(current_iova, current_phys, read, write) } {
                    Ok(()) => {
                        current_iova += SIZE_2MB;
                        current_phys += SIZE_2MB;
                        remaining -= SIZE_2MB;
                        mapped_len += SIZE_2MB;
                        continue;
                    }
                    Err(e) => {
                        // Rollback all successfully mapped pages
                        if mapped_len > 0 {
                            if let Err(rollback_err) = self.unmap_range(start_iova, mapped_len) {
                                log::error!(
                                    "[IommuDomain] rollback failed after map error: {:?} (rollback: {:?})",
                                    e,
                                    rollback_err
                                );
                                return Err(rollback_err);
                            }
                        }
                        return Err(e);
                    }
                }
            }

            // Fallback to 4KB pages (batch within a single PT)
            let pages_remaining = (remaining / SIZE_4KB) as usize;
            let pt_idx = ((current_iova >> 12) & 0x1FF) as usize;
            let pages_in_pt = core::cmp::min(pages_remaining, PT_ENTRIES - pt_idx);

            match self.map_range_4k(current_iova, current_phys, pages_in_pt, read, write) {
                Ok(pages_mapped) => {
                    let mapped_bytes = (pages_mapped as u64) * SIZE_4KB;
                    current_iova += mapped_bytes;
                    current_phys += mapped_bytes;
                    remaining -= mapped_bytes;
                    mapped_len += mapped_bytes;
                }
                Err(e) => {
                    // Rollback all successfully mapped pages
                    if mapped_len > 0 {
                        if let Err(rollback_err) = self.unmap_range(start_iova, mapped_len) {
                            log::error!(
                                "[IommuDomain] rollback failed after map error: {:?} (rollback: {:?})",
                                e,
                                rollback_err
                            );
                            return Err(rollback_err);
                        }
                    }
                    return Err(e);
                }
            }
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

    /// Unmap a 2MB super-page (for rollback)
    fn unmap_super_page_2mb(&mut self, iova: u64) -> Result<(), IommuError> {
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
    fn unmap_super_page_1gb(&mut self, iova: u64) -> Result<(), IommuError> {
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
    pub fn map_identity(
        &mut self,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        self.map(phys, phys, size, read, write)
    }

    /// Map a contiguous run of 4KB pages within a single PT.
    fn map_range_4k(
        &mut self,
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

        let mut newly_allocated: [Option<PageTableScope>; 3] = [None, None, None];

        unsafe {
            let pml4_phys = virt_ptr_to_phys(self.page_table as *const u8)?;
            let pml4_entry = self.page_table.add(pml4_idx);

            if !(*pml4_entry).is_present() {
                let mut pdp_scope = self.allocate_page_table()?;
                pdp_scope.attach_to_parent(pml4_entry, pml4_phys, self.pte_format, 3);
                newly_allocated[0] = Some(pdp_scope);
            }

            let pdp_table = (*pml4_entry).phys_addr() as *mut SlPte;
            let pdp_phys = (*pml4_entry).phys_addr();

            let pdp_entry = pdp_table.add(pdp_idx);
            if !(*pdp_entry).is_present() {
                let mut pd_scope = self.allocate_page_table()?;
                pd_scope.attach_to_parent(pdp_entry, pdp_phys, self.pte_format, 2);
                newly_allocated[1] = Some(pd_scope);
            } else if (*pdp_entry).is_super_page(self.pte_format) {
                return Err(IommuError::AlreadyMapped);
            }

            let pd_table = (*pdp_entry).phys_addr() as *mut SlPte;
            let pd_phys = (*pdp_entry).phys_addr();

            let pd_entry = pd_table.add(pd_idx);
            if !(*pd_entry).is_present() {
                let mut pt_scope = self.allocate_page_table()?;
                pt_scope.attach_to_parent(pd_entry, pd_phys, self.pte_format, 1);
                newly_allocated[2] = Some(pt_scope);
            } else if (*pd_entry).is_super_page(self.pte_format) {
                return Err(IommuError::AlreadyMapped);
            }

            let pt_table = (*pd_entry).phys_addr() as *mut SlPte;
            let pt_phys = (*pd_entry).phys_addr();
            let pages_in_pt = core::cmp::min(pages, PT_ENTRIES - pt_idx);

            if newly_allocated[2].is_none() {
                for idx in 0..pages_in_pt {
                    let pt_entry = pt_table.add(pt_idx + idx);
                    if (*pt_entry).is_present() {
                        return Err(IommuError::AlreadyMapped);
                    }
                }
            }

            for idx in 0..pages_in_pt {
                let pt_entry = pt_table.add(pt_idx + idx);
                let entry_phys = phys + (idx as u64 * SIZE_4KB);
                match self.pte_format {
                    PteFormat::Intel => {
                        *pt_entry = SlPte::mapping(entry_phys, read, write);
                    }
                    PteFormat::Amd => {
                        let amd_pte = AmdPte::mapping(entry_phys, read, write, 0);
                        *pt_entry = SlPte(amd_pte.0);
                    }
                }
            }

            for scope in newly_allocated.iter_mut() {
                if let Some(scope) = scope {
                    scope.commit();
                }
            }

            for _ in 0..pages_in_pt {
                inc_ref(pt_phys);
            }

            Ok(pages_in_pt)
        }
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
                // We are attaching a PDP (Level 3 table) to PML4
                pdp_scope.attach_to_parent(pml4_entry, pml4_phys, self.pte_format, 3);

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

                // We are attaching a PD (Level 2 table) to PDP
                pd_scope.attach_to_parent(pdp_entry, pdp_phys, self.pte_format, 2);
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

                // We are attaching a PT (Level 1 table) to PD
                pt_scope.attach_to_parent(pd_entry, pd_phys, self.pte_format, 1);
                newly_allocated[2] = Some(pt_scope);
            }
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
                    let amd_pte = AmdPte::mapping(phys, read, write, 0); // Level 1 = 4KB
                    *pt_entry = SlPte(amd_pte.0); // Transmute to SlPte for storage
                }
            }

            // Increment PT count
            inc_ref(pt_phys);

            // Commit newly allocated page tables into accounting
            for slot in newly_allocated.iter_mut() {
                if let Some(scope) = slot {
                    scope.commit();
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

            // Attach to parent (writes PML4 entry)
            // Attaching PDP (Level 3) to PML4
            pdp_scope.attach_to_parent(pml4_entry, pml4_phys, self.pte_format, 3);
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

            pd_scope.attach_to_parent(pdp_entry, pdp_phys, self.pte_format, 2);
            newly_allocated[1] = Some(pd_scope);
        } else if (unsafe { *pdp_entry }).is_super_page(self.pte_format) {
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
        match self.pte_format {
            PteFormat::Intel => unsafe { *pd_entry = SlPte::super_page_2mb(phys, read, write) },
            PteFormat::Amd => {
                // For AMD, 2MB page is at Level 2 (PD). Next Level field (9-11) should be 0.
                // Level 2 entry -> Next Level 0 -> Maps 2MB page
                let amd_pte = AmdPte::mapping(phys, read, write, 0); // Mapping creates leaf (Next Level 0)
                unsafe { *pd_entry = SlPte(amd_pte.0) };
            }
        }
        // Increment PD count (valid entry)
        inc_ref(pd_phys);

        // Commit any newly allocated page tables into accounting
        for slot in newly_allocated.iter_mut() {
            if let Some(scope) = slot {
                scope.commit();
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

            // Attaching PDP (Level 3) to PML4
            pdp_scope.attach_to_parent(pml4_entry, pml4_phys, self.pte_format, 3);
            newly_allocated_pdp = Some(pdp_scope);
        } else if (unsafe { *pml4_entry }).is_super_page(self.pte_format) {
            // PML4 entry cannot be a super page in 4-level paging (512GB pages not supported)
            // But if it were, we should fail.
            // Actually, PML4 entries point to PDP. If "is_super_page" is true, it means generic mismatch?
            // Intel Bit 7 in PML4 entry matches 'Reserved'? Or 'Page Size'?
            // For safety we can check.
            return Err(IommuError::AlreadyMapped);
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

    /// Unmap a DMA region
    pub fn unmap(&mut self, iova: u64) -> Result<DmaMapping, IommuError> {
        let mapping = self.mappings.remove(&iova).ok_or(IommuError::NotMapped)?;

        if self.domain_type != IommuDomainType::Passthrough {
            self.unmap_range(iova, mapping.size)?;
        }

        self.mapped_size -= mapping.size;

        Ok(mapping)
    }

    /// Unmap a range using super-page aware traversal.
    fn unmap_range(&mut self, iova: u64, size: u64) -> Result<(), IommuError> {
        let mut current = iova;
        let mut remaining = size;

        while remaining > 0 {
            let unmapped = self.unmap_entry(current)?;
            if unmapped > remaining {
                return Err(IommuError::InvalidAlignment);
            }
            current += unmapped;
            remaining -= unmapped;
        }

        Ok(())
    }

    /// Unmap a single entry at `iova` and return the unmapped size.
    fn unmap_entry(&mut self, iova: u64) -> Result<u64, IommuError> {
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
        &mut self,
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

        // Allocate IOVA from context
        let iova = match context.allocate_iova(aligned_size) {
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
            let _ = context.free_iova(iova, aligned_size);
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
        &mut self,
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

        // Free IOVA
        if let Err(e) = context.free_iova(iova, aligned_size) {
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
    /// * `context` - The IOMMU context for IOVA deallocation
    /// * `invalidator` - Invalidator for async IOTLB flush
    ///
    /// # Returns
    /// A future that resolves to `Result<RRef<T>, UnmapError<T>>`
    pub async fn unmap_buffer_async<T, I: IommuInvalidator + Sync>(
        &mut self,
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

    /// Recursively deallocate all page tables under the given table.
    ///
    /// Uses a bounded recursion depth (4 levels) to avoid heap allocation in Drop.
    ///
    /// # Safety
    /// - The domain must not be in use by hardware (IOMMU disabled or domain detached)
    unsafe fn deallocate_page_tables_iterative(&mut self) {
        let layout =
            alloc::alloc::Layout::from_size_align(PT_ENTRIES * core::mem::size_of::<SlPte>(), 4096)
                .expect("invalid page table layout");

        unsafe fn free_table(
            domain: &IommuDomain,
            table_ptr: *mut SlPte,
            level: usize,
            layout: alloc::alloc::Layout,
        ) {
            if level > 1 {
                for idx in 0..PT_ENTRIES {
                    let entry = *table_ptr.add(idx);
                    if !entry.is_present() {
                        continue;
                    }
                    if (level == 3 || level == 2) && entry.is_super_page(domain.pte_format) {
                        continue;
                    }
                    let child_phys = entry.phys_addr();
                    let child_ptr = phys_to_virt_usize(child_phys) as *mut SlPte;
                    free_table(domain, child_ptr, level - 1, layout);
                }
            }

            if let Ok(phys) = virt_ptr_to_phys(table_ptr as *const u8) {
                unregister_page_table(phys);
            }
            alloc::alloc::dealloc(table_ptr as *mut u8, layout);
        }

        free_table(self, self.page_table, PT_LEVELS, layout);
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
