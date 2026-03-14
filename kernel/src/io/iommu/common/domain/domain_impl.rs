// ============================================================================
// kernel/src/io/iommu/common/domain/domain_impl.rs
// ============================================================================

use super::*;

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
    /// * `pt_levels` - Second-level page table depth (2..=5)
    /// * `domain_type` - Domain type (Strict, Passthrough, etc.)
    /// * `page_table_pool` - Shared page table pool for recycling
    pub fn new(
        id: u16,
        numa_node: Option<usize>,
        supports_2mb: bool,
        supports_1gb: bool,
        max_addr_bits: u8,
        pt_levels: u8,
        domain_type: IommuDomainType,
        page_table_pool: Arc<crate::io::iommu::common::dma::page_table_pool::PageTablePool>,
        pte_format: PteFormat,
    ) -> Self {
        let pt_levels = pt_levels.clamp(MIN_PT_LEVELS, MAX_PT_LEVELS);
        // Allocate page table on the preferred NUMA node when possible.
        // For Passthrough, we still allocate it to simplify logic (or we could skip it)
        // But the hardware won't use it if we set TT=Passthrough.
        // Let's allocate it to avoid null pointer checks elsewhere, or make it Option.
        // For now: Allocate it.
        let layout =
            alloc::alloc::Layout::from_size_align(PT_ENTRIES * core::mem::size_of::<SlPte>(), 4096)
                .expect("Invalid layout for page table");

        let page_table = crate::mm::numa::topology::allocate_zeroed_on_node(layout, numa_node)
            .expect("Failed to allocate IOMMU page table")
            .as_ptr() as *mut SlPte;

        let root_phys = virt_ptr_to_phys(page_table as *const u8)
            .expect("Failed to get root page table physical address");

        // Security: Register and protect the root page table IMMEDIATELY after allocation.
        register_page_table(root_phys, page_table as usize, numa_node.unwrap_or(0));

        debug_assert_eq!(PT_ENTRIES % DOMAIN_SHARD_COUNT, 0);
        debug_assert!(PML4_ENTRIES_PER_SHARD > 0);
        let mut shards = Vec::with_capacity(DOMAIN_SHARD_COUNT);
        for _i in 0..DOMAIN_SHARD_COUNT {
            shards.push(PoisonLock::new(DomainShard::new()));
        }

        let (default_iova_base, default_iova_size) = if cfg!(feature = "qemu-test-export") {
            // Keep qemu migration suites deterministic under their fixed bump allocator.
            (0x1_0000_0000, 0x1000_0000) // 4GB base, 256MB window
        } else {
            (0x1_0000_0000, 0x8_0000_0000) // 4GB base, 32GB window
        };
        let per_domain_iova = crate::io::iommu::common::dma::iova_allocator::IovaAllocator::new(
            default_iova_base,
            default_iova_size,
        );

        let new_domain = Self {
            id,
            domain_type,
            page_table,
            page_table_phys: root_phys,
            shards: shards.into_boxed_slice(),
            mapped_size: AtomicU64::new(0),
            numa_node: RwLock::new(numa_node),
            supports_2mb: supports_2mb && pt_levels >= 2,
            supports_1gb: supports_1gb && pt_levels >= 3,
            max_addr_bits: max_addr_bits.clamp(1, 64),
            pt_levels,
            quarantine: QuarantineQueue::new(),
            // Pre-allocated contexts for zero-allocation flush (Phase 5)
            // CRITICAL: This capacity must never be exceeded. The quarantine's
            // drain_pending_invalidations() asserts this in debug builds.
            flush_context: PoisonLock::new(
                crate::io::iommu::runtime::quarantine::FlushContext::new(),
            ),
            page_table_pool,
            pte_format,
            security_notifier: Once::new(),
            poisoned: AtomicBool::new(false),
            // Per-domain IOVA allocator: Default 256GB space starting at 4GB
            // Avoids low addresses (reserved for 32-bit legacy devices) and
            // provides ample space for typical workloads.
            // Uses the bitmap-based IovaAllocator with O(1) magazine allocation.
            per_domain_iova,
            dma_registry: DmaResourceRegistry::new(),
            pending_pt_release: PoisonLock::new(Vec::new()),
            paging_lock: IrqMutex::new(()),
        };
        new_domain
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
    /// * `pt_levels` - Second-level page table depth (2..=5)
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
        pt_levels: u8,
        domain_type: IommuDomainType,
        page_table_pool: Arc<crate::io::iommu::common::dma::page_table_pool::PageTablePool>,
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
            pt_levels,
            domain_type,
            page_table_pool,
            pte_format,
        );

        // Override with custom IOVA range
        domain.per_domain_iova =
            crate::io::iommu::common::dma::iova_allocator::IovaAllocator::new(iova_base, iova_size);

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
    /// Uses IovaAllocator with O(1) per-CPU magazine allocation.
    /// All domains have their own IOVA allocator, eliminating lock contention.
    #[inline]
    pub fn allocate_iova(&self, size: u64) -> Result<u64, crate::io::iommu::types::IommuError> {
        use crate::io::iommu::common::dma::iova_allocator::PageGranularity;

        // IovaAllocator is internally lock-free for common paths
        self.per_domain_iova
            .allocate(size, PageGranularity::Page4K)
            .ok_or(crate::io::iommu::types::IommuError::OutOfIova)
    }

    /// Free IOVA back to this domain's allocator.
    ///
    /// Uses IovaAllocator with O(1) per-CPU magazine deallocation.
    #[inline]
    pub fn free_iova(
        &self,
        iova: u64,
        size: u64,
    ) -> Result<(), crate::io::iommu::types::IommuError> {
        // IovaAllocator is internally lock-free for common paths
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
    pub fn unregister_dma_mapping(
        &self,
        iova: u64,
    ) -> Result<Option<DmaRegistryEntry>, IommuError> {
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
        self.page_table_phys
    }

    /// Get optional NUMA node affinity for this domain
    pub fn numa_node(&self) -> Option<usize> {
        *self.numa_node.read()
    }

    /// Set domain NUMA affinity hint
    pub fn set_numa_node(&self, numa_node: Option<usize>) {
        *self.numa_node.write() = numa_node;
    }
}

// ============================================================================
// Phase 7: IommuHardwareContext implementation for IommuDomain
// ============================================================================

impl crate::io::iommu::common::interface::IommuHardwareContext for IommuDomain {
    fn allocate_iova_aligned(&self, size: u64, alignment: u64) -> Result<u64, IommuError> {
        use crate::io::iommu::common::dma::iova_allocator::PageGranularity;

        // Map alignment to granularity
        let granularity = if alignment >= 1024 * 1024 * 1024 {
            PageGranularity::Page1G
        } else if alignment >= 2 * 1024 * 1024 {
            PageGranularity::Page2M
        } else {
            PageGranularity::Page4K
        };

        self.per_domain_iova
            .allocate(size, granularity)
            .ok_or(IommuError::OutOfIova)
    }

    fn allocate_iova_masked(
        &self,
        size: u64,
        _alignment: u64,
        mask: u64,
    ) -> Result<u64, IommuError> {
        use crate::io::iommu::common::dma::iova_allocator::PageGranularity;

        self.per_domain_iova
            .allocate_with_limit(size, PageGranularity::Page4K, mask)
            .ok_or(IommuError::OutOfIova)
    }

    fn free_iova(&self, iova: u64, size: u64) -> Result<(), IommuError> {
        // SECURITY: For domain-local IOVA free, we MUST NOT use immediate free
        // if this path can be called from outside flush().
        // However, IommuDomain mostly uses its internal QuarantineQueue for unmaps.
        // If this is called, we default to the allocator's internal quarantine
        // to be safe against IOTLB Use-After-Free.
        self.per_domain_iova.free(iova, size)
    }

    fn free_iova_immediate(&self, iova: u64, size: u64) -> Result<(), IommuError> {
        // Since caller guarantees IOTLB consistency (flush confirmed),
        // we can safely bypass the redundant allocator quarantine.
        // IovaAllocator::free_immediate handles the splitting of ranges.
        self.per_domain_iova.free_immediate(iova, size)
    }
}

impl IommuDomain {
    /// Attach a security notifier for fatal domain errors (best-effort, one-time).
    pub(crate) fn set_security_notifier(&self, notifier: Arc<dyn SecurityNotifier>) -> bool {
        let mut set = false;
        self.security_notifier.call_once(|| {
            set = true;
            notifier
        });
        set
    }

    pub(super) fn notify_security(&self, event: SecurityEvent) {
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
    pub(super) fn verify_and_lock_for_clear(
        &self,
        iova: u64,
        size: u64,
    ) -> Result<
        (
            DmaMapping,
            Vec<crate::sync::PoisonLockGuard<'_, DomainShard>>,
        ),
        IommuError,
    > {
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

        // SECURITY: Unregister from resource registry to maintain consistency.
        let _ = self.dma_registry.unregister(iova);

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
        _context: &dyn IommuHardwareContext,
    ) -> Result<(), IommuError> {
        let mut fctx = self
            .flush_context
            .lock()
            .map_err(|_| IommuError::Poisoned)?;

        fctx.clear();

        // 1. Drain pending data page invalidations from quarantine
        let drained_batch = match self
            .quarantine
            .drain_pending_invalidations(&mut fctx.requests)
        {
            crate::io::iommu::runtime::quarantine::DrainResult::Drained { batch } => Some(batch),
            crate::io::iommu::runtime::quarantine::DrainResult::NoWork { .. } => None,
            crate::io::iommu::runtime::quarantine::DrainResult::NotReady { batch: _ } => {
                // Round 9 Safety: Reserved slots pending. Skip for now.
                return Ok(());
            }
            crate::io::iommu::runtime::quarantine::DrainResult::Poisoned { .. } => {
                return Err(IommuError::Poisoned);
            }
        };

        // 2. Check if we have any empty page tables pending release
        let has_pending_pts = if let Ok(pending) = self.pending_pt_release.lock() {
            !pending.is_empty()
        } else {
            false
        };

        // Skip if absolutely nothing to do
        if drained_batch.is_none() && !has_pending_pts {
            return Ok(());
        }

        // 3. Security: If we are releasing page tables, we MUST perform a domain-selective
        // IOTLB invalidation to clear any cached paging-structure entries (Level 2/3/4 caches).
        // Page-selective invalidation is NOT sufficient for clearing intermediate caches.
        if has_pending_pts {
            fctx.requests
                .push(InvalidateRequest::domain(self.id).with_ats());
        }

        // 4. Process all invalidation requests in a single batch (hardware-optimized)
        if !fctx.requests.is_empty() {
            if let Err(err) = invalidator.process_invalidations(fctx.requests.as_slice()) {
                return Err(err);
            }
        }

        // 5. Reap and process completed data entries for this batch
        if let Some(batch) = drained_batch {
            self.quarantine.reap_completed(batch, &mut fctx, self);
        }

        // 6. Security: Now that IOTLB (and paging-structure caches) are confirmed clear,
        // it is safe to release the empty page tables back to the global pool.
        if let Ok(mut pending) = self.pending_pt_release.lock() {
            for pt in pending.drain(..) {
                self.page_table_pool.release(pt);
            }
        }

        Ok(())
    }

    pub(super) fn within_addr_width(&self, addr: u64, size: u64) -> bool {
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

    #[inline]
    pub(super) fn page_table_levels(&self) -> u8 {
        self.pt_levels
    }

    #[inline]
    pub(super) fn level_shift(level: u8) -> u8 {
        debug_assert!(level >= 1);
        12 + (level - 1) * 9
    }

    #[inline]
    pub(super) fn level_index(iova: u64, level: u8) -> usize {
        ((iova >> Self::level_shift(level)) & 0x1FF) as usize
    }

    #[inline]
    pub(super) fn root_level_shift(&self) -> u8 {
        Self::level_shift(self.page_table_levels())
    }

    pub(super) fn shard_for_iova(&self, iova: u64) -> usize {
        let root_idx = ((iova >> self.root_level_shift()) & 0x1FF) as usize;
        root_idx / PML4_ENTRIES_PER_SHARD
    }

    pub(super) fn shard_range(&self, iova: u64, size: u64) -> Result<(usize, usize), IommuError> {
        if size == 0 {
            return Err(IommuError::InvalidAlignment);
        }
        let end = iova.checked_add(size).ok_or(IommuError::InvalidAddress)?;
        let last = end.saturating_sub(1);
        let start = self.shard_for_iova(iova);
        let end = self.shard_for_iova(last);
        Ok((start, end))
    }

    pub(super) fn lock_shards(
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
    pub(super) fn mapping_overlaps(mappings: &MappingSlab, iova: u64, size: u64) -> bool {
        mappings.overlaps(iova, size)
    }

    /// Validate alignment, address width, and poison state for a map operation.
    pub(super) fn validate_map_args(
        &self,
        iova: u64,
        phys: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(IommuError::Poisoned);
        }

        if iova & 0xFFF != 0 || phys & 0xFFF != 0 || size & 0xFFF != 0 {
            return Err(IommuError::InvalidAlignment);
        }

        if !self.within_addr_width(iova, size) || !self.within_addr_width(phys, size) {
            return Err(IommuError::InvalidAddress);
        }

        // Security: Validate that the physical range does not overlap with the kernel image
        // or other protected physical regions (like MMIO).
        crate::io::iommu::runtime::security::validate_dma_region(phys, size)?;

        Ok(())
    }

    /// Check that no existing mapping overlaps the given range across all shards.
    pub(super) fn check_no_overlap(
        &self,
        guards: &[PoisonLockGuard<'_, DomainShard>],
        iova: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        // 1. Check active mappings
        for guard in guards.iter() {
            if Self::mapping_overlaps(&guard.mappings, iova, size) {
                return Err(IommuError::AlreadyMapped);
            }
        }

        // 2. SECURITY: Check quarantine queue to prevent IOVA reuse before IOTLB invalidation
        if self.quarantine.is_range_quarantined(iova, size) {
            log::warn!(
                "[IOMMU][SECURITY] Attempted to map IOVA range {:#x}-{:#x} that is still in quarantine",
                iova,
                iova + size
            );
            return Err(IommuError::AlreadyMapped);
        }

        Ok(())
    }

    /// Check whether a 1GB huge page can be used for the current mapping position.
    pub(super) fn can_use_1gb_page(&self, iova: u64, phys: u64, remaining: u64) -> bool {
        const SIZE_1GB: u64 = 1024 * 1024 * 1024;
        self.supports_1gb
            && self.page_table_levels() >= 3
            && remaining >= SIZE_1GB
            && iova % SIZE_1GB == 0
            && phys % SIZE_1GB == 0
            && (phys as u64 & 0x3FFF_FFFF) == 0
    }

    /// Check whether a 2MB huge page can be used for the current mapping position.
    pub(super) fn can_use_2mb_page(&self, iova: u64, phys: u64, remaining: u64) -> bool {
        const SIZE_2MB: u64 = 2 * 1024 * 1024;
        self.supports_2mb
            && self.page_table_levels() >= 2
            && remaining >= SIZE_2MB
            && iova % SIZE_2MB == 0
            && phys % SIZE_2MB == 0
    }

    /// Attempt to map pages at the best available page size (1GB > 2MB > 4KB).
    ///
    /// Returns the number of bytes successfully mapped in this chunk.
    pub(super) fn map_next_chunk(
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
        let pt_idx = Self::level_index(iova, 1);
        let pages_in_pt = core::cmp::min(pages_remaining, PT_ENTRIES - pt_idx);
        let pages_mapped = self.map_range_4k(iova, phys, pages_in_pt, read, write)?;
        Ok((pages_mapped as u64) * SIZE_4KB)
    }

    /// Rollback previously mapped pages and return the appropriate error.
    ///
    /// If rollback itself fails, the domain is poisoned.
    pub(super) fn rollback_mapping(
        &self,
        start_iova: u64,
        mapped_len: u64,
        error: IommuError,
    ) -> IommuError {
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
    pub(super) fn map_pages_transactional(
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
        self.map_internal(iova, phys, size, read, write)
    }

    /// Map a physical range to an IOVA with permissions, bypassing security checks.
    ///
    /// # Safety
    /// This should ONLY be used for trusted system regions like RMRR or IVMD
    /// that are parsed from ACPI and must be mapped for device functionality.
    pub unsafe fn map_privileged(
        &self,
        iova: u64,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(IommuError::Poisoned);
        }

        // SECURITY: Still perform basic alignment and width checks for stability and safety.
        // Privileged mappings must still be page-aligned to prevent unexpected hardware behavior.
        if (iova | phys | size) & 0xFFF != 0 {
            log::error!(
                "[IOMMU][SECURITY] Unaligned privileged mapping attempt: iova={:#x}, phys={:#x}, size={:#x}",
                iova,
                phys,
                size
            );
            return Err(IommuError::InvalidAlignment);
        }
        if !self.within_addr_width(iova, size) || !self.within_addr_width(phys, size) {
            log::error!(
                "[IOMMU][SECURITY] Out-of-bounds privileged mapping attempt: iova={:#x}, phys={:#x}, size={:#x}",
                iova,
                phys,
                size
            );
            return Err(IommuError::InvalidAddress);
        }

        // SECURITY: Even privileged mappings MUST NOT overlap with truly critical system memory.
        // The improved validate_critical_dma_region now checks all protected regions (APIC, Page Tables, etc.)
        crate::io::iommu::runtime::security::validate_critical_dma_region(phys, size)?;

        self.map_internal(iova, phys, size, read, write)
    }

    /// Internal mapping implementation (shared by map and map_privileged)
    fn map_internal(
        &self,
        iova: u64,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        let _paging_guard = self.paging_lock.lock();
        let (start_shard, end_shard) = self.shard_range(iova, size)?;
        let mut guards = self.lock_shards(start_shard, end_shard)?;

        self.check_no_overlap(&guards, iova, size)?;

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
            if guard.mappings.insert(mapping.clone()).is_err() {
                log::error!(
                    "[IOMMU] Mapping slab full: failed to insert iova={:#x} size={:#x}",
                    iova,
                    size
                );
                // Rollback the page table mapping on slab overflow
                if self.domain_type != IommuDomainType::Passthrough {
                    let _ = self.unmap_range(iova, size);
                }
                // Also remove entries already inserted into earlier shards
                for prev in guards.iter_mut() {
                    prev.mappings.remove(iova);
                }
                return Err(IommuError::OutOfMemory);
            }
        }

        // SECURITY: Register the mapping in the resource registry to enable force-unmap
        // on domain destruction, preventing DMA-after-free leaks.
        if let Err(e) = self.dma_registry.register(iova, phys, size) {
            log::error!(
                "[IOMMU] Failed to register DMA mapping in registry: {:?}",
                e
            );
            // Rollback the mapping if registration fails to maintain consistency
            for guard in guards.iter_mut() {
                guard.mappings.remove(iova);
            }
            if self.domain_type != IommuDomainType::Passthrough {
                let _ = self.unmap_range(iova, size);
            }
            return Err(e);
        }

        self.mapped_size.fetch_add(size, Ordering::Relaxed);

        Ok(())
    }

    /// Unmap a 2MB super-page (for rollback)
    pub(super) fn unmap_super_page_2mb(&self, iova: u64) -> Result<(), IommuError> {
        if self.page_table_levels() < 2 {
            return Err(IommuError::NotSupported);
        }

        unsafe {
            let l2_idx = Self::level_index(iova, 2);
            let (l2_table, table_phys_by_level, parent_entry_by_level) =
                if self.page_table_levels() == 2 {
                    let mut table_phys = [0u64; MAX_TABLE_PATH_DEPTH];
                    table_phys[2] = self.root_table_phys();
                    (
                        self.page_table,
                        table_phys,
                        [core::ptr::null_mut::<SlPte>(); MAX_TABLE_PATH_DEPTH],
                    )
                } else {
                    self.walk_table_path_to_level(iova, 2, true)?
                };

            let l2_entry = l2_table.add(l2_idx);
            if !(*l2_entry).is_present() || !(*l2_entry).is_super_page(self.pte_format) {
                return Err(IommuError::NotMapped);
            }

            *l2_entry = SlPte::new();

            let l2_phys = table_phys_by_level[2];
            if l2_phys != 0 && dec_ref(l2_phys) && self.page_table_levels() > 2 {
                self.reclaim_empty_table_cascade(2, &table_phys_by_level, &parent_entry_by_level);
            }
        }
        Ok(())
    }

    /// Unmap a 1GB super-page (for rollback)
    pub(super) fn unmap_super_page_1gb(&self, iova: u64) -> Result<(), IommuError> {
        if self.page_table_levels() < 3 {
            return Err(IommuError::NotSupported);
        }

        unsafe {
            let (l3_table, table_phys_by_level, parent_entry_by_level) =
                self.walk_table_path_to_level(iova, 3, true)?;
            let l3_entry = l3_table.add(Self::level_index(iova, 3));
            if !(*l3_entry).is_present() || !(*l3_entry).is_super_page(self.pte_format) {
                return Err(IommuError::NotMapped);
            }

            *l3_entry = SlPte::new();

            let l3_phys = table_phys_by_level[3];
            if l3_phys != 0 && dec_ref(l3_phys) && self.page_table_levels() > 3 {
                self.reclaim_empty_table_cascade(3, &table_phys_by_level, &parent_entry_by_level);
            }
        }
        Ok(())
    }
}

impl Drop for IommuDomain {
    fn drop(&mut self) {
        // 1. Release any page tables waiting in the quarantine
        if let Ok(mut pending) = self.pending_pt_release.lock() {
            for pt in pending.drain(..) {
                self.page_table_pool.release(pt);
            }
        }

        // 2. Iteratively deallocate the main page table hierarchy
        if !self.page_table.is_null() {
            unsafe {
                self.deallocate_page_tables_iterative();
            }
        }
    }
}
