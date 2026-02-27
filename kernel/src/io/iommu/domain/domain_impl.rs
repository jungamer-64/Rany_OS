use super::*;


mod identity_mapping;
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
        page_table_pool: Arc<crate::io::iommu::page_table_pool::PageTablePool>,
        pte_format: PteFormat,
    ) -> Self {
        // Allocate page table on the preferred NUMA node when possible.
        // For Passthrough, we still allocate it to simplify logic (or we could skip it)
        // But the hardware won't use it if we set TT=Passthrough.
        // Let's allocate it to avoid null pointer checks elsewhere, or make it Option.
        // For now: Allocate it.
        crate::io::log::early_print("[IOMMU] IommuDomain::new: allocating page table\n");
        let layout =
            alloc::alloc::Layout::from_size_align(PT_ENTRIES * core::mem::size_of::<SlPte>(), 4096)
                .expect("Invalid layout for page table");

        let page_table = crate::mm::numa::topology::allocate_zeroed_on_node(layout, numa_node)
            .expect("Failed to allocate IOMMU page table")
            .as_ptr() as *mut SlPte;
        crate::io::log::early_print("[IOMMU] IommuDomain::new: allocated page table\n");

        let root_phys = virt_ptr_to_phys(page_table as *const u8)
            .expect("Failed to get root page table physical address");
        crate::io::log::early_print("[IOMMU] IommuDomain::new: got root_phys\n");
        register_page_table(root_phys);
        crate::io::log::early_print("[IOMMU] IommuDomain::new: registered page table\n");

        debug_assert_eq!(PT_ENTRIES % DOMAIN_SHARD_COUNT, 0);
        debug_assert!(PML4_ENTRIES_PER_SHARD > 0);
        crate::io::log::early_print("[IOMMU] IommuDomain::new: creating shards vec\n");
        let mut shards = Vec::with_capacity(DOMAIN_SHARD_COUNT);
        for i in 0..DOMAIN_SHARD_COUNT {
            crate::io::log::early_print("[IOMMU] IommuDomain::new: creating shard ");
            crate::io::log::early_print_dec(i as u64);
            crate::io::log::early_print("\n");
            shards.push(PoisonLock::new(DomainShard::new()));
        }
        crate::io::log::early_print("[IOMMU] IommuDomain::new: shards created\n");

        let (default_iova_base, default_iova_size) = if cfg!(feature = "qemu-test-export") {
            // Keep qemu migration suites deterministic under their fixed bump allocator.
            (0x1_0000_0000, 0x1000_0000) // 4GB base, 256MB window
        } else {
            (0x1_0000_0000, 0x8_0000_0000) // 4GB base, 32GB window
        };
        let per_domain_iova = crate::io::iommu::IovaAllocatorFast::new(default_iova_base, default_iova_size);

        let new_domain = Self {
            id,
            domain_type,
            page_table,
            page_table_phys: root_phys,
            shards: shards.into_boxed_slice(),
            mapped_size: AtomicU64::new(0),
            numa_node: RwLock::new(numa_node),
            supports_2mb,
            supports_1gb,
            max_addr_bits: max_addr_bits.clamp(1, 64),
            quarantine: QuarantineQueue::new(),
            // Pre-allocated contexts for zero-allocation flush (Phase 5)
            // CRITICAL: This capacity must never be exceeded. The quarantine's
            // drain_pending_invalidations() asserts this in debug builds.
            flush_context: PoisonLock::new(crate::io::iommu::quarantine::FlushContext::new()),
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
        };
        crate::io::log::early_print("[IOMMU] IommuDomain::new: constructed domain object, returning\n");
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
        page_table_pool: Arc<crate::io::iommu::page_table_pool::PageTablePool>,
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
        domain.per_domain_iova = crate::io::iommu::IovaAllocatorFast::new(iova_base, iova_size);

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
    pub fn allocate_iova(&self, size: u64) -> Result<u64, crate::io::iommu::types::IommuError> {
        use crate::io::iommu::IovaGranularity;
        
        // IovaAllocatorFast is internally lock-free for common paths
        self.per_domain_iova
            .allocate(size, IovaGranularity::Page4K)
            .ok_or(crate::io::iommu::types::IommuError::OutOfIova)
    }

    /// Free IOVA back to this domain's allocator.
    ///
    /// Uses IovaAllocatorFast with O(1) per-CPU magazine deallocation.
    #[inline]
    pub fn free_iova(&self, iova: u64, size: u64) -> Result<(), crate::io::iommu::types::IommuError> {
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
        let mut fctx = self
            .flush_context
            .lock()
            .map_err(|_| IommuError::Poisoned)?;
            
        fctx.clear();

        // Drain pending invalidations (Round 9: returns DrainResult)
        let drained_batch = match self.quarantine.drain_pending_invalidations(&mut fctx.requests) {
            crate::io::iommu::quarantine::DrainResult::NoWork { .. } => return Ok(()),
            crate::io::iommu::quarantine::DrainResult::NotReady { batch: _ } => {
                // Round 9 Safety: Reserved slots pending.
                // We MUST NOT issue invalidations or reap, as that would
                // advance the batch prematurely or leave valid PTEs behind.
                // We can optionally log this or return a special error if needed,
                // but for now we just skip the flush.
                return Ok(());
            }
            crate::io::iommu::quarantine::DrainResult::Drained { batch } => batch,
            crate::io::iommu::quarantine::DrainResult::Poisoned { .. } => return Err(IommuError::Poisoned),
        };

        // Skip if nothing to flush (double check, though NoWork covers this)
        if fctx.requests.is_empty() {
            return Ok(());
        }

        // Process all invalidation requests in a single batch
        if let Err(err) = invalidator.process_invalidations(fctx.requests.as_slice()) {
            return Err(err);
        }

        // Reap and process completed entries for this batch
        self.quarantine.reap_completed(drained_batch, &mut fctx, context);

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

    pub(super) fn shard_for_iova(iova: u64) -> usize {
        let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
        pml4_idx / PML4_ENTRIES_PER_SHARD
    }

    pub(super) fn shard_range(&self, iova: u64, size: u64) -> Result<(usize, usize), IommuError> {
        if size == 0 {
            return Err(IommuError::InvalidAlignment);
        }
        let end = iova.checked_add(size).ok_or(IommuError::InvalidAddress)?;
        let last = end.saturating_sub(1);
        let start = Self::shard_for_iova(iova);
        let end = Self::shard_for_iova(last);
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
    pub(super) fn validate_map_args(&self, iova: u64, phys: u64, size: u64) -> Result<(), IommuError> {
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
        crate::io::iommu::security::validate_dma_region(phys, size)?;

        Ok(())
    }

    /// Check that no existing mapping overlaps the given range across all shards.
    pub(super) fn check_no_overlap(
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
    pub(super) fn can_use_1gb_page(&self, iova: u64, phys: u64, remaining: u64) -> bool {
        const SIZE_1GB: u64 = 1024 * 1024 * 1024;
        self.supports_1gb
            && remaining >= SIZE_1GB
            && iova % SIZE_1GB == 0
            && phys % SIZE_1GB == 0
            && (phys as u64 & 0x3FFF_FFFF) == 0
    }

    /// Check whether a 2MB huge page can be used for the current mapping position.
    pub(super) fn can_use_2mb_page(&self, iova: u64, phys: u64, remaining: u64) -> bool {
        const SIZE_2MB: u64 = 2 * 1024 * 1024;
        self.supports_2mb
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
        let pt_idx = ((iova >> 12) & 0x1FF) as usize;
        let pages_in_pt = core::cmp::min(pages_remaining, PT_ENTRIES - pt_idx);
        let pages_mapped = self.map_range_4k(iova, phys, pages_in_pt, read, write)?;
        Ok((pages_mapped as u64) * SIZE_4KB)
    }

    /// Rollback previously mapped pages and return the appropriate error.
    ///
    /// If rollback itself fails, the domain is poisoned.
    pub(super) fn rollback_mapping(&self, start_iova: u64, mapped_len: u64, error: IommuError) -> IommuError {
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
    pub(super) fn unmap_super_page_2mb(&self, iova: u64) -> Result<(), IommuError> {
        let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
        let pdp_idx = ((iova >> 30) & 0x1FF) as usize;
        let pd_idx = ((iova >> 21) & 0x1FF) as usize;

        let layout =
            alloc::alloc::Layout::from_size_align(PT_ENTRIES * core::mem::size_of::<SlPte>(), 4096)
                .expect("Failed to create page table layout");

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
    pub(super) fn unmap_super_page_1gb(&self, iova: u64) -> Result<(), IommuError> {
        let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
        let pdp_idx = ((iova >> 30) & 0x1FF) as usize;

        let layout =
            alloc::alloc::Layout::from_size_align(PT_ENTRIES * core::mem::size_of::<SlPte>(), 4096)
                .expect("Failed to create page table layout");

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
