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
    pub fn try_new(
        id: u16,
        numa_node: Option<usize>,
        supports_2mb: bool,
        supports_1gb: bool,
        max_addr_bits: u8,
        pt_levels: u8,
        domain_type: IommuDomainType,
        page_table_pool: Arc<crate::io::iommu::common::dma::page_table_pool::PageTablePool>,
        pte_format: PteFormat,
    ) -> Result<Self, IommuError> {
        let pt_levels = pt_levels.clamp(MIN_PT_LEVELS, MAX_PT_LEVELS);
        let root = page_table_pool.acquire(numa_node)?;
        let page_table = root.ptr().as_ptr();
        let root_phys = root.phys();

        debug_assert_eq!(PT_ENTRIES % DOMAIN_SHARD_COUNT, 0);
        debug_assert!(PML4_ENTRIES_PER_SHARD > 0);
        let mut shards = Vec::with_capacity(DOMAIN_SHARD_COUNT);
        for _i in 0..DOMAIN_SHARD_COUNT {
            shards.push(PoisonLock::new(DomainShard::new()));
        }

        crate::io::iommu::common::dma::page_table_pool::publish_table(root);

        Ok(Self {
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
            page_table_pool,
            pte_format,
            security_notifier: crate::sync::InitOnce::new(),
            poisoned: AtomicBool::new(false),
            dma_registry: DmaResourceRegistry::new(),
            pending_pt_release: PoisonLock::new(
                crate::io::iommu::common::dma::page_table_pool::TableRetirement::default(),
            ),
            paging_lock: IrqMutex::new(()),
        })
    }

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
        Self::try_new(
            id,
            numa_node,
            supports_2mb,
            supports_1gb,
            max_addr_bits,
            pt_levels,
            domain_type,
            page_table_pool,
            pte_format,
        )
        .expect("Failed to create IOMMU domain")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn domain_admission_preserves_page_pool_placement_rejection() {
        let pool = crate::io::iommu::common::dma::page_table_pool::PageTablePool::new(1, 1);
        let result = IommuDomain::try_new(
            1,
            Some(1),
            false,
            false,
            48,
            4,
            IommuDomainType::Translated,
            pool,
            PteFormat::Intel,
        );
        assert!(matches!(result, Err(IommuError::InvalidAddress)));
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

    /// The returned guards protect ledger removal through the PTE commit.
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
        let _paging_guard = self.paging_lock.lock();
        let (_mapping, mut guards) = self.verify_and_lock_for_clear(iova, size)?;
        let mut registry = self
            .dma_registry
            .state
            .lock()
            .map_err(|_| IommuError::Poisoned)?;
        if self.domain_type != IommuDomainType::Passthrough {
            self.unmap_range(iova, size)?;
        }
        for guard in guards.iter_mut() {
            guard.mappings.remove(iova);
        }
        self.dma_registry.unregister_locked(&mut registry, iova);

        self.mapped_size.fetch_sub(size, Ordering::Relaxed);

        Ok(())
    }

    /// The completion owner supplies a cohort removed from pending storage;
    /// another flush cannot authorize or consume these tables.
    /// # Safety
    /// Completion covers this domain's paging structures and ATS after capture.
    pub(in crate::io::iommu) unsafe fn release_detached_tables(
        &self,
        tables: crate::io::iommu::common::dma::page_table_pool::DetachedTables,
    ) {
        unsafe { tables.release(&self.page_table_pool) };
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
        let mut guards = Vec::new();
        guards
            .try_reserve_exact(end.saturating_sub(start) + 1)
            .map_err(|_| IommuError::MetadataAllocation)?;
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

        Ok(())
    }

    /// Check whether a 1GB huge page can be used for the current mapping position.
    pub(super) fn can_use_1gb_page(&self, iova: u64, phys: u64, remaining: u64) -> bool {
        const SIZE_1GB: u64 = 1024 * 1024 * 1024;
        self.supports_1gb
            && self.page_table_levels() >= 3
            && remaining >= SIZE_1GB
            && iova.is_multiple_of(SIZE_1GB)
            && phys.is_multiple_of(SIZE_1GB)
            && (phys & 0x3FFF_FFFF) == 0
    }

    /// Check whether a 2MB huge page can be used for the current mapping position.
    pub(super) fn can_use_2mb_page(&self, iova: u64, phys: u64, remaining: u64) -> bool {
        const SIZE_2MB: u64 = 2 * 1024 * 1024;
        self.supports_2mb
            && self.page_table_levels() >= 2
            && remaining >= SIZE_2MB
            && iova.is_multiple_of(SIZE_2MB)
            && phys.is_multiple_of(SIZE_2MB)
    }

    /// Map a DMA region
    ///
    /// All fallible table and metadata admission precedes DMA leaf publication.
    /// Failure leaves data pages unmapped; intermediate table rollback retains
    /// physical owners in quarantine until the next domain IOTLB/ATS completion.
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

        if !read && !write {
            return Err(IommuError::InvalidPermissions);
        }
        let prepared = if self.domain_type != IommuDomainType::Passthrough {
            Some(self.prepare_range(iova, phys, size)?)
        } else {
            None
        };

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
                for prev in guards.iter_mut() {
                    prev.mappings.remove(iova);
                }
                return Err(IommuError::OutOfMemory);
            }
        }

        // Keep registry observers excluded through leaf commit. Lock failure
        // precedes publication, so caller still owns wholly unmapped data RAM.
        let mut registry = match self.dma_registry.state.lock() {
            Ok(registry) => registry,
            Err(_) => {
                for guard in guards.iter_mut() {
                    guard.mappings.remove(iova);
                }
                return Err(IommuError::Poisoned);
            }
        };
        if let Err(e) = self
            .dma_registry
            .register_locked(&mut registry, iova, phys, size)
        {
            log::error!(
                "[IOMMU] Failed to register DMA mapping in registry: {:?}",
                e
            );
            // Rollback the mapping if registration fails to maintain consistency
            for guard in guards.iter_mut() {
                guard.mappings.remove(iova);
            }
            return Err(e);
        }

        if let Some(prepared) = prepared {
            // SAFETY: all metadata admission succeeded and paging/shard locks
            // retain the exact conflict-checked hierarchy through this commit.
            unsafe { prepared.commit(self.pte_format, read, write) };
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

impl IommuDomain {
    /// Retire a uniquely owned domain after its hardware context has been removed.
    /// # Safety
    /// No device, CPU borrower or controller context can access this domain.
    /// Context, domain paging-structure and ATS invalidations completed after
    /// removal. Dropping a domain without this proof retains its physical RAM.
    pub(in crate::io::iommu) unsafe fn retire_after_invalidation(mut self) {
        let detached = self
            .pending_pt_release
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take_pending();
        // SAFETY: unique finalization follows completion for every retained
        // table in this domain. The metadata lock is released before pool work.
        unsafe { detached.release(&self.page_table_pool) };
        // SAFETY: all hardware users and borrowers are retired by caller.
        unsafe { self.deallocate_page_tables_iterative() };
        self.page_table = core::ptr::null_mut();
    }
}
