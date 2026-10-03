// ============================================================================
// kernel/src/io/iommu/common/domain/mapping.rs
// ============================================================================

use super::*;

use super::leaf_walk::{PreparedDmaRange, PreparedLeaf};

impl IommuDomain {
    /// Perform all fallible table and vector admission before publishing a leaf.
    /// The caller retains paging_lock through either drop or commit of the range.
    pub(super) fn prepare_range(
        &self,
        iova: u64,
        phys: u64,
        size: u64,
    ) -> Result<PreparedDmaRange<'_>, IommuError> {
        let bound = super::leaf_walk::retirement_table_bound(iova, size, self.page_table_levels())?;
        self.reserve_range_retirement(iova, size)?;
        let mut prepared = PreparedDmaRange {
            leaves: Vec::new(),
            scopes: Vec::new(),
        };
        prepared
            .leaves
            .try_reserve_exact(bound)
            .map_err(|_| IommuError::MetadataAllocation)?;
        prepared
            .scopes
            .try_reserve_exact(bound)
            .map_err(|_| IommuError::MetadataAllocation)?;
        let mut current_iova = iova;
        let mut current_phys = phys;
        let mut remaining = size;
        // LOOP_PROOF: mode=condition; reason=Each prepared leaf run consumes a positive aligned extent and any admission or conflict failure returns before leaf publication.;
        while remaining > 0 {
            let level = if self.can_use_1gb_page(current_iova, current_phys, remaining) {
                3
            } else if self.can_use_2mb_page(current_iova, current_phys, remaining) {
                2
            } else {
                1
            };
            let index = Self::level_index(current_iova, level);
            let count = if level == 1 {
                core::cmp::min(remaining / 4096, (PT_ENTRIES - index) as u64) as usize
            } else {
                1
            };
            // SAFETY: paging_lock retains every parent through prepared drop or commit.
            let (table, table_phys, mut scopes, scope_count, _) =
                unsafe { self.ensure_table_path_to_level(current_iova, level)? };
            // Retain all new scopes before any fallible conflict check so failure
            // clears their parents while the prepared storage is still alive.
            for scope in scopes.iter_mut().take(scope_count).filter_map(Option::take) {
                assert!(
                    prepared.scopes.len() < prepared.scopes.capacity(),
                    "table window bound admits every scope"
                );
                prepared.scopes.push(scope);
            }
            // SAFETY: the retained table has PT_ENTRIES entries; this check publishes nothing.
            unsafe { Self::check_pt_no_conflicts(table, index, count)? };
            prepared.leaves.push(PreparedLeaf {
                table,
                table_phys,
                index,
                count,
                level,
                phys: current_phys,
            });
            let bytes = if level == 1 {
                count as u64 * 4096
            } else {
                1u64 << Self::level_shift(level)
            };
            current_iova += bytes;
            current_phys += bytes;
            remaining -= bytes;
        }
        Ok(prepared)
    }

    /// Walk all intermediate levels and ensure a Level-1 table (PT) exists.
    unsafe fn ensure_page_tables_4k(
        &self,
        iova: u64,
    ) -> Result<(*mut SlPte, u64, [Option<PageTableScope>; 4], usize, bool), IommuError> {
        unsafe { self.ensure_table_path_to_level(iova, 1) }
    }

    /// Map a contiguous run of 4KB pages within a single PT.
    pub(super) fn map_range_4k(
        &self,
        iova: u64,
        phys: u64,
        pages: usize,
        read: bool,
        write: bool,
    ) -> Result<usize, IommuError> {
        if pages == 0 {
            return Ok(0);
        }

        let pt_idx = Self::level_index(iova, 1);

        unsafe {
            let (pt_table, pt_phys, mut newly_allocated, scope_count, target_allocated) =
                self.ensure_page_tables_4k(iova)?;

            let pages_in_pt = core::cmp::min(pages, PT_ENTRIES - pt_idx);

            if !target_allocated {
                Self::check_pt_no_conflicts(pt_table, pt_idx, pages_in_pt)?;
            }

            Self::write_pt_entries_4k(
                pt_table,
                pt_idx,
                phys,
                pages_in_pt,
                read,
                write,
                self.pte_format,
            );

            for scope in newly_allocated
                .iter_mut()
                .take(scope_count)
                .filter_map(Option::take)
            {
                scope.commit();
            }

            for _ in 0..pages_in_pt {
                inc_ref(pt_phys);
            }

            Ok(pages_in_pt)
        }
    }

    /// Map a 2MB super-page.
    pub unsafe fn map_page_2mb(
        &self,
        iova: u64,
        phys: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        const SIZE_2MB: u64 = 2 * 1024 * 1024;

        if self.page_table_levels() < 2 {
            return Err(IommuError::NotSupported);
        }
        if iova % SIZE_2MB != 0 || phys % SIZE_2MB != 0 {
            return Err(IommuError::InvalidAddress);
        }

        let l2_idx = Self::level_index(iova, 2);

        let (l2_table, l2_phys, mut newly_allocated, scope_count, _target_allocated) =
            unsafe { self.ensure_table_path_to_level(iova, 2)? };

        let l2_entry = unsafe { l2_table.add(l2_idx) };
        if unsafe { (*l2_entry).is_present() } {
            return Err(IommuError::AlreadyMapped);
        }

        match self.pte_format {
            PteFormat::Intel => unsafe {
                *l2_entry = SlPte::super_page_2mb(phys, read, write);
            },
            PteFormat::Amd => {
                let amd_pte = AmdPte::mapping(phys, read, write, 0);
                unsafe {
                    *l2_entry = SlPte(amd_pte.0);
                }
            }
        }
        inc_ref(l2_phys);

        for scope in newly_allocated
            .iter_mut()
            .take(scope_count)
            .filter_map(Option::take)
        {
            scope.commit();
        }

        Ok(())
    }

    /// Map a 1GB super-page.
    pub unsafe fn map_page_1gb(
        &self,
        iova: u64,
        phys: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        const SIZE_1GB: u64 = 1024 * 1024 * 1024;

        if self.page_table_levels() < 3 {
            return Err(IommuError::NotSupported);
        }
        if iova % SIZE_1GB != 0 || phys % SIZE_1GB != 0 {
            return Err(IommuError::InvalidAddress);
        }

        let l3_idx = Self::level_index(iova, 3);

        let (l3_table, l3_phys, mut newly_allocated, scope_count, _target_allocated) =
            unsafe { self.ensure_table_path_to_level(iova, 3)? };

        let l3_entry = unsafe { l3_table.add(l3_idx) };
        if unsafe { (*l3_entry).is_present() } {
            return Err(IommuError::AlreadyMapped);
        }

        match self.pte_format {
            PteFormat::Intel => unsafe {
                *l3_entry = SlPte::super_page_1gb(phys, read, write);
            },
            PteFormat::Amd => {
                let amd_pte = AmdPte::mapping(phys, read, write, 0);
                unsafe {
                    *l3_entry = SlPte(amd_pte.0);
                }
            }
        }
        inc_ref(l3_phys);

        for scope in newly_allocated
            .iter_mut()
            .take(scope_count)
            .filter_map(Option::take)
        {
            scope.commit();
        }

        Ok(())
    }

    /// 複数シャードのガードを取得する
    pub(super) fn acquire_shard_guards<'a>(
        &'a self,
        start_shard: usize,
        end_shard: usize,
        first_guard: crate::sync::PoisonLockGuard<'a, DomainShard>,
    ) -> Result<Vec<crate::sync::PoisonLockGuard<'a, DomainShard>>, IommuError> {
        let mut guards = Vec::new();
        guards
            .try_reserve_exact(end_shard.saturating_sub(start_shard) + 1)
            .map_err(|_| IommuError::MetadataAllocation)?;
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

        let _paging_guard = self.paging_lock.lock();
        self.unmap_locked(iova)
    }

    /// Detach this owner's exact range. All fallible admission and leaf
    /// validation finish before any mutation; the caller records DataDetached
    /// immediately on success, before attempting fallible cohort capture.
    pub(in crate::io::iommu) fn detach_owned_range(
        &self,
        iova: u64,
        phys: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        let _paging = self.paging_lock.lock();
        let mapping = self.mapping(iova).ok_or(IommuError::NotMapped)?;
        if mapping.phys != phys || mapping.size != size {
            return Err(IommuError::InvalidAddress);
        }
        self.unmap_locked(iova)?;
        Ok(())
    }
    pub(in crate::io::iommu) fn capture_detached_tables(
        &self,
    ) -> Result<super::super::dma::page_table_pool::DetachedTables, IommuError> {
        let _paging = self.paging_lock.lock();
        Ok(self
            .pending_pt_release
            .lock()
            .map_err(|_| IommuError::Poisoned)?
            .take_pending())
    }

    fn unmap_locked(&self, iova: u64) -> Result<DmaMapping, IommuError> {
        let start_shard = self.shard_for_iova(iova);
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

        let mut registry = self
            .dma_registry
            .state
            .lock()
            .map_err(|_| IommuError::Poisoned)?;
        if self.domain_type != IommuDomainType::Passthrough {
            self.unmap_range(iova, mapping.size)?;
        }
        for guard in guards.iter_mut() {
            guard.mappings.remove(iova);
        }
        self.dma_registry.unregister_locked(&mut registry, iova);

        self.mapped_size.fetch_sub(mapping.size, Ordering::Relaxed);

        Ok(mapping)
    }

    /// Bound detached table owners by table windows, rather than leaf pages.
    /// A 1GiB range intersects 512 PT windows, one PD and one PDPT window.
    /// The root stays owned by the domain and is never queued here.
    pub(super) fn reserve_range_retirement(&self, iova: u64, size: u64) -> Result<(), IommuError> {
        let count = super::leaf_walk::retirement_table_bound(iova, size, self.page_table_levels())?;
        self.pending_pt_release
            .lock()
            .map_err(|_| IommuError::Poisoned)?
            .reserve(count)
    }

    /// Validate every leaf before clearing any entry. The paging lock keeps
    /// this proof fresh through the mutation; partial huge leaves are rejected.
    fn validate_unmap_range(&self, iova: u64, size: u64) -> Result<(), IommuError> {
        if size == 0 || (iova | size) & 4095 != 0 {
            return Err(IommuError::InvalidAlignment);
        }
        let end = iova.checked_add(size).ok_or(IommuError::InvalidAddress)?;
        if !self.within_addr_width(iova, size) {
            return Err(IommuError::InvalidAddress);
        }
        let mut current = iova;
        // LOOP_PROOF: mode=condition; reason=Each verified leaf run advances current by a positive extent toward the validated end.;
        while current < end {
            current += unsafe {
                super::leaf_walk::unmap_leaf_run(
                    self.page_table,
                    self.page_table_levels(),
                    self.pte_format,
                    current,
                    end - current,
                )?
            }
            .0;
        }
        Ok(())
    }

    /// Admit metadata and validate all leaves before mutation. Callers retain
    /// mapping/registry metadata until this succeeds and hold the paging lock.
    pub(super) fn unmap_range(&self, iova: u64, size: u64) -> Result<(), IommuError> {
        self.validate_unmap_range(iova, size)?;
        self.reserve_range_retirement(iova, size)?;
        self.unmap_range_admitted(iova, size)
    }

    /// Rollback uses the capacity admitted before mapping; it must not request
    /// new heap memory after partial publication. The caller holds paging_lock.
    pub(super) fn unmap_range_admitted(&self, iova: u64, size: u64) -> Result<(), IommuError> {
        self.validate_unmap_range(iova, size)?;
        let mut current = iova;
        let mut remaining = size;
        // LOOP_PROOF: mode=condition; reason=Each verified unmap consumes a positive leaf run from remaining until the whole range is cleared.;
        while remaining > 0 {
            let (bytes, level) = unsafe {
                super::leaf_walk::unmap_leaf_run(
                    self.page_table,
                    self.page_table_levels(),
                    self.pte_format,
                    current,
                    remaining,
                )?
            };
            match level {
                3 => self.unmap_super_page_1gb(current)?,
                2 => self.unmap_super_page_2mb(current)?,
                1 => {
                    self.unmap_range_4k(current, (bytes / 4096) as usize)?;
                }
                _ => unreachable!("verified leaf level is 1, 2 or 3"),
            }
            current += bytes;
            remaining -= bytes;
        }
        Ok(())
    }

    pub(super) fn verify_pt_entries_present(
        pt_table: *mut SlPte,
        pt_idx: usize,
        count: usize,
    ) -> Result<(), IommuError> {
        for idx in 0..count {
            let pt_entry = unsafe { pt_table.add(pt_idx + idx) };
            if !unsafe { *pt_entry }.is_present() {
                return Err(IommuError::NotMapped);
            }
        }
        Ok(())
    }
}
