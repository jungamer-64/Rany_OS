// ============================================================================
// kernel/src/io/iommu/common/domain/mapping.rs
// ============================================================================

use super::*;

impl IommuDomain {
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
        const SIZE_4KB: u64 = 4096;

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

            for scope in newly_allocated.iter_mut().take(scope_count).flatten() {
                scope.commit();
            }

            for _ in 0..pages_in_pt {
                inc_ref(pt_phys);
            }

            Ok(pages_in_pt)
        }
    }

    /// Map a single 4KB page.
    pub(super) fn map_page(
        &self,
        iova: u64,
        phys: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        let mapped = self.map_range_4k(iova, phys, 1, read, write)?;
        if mapped != 1 {
            return Err(IommuError::HardwareError);
        }
        Ok(())
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

        for scope in newly_allocated.iter_mut().take(scope_count).flatten() {
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

        for scope in newly_allocated.iter_mut().take(scope_count).flatten() {
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

        let _paging_guard = self.paging_lock.lock();

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

        for guard in guards.iter_mut() {
            guard.mappings.remove(iova);
        }

        // SECURITY: Unregister from resource registry to maintain consistency.
        let _ = self.dma_registry.unregister(iova);

        if self.domain_type != IommuDomainType::Passthrough {
            self.unmap_range(iova, mapping.size)?;
        }

        self.mapped_size.fetch_sub(mapping.size, Ordering::Relaxed);

        Ok(mapping)
    }

    /// Unmap a range using super-page aware traversal.
    pub(super) fn unmap_range(&self, iova: u64, size: u64) -> Result<(), IommuError> {
        let mut current = iova;
        let mut remaining = size;
        const SIZE_4KB: u64 = 4096;

        // LOOP_PROOF: mode=condition; reason=Remaining byte count is reduced by each successful unmap step until it reaches zero.;
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
            let pt_idx = Self::level_index(current, 1);
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

    pub(super) fn try_unmap_superpage(&self, iova: u64) -> Result<Option<u64>, IommuError> {
        const SIZE_1GB: u64 = 1024 * 1024 * 1024;
        const SIZE_2MB: u64 = 2 * 1024 * 1024;

        if self.page_table_levels() >= 3 {
            unsafe {
                let (l3_table, _table_phys, _parents) =
                    self.walk_table_path_to_level(iova, 3, false)?;
                let l3_entry = l3_table.add(Self::level_index(iova, 3));
                if !(*l3_entry).is_present() {
                    return Err(IommuError::NotMapped);
                }
                if (*l3_entry).is_super_page(self.pte_format) {
                    self.unmap_super_page_1gb(iova)?;
                    return Ok(Some(SIZE_1GB));
                }

                let l2_table = phys_to_virt_usize((*l3_entry).phys_addr()) as *mut SlPte;
                let l2_entry = l2_table.add(Self::level_index(iova, 2));
                if !(*l2_entry).is_present() {
                    return Err(IommuError::NotMapped);
                }
                if (*l2_entry).is_super_page(self.pte_format) {
                    self.unmap_super_page_2mb(iova)?;
                    return Ok(Some(SIZE_2MB));
                }
            }
            return Ok(None);
        }

        unsafe {
            let l2_table = self.page_table;
            let l2_entry = l2_table.add(Self::level_index(iova, 2));
            if !(*l2_entry).is_present() {
                return Err(IommuError::NotMapped);
            }
            if (*l2_entry).is_super_page(self.pte_format) {
                self.unmap_super_page_2mb(iova)?;
                return Ok(Some(SIZE_2MB));
            }
        }

        Ok(None)
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
