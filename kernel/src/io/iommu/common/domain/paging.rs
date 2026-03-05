// ============================================================================
// kernel/src/io/iommu/common/domain/paging.rs
// ============================================================================

use super::*;

impl IommuDomain {
    #[inline]
    pub(super) fn root_table_phys(&self) -> u64 {
        self.page_table_phys
    }

    /// Walk or create intermediate tables down to `target_level`.
    ///
    /// Returns `(table_ptr, table_phys, newly_allocated_scopes, count, target_allocated)`.
    pub(super) unsafe fn ensure_table_path_to_level(
        &self,
        iova: u64,
        target_level: u8,
    ) -> Result<(*mut SlPte, u64, [Option<PageTableScope>; 4], usize, bool), IommuError> {
        if target_level == 0 || target_level > self.page_table_levels() {
            return Err(IommuError::InvalidAddress);
        }

        let mut scopes: [Option<PageTableScope>; 4] = core::array::from_fn(|_| None);
        let mut scope_count = 0usize;
        let mut target_allocated = false;

        let mut table_ptr = self.page_table;
        let mut table_phys = self.root_table_phys();
        let mut level = self.page_table_levels();

        while level > target_level {
            let idx = Self::level_index(iova, level);
            let next_level = level - 1;
            let check_super_page = level <= 3;

            let (next_ptr, next_phys, scope) = unsafe {
                self.ensure_intermediate_table(
                    table_ptr,
                    table_phys,
                    idx,
                    next_level,
                    check_super_page,
                )?
            };

            if let Some(scope) = scope {
                if scope_count >= scopes.len() {
                    return Err(IommuError::HardwareError);
                }
                if next_level == target_level {
                    target_allocated = true;
                }
                scopes[scope_count] = Some(scope);
                scope_count += 1;
            }

            table_ptr = next_ptr;
            table_phys = next_phys;
            level = next_level;
        }

        Ok((table_ptr, table_phys, scopes, scope_count, target_allocated))
    }

    /// Walk existing tables down to `target_level` without allocating.
    ///
    /// Returns `(table_ptr, table_phys_by_level, parent_entry_by_level)`.
    /// `table_phys_by_level[level]` is valid for `1..=pt_levels`.
    /// `parent_entry_by_level[level]` points to the entry in level+1 that references level.
    pub(super) unsafe fn walk_table_path_to_level(
        &self,
        iova: u64,
        target_level: u8,
        reject_superpages: bool,
    ) -> Result<
        (
            *mut SlPte,
            [u64; MAX_TABLE_PATH_DEPTH],
            [*mut SlPte; MAX_TABLE_PATH_DEPTH],
        ),
        IommuError,
    > {
        if target_level == 0 || target_level > self.page_table_levels() {
            return Err(IommuError::InvalidAddress);
        }

        let mut table_ptr = self.page_table;
        let mut table_phys_by_level = [0u64; MAX_TABLE_PATH_DEPTH];
        let mut parent_entry_by_level = [core::ptr::null_mut::<SlPte>(); MAX_TABLE_PATH_DEPTH];
        let mut level = self.page_table_levels();
        table_phys_by_level[level as usize] = self.root_table_phys();

        while level > target_level {
            let idx = Self::level_index(iova, level);
            let entry = unsafe { table_ptr.add(idx) };
            if unsafe { !(*entry).is_present() } {
                return Err(IommuError::NotMapped);
            }
            if reject_superpages && level <= 3 && unsafe { (*entry).is_super_page(self.pte_format) }
            {
                return Err(IommuError::InvalidAlignment);
            }

            let child_phys = unsafe { (*entry).phys_addr() };
            let child_ptr = phys_to_virt_usize(child_phys) as *mut SlPte;

            parent_entry_by_level[(level - 1) as usize] = entry;
            table_phys_by_level[(level - 1) as usize] = child_phys;

            table_ptr = child_ptr;
            level -= 1;
        }

        Ok((table_ptr, table_phys_by_level, parent_entry_by_level))
    }

    #[inline]
    pub(super) fn quarantine_table_phys(&self, table_phys: u64) {
        if let Some(pt) =
            crate::io::iommu::common::dma::page_table_pool::reconstruct_pooled_pt(table_phys)
        {
            if let Ok(mut pending) = self.pending_pt_release.lock() {
                pending.push(pt);
            }
        }
    }

    /// Reclaim an empty table and propagate upward while parent tables become empty.
    ///
    /// `emptied_level` is the level of the table that is already known to be empty.
    /// This clears parent pointers, quarantines reclaimed tables, and decrements
    /// parent refcounts up to the root table.
    pub(super) unsafe fn reclaim_empty_table_cascade(
        &self,
        mut emptied_level: u8,
        table_phys_by_level: &[u64; MAX_TABLE_PATH_DEPTH],
        parent_entry_by_level: &[*mut SlPte; MAX_TABLE_PATH_DEPTH],
    ) {
        while emptied_level < self.page_table_levels() {
            let parent_entry = parent_entry_by_level[emptied_level as usize];
            if parent_entry.is_null() {
                return;
            }

            unsafe {
                *parent_entry = SlPte::new();
            }
            let emptied_phys = table_phys_by_level[emptied_level as usize];
            if emptied_phys != 0 {
                self.quarantine_table_phys(emptied_phys);
            }

            let parent_level = emptied_level + 1;
            let parent_phys = table_phys_by_level[parent_level as usize];
            if parent_phys == 0 || !dec_ref(parent_phys) {
                return;
            }

            emptied_level = parent_level;
        }
    }

    /// Ensure an intermediate page table exists at the given index.
    ///
    /// If the entry is not present, allocate a new page table and attach it.
    /// If `check_super_page` is true and the entry is a super page, return `AlreadyMapped`.
    /// Returns the child table pointer, its physical address, and an optional scope.
    pub(super) unsafe fn ensure_intermediate_table(
        &self,
        parent_table: *mut SlPte,
        parent_phys: u64,
        idx: usize,
        level: u8,
        check_super_page: bool,
    ) -> Result<(*mut SlPte, u64, Option<PageTableScope>), IommuError> {
        let entry = unsafe { parent_table.add(idx) };
        if unsafe { (*entry).is_present() } {
            if check_super_page && unsafe { (*entry).is_super_page(self.pte_format) } {
                return Err(IommuError::AlreadyMapped);
            }
            let child = unsafe { phys_to_virt_usize((*entry).phys_addr()) as *mut SlPte };
            let phys = unsafe { (*entry).phys_addr() };
            Ok((child, phys, None))
        } else {
            let mut scope = self.allocate_page_table()?;
            scope.attach_to_parent(entry, parent_phys, self.pte_format, level);
            let child = unsafe { phys_to_virt_usize((*entry).phys_addr()) as *mut SlPte };
            let phys = unsafe { (*entry).phys_addr() };
            Ok((child, phys, Some(scope)))
        }
    }

    /// Check that no existing PT entries in the target range are present.
    pub(super) unsafe fn check_pt_no_conflicts(
        pt_table: *mut SlPte,
        pt_idx: usize,
        count: usize,
    ) -> Result<(), IommuError> {
        for idx in 0..count {
            let pt_entry = unsafe { pt_table.add(pt_idx + idx) };
            if unsafe { (*pt_entry).is_present() } {
                return Err(IommuError::AlreadyMapped);
            }
        }
        Ok(())
    }

    /// Write 4KB page table entries for the given range.
    pub(super) unsafe fn write_pt_entries_4k(
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
            let pt_entry = unsafe { pt_table.add(pt_idx + idx) };
            let entry_phys = phys + (idx as u64 * SIZE_4KB);
            match pte_format {
                PteFormat::Intel => {
                    unsafe { *pt_entry = SlPte::mapping(entry_phys, read, write) };
                }
                PteFormat::Amd => {
                    let amd_pte = AmdPte::mapping(entry_phys, read, write, 0);
                    unsafe { *pt_entry = SlPte(amd_pte.0) };
                }
            }
        }
    }

    /// 新規割り当て済みページテーブルをコミットする
    pub(super) fn commit_allocated_tables(tables: &mut [Option<PageTableScope>]) {
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
    pub(super) fn allocate_page_table(&self) -> Result<PageTableScope, IommuError> {
        PageTableScope::new_with_pool(self.page_table_pool.clone(), self.numa_node())
    }

    /// Ensure a PDP table exists for the given PML4 entry, allocating if needed.
    pub(super) unsafe fn ensure_pdp_table(
        &self,
        pml4_entry: *mut SlPte,
        pml4_phys: u64,
    ) -> Result<Option<PageTableScope>, IommuError> {
        if unsafe { (*pml4_entry).is_present() } {
            return Ok(None);
        }
        let mut pdp_scope = self.allocate_page_table()?;
        pdp_scope.attach_to_parent(pml4_entry, pml4_phys, self.pte_format, 3);
        Ok(Some(pdp_scope))
    }

    /// Ensure a PD table exists for the given PDP entry, allocating if needed.
    /// Returns Err(AlreadyMapped) if a 1GB super-page already exists.
    pub(super) unsafe fn ensure_pd_table(
        &self,
        pdp_entry: *mut SlPte,
        pdp_phys: u64,
    ) -> Result<Option<PageTableScope>, IommuError> {
        if unsafe { (*pdp_entry).is_present() } {
            if unsafe { (*pdp_entry).is_super_page(self.pte_format) } {
                return Err(IommuError::AlreadyMapped);
            }
            return Ok(None);
        }
        let mut pd_scope = self.allocate_page_table()?;
        pd_scope.attach_to_parent(pdp_entry, pdp_phys, self.pte_format, 2);
        Ok(Some(pd_scope))
    }

    /// Ensure a PT (Level 1) table exists for the given PD entry, allocating if needed.
    pub(super) unsafe fn ensure_pt_table(
        &self,
        pd_entry: *mut SlPte,
        pd_phys: u64,
    ) -> Result<Option<PageTableScope>, IommuError> {
        if unsafe { (*pd_entry).is_present() } {
            return Ok(None);
        }
        let mut pt_scope = self.allocate_page_table()?;
        pt_scope.attach_to_parent(pd_entry, pd_phys, self.pte_format, 1);
        Ok(Some(pt_scope))
    }

    pub(super) unsafe fn ensure_pdp_for_super_page(
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

    /// Cascade-cleanup empty page tables after all 4K entries in a PT are removed.
    pub(super) unsafe fn cleanup_empty_page_tables_4k(
        &self,
        pml4_entry: *mut SlPte,
        pdp_entry: *mut SlPte,
        _pdp_table: *mut SlPte,
        pdp_phys: u64,
        pd_entry: *mut SlPte,
        _pd_table: *mut SlPte,
        pd_phys: u64,
        _pt_table: *mut SlPte,
        pt_phys: u64,
        _layout: alloc::alloc::Layout,
    ) {
        if get_ref_count(pt_phys) != 0 {
            return;
        }

        // Remove PT from hierarchy
        unsafe {
            *pd_entry = SlPte::new();
        }

        // Quarantine PT instead of immediate deallocation
        if let Some(pt) =
            crate::io::iommu::common::dma::page_table_pool::reconstruct_pooled_pt(pt_phys)
        {
            if let Ok(mut pending) = self.pending_pt_release.lock() {
                pending.push(pt);
            }
        }

        if !dec_ref(pd_phys) {
            return;
        }

        // Remove PD from hierarchy
        unsafe {
            *pdp_entry = SlPte::new();
        }

        // Quarantine PD
        if let Some(pd) =
            crate::io::iommu::common::dma::page_table_pool::reconstruct_pooled_pt(pd_phys)
        {
            if let Ok(mut pending) = self.pending_pt_release.lock() {
                pending.push(pd);
            }
        }

        if !dec_ref(pdp_phys) {
            return;
        }

        // Remove PDP from hierarchy
        unsafe {
            *pml4_entry = SlPte::new();
        }

        // Quarantine PDP
        if let Some(pdp) =
            crate::io::iommu::common::dma::page_table_pool::reconstruct_pooled_pt(pdp_phys)
        {
            if let Ok(mut pending) = self.pending_pt_release.lock() {
                pending.push(pdp);
            }
        }

        let pml4_phys =
            virt_ptr_to_phys(self.page_table as *const u8).expect("Failed to get pml4 phys");
        dec_ref(pml4_phys);
    }
}
