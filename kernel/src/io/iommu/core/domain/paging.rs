// ============================================================================
// kernel/src/io/iommu/core/domain/paging.rs
// ============================================================================

use super::*;

impl IommuDomain {
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
            let child = unsafe { (*entry).phys_addr() as *mut SlPte };
            let phys = unsafe { (*entry).phys_addr() };
            Ok((child, phys, None))
        } else {
            let mut scope = self.allocate_page_table()?;
            scope.attach_to_parent(entry, parent_phys, self.pte_format, level);
            let child = unsafe { (*entry).phys_addr() as *mut SlPte };
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
        unsafe { *pd_entry = SlPte::new(); }

        // Quarantine PT instead of immediate deallocation
        if let Some(pt) = crate::io::iommu::core::dma::page_table_pool::reconstruct_pooled_pt(pt_phys) {
            if let Ok(mut pending) = self.pending_pt_release.lock() {
                pending.push(pt);
            }
        }

        if !dec_ref(pd_phys) {
            return;
        }

        // Remove PD from hierarchy
        unsafe { *pdp_entry = SlPte::new(); }

        // Quarantine PD
        if let Some(pd) = crate::io::iommu::core::dma::page_table_pool::reconstruct_pooled_pt(pd_phys) {
            if let Ok(mut pending) = self.pending_pt_release.lock() {
                pending.push(pd);
            }
        }

        if !dec_ref(pdp_phys) {
            return;
        }

        // Remove PDP from hierarchy
        unsafe { *pml4_entry = SlPte::new(); }

        // Quarantine PDP
        if let Some(pdp) = crate::io::iommu::core::dma::page_table_pool::reconstruct_pooled_pt(pdp_phys) {
            if let Ok(mut pending) = self.pending_pt_release.lock() {
                pending.push(pdp);
            }
        }

        let pml4_phys = virt_ptr_to_phys(self.page_table as *const u8)
            .expect("Failed to get pml4 phys");
        dec_ref(pml4_phys);
    }
}
