use super::*;

mod _split_1;
impl IommuDomain {

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
}
