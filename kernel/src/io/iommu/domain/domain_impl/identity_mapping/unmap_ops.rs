use super::*;

impl IommuDomain {

    /// Unmap a contiguous run of 4KB entries within a single PT.
    pub(super) fn unmap_range_4k(&self, iova: u64, pages: usize) -> Result<usize, IommuError> {
        if pages == 0 {
            return Ok(0);
        }

        let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
        let pdp_idx = ((iova >> 30) & 0x1FF) as usize;
        let pd_idx = ((iova >> 21) & 0x1FF) as usize;
        let pt_idx = ((iova >> 12) & 0x1FF) as usize;
        let pages_in_pt = core::cmp::min(pages, PT_ENTRIES - pt_idx);

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
            if (*pdp_entry).is_super_page(self.pte_format) {
                return Err(IommuError::InvalidAlignment);
            }
            let pd_table = (*pdp_entry).phys_addr() as *mut SlPte;
            let pd_phys = (*pdp_entry).phys_addr();

            let pd_entry = pd_table.add(pd_idx);
            if !(*pd_entry).is_present() {
                return Err(IommuError::NotMapped);
            }
            if (*pd_entry).is_super_page(self.pte_format) {
                return Err(IommuError::InvalidAlignment);
            }
            let pt_table = (*pd_entry).phys_addr() as *mut SlPte;
            let pt_phys = (*pd_entry).phys_addr();

            Self::verify_pt_entries_present(pt_table, pt_idx, pages_in_pt)?;

            for idx in 0..pages_in_pt {
                let pt_entry = pt_table.add(pt_idx + idx);
                *pt_entry = SlPte::new();
                let _ = dec_ref(pt_phys);
            }

            self.cleanup_empty_page_tables_4k(
                pml4_entry, pdp_entry, pdp_table, pdp_phys,
                pd_entry, pd_table, pd_phys,
                pt_table, pt_phys, layout,
            );
        }

        Ok(pages_in_pt)
    }

    /// Unmap a single entry at `iova` and return the unmapped size.
    #[allow(dead_code)]
    pub(super) fn unmap_entry(&self, iova: u64) -> Result<u64, IommuError> {
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
    #[allow(unused_assignments)]
    pub(super) fn unmap_page(&self, iova: u64) -> Result<(), IommuError> {
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
        self.mapped_size.load(Ordering::Relaxed)
    }

    pub(crate) fn poison(&self) {
        if !self.poisoned.swap(true, Ordering::AcqRel) {
            self.notify_security(SecurityEvent::QuarantinePoisoned { domain_id: self.id });
            log::error!(
                "[IommuDomain] domain {} poisoned due to rollback failure",
                self.id
            );
        }
    }

    /// Lookup a mapping by its IOVA base.
    pub fn mapping(&self, iova: u64) -> Option<DmaMapping> {
        let shard = Self::shard_for_iova(iova);
        let guard = match self.shards[shard].lock() {
            Ok(guard) => guard,
            Err(_) => return None,
        };
        guard.mappings.lookup(iova).cloned()
    }

    /// Get a snapshot of all mappings (deduplicated across shards).
    /// Returns mappings sorted by IOVA address.
    pub fn mappings_snapshot(&self) -> Vec<DmaMapping> {
        let mut snapshot = Vec::new();
        for shard in self.shards.iter() {
            let guard = match shard.lock() {
                Ok(guard) => guard,
                Err(_) => continue,
            };
            for mapping in guard.mappings.iter() {
                // Deduplicate by IOVA (only add if not already present)
                if !snapshot.iter().any(|m: &DmaMapping| m.iova == mapping.iova) {
                    snapshot.push(mapping.clone());
                }
            }
        }
        // Sort by IOVA for consistent ordering
        snapshot.sort_by_key(|m| m.iova);
        snapshot
    }

    #[cfg(test)]
    pub fn drop_mapping_for_test(&self, iova: u64) -> Option<DmaMapping> {
        let mapping = self.mapping(iova)?;
        let (start_shard, end_shard) = self.shard_range(iova, mapping.size).ok()?;
        let mut guards = self.lock_shards(start_shard, end_shard).ok()?;
        for guard in guards.iter_mut() {
            guard.mappings.remove(iova);
        }
        self.mapped_size
            .fetch_sub(mapping.size, Ordering::Relaxed);
        Some(mapping)
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
        &self,
        rref: crate::ipc::RRef<T>,
        context: &dyn IommuHardwareContext,
        direction: crate::io::iommu::dma_handle::DmaDirection,
    ) -> Result<crate::io::iommu::dma_handle::DmaHandle<T>, crate::io::iommu::dma_handle::MapError<T>> {
        use crate::io::iommu::dma_handle::{DmaHandle, MapError, MapErrorKind, MappingKind};
        use x86_64::VirtAddr;

        // Get physical address from RRef's virtual pointer
        let virt_ptr = &*rref as *const T as u64;
        let virt_addr = VirtAddr::new(virt_ptr);
        let phys_addr = crate::mm::virt::mapping::virt_to_phys(virt_addr);
        let phys = phys_addr.as_u64();

        let size = core::mem::size_of::<T>() as u64;

        // Page-align the size (round up)
        let aligned_size = (size + 4095) & !4095;
        if aligned_size == 0 {
            return Err(MapError::new(rref, MapErrorKind::InvalidAlignment));
        }

        // Allocate IOVA from domain's per-domain allocator (Phase 7)
        // This eliminates lock contention between domains for 100Gbps+ I/O
        let iova = match self.allocate_iova(aligned_size) {
            Ok(addr) => addr,
            Err(e) => return Err(MapError::new(rref, MapErrorKind::IommuError(e))),
        };
        let _ = context; // context kept for API compatibility but not used for IOVA

        // Determine permissions from direction
        let (read, write) = match direction {
            crate::io::iommu::dma_handle::DmaDirection::ToDevice => (true, false),
            crate::io::iommu::dma_handle::DmaDirection::FromDevice => (false, true),
            crate::io::iommu::dma_handle::DmaDirection::Bidirectional => (true, true),
        };

        // Create page table mappings
        if let Err(e) = self.map(iova, phys, aligned_size, read, write) {
            // Mapping failed - free IOVA back to domain allocator and return error with RRef
            let _ = self.free_iova(iova, aligned_size);
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
        &self,
        mut handle: crate::io::iommu::dma_handle::DmaHandle<T>,
        context: &dyn IommuHardwareContext,
        invalidator: &I,
    ) -> Result<crate::ipc::RRef<T>, crate::io::iommu::dma_handle::UnmapError<T>> {
        use crate::io::iommu::dma_handle::{UnmapError, UnmapErrorKind};

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

        // Free IOVA back to domain's per-domain allocator
        if let Err(e) = self.free_iova(iova, aligned_size) {
            // IOVA free failed - log but continue since mapping is already removed
            log::warn!("[IommuDomain] IOVA free failed for 0x{:x}: {:?}", iova, e);
        }
        let _ = context; // context kept for API compatibility

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
        &self,
        mut handle: crate::io::iommu::dma_handle::DmaHandle<T>,
        context: &dyn IommuHardwareContext,
        invalidator: &I,
    ) -> Result<crate::ipc::RRef<T>, crate::io::iommu::dma_handle::UnmapError<T>> {
        use crate::io::iommu::dma_handle::{UnmapError, UnmapErrorKind};

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

    /// Find the next child page table entry starting from `start_idx`.
    ///
    /// Returns `(child_ptr, child_level, next_idx_after_child)` or `None` if no child found.
    unsafe fn find_next_child_table(
        table_ptr: *mut SlPte,
        level: usize,
        start_idx: usize,
        pte_format: PteFormat,
    ) -> Option<(*mut SlPte, usize, usize)> {
        let mut idx = start_idx;
        while idx < PT_ENTRIES {
            let pte = unsafe { *table_ptr.add(idx) };
            idx += 1;

            if !pte.is_present() {
                continue;
            }

            // Skip super pages (2MB at level 2, 1GB at level 3)
            if (level == 3 || level == 2) && pte.is_super_page(pte_format) {
                continue;
            }

            let child_phys = pte.phys_addr();
            let child_ptr = phys_to_virt_usize(child_phys) as *mut SlPte;
            return Some((child_ptr, level - 1, idx));
        }
        None
    }

    /// Iteratively deallocate all page tables using an explicit stack.
    ///
    /// This implementation avoids recursion entirely by using a fixed-size
    /// explicit stack. The stack size is bounded by the maximum page table
    /// depth (PT_LEVELS) multiplied by the fan-out (PT_ENTRIES), but in practice
    /// we process tables level-by-level to keep stack usage minimal.
    ///
    /// # Design
    ///
    /// Uses post-order traversal: children are freed before parents.
    /// The algorithm:
    /// 1. Push root table with level info
    /// 2. For each table, push all child tables (non-super-page entries)
    /// 3. When a table has no more children to process, free it
    ///
    /// # Safety
    /// - The domain must not be in use by hardware (IOMMU disabled or domain detached)
    pub(crate) unsafe fn deallocate_page_tables_iterative(&mut self) { unsafe {
        let layout =
            alloc::alloc::Layout::from_size_align(PT_ENTRIES * core::mem::size_of::<SlPte>(), 4096)
                .expect("invalid page table layout");

        /// Stack entry for iterative page table traversal.
        /// Using a fixed-size array avoids heap allocation during Drop.
        #[derive(Clone, Copy)]
        struct StackEntry {
            table_ptr: *mut SlPte,
            level: usize,
            next_idx: usize, // Next child index to process
        }

        // Maximum stack depth: one entry per level, plus entries being processed
        // PT_LEVELS is typically 4, so 16 entries is more than enough for worst case
        const MAX_STACK_DEPTH: usize = 16;
        let mut stack: [StackEntry; MAX_STACK_DEPTH] = [StackEntry {
            table_ptr: core::ptr::null_mut(),
            level: 0,
            next_idx: 0,
        }; MAX_STACK_DEPTH];
        // Push root table
        stack[0] = StackEntry {
            table_ptr: self.page_table,
            level: PT_LEVELS,
            next_idx: 0,
        };
        let mut stack_top: usize = 1;

        while stack_top > 0 {
            let entry_idx = stack_top - 1;

            // Copy current entry values to avoid borrow conflicts
            let table_ptr = stack[entry_idx].table_ptr;
            let level = stack[entry_idx].level;
            let next_idx = stack[entry_idx].next_idx;

            // Leaf level (level 1) or all children processed - free this table
            if level <= 1 || next_idx >= PT_ENTRIES {
                stack_top -= 1;

                // Unregister and deallocate the table
                if let Ok(phys) = virt_ptr_to_phys(table_ptr as *const u8) {
                    unregister_page_table(phys);
                }
                alloc::alloc::dealloc(table_ptr as *mut u8, layout);
                continue;
            }

            // Find next child table to process
            match Self::find_next_child_table(table_ptr, level, next_idx, self.pte_format) {
                Some((child_ptr, child_level, updated_next_idx)) => {
                    stack[entry_idx].next_idx = updated_next_idx;
                    if stack_top < MAX_STACK_DEPTH {
                        stack[stack_top] = StackEntry {
                            table_ptr: child_ptr,
                            level: child_level,
                            next_idx: 0,
                        };
                        stack_top += 1;
                    } else {
                        log::error!(
                            "[IommuDomain] Page table deallocation stack overflow at level {}",
                            level
                        );
                    }
                }
                None => {
                    stack[entry_idx].next_idx = PT_ENTRIES;
                }
            }
        }
    }}

    /// Legacy recursive deallocation - kept for reference but not used.
    #[allow(dead_code)]
    unsafe fn deallocate_page_tables_recursive(&mut self) { unsafe {
        // Delegate to the iterative version
        self.deallocate_page_tables_iterative();
    }}
}
