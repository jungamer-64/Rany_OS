// ============================================================================
// kernel/src/io/iommu/common/domain/unmap_ops.rs
// ============================================================================
//
// NOTE: this module formerly also contained `map_buffer`, but mapping logic
// has been relocated to `map_ops.rs` to preserve the expectation that the
// filename reflects its contents.  The remaining methods focus on unmapping
// and related DMA handle teardown.

use super::*;

impl IommuDomain {
    /// Unmap a contiguous run of 4KB entries within a single PT.
    pub(super) fn unmap_range_4k(&self, iova: u64, pages: usize) -> Result<usize, IommuError> {
        if pages == 0 {
            return Ok(0);
        }

        let pt_idx = Self::level_index(iova, 1);
        let pages_in_pt = core::cmp::min(pages, PT_ENTRIES - pt_idx);

        unsafe {
            let (pt_table, table_phys_by_level, parent_entry_by_level) =
                self.walk_table_path_to_level(iova, 1, true)?;
            let pt_phys = table_phys_by_level[1];
            if pt_phys == 0 {
                return Err(IommuError::HardwareError);
            }

            Self::verify_pt_entries_present(pt_table, pt_idx, pages_in_pt)?;

            for idx in 0..pages_in_pt {
                let pt_entry = pt_table.add(pt_idx + idx);
                *pt_entry = SlPte::new();
                let _ = dec_ref(pt_phys);
            }

            if get_ref_count(pt_phys) == 0 {
                self.reclaim_empty_table_cascade(1, &table_phys_by_level, &parent_entry_by_level);
            }
        }

        Ok(pages_in_pt)
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
        let shard = self.shard_for_iova(iova);
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

    // =========================================================================
    // DMA unmap helpers
    // =========================================================================

    #[cfg(test)]
    pub(crate) fn drop_mapping_for_test(&self, iova: u64) -> Option<DmaMapping> {
        let mapping = self.mapping(iova)?;
        let (start_shard, end_shard) = self.shard_range(iova, mapping.size).ok()?;
        let mut guards = self.lock_shards(start_shard, end_shard).ok()?;
        for guard in guards.iter_mut() {
            guard.mappings.remove(iova);
        }
        self.mapped_size.fetch_sub(mapping.size, Ordering::Relaxed);
        Some(mapping)
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
        mut handle: crate::io::iommu::common::dma::handle::DmaHandle<T>,
        context: &dyn IommuHardwareContext,
        invalidator: &I,
    ) -> Result<crate::ipc::RRef<T>, crate::io::iommu::common::dma::handle::UnmapError<T>> {
        use crate::io::iommu::common::dma::handle::{UnmapError, UnmapErrorKind};

        let iova = handle.iova();
        let size = handle.size();

        // Page-align the size (round up)
        let aligned_size = (size + 4095) & !4095;

        // 1. Monitor page table releases to detect if paging-structure caches need clearing
        let pts_before = self.pending_pt_release.lock().map(|p| p.len()).unwrap_or(0);

        // Unmap from page tables
        if let Err(e) = self.unmap(iova) {
            return Err(UnmapError::new(handle, UnmapErrorKind::IommuError(e)));
        }

        let pts_after = self.pending_pt_release.lock().map(|p| p.len()).unwrap_or(0);
        let pt_removed = pts_after > pts_before;

        // 2. Invalidate IOTLB
        let mut req = InvalidateRequest::pages(self.id, iova, aligned_size).with_ats();
        if pt_removed {
            // SECURITY: If a page table was removed, we MUST perform a domain-selective
            // invalidation to clear cached paging-structure entries (Level 2/3/4 caches).
            // Page-selective invalidation is NOT sufficient for clearing intermediate caches.
            req = InvalidateRequest::domain(self.id).with_ats();
        }

        if let Err(e) = invalidator.invalidate(req) {
            // IOTLB invalidation failed - this is critical!
            // We can't return the RRef because device may still access it
            return Err(UnmapError::new(handle, UnmapErrorKind::IommuError(e)));
        }

        // 3. If we performed a domain-selective flush, it is safe to release the PTs now
        if pt_removed {
            let _ = self.flush(invalidator, context);
        }

        // SECURITY: Use immediate free because we have just confirmed IOTLB invalidation
        // for this specific range (or the entire domain). Bypassing the allocator's
        // internal quarantine is safe here and prevents permanent IOVA leaks since
        // the per-domain allocator's epoch is not automatically advanced by the controller.
        if let Err(e) = self.free_iova_immediate(iova, aligned_size) {
            log::error!(
                "[IommuDomain] IOVA immediate free failed for 0x{:x}: {:?}",
                iova,
                e
            );
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
        mut handle: crate::io::iommu::common::dma::handle::DmaHandle<T>,
        context: &dyn IommuHardwareContext,
        invalidator: &I,
    ) -> Result<crate::ipc::RRef<T>, crate::io::iommu::common::dma::handle::UnmapError<T>> {
        use crate::io::iommu::common::dma::handle::{UnmapError, UnmapErrorKind};

        let iova = handle.iova();
        let size = handle.size();
        let domain_id = self.id;

        // Page-align the size (round up)
        let aligned_size = (size + 4095) & !4095;

        // 1. Monitor page table releases
        let pts_before = self.pending_pt_release.lock().map(|p| p.len()).unwrap_or(0);

        // Unmap from page tables (sync)
        if let Err(e) = self.unmap(iova) {
            return Err(UnmapError::new(handle, UnmapErrorKind::IommuError(e)));
        }

        let pts_after = self.pending_pt_release.lock().map(|p| p.len()).unwrap_or(0);
        let pt_removed = pts_after > pts_before;

        // 2. Invalidate IOTLB asynchronously
        let mut req = InvalidateRequest::pages(domain_id, iova, aligned_size).with_ats();
        if pt_removed {
            // SECURITY: Clear paging-structure entries
            req = InvalidateRequest::domain(domain_id).with_ats();
        }

        if let Err(e) = invalidator.invalidate_async(req).await {
            // IOTLB invalidation failed - critical!
            // We can't return the RRef because device may still access it
            return Err(UnmapError::new(handle, UnmapErrorKind::IommuError(e)));
        }

        // 3. Cleanup released PTs after confirmed invalidation
        if pt_removed {
            let _ = self.flush(invalidator, context);
        }

        // SECURITY: Use immediate free because we have just confirmed IOTLB invalidation
        // for this range (async). Bypassing the allocator's internal quarantine is safe
        // here and prevents permanent IOVA leaks.
        if let Err(e) = self.free_iova_immediate(iova, aligned_size) {
            log::error!(
                "[IommuDomain] IOVA async immediate free failed for 0x{:x}: {:?}",
                iova,
                e
            );
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
        // LOOP_PROOF: mode=condition; reason=Index increments each iteration and loop exits at PT_ENTRIES or returns once a child table is found.;
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
    /// depth multiplied by the fan-out (PT_ENTRIES), but in practice
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
    /// - The domain must not be in use by hardware and should already be detached
    pub(crate) unsafe fn deallocate_page_tables_iterative(&mut self) {
        unsafe {
            let layout = alloc::alloc::Layout::from_size_align(
                PT_ENTRIES * core::mem::size_of::<SlPte>(),
                4096,
            )
            .expect("invalid page table layout");

            /// Stack entry for iterative page table traversal.
            /// Using a fixed-size array avoids heap allocation during Drop.
            #[derive(Clone, Copy)]
            struct StackEntry {
                table_ptr: *mut SlPte,
                level: usize,
                next_idx: usize, // Next child index to process
            }

            // Maximum stack depth: one entry per level, plus entries being processed.
            // 5-level page tables still fit well within this bound.
            const MAX_STACK_DEPTH: usize = 32;
            let mut stack: [StackEntry; MAX_STACK_DEPTH] = [StackEntry {
                table_ptr: core::ptr::null_mut(),
                level: 0,
                next_idx: 0,
            }; MAX_STACK_DEPTH];
            // Push root table
            stack[0] = StackEntry {
                table_ptr: self.page_table,
                level: self.page_table_levels() as usize,
                next_idx: 0,
            };
            let mut stack_top: usize = 1;

            // LOOP_PROOF: mode=condition; reason=Explicit traversal stack is popped as children finish and loop exits when stack_top reaches zero.;
            while stack_top > 0 {
                let entry_idx = stack_top - 1;

                // Copy current entry values to avoid borrow conflicts
                let table_ptr = stack[entry_idx].table_ptr;
                let level = stack[entry_idx].level;
                let next_idx = stack[entry_idx].next_idx;

                // Leaf level (level 1) or all children processed - free this table
                if level <= 1 || next_idx >= PT_ENTRIES {
                    stack_top -= 1;

                    // Return table to pool (it will unregister if pool is full and truly deallocating)
                    if let Ok(phys) = virt_ptr_to_phys(table_ptr as *const u8) {
                        if let Some(pt) =
                            crate::io::iommu::common::dma::page_table_pool::reconstruct_pooled_pt(
                                phys,
                            )
                        {
                            self.page_table_pool.release(pt);
                        } else {
                            // Fallback for direct allocations not in registry
                            unregister_page_table(phys);
                            alloc::alloc::dealloc(table_ptr as *mut u8, layout);
                        }
                    } else {
                        alloc::alloc::dealloc(table_ptr as *mut u8, layout);
                    }
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
        }
    }
}
