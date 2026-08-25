use super::*;

impl FastBitmapAllocator {
    /// Create a new fast bitmap allocator
    pub fn new(base: u64, size: u64, cache_policy: LocalCachePolicy) -> Self {
        let total_pages = (size / PAGE_SIZE_4K) as usize;
        let bitmap = HugePageBitmap::new(total_pages);
        let magazines = match cache_policy {
            LocalCachePolicy::PerCpu => {
                alloc::vec![Arc::new(PerCpuFastMagazine::new(CpuId::BOOTSTRAP))]
            }
            LocalCachePolicy::SharedBitmap => Vec::new(),
        };

        Self {
            base,
            size,
            bitmap,
            magazines: IrqPoisonLock::new(magazines),
            provision_lock: PoisonLock::new(()),
            cache_policy,
            stats: FastAllocatorStats::new(),
        }
    }

    /// Get base address
    #[inline]
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Get total size
    #[inline]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Get current CPU ID
    #[inline]
    pub(super) fn current_magazine(&self) -> Option<Arc<PerCpuFastMagazine>> {
        let cpu_id = crate::cpu::CurrentCpu::acquire()?.id();
        self.magazines
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(cpu_id.as_usize())
            .filter(|magazine| magazine.cpu_id == cpu_id)
            .cloned()
    }

    // ========================================================================
    // 4KB Allocation
    // ========================================================================

    /// Per-CPU マガジンから 4KB ページの割り当てを試みる。
    pub(super) fn try_magazine_4k(&self, magazine: &PerCpuFastMagazine) -> Option<u64> {
        if let Some(mag_lock) = magazine.get_magazine(0) {
            let mut mag = mag_lock.lock().expect("lock poisoned");
            if let Some(addr) = mag.pop() {
                self.stats.magazine_hits.fetch_add(1, Ordering::Relaxed);
                return Some(addr);
            }
        }
        None
    }

    /// Allocate a 4KB page
    #[inline]
    pub fn allocate_4k(&self) -> Option<u64> {
        if let Some(magazine) = self.current_magazine() {
            if let Some(addr) = self.try_magazine_4k(&magazine) {
                return Some(addr);
            }
        }
        // Slow path: bitmap allocation
        self.allocate_4k_from_bitmap()
    }

    /// Allocate from bitmap (slow path)
    pub(super) fn allocate_4k_from_bitmap(&self) -> Option<u64> {
        // Try partial 2MB blocks first (hugepage preservation)
        if let Some(page_idx) = self.bitmap.allocate_4k_from_partial() {
            let addr = self.base + (page_idx as u64) * PAGE_SIZE_4K;
            self.stats.bitmap_allocs.fetch_add(1, Ordering::Relaxed);
            self.stats
                .allocs_from_partial_2m
                .fetch_add(1, Ordering::Relaxed);
            return Some(addr);
        }

        // Fallback: use base hierarchical bitmap
        if let Some(page_idx) = self.bitmap.base_bitmap().allocate_one() {
            let addr = self.base + (page_idx as u64) * PAGE_SIZE_4K;
            self.stats.bitmap_allocs.fetch_add(1, Ordering::Relaxed);
            self.stats
                .hugepage_pollutions
                .fetch_add(1, Ordering::Relaxed);
            // Update 2MB hierarchy
            self.bitmap.on_page_allocated(page_idx);
            return Some(addr);
        }

        self.stats.magazine_misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    // ========================================================================
    // 2MB/1GB Allocation
    // ========================================================================

    /// Allocate a 2MB super-page
    pub fn allocate_2m(&self) -> Option<u64> {
        // Try magazine first
        if let Some(magazine) = self.current_magazine() {
            if let Some(mag_lock) = magazine.get_magazine(1) {
                let mut mag = mag_lock.lock().expect("lock poisoned");
                if let Some(addr) = mag.pop() {
                    self.stats.magazine_hits.fetch_add(1, Ordering::Relaxed);
                    return Some(addr);
                }
            }
        }

        // Bitmap fallback
        if let Some(block_idx) = self.bitmap.allocate_2m() {
            let addr = self.base + (block_idx as u64) * PAGE_SIZE_2M;
            self.stats.bitmap_allocs.fetch_add(1, Ordering::Relaxed);
            return Some(addr);
        }

        None
    }

    /// Allocate a 1GB huge-page
    pub fn allocate_1g(&self) -> Option<u64> {
        if let Some(block_idx) = self.bitmap.allocate_1g() {
            let addr = self.base + (block_idx as u64) * PAGE_SIZE_1G;
            self.stats.bitmap_allocs.fetch_add(1, Ordering::Relaxed);
            return Some(addr);
        }
        None
    }

    // ========================================================================
    // Bounded Allocation
    // ========================================================================

    /// Allocate 4KB page below limit
    pub fn allocate_4k_below(&self, limit: u64) -> Option<u64> {
        if limit >= self.base + self.size {
            return self.allocate_4k();
        }
        if limit <= self.base {
            return None;
        }

        // Strict limit: bypass magazine
        let limit_idx = ((limit - self.base) / PAGE_SIZE_4K) as usize;

        if let Some(idx) = self.bitmap.allocate_4k_below(limit_idx) {
            let addr = self.base + (idx as u64) * PAGE_SIZE_4K;
            self.stats.bitmap_allocs.fetch_add(1, Ordering::Relaxed);
            Some(addr)
        } else {
            None
        }
    }

    /// Allocate 2MB page below limit
    pub fn allocate_2m_below(&self, limit: u64) -> Option<u64> {
        if limit >= self.base + self.size {
            return self.allocate_2m();
        }
        if limit <= self.base {
            return None;
        }

        let limit_idx = ((limit - self.base) / PAGE_SIZE_2M) as usize;
        if let Some(idx) = self.bitmap.allocate_2m_below(limit_idx) {
            let addr = self.base + (idx as u64) * PAGE_SIZE_2M;
            self.stats.bitmap_allocs.fetch_add(1, Ordering::Relaxed);
            Some(addr)
        } else {
            None
        }
    }

    /// Allocate 1GB page below limit
    pub fn allocate_1g_below(&self, limit: u64) -> Option<u64> {
        if limit >= self.base + self.size {
            return self.allocate_1g();
        }
        if limit <= self.base {
            return None;
        }

        let limit_idx = ((limit - self.base) / PAGE_SIZE_1G) as usize;
        if let Some(idx) = self.bitmap.allocate_1g_below(limit_idx) {
            let addr = self.base + (idx as u64) * PAGE_SIZE_1G;
            self.stats.bitmap_allocs.fetch_add(1, Ordering::Relaxed);
            Some(addr)
        } else {
            None
        }
    }

    // ========================================================================
    // Free Operations
    // ========================================================================

    /// Free a 4KB page
    pub fn free_4k(&self, addr: u64) -> bool {
        if addr < self.base || addr >= self.base + self.size {
            return false;
        }

        let page_idx = ((addr - self.base) / PAGE_SIZE_4K) as usize;

        // Try local magazine first
        if let Some(magazine) = self.current_magazine() {
            if Self::try_free_magazine(&magazine, addr) {
                return true;
            }
        }

        // Fallback: direct bitmap free
        self.bitmap.free_4k(page_idx)
    }

    /// Attempt to free a page via the per-CPU magazine.
    pub(super) fn try_free_magazine(magazine: &PerCpuFastMagazine, addr: u64) -> bool {
        if let Some(mag_lock) = magazine.get_magazine(0) {
            let mut mag = mag_lock.lock().expect("lock poisoned");
            if !mag.is_full() {
                if mag.push(addr) {
                    return true;
                }
            }
        }
        false
    }

    /// Free a 2MB super-page
    pub fn free_2m(&self, addr: u64) -> bool {
        if addr < self.base || addr >= self.base + self.size {
            return false;
        }

        let block_idx = ((addr - self.base) / PAGE_SIZE_2M) as usize;

        // Try magazine first
        if let Some(magazine) = self.current_magazine() {
            if let Some(mag_lock) = magazine.get_magazine(1) {
                let mut mag = mag_lock.lock().expect("lock poisoned");
                if !mag.is_full() {
                    if mag.push(addr) {
                        return true;
                    }
                }
            }
        }

        self.bitmap.free_2m(block_idx)
    }

    /// Free a 1GB huge-page
    pub fn free_1g(&self, addr: u64) -> bool {
        if addr < self.base || addr >= self.base + self.size {
            return false;
        }

        let block_idx = ((addr - self.base) / PAGE_SIZE_1G) as usize;
        self.bitmap.free_1g(block_idx)
    }

    // ========================================================================
    // CPU-local cache lifecycle
    // ========================================================================

    /// Returns every cached address owned by the executing CPU to the shared
    /// bitmap. The caller must have stopped task polling and disabled local
    /// interrupts so no later cache operation can occur before the CPU parks.
    pub fn quiesce_current_cpu(&self) -> CpuMagazineDrain {
        let Some(magazine) = self.current_magazine() else {
            return CpuMagazineDrain::default();
        };

        self.drain_magazine(&magazine)
    }

    fn drain_magazine(&self, magazine: &PerCpuFastMagazine) -> CpuMagazineDrain {
        let mut drained = CpuMagazineDrain::default();
        for size_class in 0..MAGAZINE_SIZE_CLASSES {
            let magazine_lock = magazine
                .get_magazine(size_class)
                .expect("physical magazine size class is missing");
            let mut cache = magazine_lock.lock().expect("lock poisoned");
            cache.drain(
                |addr| match PageGranularity::from_size_class(size_class as u8) {
                    PageGranularity::Page4K => {
                        assert!(
                            addr >= self.base
                                && addr < self.base.saturating_add(self.size)
                                && addr % PAGE_SIZE_4K == 0,
                            "cached 4KiB address is outside the allocator"
                        );
                        let page = ((addr - self.base) / PAGE_SIZE_4K) as usize;
                        assert!(
                            self.bitmap.free_4k(page),
                            "cached 4KiB address was not allocated in the shared bitmap"
                        );
                        drained.page_4k += 1;
                    }
                    PageGranularity::Page2M => {
                        assert!(
                            addr >= self.base
                                && addr < self.base.saturating_add(self.size)
                                && addr % PAGE_SIZE_2M == 0,
                            "cached 2MiB address is outside the allocator"
                        );
                        let block = ((addr - self.base) / PAGE_SIZE_2M) as usize;
                        assert!(
                            self.bitmap.free_2m(block),
                            "cached 2MiB address was not allocated in the shared bitmap"
                        );
                        drained.page_2m += 1;
                    }
                    PageGranularity::Page1G => {
                        assert!(
                            addr >= self.base
                                && addr < self.base.saturating_add(self.size)
                                && addr % PAGE_SIZE_1G == 0,
                            "cached 1GiB address is outside the allocator"
                        );
                        let block = ((addr - self.base) / PAGE_SIZE_1G) as usize;
                        assert!(
                            self.bitmap.free_1g(block),
                            "cached 1GiB address was not allocated in the shared bitmap"
                        );
                        drained.page_1g += 1;
                    }
                },
            );
        }
        drained
    }

    // ========================================================================
    // Statistics
    // ========================================================================

    /// Get free count for 4KB pages
    #[inline]
    pub fn free_count(&self) -> usize {
        self.bitmap.free_count_4k()
    }

    /// Get free count for 2MB blocks
    #[inline]
    pub fn free_count_2m(&self) -> usize {
        self.bitmap.free_count_2m()
    }

    /// Get free count for 1GB blocks
    #[inline]
    pub fn free_count_1g(&self) -> usize {
        self.bitmap.free_count_1g()
    }

    /// Get total pages
    #[inline]
    pub fn total_pages(&self) -> usize {
        self.bitmap.total_pages()
    }

    /// Get statistics
    pub fn stats(&self) -> &FastAllocatorStats {
        &self.stats
    }

    /// Get access to bitmap for advanced operations
    #[inline]
    pub fn bitmap(&self) -> &HugePageBitmap {
        &self.bitmap
    }

    /// Provision stable cache slots for every discovered CPU identity.
    pub fn provision_cpu_set(&self, cpu_ids: &CpuSet) -> Result<(), CpuCacheProvisionError> {
        if self.cache_policy == LocalCachePolicy::SharedBitmap {
            return Ok(());
        }
        let required_slots = cpu_ids
            .iter()
            .map(CpuId::as_usize)
            .max()
            .map_or(1, |cpu_id| cpu_id + 1);

        let _provision = self
            .provision_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut magazines = {
            let mut registry = self
                .magazines
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            core::mem::take(&mut *registry)
        };

        // The registry is deliberately empty while its backing allocation is
        // grown. Heap allocation can recurse into this PMM; that path must use
        // the shared bitmap instead of attempting to lock this registry again.
        if magazines
            .try_reserve_exact(required_slots.saturating_sub(magazines.len()))
            .is_err()
        {
            let mut registry = self
                .magazines
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            debug_assert!(registry.is_empty());
            *registry = magazines;
            return Err(CpuCacheProvisionError::Allocation);
        }
        while magazines.len() < required_slots {
            let cpu_id = CpuId::from_valid_index(magazines.len());
            magazines.push(Arc::new(PerCpuFastMagazine::new(cpu_id)));
        }

        let mut registry = self
            .magazines
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        debug_assert!(registry.is_empty());
        *registry = magazines;
        Ok(())
    }

    // ========================================================================
    // Reserve/Contiguous Allocation (PMM compatibility)
    // ========================================================================

    /// Reserve a range of addresses (mark as allocated)
    ///
    /// Used for marking memory holes, reserved regions, etc.
    /// Ensures that any page that partially overlaps with the requested range [start, start + size) is reserved.
    pub fn reserve(&self, start: u64, size: u64) -> Result<(), ()> {
        if start < self.base || size == 0 {
            return Err(());
        }

        let end = start.checked_add(size).ok_or(())?;
        if end > self.base.saturating_add(self.size) {
            return Err(());
        }

        // Round down start and round up end to reserve all affected pages
        let start_page = ((start - self.base) / PAGE_SIZE_4K) as usize;
        let end_page = ((end - self.base + PAGE_SIZE_4K - 1) / PAGE_SIZE_4K) as usize;

        for page_idx in start_page..end_page {
            // Only update counts if the page was successfully marked as allocated.
            // This prevents double-incrementing 'used_count_2m' if 'reserve' is called multiple times.
            if self.bitmap.base_bitmap().mark_allocated(page_idx) {
                self.bitmap.on_page_allocated(page_idx);
            }
        }

        Ok(())
    }

    /// 指定範囲の連続ページを確保してマークする
    pub(super) fn try_mark_contiguous_range(&self, start_page: usize, pages_needed: usize) -> bool {
        let base_bitmap = self.bitmap.base_bitmap();
        if !base_bitmap.is_range_free(start_page, pages_needed) {
            return false;
        }
        for i in 0..pages_needed {
            let page_idx = start_page + i;
            if !base_bitmap.mark_allocated(page_idx) {
                // Rollback: must undo both bitmap marking and HugePageBitmap counters
                for j in 0..i {
                    let prev_idx = start_page + j;
                    base_bitmap.mark_free(prev_idx);
                    self.bitmap.on_page_freed(prev_idx);
                }
                return false;
            }
            self.bitmap.on_page_allocated(page_idx);
        }
        true
    }

    /// Allocate contiguous pages
    ///
    /// Returns the start address if successful.
    pub fn allocate_contiguous(&self, size: u64, align: u64) -> Option<u64> {
        if size == 0 || align == 0 {
            return None;
        }

        // Use checked arithmetic to avoid overflow
        let pages_needed = (size.checked_add(PAGE_SIZE_4K - 1)? / PAGE_SIZE_4K) as usize;
        // Ensure alignment is at least page-sized and a multiple of PAGE_SIZE_4K for simplicity
        let align = align.max(PAGE_SIZE_4K);
        let align_pages = (align.checked_add(PAGE_SIZE_4K - 1)? / PAGE_SIZE_4K) as usize;

        if align_pages == 0 {
            return None;
        }

        let total_pages = self.bitmap.total_pages();

        // Simple linear scan for contiguous free pages
        let mut start_page = 0;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while start_page < total_pages {
            // Align start address, taking self.base into account
            let addr = self.base + (start_page as u64) * PAGE_SIZE_4K;
            if addr % align != 0 {
                let next_addr = (addr.checked_add(align - 1)?) / align * align;
                start_page = ((next_addr - self.base) / PAGE_SIZE_4K) as usize;
                continue;
            }

            if start_page.checked_add(pages_needed)? > total_pages {
                break;
            }

            if self.try_mark_contiguous_range(start_page, pages_needed) {
                let addr = self.base + (start_page as u64) * PAGE_SIZE_4K;
                self.stats.bitmap_allocs.fetch_add(1, Ordering::Relaxed);
                return Some(addr);
            }

            start_page = start_page.saturating_add(1);
        }

        None
    }

    /// Free immediately (without quarantine)
    pub fn free_immediate(&self, addr: u64, granularity: PageGranularity) -> Result<(), ()> {
        match granularity {
            PageGranularity::Page4K => {
                if self.free_4k(addr) {
                    Ok(())
                } else {
                    Err(())
                }
            }
            PageGranularity::Page2M => {
                if self.free_2m(addr) {
                    Ok(())
                } else {
                    Err(())
                }
            }
            PageGranularity::Page1G => {
                if self.free_1g(addr) {
                    Ok(())
                } else {
                    Err(())
                }
            }
        }
    }

    /// Free a range of pages immediately
    ///
    /// Only frees pages that are FULLY contained within the specified range [start, start + size).
    pub fn free_range_immediate(&self, start: u64, size: u64) -> Result<(), ()> {
        if start < self.base || size == 0 {
            return Err(());
        }

        let end = start.saturating_add(size);
        if end > self.base + self.size {
            return Err(());
        }

        // Round up start and round down end to find pages fully within range
        let start_page = ((start - self.base + PAGE_SIZE_4K - 1) / PAGE_SIZE_4K) as usize;
        let end_page = ((end - self.base) / PAGE_SIZE_4K) as usize;

        if start_page < end_page {
            for page_idx in start_page..end_page {
                self.bitmap.free_4k(page_idx);
            }
        }

        Ok(())
    }

    /// Get PMM-compatible stats (free_pages, total_pages)
    pub fn pmm_stats(&self) -> (u64, usize) {
        (self.free_count() as u64, self.total_pages())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_cpu_cache_slots_are_stable_and_bounded() {
        let allocator =
            FastBitmapAllocator::new(0x1000_0000, PAGE_SIZE_2M, LocalCachePolicy::PerCpu);
        let sparse =
            CpuSet::from_ids(3, [CpuId::BOOTSTRAP, CpuId::try_from(2usize).unwrap()]).unwrap();

        allocator
            .provision_cpu_set(&sparse)
            .expect("sparse CPU cache provisioning must succeed");
        let registry = allocator.magazines.lock().expect("registry lock poisoned");
        assert_eq!(registry.len(), 3);
        assert_eq!(registry[0].cpu_id, CpuId::BOOTSTRAP);
        assert_eq!(registry[2].cpu_id, CpuId::try_from(2usize).unwrap());
        drop(registry);

        let maximum = CpuSet::from_ids(
            crate::cpu::MAX_POSSIBLE_CPUS,
            [CpuId::try_from(crate::cpu::MAX_POSSIBLE_CPUS - 1).unwrap()],
        )
        .unwrap();
        allocator
            .provision_cpu_set(&maximum)
            .expect("maximum CPU identity must remain provisionable");
        assert_eq!(
            allocator
                .magazines
                .lock()
                .expect("registry lock poisoned")
                .len(),
            crate::cpu::MAX_POSSIBLE_CPUS
        );
    }

    #[test]
    fn draining_cpu_magazine_returns_reserved_page_to_bitmap() {
        let allocator =
            FastBitmapAllocator::new(0x2000_0000, PAGE_SIZE_2M, LocalCachePolicy::PerCpu);
        let addr = allocator
            .allocate_4k_from_bitmap()
            .expect("test page allocation must succeed");
        let magazine = allocator.magazines.lock().expect("registry lock poisoned")[0].clone();
        assert!(FastBitmapAllocator::try_free_magazine(&magazine, addr));
        assert!(!allocator.bitmap.is_page_free(0));

        let drained = allocator.drain_magazine(&magazine);

        assert_eq!(drained.page_4k, 1);
        assert_eq!(drained.total(), 1);
        assert!(allocator.bitmap.is_page_free(0));
    }
}
