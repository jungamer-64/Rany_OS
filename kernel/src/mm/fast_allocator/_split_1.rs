use super::*;


impl FastBitmapAllocator {
    /// Create a new fast bitmap allocator
    pub fn new(base: u64, size: u64) -> Self {
        let total_pages = (size / PAGE_SIZE_4K) as usize;
        let bitmap = HugePageBitmap::new(total_pages);

        // Calculate arena sizes
        let total_words_4k = (total_pages + BITS_PER_WORD - 1) / BITS_PER_WORD;
        let total_blocks_2m = total_pages / PAGES_PER_2MB_BLOCK;

        let words_per_cpu = (total_words_4k + MAX_CPUS - 1) / MAX_CPUS;
        let blocks_2m_per_cpu = if total_blocks_2m >= MAX_CPUS {
            (total_blocks_2m + MAX_CPUS - 1) / MAX_CPUS
        } else {
            1
        };

        // Create per-CPU magazines
        let mut magazines = Vec::with_capacity(MAX_CPUS);
        for cpu_id in 0..MAX_CPUS {
            let mut mag = PerCpuFastMagazine::new();

            let arena_start_4k = cpu_id * words_per_cpu;
            let arena_end_4k = ((cpu_id + 1) * words_per_cpu).min(total_words_4k);

            let arena_start_2m = cpu_id * blocks_2m_per_cpu;
            let arena_end_2m = ((cpu_id + 1) * blocks_2m_per_cpu).min(total_blocks_2m);

            mag.set_arena(cpu_id, arena_start_4k, arena_end_4k, arena_start_2m, arena_end_2m);
            magazines.push(mag);
        }

        let arena_ownership = ArenaOwnership::new(total_words_4k, MAX_CPUS);

        Self {
            base,
            size,
            bitmap,
            magazines: magazines.into_boxed_slice(),
            arena_ownership,
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
    fn current_cpu_id() -> Option<usize> {
        crate::mm::per_cpu::try_current_cpu_id().filter(|&cpu_id| cpu_id < MAX_CPUS)
    }

    // ========================================================================
    // Single-Writer Arena Management
    // ========================================================================

    /// Enable single-writer arena mode
    pub fn enable_single_writer_arenas(&self) {
        let global_detail = self.bitmap.detail();

        for cpu_id in 0..MAX_CPUS {
            let magazine = &self.magazines[cpu_id];

            if magazine.arena_end_4k > magazine.arena_start_4k {
                let num_words = magazine.arena_end_4k - magazine.arena_start_4k;

                // Only enable if arena fits or use windowing
                if num_words <= MAX_WORDS_PER_ARENA * 4 {
                    magazine.init_single_writer_arena(global_detail);
                }
            }
        }
    }

    /// Sync single-writer arenas to global bitmap
    pub fn sync_single_writer_arenas(&self) {
        let global_detail = self.bitmap.detail();

        for cpu_id in 0..MAX_CPUS {
            let magazine = &self.magazines[cpu_id];
            if magazine.is_single_writer_enabled() {
                let arena_guard = magazine.arena_detail.lock();
                if let Some(ref arena) = *arena_guard {
                    arena.sync_to_global(global_detail);
                }
            }
        }
    }

    // ========================================================================
    // 4KB Allocation
    // ========================================================================

    /// Single-writer arena から 4KB ページの割り当てを試みる
    fn try_arena_4k(&self, magazine: &PerCpuFastMagazine) -> Option<u64> {
        if !magazine.is_single_writer_enabled() {
            return None;
        }
        let mut arena_guard = magazine.arena_detail.lock();
        let arena = arena_guard.as_mut()?;
        if arena.is_frozen() {
            return None;
        }
        self.try_arena_allocate_page(arena)
    }

    /// arena から1ページ割り当て (ウィンドウリロード含む)
    fn try_arena_allocate_page(&self, arena: &mut PerArenaDetail) -> Option<u64> {
        if let Some(page_idx) = arena.allocate_page() {
            self.stats.single_writer_allocs.fetch_add(1, Ordering::Relaxed);
            return Some(self.base + (page_idx as u64) * PAGE_SIZE_4K);
        }
        if arena.is_windowed() && arena.has_next_window() {
            let global_detail = self.bitmap.detail();
            if arena.reload_next_window(global_detail) {
                if let Some(page_idx) = arena.allocate_page() {
                    self.stats.single_writer_allocs.fetch_add(1, Ordering::Relaxed);
                    return Some(self.base + (page_idx as u64) * PAGE_SIZE_4K);
                }
            }
        }
        None
    }

    /// Per-CPU マガジンから 4KB ページの割り当てを試みる (sub-magazine + magazine)
    fn try_magazine_4k(&self, magazine: &PerCpuFastMagazine) -> Option<u64> {
        {
            let mut sub_mag = magazine.sub_magazine_4k.lock();
            if sub_mag.has_frames() {
                if let Some(frame) = sub_mag.allocate() {
                    let addr = frame.start_address().as_u64();
                    self.stats.magazine_hits.fetch_add(1, Ordering::Relaxed);
                    return Some(addr);
                }
            }
        }
        if let Some(mag_lock) = magazine.get_magazine(0) {
            let mut mag = mag_lock.lock();
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
        if let Some(cpu_id) = Self::current_cpu_id() {
            let magazine = &self.magazines[cpu_id];
            if let Some(addr) = self.try_arena_4k(magazine) {
                return Some(addr);
            }
            if let Some(addr) = self.try_magazine_4k(magazine) {
                return Some(addr);
            }
        }
        // Slow path: bitmap allocation
        self.allocate_4k_from_bitmap()
    }

    /// Allocate from bitmap (slow path)
    fn allocate_4k_from_bitmap(&self) -> Option<u64> {
        // Try partial 2MB blocks first (hugepage preservation)
        if let Some(page_idx) = self.bitmap.allocate_4k_from_partial() {
            let addr = self.base + (page_idx as u64) * PAGE_SIZE_4K;
            self.stats.bitmap_allocs.fetch_add(1, Ordering::Relaxed);
            self.stats.allocs_from_partial_2m.fetch_add(1, Ordering::Relaxed);
            return Some(addr);
        }

        // Fallback: use base hierarchical bitmap
        if let Some(page_idx) = self.bitmap.base_bitmap().allocate_one() {
            let addr = self.base + (page_idx as u64) * PAGE_SIZE_4K;
            self.stats.bitmap_allocs.fetch_add(1, Ordering::Relaxed);
            self.stats.hugepage_pollutions.fetch_add(1, Ordering::Relaxed);
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
        if let Some(cpu_id) = Self::current_cpu_id() {
            let magazine = &self.magazines[cpu_id];
            if let Some(mag_lock) = magazine.get_magazine(1) {
                let mut mag = mag_lock.lock();
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
        if limit <= self.base { return None; }
        
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
        if limit <= self.base { return None; }

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
         if limit <= self.base { return None; }

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
        if let Some(cpu_id) = Self::current_cpu_id() {
            let magazine = &self.magazines[cpu_id];
            if self.try_free_single_writer(magazine, page_idx) {
                return true;
            }
            if Self::try_free_magazine(magazine, addr) {
                return true;
            }
        }

        // Fallback: direct bitmap free
        self.bitmap.free_4k(page_idx)
    }

    /// Attempt to free a page via the single-writer arena path.
    fn try_free_single_writer(&self, magazine: &PerCpuFastMagazine, page_idx: usize) -> bool {
        if !magazine.is_single_writer_enabled() {
            return false;
        }
        let mut arena_guard = magazine.arena_detail.lock();
        if let Some(ref mut arena) = *arena_guard {
            if arena.in_current_window(page_idx) && !arena.is_frozen() {
                if arena.free_page(page_idx) {
                    self.stats.single_writer_frees.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
            }
        }
        false
    }

    /// Attempt to free a page via the per-CPU magazine.
    fn try_free_magazine(magazine: &PerCpuFastMagazine, addr: u64) -> bool {
        if let Some(mag_lock) = magazine.get_magazine(0) {
            let mut mag = mag_lock.lock();
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
        if let Some(cpu_id) = Self::current_cpu_id() {
            let magazine = &self.magazines[cpu_id];
            if let Some(mag_lock) = magazine.get_magazine(1) {
                let mut mag = mag_lock.lock();
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
    // Remote Free Draining
    // ========================================================================

    /// Drain remote free ring for current CPU
    pub fn drain_remote_frees(&self) -> usize {
        let Some(cpu_id) = Self::current_cpu_id() else {
            return 0;
        };

        self.drain_remote_frees_for_cpu(cpu_id)
    }

    /// Drain remote free ring for a specific CPU
    #[allow(unused_assignments)]
    fn drain_remote_frees_for_cpu(&self, cpu_id: usize) -> usize {
        let magazine = &self.magazines[cpu_id];
        let mut drained = 0;

        // Drain entries from remote free ring using closure
        let base = self.base;
        let bitmap = &self.bitmap;
        
        drained = magazine.remote_free_ring.drain_with(64, |entry| {
            let page_idx = ((entry.addr - base) / PAGE_SIZE_4K) as usize;
            let _ = bitmap.free_4k(page_idx);
        });

        if drained > 0 {
            self.stats.remote_frees_drained.fetch_add(drained as u64, Ordering::Relaxed);
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

    /// Reconfigure arenas for specific CPU list (NUMA-aware)
    pub fn reconfigure_for_cpu_ids(&mut self, cpu_ids: &[usize]) {
        let total_pages = self.bitmap.total_pages();
        let total_words_4k = (total_pages + BITS_PER_WORD - 1) / BITS_PER_WORD;
        let total_blocks_2m = total_pages / PAGES_PER_2MB_BLOCK;

        let num_cpus = cpu_ids.len().max(1);
        let words_per_cpu = (total_words_4k + num_cpus - 1) / num_cpus;
        let blocks_2m_per_cpu = if total_blocks_2m >= num_cpus {
            (total_blocks_2m + num_cpus - 1) / num_cpus
        } else {
            1
        };

        for (idx, &cpu_id) in cpu_ids.iter().enumerate() {
            if cpu_id < MAX_CPUS {
                let arena_start_4k = (idx * words_per_cpu).min(total_words_4k);
                let arena_end_4k = ((idx + 1) * words_per_cpu).min(total_words_4k);

                let arena_start_2m = (idx * blocks_2m_per_cpu).min(total_blocks_2m);
                let arena_end_2m = ((idx + 1) * blocks_2m_per_cpu).min(total_blocks_2m);

                let mag = &mut self.magazines[cpu_id];
                mag.set_arena(cpu_id, arena_start_4k, arena_end_4k, arena_start_2m, arena_end_2m);
                mag.single_writer_enabled.store(false, Ordering::Release);
                *mag.arena_detail.lock() = None;
            }
        }

        self.arena_ownership.reconfigure_for_cpu_list(total_words_4k, cpu_ids);
    }

    // ========================================================================
    // Reserve/Contiguous Allocation (PMM compatibility)
    // ========================================================================

    /// Reserve a range of addresses (mark as allocated)
    ///
    /// Used for marking memory holes, reserved regions, etc.
    pub fn reserve(&self, start: u64, size: u64) -> Result<(), ()> {
        if start < self.base || size == 0 {
            return Err(());
        }

        let end = start.saturating_add(size);
        if end > self.base + self.size {
            return Err(());
        }

        let start_page = ((start - self.base) / PAGE_SIZE_4K) as usize;
        let end_page = ((end - self.base) / PAGE_SIZE_4K) as usize;

        for page_idx in start_page..end_page {
            self.bitmap.base_bitmap().mark_allocated(page_idx);
            self.bitmap.on_page_allocated(page_idx);
        }

        Ok(())
    }

    /// 指定範囲の連続ページを確保してマークする
    fn try_mark_contiguous_range(&self, start_page: usize, pages_needed: usize) -> bool {
        let base_bitmap = self.bitmap.base_bitmap();
        if !base_bitmap.is_range_free(start_page, pages_needed) {
            return false;
        }
        for i in 0..pages_needed {
            if !base_bitmap.mark_allocated(start_page + i) {
                // Rollback
                for j in 0..i {
                    base_bitmap.mark_free(start_page + j);
                }
                return false;
            }
            self.bitmap.on_page_allocated(start_page + i);
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

        let pages_needed = ((size + PAGE_SIZE_4K - 1) / PAGE_SIZE_4K) as usize;
        let align_pages = ((align + PAGE_SIZE_4K - 1) / PAGE_SIZE_4K) as usize;
        let total_pages = self.bitmap.total_pages();

        // Simple linear scan for contiguous free pages
        let mut start_page = 0;
        while start_page < total_pages {
            // Align start
            if start_page % align_pages != 0 {
                start_page = ((start_page / align_pages) + 1) * align_pages;
                continue;
            }

            if start_page + pages_needed > total_pages {
                break;
            }

            if self.try_mark_contiguous_range(start_page, pages_needed) {
                let addr = self.base + (start_page as u64) * PAGE_SIZE_4K;
                self.stats.bitmap_allocs.fetch_add(1, Ordering::Relaxed);
                return Some(addr);
            }

            start_page += 1;
        }

        None
    }

    /// Free immediately (without quarantine)
    pub fn free_immediate(&self, addr: u64, granularity: PageGranularity) -> Result<(), ()> {
        match granularity {
            PageGranularity::Page4K => {
                if self.free_4k(addr) { Ok(()) } else { Err(()) }
            }
            PageGranularity::Page2M => {
                if self.free_2m(addr) { Ok(()) } else { Err(()) }
            }
            PageGranularity::Page1G => {
                if self.free_1g(addr) { Ok(()) } else { Err(()) }
            }
        }
    }

    /// Free a range of pages immediately
    pub fn free_range_immediate(&self, start: u64, size: u64) -> Result<(), ()> {
        if start < self.base || size == 0 {
            return Err(());
        }

        let end = start.saturating_add(size);
        if end > self.base + self.size {
            return Err(());
        }

        let start_page = ((start - self.base) / PAGE_SIZE_4K) as usize;
        let end_page = ((end - self.base) / PAGE_SIZE_4K) as usize;

        for page_idx in start_page..end_page {
            self.bitmap.free_4k(page_idx);
        }

        Ok(())
    }

    /// Get PMM-compatible stats (free_pages, total_pages)
    pub fn pmm_stats(&self) -> (u64, usize) {
        (self.free_count() as u64, self.total_pages())
    }
}
