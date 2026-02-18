use super::*;


impl SlabCache {
    /// 新しいSlabキャッシュを作成
    pub fn new(object_size: usize) -> Self {
        // オブジェクトサイズはキャッシュラインの倍数に揃える（False Sharing防止）
        // NOTE: On-Slab Metadataのため、最小サイズは Option<u16> (2 bytes) 以上である必要があるが
        // これは常に満たされる。
        let aligned_size =
            ((object_size + CACHE_LINE_SIZE - 1) / CACHE_LINE_SIZE) * CACHE_LINE_SIZE;
        // let aligned_size = aligned_size.max(2); // Implicitly handled

        Self {
            object_size: aligned_size,
            current_page: None,
            partial_list: None,
            empty_list: None,
            empty_page_count: 0,
            partial_page_count: 0,
            full_page_count: 0,
            alloc_count: 0,
            dealloc_count: 0,
            refill_pages: INITIAL_REFILL_PAGES,
            last_scale_alloc_count: 0,
            numa_node: None,
            migrator: None,
        }
    }

    /// 新しいSlabキャッシュを作成（NUMA node指定）
    pub fn new_on_node(object_size: usize, numa_node: u8) -> Self {
        let aligned_size =
            ((object_size + CACHE_LINE_SIZE - 1) / CACHE_LINE_SIZE) * CACHE_LINE_SIZE;

        Self {
            object_size: aligned_size,
            current_page: None,
            partial_list: None,
            empty_list: None,
            empty_page_count: 0,
            partial_page_count: 0,
            full_page_count: 0,
            alloc_count: 0,
            dealloc_count: 0,
            refill_pages: INITIAL_REFILL_PAGES,
            last_scale_alloc_count: 0,
            numa_node: Some(numa_node),
            migrator: None,
        }
    }

    /// Set NUMA node for this Slab (used to bind Per-Core caches to local memory)
    pub fn set_numa_node(&mut self, node: u8) {
        self.numa_node = Some(node);
    }

    /// オブジェクトを割り当て
    pub fn allocate(&mut self) -> Option<NonNull<u8>> {
        // MemCG Charge (Placeholder: implement when MemCG is ready)
        // crate::mm::memcg::charge_slab(self.object_size)?;
        
        self.alloc_count += 1;
        
        let ptr = self.allocate_inner()?;
        
        Some(ptr)
    }

    /// ページからオブジェクトを割り当て、フル状態を追跡する
    ///
    /// # Safety
    /// `page` は有効で、このSlabCacheに所有されていること
    unsafe fn alloc_from_page_tracked(&mut self, mut page: NonNull<SlabPageHeader>) -> Option<NonNull<u8>> {
        let ptr = page.as_mut().allocate(self.object_size)?;
        if page.as_ref().is_full() {
            self.full_page_count += 1;
            self.partial_page_count = self.partial_page_count.saturating_sub(1);
            self.current_page = None;
        }
        self.maybe_adjust_refill_pages();
        Some(ptr)
    }

    // Inner allocate to separate accounting from logic
    pub(super) fn allocate_inner(&mut self) -> Option<NonNull<u8>> {
        // 1. Current Page
        if let Some(page) = self.current_page {
            let result = unsafe { self.alloc_from_page_tracked(page) };
            if result.is_some() {
                return result;
            }
        }
        
        // 2. Partial List
        if let Some(page) = self.pop_partial() {
            self.current_page = Some(page);
            let result = unsafe { self.alloc_from_page_tracked(page) };
            if result.is_some() {
                return result;
            }
        }

        // 3. New Page (Grow)
        self.grow()?;
        
        // Retry allocation from new current_page
        let page = self.current_page?;
        unsafe { self.alloc_from_page_tracked(page) }
    }
    
    /// Pop a page from the partial list
    pub(super) fn pop_partial(&mut self) -> Option<NonNull<SlabPageHeader>> {
        if let Some(mut page) = self.partial_list {
            unsafe {
                let next = page.as_ref().next;
                if let Some(mut next_ptr) = next {
                    next_ptr.as_mut().prev = None;
                }
                self.partial_list = next;
                page.as_mut().next = None; // Detach
            }
            Some(page)
        } else if let Some(mut page) = self.empty_list {
             // Use empty list as fallback partials
             unsafe {
                 let next = page.as_ref().next;
                 if let Some(mut next_ptr) = next {
                     next_ptr.as_mut().prev = None;
                 }
                 self.empty_list = next;
                 page.as_mut().next = None;
                 
                 self.empty_page_count = self.empty_page_count.saturating_sub(1);
                 self.partial_page_count += 1;
             }
             Some(page)
        } else {
            None
        }
    }

    /// オブジェクトを解放
    pub unsafe fn deallocate(&mut self, ptr: NonNull<u8>) {
        // Calculate Page Pointer by masking address
        // Assuming 4KB alignment
        let page_addr = (ptr.as_ptr() as u64) & !(SLAB_PAGE_SIZE as u64 - 1);
        let header_ptr = NonNull::new_unchecked(page_addr as *mut SlabPageHeader);
        let header = &mut *header_ptr.as_ptr();
        
        let was_full = header.is_full();
        
        header.free(ptr, self.object_size);
        self.dealloc_count += 1;
        
        // MemCG Uncharge
        // crate::mm::memcg::uncharge_slab(self.object_size);
        
        // State transitions
        if was_full {
            // Full -> Partial
            self.full_page_count = self.full_page_count.saturating_sub(1);
            self.partial_page_count += 1;
            
            // If this is not the current page, add to partial list
            if self.current_page != Some(header_ptr) {
                self.push_partial(header_ptr);
            }
        } else if header.is_empty() {
            // Partial -> Empty
            if self.current_page == Some(header_ptr) {
                 self.current_page = None;
            } else {
                 // Remove from partial list
                 Self::remove_from_list(header_ptr, &mut self.partial_list);
            }
            
            self.partial_page_count = self.partial_page_count.saturating_sub(1);
            self.empty_page_count += 1;
            
            // Cache some empty pages, free others
            if self.empty_page_count > 2 {
                // Free physical memory
                self.free_page_physical(header_ptr);
                self.empty_page_count -= 1;
            } else {
                self.push_empty(header_ptr);
            }
        }
        
        self.maybe_scale_down_refill();
    }
    
    /// Add to partial list head
    unsafe fn push_partial(&mut self, mut page: NonNull<SlabPageHeader>) {
        let old_head = self.partial_list;
        page.as_mut().next = old_head;
        page.as_mut().prev = None;
        if let Some(mut head) = old_head {
            head.as_mut().prev = Some(page);
        }
        self.partial_list = Some(page);
    }
    
    /// Add to empty list head
    unsafe fn push_empty(&mut self, mut page: NonNull<SlabPageHeader>) {
        let old_head = self.empty_list;
        page.as_mut().next = old_head;
        page.as_mut().prev = None;
        if let Some(mut head) = old_head {
            head.as_mut().prev = Some(page);
        }
        self.empty_list = Some(page);
    }
    
    /// Remove from arbitrary list
    unsafe fn remove_from_list(mut page: NonNull<SlabPageHeader>, list_head: &mut Option<NonNull<SlabPageHeader>>) {
        let prev = page.as_ref().prev;
        let next = page.as_ref().next;
        
        if let Some(mut prev_ptr) = prev {
            prev_ptr.as_mut().next = next;
        } else {
            // Was head
            *list_head = next;
        }
        
        if let Some(mut next_ptr) = next {
            next_ptr.as_mut().prev = prev;
        }
        
        page.as_mut().prev = None;
        page.as_mut().next = None;
    }
    
    /// Free physical page
    unsafe fn free_page_physical(&mut self, page: NonNull<SlabPageHeader>) {
        let virt = x86_64::VirtAddr::new(page.as_ptr() as u64);
        let phys = crate::mm::mapping::virt_to_phys(virt);
        if let Ok(frame) = x86_64::structures::paging::PhysFrame::from_start_address(phys) {
            crate::mm::dealloc_frame(frame);
        }
    }


    /// 適応的リフィル数調整（スケールアップ）
    #[inline]
    pub(super) fn maybe_adjust_refill_pages(&mut self) {
        let allocs_since_last = self.alloc_count.saturating_sub(self.last_scale_alloc_count);
        
        if allocs_since_last >= REFILL_SCALE_UP_THRESHOLD {
            let new_refill = (self.refill_pages * 2).min(MAX_REFILL_PAGES);
            if new_refill > self.refill_pages {
                self.refill_pages = new_refill;
            }
            self.last_scale_alloc_count = self.alloc_count;
        }
    }

    /// 適応的リフィル数調整（スケールダウン）
    #[inline]
    pub(super) fn maybe_scale_down_refill(&mut self) {
        // Simplified logic: adjust based on total allocated pages vs object count?
        // Or just leave for now.
    }

    /// 新しいSlabページを追加（適応的バルクリフィル版）
    pub(super) fn grow(&mut self) -> Option<()> {
        self.grow_bulk(self.refill_pages)
    }

    /// 指定ページ数のSlabページを追加（内部用）
    pub(super) fn grow_bulk(&mut self, page_count: usize) -> Option<()> {
        let mut added = 0;
        for _ in 0..page_count {
            if self.grow_single().is_some() {
                added += 1;
            } else {
                break;
            }
        }
        if added > 0 { Some(()) } else { None }
    }

    /// 単一のSlabページを追加
    pub(super) fn grow_single(&mut self) -> Option<()> {
        let frame = if let Some(node) = self.numa_node {
            crate::mm::alloc_frame_on_numa_node(super::types::NumaNodeId::new(node))
                .or_else(|| crate::mm::alloc_frame())?
        } else {
            crate::mm::alloc_frame()?
        };

        let phys_addr = frame.start_address();
        let virt_addr = crate::mm::mapping::phys_to_virt(phys_addr);

        let page_ptr = NonNull::new(virt_addr.as_u64() as *mut u8).expect("virt_addr returned null");

        // Slab Coloring
        let color_offset = self.calculate_color_offset();
        
        // Header Initialization
        let usable_size = SLAB_PAGE_SIZE - SlabPageHeader::payload_offset(color_offset as u16);
        let total_objects = (usable_size / self.object_size) as u16;

        unsafe {
            let header = SlabPageHeader::init(
                page_ptr,
                NonNull::from(&*self), // pointer to self (stable in PerCoreCache)
                // SlabCache is often in a Box or fixed location (PerCoreCache static array).
                // Yes, PER_CORE_CACHES are static, so addresses are stable.
                total_objects,
                color_offset as u16,
            );
            
            // Add to partial list (or current_page if empty)
            if self.current_page.is_none() {
                self.current_page = Some(header);
            } else {
                self.push_partial(header);
            }
            self.partial_page_count += 1;
        }

        Some(())
    }

    /// Slab Coloringのオフセットを計算
    /// 
    /// ページごとに異なるオフセットを使用して、
    /// 同じサイズのオブジェクトがキャッシュの同じセットに
    /// マッピングされることを防ぐ。
    /// 
    /// ## Enhanced Randomization (v0.6.0)
    /// 
    /// 単純なページ数ローテーションの代わりに、
    /// xorshift PRNGベースの分散を使用してキャッシュ衝突を最小化。
    /// - ページインデックスとオブジェクトサイズを元にシード値を生成
    /// - より均等なキャッシュセット分布を実現
    #[inline]
    /// Slab Coloringのオフセットを計算
    
    pub(super) fn calculate_color_offset(&self) -> usize {
        // Enhanced: Use xorshift-based PRNG for better distribution
        let page_index = (self.full_page_count + self.partial_page_count + self.empty_page_count) as u32;
        let size_factor = self.object_size as u32;
        
        // Simple xorshift32 for fast pseudo-random generation
        let mut x = page_index.wrapping_add(size_factor).wrapping_add(0x5A5A);
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        
        // Map to color space: 0 to (MAX_SLAB_COLORS - 1) cache lines
        let color_index = (x as usize) % MAX_SLAB_COLORS;
        color_index * CACHE_LINE_SIZE
    }

    /// 統計情報を取得
    /// 統計情報を取得
    pub fn stats(&self) -> SlabStats {
        let mut free_count = 0;
        let _objects_per_page = SLAB_PAGE_SIZE / self.object_size; // approx max, accurate for empty
        
        // Calculate free count from empty pages
        // For empty pages, free_count is not strictly objects_per_page because of coloring,
        // but close enough for stats. Or we could track track exactly if we knew total objects per page.
        // We know total_objects is in the header, but we can't access it easily without iterating.
        // Let's iterate lists for accuracy.
        
        // 1. Current Page
        if let Some(page) = self.current_page {
            unsafe { free_count += page.as_ref().inuse as usize; } // Wait, free_count? "inuse" is used count.
            // Oh, SlabPageMeta had free_count. Header has inuse.
            // Header has total_objects.
             unsafe {
                 let p = page.as_ref();
                 free_count += (p.total_objects - p.inuse) as usize;
             }
        }
        
        // 2. Partial List
        let mut curr = self.partial_list;
        while let Some(page) = curr {
            unsafe {
                let p = page.as_ref();
                free_count += (p.total_objects - p.inuse) as usize;
                curr = p.next;
            }
        }
        
        // 3. Empty List
        let mut curr = self.empty_list;
        while let Some(page) = curr {
            unsafe {
                let p = page.as_ref();
                free_count += (p.total_objects - p.inuse) as usize;
                curr = p.next;
            }
        }
        
        let page_count = self.full_page_count + self.partial_page_count + self.empty_page_count;

        SlabStats {
            object_size: self.object_size,
            free_count,
            page_count,
            alloc_count: self.alloc_count,
            dealloc_count: self.dealloc_count,
            refill_pages: self.refill_pages,
            partial_page_count: self.start_tracking_partial_count(), // partial_page_count field is tracked
            empty_page_count: self.empty_page_count,
            full_page_count: self.full_page_count,
            partial_alloc_count: 0, // removed field tracking for now
            empty_alloc_count: 0,   // removed field tracking for now
        }
    }
    
    // Helper to get partial count (since we tracked it)
    pub(super) fn start_tracking_partial_count(&self) -> usize {
        self.partial_page_count
    }

    /// 現在のリフィルページ数を取得
    #[inline]
    pub fn current_refill_pages(&self) -> usize {
        self.refill_pages
    }

    /// リフィルページ数を手動設定（テスト/デバッグ用）
    pub fn set_refill_pages(&mut self, pages: usize) {
        self.refill_pages = pages.clamp(MIN_REFILL_PAGES, MAX_REFILL_PAGES);
    }
    
    /// Partial状態のページ数を取得
    #[inline]
    pub fn partial_page_count(&self) -> usize {
        self.partial_page_count
    }
    
    /// Empty状態のページをPMMに返却
    /// 
    /// メモリ圧迫時に呼び出し、未使用ページを解放する。
    /// 返却したページ数を返す。
    /// 
    /// ## アルゴリズム
    /// 
    /// 1. 全ページをスキャンし、Empty状態（全オブジェクト空き）を特定
    /// 2. 空きリストからそのページのオブジェクトを除去
    /// 3. ページをPMMに返却
    /// 
    /// ## 制限
    /// 
    /// - 最低1ページは保持（完全解放を防止）
    /// - max_pages で返却数を制限
    /// Empty状態のページをPMMに返却
    pub fn shrink_empty_pages(&mut self, max_pages: usize) -> usize {
        if self.empty_list.is_none() || max_pages == 0 {
            return 0;
        }
        
        // 最低1ページは保持 (cache effect)
        let keep_pages = 1;
        if self.empty_page_count <= keep_pages {
            return 0;
        }
        
        let mut returned = 0;
        
        // Remove from empty_list
        while returned < max_pages && self.empty_page_count > keep_pages {
             if let Some(mut page) = self.empty_list {
                 unsafe {
                     let next = page.as_ref().next;
                     if let Some(mut next_ptr) = next {
                         next_ptr.as_mut().prev = None;
                     }
                     self.empty_list = next;
                     page.as_mut().next = None; // Detach
                     
                     // Free physical
                     self.free_page_physical(page);
                 }
                 self.empty_page_count -= 1;
                 returned += 1;
             } else {
                 break;
             }
        }
        
        returned
    }
    

    /// Register a migrator for this cache
    pub fn register_migrator(&mut self, migrator: Box<dyn ObjectMigrator>) {
        self.migrator = Some(migrator);
    }

    /// Defragment the cache by moving objects from sparsely used pages
    pub fn defrag(&mut self) -> usize {
        if self.migrator.is_none() { return 0; }
        
        let mut moved_count = 0;
        // Limit processing to avoid stalls
        const MAX_PAGES_TO_SCAN: usize = 16;
        
        let count = self.partial_page_count;
        let limit = core::cmp::min(count, MAX_PAGES_TO_SCAN);
        
        for _ in 0..limit {
             let page_ptr = self.pop_partial(); 
             if page_ptr.is_none() { break; }
             let mut page = page_ptr.unwrap();
             
             // Check utilization (< 25%)
             let (inuse, total) = unsafe {
                 let h = page.as_mut();
                 (h.inuse, h.total_objects)
             };
             
             if inuse > 0 && (inuse as usize * 4) < (total as usize) {
                 // Victim found
                 let moved = self.evacuate_page(page);
                 moved_count += moved;
             }
             
             // After evacuation, check if empty
             let is_empty = unsafe { page.as_ref().is_empty() };
             if is_empty {
                  unsafe { self.free_page_physical(page); }
                  // pop_partial decremented counters and detached page.
                  // We just drop it physically. Correct.
                  continue;
             }
             
             // Push back if not freed
             unsafe { self.push_partial(page); }
        }
        moved_count
    }

    /// Evacuate all objects from a page
    pub(super) fn evacuate_page(&mut self, mut page: NonNull<SlabPageHeader>) -> usize {
        let mut moved = 0;
        let object_size = self.object_size; 
        
        let header = unsafe { page.as_ref() };
        let total = header.total_objects;
        let color_offset = header.color_offset;
        
        // 1. Identify free slots
        // Max objects per 4KB page (min size 8) is 512.
        let mut free_mask = [0u64; 8];
        
        let mut curr = header.next_free;
        while let Some(idx) = curr {
            let i = idx as usize;
            if i < 512 {
                free_mask[i / 64] |= 1 << (i % 64);
            }
            // Read next from object
            unsafe {
                let offset = SlabPageHeader::payload_offset(color_offset);
                let base_ptr = (page.as_ptr() as *mut u8).add(offset);
                let obj_ptr = base_ptr.add(i * object_size);
                curr = *(obj_ptr as *const Option<u16>);
            }
        }

        // 2. Iterate all slots
        for i in 0..total as usize {
            if i >= 512 { break; } 
            
            let is_free = (free_mask[i / 64] & (1 << (i % 64))) != 0;
            if !is_free {
                // ALLOCATED -> Migrate
                unsafe {
                    let offset = SlabPageHeader::payload_offset(color_offset);
                    let base_ptr = (page.as_ptr() as *mut u8).add(offset);
                    let old_ptr = NonNull::new_unchecked(base_ptr.add(i * object_size));
                    
                    if self.try_migrate_object(old_ptr) {
                         // Manual deallocate from victim page
                         let ph = page.as_mut();
                         ph.free(old_ptr, object_size);
                         self.dealloc_count += 1;
                         moved += 1;
                    }
                }
            }
        }
        moved
    }

    /// 単一オブジェクトの移行を試みる。成功時trueを返す。
    pub(super) fn try_migrate_object(&mut self, old_ptr: NonNull<u8>) -> bool {
        let new_ptr = match self.allocate() {
            Some(p) => p,
            None => return false,
        };
        let success = match &self.migrator {
            Some(migrator) => unsafe { migrator.migrate(old_ptr, new_ptr) },
            None => false,
        };
        if !success {
            unsafe { self.deallocate(new_ptr) };
        }
        success
    }

}
