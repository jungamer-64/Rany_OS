use super::*;


mod promotion;
pub use promotion::*;
impl ProcessAddressSpace {
    /// 新しいアドレス空間を作成
    pub fn new() -> Self {
        Self {
            asid: allocate_asid(),
            page_table_root: AtomicU64::new(0),
            regions: RwLock::new(BTreeMap::new()),
            vma_list: VmaList::new(),
            heap_end: AtomicU64::new(DEFAULT_HEAP_START),
            mmap_hint: AtomicU64::new(DEFAULT_MMAP_BASE),
            stack_top: AtomicU64::new(DEFAULT_STACK_TOP),
            memcg_id: MemcgId::ROOT,
            mapped_pages: AtomicU64::new(0),
            initialized: AtomicBool::new(false),
        }
    }
    
    /// ページテーブルを初期化
    pub fn init_page_table(&self) -> Result<(), AddressSpaceError> {
        // 新しいページテーブルを割り当て
        let frame = alloc_frame().ok_or(AddressSpaceError::OutOfMemory)?;
        let pt_phys = frame.start_address().as_u64();
        
        // ゼロクリア
        let virt = crate::mm::mapping::phys_to_virt(frame.start_address());
        unsafe {
            core::ptr::write_bytes(virt.as_u64() as *mut u8, 0, PAGE_SIZE as usize);
        }
        
        // カーネル空間のマッピングをコピー（Higher Half）
        let current_pml4_phys = crate::mm::higher_half::get_cr3();
        let new_pml4_phys = PhysAddr::new(pt_phys);
        let kernel_pml4_index = VirtAddr::new(KERNEL_SPACE_START).page_table_indices()[0];
        unsafe {
            let current_pml4 = &*crate::mm::higher_half::phys_to_virt(current_pml4_phys)
                .as_ptr::<crate::mm::higher_half::PageTable>();
            let new_pml4 = &mut *crate::mm::higher_half::phys_to_virt(new_pml4_phys)
                .as_mut_ptr::<crate::mm::higher_half::PageTable>();

            for i in kernel_pml4_index..512 {
                *new_pml4.entry_mut(i) = *current_pml4.entry(i);
            }
        }
        
        self.page_table_root.store(pt_phys, Ordering::Release);
        self.initialized.store(true, Ordering::Release);
        
        Ok(())
    }
    
    /// ASIDを取得
    pub fn asid(&self) -> u64 {
        self.asid
    }
    
    /// ページテーブルルートを取得
    pub fn page_table_root(&self) -> u64 {
        self.page_table_root.load(Ordering::Acquire)
    }
    
    // ========================================================================
    // Memory Region Management
    // ========================================================================
    
    /// 領域を追加
    pub fn add_region(&self, region: MemoryRegion) -> Result<(), AddressSpaceError> {
        let start = region.start.as_u64();
        let end = region.end.as_u64();
        
        // 範囲チェック
        if start >= end {
            return Err(AddressSpaceError::InvalidRange);
        }
        
        let mut regions = self.regions.write();
        
        // 重複チェック
        for existing in regions.values() {
            if existing.overlaps(region.start, region.end) {
                return Err(AddressSpaceError::RegionOverlap);
            }
        }
        
        let vma = region.to_vma();
        regions.insert(start, Box::new(region));
        self.vma_list.insert(Box::new(vma));
        Ok(())
    }
    
    /// アドレスに対応する領域を検索
    pub fn find_region(&self, addr: VirtAddr) -> Option<u64> {
        self.vma_list.find(addr).map(|info| info.start.as_u64())
    }
    
    /// 領域を取得
    pub fn get_region(&self, start_addr: u64) -> Option<Protection> {
        let regions = self.regions.read();
        regions.get(&start_addr).map(|r| r.protection)
    }
    
    /// 領域を削除
    pub fn remove_region(&self, start_addr: u64) -> Result<(), AddressSpaceError> {
        let mut regions = self.regions.write();
        
        if let Some(region) = regions.remove(&start_addr) {
            let _ = self.vma_list.remove(region.start);
            // マッピングを解除
            let page_count = region.page_count();
            for i in 0..page_count {
                let addr = VirtAddr::new(region.start.as_u64() + i * PAGE_SIZE);
                unsafe { let _ = global_unmap_page(addr); }
            }
            self.mapped_pages.fetch_sub(page_count, Ordering::Relaxed);
            Ok(())
        } else {
            Err(AddressSpaceError::RegionNotFound)
        }
    }
    
    // ========================================================================
    // Memory Mapping API (mmap/munmap/mprotect)
    // ========================================================================
    
    /// メモリをマッピング（mmapの実装）
    pub fn mmap(
        &self,
        addr_hint: Option<VirtAddr>,
        size: u64,
        prot: Protection,
        region_type: RegionType,
    ) -> Result<VirtAddr, AddressSpaceError> {
        if size == 0 {
            return Err(AddressSpaceError::InvalidSize);
        }
        
        let size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1); // ページアラインメント
        
        // アドレスを決定
        let start_addr = if let Some(hint) = addr_hint {
            hint.as_u64()
        } else {
            // mmap領域から割り当て
            let hint = self.mmap_hint.fetch_add(size, Ordering::Relaxed);
            hint
        };
        
        let start = VirtAddr::new(start_addr);
        let end = VirtAddr::new(start_addr + size);
        
        // 領域を作成
        let region = MemoryRegion::new(start, end, region_type, prot);
        self.add_region(region)?;
        
        // Demand Pagingを使用するため、実際のページ割り当ては遅延
        // （ページフォルト時に割り当て）
        
        Ok(start)
    }
    
    /// メモリのマッピングを解除（munmapの実装）
    pub fn munmap(&self, addr: VirtAddr, size: u64) -> Result<(), AddressSpaceError> {
        if size == 0 {
            return Err(AddressSpaceError::InvalidSize);
        }
        
        let start_key = self.find_region(addr)
            .ok_or(AddressSpaceError::RegionNotFound)?;
        
        self.remove_region(start_key)
    }
    
    /// mprotectで必要な領域分割を行い、新領域を登録する
    pub(super) fn split_and_reinsert_regions(
        &self,
        regions: &mut alloc::collections::BTreeMap<u64, Box<MemoryRegion>>,
        region: Box<MemoryRegion>,
        req_start: VirtAddr,
        req_end: VirtAddr,
        prot: Protection,
    ) {
        let _ = self.vma_list.remove(region.start);

        let mut new_regions = Vec::new();
        if req_start > region.start {
            new_regions.push(clone_region_with_range(&region, region.start, req_start, region.protection));
        }
        new_regions.push(clone_region_with_range(&region, req_start, req_end, prot));
        if req_end < region.end {
            new_regions.push(clone_region_with_range(&region, req_end, region.end, region.protection));
        }

        for new_region in new_regions {
            let start = new_region.start.as_u64();
            let vma = new_region.to_vma();
            regions.insert(start, Box::new(new_region));
            self.vma_list.insert(Box::new(vma));
        }
    }

    /// メモリ保護を変更（mprotectの実装）
    pub fn mprotect(&self, addr: VirtAddr, size: u64, prot: Protection) -> Result<(), AddressSpaceError> {
        let start_key = self.find_region(addr)
            .ok_or(AddressSpaceError::RegionNotFound)?;
        
        let mut regions = self.regions.write();
        
        let region = match regions.remove(&start_key) {
            Some(region) => region,
            None => return Err(AddressSpaceError::RegionNotFound),
        };

        // 範囲チェック
        let mut req_start = addr;
        let mut req_end = VirtAddr::new(addr.as_u64() + size);
        if size == 0 {
            req_start = region.start;
            req_end = region.end;
        }
        if req_end > region.end {
            regions.insert(start_key, region);
            return Err(AddressSpaceError::InvalidRange);
        }

        self.split_and_reinsert_regions(&mut regions, region, req_start, req_end, prot);

        // ページテーブルエントリを更新
        let page_count = size / PAGE_SIZE;
        for i in 0..page_count {
            let page_addr = VirtAddr::new(addr.as_u64() + i * PAGE_SIZE);
            let flags = prot.to_page_flags();
            unsafe { let _ = crate::mm::higher_half::global_update_flags(page_addr, flags); }
        }

        Ok(())
    }
    
    // ========================================================================
    // Heap Management (brk)
    // ========================================================================
    
    /// ヒープ境界を取得
    pub fn brk(&self) -> u64 {
        self.heap_end.load(Ordering::Acquire)
    }
    
    /// ヒープ境界を設定
    pub fn set_brk(&self, new_brk: u64) -> Result<u64, AddressSpaceError> {
        let current = self.heap_end.load(Ordering::Acquire);
        
        if new_brk < DEFAULT_HEAP_START {
            return Err(AddressSpaceError::InvalidRange);
        }
        
        if new_brk > current {
            // ヒープ拡張
            let size = new_brk - current;
            let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
            
            // Memcgチャージ
            let pages = aligned_size / PAGE_SIZE;
            if memcg_charge(self.memcg_id, pages, ChargeType::Anon).is_err() {
                return Err(AddressSpaceError::OutOfMemory);
            }
            
            // 実際のページ割り当てはDemand Paging
        } else if new_brk < current {
            // ヒープ縮小
            let size = current - new_brk;
            let pages = size / PAGE_SIZE;
            
            // ページを解放
            for i in 0..pages {
                let addr = VirtAddr::new(new_brk + i * PAGE_SIZE);
                if let Some(phys) = global_translate(addr) {
                    unsafe { let _ = global_unmap_page(addr); }
                    page_put(phys.as_u64());
                }
            }
            
            memcg_uncharge(self.memcg_id, pages, ChargeType::Anon);
        }
        
        self.heap_end.store(new_brk, Ordering::Release);
        Ok(new_brk)
    }
    
    // ========================================================================
    // Fork Support (Copy-on-Write)
    // ========================================================================
    
    /// アドレス空間を複製（fork用）
    ///
    /// Copy-on-Writeを使用して効率的に複製する。
    /// 全ての書き込み可能ページをRead-onlyに変更し、
    /// フォルト時に実際のコピーを行う。
    pub fn fork(&self) -> Result<Box<ProcessAddressSpace>, AddressSpaceError> {
        let child = Box::new(ProcessAddressSpace::new());
        
        // ページテーブルを初期化
        child.init_page_table()?;
        
        let regions = self.regions.read();
        
        for (&start, region) in regions.iter() {
            // 子プロセス用の新しい領域を作成
            let mut child_region = MemoryRegion::new(
                region.start,
                region.end,
                region.region_type,
                region.protection,
            );
            child_region.cow = true;
            child_region.file_info = region.file_info.clone();
            
            // 親のページをCoWとしてマーク
            if region.protection.write {
                let page_count = region.page_count();
                for i in 0..page_count {
                    let addr = VirtAddr::new(region.start.as_u64() + i * PAGE_SIZE);
                    
                    // ページが存在する場合のみ処理
                    if let Some(phys) = global_translate(addr) {
                        // 親をRead-onlyに変更（CoWマーク）
                        let _ = cow_mark_page(addr);
                        
                        // 参照カウントを増加
                        page_get(phys.as_u64());
                        
                        // 子のページテーブルにエントリをコピー
                        let _ = cow_copy_pte(addr, child.page_table_root());
                    }
                }
            }
            
            // 子に領域を追加
            let mut child_regions = child.regions.write();
            let child_vma = child_region.to_vma();
            child_regions.insert(start, Box::new(child_region));
            child.vma_list.insert(Box::new(child_vma));
        }
        
        // ヒープとスタック境界をコピー
        child.heap_end.store(self.heap_end.load(Ordering::Acquire), Ordering::Release);
        child.stack_top.store(self.stack_top.load(Ordering::Acquire), Ordering::Release);
        child.mmap_hint.store(self.mmap_hint.load(Ordering::Acquire), Ordering::Release);
        
        Ok(child)
    }
    
    // ========================================================================
    // Exec Support
    // ========================================================================
    
    /// アドレス空間をリセット（exec用）
    ///
    /// 全てのユーザー空間マッピングを解除し、
    /// 新しいプログラムのロード準備をする。
    pub fn exec_reset(&self) -> Result<(), AddressSpaceError> {
        let mut regions = self.regions.write();
        
        // 全領域を削除
        let keys: Vec<u64> = regions.keys().copied().collect();
        for start in keys {
            if let Some(region) = regions.remove(&start) {
                let _ = self.vma_list.remove(region.start);
                // ユーザー空間のみ解除
                if region.start.as_u64() < KERNEL_SPACE_START {
                    let page_count = region.page_count();
                    for i in 0..page_count {
                        let addr = VirtAddr::new(region.start.as_u64() + i * PAGE_SIZE);
                        if let Some(phys) = global_translate(addr) {
                            unsafe { let _ = global_unmap_page(addr); }
                            page_put(phys.as_u64());
                        }
                    }
                }
            }
        }
        
        // 境界をリセット
        self.heap_end.store(DEFAULT_HEAP_START, Ordering::Release);
        self.mmap_hint.store(DEFAULT_MMAP_BASE, Ordering::Release);
        self.stack_top.store(DEFAULT_STACK_TOP, Ordering::Release);
        self.mapped_pages.store(0, Ordering::Release);
        
        Ok(())
    }
    
    /// 新しいプログラムセグメントをロード
    pub fn load_segment(
        &self,
        vaddr: VirtAddr,
        size: u64,
        prot: Protection,
        region_type: RegionType,
    ) -> Result<(), AddressSpaceError> {
        let region = MemoryRegion::new(
            vaddr,
            VirtAddr::new(vaddr.as_u64() + size),
            region_type,
            prot,
        );
        self.add_region(region)
    }
    
    // ========================================================================
    // Stack Management
    // ========================================================================
    
    /// スタックをセットアップ
    pub fn setup_stack(&self, stack_top: VirtAddr, initial_size: u64, max_size: u64) -> Result<VirtAddr, AddressSpaceError> {
        // スタック領域を作成
        let stack_bottom = VirtAddr::new(stack_top.as_u64() - initial_size);
        
        let region = MemoryRegion::new(
            stack_bottom,
            stack_top,
            RegionType::Stack,
            Protection::READ_WRITE,
        );
        self.add_region(region)?;
        
        // スタック管理に登録
        match create_stack(self.asid, stack_top, initial_size, max_size) {
            StackResult::Ok => {
                self.stack_top.store(stack_top.as_u64(), Ordering::Release);
                Ok(stack_top)
            }
            _ => Err(AddressSpaceError::OutOfMemory),
        }
    }
    
    // ========================================================================
    // Statistics
    // ========================================================================
    
    /// 統計情報を取得
    pub fn stats(&self) -> AddressSpaceStats {
        let regions = self.regions.read();
        
        let mut total_virtual = 0u64;
        let mut region_count = 0usize;
        
        for region in regions.values() {
            total_virtual += region.size();
            region_count += 1;
        }
        
        AddressSpaceStats {
            asid: self.asid,
            total_virtual,
            mapped_pages: self.mapped_pages.load(Ordering::Relaxed),
            region_count,
            heap_size: self.heap_end.load(Ordering::Relaxed) - DEFAULT_HEAP_START,
        }
    }
    /// 領域内のページをスキャンしてNUMAヒントを設定する
    pub(super) fn scan_region_numa_hints(
        &self,
        region_start: VirtAddr,
        region_end: VirtAddr,
        scan_from: VirtAddr,
        remaining: usize,
    ) -> (usize, usize, VirtAddr) {
        let region_scan_start = if scan_from < region_start {
            region_start
        } else {
            scan_from
        };

        let mut page_addr = region_scan_start;
        let mut scanned = 0;
        let mut faults = 0;
        while page_addr < region_end && scanned < remaining {
            if self.update_pte_for_numa_hint(page_addr) {
                faults += 1;
            }
            scanned += 1;
            page_addr = VirtAddr::new(page_addr.as_u64() + PAGE_SIZE);
        }
        (scanned, faults, page_addr)
    }

    /// NUMAヒントスキャンを実行
    ///
    /// 指定されたアドレスからスキャンを開始し、PresentなページのPresentフラグを落とし、
    /// NUMA_HINTフラグを立てる。
    ///
    /// # Returns
    /// (scanned_pages, faults_set, next_scan_addr)
    pub fn scan_numa_hints(&self, start_addr: VirtAddr, batch_size: usize) -> (usize, usize, VirtAddr) {
        let mut scanned = 0;
        let mut faults = 0;
        let mut current_addr = start_addr;
        let regions = self.regions.read();

        for (&_r_start, region) in regions.range(..).filter(|&(&_s, ref r)| r.end > start_addr) {
            if scanned >= batch_size {
                break;
            }

            // スキャン対象外の領域（カーネル、デバイスなど）はスキップ
            match region.region_type {
                RegionType::Data | RegionType::Stack | RegionType::Heap | RegionType::Bss | RegionType::Mmap => {} // OK
                _ => {
                    if current_addr < region.end {
                        current_addr = region.end;
                    }
                    continue;
                }
            }

            let (s, f, next_addr) = self.scan_region_numa_hints(
                region.start, region.end, current_addr, batch_size - scanned,
            );
            scanned += s;
            faults += f;
            current_addr = next_addr;
        }

        (scanned, faults, current_addr)
    }

    /// PTEを更新してNUMAヒントを設定
    pub(super) fn update_pte_for_numa_hint(&self, addr: VirtAddr) -> bool {
        // ページテーブルをウォークしてPTEを取得
        let pt_root = self.page_table_root.load(Ordering::Acquire);
        if pt_root == 0 {
            return false;
        }

        let indices = addr.page_table_indices();
        
        // Manual four-level walk using phys_to_virt
        // Level 4 (PML4)
        let pml4_phys = PhysAddr::new(pt_root);
        let pml4_ptr = crate::mm::higher_half::phys_to_virt(pml4_phys).as_mut_ptr::<crate::mm::higher_half::PageTable>();
        let pml4 = unsafe { &mut *pml4_ptr };
        let pml4e = pml4.entry_mut(indices[0]);
        if !pml4e.is_present() { return false; }

        // Level 3 (PDPT)
        let pdpt_phys = pml4e.phys_addr();
        let pdpt_ptr = crate::mm::higher_half::phys_to_virt(pdpt_phys).as_mut_ptr::<crate::mm::higher_half::PageTable>();
        let pdpt = unsafe { &mut *pdpt_ptr };
        let pdpte = pdpt.entry_mut(indices[1]);
        if !pdpte.is_present() { return false; }
        if pdpte.is_huge() { return false; } // 1GB pages not supported for auto numa yet

        // Level 2 (PD)
        let pd_phys = pdpte.phys_addr();
        let pd_ptr = crate::mm::higher_half::phys_to_virt(pd_phys).as_mut_ptr::<crate::mm::higher_half::PageTable>();
        let pd = unsafe { &mut *pd_ptr };
        let pde = pd.entry_mut(indices[2]);
        if !pde.is_present() { return false; }
        if pde.is_huge() { return false; } // 2MB pages not supported for auto numa yet

        // Level 1 (PT)
        let pt_phys = pde.phys_addr();
        let pt_ptr = crate::mm::higher_half::phys_to_virt(pt_phys).as_mut_ptr::<crate::mm::higher_half::PageTable>();
        let pt = unsafe { &mut *pt_ptr };
        let pte = pt.entry_mut(indices[3]);

        // Hint設定
        if pte.is_present() {
            let mut flags = pte.flags();
            // 既にHintが立っている場合はスキップ
            if flags.contains(PageFlags::NUMA_HINT) {
                return false;
            }
            // Presentを落とし、Hintを立てる
            flags = flags.clear(PageFlags::PRESENT).set(PageFlags::NUMA_HINT);
            pte.set_flags(flags);
            
            // TLB Invalidation handled by caller (usually flush_tlb_local if current, or ignored until next context switch)
            return true;
        }

        false
    }

    /// THP昇格候補を検索
    ///
    /// 指定されたアドレスからスキャンを開始し、昇格可能な2MB領域を探す。
    /// Scan a 2MB-aligned range within a region for THP candidates.
    pub(super) fn scan_aligned_range_for_thp(
        &self,
        scan_start: VirtAddr,
        region_end: VirtAddr,
        limit: usize,
        candidates: &mut Vec<ThpCandidate>,
    ) -> VirtAddr {
        let mut cursor = VirtAddr::new((scan_start.as_u64() + 0x1FFFFF) & !0x1FFFFF);
        while cursor.as_u64() + 0x200000 <= region_end.as_u64() && candidates.len() < limit {
            if let Some(candidate) = self.check_if_thp_candidate(cursor) {
                candidates.push(candidate);
            }
            cursor = VirtAddr::new(cursor.as_u64() + 0x200000);
        }
        cursor
    }

    pub fn find_thp_candidates(&self, start_addr: VirtAddr, limit: usize) -> (Vec<ThpCandidate>, VirtAddr) {
        let mut candidates = Vec::new();
        let mut current_addr = start_addr;
        let regions = self.regions.read();
        
        // Iterate regions starting from start_addr
        for (&_r_start, region) in regions.range(..).filter(|&(&_s, ref r)| r.end > start_addr) {
            if candidates.len() >= limit {
                break;
            }

            // Skip unsuitable regions (e.g. non-Anon, non-aligned size check?)
            match region.region_type {
                 RegionType::Heap | RegionType::Bss | RegionType::Data => {}
                 _ => {
                     // Determine skip
                     if current_addr < region.end { current_addr = region.end; }
                     continue;
                 }
            }
            
            // Adjust scan start within this region
            let region_scan_start = if current_addr < region.start { region.start } else { current_addr };
            current_addr = self.scan_aligned_range_for_thp(region_scan_start, region.end, limit, &mut candidates);
        }
        
        (candidates, current_addr)
    }

    /// Check if a 2MB range is a candidate
    pub(super) fn check_if_thp_candidate(&self, start: VirtAddr) -> Option<ThpCandidate> {
        // Here we need to check if pages are mapped and present
        let mut used_pages = 0;
        
        // This is a simplified check. In reality we'd walk the PT.
        for i in 0..512 {
            let addr = VirtAddr::new(start.as_u64() + i * 4096);
            if let Some(_phys) = global_translate(addr) {
                used_pages += 1;
            }
        }

        // Threshold: 50%
        if used_pages > 256 {
            Some(ThpCandidate {
                start_addr: start,
                used_pages: used_pages as u16,
                flags: 0, // Fill later or get from first page
                priority: ((used_pages * 100 / 512).min(255)) as u8,
            })
        } else {
            None
        }
    }

    /// Promote a 2MB range to a Huge Page
    pub fn promote_huge_page(&self, start_addr: VirtAddr) -> bool {
        // 1. alignment check
        if !start_addr.is_page_aligned() || start_addr.as_u64() & 0x1FFFFF != 0 {
            return false;
        }

        // 2. Get protection flags from region
        let protection = match self.get_region(start_addr.as_u64()) {
            Some(p) => p,
            None => return false,
        };

        // 3. Allocate Huge Frame
        let huge_frame: PhysFrame<Size2MiB> = match alloc_huge_frame() {
            Some(f) => f,
            None => return false,
        };
        let huge_phys_x64 = huge_frame.start_address(); // x86_64::PhysAddr
        let huge_virt = crate::mm::mapping::phys_to_virt(huge_phys_x64); // mapping uses x86_64 types
        // For higher_half functions, convert:
        let _huge_phys = PhysAddr::new(huge_phys_x64.as_u64());

        // 4. Zero the huge page (safety)
        unsafe {
            core::ptr::write_bytes(huge_virt.as_mut_ptr::<u8>(), 0, 0x200000);
        }

        // 5. Copy data and prepare for switch
        let pt_root = self.page_table_root.load(Ordering::Acquire);
        if pt_root == 0 {
            buddy_dealloc_frame_2m(huge_frame);
            return false; 
        }

        // Walk to PDE
        let indices = start_addr.page_table_indices();
        
        // Scope for unsafe PT walk and updates
        let result = unsafe { self.perform_promotion(pt_root, indices, huge_phys_x64, protection) };
        
        if !result {
            buddy_dealloc_frame_2m(huge_frame);
        }
        
        result
    }
}
