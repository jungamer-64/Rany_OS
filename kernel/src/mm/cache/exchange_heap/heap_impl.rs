use super::*;


// SegregatedFreeListHeap は PoisonLock で保護されるため Send/Sync は安全
unsafe impl Send for SegregatedFreeListHeap {}
unsafe impl Sync for SegregatedFreeListHeap {}

impl SegregatedFreeListHeap {
    pub(super) const fn empty() -> Self {
        Self {
            heap_start: 0,
            heap_end: 0,
            free_lists: [None; SIZE_CLASS_COUNT],
            free_bitmap: 0,
            allocated_bytes: 0,
            alloc_count: 0,
            dealloc_count: 0,
            split_count: 0,
            coalesce_count: 0,
        }
    }

    /// サイズからサイズクラスインデックスを計算（切り上げ）
    ///
    /// # Returns
    /// サイズを収容できる最小のクラスインデックス
    #[inline]
    pub(super) fn size_to_class(size: usize) -> usize {
        if size <= MIN_BLOCK_SIZE {
            return 0;
        }
        // size > MIN_BLOCK_SIZE の場合
        // 必要なクラス = ceil(log2(size)) - MIN_BLOCK_SIZE_LOG2
        let bits_needed = usize::BITS - (size - 1).leading_zeros();
        let class = (bits_needed as usize).saturating_sub(MIN_BLOCK_SIZE_LOG2);
        class.min(SIZE_CLASS_COUNT - 1)
    }

    /// サイズクラスからブロックサイズを計算
    #[inline]
    pub(super) fn class_to_size(class: usize) -> usize {
        MIN_BLOCK_SIZE << class
    }

    /// ヒープを初期化
    ///
    /// # Safety
    /// - `heap_start` は有効なメモリ領域を指す
    /// - `size` バイトがアクセス可能
    pub(crate) unsafe fn init(&mut self, heap_start: *mut u8, size: usize) {
        crate::io::log::early_print("[ExHeap] init heap_start=");
        crate::io::log::early_print_hex(heap_start as u64);
        crate::io::log::early_print(" size=");
        crate::io::log::early_print_hex(size as u64);
        crate::io::log::early_print("\n");

        self.heap_start = heap_start as usize;
        self.heap_end = self.heap_start + size;
        self.allocated_bytes = 0;
        self.free_bitmap = 0;
        self.alloc_count = 0;
        self.dealloc_count = 0;
        self.split_count = 0;
        self.coalesce_count = 0;

        // フリーリストをクリア
        for list in self.free_lists.iter_mut() {
            *list = None;
        }

        // 初期状態: 全体を最大サイズのブロックとして登録
        if size >= core::mem::size_of::<FreeBlock>() {
            self.add_free_block(heap_start as usize, size);
        }
    }

    /// 空きブロックを適切なサイズクラスに追加（結合を試みる）
    pub(super) fn add_free_block(&mut self, addr: usize, size: usize) {
        let min_size = MIN_BLOCK_WITH_FOOTER;
        if size < min_size {
            return;
        }

        // Try to coalesce with previous block
        let (final_addr, final_size) = self.try_coalesce_prev(addr, size);
        
        // Try to coalesce with next block
        let (final_addr, final_size) = self.try_coalesce_next(final_addr, final_size);

        let class = Self::size_to_class(final_size);
        let block_ptr = final_addr as *mut FreeBlock;

        unsafe {
            // Set header (use checked store for debug)
            crate::memory::checked_store_usize(block_ptr as usize, final_size, "ExHeap header size store");
            (*block_ptr).next = self.free_lists[class];

            #[cfg(debug_assertions)] {
                let next_val = match (*block_ptr).next { Some(nn) => nn.as_ptr() as usize, None => 0usize };
                if next_val == crate::memory::EXCHANGE_HEAP_SIZE {
                    crate::io::log::early_print("[ExHeap] WARNING: next pointer equal to EXCHANGE_HEAP_SIZE!\n");
                    let bt = crate::unwind::Backtrace::capture();
                    for entry in bt.iter() {
                        crate::io::log::early_print("[ExHeap][BT] IP=");
                        crate::io::log::early_print_hex(entry.frame.instruction_pointer as u64);
                        crate::io::log::early_print("\n");
                    }
                }
            }

            // Set footer (boundary tag) using checked store for its size
            let footer_addr = final_addr + final_size - core::mem::size_of::<BlockFooter>();
            crate::memory::checked_store_usize(footer_addr, final_size, "ExHeap footer size store");
            let footer_ptr = footer_addr as *mut BlockFooter;
            (*footer_ptr).is_free = true;
        }

        self.free_lists[class] = NonNull::new(block_ptr);
        self.free_bitmap |= 1u32 << class;
    }
    
    /// Try to coalesce with the previous block (using its footer)
    pub(super) fn try_coalesce_prev(&mut self, addr: usize, size: usize) -> (usize, usize) {
        if addr <= self.heap_start + core::mem::size_of::<BlockFooter>() {
            return (addr, size);
        }
        
        let prev_footer_addr = addr - core::mem::size_of::<BlockFooter>();
        if prev_footer_addr < self.heap_start {
            return (addr, size);
        }
        
        let prev_footer = unsafe { &*(prev_footer_addr as *const BlockFooter) };
        
        if !prev_footer.is_free {
            return (addr, size);
        }
        
        let prev_size = prev_footer.size;
        if prev_size == 0 || prev_size > addr - self.heap_start {
            return (addr, size);
        }
        
        let prev_addr = addr - prev_size;
        if prev_addr < self.heap_start {
            return (addr, size);
        }
        
        // Remove previous block from its free list
        if self.remove_from_free_list(prev_addr, prev_size) {
            self.coalesce_count += 1;
            return (prev_addr, prev_size + size);
        }
        
        (addr, size)
    }
    
    /// Try to coalesce with the next block
    pub(super) fn try_coalesce_next(&mut self, addr: usize, size: usize) -> (usize, usize) {
        let next_addr = addr + size;
        if next_addr >= self.heap_end {
            return (addr, size);
        }
        
        let next_block = unsafe { &*(next_addr as *const FreeBlock) };
        let next_size = next_block.size;
        
        if next_size == 0 || next_addr + next_size > self.heap_end {
            return (addr, size);
        }
        
        // Check if next block is free by checking its footer
        let next_footer_addr = next_addr + next_size - core::mem::size_of::<BlockFooter>();
        if next_footer_addr >= self.heap_end {
            return (addr, size);
        }
        
        let next_footer = unsafe { &*(next_footer_addr as *const BlockFooter) };
        if !next_footer.is_free {
            return (addr, size);
        }
        
        // Remove next block from its free list
        if self.remove_from_free_list(next_addr, next_size) {
            self.coalesce_count += 1;
            return (addr, size + next_size);
        }
        
        (addr, size)
    }
    
    /// Remove a block from its free list
    pub(super) fn remove_from_free_list(&mut self, addr: usize, size: usize) -> bool {
        let class = Self::size_to_class(size);
        let target_ptr = addr as *mut FreeBlock;
        
        let mut prev: Option<NonNull<FreeBlock>> = None;
        let mut current = self.free_lists[class];
        
        while let Some(block) = current {
            if block.as_ptr() == target_ptr {
                // Found the block, remove it
                let next = unsafe { (*block.as_ptr()).next };
                
                match prev {
                    Some(p) => unsafe { (*p.as_ptr()).next = next },
                    None => self.free_lists[class] = next,
                }
                
                if self.free_lists[class].is_none() {
                    self.free_bitmap &= !(1u32 << class);
                }
                
                return true;
            }
            
            prev = current;
            current = unsafe { (*block.as_ptr()).next };
        }
        
        false
    }

    /// 指定サイズクラスから空きブロックを取得
    pub(super) fn pop_free_block(&mut self, class: usize) -> Option<NonNull<FreeBlock>> {
        let block = self.free_lists[class]?;
        let block_addr = block.as_ptr() as usize;

        // Security check: Validate pointer (High-risk vulnerability fix)
        if block_addr < self.heap_start || block_addr >= self.heap_end {
            panic!("[ExHeap] Security Fault: Corrupted free list (head) at class {}", class);
        }

        unsafe {
            let next = (*block.as_ptr()).next;
            // Security check: Validate next pointer
            if let Some(next_nn) = next {
                let next_addr = next_nn.as_ptr() as usize;
                if next_addr < self.heap_start || next_addr >= self.heap_end {
                    panic!("[ExHeap] Security Fault: Corrupted free list (next) at class {}", class);
                }
            }
            self.free_lists[class] = next;
        }

        // リストが空になったらビットマップをクリア
        if self.free_lists[class].is_none() {
            self.free_bitmap &= !(1u32 << class);
        }

        Some(block)
    }

    /// メモリを割り当て（O(1) Segregated Fit）
    pub(super) fn allocate(&mut self, layout: Layout) -> Result<NonNull<u8>, ()> {
        let align = layout.align().max(core::mem::align_of::<FreeBlock>());
        let size = layout.size().max(core::mem::size_of::<FreeBlock>());

        // 要求サイズに対応するクラスを計算
        let required_class = Self::size_to_class(size);

        // このクラス以上で空きがあるクラスをビットマップで O(1) 探索
        let available_mask = self.free_bitmap & !((1u32 << required_class) - 1);
        if available_mask == 0 {
            return Err(());
        }

        // 最小の空きクラスを取得 (trailing_zeros = tzcnt/bsf 命令)
        let found_class = available_mask.trailing_zeros() as usize;

        // そのクラスからブロックを取得
        let block = self.pop_free_block(found_class).ok_or(())?;
        let block_ptr = block.as_ptr();
        let block_size = unsafe { (*block_ptr).size };
        let block_addr = block_ptr as usize;

        // アライメント調整
        let aligned_addr = (block_addr + align - 1) & !(align - 1);
        let padding = aligned_addr - block_addr;

        // 必要な総サイズ
        let total_needed = padding + size;

        if block_size < total_needed {
            // サイズ不足（通常起こらないが安全のため）
            self.add_free_block(block_addr, block_size);
            return Err(());
        }

        let remaining = block_size - total_needed;

        // 残りが十分大きければ分割して別クラスに戻す
        let min_split_size = core::mem::size_of::<FreeBlock>();
        if remaining >= min_split_size {
            let new_block_addr = aligned_addr + size;
            self.add_free_block(new_block_addr, remaining);
            self.split_count += 1;
        }

        self.allocated_bytes += total_needed;
        self.alloc_count += 1;
        
        // Mark block as allocated in footer
        let footer_addr = aligned_addr + size - core::mem::size_of::<BlockFooter>();
        if footer_addr >= aligned_addr && footer_addr + core::mem::size_of::<BlockFooter>() <= self.heap_end {
            unsafe {
                let footer_ptr = footer_addr as *mut BlockFooter;
                (*footer_ptr).size = size;
                (*footer_ptr).is_free = false;
            }
        }

        Ok(NonNull::new(aligned_addr as *mut u8).expect("aligned addr null"))
    }

    /// メモリを解放
    ///
    /// # Safety
    /// - `ptr` は以前に `allocate` で取得したポインタ
    pub(crate) unsafe fn deallocate(&mut self, ptr: NonNull<u8>, layout: Layout) {
        let size = layout.size().max(core::mem::size_of::<FreeBlock>());
        let addr = ptr.as_ptr() as usize;

        // 境界チェック (Security Check)
        if addr < self.heap_start || addr >= self.heap_end {
            panic!("[ExHeap] Security Fault: deallocate got invalid ptr {:#x} (heap: {:#x}-{:#x})", 
                addr, self.heap_start, self.heap_end);
        }

        // アライメントチェック (Security Check)
        if addr % MIN_BLOCK_SIZE != 0 {
            panic!("[ExHeap] Security Fault: deallocate got unaligned ptr {:#x}", addr);
        }

        // Double-free check via boundary tag (Security Check)
        let footer_addr = addr + size - core::mem::size_of::<BlockFooter>();
        if footer_addr >= addr && footer_addr + core::mem::size_of::<BlockFooter>() <= self.heap_end {
            let footer = unsafe { &*(footer_addr as *const BlockFooter) };
            if footer.is_free {
                panic!("[ExHeap] Security Fault: Double free detected at {:#x}", addr);
            }
        }

        self.allocated_bytes = self.allocated_bytes.saturating_sub(size);
        self.dealloc_count += 1;

        // 空きブロックとして追加
        self.add_free_block(addr, size);
    }

    /// Try to coalesce adjacent free blocks
    ///
    /// Now implemented via boundary tags in add_free_block

    pub(super) fn used(&self) -> usize {
        self.allocated_bytes
    }

    pub(super) fn free(&self) -> usize {
        (self.heap_end - self.heap_start).saturating_sub(self.allocated_bytes)
    }

    /// 拡張統計情報を取得
    pub(super) fn extended_stats(&self) -> ExtendedHeapStats {
        let mut non_empty_classes = 0u32;
        for i in 0..SIZE_CLASS_COUNT {
            if self.free_lists[i].is_some() {
                non_empty_classes |= 1u32 << i;
            }
        }

        ExtendedHeapStats {
            allocated: self.allocated_bytes,
            free: self.free(),
            alloc_count: self.alloc_count,
            dealloc_count: self.dealloc_count,
            split_count: self.split_count,
            coalesce_count: self.coalesce_count,
            non_empty_classes,
        }
    }
}
