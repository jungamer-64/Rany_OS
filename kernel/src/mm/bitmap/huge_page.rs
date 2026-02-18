use super::*;


mod demoted_alloc;
impl HugePageBitmap {
    /// Create a new HugePageBitmap
    ///
    /// # Arguments
    /// * `total_pages` - Total 4KB pages to manage
    ///
    /// # Note
    /// Only **complete** 2MB/1GB blocks are marked as fully-free.
    /// Trailing partial blocks are tracked but not marked as fully-free.
    pub fn new(total_pages: usize) -> Self {
        let base = HierarchicalBitmap::new(total_pages);
        
        // Calculate block counts
        let complete_2m_blocks = total_pages / PAGES_PER_2MB;
        let total_2m_blocks = (total_pages + PAGES_PER_2MB - 1) / PAGES_PER_2MB;
        let complete_1g_blocks = complete_2m_blocks / BLOCKS_2MB_PER_1GB;
        let total_1g_blocks = (total_2m_blocks + BLOCKS_2MB_PER_1GB - 1) / BLOCKS_2MB_PER_1GB;
        
        // 2MB level
        let bitmap_2m_words = (total_2m_blocks + BITS_PER_WORD - 1) / BITS_PER_WORD;
        
        // Initialize used_count_2m (all 0 = all free)
        let used_count_2m: Vec<AtomicU16> = (0..total_2m_blocks)
            .map(|_| AtomicU16::new(0))
            .collect();
        
        // Initialize bitmap_2m (only complete blocks are fully-free)
        let mut bitmap_2m = Vec::with_capacity(bitmap_2m_words);
        for i in 0..bitmap_2m_words {
            let block_start = i * BITS_PER_WORD;
            let remaining = complete_2m_blocks.saturating_sub(block_start);
            let bits = if remaining >= BITS_PER_WORD {
                u64::MAX
            } else {
                (1u64 << remaining) - 1
            };
            bitmap_2m.push(AtomicU64::new(bits));
        }
        
        // Initialize bitmap_2m_partial (all 0 initially)
        let bitmap_2m_partial: Vec<AtomicU64> = (0..bitmap_2m_words)
            .map(|_| AtomicU64::new(0))
            .collect();
        
        // Initialize demoted_2m (all 0)
        let demoted_2m: Vec<AtomicU64> = (0..bitmap_2m_words)
            .map(|_| AtomicU64::new(0))
            .collect();
        
        // Initialize free_word_mask_2m (all 0xFF = all words have free pages)
        let free_word_mask_2m: Vec<AtomicU8> = (0..total_2m_blocks)
            .map(|_| AtomicU8::new(0xFF))
            .collect();
        
        // 1GB level
        let bitmap_1g_words = (total_1g_blocks + BITS_PER_WORD - 1) / BITS_PER_WORD;
        
        // Initialize used_count_1g (all 0)
        let used_count_1g: Vec<AtomicU16> = (0..total_1g_blocks)
            .map(|_| AtomicU16::new(0))
            .collect();
        
        // Initialize bitmap_1g (only complete blocks)
        let mut bitmap_1g = Vec::with_capacity(bitmap_1g_words);
        for i in 0..bitmap_1g_words {
            let block_start = i * BITS_PER_WORD;
            let remaining = complete_1g_blocks.saturating_sub(block_start);
            let bits = if remaining >= BITS_PER_WORD {
                u64::MAX
            } else {
                (1u64 << remaining) - 1
            };
            bitmap_1g.push(AtomicU64::new(bits));
        }
        
        Self {
            base,
            used_count_2m: used_count_2m.into_boxed_slice(),
            bitmap_2m: bitmap_2m.into_boxed_slice(),
            bitmap_2m_partial: bitmap_2m_partial.into_boxed_slice(),
            demoted_2m: demoted_2m.into_boxed_slice(),
            free_word_mask_2m: free_word_mask_2m.into_boxed_slice(),
            total_2m_blocks,
            free_count_2m: AtomicUsize::new(complete_2m_blocks),
            partial_count_2m: AtomicUsize::new(0),
            demoted_count_2m: AtomicUsize::new(0),
            hint_2m: AtomicUsize::new(0),
            hint_2m_partial: AtomicUsize::new(0),
            used_count_1g: used_count_1g.into_boxed_slice(),
            bitmap_1g: bitmap_1g.into_boxed_slice(),
            total_1g_blocks,
            free_count_1g: AtomicUsize::new(complete_1g_blocks),
        }
    }
    
    // ========================================================================
    // Getters
    // ========================================================================
    
    /// Get total 4KB pages
    #[inline]
    pub fn total_pages(&self) -> usize {
        self.base.total_units()
    }
    
    /// Get free 4KB page count
    #[inline]
    pub fn free_count_4k(&self) -> usize {
        self.base.free_count()
    }
    
    /// Get free 2MB block count
    #[inline]
    pub fn free_count_2m(&self) -> usize {
        self.free_count_2m.load(Ordering::Relaxed)
    }
    
    /// Get partial 2MB block count
    #[inline]
    pub fn partial_count_2m(&self) -> usize {
        self.partial_count_2m.load(Ordering::Relaxed)
    }
    
    /// Get free 1GB block count
    #[inline]
    pub fn free_count_1g(&self) -> usize {
        self.free_count_1g.load(Ordering::Relaxed)
    }
    
    /// Get total 2MB blocks
    #[inline]
    pub fn total_2m_blocks(&self) -> usize {
        self.total_2m_blocks
    }
    
    /// Get total 1GB blocks
    #[inline]
    pub fn total_1g_blocks(&self) -> usize {
        self.total_1g_blocks
    }
    
    /// Access base 4KB bitmap
    #[inline]
    pub fn base(&self) -> &HierarchicalBitmap {
        &self.base
    }
    
    // ========================================================================
    // 4KB Allocation (delegates to base)
    // ========================================================================
    
    /// Allocate a single 4KB page
    ///
    /// This is a simple allocation that doesn't consider hugepage preservation.
    /// For hugepage-aware allocation, use `allocate_4k_from_partial()`.
    pub fn allocate_4k(&self) -> Option<usize> {
        let page_idx = self.base.allocate_one()?;
        self.on_page_allocated(page_idx);
        Some(page_idx)
    }
    
    /// Free a 4KB page
    pub fn free_4k(&self, page_idx: usize) -> bool {
        if self.base.mark_free(page_idx) {
            self.on_page_freed(page_idx);
            true
        } else {
            false
        }
    }
    
    /// Check if a 4KB page is free
    #[inline]
    pub fn is_page_free(&self, page_idx: usize) -> bool {
        self.base.is_free(page_idx)
    }
    
    // ========================================================================
    // 2MB Allocation
    // ========================================================================
    
    /// Allocate a fully-free 2MB block
    ///
    /// Returns the block index, or None if no fully-free 2MB blocks available.
    pub fn allocate_2m(&self) -> Option<usize> {
        let hint = self.hint_2m.load(Ordering::Relaxed) % self.bitmap_2m.len().max(1);
        
        for offset in 0..self.bitmap_2m.len() {
            let word_idx = (hint + offset) % self.bitmap_2m.len();
            
            loop {
                let word = self.bitmap_2m[word_idx].load(Ordering::Acquire);
                if word == 0 {
                    break; // No free blocks in this word
                }
                
                let bit_idx = word.trailing_zeros() as usize;
                let bit_mask = 1u64 << bit_idx;
                
                // Try to clear the bit
                match self.bitmap_2m[word_idx].compare_exchange_weak(
                    word,
                    word & !bit_mask,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        let block_idx = word_idx * BITS_PER_WORD + bit_idx;
                        
                        // Mark all 512 pages as allocated in base bitmap
                        let page_start = block_idx * PAGES_PER_2MB;
                        for i in 0..PAGES_PER_2MB {
                            self.base.mark_allocated(page_start + i);
                        }
                        
                        // Update used count
                        self.used_count_2m[block_idx].store(PAGES_PER_2MB as u16, Ordering::Release);
                        
                        // Update free word mask
                        self.free_word_mask_2m[block_idx].store(0, Ordering::Release);
                        
                        // Update 1GB tracking
                        let block_1g = block_idx / BLOCKS_2MB_PER_1GB;
                        if block_1g < self.used_count_1g.len() {
                            let old_used = self.used_count_1g[block_1g].fetch_add(1, Ordering::AcqRel);
                            if old_used == 0 {
                                // 1GB block was fully free, now it's not
                                let word_1g = block_1g / BITS_PER_WORD;
                                let bit_1g = block_1g % BITS_PER_WORD;
                                self.bitmap_1g[word_1g].fetch_and(!(1u64 << bit_1g), Ordering::AcqRel);
                                self.free_count_1g.fetch_sub(1, Ordering::Relaxed);
                            }
                        }
                        
                        self.free_count_2m.fetch_sub(1, Ordering::Relaxed);
                        self.hint_2m.store(word_idx, Ordering::Relaxed);
                        
                        return Some(block_idx);
                    }
                    Err(_) => {
                        core::hint::spin_loop();
                    }
                }
            }
        }
        
        None
    }
    
    /// Free a 2MB block
    ///
    /// All 512 pages in the block must be allocated (used_count == 512).
    pub fn free_2m(&self, block_idx: usize) -> bool {
        if block_idx >= self.total_2m_blocks {
            return false;
        }
        
        // Check if block is fully allocated
        let used = self.used_count_2m[block_idx].load(Ordering::Acquire);
        if used != PAGES_PER_2MB as u16 {
            return false; // Not fully allocated
        }
        
        // Mark all pages as free in base bitmap
        let page_start = block_idx * PAGES_PER_2MB;
        for i in 0..PAGES_PER_2MB {
            self.base.mark_free(page_start + i);
        }
        
        // Update used count
        self.used_count_2m[block_idx].store(0, Ordering::Release);
        
        // Update free word mask
        self.free_word_mask_2m[block_idx].store(0xFF, Ordering::Release);
        
        // Set 2MB fully-free bit
        let word_idx = block_idx / BITS_PER_WORD;
        let bit_idx = block_idx % BITS_PER_WORD;
        self.bitmap_2m[word_idx].fetch_or(1u64 << bit_idx, Ordering::AcqRel);
        self.free_count_2m.fetch_add(1, Ordering::Relaxed);
        
        // Update 1GB tracking
        let block_1g = block_idx / BLOCKS_2MB_PER_1GB;
        if block_1g < self.used_count_1g.len() {
            let old_used = self.used_count_1g[block_1g].fetch_sub(1, Ordering::AcqRel);
            if old_used == 1 {
                // 1GB block is now fully free
                let word_1g = block_1g / BITS_PER_WORD;
                let bit_1g = block_1g % BITS_PER_WORD;
                self.bitmap_1g[word_1g].fetch_or(1u64 << bit_1g, Ordering::AcqRel);
                self.free_count_1g.fetch_add(1, Ordering::Relaxed);
            }
        }
        
        true
    }
    
    /// Check if a 2MB block is fully free
    #[inline]
    pub fn is_2m_free(&self, block_idx: usize) -> bool {
        if block_idx >= self.total_2m_blocks {
            return false;
        }
        let word_idx = block_idx / BITS_PER_WORD;
        let bit_idx = block_idx % BITS_PER_WORD;
        let word = self.bitmap_2m[word_idx].load(Ordering::Acquire);
        (word & (1u64 << bit_idx)) != 0
    }
    
    /// Check if a 2MB block is demoted
    #[inline]
    pub fn is_block_demoted(&self, block_idx: usize) -> bool {
        if block_idx >= self.total_2m_blocks {
            return false;
        }
        let word_idx = block_idx / BITS_PER_WORD;
        let bit_idx = block_idx % BITS_PER_WORD;
        let word = self.demoted_2m[word_idx].load(Ordering::Acquire);
        (word & (1u64 << bit_idx)) != 0
    }
    
    // ========================================================================
    // 1GB Allocation
    // ========================================================================
    
    /// Allocate a fully-free 1GB block
    ///
    /// Returns the block index, or None if no fully-free 1GB blocks available.
    pub fn allocate_1g(&self) -> Option<usize> {
        for word_idx in 0..self.bitmap_1g.len() {
            loop {
                let word = self.bitmap_1g[word_idx].load(Ordering::Acquire);
                if word == 0 {
                    break;
                }
                
                let bit_idx = word.trailing_zeros() as usize;
                let bit_mask = 1u64 << bit_idx;
                
                match self.bitmap_1g[word_idx].compare_exchange_weak(
                    word,
                    word & !bit_mask,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        let block_1g_idx = word_idx * BITS_PER_WORD + bit_idx;
                        
                        // Mark all 512 2MB blocks as allocated
                        let block_2m_start = block_1g_idx * BLOCKS_2MB_PER_1GB;
                        for i in 0..BLOCKS_2MB_PER_1GB {
                            let block_2m = block_2m_start + i;
                            if block_2m < self.total_2m_blocks {
                                // Clear 2MB fully-free bit
                                let w2m = block_2m / BITS_PER_WORD;
                                let b2m = block_2m % BITS_PER_WORD;
                                self.bitmap_2m[w2m].fetch_and(!(1u64 << b2m), Ordering::AcqRel);
                                
                                // Update used count
                                self.used_count_2m[block_2m].store(PAGES_PER_2MB as u16, Ordering::Release);
                                
                                // Clear free word mask
                                self.free_word_mask_2m[block_2m].store(0, Ordering::Release);
                            }
                        }
                        
                        // Mark all pages as allocated
                        let page_start = block_1g_idx * BLOCKS_2MB_PER_1GB * PAGES_PER_2MB;
                        let page_count = BLOCKS_2MB_PER_1GB * PAGES_PER_2MB;
                        for i in 0..page_count {
                            let page = page_start + i;
                            if page < self.base.total_units() {
                                self.base.mark_allocated(page);
                            }
                        }
                        
                        // Update counts
                        self.used_count_1g[block_1g_idx].store(BLOCKS_2MB_PER_1GB as u16, Ordering::Release);
                        self.free_count_1g.fetch_sub(1, Ordering::Relaxed);
                        self.free_count_2m.fetch_sub(BLOCKS_2MB_PER_1GB.min(self.total_2m_blocks - block_2m_start), Ordering::Relaxed);
                        
                        return Some(block_1g_idx);
                    }
                    Err(_) => {
                        core::hint::spin_loop();
                    }
                }
            }
        }
        
        None
    }
    
    /// Check if a 1GB block is fully free
    #[inline]
    pub fn is_1g_free(&self, block_idx: usize) -> bool {
        if block_idx >= self.total_1g_blocks {
            return false;
        }
        let word_idx = block_idx / BITS_PER_WORD;
        let bit_idx = block_idx % BITS_PER_WORD;
        let word = self.bitmap_1g[word_idx].load(Ordering::Acquire);
        (word & (1u64 << bit_idx)) != 0
    }

    /// Free a 1GB block
    ///
    /// All 512 2MB blocks in this 1GB block must be fully allocated.
    pub(crate) fn free_1g(&self, block_idx: usize) -> bool {
        if block_idx >= self.total_1g_blocks {
            return false;
        }
        
        // Free all 512 2MB blocks
        let block_2m_start = block_idx * BLOCKS_2MB_PER_1GB;
        let block_2m_end = (block_2m_start + BLOCKS_2MB_PER_1GB).min(self.total_2m_blocks);
        
        let mut success = true;
        for block_2m in block_2m_start..block_2m_end {
            if !self.free_2m(block_2m) {
                success = false;
            }
        }
        
        success
    }

    // ========================================================================
    // Bounded Allocation (for strict address limits)
    // ========================================================================

    /// Allocate 4KB page below specific limit
    pub fn allocate_4k_below(&self, limit_page_idx: usize) -> Option<usize> {
        // Try partial blocks first (but restricted by limit)
        if let Some(page) = self.allocate_4k_from_partial_below(limit_page_idx) {
             return Some(page);
        }
        
        // Try base bitmap
        if let Some(page) = self.base.allocate_one_below(limit_page_idx) {
             self.on_page_allocated(page);
             return Some(page);
        }
        
        None
    }

    /// Allocate 4KB from partial/demoted blocks below limit
    pub(super) fn allocate_4k_from_partial_below(&self, limit_page_idx: usize) -> Option<usize> {
        let limit_block = (limit_page_idx + PAGES_PER_2MB - 1) / PAGES_PER_2MB;
        let limit_word = (limit_block + BITS_PER_WORD - 1) / BITS_PER_WORD;

        // 1. Try demoted blocks (linear scan 0..limit)
        if let Some(page) = self.scan_bitmap_below(&self.demoted_2m, limit_word, limit_block, limit_page_idx) {
            return Some(page);
        }

        // 2. Try partial blocks (linear scan 0..limit)
        if let Some(page) = self.scan_bitmap_below(&self.bitmap_2m_partial, limit_word, limit_block, limit_page_idx) {
            return Some(page);
        }

        // 3. Demote fully free block (linear scan 0..limit)
        if let Some(block) = self.demote_2m_block_below(limit_block) {
             return self.allocate_from_block(block);
        }

        None
    }

    /// Scan a bitmap for a usable block below the given limits and allocate a page from it.
    /// Scan individual bits in a single bitmap word for an allocatable page below limit.
    pub(super) fn scan_word_bits_below(
        &self,
        word: u64,
        word_idx: usize,
        limit_block: usize,
        limit_page_idx: usize,
    ) -> Option<usize> {
        for bit in 0..BITS_PER_WORD {
            let block_idx = word_idx * BITS_PER_WORD + bit;
            if block_idx >= limit_block { return None; }
            if (word & (1u64 << bit)) != 0 {
                if let Some(page) = self.allocate_from_block(block_idx) {
                    if page < limit_page_idx { return Some(page); }
                }
            }
        }
        None
    }

    pub(super) fn scan_bitmap_below(
        &self,
        bitmap: &[AtomicU64],
        limit_word: usize,
        limit_block: usize,
        limit_page_idx: usize,
    ) -> Option<usize> {
        let scan_end = limit_word.min(bitmap.len());

        for word_idx in 0..scan_end {
            if word_idx * BITS_PER_WORD >= limit_block { break; }
            let word = bitmap[word_idx].load(Ordering::Acquire);
            if word == 0 { continue; }

            if let Some(page) = self.scan_word_bits_below(word, word_idx, limit_block, limit_page_idx) {
                return Some(page);
            }
        }
        None
    }

    /// Demote a fully-free 2MB block below limit
    pub(super) fn demote_2m_block_below(&self, limit_block: usize) -> Option<usize> {
        let limit_word = (limit_block + BITS_PER_WORD - 1) / BITS_PER_WORD;
        let scan_end = limit_word.min(self.bitmap_2m.len());

        for word_idx in 0..scan_end {
            if word_idx * BITS_PER_WORD >= limit_block { return None; }
            loop {
                let word = self.bitmap_2m[word_idx].load(Ordering::Acquire);
                if word == 0 { break; }
                
                let bit_idx = word.trailing_zeros() as usize;
                let block_idx = word_idx * BITS_PER_WORD + bit_idx;
                if block_idx >= limit_block { return None; }

                let bit_mask = 1u64 << bit_idx;
                
                // Check demoted
                let demoted = self.demoted_2m[word_idx].load(Ordering::Acquire);
                if (demoted & bit_mask) != 0 {
                    // Already demoted, try next bit 
                    // But trailing_zeros finds FIRST. If first is demoted, we must mask it out to find next?
                    // Optimized loop should rely on masking or iterator?
                    // This naive loop is broken if we just 'continue' without changing 'word'.
                    // Actually demoted blocks are removed from bitmap_2m? 
                    // No. bitmap_2m tracks "fully free".
                    // demoted_2m tracks "demoted (was fully free, now for 4k)".
                    // If demoted, it IS fully free in 2MB sense? No, it's BEING USESD for 4K.
                    // Wait, `demote_2m_block` implementation (Line 1097) checks `demoted_2m`.
                    // And it attempts to CLEAR `bitmap_2m`.
                    // `match self.bitmap_2m... compare_exchange(word, word & !bit_mask ...)`
                    // So if it succeeds, it REMOVES from bitmap_2m.
                    // So next strict loop read will see 'word' without that bit.
                    // BUT: if we fail CAS or find demoted, we need to retry loop with refreshed 'word'.
                    // My loop `let word = ...` is inside `loop`.
                    
                    // But if (demoted & bit_mask) != 0:
                    // It means bit is set in `bitmap_2m`.
                    // But it is ALSO set in `demoted_2m`?
                    // No, `allocate_4k_from_demoted` consumes pages.
                    // If a block is demoted, it should NOT be in `bitmap_2m` as "Full Free".
                    // Line 1105: `word & !bit_mask`. It clears it from `bitmap_2m`.
                    // So `bitmap_2m` bit 1 means "Fully Free and NOT Demoted".
                    // So `demote_2m_block` check at 1097 `if (demoted_word & bit_mask) != 0` seems redundant or paranoid?
                    // Ah, maybe race condition where it was added to demoted but not yet removed from bitmap_2m (unlikely with CAS).
                    // Or maybe I misunderstand `bitmap_2m` semantics.
                    // `bitmap_2m` = "Fully Free 2MB Block".
                }
                
                match self.bitmap_2m[word_idx].compare_exchange_weak(word, word & !bit_mask, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => {
                        self.demoted_2m[word_idx].fetch_or(bit_mask, Ordering::AcqRel);
                        self.bitmap_2m_partial[word_idx].fetch_or(bit_mask, Ordering::AcqRel);
                        self.free_count_2m.fetch_sub(1, Ordering::Relaxed);
                        self.partial_count_2m.fetch_add(1, Ordering::Relaxed);
                        self.demoted_count_2m.fetch_add(1, Ordering::Relaxed);
                        return Some(block_idx);
                    }
                    Err(_) => { core::hint::spin_loop(); }
                }
            }
        }
        None
    }

    /// Allocate 2MB super-page below specific limit
    pub fn allocate_2m_below(&self, limit_block_idx: usize) -> Option<usize> {
        let limit_word = (limit_block_idx + BITS_PER_WORD - 1) / BITS_PER_WORD;
        let scan_end = limit_word.min(self.bitmap_2m.len());

        for word_idx in 0..scan_end {
            if word_idx * BITS_PER_WORD >= limit_block_idx { return None; }
            loop {
                let word = self.bitmap_2m[word_idx].load(Ordering::Acquire);
                if word == 0 { break; }
                
                let bit_idx = word.trailing_zeros() as usize;
                let block_idx = word_idx * BITS_PER_WORD + bit_idx;
                if block_idx >= limit_block_idx { return None; }
                
                let bit_mask = 1u64 << bit_idx;
                match self.bitmap_2m[word_idx].compare_exchange_weak(word, word & !bit_mask, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => {
                         // Init block logic (duplicated from allocate_2m)
                        self.base.mark_allocated_range(block_idx * PAGES_PER_2MB, PAGES_PER_2MB);
                        self.used_count_2m[block_idx].store(PAGES_PER_2MB as u16, Ordering::Release);
                        self.free_word_mask_2m[block_idx].store(0, Ordering::Release);
                        
                        // Update 1GB tracking
                        let block_1g = block_idx / BLOCKS_2MB_PER_1GB;
                        if block_1g < self.used_count_1g.len() {
                            let old_used = self.used_count_1g[block_1g].fetch_add(1, Ordering::AcqRel);
                            if old_used == 0 {
                                // Was fully free (should have been caught by 1G alloc? No)
                                // If it was 0, it means 1GB was empty.
                                // Clear 1GB free bit
                                let w1g = block_1g / BITS_PER_WORD;
                                let b1g = block_1g % BITS_PER_WORD;
                                self.bitmap_1g[w1g].fetch_and(!(1u64 << b1g), Ordering::AcqRel);
                                self.free_count_1g.fetch_sub(1, Ordering::Relaxed);
                            }
                        }
                        
                        self.free_count_2m.fetch_sub(1, Ordering::Relaxed);
                        return Some(block_idx);
                    }
                    Err(_) => { core::hint::spin_loop(); }
                }
            }
        }
        None
    }

    /// Allocate 1GB huge-page below specific limit
    pub fn allocate_1g_below(&self, limit_block_idx: usize) -> Option<usize> {
        let limit_word = (limit_block_idx + BITS_PER_WORD - 1) / BITS_PER_WORD;
        let scan_end = limit_word.min(self.bitmap_1g.len());

        for word_idx in 0..scan_end {
            if word_idx * BITS_PER_WORD >= limit_block_idx { return None; }
            loop {
                let word = self.bitmap_1g[word_idx].load(Ordering::Acquire);
                if word == 0 { break; }
                
                let bit_idx = word.trailing_zeros() as usize;
                let block_idx = word_idx * BITS_PER_WORD + bit_idx;
                if block_idx >= limit_block_idx { return None; }

                let bit_mask = 1u64 << bit_idx;
                match self.bitmap_1g[word_idx].compare_exchange_weak(word, word & !bit_mask, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => {
                         // Initialize 1GB block (duplicated from allocate_1g)
                         // Mark 2MB blocks as allocated
                        let block_2m_start = block_idx * BLOCKS_2MB_PER_1GB;
                        for i in 0..BLOCKS_2MB_PER_1GB {
                             let block_2m = block_2m_start + i;
                             if block_2m < self.total_2m_blocks {
                                  // Clear 2MB free bit
                                  let w2m = block_2m / BITS_PER_WORD;
                                  let b2m = block_2m % BITS_PER_WORD;
                                  self.bitmap_2m[w2m].fetch_and(!(1u64 << b2m), Ordering::AcqRel);
                                  self.used_count_2m[block_2m].store(PAGES_PER_2MB as u16, Ordering::Release);
                                  self.free_word_mask_2m[block_2m].store(0, Ordering::Release);
                             }
                        }
                        // Mark pages
                        self.base.mark_allocated_range(block_idx * BLOCKS_2MB_PER_1GB * PAGES_PER_2MB, BLOCKS_2MB_PER_1GB * PAGES_PER_2MB);
                        
                        self.used_count_1g[block_idx].store(BLOCKS_2MB_PER_1GB as u16, Ordering::Release);
                        self.free_count_1g.fetch_sub(1, Ordering::Relaxed);
                        self.free_count_2m.fetch_sub(BLOCKS_2MB_PER_1GB.min(self.total_2m_blocks - block_2m_start), Ordering::Relaxed);

                        return Some(block_idx);
                    }
                    Err(_) => { core::hint::spin_loop(); }
                }
            }
        }
        None
    }
    
    // ========================================================================
    // Hugepage-Preserving 4KB Allocation
    // ========================================================================
    
    /// Allocate 4KB from partial 2MB blocks
    ///
    /// This preserves fully-free 2MB blocks for hugepage allocation by
    /// preferring to allocate from blocks that are already partially used.
    pub fn allocate_4k_from_partial(&self) -> Option<usize> {
        // First try demoted blocks
        if let Some(page) = self.allocate_4k_from_demoted() {
            return Some(page);
        }
        
        // Then try partial blocks
        let hint = self.hint_2m_partial.load(Ordering::Relaxed) % self.bitmap_2m_partial.len().max(1);
        
        for offset in 0..self.bitmap_2m_partial.len() {
            let word_idx = (hint + offset) % self.bitmap_2m_partial.len();
            let word = self.bitmap_2m_partial[word_idx].load(Ordering::Acquire);
            if word == 0 {
                continue;
            }
            
            // Find a partial block
            let bit_idx = word.trailing_zeros() as usize;
            let block_idx = word_idx * BITS_PER_WORD + bit_idx;
            
            if block_idx >= self.total_2m_blocks {
                continue;
            }
            
            // Try to allocate from this block's free words
            if let Some(page) = self.allocate_from_block(block_idx) {
                self.hint_2m_partial.store(word_idx, Ordering::Relaxed);
                return Some(page);
            }
        }
        
        // Finally, demote a fully-free 2MB block
        if let Some(block) = self.demote_2m_block() {
            return self.allocate_from_block(block);
        }
        
        None
    }
}

// ============================================================================
// QEMU smoke tests
// ============================================================================

#[cfg(feature = "qemu-test-export")]
#[path = "qemu_tests.rs"]
pub mod qemu_tests;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

