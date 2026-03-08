use super::*;

impl HugePageBitmap {
    /// Allocate 4KB from demoted blocks
    pub(super) fn allocate_4k_from_demoted(&self) -> Option<usize> {
        for word_idx in 0..self.demoted_2m.len() {
            let word = self.demoted_2m[word_idx].load(Ordering::Acquire);
            if word == 0 {
                continue;
            }

            for bit in 0..BITS_PER_WORD {
                if (word & (1u64 << bit)) == 0 {
                    continue;
                }

                let block_idx = word_idx * BITS_PER_WORD + bit;
                if block_idx >= self.total_2m_blocks {
                    break;
                }

                if let Some(page) = self.allocate_from_block(block_idx) {
                    return Some(page);
                }
            }
        }

        None
    }

    /// Allocate a 4KB page from a specific 2MB block
    pub(super) fn allocate_from_block(&self, block_idx: usize) -> Option<usize> {
        let mask = self.free_word_mask_2m[block_idx].load(Ordering::Acquire);
        if mask == 0 {
            return None;
        }

        let word_in_block = mask.trailing_zeros() as usize;
        let detail_word_idx = block_idx * WORDS_PER_2MB + word_in_block;

        if let Some(page_idx) = self.base.try_allocate_from_word(detail_word_idx) {
            self.on_page_allocated(page_idx);
            return Some(page_idx);
        }

        None
    }

    /// Demote a fully-free 2MB block for 4KB allocation
    pub(super) fn demote_2m_block(&self) -> Option<usize> {
        // Find a fully-free, non-demoted block
        for word_idx in 0..self.bitmap_2m.len() {
            // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
            loop {
                let word = self.bitmap_2m[word_idx].load(Ordering::Acquire);
                if word == 0 {
                    break;
                }

                let bit_idx = word.trailing_zeros() as usize;
                let bit_mask = 1u64 << bit_idx;
                let block_idx = word_idx * BITS_PER_WORD + bit_idx;

                // Check if already demoted
                let demoted_word = self.demoted_2m[word_idx].load(Ordering::Acquire);
                if (demoted_word & bit_mask) != 0 {
                    // Already demoted — clear stale bit from bitmap_2m to prevent
                    // infinite loop (trailing_zeros would find the same bit forever).
                    let _ = self.bitmap_2m[word_idx].compare_exchange_weak(
                        word,
                        word & !bit_mask,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );
                    continue;
                }

                // Try to clear fully-free bit and set demoted bit atomically
                match self.bitmap_2m[word_idx].compare_exchange_weak(
                    word,
                    word & !bit_mask,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        // Set demoted bit
                        self.demoted_2m[word_idx].fetch_or(bit_mask, Ordering::AcqRel);

                        // Mark as partial
                        self.bitmap_2m_partial[word_idx].fetch_or(bit_mask, Ordering::AcqRel);

                        self.free_count_2m.fetch_sub(1, Ordering::Relaxed);
                        self.partial_count_2m.fetch_add(1, Ordering::Relaxed);
                        self.demoted_count_2m.fetch_add(1, Ordering::Relaxed);

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

    // ========================================================================
    // Hierarchy Maintenance Callbacks
    // ========================================================================

    /// Called when a 4KB page is allocated
    ///
    /// Updates 2MB and 1GB tracking accordingly.
    pub(crate) fn on_page_allocated(&self, page_idx: usize) {
        let block_2m = page_idx / PAGES_PER_2MB;
        if block_2m >= self.total_2m_blocks {
            return;
        }

        // Update used count
        let old_used = self.used_count_2m[block_2m].fetch_add(1, Ordering::AcqRel);

        // Update word mask
        let word_in_block = (page_idx % PAGES_PER_2MB) / BITS_PER_WORD;
        let detail_word_idx = block_2m * WORDS_PER_2MB + word_in_block;
        if self.base.detail()[detail_word_idx].load(Ordering::Acquire) == 0 {
            let mask_bit = 1u8 << word_in_block;
            self.free_word_mask_2m[block_2m].fetch_and(!mask_bit, Ordering::AcqRel);
        }

        if old_used == 0 {
            // Block was fully free, now it's not
            let word_idx = block_2m / BITS_PER_WORD;
            let bit_idx = block_2m % BITS_PER_WORD;
            let bit_mask = 1u64 << bit_idx;

            // Clear fully-free bit
            self.bitmap_2m[word_idx].fetch_and(!bit_mask, Ordering::AcqRel);

            // Set partial bit
            self.bitmap_2m_partial[word_idx].fetch_or(bit_mask, Ordering::AcqRel);

            self.free_count_2m.fetch_sub(1, Ordering::Relaxed);
            self.partial_count_2m.fetch_add(1, Ordering::Relaxed);

            // Update 1GB
            let block_1g = block_2m / BLOCKS_2MB_PER_1GB;
            if block_1g < self.used_count_1g.len() {
                let old_1g = self.used_count_1g[block_1g].fetch_add(1, Ordering::AcqRel);
                if old_1g == 0 {
                    let w1g = block_1g / BITS_PER_WORD;
                    let b1g = block_1g % BITS_PER_WORD;
                    self.bitmap_1g[w1g].fetch_and(!(1u64 << b1g), Ordering::AcqRel);
                    self.free_count_1g.fetch_sub(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Called when a 4KB page is freed
    ///
    /// Updates 2MB and 1GB tracking accordingly.
    pub(crate) fn on_page_freed(&self, page_idx: usize) {
        let block_2m = page_idx / PAGES_PER_2MB;
        if block_2m >= self.total_2m_blocks {
            return;
        }

        // Update word mask
        let word_in_block = (page_idx % PAGES_PER_2MB) / BITS_PER_WORD;
        let mask_bit = 1u8 << word_in_block;
        self.free_word_mask_2m[block_2m].fetch_or(mask_bit, Ordering::AcqRel);

        // Update used count
        let old_used = self.used_count_2m[block_2m].fetch_sub(1, Ordering::AcqRel);

        if old_used == 1 {
            // Block is now potentially fully free
            let word_idx = block_2m / BITS_PER_WORD;
            let bit_idx = block_2m % BITS_PER_WORD;
            let bit_mask = 1u64 << bit_idx;

            // 脆弱性修正: used_count_2m が 0 であることを確認しながらビットを立てる。
            // これにより、fetch_sub(1) の直後に別の CPU が 4KB 確保を行った場合に
            // 誤って bitmap_2m のビットを立ててしまう（二重割当の原因）のを防ぐ。
            if self.used_count_2m[block_2m].load(Ordering::Acquire) == 0 {
                // Clear partial bit
                self.bitmap_2m_partial[word_idx].fetch_and(!bit_mask, Ordering::AcqRel);
                self.partial_count_2m.fetch_sub(1, Ordering::Relaxed);

                // Check if demoted
                let demoted = self.demoted_2m[word_idx].load(Ordering::Acquire);
                if (demoted & bit_mask) != 0 {
                    // Clear demoted bit and set fully-free
                    self.demoted_2m[word_idx].fetch_and(!bit_mask, Ordering::AcqRel);
                    self.demoted_count_2m.fetch_sub(1, Ordering::Relaxed);
                }

                // Set fully-free bit
                self.bitmap_2m[word_idx].fetch_or(bit_mask, Ordering::AcqRel);
                self.free_count_2m.fetch_add(1, Ordering::Relaxed);

                // Update 1GB
                let block_1g = block_2m / BLOCKS_2MB_PER_1GB;
                if block_1g < self.used_count_1g.len() {
                    let old_1g = self.used_count_1g[block_1g].fetch_sub(1, Ordering::AcqRel);
                    if old_1g == 1 {
                        let w1g = block_1g / BITS_PER_WORD;
                        let b1g = block_1g % BITS_PER_WORD;
                        self.bitmap_1g[w1g].fetch_or(1u64 << b1g, Ordering::AcqRel);
                        self.free_count_1g.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    // ========================================================================
    // Accessors for IovaBitmap Integration (Phase 3.2)
    // ========================================================================

    // Accessors for IovaBitmap Integration (Phase 3.2)
    // ========================================================================

    /// Access the base 4KB hierarchical bitmap (immutable)
    #[inline]
    pub(crate) fn base_bitmap(&self) -> &HierarchicalBitmap {
        &self.base
    }

    /// Access the base 4KB hierarchical bitmap (mutable)
    #[inline]
    pub fn base_mut(&mut self) -> &mut HierarchicalBitmap {
        &mut self.base
    }

    /// Access detail bitmap directly
    #[inline]
    pub fn detail(&self) -> &[AtomicU64] {
        self.base.detail()
    }

    /// Access summary bitmap directly
    #[inline]
    pub fn summary(&self) -> &[AtomicU64] {
        self.base.summary()
    }

    /// Access L2 summary bitmap directly
    #[inline]
    pub fn summary_l2(&self) -> &[AtomicU64] {
        self.base.summary_l2()
    }

    /// Get valid mask for a detail word
    #[inline]
    pub fn valid_mask(&self, word_idx: usize) -> u64 {
        self.base.valid_mask(word_idx)
    }

    /// Access used_count_2m directly
    #[inline]
    pub fn used_count_2m(&self) -> &[AtomicU16] {
        &self.used_count_2m
    }

    /// Access bitmap_2m directly
    #[inline]
    pub fn bitmap_2m(&self) -> &[AtomicU64] {
        &self.bitmap_2m
    }

    /// Access bitmap_2m_partial directly
    #[inline]
    pub fn bitmap_2m_partial(&self) -> &[AtomicU64] {
        &self.bitmap_2m_partial
    }

    /// Access demoted_2m directly
    #[inline]
    pub fn demoted_2m(&self) -> &[AtomicU64] {
        &self.demoted_2m
    }

    /// Access free_word_mask_2m directly
    #[inline]
    pub fn free_word_mask_2m(&self) -> &[AtomicU8] {
        &self.free_word_mask_2m
    }

    /// Access used_count_1g directly
    #[inline]
    pub fn used_count_1g(&self) -> &[AtomicU16] {
        &self.used_count_1g
    }

    /// Access bitmap_1g directly
    #[inline]
    pub fn bitmap_1g(&self) -> &[AtomicU64] {
        &self.bitmap_1g
    }

    /// Get demoted 2MB block count
    #[inline]
    pub fn demoted_count_2m(&self) -> usize {
        self.demoted_count_2m.load(Ordering::Relaxed)
    }

    /// Get hint for 4KB allocation
    #[inline]
    pub fn hint_4k(&self) -> usize {
        self.base.hint.load(Ordering::Relaxed)
    }

    /// Set hint for 4KB allocation
    #[inline]
    pub fn set_hint_4k(&self, hint: usize) {
        self.base.hint.store(hint, Ordering::Relaxed);
    }

    /// Get hint for 2MB allocation
    #[inline]
    pub fn hint_2m(&self) -> usize {
        self.hint_2m.load(Ordering::Relaxed)
    }

    /// Set hint for 2MB allocation
    #[inline]
    pub fn set_hint_2m(&self, hint: usize) {
        self.hint_2m.store(hint, Ordering::Relaxed);
    }

    /// Get hint for partial 2MB allocation
    #[inline]
    pub fn hint_2m_partial(&self) -> usize {
        self.hint_2m_partial.load(Ordering::Relaxed)
    }

    /// Set hint for partial 2MB allocation
    #[inline]
    pub fn set_hint_2m_partial(&self, hint: usize) {
        self.hint_2m_partial.store(hint, Ordering::Relaxed);
    }

    /// Mark a page as allocated (low-level)
    #[inline]
    pub fn mark_page_allocated(&self, page_idx: usize) -> bool {
        if self.base.mark_allocated(page_idx) {
            self.on_page_allocated(page_idx);
            true
        } else {
            false
        }
    }

    /// Mark a page as free (low-level)
    #[inline]
    pub fn mark_page_free(&self, page_idx: usize) -> bool {
        if self.base.mark_free(page_idx) {
            self.on_page_freed(page_idx);
            true
        } else {
            false
        }
    }

    /// Try to allocate from a specific word (for single-writer arena)
    #[inline]
    pub fn try_allocate_from_word(&self, word_idx: usize) -> Option<usize> {
        if let Some(page_idx) = self.base.try_allocate_from_word(word_idx) {
            self.on_page_allocated(page_idx);
            Some(page_idx)
        } else {
            None
        }
    }

    /// Try to claim an entire word (for single-writer arena batch allocation)
    #[inline]
    pub fn try_claim_word(&self, word_idx: usize) -> u64 {
        let bits = self.base.try_claim_word(word_idx);
        // Note: on_page_allocated must be called for each allocated page
        // This is handled by the caller
        bits
    }

    /// Return bits to a word (for single-writer arena)
    #[inline]
    pub fn return_word(&self, word_idx: usize, bits: u64) {
        self.base.return_word(word_idx, bits);
        // Note: on_page_freed must be called for each freed page
        // This is handled by the caller
    }

    // ========================================================================
    // Coalesced Free Optimization (N frees → 1 atomic)
    // ========================================================================

    /// Free multiple pages in the same word with a single atomic operation
    ///
    /// Instead of N separate `mark_free()` calls (N atomics), this combines
    /// them into a single `fetch_or` operation.
    ///
    /// # Arguments
    /// * `word_idx` - Word index in detail bitmap
    /// * `coalesced_mask` - Bitmask of pages to free (1 = free that page)
    ///
    /// # Returns
    /// * `Ok(freed_count)` - Number of pages actually freed
    /// * `Err(())` - Invalid word index
    ///
    /// # Performance
    /// - Single atomic `fetch_or` instead of N `compare_exchange_weak` loops
    /// - Particularly effective for batch free in RemoteFreeRing drain
    ///
    /// # Example
    /// ```ignore
    /// // Free pages 0, 1, 5, 6, 7 in word 10 (5 pages, 1 atomic)
    /// let mask = 0b11100011; // bits 0,1,5,6,7
    /// bitmap.free_pages_coalesced(10, mask)?;
    /// ```
    pub fn free_pages_coalesced(&self, word_idx: usize, coalesced_mask: u64) -> Result<usize, ()> {
        if word_idx >= self.base.detail().len() {
            return Err(());
        }

        let valid_mask = self.base.valid_mask(word_idx);
        let bits_to_free = coalesced_mask & valid_mask;

        if bits_to_free == 0 {
            return Ok(0);
        }

        // Single atomic operation to free all pages in the mask
        let old = self.base.detail()[word_idx].fetch_or(bits_to_free, Ordering::AcqRel);

        // Count how many pages were actually freed (were 0 before, now 1)
        let actually_freed = bits_to_free & !old;
        let freed_count = actually_freed.count_ones() as usize;

        if freed_count == 0 {
            return Ok(0);
        }

        // Update free count
        self.base
            .free_count
            .fetch_add(freed_count, Ordering::Relaxed);

        // Update summary if word was empty
        if old == 0 {
            self.base.set_summary_bit(word_idx);
        }

        // Update 2MB hierarchy for affected pages
        self.update_2m_hierarchy_on_free(word_idx, freed_count);

        Ok(freed_count)
    }

    /// Update 2MB/1GB hierarchy after freeing pages in a word
    pub(super) fn update_2m_hierarchy_on_free(&self, word_idx: usize, freed_count: usize) {
        let start_page = word_idx * BITS_PER_WORD;
        let block_2m = start_page / PAGES_PER_2MB;

        if block_2m >= self.total_2m_blocks {
            return;
        }

        let word_in_block = (start_page % PAGES_PER_2MB) / BITS_PER_WORD;
        let mask_bit = 1u8 << word_in_block;
        self.free_word_mask_2m[block_2m].fetch_or(mask_bit, Ordering::AcqRel);

        let old_used = self.used_count_2m[block_2m].fetch_sub(freed_count as u16, Ordering::AcqRel);
        let new_used = old_used.saturating_sub(freed_count as u16);

        if new_used == 0 && old_used > 0 {
            let bword = block_2m / BITS_PER_WORD;
            let bbit = block_2m % BITS_PER_WORD;
            let bmask = 1u64 << bbit;

            // 脆弱性修正: アトミックに 0 であることを再確認
            if self.used_count_2m[block_2m].load(Ordering::Acquire) == 0 {
                self.bitmap_2m_partial[bword].fetch_and(!bmask, Ordering::AcqRel);
                self.partial_count_2m.fetch_sub(1, Ordering::Relaxed);

                let demoted = self.demoted_2m[bword].load(Ordering::Acquire);
                if (demoted & bmask) != 0 {
                    self.demoted_2m[bword].fetch_and(!bmask, Ordering::AcqRel);
                    self.demoted_count_2m.fetch_sub(1, Ordering::Relaxed);
                }

                self.bitmap_2m[bword].fetch_or(bmask, Ordering::AcqRel);
                self.free_count_2m.fetch_add(1, Ordering::Relaxed);

                let block_1g = block_2m / BLOCKS_2MB_PER_1GB;
                if block_1g < self.used_count_1g.len() {
                    let old_1g = self.used_count_1g[block_1g].fetch_sub(1, Ordering::AcqRel);
                    if old_1g == 1 {
                        let w1g = block_1g / BITS_PER_WORD;
                        let b1g = block_1g % BITS_PER_WORD;
                        self.bitmap_1g[w1g].fetch_or(1u64 << b1g, Ordering::AcqRel);
                        self.free_count_1g.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    // ========================================================================
    // O(1) Word Selection in Partial Blocks
    // ========================================================================

    /// Find a non-empty word in partial 2MB blocks using free_word_mask
    ///
    /// Uses the `free_word_mask_2m` optimization for O(1) word selection
    /// within partial blocks, instead of scanning all 8 words per block.
    ///
    /// # Arguments
    /// * `hint` - Starting block index (modulo total blocks)
    ///
    /// # Returns
    /// * `Some(word_idx)` - Global detail word index with free pages
    /// * `None` - No partial blocks have free pages
    ///
    /// # Performance
    /// - O(1) word selection within each block (via tzcnt on 8-bit mask)
    /// - Scans partial block bitmap at word granularity
    pub fn find_non_empty_word_in_partial(&self, hint: usize) -> Option<usize> {
        let hint_block = hint % self.total_2m_blocks.max(1);

        for offset in 0..self.bitmap_2m_partial.len() {
            let word_idx = (hint_block / BITS_PER_WORD + offset) % self.bitmap_2m_partial.len();
            let partial_word = self.bitmap_2m_partial[word_idx].load(Ordering::Acquire);

            if partial_word == 0 {
                continue;
            }

            // Iterate through partial blocks in this word
            let mut remaining = partial_word;
            // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
            while remaining != 0 {
                let bit_idx = remaining.trailing_zeros() as usize;
                remaining &= remaining - 1; // Clear lowest bit

                let block_idx = word_idx * BITS_PER_WORD + bit_idx;
                if block_idx >= self.total_2m_blocks {
                    continue;
                }

                // Use free_word_mask for O(1) word selection within block
                let free_mask = self.free_word_mask_2m[block_idx].load(Ordering::Acquire);
                if free_mask == 0 {
                    continue;
                }

                let word_in_block = free_mask.trailing_zeros() as usize;
                let global_word_idx = block_idx * WORDS_PER_2MB + word_in_block;

                return Some(global_word_idx);
            }
        }

        None
    }

    /// Try to claim a word from partial blocks for SubMagazine
    ///
    /// Combines `find_non_empty_word_in_partial` with `try_claim_word` for
    /// efficient SubMagazine refill.
    ///
    /// # Returns
    /// * `Some((word_idx, bits, base_addr))` - Claimed word info for SubMagazine
    /// * `None` - No claimable words in partial blocks
    pub fn try_claim_word_from_partial(
        &self,
        hint: usize,
        base_addr: u64,
    ) -> Option<(usize, u64, u64)> {
        let word_idx = self.find_non_empty_word_in_partial(hint)?;
        let bits = self.try_claim_word(word_idx);

        if bits == 0 {
            return None;
        }

        // Calculate physical address for this word
        let page_base = word_idx * BITS_PER_WORD;
        let word_base_addr = base_addr + (page_base as u64) * 4096;

        Some((word_idx, bits, word_base_addr))
    }
}
