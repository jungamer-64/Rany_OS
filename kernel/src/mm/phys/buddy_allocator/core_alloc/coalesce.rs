use super::*;

impl BuddyFrameAllocator {

    /// Buddyとの合体を反復的に試みる
    ///
    /// 以前の再帰実装はスタックオーバーフローのリスクがあったため、
    /// ループベースの反復的実装に変更。
    pub(super) fn coalesce(&mut self, block_idx: usize, order: usize) {
        let mut current_block = block_idx;
        let mut current_order = order;

        // 反復的に合体を試みる
        while current_order < MAX_ORDER {
            let buddy = current_block ^ 1;
            if buddy >= self.order_block_counts[current_order] {
                break;
            }

            // Buddyが存在し、かつ同じオーダーで空いているか確認
            if !self.is_block_free(current_order, buddy) {
                break;
            }

            // Buddyと自分のブロックを消去して上位を空きにする
            self.clear_free_block(current_order, current_block);
            self.clear_free_block(current_order, buddy);

            self.coalesce_count += 1;

            // 次のオーダーへ
            current_block >>= 1;
            current_order += 1;

            self.set_free_block(current_order, current_block);
        }
    }

    /// 必要フレーム数から適切なオーダーを計算
    pub(super) fn frames_to_order(frames: usize) -> usize {
        if frames == 0 {
            return 0;
        }
        (usize::BITS - (frames - 1).leading_zeros()) as usize
    }

    /// 4KiB フレームを1つ割り当て
    pub fn allocate_4k_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.allocate_order(0).map(|frame| {
            let addr = PhysAddr::new(frame.to_phys_addr());
            PhysFrame::containing_address(addr)
        })
    }

    /// 2MiB フレームを割り当て（order 9 = 512 * 4KiB = 2MiB）
    pub fn allocate_2m_frame(&mut self) -> Option<PhysFrame<Size2MiB>> {
        let order = Self::frames_to_order(PAGE_SIZE_2M / PAGE_SIZE_4K);
        self.allocate_order(order).map(|frame| {
            let addr = PhysAddr::new(frame.to_phys_addr());
            PhysFrame::containing_address(addr)
        })
    }

    /// 1GiB フレームを割り当て（order 18 = 262144 * 4KiB = 1GiB）
    pub fn allocate_1g_frame(&mut self) -> Option<PhysFrame<Size1GiB>> {
        let order = Self::frames_to_order(PAGE_SIZE_1G / PAGE_SIZE_4K);
        self.allocate_order(order).map(|frame| {
            let addr = PhysAddr::new(frame.to_phys_addr());
            PhysFrame::containing_address(addr)
        })
    }

    /// 4KiB フレームを解放
    pub fn deallocate_4k_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        let frame_idx = FrameIndex::from_phys_addr(frame.start_address().as_u64());

        // Phase 6: Check for Folio order
        let order = crate::mm::meta::page_flags::get_order(frame_idx) as usize;

        // Memcg: ページがmemcgでトラックされている場合はアンチャージ
        crate::mm::meta::memcg::memcg_untrack_and_uncharge(frame_idx, 1);

        self.deallocate_order(frame_idx, order);
    }

    /// 2MiB フレームを解放
    ///
    /// 大きなブロックは即時結合を使用（スラッシングのリスクが低い）
    pub fn deallocate_2m_frame(&mut self, frame: PhysFrame<Size2MiB>) {
        let start_frame = FrameIndex::from_phys_addr(frame.start_address().as_u64());
        let frames_count = PAGE_SIZE_2M / PAGE_SIZE_4K;

        // Memcg: 各4KiBページについてアンチャージ/アンストラックする
        for i in 0..frames_count {
            let idx = FrameIndex::new(start_frame.as_usize() + i);
            crate::mm::meta::memcg::memcg_untrack_and_uncharge(idx, 1);
        }

        let order = Self::frames_to_order(PAGE_SIZE_2M / PAGE_SIZE_4K);
        self.deallocate_order_immediate(start_frame, order);
    }

    /// 1GiB フレームを解放
    ///
    /// 大きなブロックは即時結合を使用（スラッシングのリスクが低い）
    pub fn deallocate_1g_frame(&mut self, frame: PhysFrame<Size1GiB>) {
        let start_frame = FrameIndex::from_phys_addr(frame.start_address().as_u64());
        let frames_count = PAGE_SIZE_1G / PAGE_SIZE_4K;

        // Memcg: 各4KiBページについてアンチャージ/アンストラックする
        for i in 0..frames_count {
            let idx = FrameIndex::new(start_frame.as_usize() + i);
            crate::mm::meta::memcg::memcg_untrack_and_uncharge(idx, 1);
        }

        let order = Self::frames_to_order(PAGE_SIZE_1G / PAGE_SIZE_4K);
        self.deallocate_order_immediate(start_frame, order);
    }

    /// 連続する物理フレームを割り当て（2のべき乗に切り上げ）
    pub fn allocate_contiguous(&mut self, frame_count: usize) -> Option<PhysAddr> {
        let order = Self::frames_to_order(frame_count);
        if order > MAX_ORDER {
            return None;
        }
        self.allocate_order(order)
            .map(|frame| PhysAddr::new(frame.to_phys_addr()))
    }

    /// Register a NUMA region for a node and add it to the allocator
    pub fn register_numa_region(&mut self, node: NumaNodeId, start: FrameIndex, end: FrameIndex) {
        self.init_layout();

        if self.numa_regions.is_none() {
            self.numa_regions = Some(BTreeMap::new());
        }
        let map = self.numa_regions.as_mut().unwrap();
        map.entry(node)
            .or_insert_with(|| alloc::vec![])
            .push((start, end));

        // Add the region to the global free bitsets
        self.add_region(start, end);

        // Update total_frames to cover the new region
        self.total_frames = self.total_frames.max(end.as_usize().min(MAX_4K_FRAMES));
        self.update_order_limits();
    }

    /// Allocate an order block restricted to [start_frame, end_frame)
    pub(super) fn allocate_order_in_range(
        &mut self,
        order: usize,
        start_frame: usize,
        end_frame: usize,
    ) -> Option<FrameIndex> {
        if order > MAX_ORDER {
            return None;
        }
        for current_order in order..=MAX_ORDER {
            let block_size = 1 << current_order;
            let start_block = (start_frame + block_size - 1) / block_size;
            let end_block = end_frame / block_size;

            if let Some(block_idx) =
                self.find_free_block_in_range(current_order, start_block, end_block)
            {
                self.clear_free_block(current_order, block_idx);
                let frame = FrameIndex::new(block_idx << current_order);

                self.split_block(frame, current_order, order);

                let target_size = 1u64 << order;
                debug_assert!(self.free_frames >= target_size);
                self.free_frames = self.free_frames.saturating_sub(target_size);

                return Some(frame);
            }
        }
        None
    }

    /// NUMA-aware allocation helper: try preferred node, then other nodes.
    /// Returns a raw FrameIndex if successful.
    pub(super) fn allocate_on_numa_node(&mut self, node: NumaNodeId, order: usize) -> Option<FrameIndex> {
        let map_clone = self.numa_regions.clone();
        let map = map_clone.as_ref()?;

        // Preferred node first
        if let Some(ranges) = map.get(&node) {
            for &(start, end) in ranges.iter() {
                if let Some(frame) = self.allocate_order_in_range(order, start.as_usize(), end.as_usize()) {
                    return Some(frame);
                }
            }
        }

        // Fallback to other nodes
        for (&other, ranges) in map.iter() {
            if other == node { continue; }
            for &(start, end) in ranges.iter() {
                if let Some(frame) = self.allocate_order_in_range(order, start.as_usize(), end.as_usize()) {
                    return Some(frame);
                }
            }
        }

        None
    }

    /// Try to allocate a 4KiB frame on a preferred NUMA node; fallback to others and global
    pub fn allocate_4k_frame_on_node(&mut self, node: NumaNodeId) -> Option<PhysFrame<Size4KiB>> {
        if let Some(frame) = self.allocate_on_numa_node(node, 0) {
            let addr = PhysAddr::new(frame.to_phys_addr());
            return Some(PhysFrame::containing_address(addr));
        }
        self.allocate_4k_frame()
    }

    /// 2MiB allocation on a preferred NUMA node
    pub fn allocate_2m_frame_on_node(&mut self, node: NumaNodeId) -> Option<PhysFrame<Size2MiB>> {
        let order = Self::frames_to_order(PAGE_SIZE_2M / PAGE_SIZE_4K);
        if let Some(frame) = self.allocate_on_numa_node(node, order) {
            let addr = PhysAddr::new(frame.to_phys_addr());
            return Some(PhysFrame::containing_address(addr));
        }
        self.allocate_2m_frame()
    }

    /// 1GiB allocation on a preferred NUMA node
    pub fn allocate_1g_frame_on_node(&mut self, node: NumaNodeId) -> Option<PhysFrame<Size1GiB>> {
        let order = Self::frames_to_order(PAGE_SIZE_1G / PAGE_SIZE_4K);
        if let Some(frame) = self.allocate_on_numa_node(node, order) {
            let addr = PhysAddr::new(frame.to_phys_addr());
            return Some(PhysFrame::containing_address(addr));
        }
        self.allocate_1g_frame()
    }

    /// 空きフレーム数を取得
    pub fn free_frame_count(&self) -> u64 {
        self.free_frames
    }

    /// 総フレーム数を取得
    pub fn total_frame_count(&self) -> usize {
        self.total_frames
    }

    /// 統計情報を取得
    pub fn stats(&self) -> BuddyAllocatorStats {
        let mut order_stats = [(0usize, 0usize); MAX_ORDER + 1];

        for order in 0..=MAX_ORDER {
            let block_frames = 1 << order;
            let free_blocks = self.order_free_counts[order];
            let total_frames = free_blocks * block_frames;
            order_stats[order] = (free_blocks, total_frames);
        }

        BuddyAllocatorStats {
            total_frames: self.total_frames,
            free_frames: self.free_frames,
            split_count: self.split_count,
            coalesce_count: self.coalesce_count,
            order_stats,
        }
    }

    // ========================================================================
    // ゼロクリア済みページ管理
    // ========================================================================

    /// ゼロクリア済みブロックかどうかをチェック
    #[inline]
    pub(super) fn is_block_zeroed(&self, order: usize, block_idx: usize) -> bool {
        if order > MAX_ORDER {
            return false;
        }
        let detail_start = self.order_detail_word_start[order];
        let word_idx = detail_start + (block_idx / 64);
        let bit_idx = block_idx % 64;
        if word_idx < TOTAL_DETAIL_WORDS {
            (self.zeroed_bits[word_idx] >> bit_idx) & 1 != 0
        } else {
            false
        }
    }

    /// ブロックをゼロクリア済みとしてマーク
    #[inline]
    pub(super) fn set_block_zeroed(&mut self, order: usize, block_idx: usize) {
        if order > MAX_ORDER {
            return;
        }
        let detail_start = self.order_detail_word_start[order];
        let word_idx = detail_start + (block_idx / 64);
        let bit_idx = block_idx % 64;
        if word_idx < TOTAL_DETAIL_WORDS {
            let old = self.zeroed_bits[word_idx];
            if old & (1u64 << bit_idx) == 0 {
                self.zeroed_bits[word_idx] = old | (1u64 << bit_idx);
                self.zeroed_counts[order] += 1;
            }
        }
    }

    /// ブロックのゼロクリア済みフラグをクリア
    #[inline]
    pub(super) fn clear_block_zeroed(&mut self, order: usize, block_idx: usize) {
        if order > MAX_ORDER {
            return;
        }
        let detail_start = self.order_detail_word_start[order];
        let word_idx = detail_start + (block_idx / 64);
        let bit_idx = block_idx % 64;
        if word_idx < TOTAL_DETAIL_WORDS {
            let old = self.zeroed_bits[word_idx];
            if old & (1u64 << bit_idx) != 0 {
                self.zeroed_bits[word_idx] = old & !(1u64 << bit_idx);
                self.zeroed_counts[order] = self.zeroed_counts[order].saturating_sub(1);
            }
        }
    }

    /// ゼロクリア済みの空きブロックを探索
    pub(super) fn find_zeroed_free_block(&self, order: usize) -> Option<usize> {
        if self.zeroed_counts[order] == 0 {
            return None;
        }

        let detail_start = self.order_detail_word_start[order];
        let detail_len = self.order_detail_word_len[order];
        let max_blocks = self.order_block_counts[order];

        for word_offset in 0..detail_len {
            let word_idx = detail_start + word_offset;
            // 空きかつゼロクリア済みのブロックを探す
            let combined = self.free_bits[word_idx] & self.zeroed_bits[word_idx];
            if combined != 0 {
                let bit = combined.trailing_zeros() as usize;
                let block_idx = word_offset * 64 + bit;
                if block_idx < max_blocks {
                    return Some(block_idx);
                }
            }
        }

        None
    }

    /// ゼロクリア済みページを優先して割り当て
    ///
    /// ゼロクリア済みブロックがあればそれを使用し、なければ通常割り当て後に
    /// 呼び出し元でゼロクリアする必要がある。
    ///
    /// # Returns
    /// - `Some((frame, true))`: ゼロクリア済みブロックを割り当て
    /// - `Some((frame, false))`: 通常ブロックを割り当て（要ゼロクリア）
    /// - `None`: 割り当て失敗
    pub fn allocate_order_prefer_zeroed(&mut self, order: usize) -> Option<(FrameIndex, bool)> {
        if order > MAX_ORDER {
            return None;
        }

        // まずゼロクリア済みブロックを探す
        if let Some(block_idx) = self.find_zeroed_free_block(order) {
            self.clear_free_block(order, block_idx);
            self.clear_block_zeroed(order, block_idx);
            let frame = FrameIndex::new(block_idx << order);
            let block_size = 1u64 << order;
            self.free_frames = self.free_frames.saturating_sub(block_size);
            self.zeroed_allocs += 1;
            return Some((frame, true));
        }

        // ゼロクリア済みがなければ通常割り当て
        self.allocate_order(order).map(|frame| (frame, false))
    }

    /// 4KiBフレームをゼロクリア済みとして割り当て
    pub fn allocate_4k_zeroed(&mut self) -> Option<(PhysFrame<Size4KiB>, bool)> {
        self.allocate_order_prefer_zeroed(0).map(|(frame, zeroed)| {
            let phys_addr = PhysAddr::new(frame.to_phys_addr());
            (unsafe { PhysFrame::from_start_address_unchecked(phys_addr) }, zeroed)
        })
    }

    /// バックグラウンドスクラブ: 1つの空きページをゼロクリア
    ///
    /// アイドルタスクから呼び出し、非ゼロの空きページを見つけてゼロクリアする。
    /// 実際のゼロクリア（memset）は呼び出し元で行い、完了後に `mark_scrubbed` を呼ぶ。
    ///
    /// # Returns
    /// ゼロクリア対象のフレームアドレス。ゼロクリア不要な場合はNone。
    pub fn find_dirty_free_page(&self, order: usize) -> Option<FrameIndex> {
        if order > MAX_ORDER || self.order_free_counts[order] == 0 {
            return None;
        }

        let detail_start = self.order_detail_word_start[order];
        let detail_len = self.order_detail_word_len[order];
        let max_blocks = self.order_block_counts[order];

        for word_offset in 0..detail_len {
            let word_idx = detail_start + word_offset;
            // 空きだがゼロクリア済みでないブロックを探す
            let free_word = self.free_bits[word_idx];
            let zeroed_word = self.zeroed_bits[word_idx];
            let dirty = free_word & !zeroed_word;
            if dirty != 0 {
                let bit = dirty.trailing_zeros() as usize;
                let block_idx = word_offset * 64 + bit;
                if block_idx < max_blocks {
                    return Some(FrameIndex::new(block_idx << order));
                }
            }
        }

        None
    }

    /// スクラブ完了をマーク
    ///
    /// `find_dirty_free_page` で見つけたページをゼロクリアした後に呼び出す。
    pub fn mark_scrubbed(&mut self, frame: FrameIndex, order: usize) {
        let block_idx = frame.as_usize() >> order;
        // まだ空きブロックであることを確認
        if self.is_block_free(order, block_idx) {
            self.set_block_zeroed(order, block_idx);
            self.scrub_count += 1;
        }
    }

    /// ゼロクリア統計を取得
    pub fn zeroed_stats(&self) -> (u64, u64, [usize; MAX_ORDER + 1]) {
        (self.zeroed_allocs, self.scrub_count, self.zeroed_counts)
    }

    // ========================================================================
    // Fragmentation Index (Phase 2.1)
    // ========================================================================

    /// 詳細なフラグメンテーション指標を計算
    ///
    /// 外部/内部フラグメンテーションを分離して計算し、
    /// 適切な対処法（コンパクション vs 結合）を推奨する。
    ///
    /// # Arguments
    /// * `target_order` - 特定オーダーの使用不能率を計算する場合に指定
    ///
    /// # Returns
    /// FragmentationIndex 構造体
    pub fn fragmentation_index(&self, target_order: Option<usize>) -> FragmentationIndex {
        FragmentationIndex::calculate(
            &self.order_free_counts,
            self.total_frames,
            target_order,
        )
    }

    /// 各オーダーの空きブロック数を取得
    pub fn order_free_counts(&self) -> [usize; MAX_ORDER + 1] {
        self.order_free_counts
    }
}
