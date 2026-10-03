use super::*;

pub(crate) const PAGES_PER_PAGEBLOCK: usize = PAGE_SIZE_2M / PAGE_SIZE_4K;
static NEXT_POOL: AtomicU64 = AtomicU64::new(1);

impl FreeListBuddyAllocator {
    /// Admission consumes a PMM loan. Metadata failure returns that same owner;
    /// no bitmap, descriptor, or free list can independently admit boot RAM.
    pub fn from_allocation(backing: PhysicalAllocation) -> Result<Self, LoanAdmissionError> {
        let base_frame = FrameIndex::from_phys_addr(backing.as_u64()).as_usize();
        let total_frames = backing.page_count();
        let mut descriptors = Vec::new();
        if descriptors.try_reserve_exact(total_frames).is_err() {
            return Err(LoanAdmissionError {
                cause: FrameAllocError::MetadataAllocation,
                allocation: backing,
            });
        }
        descriptors.resize_with(total_frames, PageDescriptor::new);
        let blocks = (base_frame + total_frames).div_ceil(PAGES_PER_PAGEBLOCK)
            - base_frame / PAGES_PER_PAGEBLOCK;
        let mut flags = Vec::new();
        if flags.try_reserve_exact(blocks).is_err() {
            return Err(LoanAdmissionError {
                cause: FrameAllocError::MetadataAllocation,
                allocation: backing,
            });
        }
        flags.resize(blocks, MigrateType::Movable);
        let mut pool = Self {
            free_areas: core::array::from_fn(|_| core::array::from_fn(|_| FreeArea::new())),
            page_descriptors: descriptors,
            backing,
            base_frame,
            identity: NEXT_POOL.fetch_add(1, Ordering::Relaxed),
            total_frames,
            free_frames: AtomicU64::new(0),
            split_count: AtomicU64::new(0),
            coalesce_count: AtomicU64::new(0),
            migrate_allocs: [const { AtomicU64::new(0) }; MigrateType::COUNT],
            fallback_count: AtomicU64::new(0),
            color_free_counts: [const { AtomicUsize::new(0) }; NUM_CACHE_COLORS],
            pageblock_flags: flags,
        };
        pool.add_free_region(base_frame, base_frame + total_frames);
        Ok(pool)
    }

    pub fn allocate(
        &mut self,
        order: usize,
        migrate_type: MigrateType,
    ) -> Result<MobilityAllocation, FrameAllocError> {
        if order > MAX_ORDER {
            return Err(FrameAllocError::InvalidRange);
        }
        let frame = self
            .allocate_index(order, migrate_type)
            .ok_or(FrameAllocError::Exhausted)?;
        Ok(MobilityAllocation {
            frame,
            order,
            pool: self.identity,
        })
    }

    pub fn allocate_with_color(
        &mut self,
        order: usize,
        migrate_type: MigrateType,
        color: u8,
    ) -> Result<MobilityAllocation, FrameAllocError> {
        if order > MAX_ORDER {
            return Err(FrameAllocError::InvalidRange);
        }
        if color as usize >= NUM_CACHE_COLORS {
            return Err(FrameAllocError::InvalidRange);
        }
        let frame = self
            .allocate_color_index(order, migrate_type, color)
            .ok_or(FrameAllocError::Exhausted)?;
        Ok(MobilityAllocation {
            frame,
            order,
            pool: self.identity,
        })
    }

    /// Consumes only this pool's child. A mistaken destination rejects the
    /// request without losing the unaccepted allocation owner.
    pub fn deallocate(&mut self, allocation: MobilityAllocation) -> Result<(), MobilityAllocation> {
        if allocation.pool != self.identity {
            return Err(allocation);
        }
        self.release_index(allocation.frame, allocation.order);
        Ok(())
    }

    /// Return of an empty pool transfers its original PMM authority intact.
    /// Outstanding children reject reclamation and return the unchanged pool.
    pub fn into_allocation(self) -> Result<PhysicalAllocation, Self> {
        if self.free_count() != self.total_frames as u64 {
            return Err(self);
        }
        Ok(self.backing)
    }

    pub(crate) fn frames_to_order(frames: usize) -> Option<usize> {
        if frames == 0 {
            return None;
        }
        Some((usize::BITS - (frames - 1).leading_zeros()) as usize)
    }
    /// ページ記述子を取得
    #[inline]
    pub(super) fn get_page(&self, frame_idx: usize) -> Option<&PageDescriptor> {
        self.page_descriptors
            .get(frame_idx.checked_sub(self.base_frame)?)
    }

    /// ページ記述子を取得（可変）
    #[inline]
    pub(super) fn get_page_mut(&mut self, frame_idx: usize) -> Option<&mut PageDescriptor> {
        self.page_descriptors
            .get_mut(frame_idx.checked_sub(self.base_frame)?)
    }

    /// 2MBページブロックのモビリティタイプを取得
    #[inline]
    pub fn get_pageblock_migratetype(&self, frame_idx: usize) -> MigrateType {
        let block_idx =
            (frame_idx / PAGES_PER_PAGEBLOCK).checked_sub(self.base_frame / PAGES_PER_PAGEBLOCK);
        block_idx
            .and_then(|index| self.pageblock_flags.get(index).copied())
            .unwrap_or(MigrateType::Movable)
    }

    /// 2MBページブロックのモビリティタイプを設定
    #[inline]
    fn set_pageblock_migratetype(&mut self, frame_idx: usize, mt: MigrateType) {
        let block_idx =
            (frame_idx / PAGES_PER_PAGEBLOCK).checked_sub(self.base_frame / PAGES_PER_PAGEBLOCK);
        if let Some(flag) = block_idx.and_then(|index| self.pageblock_flags.get_mut(index)) {
            *flag = mt;
        }
    }

    /// 指定範囲に含まれる全pageblockのモビリティタイプを設定
    ///
    /// `order >= 9`（2MB以上）の割り当て/解放では、複数のpageblockを跨ぐため、
    /// 範囲内の全pageblockを更新する必要がある。
    ///
    /// # Arguments
    /// * `start_frame` - 開始フレームインデックス
    /// * `order` - ブロックオーダー
    /// * `mt` - 設定するモビリティタイプ
    pub(super) fn set_pageblocks_mt_for_range(
        &mut self,
        start_frame: usize,
        order: usize,
        mt: MigrateType,
    ) {
        let pages = 1usize << order;
        // 開始pageblockの先頭にアライン
        let start = start_frame & !(PAGES_PER_PAGEBLOCK - 1);
        // 終了位置を次のpageblock境界にアライン
        let end = (start_frame + pages + PAGES_PER_PAGEBLOCK - 1) & !(PAGES_PER_PAGEBLOCK - 1);

        let mut f = start;
        // LOOP_PROOF: mode=condition; reason=f advances by one pageblock until the finite admitted end boundary.;
        while f < end {
            self.set_pageblock_migratetype(f, mt);
            f += PAGES_PER_PAGEBLOCK;
        }
    }

    // ========================================================================
    // フリーリスト操作
    // ========================================================================

    /// フリーリストの先頭にブロックを追加
    pub(super) fn list_add_head(
        &mut self,
        frame_idx: usize,
        order: usize,
        migrate_type: MigrateType,
    ) {
        let mt = migrate_type as usize;

        // 先にヘッドの値を読み取る
        let old_head = self.free_areas[mt][order].head.load(Ordering::Acquire);

        // ページ記述子を更新
        if let Some(page) = self.get_page_mut(frame_idx) {
            page.order = order as u8;
            page.migrate_type = migrate_type;
            page.flags.insert(PageFlags::FREE);
            page.color = frame_to_color(frame_idx);

            page.next.store(old_head, Ordering::Release);
            page.prev.store(LIST_END, Ordering::Release);
        } else {
            return;
        }

        // リストヘッドを更新
        self.free_areas[mt][order]
            .head
            .store(frame_idx as u64, Ordering::Release);

        if old_head != LIST_END {
            // 旧ヘッドのprevを更新
            if let Some(old_page) = self.get_page_mut(old_head as usize) {
                old_page.prev.store(frame_idx as u64, Ordering::Release);
            }
        } else {
            // リストが空だった場合、tailも更新
            self.free_areas[mt][order]
                .tail
                .store(frame_idx as u64, Ordering::Release);
        }

        self.free_areas[mt][order]
            .nr_free
            .fetch_add(1, Ordering::Relaxed);

        // カラー統計を更新
        let color = frame_to_color(frame_idx);
        self.color_free_counts[color as usize].fetch_add(1 << order, Ordering::Relaxed);
    }

    /// フリーリストからブロックを削除
    pub(super) fn list_del(&mut self, frame_idx: usize, order: usize, migrate_type: MigrateType) {
        // デバッグ: 削除するページがFREEであることを確認
        debug_assert!(
            self.get_page(frame_idx)
                .map(|p| p.is_free())
                .unwrap_or(false),
            "Attempting to delete non-FREE page at frame_idx {}",
            frame_idx
        );

        let (prev_idx, next_idx) = {
            let page = match self.get_page(frame_idx) {
                Some(p) => p,
                None => return,
            };
            (
                page.prev.load(Ordering::Acquire),
                page.next.load(Ordering::Acquire),
            )
        };

        let mt = migrate_type as usize;

        // 前のノードを更新
        if prev_idx != LIST_END {
            if let Some(prev_page) = self.get_page_mut(prev_idx as usize) {
                prev_page.next.store(next_idx, Ordering::Release);
            }
        } else {
            // これがヘッドだった
            self.free_areas[mt][order]
                .head
                .store(next_idx, Ordering::Release);
        }

        // 次のノードを更新
        if next_idx != LIST_END {
            if let Some(next_page) = self.get_page_mut(next_idx as usize) {
                next_page.prev.store(prev_idx, Ordering::Release);
            }
        } else {
            // これがテールだった
            self.free_areas[mt][order]
                .tail
                .store(prev_idx, Ordering::Release);
        }

        // ページ記述子をクリア
        if let Some(page) = self.get_page_mut(frame_idx) {
            page.flags.remove(PageFlags::FREE);
            page.next.store(LIST_END, Ordering::Release);
            page.prev.store(LIST_END, Ordering::Release);
        }

        self.free_areas[mt][order]
            .nr_free
            .fetch_sub(1, Ordering::Relaxed);

        // カラー統計を更新
        let color = frame_to_color(frame_idx);
        self.color_free_counts[color as usize].fetch_sub(1 << order, Ordering::Relaxed);
    }

    /// フリーリストの先頭からブロックを取り出す（O(1)）
    pub(super) fn list_pop_head(
        &mut self,
        order: usize,
        migrate_type: MigrateType,
    ) -> Option<usize> {
        let mt = migrate_type as usize;
        let head = self.free_areas[mt][order].head.load(Ordering::Acquire);

        if head == LIST_END {
            return None;
        }

        let frame_idx = head as usize;
        self.list_del(frame_idx, order, migrate_type);
        Some(frame_idx)
    }

    /// ページブロック内の空きページを指定のモビリティタイプに移動
    ///
    /// 断片化防止のため、あるブロックからページを「盗む」際に、
    /// そのブロック内の他の空きページもまとめて移動させるために使用。
    pub(super) fn move_freepages_block(
        &mut self,
        start_frame: usize,
        end_frame: usize,
        new_mt: MigrateType,
    ) -> usize {
        let mut moved_count = 0;
        let mut curr = start_frame.max(self.base_frame);

        // LOOP_PROOF: mode=condition; reason=Every path advances curr by at least one page or exits the finite backing extent.;
        while curr < end_frame {
            // ページ記述子を取得（範囲外チェック含む）
            let page = match self.get_page(curr) {
                Some(p) => p,
                None => break,
            };

            // 空きページでなければスキップ
            // 注意: フリーブロックのHeadのみがFREEフラグを持つ
            if !page.is_free() {
                curr += 1;
                continue;
            }

            // 空きページ発見
            let order = page.order as usize;
            let old_mt = page.migrate_type;

            // 巨大ブロック（2MBを超える）はpageblock境界を跨ぐため、
            // 移動しない（安全第一）。本来はブロックを分割して境界内の
            // 部分だけ移動すべきだが、実装が複雑になるため現状はスキップ。
            const PAGEBLOCK_ORDER: usize = 9; // 2MB = 512 pages = order 9
            if order > PAGEBLOCK_ORDER {
                curr += 1 << order;
                continue;
            }

            // 既に同じタイプなら移動不要
            if old_mt != new_mt {
                // リストから削除して、新しいタイプで追加し直す
                self.list_del(curr, order, old_mt);
                self.list_add_head(curr, order, new_mt);
                moved_count += 1;
            }

            // 次のブロックへ（現在のオーダー分進む）
            // バディアロケータの整合性により、curr + (1<<order) は次のブロックの先頭になる
            curr += 1 << order;
        }

        moved_count
    }

    // ========================================================================
    // 割り当て
    // ========================================================================

    /// 指定オーダー・モビリティタイプでフレームを割り当て
    ///
    /// ## アルゴリズム
    ///
    /// 1. 要求されたモビリティタイプのフリーリストを確認
    /// 2. 見つからなければ上位オーダーから分割
    /// 3. それでも見つからなければフォールバックタイプを試行
    fn allocate_index(&mut self, order: usize, migrate_type: MigrateType) -> Option<FrameIndex> {
        if order > MAX_ORDER {
            return None;
        }

        // まず要求タイプで試行
        if let Some(frame) = self.try_allocate_internal(order, migrate_type) {
            self.migrate_allocs[migrate_type as usize].fetch_add(1, Ordering::Relaxed);

            // 巨大ブロック（order >= 9）は複数pageblockを跨ぐため、
            // 範囲内の全pageblockを更新
            if order >= 9 {
                self.set_pageblocks_mt_for_range(frame.as_usize(), order, migrate_type);
            }

            return Some(frame);
        }

        // フォールバック
        for &fallback_type in migrate_type.fallback_order() {
            if let Some(frame) = self.try_allocate_internal(order, fallback_type) {
                self.fallback_count.fetch_add(1, Ordering::Relaxed);
                self.migrate_allocs[fallback_type as usize].fetch_add(1, Ordering::Relaxed);

                let frame_idx = frame.as_usize();

                // ページブロック制御（断片化防止 - 2MB Huge Page最適化）
                if order >= 9 {
                    // 2MB以上の割り当てなら、跨ぐ全pageblockのタイプを変更
                    // (Huge Page割り当て成功時)
                    self.set_pageblocks_mt_for_range(frame_idx, order, migrate_type);
                } else {
                    // 小さな割り当てでフォールバックが発生した場合
                    // ページブロック全体を「盗む」ことで、将来のHuge Page割り当てを保護する

                    // ページブロックの境界を計算
                    let block_start = frame_idx & !(PAGES_PER_PAGEBLOCK - 1);
                    let block_end = block_start + PAGES_PER_PAGEBLOCK;

                    // 現在のブロックのタイプを確認
                    let current_block_mt = self.get_pageblock_migratetype(frame_idx);

                    // ブロックのタイプが要求と異なる場合、ブロックごと乗っ取る
                    if current_block_mt != migrate_type {
                        // ブロックのタイプを変更
                        self.set_pageblock_migratetype(frame_idx, migrate_type);

                        // ブロック内の他の空きページも全て新しいタイプに移動
                        // これにより、このブロックは新しいタイプ専用（排他）になる
                        self.move_freepages_block(block_start, block_end, migrate_type);
                    }
                }

                return Some(frame);
            }
        }

        None
    }

    /// 内部割り当て実装
    pub(super) fn try_allocate_internal(
        &mut self,
        order: usize,
        migrate_type: MigrateType,
    ) -> Option<FrameIndex> {
        // 要求オーダー以上の空きブロックを探す
        for current_order in order..=MAX_ORDER {
            if let Some(frame_idx) = self.list_pop_head(current_order, migrate_type) {
                let frame = FrameIndex::new(frame_idx);

                // 必要に応じて分割
                self.split_block(frame, current_order, order, migrate_type);

                let block_size = 1u64 << order;
                self.free_frames.fetch_sub(block_size, Ordering::Relaxed);

                return Some(frame);
            }
        }

        None
    }

    /// ブロックを分割
    pub(super) fn split_block(
        &mut self,
        frame: FrameIndex,
        from_order: usize,
        to_order: usize,
        migrate_type: MigrateType,
    ) {
        let mut current_order = from_order;

        // LOOP_PROOF: mode=condition; reason=current_order decreases by one for each split until the target order.;
        while current_order > to_order {
            current_order -= 1;

            // 後半のBuddyをフリーリストに追加
            let buddy_frame = frame.as_usize() + (1 << current_order);
            self.list_add_head(buddy_frame, current_order, migrate_type);

            self.split_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    // ========================================================================
    // 解放
    // ========================================================================

    /// フレームを解放
    fn release_index(&mut self, frame: FrameIndex, order: usize) {
        if order > MAX_ORDER {
            return;
        }

        // デバッグ: フレームがorderに整列しているか確認
        debug_assert_eq!(
            frame.as_usize() & ((1usize << order) - 1),
            0,
            "Frame {:?} is not aligned to order {}",
            frame,
            order
        );

        // アライメントマスクでorder境界に切り下げ
        let aligned_frame = frame.as_usize() & !((1usize << order) - 1);

        // ページブロックのモビリティタイプを取得
        let migrate_type = self.get_pageblock_migratetype(aligned_frame);

        // Buddyとの結合を試みる
        self.free_one_page(aligned_frame, order, migrate_type);
    }

    /// 1ページ（ブロック）を解放し、Buddyと結合
    ///
    /// # 設計ノート
    ///
    /// 現在の実装は「メモリ効率優先」で、異なるmigrate typeのbuddyとも結合します。
    /// 最終的なブロックは元のmigrate typeで登録されるため、migrate type境界を跨いだ
    /// 結合が発生します。
    ///
    /// **THP成功率を最優先する場合の改善案:**
    /// ```rust
    /// // Buddyのmigrate typeが異なる場合は結合を停止
    /// if buddy_mt != migrate_type {
    ///     break;
    /// }
    /// ```
    /// これにより、migrate type隔離が強化され、2MB huge page割り当ての成功率が向上します。
    pub(super) fn free_one_page(
        &mut self,
        frame_idx: usize,
        order: usize,
        migrate_type: MigrateType,
    ) {
        let mut current_frame = frame_idx;
        let mut current_order = order;

        // 反復的にBuddyとの結合を試みる
        // LOOP_PROOF: mode=condition; reason=A successful merge increments current_order, and a missing buddy exits.;
        while current_order < MAX_ORDER {
            let buddy_idx = current_frame ^ (1 << current_order);

            // Buddyが存在し空いているか確認
            let buddy_free = self
                .get_page(buddy_idx)
                .map(|p| p.is_free() && p.order == current_order as u8)
                .unwrap_or(false);

            if !buddy_free {
                break;
            }

            // Buddyをフリーリストから削除
            let buddy_mt = self
                .get_page(buddy_idx)
                .map(|p| p.migrate_type)
                .unwrap_or(migrate_type);
            self.list_del(buddy_idx, current_order, buddy_mt);

            // TODO: THP成功率優先の場合、ここでmigrate type不一致をチェック
            // if buddy_mt != migrate_type { break; }

            self.coalesce_count.fetch_add(1, Ordering::Relaxed);

            // 親ブロックへ移動
            current_frame = current_frame & !(1 << current_order);
            current_order += 1;
        }

        // 最終的なブロックをフリーリストに追加
        self.list_add_head(current_frame, current_order, migrate_type);

        let block_size = 1u64 << order;
        self.free_frames.fetch_add(block_size, Ordering::Relaxed);
    }

    // ========================================================================
    // カラーリング対応割り当て
    // ========================================================================

    /// 特定のキャッシュカラーを優先して割り当て
    ///
    /// フリーリストを走査して `preferred_color` に一致するフレームを探す。
    /// 一致するフレームが見つかった場合、そのブロックをリストから除去し、
    /// 必要に応じて分割して返す。見つからなければ通常割り当てにフォールバック。
    ///
    /// ## 用途
    /// - プロセスごとに異なるカラーを割り当てることでキャッシュ競合を軽減
    /// - DMAバッファなど、キャッシュ効率が重要な用途
    fn allocate_color_index(
        &mut self,
        order: usize,
        migrate_type: MigrateType,
        preferred_color: u8,
    ) -> Option<FrameIndex> {
        if order > MAX_ORDER {
            return None;
        }
        let requested = 1usize << order;
        for source_type in
            core::iter::once(migrate_type).chain(migrate_type.fallback_order().iter().copied())
        {
            for current_order in order..=MAX_ORDER {
                let mut current = self.free_areas[source_type as usize][current_order]
                    .head
                    .load(Ordering::Acquire);
                let max_walk = self.free_areas[source_type as usize][current_order].count();
                for _ in 0..max_walk {
                    if current == LIST_END {
                        break;
                    }
                    let start = current as usize;
                    let offset = (preferred_color as usize + NUM_CACHE_COLORS
                        - start % NUM_CACHE_COLORS)
                        % NUM_CACHE_COLORS;
                    let target = start + offset;
                    if target % requested == 0 && offset + requested <= 1usize << current_order {
                        self.list_del(start, current_order, source_type);
                        let mut frame = start;
                        let mut level = current_order;
                        // LOOP_PROOF: mode=condition; reason=level decreases by one while splitting the selected finite buddy block.;
                        while level > order {
                            level -= 1;
                            let upper = frame + (1usize << level);
                            if target >= upper {
                                self.list_add_head(frame, level, source_type);
                                frame = upper;
                            } else {
                                self.list_add_head(upper, level, source_type);
                            }
                            self.split_count.fetch_add(1, Ordering::Relaxed);
                        }
                        self.free_frames
                            .fetch_sub(requested as u64, Ordering::Relaxed);
                        self.migrate_allocs[migrate_type as usize].fetch_add(1, Ordering::Relaxed);
                        if order >= 9 {
                            self.set_pageblocks_mt_for_range(frame, order, migrate_type);
                        }
                        if source_type != migrate_type {
                            self.fallback_count.fetch_add(1, Ordering::Relaxed);
                            if order < 9 {
                                self.set_pageblock_migratetype(frame, migrate_type);
                                let start = frame & !(PAGES_PER_PAGEBLOCK - 1);
                                self.move_freepages_block(
                                    start,
                                    start + PAGES_PER_PAGEBLOCK,
                                    migrate_type,
                                );
                            }
                        }
                        return Some(FrameIndex::new(frame));
                    }
                    current = self.get_page(start)?.next.load(Ordering::Acquire);
                }
            }
        }
        self.allocate_index(order, migrate_type)
    }

    // ========================================================================
    // 統計
    // ========================================================================

    /// 空きフレーム数を取得
    pub fn free_count(&self) -> u64 {
        self.free_frames.load(Ordering::Relaxed)
    }

    /// 総フレーム数を取得
    pub fn total_count(&self) -> usize {
        self.total_frames
    }

    /// モビリティタイプ別の統計
    pub fn migrate_stats(&self) -> [u64; MigrateType::COUNT] {
        [
            self.migrate_allocs[0].load(Ordering::Relaxed),
            self.migrate_allocs[1].load(Ordering::Relaxed),
            self.migrate_allocs[2].load(Ordering::Relaxed),
            self.migrate_allocs[3].load(Ordering::Relaxed),
        ]
    }

    /// フォールバック回数
    pub fn fallback_count(&self) -> u64 {
        self.fallback_count.load(Ordering::Relaxed)
    }

    /// オーダー・モビリティタイプ別の空きブロック数
    pub fn free_area_count(&self, order: usize, migrate_type: MigrateType) -> usize {
        if order > MAX_ORDER {
            return 0;
        }
        self.free_areas[migrate_type as usize][order].count()
    }

    /// カラー別の空きフレーム数
    pub fn color_stats(&self) -> [usize; NUM_CACHE_COLORS] {
        let mut stats = [0usize; NUM_CACHE_COLORS];
        for (i, count) in self.color_free_counts.iter().enumerate() {
            stats[i] = count.load(Ordering::Relaxed);
        }
        stats
    }

    pub(super) fn add_free_region(&mut self, start_frame: usize, end_frame: usize) {
        let mut current = start_frame;

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while current < end_frame {
            // 現在の位置から最大のアライメントブロックを見つける
            let remaining = end_frame - current;

            // 最大オーダーを計算:
            // 1. currentのアライメントから決まる最大オーダー
            // 2. 残りフレーム数に収まるオーダー
            let align_order = if current == 0 {
                MAX_ORDER
            } else {
                current.trailing_zeros() as usize
            };

            let size_order = if remaining == 0 {
                0
            } else {
                (usize::BITS - remaining.leading_zeros() - 1) as usize
            };

            let order = align_order.min(size_order).min(MAX_ORDER);
            let block_size = 1usize << order;

            // フリーリストに追加
            self.list_add_head(current, order, MigrateType::Movable);
            self.free_frames
                .fetch_add(block_size as u64, Ordering::Relaxed);

            current += block_size;
        }
    }

    pub fn stats(&self) -> FreeListBuddyStats {
        let mut order_stats = [(0usize, 0usize); MAX_ORDER + 1];

        for order in 0..=MAX_ORDER {
            let mut free_blocks = 0;
            for mt in 0..MigrateType::COUNT {
                free_blocks += self.free_areas[mt][order].count();
            }
            let total_pages = free_blocks * (1 << order);
            order_stats[order] = (free_blocks, total_pages);
        }

        FreeListBuddyStats {
            total_frames: self.total_frames,
            free_frames: self.free_frames.load(Ordering::Relaxed),
            split_count: self.split_count.load(Ordering::Relaxed),
            coalesce_count: self.coalesce_count.load(Ordering::Relaxed),
            fallback_count: self.fallback_count.load(Ordering::Relaxed),
            order_stats,
            migrate_stats: self.migrate_stats(),
        }
    }
}
