use super::*;


mod _split_1;
mod _split_2;
impl CompactionCandidates {
    pub const fn new() -> Self {
        Self {
            by_order: [0; 19],
            count: 0,
        }
    }
    
    pub fn add(&mut self, order: usize, count: usize) {
        if order < 19 {
            self.by_order[order] += count;
            self.count += count;
        }
    }
}

/// 遅延結合の閾値（解放回数がこれを超えたら結合を試みる）
pub(crate) const LAZY_COALESCE_THRESHOLD: u64 = 64;

/// Buddy Allocator
///
/// オーダー n のブロックは 2^n 個の連続した4KiBフレームを表す
/// - order 0: 4KiB (1フレーム)
/// - order 9: 2MiB (512フレーム)
/// - order 18: 1GiB (262144フレーム)
///
/// ## 遅延結合 (Lazy Coalescing)
///
/// フレーム解放時に即座にBuddyとの結合を試みると、割り当てと解放が
/// 境界付近で繰り返される場合に「分割→結合→分割→結合」のスラッシングが
/// 発生し、CPUサイクルを浪費します。
///
/// 遅延結合では、解放時にはブロックをフリーリストに戻すだけにし、
/// 以下のタイミングでまとめて結合処理を行います：
/// - 解放回数が閾値を超えた場合
/// - 要求サイズのブロックが見つからない場合（allocate_order内）
/// - 明示的な `try_coalesce_all` 呼び出し
pub struct BuddyFrameAllocator {
    /// 各オーダーの空きブロックビット（1 = free）
    free_bits: [u64; TOTAL_DETAIL_WORDS],
    /// 各オーダーの空きサマリービット（1 = detail word has free blocks）
    free_summary: [u64; TOTAL_SUMMARY_WORDS],
    /// オーダーごとのブロック数（capacity, MAX_PHYSICAL_MEMORYに基づく）
    order_block_capacity: [usize; MAX_ORDER + 1],
    /// オーダーごとのブロック数（total_framesに基づく上限）
    order_block_counts: [usize; MAX_ORDER + 1],
    /// オーダーごとの詳細ビット開始位置（word index）
    order_detail_word_start: [usize; MAX_ORDER + 1],
    /// オーダーごとの詳細ビット長（word数）
    order_detail_word_len: [usize; MAX_ORDER + 1],
    /// オーダーごとのサマリービット開始位置（word index）
    order_summary_word_start: [usize; MAX_ORDER + 1],
    /// オーダーごとのサマリービット長（word数）
    order_summary_word_len: [usize; MAX_ORDER + 1],
    /// オーダーごとの空きブロック数
    order_free_counts: [usize; MAX_ORDER + 1],
    /// レイアウト初期化済みフラグ
    layout_initialized: bool,
    /// 総フレーム数
    total_frames: usize,
    /// 空きフレーム数（4KiB単位）
    free_frames: u64,
    /// 統計: 分割回数
    split_count: u64,
    /// 統計: 合体回数
    coalesce_count: u64,
    /// 遅延結合: 前回の結合以降の解放回数
    deferred_dealloc_count: u64,
    /// 遅延結合: スキップした結合の回数（統計用）
    deferred_coalesce_skipped: u64,
    /// NUMA node -> list of managed (start_frame, end_frame) ranges
    /// This is optional so the allocator can remain const-constructible; it is
    /// initialized during `init` or when regions are registered.
    numa_regions: Option<BTreeMap<NumaNodeId, alloc::vec::Vec<(FrameIndex, FrameIndex)>>>,
    /// 探索カーソル: 各オーダーの次回探索開始位置（Round-Robin）
    /// これにより特定領域への割り当て集中を防ぎ、メモリ全体を均等に使用
    search_cursor: [usize; MAX_ORDER + 1],
    /// ゼロクリア済みフラグビットマップ（1 = zeroed）
    /// free_bitsと同じレイアウトで、空きブロックのうちゼロクリア済みのものを追跡
    zeroed_bits: [u64; TOTAL_DETAIL_WORDS],
    /// ゼロクリア済み空きブロック数（オーダーごと）
    zeroed_counts: [usize; MAX_ORDER + 1],
    /// 統計: ゼロクリア済みページからの割り当て数
    zeroed_allocs: u64,
    /// 統計: スクラブ（バックグラウンドゼロクリア）回数
    scrub_count: u64,
    /// Coalesceポリシー（Hysteresisベース）
    coalesce_policy: CoalescePolicy,
}

impl BuddyFrameAllocator {
    pub const fn new() -> Self {
        Self {
            free_bits: [0u64; TOTAL_DETAIL_WORDS],
            free_summary: [0u64; TOTAL_SUMMARY_WORDS],
            order_block_capacity: [0usize; MAX_ORDER + 1],
            order_block_counts: [0usize; MAX_ORDER + 1],
            order_detail_word_start: [0usize; MAX_ORDER + 1],
            order_detail_word_len: [0usize; MAX_ORDER + 1],
            order_summary_word_start: [0usize; MAX_ORDER + 1],
            order_summary_word_len: [0usize; MAX_ORDER + 1],
            order_free_counts: [0usize; MAX_ORDER + 1],
            layout_initialized: false,
            total_frames: 0,
            free_frames: 0,
            split_count: 0,
            coalesce_count: 0,
            deferred_dealloc_count: 0,
            deferred_coalesce_skipped: 0,
            numa_regions: None,
            search_cursor: [0usize; MAX_ORDER + 1],
            zeroed_bits: [0u64; TOTAL_DETAIL_WORDS],
            zeroed_counts: [0usize; MAX_ORDER + 1],
            zeroed_allocs: 0,
            scrub_count: 0,
            coalesce_policy: CoalescePolicy::new(),
        }
    }

    fn clear_state(&mut self) {
        for word in self.free_bits.iter_mut() {
            *word = 0;
        }
        for word in self.free_summary.iter_mut() {
            *word = 0;
        }
        for count in self.order_free_counts.iter_mut() {
            *count = 0;
        }
        self.free_frames = 0;
        self.split_count = 0;
        self.coalesce_count = 0;
        self.deferred_dealloc_count = 0;
        self.deferred_coalesce_skipped = 0;
        for cursor in self.search_cursor.iter_mut() {
            *cursor = 0;
        }
        for word in self.zeroed_bits.iter_mut() {
            *word = 0;
        }
        for count in self.zeroed_counts.iter_mut() {
            *count = 0;
        }
        self.zeroed_allocs = 0;
        self.scrub_count = 0;
    }

    /// メモリマップに基づいてアロケータを初期化
    ///
    /// # Safety
    /// - `usable_regions` は正しい使用可能メモリ領域を示す必要がある
    pub unsafe fn init(&mut self, usable_regions: &[(PhysAddr, u64)]) {
        self.init_layout();
        self.clear_state();

        let mut total = 0usize;

        // 使用可能な領域を空きブロックとして登録
        if self.numa_regions.is_none() {
            self.numa_regions = Some(BTreeMap::new());
        }

        for &(start, size) in usable_regions {
            let start_frame = FrameIndex::from_phys_addr(start.as_u64());
            let end_frame = FrameIndex::from_phys_addr(start.as_u64() + size);

            total = total.max(end_frame.as_usize());

            // 領域を最大オーダーのブロックに分割して登録
            self.add_region(start_frame, end_frame);

            if let Some(map) = self.numa_regions.as_mut() {
                map.entry(NumaNodeId::NODE_0)
                    .or_insert_with(alloc::vec::Vec::new)
                    .push((start_frame, end_frame));
            }
        }

        self.total_frames = total.min(MAX_4K_FRAMES);
        self.update_order_limits();
    }

    fn init_layout(&mut self) {
        if self.layout_initialized {
            return;
        }

        let mut detail_offset = 0usize;
        let mut summary_offset = 0usize;

        for order in 0..=MAX_ORDER {
            let blocks = MAX_4K_FRAMES >> order;
            let detail_words = (blocks + 63) / 64;
            let summary_words = (detail_words + 63) / 64;

            self.order_block_capacity[order] = blocks;
            self.order_detail_word_start[order] = detail_offset;
            self.order_detail_word_len[order] = detail_words;
            self.order_summary_word_start[order] = summary_offset;
            self.order_summary_word_len[order] = summary_words;

            detail_offset += detail_words;
            summary_offset += summary_words;
        }

        debug_assert!(detail_offset <= TOTAL_DETAIL_WORDS);
        debug_assert!(summary_offset <= TOTAL_SUMMARY_WORDS);

        self.layout_initialized = true;
    }

    fn update_order_limits(&mut self) {
        for order in 0..=MAX_ORDER {
            self.order_block_counts[order] = self.total_frames >> order;
        }
    }

    /// 連続した空き領域を Buddy システムに追加
    fn add_region(&mut self, start: FrameIndex, end: FrameIndex) {
        let mut current = start.as_usize();
        let mut end_idx = end.as_usize();

        if current >= MAX_4K_FRAMES {
            return;
        }
        if end_idx > MAX_4K_FRAMES {
            log::warn!(
                "[Buddy] Region beyond MAX_PHYSICAL_MEMORY: clamping end {:#x} -> {:#x}",
                end_idx * PAGE_SIZE_4K,
                MAX_4K_FRAMES * PAGE_SIZE_4K
            );
            end_idx = MAX_4K_FRAMES;
        }

        while current < end_idx {
            // 現在位置からアラインされた最大ブロックを見つける
            let remaining = end_idx - current;

            // 使用可能な最大オーダーを計算
            let max_order_by_alignment = current.trailing_zeros() as usize;
            let max_order_by_size = (usize::BITS - remaining.leading_zeros() - 1) as usize;
            let order = max_order_by_alignment.min(max_order_by_size).min(MAX_ORDER);

            let block_size = 1 << order;

            // このブロックを空きとして登録
            let frame = FrameIndex::new(current);
            self.set_free_block_by_frame(order, frame);
            self.free_frames += block_size as u64;

            current += block_size;
        }
    }

    #[inline]
    fn set_summary_bit(&mut self, order: usize, detail_word_idx: usize) {
        let summary_word_idx =
            self.order_summary_word_start[order] + (detail_word_idx / 64);
        let summary_bit = detail_word_idx % 64;
        if summary_word_idx < self.free_summary.len() {
            self.free_summary[summary_word_idx] |= 1u64 << summary_bit;
        }
    }

    #[inline]
    fn clear_summary_bit(&mut self, order: usize, detail_word_idx: usize) {
        let summary_word_idx =
            self.order_summary_word_start[order] + (detail_word_idx / 64);
        let summary_bit = detail_word_idx % 64;
        if summary_word_idx < self.free_summary.len() {
            self.free_summary[summary_word_idx] &= !(1u64 << summary_bit);
        }
    }

    #[inline]
    fn set_free_block(&mut self, order: usize, block_idx: usize) {
        if block_idx >= self.order_block_capacity[order] {
            return;
        }
        let detail_word_idx = block_idx / 64;
        let bit_idx = block_idx % 64;
        let word_idx = self.order_detail_word_start[order] + detail_word_idx;
        let word = self.free_bits[word_idx];
        let new_word = word | (1u64 << bit_idx);
        if new_word != word {
            self.free_bits[word_idx] = new_word;
            self.order_free_counts[order] += 1;
            if word == 0 {
                self.set_summary_bit(order, detail_word_idx);
            }
        }
    }

    #[inline]
    fn clear_free_block(&mut self, order: usize, block_idx: usize) {
        if block_idx >= self.order_block_capacity[order] {
            return;
        }
        let detail_word_idx = block_idx / 64;
        let bit_idx = block_idx % 64;
        let word_idx = self.order_detail_word_start[order] + detail_word_idx;
        let word = self.free_bits[word_idx];
        if (word & (1u64 << bit_idx)) == 0 {
            return;
        }
        let new_word = word & !(1u64 << bit_idx);
        self.free_bits[word_idx] = new_word;
        self.order_free_counts[order] = self.order_free_counts[order].saturating_sub(1);
        if new_word == 0 {
            self.clear_summary_bit(order, detail_word_idx);
        }
    }

    #[inline]
    fn is_block_free(&self, order: usize, block_idx: usize) -> bool {
        if block_idx >= self.order_block_capacity[order] {
            return false;
        }
        let detail_word_idx = block_idx / 64;
        let bit_idx = block_idx % 64;
        let word_idx = self.order_detail_word_start[order] + detail_word_idx;
        (self.free_bits[word_idx] & (1u64 << bit_idx)) != 0
    }

    #[inline]
    fn set_free_block_by_frame(&mut self, order: usize, frame: FrameIndex) {
        let block_idx = frame.as_usize() >> order;
        self.set_free_block(order, block_idx);
    }

    /// サマリーワード範囲をスキャンして空きブロックを検索
    fn scan_summary_range(
        &mut self,
        order: usize,
        begin: usize,
        end: usize,
    ) -> Option<usize> {
        let summary_start = self.order_summary_word_start[order];
        let detail_start = self.order_detail_word_start[order];
        let detail_len = self.order_detail_word_len[order];
        let summary_len = self.order_summary_word_len[order];
        let max_blocks = self.order_block_counts[order];

        for summary_idx in begin..end {
            let mut summary_word = self.free_summary[summary_start + summary_idx];
            while summary_word != 0 {
                let bit = fast_tzcnt_u64(summary_word) as usize;
                let detail_idx = summary_idx * 64 + bit;
                if detail_idx >= detail_len {
                    break;
                }
                let detail_word = self.free_bits[detail_start + detail_idx];
                if detail_word == 0 {
                    self.clear_summary_bit(order, detail_idx);
                } else {
                    let block_bit = fast_tzcnt_u64(detail_word) as usize;
                    let block_idx = detail_idx * 64 + block_bit;
                    if block_idx < max_blocks {
                        self.search_cursor[order] = (summary_idx + 1) % summary_len.max(1);
                        return Some(block_idx);
                    }
                }
                summary_word &= summary_word - 1;
            }
        }
        None
    }

    fn find_free_block(&mut self, order: usize) -> Option<usize> {
        if self.order_free_counts[order] == 0 || self.order_block_counts[order] == 0 {
            return None;
        }

        let summary_len = self.order_summary_word_len[order];
        let start_summary = self.search_cursor[order] % summary_len.max(1);

        self.scan_summary_range(order, start_summary, summary_len)
            .or_else(|| self.scan_summary_range(order, 0, start_summary))
    }

    /// ワード内のビットマスクを範囲制限付きで計算
    fn compute_word_mask(word_base: usize, start_block: usize, end_block: usize) -> u64 {
        let mut mask = u64::MAX;
        if word_base < start_block {
            mask &= !((1u64 << (start_block - word_base)) - 1);
        }
        if word_base + 64 > end_block {
            let tail = end_block - word_base;
            if tail < 64 {
                mask &= (1u64 << tail) - 1;
            }
        }
        mask
    }

    fn find_free_block_in_range(
        &mut self,
        order: usize,
        start_block: usize,
        end_block: usize,
    ) -> Option<usize> {
        if start_block >= end_block {
            return None;
        }

        let max_blocks = self.order_block_counts[order];
        let end_block = end_block.min(max_blocks);
        if start_block >= end_block || self.order_free_counts[order] == 0 {
            return None;
        }

        let detail_start = self.order_detail_word_start[order];
        let detail_len = self.order_detail_word_len[order];
        let start_word = start_block / 64;
        let end_word = (end_block + 63) / 64;

        for word_idx in start_word..end_word.min(detail_len) {
            let word = self.free_bits[detail_start + word_idx];
            if word == 0 {
                continue;
            }

            let word_base = word_idx * 64;
            let masked = word & Self::compute_word_mask(word_base, start_block, end_block);
            if masked == 0 {
                continue;
            }
            let bit = masked.trailing_zeros() as usize;
            let block_idx = word_base + bit;
            if block_idx < end_block {
                return Some(block_idx);
            }
        }

        None
    }

    /// 指定オーダーのブロックを割り当て
    /// 
    /// ## 遅延結合との連携
    /// 
    /// 要求サイズのブロックが見つからない場合、まず遅延されていた
    /// 結合処理を実行してから再度探索を試みる。
    fn allocate_order(&mut self, order: usize) -> Option<FrameIndex> {
        if order > MAX_ORDER {
            return None;
        }

        // 第1試行: 通常の探索
        if let Some(frame) = self.try_allocate_order_internal(order) {
            return Some(frame);
        }

        // 空きブロックが見つからなかった場合、遅延結合を実行
        if self.deferred_dealloc_count > 0 {
            self.try_coalesce_all();
            self.deferred_dealloc_count = 0;

            // 第2試行: 結合後に再探索
            return self.try_allocate_order_internal(order);
        }

        None
    }

    /// allocate_orderの内部実装（結合なし）
    fn try_allocate_order_internal(&mut self, order: usize) -> Option<FrameIndex> {
        // 要求オーダー以上の空きブロックを探す
        for current_order in order..=MAX_ORDER {
            if let Some(block_idx) = self.find_free_block(current_order) {
                self.clear_free_block(current_order, block_idx);
                let frame = FrameIndex::new(block_idx << current_order);

                // 必要に応じてブロックを分割
                self.split_block(frame, current_order, order);

                let block_size = 1u64 << order;
                debug_assert!(self.free_frames >= block_size);
                self.free_frames = self.free_frames.saturating_sub(block_size);

                // Phase 6: Set Folio (Compound Page) flags
                if order > 0 {
                    use crate::mm::page_flags::{self, PageMetaFlags};
                    // Set order
                    unsafe { page_flags::set_order(frame, order as u8); }

                    // Head page
                    page_flags::set_flag(frame, PageMetaFlags::CompoundHead);
                    // Tail pages
                    for i in 1..block_size {
                         let tail_frame = FrameIndex::new(frame.as_usize() + i as usize);
                         page_flags::set_flag(tail_frame, PageMetaFlags::CompoundTail);
                    }
                }

                return Some(frame);
            }
        }

        None
    }

    /// 大きなブロックを目標オーダーまで分割
    fn split_block(&mut self, frame: FrameIndex, from_order: usize, to_order: usize) {
        let mut current_order = from_order;

        while current_order > to_order {
            current_order -= 1;

            // 後半のBuddyを空きビットに追加
            let buddy = FrameIndex::new(frame.as_usize() + (1 << current_order));
            self.set_free_block_by_frame(current_order, buddy);

            self.split_count += 1;
        }
    }

    /// 指定オーダーのブロックを解放
    /// 
    /// ## 遅延結合 (Lazy Coalescing)
    /// 
    /// 即座にBuddyとの結合を試みず、フリービットをセットするだけにする。
    /// 結合は以下のタイミングで行われる：
    /// - 解放回数が閾値 (LAZY_COALESCE_THRESHOLD) を超えた場合
    /// - allocate_order で要求サイズのブロックが見つからない場合
    /// - 明示的な try_coalesce_all 呼び出し
    fn deallocate_order(&mut self, frame: FrameIndex, order: usize) {
        debug_assert_eq!(frame.align_down(order), frame);

        // Phase 6: Clear Folio flags
        if order > 0 {
            use crate::mm::page_flags::{self, PageMetaFlags};
            unsafe { page_flags::set_order(frame, 0); }

            let count = 1usize << order;
             page_flags::clear_flag(frame, PageMetaFlags::CompoundHead);
             for i in 1..count {
                 let tail_frame = FrameIndex::new(frame.as_usize() + i);
                 page_flags::clear_flag(tail_frame, PageMetaFlags::CompoundTail);
             }
        }

        // フレームを空きとしてマーク
        let block_idx = frame.as_usize() >> order;
        if self.is_block_free(order, block_idx) {
            log::error!(
                "[Buddy] Double free detected: frame={:#x} order={}",
                frame.to_phys_addr(),
                order
            );
            return;
        }
        self.set_free_block(order, block_idx);
        self.free_frames += 1u64 << order;

        // 遅延結合: 解放回数をインクリメント
        self.deferred_dealloc_count += 1;

        // 閾値を超えたら結合を試みる
        if self.deferred_dealloc_count >= LAZY_COALESCE_THRESHOLD {
            self.try_coalesce_all();
            self.deferred_dealloc_count = 0;
        } else {
            self.deferred_coalesce_skipped += 1;
        }
    }

    /// 指定オーダーのブロックを解放（即時結合版）
    /// 
    /// 遅延結合を使用せず、即座にBuddyとの結合を試みる。
    /// 大きなブロック（2MB以上）の解放など、結合が有利な場合に使用。
    fn deallocate_order_immediate(&mut self, frame: FrameIndex, order: usize) {
        debug_assert_eq!(frame.align_down(order), frame);

        // Phase 6: Clear Folio flags
        if order > 0 {
            use crate::mm::page_flags::{self, PageMetaFlags};
            unsafe { page_flags::set_order(frame, 0); }

            let count = 1usize << order;
             page_flags::clear_flag(frame, PageMetaFlags::CompoundHead);
             for i in 1..count {
                 let tail_frame = FrameIndex::new(frame.as_usize() + i);
                 page_flags::clear_flag(tail_frame, PageMetaFlags::CompoundTail);
             }
        }

        let block_idx = frame.as_usize() >> order;
        if self.is_block_free(order, block_idx) {
            log::error!(
                "[Buddy] Double free detected: frame={:#x} order={}",
                frame.to_phys_addr(),
                order
            );
            return;
        }
        self.set_free_block(order, block_idx);
        self.free_frames += 1u64 << order;

        // 即座にBuddyとの合体を試みる
        self.coalesce(block_idx, order);
    }

    /// 全オーダーで結合可能なブロックを結合する
    /// 
    /// アイドル時やメモリ不足時に呼び出すことで、
    /// 断片化を解消し大きな連続領域を確保できる。
    pub fn try_coalesce_all(&mut self) {
        // 下位オーダーから順に結合を試みる
        for order in 0..MAX_ORDER {
            self.try_coalesce_order(order);
        }
    }

    /// 特定オーダーのブロックを結合可能な限り結合する
    fn try_coalesce_order(&mut self, order: usize) {
        if order >= MAX_ORDER {
            return;
        }

        let max_blocks = self.order_block_counts[order];
        let _detail_start = self.order_detail_word_start[order];
        let _detail_len = self.order_detail_word_len[order];

        // 全ブロックをスキャンして結合可能なペアを探す
        let mut block_idx = 0usize;
        while block_idx < max_blocks {
            // 偶数インデックスのブロックのみチェック（奇数はBuddyなので）
            if block_idx % 2 != 0 {
                block_idx += 1;
                continue;
            }

            let buddy_idx = block_idx + 1;
            if buddy_idx >= max_blocks {
                break;
            }

            // 両方が空いているかチェック
            if self.is_block_free(order, block_idx) && self.is_block_free(order, buddy_idx) {
                // 結合実行
                self.clear_free_block(order, block_idx);
                self.clear_free_block(order, buddy_idx);

                // 上位オーダーに空きブロックを追加
                let parent_idx = block_idx >> 1;
                self.set_free_block(order + 1, parent_idx);

                self.coalesce_count += 1;
            }

            block_idx += 2;
        }
    }
}
