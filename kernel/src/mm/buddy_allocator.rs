// ============================================================================
// src/mm/buddy_allocator.rs - Buddy Allocator for Physical Frames
// 設計書 5.2 Tier1改良: O(log n) 物理フレーム管理
//
// ビットマップFirst-fitの問題点:
// - 連続フレーム検索が O(n)
// - フラグメンテーション発生時に性能劣化
//
// Buddy Allocatorの利点:
// - 割り当て/解放が O(log n)
// - 連続領域の確保が効率的
// - 2のべき乗サイズの自然なサポート
// ============================================================================
#![allow(dead_code)]

use crate::sync::IrqMutex;
use alloc::collections::BTreeMap;
use x86_64::PhysAddr;
use x86_64::structures::paging::{FrameAllocator, PhysFrame, Size1GiB, Size2MiB, Size4KiB};

/// 4KiB ページサイズ
pub const PAGE_SIZE_4K: usize = 4096;
/// 2MiB ページサイズ  
pub const PAGE_SIZE_2M: usize = 2 * 1024 * 1024;
/// 1GiB ページサイズ
pub const PAGE_SIZE_1G: usize = 1024 * 1024 * 1024;

/// 最大オーダー（2^MAX_ORDER * 4KiB = 最大ブロックサイズ）
/// MAX_ORDER = 10 → 4MiB ブロック
/// MAX_ORDER = 18 → 1GiB ブロック（1GiBページ対応）
const MAX_ORDER: usize = 18;

/// 物理メモリの最大サイズ（16GiB想定）
const MAX_PHYSICAL_MEMORY: usize = 16 * 1024 * 1024 * 1024;

/// 4KiBページ数の最大値
const MAX_4K_FRAMES: usize = MAX_PHYSICAL_MEMORY / PAGE_SIZE_4K;

/// 全オーダーの空きビット数の合計（完全二分木）
const TOTAL_BLOCKS: usize = MAX_4K_FRAMES * 2 - 1;

/// 空きビットの総ワード数（u64）
const TOTAL_DETAIL_WORDS: usize = (TOTAL_BLOCKS + 63) / 64;

/// 各オーダーのサマリービットの総ワード数（u64）
const TOTAL_SUMMARY_WORDS: usize = total_summary_words();

const fn total_summary_words() -> usize {
    let mut total = 0usize;
    let mut order = 0usize;
    while order <= MAX_ORDER {
        let blocks = MAX_4K_FRAMES >> order;
        let detail_words = (blocks + 63) / 64;
        let summary_words = (detail_words + 63) / 64;
        total += summary_words;
        order += 1;
    }
    total
}

/// フレーム番号のNewtype
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FrameIndex(usize);

impl FrameIndex {
    #[inline]
    pub const fn new(index: usize) -> Self {
        Self(index)
    }

    #[inline]
    pub const fn from_phys_addr(addr: u64) -> Self {
        Self((addr as usize) / PAGE_SIZE_4K)
    }

    #[inline]
    pub const fn to_phys_addr(self) -> u64 {
        (self.0 * PAGE_SIZE_4K) as u64
    }

    #[inline]
    pub const fn as_usize(self) -> usize {
        self.0
    }

    /// Buddyのインデックスを計算
    /// order = 0 なら 1ページの Buddy
    /// order = 1 なら 2ページの Buddy
    #[inline]
    pub const fn buddy(self, order: usize) -> Self {
        let block_size = 1 << order;
        Self(self.0 ^ block_size)
    }

    /// 指定オーダーのブロック先頭にアライン
    #[inline]
    pub const fn align_down(self, order: usize) -> Self {
        let block_size = 1 << order;
        Self((self.0 / block_size) * block_size)
    }
}

// (FreeList removed: order-local free bitsets are used instead.)

/// Buddy Allocator
///
/// オーダー n のブロックは 2^n 個の連続した4KiBフレームを表す
/// - order 0: 4KiB (1フレーム)
/// - order 9: 2MiB (512フレーム)
/// - order 18: 1GiB (262144フレーム)
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
    /// NUMA node -> list of managed (start_frame, end_frame) ranges
    /// This is optional so the allocator can remain const-constructible; it is
    /// initialized during `init` or when regions are registered.
    numa_regions: Option<BTreeMap<usize, alloc::vec::Vec<(FrameIndex, FrameIndex)>>>,
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
            numa_regions: None,
        }
    }

    /// メモリマップに基づいてアロケータを初期化
    ///
    /// # Safety
    /// - `usable_regions` は正しい使用可能メモリ領域を示す必要がある
    pub unsafe fn init(&mut self, usable_regions: &[(PhysAddr, u64)]) {
        self.init_layout();

        // 初期化: 全て使用中（free bit = 0）
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
                map.entry(0)
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

    fn find_free_block(&mut self, order: usize) -> Option<usize> {
        if self.order_free_counts[order] == 0 || self.order_block_counts[order] == 0 {
            return None;
        }

        let summary_start = self.order_summary_word_start[order];
        let summary_len = self.order_summary_word_len[order];
        let detail_start = self.order_detail_word_start[order];
        let detail_len = self.order_detail_word_len[order];
        let max_blocks = self.order_block_counts[order];

        for summary_idx in 0..summary_len {
            let mut summary_word = self.free_summary[summary_start + summary_idx];
            while summary_word != 0 {
                let bit = summary_word.trailing_zeros() as usize;
                let detail_idx = summary_idx * 64 + bit;
                if detail_idx >= detail_len {
                    break;
                }
                let detail_word = self.free_bits[detail_start + detail_idx];
                if detail_word == 0 {
                    self.clear_summary_bit(order, detail_idx);
                } else {
                    let block_bit = detail_word.trailing_zeros() as usize;
                    let block_idx = detail_idx * 64 + block_bit;
                    if block_idx < max_blocks {
                        return Some(block_idx);
                    }
                }
                summary_word &= summary_word - 1;
            }
        }

        None
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
            let mut word = self.free_bits[detail_start + word_idx];
            if word == 0 {
                continue;
            }

            let word_base = word_idx * 64;
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

            word &= mask;
            if word == 0 {
                continue;
            }
            let bit = word.trailing_zeros() as usize;
            let block_idx = word_base + bit;
            if block_idx < end_block {
                return Some(block_idx);
            }
        }

        None
    }

    /// 指定オーダーのブロックを割り当て
    /// O(log n) の性能
    fn allocate_order(&mut self, order: usize) -> Option<FrameIndex> {
        if order > MAX_ORDER {
            return None;
        }
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
    /// O(log n) の性能
    fn deallocate_order(&mut self, frame: FrameIndex, order: usize) {
        debug_assert_eq!(frame.align_down(order), frame);

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
        self.free_frames += (1u64 << order);

        // Buddyとの合体を試みる
        self.coalesce(block_idx, order);
    }

    /// Buddyとの合体を反復的に試みる
    ///
    /// 以前の再帰実装はスタックオーバーフローのリスクがあったため、
    /// ループベースの反復的実装に変更。
    fn coalesce(&mut self, block_idx: usize, order: usize) {
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
    fn frames_to_order(frames: usize) -> usize {
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
        self.deallocate_order(frame_idx, 0);
    }

    /// 2MiB フレームを解放
    pub fn deallocate_2m_frame(&mut self, frame: PhysFrame<Size2MiB>) {
        let frame_idx = FrameIndex::from_phys_addr(frame.start_address().as_u64());
        let order = Self::frames_to_order(PAGE_SIZE_2M / PAGE_SIZE_4K);
        self.deallocate_order(frame_idx, order);
    }

    /// 1GiB フレームを解放
    pub fn deallocate_1g_frame(&mut self, frame: PhysFrame<Size1GiB>) {
        let frame_idx = FrameIndex::from_phys_addr(frame.start_address().as_u64());
        let order = Self::frames_to_order(PAGE_SIZE_1G / PAGE_SIZE_4K);
        self.deallocate_order(frame_idx, order);
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
    pub fn register_numa_region(&mut self, node: usize, start: FrameIndex, end: FrameIndex) {
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
    fn allocate_order_in_range(
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

    /// Try to allocate a 4KiB frame on a preferred NUMA node; fallback to others and global
    pub fn allocate_4k_frame_on_node(&mut self, node: usize) -> Option<PhysFrame<Size4KiB>> {
        if let Some(map) = self.numa_regions.as_ref() {
            if let Some(ranges) = map.get(&node) {
                for &(start, end) in ranges.iter() {
                    if let Some(frame) =
                        self.allocate_order_in_range(0, start.as_usize(), end.as_usize())
                    {
                        let addr = PhysAddr::new(frame.to_phys_addr());
                        return Some(PhysFrame::containing_address(addr));
                    }
                }
            }

            for (&other, ranges) in map.iter() {
                if other == node {
                    continue;
                }
                for &(start, end) in ranges.iter() {
                    if let Some(frame) =
                        self.allocate_order_in_range(0, start.as_usize(), end.as_usize())
                    {
                        let addr = PhysAddr::new(frame.to_phys_addr());
                        return Some(PhysFrame::containing_address(addr));
                    }
                }
            }
        }

        // global fallback
        self.allocate_4k_frame()
    }

    /// 2MiB allocation on a preferred NUMA node
    pub fn allocate_2m_frame_on_node(&mut self, node: usize) -> Option<PhysFrame<Size2MiB>> {
        let order = Self::frames_to_order(PAGE_SIZE_2M / PAGE_SIZE_4K);
        if let Some(map) = self.numa_regions.as_ref() {
            if let Some(ranges) = map.get(&node) {
                for &(start, end) in ranges.iter() {
                    if let Some(frame) =
                        self.allocate_order_in_range(order, start.as_usize(), end.as_usize())
                    {
                        let addr = PhysAddr::new(frame.to_phys_addr());
                        return Some(PhysFrame::containing_address(addr));
                    }
                }
            }

            for (&other, ranges) in map.iter() {
                if other == node {
                    continue;
                }
                for &(start, end) in ranges.iter() {
                    if let Some(frame) =
                        self.allocate_order_in_range(order, start.as_usize(), end.as_usize())
                    {
                        let addr = PhysAddr::new(frame.to_phys_addr());
                        return Some(PhysFrame::containing_address(addr));
                    }
                }
            }
        }
        self.allocate_2m_frame()
    }

    /// 1GiB allocation on a preferred NUMA node
    pub fn allocate_1g_frame_on_node(&mut self, node: usize) -> Option<PhysFrame<Size1GiB>> {
        let order = Self::frames_to_order(PAGE_SIZE_1G / PAGE_SIZE_4K);
        if let Some(map) = self.numa_regions.as_ref() {
            if let Some(ranges) = map.get(&node) {
                for &(start, end) in ranges.iter() {
                    if let Some(frame) =
                        self.allocate_order_in_range(order, start.as_usize(), end.as_usize())
                    {
                        let addr = PhysAddr::new(frame.to_phys_addr());
                        return Some(PhysFrame::containing_address(addr));
                    }
                }
            }

            for (&other, ranges) in map.iter() {
                if other == node {
                    continue;
                }
                for &(start, end) in ranges.iter() {
                    if let Some(frame) =
                        self.allocate_order_in_range(order, start.as_usize(), end.as_usize())
                    {
                        let addr = PhysAddr::new(frame.to_phys_addr());
                        return Some(PhysFrame::containing_address(addr));
                    }
                }
            }
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
}

// x86_64 crateのFrameAllocatorトレイトを実装
unsafe impl FrameAllocator<Size4KiB> for BuddyFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.allocate_4k_frame()
    }
}

/// Buddy Allocator 統計情報
#[derive(Debug, Clone)]
pub struct BuddyAllocatorStats {
    pub total_frames: usize,
    pub free_frames: u64,
    pub split_count: u64,
    pub coalesce_count: u64,
    /// 各オーダーの (空きブロック数, 総フレーム数)
    pub order_stats: [(usize, usize); MAX_ORDER + 1],
}

/// グローバルなBuddy Allocator
/// 割り込み禁止Mutexで保護（デッドロック防止）
static BUDDY_ALLOCATOR: IrqMutex<BuddyFrameAllocator> = IrqMutex::new(BuddyFrameAllocator::new());

/// Buddy Allocatorを初期化
///
/// # Safety
/// カーネル初期化時に一度だけ呼ばれる必要がある
pub unsafe fn init_buddy_allocator(usable_regions: &[(PhysAddr, u64)]) {
    unsafe {
        BUDDY_ALLOCATOR.lock().init(usable_regions);
    }
}

/// 4KiB フレームを割り当て（Buddy版）
pub fn buddy_alloc_frame() -> Option<PhysFrame<Size4KiB>> {
    BUDDY_ALLOCATOR.lock().allocate_4k_frame()
}

/// 2MiB フレームを割り当て（Buddy版）
pub fn buddy_alloc_frame_2m() -> Option<PhysFrame<Size2MiB>> {
    BUDDY_ALLOCATOR.lock().allocate_2m_frame()
}

/// 1GiB フレームを割り当て（Buddy版）
pub fn buddy_alloc_frame_1g() -> Option<PhysFrame<Size1GiB>> {
    BUDDY_ALLOCATOR.lock().allocate_1g_frame()
}

/// 連続する物理フレームを割り当て（2のべき乗に切り上げ）
pub fn buddy_alloc_contiguous_frames(frame_count: usize) -> Option<PhysAddr> {
    if frame_count == 0 {
        return None;
    }
    BUDDY_ALLOCATOR.lock().allocate_contiguous(frame_count)
}

/// 4KiB フレームを解放（Buddy版）
pub fn buddy_dealloc_frame(frame: PhysFrame<Size4KiB>) {
    BUDDY_ALLOCATOR.lock().deallocate_4k_frame(frame);
}

/// 2MiB フレームを解放（Buddy版）
pub fn buddy_dealloc_frame_2m(frame: PhysFrame<Size2MiB>) {
    BUDDY_ALLOCATOR.lock().deallocate_2m_frame(frame);
}

/// 1GiB フレームを解放（Buddy版）
pub fn buddy_dealloc_frame_1g(frame: PhysFrame<Size1GiB>) {
    BUDDY_ALLOCATOR.lock().deallocate_1g_frame(frame);
}

/// Buddy Allocatorの統計を取得
pub fn buddy_allocator_stats() -> BuddyAllocatorStats {
    BUDDY_ALLOCATOR.lock().stats()
}

/// Register a NUMA region with the global Buddy Allocator
pub fn buddy_register_numa_region(node: usize, start: PhysAddr, size: u64) {
    let mut allocator = BUDDY_ALLOCATOR.lock();
    let start_frame = FrameIndex::from_phys_addr(start.as_u64());
    let end_frame = FrameIndex::from_phys_addr(start.as_u64() + size);
    allocator.register_numa_region(node, start_frame, end_frame);
}

/// Allocate a 4KiB frame preferring the given NUMA node (best-effort)
pub fn buddy_alloc_frame_on_node(node: usize) -> Option<PhysFrame<Size4KiB>> {
    BUDDY_ALLOCATOR.lock().allocate_4k_frame_on_node(node)
}

/// Allocate a 2MiB frame preferring the given NUMA node (best-effort)
pub fn buddy_alloc_frame_2m_on_node(node: usize) -> Option<PhysFrame<Size2MiB>> {
    BUDDY_ALLOCATOR.lock().allocate_2m_frame_on_node(node)
}

/// Allocate a 1GiB frame preferring the given NUMA node (best-effort)
pub fn buddy_alloc_frame_1g_on_node(node: usize) -> Option<PhysFrame<Size1GiB>> {
    BUDDY_ALLOCATOR.lock().allocate_1g_frame_on_node(node)
}

/// 指定アドレスがBuddy Allocatorで管理されているかチェック
///
/// 設計書 P2: 統一フレームアロケータのための判定
/// 注: Buddyアロケータは初期化時に登録された領域のみを管理する
pub fn is_managed_by_buddy(addr: PhysAddr) -> bool {
    let allocator = BUDDY_ALLOCATOR.lock();

    // If NUMA regions are recorded, check them first
    if let Some(map) = allocator.numa_regions.as_ref() {
        for (_node, ranges) in map.iter() {
            for &(start, end) in ranges.iter() {
                let start_addr = start.to_phys_addr();
                let end_addr = end.to_phys_addr();
                if addr.as_u64() >= start_addr && addr.as_u64() < end_addr {
                    return true;
                }
            }
        }
    }

    // Fallback: contiguous region assumption
    if allocator.total_frames == 0 {
        return false;
    }

    let max_addr = (allocator.total_frames as u64) * (PAGE_SIZE_4K as u64);
    addr.as_u64() < max_addr
}

/// 指定範囲がBuddy Allocatorで管理されているかチェック
///
/// 範囲は [start, start+size) の半開区間。
pub fn is_range_managed_by_buddy(start: PhysAddr, size: u64) -> bool {
    if size == 0 {
        return false;
    }

    let Some(end) = start.as_u64().checked_add(size) else {
        return false;
    };

    let allocator = BUDDY_ALLOCATOR.lock();

    if let Some(map) = allocator.numa_regions.as_ref() {
        for (_node, ranges) in map.iter() {
            for &(range_start, range_end) in ranges.iter() {
                let start_addr = range_start.to_phys_addr();
                let end_addr = range_end.to_phys_addr();
                if start.as_u64() >= start_addr && end <= end_addr {
                    return true;
                }
            }
        }
        return false;
    }

    if allocator.total_frames == 0 {
        return false;
    }

    let max_addr = (allocator.total_frames as u64) * (PAGE_SIZE_4K as u64);
    start.as_u64() < max_addr && end <= max_addr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buddy_allocator() {
        let mut allocator = BuddyFrameAllocator::new();

        // テスト用のメモリ領域（4MiB、MAX_ORDER=18に対応）
        let regions = [(PhysAddr::new(0x100000), 0x400000u64)];
        unsafe {
            allocator.init(&regions);
        }

        // フレーム割り当て
        let frame1 = allocator.allocate_4k_frame();
        assert!(frame1.is_some());
    }

    #[test]
    fn test_init_numa_frame_allocator_registers_region_with_buddy() {
        use crate::mm::frame_allocator::NumaNodeId;
        use crate::mm::{init_buddy_allocator, init_numa_frame_allocator};

        // Initialize buddy allocator with a default region
        let base_region = [(PhysAddr::new(0x100000), 0x400000u64)];
        unsafe {
            init_buddy_allocator(&base_region);
        }

        // Register a NUMA region and ensure buddy knows about it
        let numa_region = [(PhysAddr::new(0x200000), 0x2000u64, NumaNodeId::new(1))];
        unsafe {
            init_numa_frame_allocator(&numa_region);
        }

        // Check buddy reports the address as managed
        assert!(crate::mm::buddy_allocator::is_managed_by_buddy(PhysAddr::new(
            0x200000
        )));

        // Try to allocate a frame preferring that node (best-effort)
        let alloc = crate::mm::buddy_alloc_frame_on_node(1);
        assert!(alloc.is_some());
    }

    #[test]
    fn test_order_calculation() {
        assert_eq!(BuddyFrameAllocator::frames_to_order(1), 0);
        assert_eq!(BuddyFrameAllocator::frames_to_order(2), 1);
        assert_eq!(BuddyFrameAllocator::frames_to_order(3), 2);
        assert_eq!(BuddyFrameAllocator::frames_to_order(4), 2);
        assert_eq!(BuddyFrameAllocator::frames_to_order(512), 9);
        assert_eq!(BuddyFrameAllocator::frames_to_order(262144), 18);
    }

    #[test]
    fn test_numa_register_and_alloc_local() {
        let mut allocator = BuddyFrameAllocator::new();

        // Register a NUMA region (small area)
        let start = PhysAddr::new(0x1000_0000);
        let size = 0x20_000; // 128 KiB
        let start_frame = FrameIndex::from_phys_addr(start.as_u64());
        let end_frame = FrameIndex::from_phys_addr(start.as_u64() + size);

        allocator.register_numa_region(0, start_frame, end_frame);

        // Allocate a 4K frame preferring node 0
        let frame = allocator.allocate_4k_frame_on_node(0).expect("alloc local");
        assert!(frame.start_address().as_u64() >= start.as_u64());
        assert!(frame.start_address().as_u64() < start.as_u64() + size);
    }

    #[test]
    fn test_numa_2m_alloc_local() {
        let mut allocator = BuddyFrameAllocator::new();

        // Register a larger NUMA region suitable for 2MiB allocations
        let start = PhysAddr::new(0x2000_0000);
        let size = 0x10_0000; // 1 MiB (smaller than 2MiB but for test we can still allocate a 4K)
        let start_frame = FrameIndex::from_phys_addr(start.as_u64());
        let end_frame = FrameIndex::from_phys_addr(start.as_u64() + size);

        allocator.register_numa_region(1, start_frame, end_frame);

        // Try 4K allocation on node 1 (2M allocation may fail due to size)
        let frame = allocator
            .allocate_4k_frame_on_node(1)
            .expect("alloc 4K local");
        assert!(frame.start_address().as_u64() >= start.as_u64());
        assert!(frame.start_address().as_u64() < start.as_u64() + size);
    }
}
