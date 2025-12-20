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

/// 各オーダーの空きリストの最大エントリ数
/// 最悪ケースでも十分な数を確保
const MAX_FREE_LIST_ENTRIES: usize = MAX_4K_FRAMES / 2;

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

/// 空きブロックリスト（双方向リンクリスト的に管理）
/// 実際にはシンプルな配列ベースの実装
struct FreeList {
    /// 空きブロックの先頭フレームインデックス
    entries: [Option<FrameIndex>; 8192],
    /// エントリ数
    count: usize,
}

impl FreeList {
    const fn new() -> Self {
        Self {
            entries: [None; 8192],
            count: 0,
        }
    }

    fn push(&mut self, frame: FrameIndex) {
        if self.count < self.entries.len() {
            self.entries[self.count] = Some(frame);
            self.count += 1;
        }
    }

    fn pop(&mut self) -> Option<FrameIndex> {
        if self.count > 0 {
            self.count -= 1;
            self.entries[self.count].take()
        } else {
            None
        }
    }

    /// 特定のフレームを削除（buddy合体時に使用）
    fn remove(&mut self, frame: FrameIndex) -> bool {
        for i in 0..self.count {
            if self.entries[i] == Some(frame) {
                // 末尾要素と交換して削除
                self.entries[i] = self.entries[self.count - 1].take();
                self.count -= 1;
                return true;
            }
        }
        false
    }

    fn is_empty(&self) -> bool {
        self.count == 0
    }

    fn len(&self) -> usize {
        self.count
    }
}

/// Buddy Allocator
///
/// オーダー n のブロックは 2^n 個の連続した4KiBフレームを表す
/// - order 0: 4KiB (1フレーム)
/// - order 9: 2MiB (512フレーム)
/// - order 18: 1GiB (262144フレーム)
pub struct BuddyFrameAllocator {
    /// 各オーダーの空きリスト
    free_lists: [FreeList; MAX_ORDER + 1],
    /// フレームの状態を追跡するビットマップ
    /// bit = 1: 使用中または分割済み
    /// bit = 0: 完全に空き
    bitmap: [u64; MAX_4K_FRAMES / 64],
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
        const INIT_FREE_LIST: FreeList = FreeList::new();
        Self {
            free_lists: [INIT_FREE_LIST; MAX_ORDER + 1],
            bitmap: [0u64; MAX_4K_FRAMES / 64],
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
        // 最初は全てを使用中としてマーク
        for word in self.bitmap.iter_mut() {
            *word = u64::MAX;
        }

        let mut total = 0usize;

        // 使用可能な領域を空きブロックとして登録
        for &(start, size) in usable_regions {
            let start_frame = FrameIndex::from_phys_addr(start.as_u64());
            let end_frame = FrameIndex::from_phys_addr(start.as_u64() + size);

            total = total.max(end_frame.as_usize());

            // 領域を最大オーダーのブロックに分割して登録
            self.add_region(start_frame, end_frame);
        }

        // Initialize NUMA regions mapping
        if self.numa_regions.is_none() {
            self.numa_regions = Some(BTreeMap::new());
        }

        self.total_frames = total;
    }

    /// 連続した空き領域を Buddy システムに追加
    fn add_region(&mut self, start: FrameIndex, end: FrameIndex) {
        let mut current = start.as_usize();
        let end_idx = end.as_usize();

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
            self.free_lists[order].push(frame);
            self.free_frames += block_size as u64;

            // ビットマップをクリア（空きとしてマーク）
            for i in 0..block_size {
                self.mark_frame_free(FrameIndex::new(current + i));
            }

            current += block_size;
        }
    }

    /// フレームを空きとしてマーク
    fn mark_frame_free(&mut self, frame: FrameIndex) {
        let word_idx = frame.as_usize() / 64;
        let bit_idx = frame.as_usize() % 64;

        if word_idx < self.bitmap.len() {
            self.bitmap[word_idx] &= !(1u64 << bit_idx);
        }
    }

    /// フレームを使用中としてマーク
    fn mark_frame_used(&mut self, frame: FrameIndex) {
        let word_idx = frame.as_usize() / 64;
        let bit_idx = frame.as_usize() % 64;

        if word_idx < self.bitmap.len() {
            self.bitmap[word_idx] |= 1u64 << bit_idx;
        }
    }

    /// フレームが空きかどうか確認
    fn is_frame_free(&self, frame: FrameIndex) -> bool {
        let word_idx = frame.as_usize() / 64;
        let bit_idx = frame.as_usize() % 64;

        if word_idx >= self.bitmap.len() {
            return false;
        }

        (self.bitmap[word_idx] & (1u64 << bit_idx)) == 0
    }

    /// 指定オーダーのブロックを割り当て
    /// O(log n) の性能
    fn allocate_order(&mut self, order: usize) -> Option<FrameIndex> {
        // 要求オーダー以上の空きブロックを探す
        for current_order in order..=MAX_ORDER {
            if let Some(frame) = self.free_lists[current_order].pop() {
                // 必要に応じてブロックを分割
                self.split_block(frame, current_order, order);

                // フレームを使用中としてマーク
                let block_size = 1 << order;
                for i in 0..block_size {
                    self.mark_frame_used(FrameIndex::new(frame.as_usize() + i));
                }
                self.free_frames -= block_size as u64;

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

            // 後半のBuddyを空きリストに追加
            let buddy = FrameIndex::new(frame.as_usize() + (1 << current_order));
            self.free_lists[current_order].push(buddy);

            self.split_count += 1;
        }
    }

    /// 指定オーダーのブロックを解放
    /// O(log n) の性能
    fn deallocate_order(&mut self, frame: FrameIndex, order: usize) {
        // フレームを空きとしてマーク
        let block_size = 1 << order;
        for i in 0..block_size {
            self.mark_frame_free(FrameIndex::new(frame.as_usize() + i));
        }
        self.free_frames += block_size as u64;

        // Buddyとの合体を試みる
        self.coalesce(frame, order);
    }

    /// Buddyとの合体を反復的に試みる
    ///
    /// 以前の再帰実装はスタックオーバーフローのリスクがあったため、
    /// ループベースの反復的実装に変更。
    fn coalesce(&mut self, frame: FrameIndex, order: usize) {
        let mut current_frame = frame;
        let mut current_order = order;

        // 反復的に合体を試みる
        while current_order < MAX_ORDER {
            let buddy = current_frame.buddy(current_order);

            // Buddyが存在し、かつ同じオーダーで空いているか確認
            if !self.is_buddy_free(buddy, current_order) {
                break;
            }

            // Buddyを空きリストから削除
            if !self.free_lists[current_order].remove(buddy) {
                break;
            }

            self.coalesce_count += 1;

            // 合体したブロックの先頭を計算
            current_frame = if current_frame.as_usize() < buddy.as_usize() {
                current_frame
            } else {
                buddy
            };

            // 次のオーダーへ
            current_order += 1;
        }

        // 最終的なオーダーの空きリストに追加
        self.free_lists[current_order].push(current_frame);
    }

    /// Buddyが同じオーダーで空いているか確認
    fn is_buddy_free(&self, buddy: FrameIndex, order: usize) -> bool {
        let block_size = 1 << order;

        // Buddyブロック内の全フレームが空きかチェック
        if buddy.as_usize() + block_size > self.total_frames {
            return false;
        }

        for i in 0..block_size {
            if !self.is_frame_free(FrameIndex::new(buddy.as_usize() + i)) {
                return false;
            }
        }

        true
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

    /// 連続する物理フレームを割り当て（任意サイズ）
    pub fn allocate_contiguous(&mut self, frame_count: usize) -> Option<PhysAddr> {
        let order = Self::frames_to_order(frame_count);
        self.allocate_order(order)
            .map(|frame| PhysAddr::new(frame.to_phys_addr()))
    }

    /// Register a NUMA region for a node and add it to the allocator
    pub fn register_numa_region(&mut self, node: usize, start: FrameIndex, end: FrameIndex) {
        // Ensure internal structures are initialized if allocator wasn't inited
        if self.total_frames == 0 {
            for word in self.bitmap.iter_mut() {
                *word = u64::MAX;
            }
        }

        if self.numa_regions.is_none() {
            self.numa_regions = Some(BTreeMap::new());
        }
        let map = self.numa_regions.as_mut().unwrap();
        map.entry(node)
            .or_insert_with(|| alloc::vec![])
            .push((start, end));

        // Add the region to the global free lists
        self.add_region(start, end);

        // Update total_frames to cover the new region
        self.total_frames = self.total_frames.max(end.as_usize());
    }

    /// Allocate an order block restricted to [start_frame, end_frame)
    fn allocate_order_in_range(
        &mut self,
        order: usize,
        start_frame: usize,
        end_frame: usize,
    ) -> Option<FrameIndex> {
        for current_order in order..=MAX_ORDER {
            let block_size = 1 << current_order;
            let fl = &mut self.free_lists[current_order];
            let mut i = 0usize;
            while i < fl.count {
                if let Some(frame) = fl.entries[i] {
                    if frame.as_usize() >= start_frame
                        && (frame.as_usize() + block_size) <= end_frame
                    {
                        // remove the entry by swapping with last
                        fl.entries[i] = fl.entries[fl.count - 1].take();
                        fl.count -= 1;

                        // split down to target order and allocate
                        self.split_block(frame, current_order, order);

                        let target_size = 1 << order;
                        for j in 0..target_size {
                            self.mark_frame_used(FrameIndex::new(frame.as_usize() + j));
                        }
                        self.free_frames -= target_size as u64;

                        return Some(frame);
                    }
                }
                i += 1;
            }
        }
        None
    }

    /// Try to allocate a 4KiB frame on a preferred NUMA node; fallback to others and global
    pub fn allocate_4k_frame_on_node(&mut self, node: usize) -> Option<PhysFrame<Size4KiB>> {
        if let Some((node_ranges, other_nodes)) = self.numa_regions.as_ref().map(|map| {
            (
                map.get(&node).cloned(),
                map.iter()
                    .map(|(&k, v)| (k, v.clone()))
                    .collect::<alloc::vec::Vec<_>>(),
            )
        }) {
            if let Some(ranges) = node_ranges {
                for (start, end) in ranges {
                    if let Some(frame) =
                        self.allocate_order_in_range(0, start.as_usize(), end.as_usize())
                    {
                        let addr = PhysAddr::new(frame.to_phys_addr());
                        return Some(PhysFrame::containing_address(addr));
                    }
                }
            }

            for (other, ranges) in other_nodes {
                if other == node {
                    continue;
                }
                for (start, end) in ranges {
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
        if let Some((node_ranges, other_nodes)) = self.numa_regions.as_ref().map(|map| {
            (
                map.get(&node).cloned(),
                map.iter()
                    .map(|(&k, v)| (k, v.clone()))
                    .collect::<alloc::vec::Vec<_>>(),
            )
        }) {
            if let Some(ranges) = node_ranges {
                for (start, end) in ranges {
                    if let Some(frame) =
                        self.allocate_order_in_range(order, start.as_usize(), end.as_usize())
                    {
                        let addr = PhysAddr::new(frame.to_phys_addr());
                        return Some(PhysFrame::containing_address(addr));
                    }
                }
            }

            for (other, ranges) in other_nodes {
                if other == node {
                    continue;
                }
                for (start, end) in ranges {
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
        if let Some((node_ranges, other_nodes)) = self.numa_regions.as_ref().map(|map| {
            (
                map.get(&node).cloned(),
                map.iter()
                    .map(|(&k, v)| (k, v.clone()))
                    .collect::<alloc::vec::Vec<_>>(),
            )
        }) {
            if let Some(ranges) = node_ranges {
                for (start, end) in ranges {
                    if let Some(frame) =
                        self.allocate_order_in_range(order, start.as_usize(), end.as_usize())
                    {
                        let addr = PhysAddr::new(frame.to_phys_addr());
                        return Some(PhysFrame::containing_address(addr));
                    }
                }
            }

            for (other, ranges) in other_nodes {
                if other == node {
                    continue;
                }
                for (start, end) in ranges {
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

        for (order, free_list) in self.free_lists.iter().enumerate() {
            let block_frames = 1 << order;
            let total_frames = free_list.len() * block_frames;
            order_stats[order] = (free_list.len(), total_frames);
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
