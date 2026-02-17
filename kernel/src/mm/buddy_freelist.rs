// ============================================================================
// src/mm/buddy_freelist.rs - Linked List based Buddy Allocator
//
// 改善点:
// 1. ビットマップからフリーリスト（双方向連結リスト）への移行
//    - 割り当て/解放が完全なO(1)に
//    - ビットスキャンのループが不要
//
// 2. ページモビリティ（Migrate Types）による断片化防止
//    - Unmovable: カーネルデータ構造（移動不可）
//    - Movable: ユーザー空間ページ（PTE書き換えで移動可能）
//    - Reclaimable: キャッシュ（破棄可能）
//    - 同一2MBブロック内は同じタイプのみ割り当て
//
// 3. ページカラーリング（Cache Coloring）
//    - L2/L3キャッシュセット競合の回避
//    - 色ごとのフリーリストで均等分散
//
// ## Atomic Ordering 設計ノート
//
// PageDescriptor と FreeArea のフィールドに AtomicU64/AtomicUsize を使用している。
// 現在の LockedFreeListBuddyAllocator は IrqMutex で全操作を保護しており、
// これらの atomic 操作はロック配下では冗長である。
//
// しかし、以下の理由で atomic を保持する:
// - 将来の Per-CPU Magazine 統合時にロックフリー list_pop_head を可能にする
// - refcount/mapcount はページテーブルウォーカー等がロック外から読む可能性がある
// - FreeArea.nr_free は統計クエリでロック外参照される可能性がある
//
// ロックフリー化を行わない場合は、next/prev/head/tail を plain u64 に変更し、
// refcount/mapcount のみ AtomicU64 を維持することを推奨。
// ============================================================================
#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use alloc::vec::Vec;
use crate::sync::IrqMutex;
use x86_64::PhysAddr;
use x86_64::structures::paging::{FrameAllocator, PhysFrame, Size1GiB, Size2MiB, Size4KiB};

use super::types::{FrameIndex, PAGE_SIZE_4K, PAGE_SIZE_2M, PAGE_SIZE_1G};

/// 最大オーダー（2^MAX_ORDER * 4KiB = 1GiB）
pub const MAX_ORDER: usize = 18;

/// ページモビリティタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MigrateType {
    /// カーネルデータ等、物理アドレス固定が必要
    Unmovable = 0,
    /// ユーザーページ、ページテーブル書き換えで移動可能
    Movable = 1,
    /// inode/dentryキャッシュ等、破棄可能
    Reclaimable = 2,
    /// ハイアトミック予約（割り込みコンテキスト用）
    HighAtomic = 3,
}

impl MigrateType {
    pub const COUNT: usize = 4;
    
    /// フォールバック順序: 要求タイプで見つからない時の代替
    pub fn fallback_order(self) -> &'static [MigrateType] {
        match self {
            MigrateType::Unmovable => &[
                MigrateType::Reclaimable,
                MigrateType::Movable,
            ],
            MigrateType::Movable => &[
                MigrateType::Reclaimable,
                MigrateType::Unmovable,
            ],
            MigrateType::Reclaimable => &[
                MigrateType::Unmovable,
                MigrateType::Movable,
            ],
            MigrateType::HighAtomic => &[
                MigrateType::Unmovable,
                MigrateType::Reclaimable,
                MigrateType::Movable,
            ],
        }
    }
}

impl Default for MigrateType {
    fn default() -> Self {
        MigrateType::Movable
    }
}

// ============================================================================
// ページ構造体（フリーリストノード埋め込み）
// ============================================================================

/// ページ構造体
/// 
/// Linux kernel の `struct page` に相当。
/// 空きページの場合、物理メモリ上のページ自体にリンクポインタを埋め込む。
/// これにより追加のメモリ割り当てなしでフリーリストを構築できる。
#[repr(C)]
pub struct PageDescriptor {
    /// フリーリストの次ノード（物理フレームインデックス、u32::MAXで終端）
    pub next: AtomicU64,
    /// フリーリストの前ノード（物理フレームインデックス、u32::MAXで終端）
    pub prev: AtomicU64,
    /// このページが属するオーダー（空きブロックの場合のみ有効）
    pub order: u8,
    /// モビリティタイプ
    pub migrate_type: MigrateType,
    /// ページフラグ
    pub flags: PageFlags,
    /// 参照カウント
    pub refcount: AtomicU64,
    /// マッピングカウント（何個のPTEから参照されているか）
    pub mapcount: AtomicU64,
    /// キャッシュカラー（0..NUM_COLORS-1）
    pub color: u8,
    _padding: [u8; 5],
}

/// ページフラグ
#[derive(Debug, Clone, Copy, Default)]
#[repr(transparent)]
pub struct PageFlags(u32);

impl PageFlags {
    pub const NONE: Self = Self(0);
    pub const FREE: Self = Self(1 << 0);
    pub const ZEROED: Self = Self(1 << 1);
    pub const COMPOUND_HEAD: Self = Self(1 << 2);
    pub const COMPOUND_TAIL: Self = Self(1 << 3);
    pub const DIRTY: Self = Self(1 << 4);
    pub const LRU: Self = Self(1 << 5);
    pub const LOCKED: Self = Self(1 << 6);
    pub const SLAB: Self = Self(1 << 7);
    
    #[inline]
    pub fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) != 0
    }
    
    #[inline]
    pub fn insert(&mut self, flag: Self) {
        self.0 |= flag.0;
    }
    
    #[inline]
    pub fn remove(&mut self, flag: Self) {
        self.0 &= !flag.0;
    }
}

const LIST_END: u64 = u64::MAX;

impl PageDescriptor {
    pub const fn new() -> Self {
        Self {
            next: AtomicU64::new(LIST_END),
            prev: AtomicU64::new(LIST_END),
            order: 0,
            migrate_type: MigrateType::Movable,
            flags: PageFlags::NONE,
            refcount: AtomicU64::new(0),
            mapcount: AtomicU64::new(0),
            color: 0,
            _padding: [0; 5],
        }
    }
    
    #[inline]
    pub fn is_free(&self) -> bool {
        self.flags.contains(PageFlags::FREE)
    }
    
    #[inline]
    pub fn is_zeroed(&self) -> bool {
        self.flags.contains(PageFlags::ZEROED)
    }
}

// ============================================================================
// フリーエリア（オーダーごとのフリーリスト）
// ============================================================================

/// フリーエリア
/// 
/// 各オーダー・各モビリティタイプごとに双方向連結リストを保持。
/// head/tailは物理フレームインデックスを格納（LIST_END = 空）。
#[repr(C)]
pub struct FreeArea {
    /// リストの先頭フレームインデックス
    head: AtomicU64,
    /// リストの末尾フレームインデックス
    tail: AtomicU64,
    /// 空きブロック数
    nr_free: AtomicUsize,
}

impl FreeArea {
    pub const fn new() -> Self {
        Self {
            head: AtomicU64::new(LIST_END),
            tail: AtomicU64::new(LIST_END),
            nr_free: AtomicUsize::new(0),
        }
    }
    
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Acquire) == LIST_END
    }
    
    #[inline]
    pub fn count(&self) -> usize {
        self.nr_free.load(Ordering::Relaxed)
    }
}

// ============================================================================
// キャッシュカラーリング
// ============================================================================

/// キャッシュカラー数（典型的なL3キャッシュ構成に基づく）
/// 
/// 計算例: 8MB L3キャッシュ、64Bラインサイズ、16-way連想
/// セット数 = 8MB / (64B * 16) = 8192 セット
/// 4KB ページでは 4KB / 64B = 64 ライン
/// カラー数 = 8192 / 64 = 128
/// 
/// 実用上は32〜128程度で十分な効果が得られる
pub const NUM_CACHE_COLORS: usize = 64;

/// フレームインデックスからキャッシュカラーを計算
#[inline]
pub fn frame_to_color(frame_idx: usize) -> u8 {
    // 物理アドレスの下位ビットからカラーを決定
    // ページサイズ(4KB)でシフトした後、カラー数でマスク
    (frame_idx % NUM_CACHE_COLORS) as u8
}

// ============================================================================
// フリーリストベース Buddy Allocator
// ============================================================================

/// フリーリストベースのBuddy Allocator
/// 
/// ## 主な改善点
/// 
/// 1. **O(1) 割り当て/解放**: ビットスキャン不要
/// 2. **ページモビリティ**: 断片化防止、THP成功率向上
/// 3. **キャッシュカラーリング**: L2/L3競合回避
pub struct FreeListBuddyAllocator {
    /// [モビリティタイプ][オーダー] のフリーエリア
    free_areas: [[FreeArea; MAX_ORDER + 1]; MigrateType::COUNT],
    
    /// ページ記述子配列（mem_map相当）
    /// 物理フレームインデックス → PageDescriptor
    page_descriptors: Option<&'static mut [PageDescriptor]>,
    
    /// 総フレーム数
    total_frames: usize,
    
    /// 空きフレーム数（4KiB換算）
    free_frames: AtomicU64,
    
    /// 統計: 分割回数
    split_count: AtomicU64,
    
    /// 統計: 結合回数  
    coalesce_count: AtomicU64,
    
    /// 統計: モビリティタイプごとの割り当て数
    migrate_allocs: [AtomicU64; MigrateType::COUNT],
    
    /// 統計: フォールバック回数
    fallback_count: AtomicU64,
    
    /// カラーごとの空きフレーム数（カラーリング統計用）
    color_free_counts: [AtomicUsize; NUM_CACHE_COLORS],
    
    /// 2MBブロックのモビリティタイプ追跡
    /// インデックス = 物理フレーム / 512 (2MB境界)
    /// 値 = そのブロック内で支配的なMigrateType
    pageblock_flags: Option<Vec<MigrateType>>,
}

/// 2MBページブロックに含まれる4KBフレーム数
const PAGES_PER_PAGEBLOCK: usize = PAGE_SIZE_2M / PAGE_SIZE_4K; // 512

impl FreeListBuddyAllocator {
    /// 新しいアロケータを作成（未初期化状態）
    pub const fn new() -> Self {
        Self {
            free_areas: [
                [const { FreeArea::new() }; MAX_ORDER + 1],
                [const { FreeArea::new() }; MAX_ORDER + 1],
                [const { FreeArea::new() }; MAX_ORDER + 1],
                [const { FreeArea::new() }; MAX_ORDER + 1],
            ],
            page_descriptors: None,
            total_frames: 0,
            free_frames: AtomicU64::new(0),
            split_count: AtomicU64::new(0),
            coalesce_count: AtomicU64::new(0),
            migrate_allocs: [const { AtomicU64::new(0) }; MigrateType::COUNT],
            fallback_count: AtomicU64::new(0),
            color_free_counts: [const { AtomicUsize::new(0) }; NUM_CACHE_COLORS],
            pageblock_flags: None,
        }
    }
    
    /// ページ記述子配列を設定
    /// 
    /// # Safety
    /// 
    /// - `descriptors` は有効なメモリ領域を指す必要がある
    /// - 領域は `total_frames` 個の `PageDescriptor` を格納できるサイズ
    pub unsafe fn set_page_descriptors(
        &mut self,
        descriptors: &'static mut [PageDescriptor],
        total_frames: usize,
    ) {
        self.page_descriptors = Some(descriptors);
        self.total_frames = total_frames;
        
        // pageblock_flags を初期化
        let num_pageblocks = (total_frames + PAGES_PER_PAGEBLOCK - 1) / PAGES_PER_PAGEBLOCK;
        self.pageblock_flags = Some(alloc::vec![MigrateType::Movable; num_pageblocks]);
    }
    
    /// ページ記述子を取得
    #[inline]
    fn get_page(&self, frame_idx: usize) -> Option<&PageDescriptor> {
        self.page_descriptors.as_ref()?.get(frame_idx)
    }
    
    /// ページ記述子を取得（可変）
    #[inline]
    fn get_page_mut(&mut self, frame_idx: usize) -> Option<&mut PageDescriptor> {
        self.page_descriptors.as_mut()?.get_mut(frame_idx)
    }
    
    /// 2MBページブロックのモビリティタイプを取得
    #[inline]
    pub fn get_pageblock_migratetype(&self, frame_idx: usize) -> MigrateType {
        let block_idx = frame_idx / PAGES_PER_PAGEBLOCK;
        self.pageblock_flags
            .as_ref()
            .and_then(|flags| flags.get(block_idx).copied())
            .unwrap_or(MigrateType::Movable)
    }
    
    /// 2MBページブロックのモビリティタイプを設定
    #[inline]
    pub fn set_pageblock_migratetype(&mut self, frame_idx: usize, mt: MigrateType) {
        let block_idx = frame_idx / PAGES_PER_PAGEBLOCK;
        if let Some(flags) = self.pageblock_flags.as_mut() {
            if let Some(flag) = flags.get_mut(block_idx) {
                *flag = mt;
            }
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
    fn set_pageblocks_mt_for_range(
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
        while f < end {
            self.set_pageblock_migratetype(f, mt);
            f += PAGES_PER_PAGEBLOCK;
        }
    }

    // ========================================================================
    // フリーリスト操作
    // ========================================================================
    
    /// フリーリストの先頭にブロックを追加
    fn list_add_head(
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
        self.free_areas[mt][order].head.store(frame_idx as u64, Ordering::Release);
        
        if old_head != LIST_END {
            // 旧ヘッドのprevを更新
            if let Some(old_page) = self.get_page_mut(old_head as usize) {
                old_page.prev.store(frame_idx as u64, Ordering::Release);
            }
        } else {
            // リストが空だった場合、tailも更新
            self.free_areas[mt][order].tail.store(frame_idx as u64, Ordering::Release);
        }
        
        self.free_areas[mt][order].nr_free.fetch_add(1, Ordering::Relaxed);
        
        // カラー統計を更新
        let color = frame_to_color(frame_idx);
        self.color_free_counts[color as usize].fetch_add(1 << order, Ordering::Relaxed);
    }
    
    /// フリーリストからブロックを削除
    fn list_del(
        &mut self,
        frame_idx: usize,
        order: usize,
        migrate_type: MigrateType,
    ) {
        // デバッグ: 削除するページがFREEであることを確認
        debug_assert!(
            self.get_page(frame_idx).map(|p| p.is_free()).unwrap_or(false),
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
            self.free_areas[mt][order].head.store(next_idx, Ordering::Release);
        }
        
        // 次のノードを更新
        if next_idx != LIST_END {
            if let Some(next_page) = self.get_page_mut(next_idx as usize) {
                next_page.prev.store(prev_idx, Ordering::Release);
            }
        } else {
            // これがテールだった
            self.free_areas[mt][order].tail.store(prev_idx, Ordering::Release);
        }
        
        // ページ記述子をクリア
        if let Some(page) = self.get_page_mut(frame_idx) {
            page.flags.remove(PageFlags::FREE);
            page.next.store(LIST_END, Ordering::Release);
            page.prev.store(LIST_END, Ordering::Release);
        }
        
        self.free_areas[mt][order].nr_free.fetch_sub(1, Ordering::Relaxed);
        
        // カラー統計を更新
        let color = frame_to_color(frame_idx);
        self.color_free_counts[color as usize].fetch_sub(1 << order, Ordering::Relaxed);
    }
    
    /// フリーリストの先頭からブロックを取り出す（O(1)）
    fn list_pop_head(
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
    fn move_freepages_block(
        &mut self,
        start_frame: usize,
        end_frame: usize,
        new_mt: MigrateType,
    ) -> usize {
        let mut moved_count = 0;
        let mut curr = start_frame;
        
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
    pub fn allocate(
        &mut self,
        order: usize,
        migrate_type: MigrateType,
    ) -> Option<FrameIndex> {
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
                    // （Linuxの claim_alloc / steal_suitable_fallback 相当）
                    
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
    fn try_allocate_internal(
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
    fn split_block(
        &mut self,
        frame: FrameIndex,
        from_order: usize,
        to_order: usize,
        migrate_type: MigrateType,
    ) {
        let mut current_order = from_order;
        
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
    pub fn deallocate(&mut self, frame: FrameIndex, order: usize) {
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
    fn free_one_page(
        &mut self,
        frame_idx: usize,
        order: usize,
        migrate_type: MigrateType,
    ) {
        let mut current_frame = frame_idx;
        let mut current_order = order;

        // 反復的にBuddyとの結合を試みる
        while current_order < MAX_ORDER {
            let buddy_idx = current_frame ^ (1 << current_order);

            // Buddyが存在し空いているか確認
            let buddy_free = self.get_page(buddy_idx)
                .map(|p| p.is_free() && p.order == current_order as u8)
                .unwrap_or(false);

            if !buddy_free {
                break;
            }

            // Buddyをフリーリストから削除
            let buddy_mt = self.get_page(buddy_idx)
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
    pub fn allocate_with_color(
        &mut self,
        order: usize,
        migrate_type: MigrateType,
        preferred_color: u8,
    ) -> Option<FrameIndex> {
        if order > MAX_ORDER {
            return None;
        }

        let mt = migrate_type as usize;

        // 要求オーダー以上の空きブロックを走査し、カラー一致を探す
        for current_order in order..=MAX_ORDER {
            let mut current = self.free_areas[mt][current_order].head.load(Ordering::Acquire);
            // サイクル検出: nr_free + 1 で打ち切り（リスト破損時の無限ループ防止）
            let max_walk = self.free_areas[mt][current_order].count() + 1;
            let mut walked = 0usize;

            while current != LIST_END && walked < max_walk {
                let frame_idx = current as usize;
                let actual_color = frame_to_color(frame_idx);

                if actual_color == preferred_color {
                    // カラー一致 — リストから除去して分割
                    self.list_del(frame_idx, current_order, migrate_type);
                    let frame = FrameIndex::new(frame_idx);
                    self.split_block(frame, current_order, order, migrate_type);
                    let block_size = 1u64 << order;
                    self.free_frames.fetch_sub(block_size, Ordering::Relaxed);
                    return Some(frame);
                }

                // 次のノードへ
                current = self.get_page(frame_idx)
                    .map(|p| p.next.load(Ordering::Acquire))
                    .unwrap_or(LIST_END);
                walked += 1;
            }
        }

        // カラー一致なし — 通常割り当てにフォールバック
        self.allocate(order, migrate_type)
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

    // ========================================================================
    // 初期化
    // ========================================================================

    /// メモリマップに基づいてアロケータを初期化
    ///
    /// PageDescriptor配列をヒープに割り当て、使用可能な領域を
    /// フリーリストに登録する。トップダウンアルゴリズムで
    /// 各領域から最大アライメントのブロックを直接登録。
    ///
    /// # Safety
    ///
    /// - `usable_regions` は正しい使用可能メモリ領域を示す必要がある
    /// - カーネル初期化時に一度だけ呼ばれること
    pub unsafe fn init(&mut self, usable_regions: &[(PhysAddr, u64)]) {
        // 1. 総フレーム数を計算
        let mut max_frame: usize = 0;
        for &(start, size) in usable_regions {
            let end = start.as_u64() + size;
            let end_frame = (end as usize) / PAGE_SIZE_4K;
            max_frame = max_frame.max(end_frame);
        }

        if max_frame == 0 {
            return;
        }

        self.total_frames = max_frame;

        // PageDescriptor配列のメモリ使用量を報告
        let descriptor_bytes = max_frame * core::mem::size_of::<PageDescriptor>();
        log::info!(
            "[buddy_freelist] init: {} frames, PageDescriptor array = {} bytes ({} MB)",
            max_frame,
            descriptor_bytes,
            descriptor_bytes / (1024 * 1024),
        );

        // 2. PageDescriptor配列をヒープに割り当て（leak で 'static に）
        let mut descriptors_vec = Vec::with_capacity(max_frame);
        for _ in 0..max_frame {
            descriptors_vec.push(PageDescriptor::new());
        }
        let descriptors_slice = descriptors_vec.leak();
        self.page_descriptors = Some(descriptors_slice);

        // 3. pageblock_flags を初期化
        let num_pageblocks = (max_frame + PAGES_PER_PAGEBLOCK - 1) / PAGES_PER_PAGEBLOCK;
        self.pageblock_flags = Some(alloc::vec![MigrateType::Movable; num_pageblocks]);

        // 4. 空きフレームをゼロリセット
        self.free_frames.store(0, Ordering::Relaxed);

        // 5. 各領域をフリーリストに登録（トップダウン: 最大ブロック優先）
        for &(start, size) in usable_regions {
            let start_frame = (start.as_u64() as usize) / PAGE_SIZE_4K;
            let end_frame = ((start.as_u64() + size) as usize) / PAGE_SIZE_4K;

            self.add_free_region(start_frame, end_frame);
        }
    }

    /// 空き領域をフリーリストに追加（トップダウンアルゴリズム）
    ///
    /// 各フレームに対して、そのアライメントで可能な最大オーダーの
    /// ブロックとして追加する。Linuxの`memblock_free_all`相当。
    fn add_free_region(&mut self, start_frame: usize, end_frame: usize) {
        let mut current = start_frame;

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
            self.free_frames.fetch_add(block_size as u64, Ordering::Relaxed);

            current += block_size;
        }
    }

    // ========================================================================
    // PhysFrame ベースの割り当て/解放 API
    // ========================================================================

    /// 必要フレーム数から適切なオーダーを計算
    fn frames_to_order(frames: usize) -> usize {
        if frames <= 1 {
            return 0;
        }
        (usize::BITS - (frames - 1).leading_zeros()) as usize
    }

    /// 4KiB フレームを1つ割り当て
    pub fn allocate_4k_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.allocate(0, MigrateType::default()).map(|frame| {
            let addr = PhysAddr::new(frame.to_phys_addr());
            PhysFrame::containing_address(addr)
        })
    }

    /// 2MiB フレームを割り当て（order 9）
    pub fn allocate_2m_frame(&mut self) -> Option<PhysFrame<Size2MiB>> {
        let order = Self::frames_to_order(PAGE_SIZE_2M / PAGE_SIZE_4K);
        self.allocate(order, MigrateType::Movable).map(|frame| {
            let addr = PhysAddr::new(frame.to_phys_addr());
            PhysFrame::containing_address(addr)
        })
    }

    /// 1GiB フレームを割り当て（order 18）
    pub fn allocate_1g_frame(&mut self) -> Option<PhysFrame<Size1GiB>> {
        let order = Self::frames_to_order(PAGE_SIZE_1G / PAGE_SIZE_4K);
        self.allocate(order, MigrateType::Movable).map(|frame| {
            let addr = PhysAddr::new(frame.to_phys_addr());
            PhysFrame::containing_address(addr)
        })
    }

    /// 4KiB フレームを解放
    pub fn deallocate_4k_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        let frame_idx = FrameIndex::from_phys_addr(frame.start_address().as_u64());
        self.deallocate(frame_idx, 0);
    }

    /// 2MiB フレームを解放
    pub fn deallocate_2m_frame(&mut self, frame: PhysFrame<Size2MiB>) {
        let frame_idx = FrameIndex::from_phys_addr(frame.start_address().as_u64());
        let order = Self::frames_to_order(PAGE_SIZE_2M / PAGE_SIZE_4K);
        self.deallocate(frame_idx, order);
    }

    /// 1GiB フレームを解放
    pub fn deallocate_1g_frame(&mut self, frame: PhysFrame<Size1GiB>) {
        let frame_idx = FrameIndex::from_phys_addr(frame.start_address().as_u64());
        let order = Self::frames_to_order(PAGE_SIZE_1G / PAGE_SIZE_4K);
        self.deallocate(frame_idx, order);
    }

    /// 連続する物理フレームを割り当て（2のべき乗に切り上げ）
    pub fn allocate_contiguous(&mut self, frame_count: usize) -> Option<PhysAddr> {
        let order = Self::frames_to_order(frame_count);
        if order > MAX_ORDER {
            return None;
        }
        self.allocate(order, MigrateType::default())
            .map(|frame| PhysAddr::new(frame.to_phys_addr()))
    }

    // ========================================================================
    // 詳細統計
    // ========================================================================

    /// 詳細な統計情報を収集
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

/// FreeListBuddy統計情報
#[derive(Debug, Clone, Copy)]
pub struct FreeListBuddyStats {
    pub total_frames: usize,
    pub free_frames: u64,
    pub split_count: u64,
    pub coalesce_count: u64,
    pub fallback_count: u64,
    /// 各オーダーの (空きブロック数, 総フレーム数)
    pub order_stats: [(usize, usize); MAX_ORDER + 1],
    /// モビリティタイプ別の割り当て数
    pub migrate_stats: [u64; MigrateType::COUNT],
}

// x86_64 crateのFrameAllocatorトレイトを実装
unsafe impl FrameAllocator<Size4KiB> for FreeListBuddyAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.allocate_4k_frame()
    }
}

// ============================================================================
// ページ割り当てフラグ（GFP相当）
// ============================================================================

/// ページ割り当てフラグ
#[derive(Debug, Clone, Copy)]
pub struct AllocFlags(u32);

impl AllocFlags {
    /// 通常のカーネル割り当て（Unmovable）
    pub const KERNEL: Self = Self(0);
    /// ユーザー空間用（Movable）
    pub const USER: Self = Self(1 << 0);
    /// ハイメモリ許可
    pub const HIGHMEM: Self = Self(1 << 1);
    /// DMA用（低メモリ必須）
    pub const DMA: Self = Self(1 << 2);
    /// ゼロクリア済みを要求
    pub const ZERO: Self = Self(1 << 3);
    /// 待機可能（スリープ許可）
    pub const WAIT: Self = Self(1 << 4);
    /// 高優先度（予約から借用可）
    pub const HIGH: Self = Self(1 << 5);
    /// Reclaimable
    pub const RECLAIMABLE: Self = Self(1 << 6);
    
    #[inline]
    pub fn migrate_type(self) -> MigrateType {
        if self.0 & Self::USER.0 != 0 {
            MigrateType::Movable
        } else if self.0 & Self::RECLAIMABLE.0 != 0 {
            MigrateType::Reclaimable
        } else if self.0 & Self::HIGH.0 != 0 {
            MigrateType::HighAtomic
        } else {
            MigrateType::Unmovable
        }
    }
}

// ============================================================================
// QEMU smoke tests
// ============================================================================

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests;

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests;

// ============================================================================
// ロック付きラッパー
// ============================================================================

/// スピンロック（割り込み禁止）で保護されたBuddy Allocator
/// 
/// `FreeListBuddyAllocator` は内部可変性を持たない（`&mut self`を要求する）ため、
/// マルチコア環境で共有するにはロックが必要。
/// カーネルアロケータとして使用する場合、割り込みコンテキストからの呼び出しも
/// 考慮して `IrqMutex` を使用する。
pub struct LockedFreeListBuddyAllocator(IrqMutex<FreeListBuddyAllocator>);

impl LockedFreeListBuddyAllocator {
    /// 新しいロック付きアロケータを作成
    pub const fn new() -> Self {
        Self(IrqMutex::new(FreeListBuddyAllocator::new()))
    }

    /// メモリマップに基づいて初期化
    ///
    /// # Safety
    /// - `usable_regions` は正しい使用可能メモリ領域を示す必要がある
    /// - カーネル初期化時に一度だけ呼ばれること
    pub unsafe fn init_from_regions(&self, usable_regions: &[(PhysAddr, u64)]) {
        unsafe { self.0.lock().init(usable_regions); }
    }

    /// ページ記述子配列を設定（初期化）
    ///
    /// # Safety
    /// `FreeListBuddyAllocator::set_page_descriptors` を参照
    pub unsafe fn init(
        &self,
        descriptors: &'static mut [PageDescriptor],
        total_frames: usize,
    ) {
        self.0.lock().set_page_descriptors(descriptors, total_frames);
    }

    /// フレームを割り当て
    pub fn allocate(
        &self,
        order: usize,
        migrate_type: MigrateType,
    ) -> Option<FrameIndex> {
        self.0.lock().allocate(order, migrate_type)
    }

    /// フレームを解放
    pub fn deallocate(&self, frame: FrameIndex, order: usize) {
        self.0.lock().deallocate(frame, order)
    }

    /// カラーリング対応割り当て
    pub fn allocate_with_color(
        &self,
        order: usize,
        migrate_type: MigrateType,
        preferred_color: u8,
    ) -> Option<FrameIndex> {
        self.0.lock().allocate_with_color(order, migrate_type, preferred_color)
    }

    /// 4KiBフレームを割り当て
    pub fn allocate_4k_frame(&self) -> Option<PhysFrame<Size4KiB>> {
        self.0.lock().allocate_4k_frame()
    }

    /// 2MiBフレームを割り当て
    pub fn allocate_2m_frame(&self) -> Option<PhysFrame<Size2MiB>> {
        self.0.lock().allocate_2m_frame()
    }

    /// 1GiBフレームを割り当て
    pub fn allocate_1g_frame(&self) -> Option<PhysFrame<Size1GiB>> {
        self.0.lock().allocate_1g_frame()
    }

    /// 4KiBフレームを解放
    pub fn deallocate_4k_frame(&self, frame: PhysFrame<Size4KiB>) {
        self.0.lock().deallocate_4k_frame(frame);
    }

    /// 2MiBフレームを解放
    pub fn deallocate_2m_frame(&self, frame: PhysFrame<Size2MiB>) {
        self.0.lock().deallocate_2m_frame(frame);
    }

    /// 1GiBフレームを解放
    pub fn deallocate_1g_frame(&self, frame: PhysFrame<Size1GiB>) {
        self.0.lock().deallocate_1g_frame(frame);
    }

    /// 統計: 空きフレーム数
    pub fn free_count(&self) -> u64 {
        self.0.lock().free_count()
    }

    /// 統計: 総フレーム数
    pub fn total_count(&self) -> usize {
        self.0.lock().total_count()
    }

    /// 詳細統計情報を取得
    pub fn stats(&self) -> FreeListBuddyStats {
        self.0.lock().stats()
    }
}

// ============================================================================
// グローバルインスタンスとモジュールレベルAPI
// ============================================================================

/// グローバルなFreeListBuddy Allocator
static FREELIST_BUDDY: LockedFreeListBuddyAllocator = LockedFreeListBuddyAllocator::new();

/// FreeListBuddy Allocatorを初期化
///
/// # Safety
/// - `usable_regions` は正しい使用可能メモリ領域を示すこと
/// - カーネル初期化時に一度だけ呼ばれること
pub unsafe fn init_freelist_buddy(usable_regions: &[(PhysAddr, u64)]) {
    unsafe { FREELIST_BUDDY.init_from_regions(usable_regions); }
}

/// 4KiBフレームを割り当て
pub fn freelist_alloc_frame() -> Option<PhysFrame<Size4KiB>> {
    FREELIST_BUDDY.allocate_4k_frame()
}

/// 2MiBフレームを割り当て
pub fn freelist_alloc_frame_2m() -> Option<PhysFrame<Size2MiB>> {
    FREELIST_BUDDY.allocate_2m_frame()
}

/// 1GiBフレームを割り当て
pub fn freelist_alloc_frame_1g() -> Option<PhysFrame<Size1GiB>> {
    FREELIST_BUDDY.allocate_1g_frame()
}

/// 4KiBフレームを解放
pub fn freelist_dealloc_frame(frame: PhysFrame<Size4KiB>) {
    FREELIST_BUDDY.deallocate_4k_frame(frame);
}

/// 2MiBフレームを解放
pub fn freelist_dealloc_frame_2m(frame: PhysFrame<Size2MiB>) {
    FREELIST_BUDDY.deallocate_2m_frame(frame);
}

/// 1GiBフレームを解放
pub fn freelist_dealloc_frame_1g(frame: PhysFrame<Size1GiB>) {
    FREELIST_BUDDY.deallocate_1g_frame(frame);
}

/// 統計情報を取得
pub fn freelist_buddy_stats() -> FreeListBuddyStats {
    FREELIST_BUDDY.stats()
}
