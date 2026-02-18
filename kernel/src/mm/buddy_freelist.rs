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
mod stats_and_flags;
pub use stats_and_flags::*;
mod allocator_core;
pub use allocator_core::*;
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
