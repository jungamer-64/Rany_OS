// ============================================================================
// src/mm/slab_cache.rs - Per-Core Slab Cache
// 設計書 5.2 Tier3: コアローカルな高速割り当て
// LinuxのSLUBアロケータに類似。各コアごとに独立したロックで動作し、False Sharingを防ぐ
//
// ## Partial Slab分離
//
// Slabページを3つの状態で管理:
// - Full: 全オブジェクト使用中 → 割り当て不可
// - Partial: 一部使用中 → 優先的に割り当て
// - Empty: 全オブジェクト空き → PMM返却候補
//
// Partial優先によりフラグメンテーションを削減し、
// メモリ使用効率を向上させる。
// ============================================================================
use crate::sync::PoisonLock;
use core::alloc::Layout;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::mm::cache::slab_registry::{SlabCacheRegistry, SlabFlags};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

// リモートフリー用の型定義
use crate::mm::remote_free::RemoteFreeRing;

/// Slab内のオブジェクトサイズクラス（2のべき乗）
mod magazine_layer;
pub use magazine_layer::*;
mod cache_impl;
pub const SLAB_SIZES: [usize; 8] = [8, 16, 32, 64, 128, 256, 512, 1024];

/// 1つのSlabページのサイズ
const SLAB_PAGE_SIZE: usize = 4096;

/// キャッシュラインサイズ（False Sharing防止）
const CACHE_LINE_SIZE: usize = 64;

/// バルクリフィルの初期ページ数
const INITIAL_REFILL_PAGES: usize = 4;

/// バルクリフィルの最小ページ数
const MIN_REFILL_PAGES: usize = 2;

/// バルクリフィルの最大ページ数
const MAX_REFILL_PAGES: usize = 32;

/// リフィル数を増加させるアロケーション閾値
/// この回数のアロケーションごとにリフィル数を倍増
const REFILL_SCALE_UP_THRESHOLD: usize = 256;

/// リフィル数を減少させる空き比率閾値
/// 空きオブジェクト数がページ容量の75%を超えたらリフィル数を半減
const REFILL_SCALE_DOWN_RATIO: usize = 75;

/// Slab Coloringの最大カラー数
/// キャッシュラインサイズ単位でローテーション
/// 4KB / 64B = 64 だが、オブジェクト用のスペースを確保するため小さめに
const MAX_SLAB_COLORS: usize = 8;

/// リモートフリーリングの容量（ロックフリークロスCPU解放用）
/// 各CPUコアが他CPUから解放要求を受け取るためのリング
const SLAB_REMOTE_FREE_CAPACITY: usize = 256;

// ============================================================================
// Partial Slab 分離 (Full/Partial/Empty 3状態管理)
// ============================================================================

/// Slabページの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SlabPageState {
    /// 全オブジェクト空き（PMM返却候補）
    Empty = 0,
    /// 一部使用中（優先的に割り当て）
    Partial = 1,
    /// 全オブジェクト使用中（割り当て不可）
    Full = 2,
}

/// On-Slab Metadata Header
///
/// Placed at the beginning of every Slab Page.
/// This allows O(1) lookup of metadata from any object pointer within the page
/// by masking the lower bits of the address (assuming aligned pages).
#[repr(C)]
pub struct SlabPageHeader {
    /// Pointer to the SlabCache that owns this page
    /// Used for validation and accounting
    pub slab_cache: NonNull<SlabCache>,

    /// Index of the first free object (freelist head)
    /// Non-None value means there are free objects.
    pub next_free: Option<u16>,

    /// Number of objects in use
    pub inuse: u16,

    /// Total number of objects in this page
    pub total_objects: u16,

    /// Slab Coloring offset
    pub color_offset: u16,

    /// Current state of the page
    /// Used to track which list (partial/full) this page belongs to
    pub state: SlabPageState,

    /// Links for Partial/Full lists (intrusive linked list)
    pub prev: Option<NonNull<SlabPageHeader>>,
    pub next: Option<NonNull<SlabPageHeader>>,
}

// Ensure header fits within reasonable bounds (e.g., less than object size if possible,
// but for small objects it will consume some space).
// For 4KB pages, header is small enough.

impl SlabPageHeader {
    /// Initialize a new Slab Page Header
    ///
    /// # Safety
    /// `page_ptr` must be a valid pointer to the start of a mapped page.
    pub unsafe fn init(
        page_ptr: NonNull<u8>,
        slab_cache: NonNull<SlabCache>,
        total_objects: u16,
        color_offset: u16,
    ) -> NonNull<Self> {
        let header_ptr = page_ptr.cast::<Self>();
        let header = &mut *header_ptr.as_ptr();

        header.slab_cache = slab_cache;
        header.next_free = Some(0); // Initial freelist head is index 0
        header.inuse = 0;
        header.total_objects = total_objects;
        header.color_offset = color_offset;
        header.state = SlabPageState::Empty;
        header.prev = None;
        header.next = None;

        // Initialize the freelist indices in the objects themselves?
        // Or strictly implicit?
        //
        // Strategy: Implicit linked list of indices embedded in free objects.
        // Each free object contains the index (u16) of the next free object.
        //
        // IMPORTANT: We need minimum object size >= sizeof(u16).
        // Since MIN_ALIGN is usually 8 or more, this is fine.

        Self::init_freelist(page_ptr, total_objects, color_offset, unsafe {
            (*slab_cache.as_ptr()).object_size
        });

        header_ptr
    }

    /// Initialize the embedded freelist in the objects
    unsafe fn init_freelist(
        page_ptr: NonNull<u8>,
        count: u16,
        color_offset: u16,
        object_size: usize,
    ) {
        let base_ptr = page_ptr.as_ptr().add(Self::payload_offset(color_offset));

        for i in 0..count {
            let obj_ptr = base_ptr.add(i as usize * object_size);
            // The next free index is i + 1, unless it's the last one
            let next_idx = if i < count - 1 { Some(i + 1) } else { None };

            // Store next_idx in the object
            // Ensure object is large enough for u16 (it is, checked in SlabCache::new)
            *(obj_ptr as *mut Option<u16>) = next_idx;
        }
    }

    /// Calculate offset to the first object (after header + color)
    #[inline]
    pub(crate) fn payload_offset(color_offset: u16) -> usize {
        let header_size = core::mem::size_of::<Self>();
        let aligned_header = (header_size + 15) & !15; // 16-byte align
        aligned_header + color_offset as usize
    }

    /// Allocate an object from this page
    /// Returns raw pointer to object
    pub unsafe fn allocate(&mut self, object_size: usize) -> Option<NonNull<u8>> {
        let free_idx = self.next_free?;

        // Calculate address of the object
        let base_ptr = (self as *mut Self as *mut u8).add(Self::payload_offset(self.color_offset));
        let obj_ptr = base_ptr.add(free_idx as usize * object_size);

        // Read the next free index from the object itself
        let next_free = *(obj_ptr as *const Option<u16>);

        // Update header
        self.next_free = next_free;
        self.inuse += 1;

        // Update state logic is handled by caller (SlabCache) or here?
        // Let's do simple state tracking here, list capabilities in caller

        Some(NonNull::new_unchecked(obj_ptr))
    }

    /// Free an object to this page
    pub unsafe fn free(&mut self, ptr: NonNull<u8>, object_size: usize) {
        // Calculate index
        let base_ptr = (self as *mut Self as *mut u8).add(Self::payload_offset(self.color_offset));
        let offset = ptr.as_ptr().offset_from(base_ptr) as usize;
        let index = (offset / object_size) as u16;

        debug_assert_eq!(offset % object_size, 0, "Unaligned free ptr");

        // Push to freelist
        *(ptr.as_ptr() as *mut Option<u16>) = self.next_free;
        self.next_free = Some(index);

        self.inuse -= 1;
    }

    /// Check if full
    pub fn is_full(&self) -> bool {
        self.inuse == self.total_objects
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.inuse == 0
    }
}

/// Trait for migrating objects during compaction (defrag)
pub trait ObjectMigrator: Send + Sync + core::fmt::Debug {
    /// Migrate object from `src` to `dst`.
    ///
    /// # Safety
    /// Caller guarantees src and dst are valid pointers of correct size.
    /// Implementor must copy data and update references.
    /// Returns true if successful. If false, migration is aborted.
    unsafe fn migrate(&self, src: NonNull<u8>, dst: NonNull<u8>) -> bool;
}

/// 1つのサイズクラス用のSlabキャッシュ
///
/// ## Partial Slab分離 (Refactored)
///
/// 内部では`current_page`と`partial_list`でページを管理:
/// - `current_page`: 割り当て用のアクティブなページ
/// - `partial_list`: 部分的に空きがあるページのリスト（スタック）
/// - `full_pages`: 全オブジェクト使用中のページ（リスト管理せずカウントのみ）
///
/// 割り当て順序: current_page → partial_list → 新規ページ確保
#[derive(Debug)]
pub struct SlabCache {
    /// オブジェクトサイズ
    object_size: usize,

    /// 現在のアクティブページ（高速パス）
    current_page: Option<NonNull<SlabPageHeader>>,

    /// Partial状態のページリスト（スタックとして使用）
    partial_list: Option<NonNull<SlabPageHeader>>,

    /// Empty状態のページリスト（キャッシュ、最大数あり）
    empty_list: Option<NonNull<SlabPageHeader>>,

    /// 統計: Empty状態のページ数
    empty_page_count: usize,
    /// 統計: Partial状態のページ数
    partial_page_count: usize,
    /// 統計: Full状態のページ数
    full_page_count: usize,

    /// 統計: 割り当て回数
    alloc_count: usize,
    /// 統計: 解放回数
    dealloc_count: usize,

    /// 動的リフィルページ数（Adaptive Bulk Refill）
    refill_pages: usize,
    /// 前回リフィル数調整時のアロケーション数
    last_scale_alloc_count: usize,

    /// NUMA node ID for this Slab
    numa_node: Option<u8>,

    /// Optional: Migrator for compaction
    migrator: Option<Box<dyn ObjectMigrator>>,
}
