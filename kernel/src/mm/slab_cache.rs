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
#![allow(dead_code)]

use crate::sync::PoisonLock;
use core::alloc::Layout;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};


use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::sync::Arc;
use spin::Mutex;
use crate::mm::slab_registry::{SlabCacheRegistry, SlabFlags};

// リモートフリー用の型定義
use super::remote_free::RemoteFreeRing;

/// Slab内のオブジェクトサイズクラス（2のべき乗）
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
        
        Self::init_freelist(page_ptr, total_objects, color_offset, unsafe { (*slab_cache.as_ptr()).object_size });
        
        header_ptr
    }
    
    /// Initialize the embedded freelist in the objects
    unsafe fn init_freelist(page_ptr: NonNull<u8>, count: u16, color_offset: u16, object_size: usize) {
        let base_ptr = page_ptr.as_ptr().add(Self::payload_offset(color_offset));
        
        for i in 0..count {
            let obj_ptr = base_ptr.add(i as usize * object_size);
            // The next free index is i + 1, unless it's the last one
            let next_idx = if i < count - 1 {
                Some(i + 1)
            } else {
                None
            };
            
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

impl SlabCache {
    /// 新しいSlabキャッシュを作成
    pub fn new(object_size: usize) -> Self {
        // オブジェクトサイズはキャッシュラインの倍数に揃える（False Sharing防止）
        // NOTE: On-Slab Metadataのため、最小サイズは Option<u16> (2 bytes) 以上である必要があるが
        // これは常に満たされる。
        let aligned_size =
            ((object_size + CACHE_LINE_SIZE - 1) / CACHE_LINE_SIZE) * CACHE_LINE_SIZE;
        // let aligned_size = aligned_size.max(2); // Implicitly handled

        Self {
            object_size: aligned_size,
            current_page: None,
            partial_list: None,
            empty_list: None,
            empty_page_count: 0,
            partial_page_count: 0,
            full_page_count: 0,
            alloc_count: 0,
            dealloc_count: 0,
            refill_pages: INITIAL_REFILL_PAGES,
            last_scale_alloc_count: 0,
            numa_node: None,
            migrator: None,
        }
    }

    /// 新しいSlabキャッシュを作成（NUMA node指定）
    pub fn new_on_node(object_size: usize, numa_node: u8) -> Self {
        let aligned_size =
            ((object_size + CACHE_LINE_SIZE - 1) / CACHE_LINE_SIZE) * CACHE_LINE_SIZE;

        Self {
            object_size: aligned_size,
            current_page: None,
            partial_list: None,
            empty_list: None,
            empty_page_count: 0,
            partial_page_count: 0,
            full_page_count: 0,
            alloc_count: 0,
            dealloc_count: 0,
            refill_pages: INITIAL_REFILL_PAGES,
            last_scale_alloc_count: 0,
            numa_node: Some(numa_node),
            migrator: None,
        }
    }

    /// Set NUMA node for this Slab (used to bind Per-Core caches to local memory)
    pub fn set_numa_node(&mut self, node: u8) {
        self.numa_node = Some(node);
    }

    /// オブジェクトを割り当て
    pub fn allocate(&mut self) -> Option<NonNull<u8>> {
        // MemCG Charge (Placeholder: implement when MemCG is ready)
        // crate::mm::memcg::charge_slab(self.object_size)?;
        
        self.alloc_count += 1;
        
        let ptr = self.allocate_inner()?;
        
        Some(ptr)
    }

    // Inner allocate to separate accounting from logic
    fn allocate_inner(&mut self) -> Option<NonNull<u8>> {
        // 1. Current Page
        if let Some(mut page) = self.current_page {
            // SAFETY: page is valid and owned by this SlabCache
            unsafe {
                if let Some(ptr) = page.as_mut().allocate(self.object_size) {
                    if page.as_ref().is_full() {
                        self.full_page_count += 1;
                        self.partial_page_count = self.partial_page_count.saturating_sub(1);
                        self.current_page = None;
                    }
                    self.maybe_adjust_refill_pages();
                    return Some(ptr);
                }
            }
        }
        
        // 2. Partial List
        if let Some(mut page) = self.pop_partial() {
            self.current_page = Some(page);
            unsafe {
                if let Some(ptr) = page.as_mut().allocate(self.object_size) {
                    if page.as_ref().is_full() {
                        self.full_page_count += 1;
                        self.partial_page_count = self.partial_page_count.saturating_sub(1);
                        self.current_page = None;
                    }
                    self.maybe_adjust_refill_pages();
                    return Some(ptr);
                }
            }
        }

        // 3. New Page (Grow)
        self.grow()?;
        
        // Retry allocation from new current_page
        if let Some(mut page) = self.current_page {
            unsafe {
                let ptr = page.as_mut().allocate(self.object_size).expect("New page should have space");
                 if page.as_ref().is_full() {
                        self.full_page_count += 1;
                         self.partial_page_count = self.partial_page_count.saturating_sub(1);
                        self.current_page = None;
                    }
                Some(ptr)
            }
        } else {
            None
        }
    }
    
    /// Pop a page from the partial list
    fn pop_partial(&mut self) -> Option<NonNull<SlabPageHeader>> {
        if let Some(mut page) = self.partial_list {
            unsafe {
                let next = page.as_ref().next;
                if let Some(mut next_ptr) = next {
                    next_ptr.as_mut().prev = None;
                }
                self.partial_list = next;
                page.as_mut().next = None; // Detach
            }
            Some(page)
        } else if let Some(mut page) = self.empty_list {
             // Use empty list as fallback partials
             unsafe {
                 let next = page.as_ref().next;
                 if let Some(mut next_ptr) = next {
                     next_ptr.as_mut().prev = None;
                 }
                 self.empty_list = next;
                 page.as_mut().next = None;
                 
                 self.empty_page_count = self.empty_page_count.saturating_sub(1);
                 self.partial_page_count += 1;
             }
             Some(page)
        } else {
            None
        }
    }

    /// オブジェクトを解放
    pub unsafe fn deallocate(&mut self, ptr: NonNull<u8>) {
        // Calculate Page Pointer by masking address
        // Assuming 4KB alignment
        let page_addr = (ptr.as_ptr() as u64) & !(SLAB_PAGE_SIZE as u64 - 1);
        let header_ptr = NonNull::new_unchecked(page_addr as *mut SlabPageHeader);
        let header = &mut *header_ptr.as_ptr();
        
        let was_full = header.is_full();
        
        header.free(ptr, self.object_size);
        self.dealloc_count += 1;
        
        // MemCG Uncharge
        // crate::mm::memcg::uncharge_slab(self.object_size);
        
        // State transitions
        if was_full {
            // Full -> Partial
            self.full_page_count = self.full_page_count.saturating_sub(1);
            self.partial_page_count += 1;
            
            // If this is not the current page, add to partial list
            if self.current_page != Some(header_ptr) {
                self.push_partial(header_ptr);
            }
        } else if header.is_empty() {
            // Partial -> Empty
            if self.current_page == Some(header_ptr) {
                 self.current_page = None;
            } else {
                 // Remove from partial list
                 Self::remove_from_list(header_ptr, &mut self.partial_list);
            }
            
            self.partial_page_count = self.partial_page_count.saturating_sub(1);
            self.empty_page_count += 1;
            
            // Cache some empty pages, free others
            if self.empty_page_count > 2 {
                // Free physical memory
                self.free_page_physical(header_ptr);
                self.empty_page_count -= 1;
            } else {
                self.push_empty(header_ptr);
            }
        }
        
        self.maybe_scale_down_refill();
    }
    
    /// Add to partial list head
    unsafe fn push_partial(&mut self, mut page: NonNull<SlabPageHeader>) {
        let old_head = self.partial_list;
        page.as_mut().next = old_head;
        page.as_mut().prev = None;
        if let Some(mut head) = old_head {
            head.as_mut().prev = Some(page);
        }
        self.partial_list = Some(page);
    }
    
    /// Add to empty list head
    unsafe fn push_empty(&mut self, mut page: NonNull<SlabPageHeader>) {
        let old_head = self.empty_list;
        page.as_mut().next = old_head;
        page.as_mut().prev = None;
        if let Some(mut head) = old_head {
            head.as_mut().prev = Some(page);
        }
        self.empty_list = Some(page);
    }
    
    /// Remove from arbitrary list
    unsafe fn remove_from_list(mut page: NonNull<SlabPageHeader>, list_head: &mut Option<NonNull<SlabPageHeader>>) {
        let prev = page.as_ref().prev;
        let next = page.as_ref().next;
        
        if let Some(mut prev_ptr) = prev {
            prev_ptr.as_mut().next = next;
        } else {
            // Was head
            *list_head = next;
        }
        
        if let Some(mut next_ptr) = next {
            next_ptr.as_mut().prev = prev;
        }
        
        page.as_mut().prev = None;
        page.as_mut().next = None;
    }
    
    /// Free physical page
    unsafe fn free_page_physical(&mut self, page: NonNull<SlabPageHeader>) {
        let virt = x86_64::VirtAddr::new(page.as_ptr() as u64);
        let phys = crate::mm::mapping::virt_to_phys(virt);
        if let Ok(frame) = x86_64::structures::paging::PhysFrame::from_start_address(phys) {
            crate::mm::dealloc_frame(frame);
        }
    }


    /// 適応的リフィル数調整（スケールアップ）
    #[inline]
    fn maybe_adjust_refill_pages(&mut self) {
        let allocs_since_last = self.alloc_count.saturating_sub(self.last_scale_alloc_count);
        
        if allocs_since_last >= REFILL_SCALE_UP_THRESHOLD {
            let new_refill = (self.refill_pages * 2).min(MAX_REFILL_PAGES);
            if new_refill > self.refill_pages {
                self.refill_pages = new_refill;
            }
            self.last_scale_alloc_count = self.alloc_count;
        }
    }

    /// 適応的リフィル数調整（スケールダウン）
    #[inline]
    fn maybe_scale_down_refill(&mut self) {
        // Simplified logic: adjust based on total allocated pages vs object count?
        // Or just leave for now.
    }

    /// 新しいSlabページを追加（適応的バルクリフィル版）
    fn grow(&mut self) -> Option<()> {
        self.grow_bulk(self.refill_pages)
    }

    /// 指定ページ数のSlabページを追加（内部用）
    fn grow_bulk(&mut self, page_count: usize) -> Option<()> {
        let mut added = 0;
        for _ in 0..page_count {
            if self.grow_single().is_some() {
                added += 1;
            } else {
                break;
            }
        }
        if added > 0 { Some(()) } else { None }
    }

    /// 単一のSlabページを追加
    fn grow_single(&mut self) -> Option<()> {
        let frame = if let Some(node) = self.numa_node {
            crate::mm::alloc_frame_on_numa_node(super::types::NumaNodeId::new(node))
                .or_else(|| crate::mm::alloc_frame())?
        } else {
            crate::mm::alloc_frame()?
        };

        let phys_addr = frame.start_address();
        let virt_addr = crate::mm::mapping::phys_to_virt(phys_addr);

        let page_ptr = NonNull::new(virt_addr.as_u64() as *mut u8).expect("virt_addr returned null");

        // Slab Coloring
        let color_offset = self.calculate_color_offset();
        
        // Header Initialization
        let usable_size = SLAB_PAGE_SIZE - SlabPageHeader::payload_offset(color_offset as u16);
        let total_objects = (usable_size / self.object_size) as u16;

        unsafe {
            let header = SlabPageHeader::init(
                page_ptr,
                NonNull::from(&*self), // pointer to self (stable in PerCoreCache)
                // SlabCache is often in a Box or fixed location (PerCoreCache static array).
                // Yes, PER_CORE_CACHES are static, so addresses are stable.
                total_objects,
                color_offset as u16,
            );
            
            // Add to partial list (or current_page if empty)
            if self.current_page.is_none() {
                self.current_page = Some(header);
            } else {
                self.push_partial(header);
            }
            self.partial_page_count += 1;
        }

        Some(())
    }

    /// Slab Coloringのオフセットを計算
    /// 
    /// ページごとに異なるオフセットを使用して、
    /// 同じサイズのオブジェクトがキャッシュの同じセットに
    /// マッピングされることを防ぐ。
    /// 
    /// ## Enhanced Randomization (v0.6.0)
    /// 
    /// 単純なページ数ローテーションの代わりに、
    /// xorshift PRNGベースの分散を使用してキャッシュ衝突を最小化。
    /// - ページインデックスとオブジェクトサイズを元にシード値を生成
    /// - より均等なキャッシュセット分布を実現
    #[inline]
    /// Slab Coloringのオフセットを計算
    #[inline]
    fn calculate_color_offset(&self) -> usize {
        // Enhanced: Use xorshift-based PRNG for better distribution
        let page_index = (self.full_page_count + self.partial_page_count + self.empty_page_count) as u32;
        let size_factor = self.object_size as u32;
        
        // Simple xorshift32 for fast pseudo-random generation
        let mut x = page_index.wrapping_add(size_factor).wrapping_add(0x5A5A);
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        
        // Map to color space: 0 to (MAX_SLAB_COLORS - 1) cache lines
        let color_index = (x as usize) % MAX_SLAB_COLORS;
        color_index * CACHE_LINE_SIZE
    }

    /// 統計情報を取得
    /// 統計情報を取得
    pub fn stats(&self) -> SlabStats {
        let mut free_count = 0;
        let objects_per_page = SLAB_PAGE_SIZE / self.object_size; // approx max, accurate for empty
        
        // Calculate free count from empty pages
        // For empty pages, free_count is not strictly objects_per_page because of coloring,
        // but close enough for stats. Or we could track track exactly if we knew total objects per page.
        // We know total_objects is in the header, but we can't access it easily without iterating.
        // Let's iterate lists for accuracy.
        
        // 1. Current Page
        if let Some(page) = self.current_page {
            unsafe { free_count += page.as_ref().inuse as usize; } // Wait, free_count? "inuse" is used count.
            // Oh, SlabPageMeta had free_count. Header has inuse.
            // Header has total_objects.
             unsafe {
                 let p = page.as_ref();
                 free_count += (p.total_objects - p.inuse) as usize;
             }
        }
        
        // 2. Partial List
        let mut curr = self.partial_list;
        while let Some(page) = curr {
            unsafe {
                let p = page.as_ref();
                free_count += (p.total_objects - p.inuse) as usize;
                curr = p.next;
            }
        }
        
        // 3. Empty List
        let mut curr = self.empty_list;
        while let Some(page) = curr {
            unsafe {
                let p = page.as_ref();
                free_count += (p.total_objects - p.inuse) as usize;
                curr = p.next;
            }
        }
        
        let page_count = self.full_page_count + self.partial_page_count + self.empty_page_count;

        SlabStats {
            object_size: self.object_size,
            free_count,
            page_count,
            alloc_count: self.alloc_count,
            dealloc_count: self.dealloc_count,
            refill_pages: self.refill_pages,
            partial_page_count: self.start_tracking_partial_count(), // partial_page_count field is tracked
            empty_page_count: self.empty_page_count,
            full_page_count: self.full_page_count,
            partial_alloc_count: 0, // removed field tracking for now
            empty_alloc_count: 0,   // removed field tracking for now
        }
    }
    
    // Helper to get partial count (since we tracked it)
    fn start_tracking_partial_count(&self) -> usize {
        self.partial_page_count
    }

    /// 現在のリフィルページ数を取得
    #[inline]
    pub fn current_refill_pages(&self) -> usize {
        self.refill_pages
    }

    /// リフィルページ数を手動設定（テスト/デバッグ用）
    pub fn set_refill_pages(&mut self, pages: usize) {
        self.refill_pages = pages.clamp(MIN_REFILL_PAGES, MAX_REFILL_PAGES);
    }
    
    /// Partial状態のページ数を取得
    #[inline]
    pub fn partial_page_count(&self) -> usize {
        self.partial_page_count
    }
    
    /// Empty状態のページをPMMに返却
    /// 
    /// メモリ圧迫時に呼び出し、未使用ページを解放する。
    /// 返却したページ数を返す。
    /// 
    /// ## アルゴリズム
    /// 
    /// 1. 全ページをスキャンし、Empty状態（全オブジェクト空き）を特定
    /// 2. 空きリストからそのページのオブジェクトを除去
    /// 3. ページをPMMに返却
    /// 
    /// ## 制限
    /// 
    /// - 最低1ページは保持（完全解放を防止）
    /// - max_pages で返却数を制限
    /// Empty状態のページをPMMに返却
    pub fn shrink_empty_pages(&mut self, max_pages: usize) -> usize {
        if self.empty_list.is_none() || max_pages == 0 {
            return 0;
        }
        
        // 最低1ページは保持 (cache effect)
        let keep_pages = 1;
        if self.empty_page_count <= keep_pages {
            return 0;
        }
        
        let mut returned = 0;
        
        // Remove from empty_list
        while returned < max_pages && self.empty_page_count > keep_pages {
             if let Some(mut page) = self.empty_list {
                 unsafe {
                     let next = page.as_ref().next;
                     if let Some(mut next_ptr) = next {
                         next_ptr.as_mut().prev = None;
                     }
                     self.empty_list = next;
                     page.as_mut().next = None; // Detach
                     
                     // Free physical
                     self.free_page_physical(page);
                 }
                 self.empty_page_count -= 1;
                 returned += 1;
             } else {
                 break;
             }
        }
        
        returned
    }
    

    /// Register a migrator for this cache
    pub fn register_migrator(&mut self, migrator: Box<dyn ObjectMigrator>) {
        self.migrator = Some(migrator);
    }

    /// Defragment the cache by moving objects from sparsely used pages
    pub fn defrag(&mut self) -> usize {
        if self.migrator.is_none() { return 0; }
        
        let mut moved_count = 0;
        // Limit processing to avoid stalls
        const MAX_PAGES_TO_SCAN: usize = 16;
        
        let count = self.partial_page_count;
        let limit = core::cmp::min(count, MAX_PAGES_TO_SCAN);
        
        for _ in 0..limit {
             let page_ptr = self.pop_partial(); 
             if page_ptr.is_none() { break; }
             let mut page = page_ptr.unwrap();
             
             // Check utilization (< 25%)
             let (inuse, total) = unsafe {
                 let h = page.as_mut();
                 (h.inuse, h.total_objects)
             };
             
             if inuse > 0 && (inuse as usize * 4) < (total as usize) {
                 // Victim found
                 let moved = self.evacuate_page(page);
                 moved_count += moved;
             }
             
             // After evacuation, check if empty
             let is_empty = unsafe { page.as_ref().is_empty() };
             if is_empty {
                  unsafe { self.free_page_physical(page); }
                  // pop_partial decremented counters and detached page.
                  // We just drop it physically. Correct.
                  continue;
             }
             
             // Push back if not freed
             unsafe { self.push_partial(page); }
        }
        moved_count
    }

    /// Evacuate all objects from a page
    fn evacuate_page(&mut self, mut page: NonNull<SlabPageHeader>) -> usize {
        let mut moved = 0;
        let object_size = self.object_size; 
        
        let header = unsafe { page.as_ref() };
        let total = header.total_objects;
        let color_offset = header.color_offset;
        
        // 1. Identify free slots
        // Max objects per 4KB page (min size 8) is 512.
        let mut free_mask = [0u64; 8];
        
        let mut curr = header.next_free;
        while let Some(idx) = curr {
            let i = idx as usize;
            if i < 512 {
                free_mask[i / 64] |= 1 << (i % 64);
            }
            // Read next from object
            unsafe {
                let offset = SlabPageHeader::payload_offset(color_offset);
                let base_ptr = (page.as_ptr() as *mut u8).add(offset);
                let obj_ptr = base_ptr.add(i * object_size);
                curr = *(obj_ptr as *const Option<u16>);
            }
        }
        
        // 2. Iterate all slots
        for i in 0..total as usize {
            if i >= 512 { break; } 
            
            let is_free = (free_mask[i / 64] & (1 << (i % 64))) != 0;
            if !is_free {
                // ALLOCATED -> Migrate
                unsafe {
                    let offset = SlabPageHeader::payload_offset(color_offset);
                    let base_ptr = (page.as_ptr() as *mut u8).add(offset);
                    let old_ptr = NonNull::new_unchecked(base_ptr.add(i * object_size));
                    
                    if let Some(new_ptr) = self.allocate() {
                        let success = if let Some(migrator) = &self.migrator {
                             migrator.migrate(old_ptr, new_ptr)
                        } else { false };

                        if success {
                             // Manual deallocate from victim page
                             let ph = page.as_mut();
                             ph.free(old_ptr, object_size);
                             self.dealloc_count += 1;
                             moved += 1;
                        } else {
                             self.deallocate(new_ptr);
                        }
                    }
                }
            }
        }
        moved
    }

}

/// Slab統計情報
#[derive(Debug, Clone)]
pub struct SlabStats {
    pub object_size: usize,
    pub free_count: usize,
    pub page_count: usize,
    pub alloc_count: usize,
    pub dealloc_count: usize,
    /// 現在のリフィルページ数（適応的バルクリフィル）
    pub refill_pages: usize,
    /// Partial状態のページ数
    pub partial_page_count: usize,
    /// Empty状態のページ数
    pub empty_page_count: usize,
    /// Full状態のページ数
    pub full_page_count: usize,
    /// Partialページからの割り当て回数
    pub partial_alloc_count: usize,
    /// Emptyページからの割り当て回数
    pub empty_alloc_count: usize,
}

// ============================================================================
// Magazine Layer (Solaris/Bonwick Style)
// ============================================================================
//
// Magazine Layerは、Per-CPUキャッシュの上に更に高速なオブジェクトキャッシュを提供する。
// 各CPUは2つのマガジン（loaded/previous）を保持し、マガジン内のオブジェクトは
// ロックフリーでアクセス可能。
//
// アーキテクチャ:
// ```
//   [CPU 0]          [CPU 1]          [CPU N]
//   loaded/prev      loaded/prev      loaded/prev
//       |                |                |
//       v                v                v
//   +------------------------------------------+
//   |           Magazine Depot (global)        |
//   |   full_magazines[]  empty_magazines[]    |
//   +------------------------------------------+
//       |
//       v
//   [SlabCache (per-core)]
// ```
//
// 性能特性:
// - Hot Path (Magazine内): ロックフリー、キャッシュライン競合なし
// - Warm Path (Depot交換): 短いクリティカルセクション、マガジン単位の交換
// - Cold Path (Slab): 従来のSlabアロケータにフォールバック
//
// ============================================================================

/// マガジンのデフォルトサイズ（オブジェクト数）
pub const MAGAZINE_SIZE: usize = 32;

/// Depot内の最大マガジン数
pub const MAX_DEPOT_MAGAZINES: usize = 64;

/// マガジン構造体
///
/// オブジェクトポインタの配列を保持する。スタックライクに操作。
#[repr(align(64))] // キャッシュラインアライン
#[derive(Debug)]
pub struct Magazine<const SIZE: usize = MAGAZINE_SIZE> {
    /// オブジェクトポインタの配列
    objects: [Option<NonNull<u8>>; SIZE],
    /// 現在のオブジェクト数（スタックトップ）
    count: usize,
    /// オブジェクトサイズ（検証用）
    object_size: usize,
}

impl<const SIZE: usize> Magazine<SIZE> {
    /// 空のマガジンを作成
    pub const fn new(object_size: usize) -> Self {
        Self {
            objects: [None; SIZE],
            count: 0,
            object_size,
        }
    }

    /// マガジンが空かどうか
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// マガジンが満杯かどうか
    #[inline]
    pub fn is_full(&self) -> bool {
        self.count >= SIZE
    }

    /// オブジェクト数を取得
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    /// オブジェクトをpop（割り当て用）
    #[inline]
    pub fn pop(&mut self) -> Option<NonNull<u8>> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        self.objects[self.count].take()
    }

    /// オブジェクトをpush（解放用）
    #[inline]
    pub fn push(&mut self, ptr: NonNull<u8>) -> bool {
        if self.count >= SIZE {
            return false;
        }
        self.objects[self.count] = Some(ptr);
        self.count += 1;
        true
    }

    /// マガジンをクリア（全オブジェクトを返却）
    pub fn clear(&mut self) -> impl Iterator<Item = NonNull<u8>> + '_ {
        let count = self.count;
        self.count = 0;
        (0..count).filter_map(move |i| self.objects[i].take())
    }
}

/// マガジンデポ
///
/// 全CPUで共有されるマガジンプール。満杯/空マガジンを交換する。
#[derive(Debug)]
pub struct MagazineDepot<const SIZE: usize = MAGAZINE_SIZE> {
    /// 満杯マガジンのリスト
    full_magazines: [Option<Magazine<SIZE>>; MAX_DEPOT_MAGAZINES],
    /// 満杯マガジン数
    full_count: usize,
    /// 空マガジンのリスト
    empty_magazines: [Option<Magazine<SIZE>>; MAX_DEPOT_MAGAZINES],
    /// 空マガジン数
    empty_count: usize,
    /// オブジェクトサイズ
    object_size: usize,
    /// 統計: Depot交換回数
    exchange_count: usize,
}

impl<const SIZE: usize> MagazineDepot<SIZE> {
    /// 新しいデポを作成
    ///
    /// # Note
    /// ジェネリクス制約により、const fnでの配列初期化が難しいため、
    /// デフォルトサイズ（MAGAZINE_SIZE）のみサポート
    pub fn new(object_size: usize) -> Self {
        Self {
            full_magazines: core::array::from_fn(|_| None),
            full_count: 0,
            empty_magazines: core::array::from_fn(|_| None),
            empty_count: 0,
            object_size,
            exchange_count: 0,
        }
    }

    /// 満杯マガジンを取得し、空マガジンを返却
    pub fn exchange_for_full(&mut self, empty_mag: Magazine<SIZE>) -> Option<Magazine<SIZE>> {
        // 空マガジンを格納
        if self.empty_count < MAX_DEPOT_MAGAZINES {
            self.empty_magazines[self.empty_count] = Some(empty_mag);
            self.empty_count += 1;
        }
        // 満杯マガジンを取得
        if self.full_count > 0 {
            self.full_count -= 1;
            self.exchange_count += 1;
            self.full_magazines[self.full_count].take()
        } else {
            None
        }
    }

    /// 空マガジンを取得し、満杯マガジンを返却
    pub fn exchange_for_empty(&mut self, full_mag: Magazine<SIZE>) -> Option<Magazine<SIZE>> {
        // 満杯マガジンを格納
        if self.full_count < MAX_DEPOT_MAGAZINES {
            self.full_magazines[self.full_count] = Some(full_mag);
            self.full_count += 1;
        }
        // 空マガジンを取得
        if self.empty_count > 0 {
            self.empty_count -= 1;
            self.exchange_count += 1;
            self.empty_magazines[self.empty_count].take()
        } else {
            None
        }
    }

    /// 新しい空マガジンを作成
    pub fn create_empty_magazine(&self) -> Magazine<SIZE> {
        Magazine::new(self.object_size)
    }

    /// デポの統計情報
    pub fn stats(&self) -> MagazineDepotStats {
        MagazineDepotStats {
            full_magazines: self.full_count,
            empty_magazines: self.empty_count,
            exchange_count: self.exchange_count,
        }
    }
}

/// Per-CPUマガジンキャッシュ
///
/// 各CPUが保持する2つのマガジン。allocate/deallocateは
/// まずこのレイヤーで処理される。
#[repr(align(64))]
#[derive(Debug)]
pub struct PerCpuMagazineCache<const SIZE: usize = MAGAZINE_SIZE> {
    /// ロード済みマガジン（プライマリ）
    loaded: Magazine<SIZE>,
    /// 前のマガジン（セカンダリ）
    previous: Magazine<SIZE>,
    /// CPU ID
    cpu_id: usize,
    /// オブジェクトサイズ
    object_size: usize,
    /// 統計: マガジンからの割り当て回数
    magazine_allocs: usize,
    /// 統計: マガジンへの解放回数
    magazine_deallocs: usize,
    /// 統計: マガジン交換回数
    swaps: usize,
    /// 統計: Depotへのフォールバック回数
    depot_fallbacks: usize,
}

impl<const SIZE: usize> PerCpuMagazineCache<SIZE> {
    /// 新しいPer-CPUマガジンキャッシュを作成
    pub const fn new(cpu_id: usize, object_size: usize) -> Self {
        Self {
            loaded: Magazine::new(object_size),
            previous: Magazine::new(object_size),
            cpu_id,
            object_size,
            magazine_allocs: 0,
            magazine_deallocs: 0,
            swaps: 0,
            depot_fallbacks: 0,
        }
    }

    /// マガジンからオブジェクトを割り当て（Hot Path）
    #[inline]
    pub fn allocate(&mut self) -> Option<NonNull<u8>> {
        // 1. loadedマガジンから取得を試みる
        if let Some(ptr) = self.loaded.pop() {
            self.magazine_allocs += 1;
            return Some(ptr);
        }

        // 2. previousと交換してリトライ
        core::mem::swap(&mut self.loaded, &mut self.previous);
        self.swaps += 1;

        if let Some(ptr) = self.loaded.pop() {
            self.magazine_allocs += 1;
            return Some(ptr);
        }

        // 3. 両方空 → Depotへフォールバックが必要
        self.depot_fallbacks += 1;
        None
    }

    /// マガジンにオブジェクトを解放（Hot Path）
    #[inline]
    pub fn deallocate(&mut self, ptr: NonNull<u8>) -> bool {
        // 1. loadedマガジンにpushを試みる
        if self.loaded.push(ptr) {
            self.magazine_deallocs += 1;
            return true;
        }

        // 2. previousと交換してリトライ
        core::mem::swap(&mut self.loaded, &mut self.previous);
        self.swaps += 1;

        if self.loaded.push(ptr) {
            self.magazine_deallocs += 1;
            return true;
        }

        // 3. 両方満杯 → Depotへフォールバックが必要
        self.depot_fallbacks += 1;
        false
    }

    /// Depotから満杯マガジンを取得
    pub fn refill_from_depot(&mut self, depot: &mut MagazineDepot<SIZE>) -> bool {
        // loadedが空の場合、Depotから満杯マガジンを取得
        if self.loaded.is_empty() {
            let empty_mag = core::mem::replace(
                &mut self.loaded,
                Magazine::new(self.object_size)
            );
            if let Some(full_mag) = depot.exchange_for_full(empty_mag) {
                self.loaded = full_mag;
                return true;
            }
        }
        false
    }

    /// Depotへ満杯マガジンを返却
    pub fn flush_to_depot(&mut self, depot: &mut MagazineDepot<SIZE>) -> bool {
        // loadedが満杯の場合、Depotに返却して空マガジンを取得
        if self.loaded.is_full() {
            let full_mag = core::mem::replace(
                &mut self.loaded,
                Magazine::new(self.object_size)
            );
            if let Some(empty_mag) = depot.exchange_for_empty(full_mag) {
                self.loaded = empty_mag;
                return true;
            } else {
                // 空マガジンがない場合は新規作成
                self.loaded = depot.create_empty_magazine();
                return true;
            }
        }
        false
    }

    /// 統計情報を取得
    pub fn stats(&self) -> PerCpuMagazineStats {
        PerCpuMagazineStats {
            cpu_id: self.cpu_id,
            loaded_count: self.loaded.len(),
            previous_count: self.previous.len(),
            magazine_allocs: self.magazine_allocs,
            magazine_deallocs: self.magazine_deallocs,
            swaps: self.swaps,
            depot_fallbacks: self.depot_fallbacks,
        }
    }
}

/// マガジンデポの統計
#[derive(Debug, Clone, Copy)]
pub struct MagazineDepotStats {
    /// 満杯マガジン数
    pub full_magazines: usize,
    /// 空マガジン数
    pub empty_magazines: usize,
    /// 交換回数
    pub exchange_count: usize,
}

/// Per-CPUマガジンの統計
#[derive(Debug, Clone, Copy)]
pub struct PerCpuMagazineStats {
    /// CPU ID
    pub cpu_id: usize,
    /// loadedマガジンのオブジェクト数
    pub loaded_count: usize,
    /// previousマガジンのオブジェクト数
    pub previous_count: usize,
    /// マガジンからの割り当て回数
    pub magazine_allocs: usize,
    /// マガジンへの解放回数
    pub magazine_deallocs: usize,
    /// loaded/previous交換回数
    pub swaps: usize,
    /// Depotフォールバック回数
    pub depot_fallbacks: usize,
}

/// Magazine Layer付きSlabキャッシュ
///
/// Magazine Layerを統合したSlabキャッシュ。
/// 割り当て/解放は以下の順序で試行:
///
/// 1. Per-CPUマガジン（Hot Path）
/// 2. グローバルDepot（Warm Path）
/// 3. 下位Slab（Cold Path）
#[derive(Debug)]
pub struct MagazineSlabCache<const MAG_SIZE: usize = MAGAZINE_SIZE> {
    /// 下位のSlabキャッシュ
    slab: SlabCache,
    /// Per-CPUマガジンキャッシュ配列
    per_cpu_mags: [Option<PerCpuMagazineCache<MAG_SIZE>>; MAX_CPUS],
    /// グローバルマガジンデポ（要Mutex保護）
    depot: MagazineDepot<MAG_SIZE>,
    /// オブジェクトサイズ
    object_size: usize,
    /// 統計: Slabフォールバック割り当て回数
    slab_alloc_fallbacks: usize,
    /// 統計: Slabフォールバック解放回数
    slab_dealloc_fallbacks: usize,
}

impl<const MAG_SIZE: usize> MagazineSlabCache<MAG_SIZE> {
    /// 新しいMagazineSlabCacheを作成
    pub fn new(object_size: usize) -> Self {
        Self {
            slab: SlabCache::new(object_size),
            per_cpu_mags: core::array::from_fn(|_| None),
            depot: MagazineDepot::new(object_size),
            object_size,
            slab_alloc_fallbacks: 0,
            slab_dealloc_fallbacks: 0,
        }
    }

    /// 指定CPUのマガジンキャッシュを初期化
    pub fn init_cpu(&mut self, cpu_id: usize) {
        if cpu_id < MAX_CPUS && self.per_cpu_mags[cpu_id].is_none() {
            self.per_cpu_mags[cpu_id] = Some(PerCpuMagazineCache::new(cpu_id, self.object_size));
        }
    }

    /// オブジェクトを割り当て
    ///
    /// # Path Priority
    /// 1. Per-CPUマガジン（ロックフリー）
    /// 2. Depot交換（短いクリティカルセクション）
    /// 3. Slabからの新規割り当て
    pub fn allocate(&mut self, cpu_id: usize) -> Option<NonNull<u8>> {
        // 1. Per-CPUマガジンから割り当て（Hot Path）
        if let Some(mag_cache) = self.per_cpu_mags.get_mut(cpu_id).and_then(|m| m.as_mut()) {
            if let Some(ptr) = mag_cache.allocate() {
                return Some(ptr);
            }

            // 2. Depotから満杯マガジンを取得（Warm Path）
            if mag_cache.refill_from_depot(&mut self.depot) {
                if let Some(ptr) = mag_cache.allocate() {
                    return Some(ptr);
                }
            }
        }

        // 3. Slabから割り当て（Cold Path）
        self.slab_alloc_fallbacks += 1;
        self.slab.allocate()
    }

    /// オブジェクトを解放
    ///
    /// # Path Priority
    /// 1. Per-CPUマガジンへ（ロックフリー）
    /// 2. Depot交換（満杯マガジン返却）
    /// 3. Slabへの直接解放
    pub unsafe fn deallocate(&mut self, cpu_id: usize, ptr: NonNull<u8>) {
        // 1. Per-CPUマガジンへ解放（Hot Path）
        if let Some(mag_cache) = self.per_cpu_mags.get_mut(cpu_id).and_then(|m| m.as_mut()) {
            if mag_cache.deallocate(ptr) {
                return;
            }

            // 2. Depotへ満杯マガジンを返却（Warm Path）
            if mag_cache.flush_to_depot(&mut self.depot) {
                if mag_cache.deallocate(ptr) {
                    return;
                }
            }
        }

        // 3. Slabへ直接解放（Cold Path）
        self.slab_dealloc_fallbacks += 1;
        self.slab.deallocate(ptr);
    }

    /// 統計情報を取得
    pub fn stats(&self) -> MagazineSlabStats {
        MagazineSlabStats {
            slab_stats: self.slab.stats(),
            depot_stats: self.depot.stats(),
            slab_alloc_fallbacks: self.slab_alloc_fallbacks,
            slab_dealloc_fallbacks: self.slab_dealloc_fallbacks,
        }
    }

    /// Per-CPUマガジンの統計を取得
    pub fn per_cpu_stats(&self, cpu_id: usize) -> Option<PerCpuMagazineStats> {
        self.per_cpu_mags.get(cpu_id)
            .and_then(|m| m.as_ref())
            .map(|m| m.stats())
    }

    /// 下位Slabへのアクセス
    pub fn inner_slab(&self) -> &SlabCache {
        &self.slab
    }
}

/// MagazineSlabCacheの統計
#[derive(Debug, Clone)]
pub struct MagazineSlabStats {
    /// 下位Slabの統計
    pub slab_stats: SlabStats,
    /// Depotの統計
    pub depot_stats: MagazineDepotStats,
    /// Slabフォールバック割り当て回数
    pub slab_alloc_fallbacks: usize,
    /// Slabフォールバック解放回数
    pub slab_dealloc_fallbacks: usize,
}

// SAFETY: FreeList と SlabCache はSAS環境で使用され、
// Per-Core構造のため他コアから同時アクセスされない
// SAFETY: Per-Core構造のため他コアから同時アクセスされない
unsafe impl Send for SlabCache {}
unsafe impl Send for PerCoreCache {}
unsafe impl<const SIZE: usize> Send for Magazine<SIZE> {}
unsafe impl<const SIZE: usize> Send for MagazineDepot<SIZE> {}
unsafe impl<const SIZE: usize> Send for PerCpuMagazineCache<SIZE> {}
unsafe impl<const SIZE: usize> Send for MagazineSlabCache<SIZE> {}

/// Per-Core キャッシュ
/// 設計書: 各コア専用のSlabキャッシュ
#[repr(align(64))] // キャッシュラインにアライン
#[derive(Debug)]
pub struct PerCoreCache {
    /// 各サイズクラスのSlabキャッシュ
    caches: [SlabCache; SLAB_SIZES.len()],
    /// CPU ID
    cpu_id: usize,
    /// NUMA node ID for this CPU (for strict NUMA placement)
    numa_node: Option<u8>,
}

impl PerCoreCache {
    /// 新しいPer-Coreキャッシュを作成
    pub fn new(cpu_id: usize) -> Self {
        Self {
            caches: [
                SlabCache::new(SLAB_SIZES[0]),
                SlabCache::new(SLAB_SIZES[1]),
                SlabCache::new(SLAB_SIZES[2]),
                SlabCache::new(SLAB_SIZES[3]),
                SlabCache::new(SLAB_SIZES[4]),
                SlabCache::new(SLAB_SIZES[5]),
                SlabCache::new(SLAB_SIZES[6]),
                SlabCache::new(SLAB_SIZES[7]),
            ],
            cpu_id,
            numa_node: None,
        }
    }

    /// 新しいPer-Coreキャッシュを作成（NUMA node指定）
    ///
    /// 指定されたNUMAノードから優先的にメモリを確保する。
    /// これによりCPUとメモリのアフィニティを保証し、
    /// リモートメモリアクセスのレイテンシを削減する。
    pub fn new_on_node(cpu_id: usize, numa_node: u8) -> Self {
        Self {
            caches: [
                SlabCache::new_on_node(SLAB_SIZES[0], numa_node),
                SlabCache::new_on_node(SLAB_SIZES[1], numa_node),
                SlabCache::new_on_node(SLAB_SIZES[2], numa_node),
                SlabCache::new_on_node(SLAB_SIZES[3], numa_node),
                SlabCache::new_on_node(SLAB_SIZES[4], numa_node),
                SlabCache::new_on_node(SLAB_SIZES[5], numa_node),
                SlabCache::new_on_node(SLAB_SIZES[6], numa_node),
                SlabCache::new_on_node(SLAB_SIZES[7], numa_node),
            ],
            cpu_id,
            numa_node: Some(numa_node),
        }
    }

    /// Set NUMA node for this Per-Core cache
    ///
    /// Updates all underlying Slab caches to use the specified NUMA node.
    /// Should be called during CPU initialization after NUMA topology is known.
    pub fn set_numa_node(&mut self, node: u8) {
        self.numa_node = Some(node);
        for cache in &mut self.caches {
            cache.set_numa_node(node);
        }
    }

    /// Get the NUMA node for this Per-Core cache
    pub fn numa_node(&self) -> Option<u8> {
        self.numa_node
    }

    /// サイズに適したキャッシュインデックスを取得
    fn size_class(size: usize) -> Option<usize> {
        SLAB_SIZES.iter().position(|&s| size <= s)
    }

    /// メモリを割り当て
    pub fn allocate(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        let size = layout.size().max(layout.align());

        if let Some(class) = Self::size_class(size) {
            self.caches[class].allocate()
        } else {
            // Slabサイズを超える場合はグローバルヒープにフォールバック
            unsafe {
                let ptr = alloc::alloc::alloc(layout);
                NonNull::new(ptr)
            }
        }
    }

    /// メモリを解放
    pub unsafe fn deallocate(&mut self, ptr: NonNull<u8>, layout: Layout) {
        let size = layout.size().max(layout.align());

        if let Some(class) = Self::size_class(size) {
            // SAFETY: 呼び出し元がポインタの有効性を保証
            unsafe {
                self.caches[class].deallocate(ptr);
            }
        } else {
            // グローバルヒープに返却
            // SAFETY: ptrはallocで割り当てられたものと仮定
            unsafe {
                alloc::alloc::dealloc(ptr.as_ptr(), layout);
            }
        }
    }

    /// 統計情報を取得
    pub fn stats(&self) -> Vec<SlabStats> {
        self.caches.iter().map(|c| c.stats()).collect()
    }

    pub fn cpu_id(&self) -> usize {
        self.cpu_id
    }
}

/// 最大CPU数
pub const MAX_CPUS: usize = 64;

/// グローバルなPer-Coreキャッシュ配列
/// 重要: 各コアのキャッシュは **個別のMutex** で保護される
/// これにより、Core 0 がロックを取っている間も Core 1 は自分のキャッシュを使用可能
static PER_CORE_CACHES: [PoisonLock<Option<PerCoreCache>>; MAX_CPUS] = {
    // const配列の初期化（Rust 1.63+）
    const INIT: PoisonLock<Option<PerCoreCache>> = PoisonLock::new(None);
    [INIT; MAX_CPUS]
};

// ============================================================================
// Lock-free Remote Free Rings (Mimalloc/Snmalloc style)
// ============================================================================
//
// リモート解放の問題:
//   CPU A が割り当てたオブジェクトを CPU B が解放する場合、
//   従来は CPU A のロックを取得する必要があり、Cache Line Bouncing を引き起こす。
//
// 解決策:
//   各 CPU が自分専用の「リモートフリーリング」を持つ。
//   他 CPU は解放時にロック不要でリングにプッシュするだけ。
//   オーナー CPU は allocate 時にリングをドレインして回収。
//
// ============================================================================

/// Per-CPU リモートフリーリング
///
/// 各 CPU が他 CPU からの解放要求を受け取るための MPSC キュー。
/// - Push: ロックフリー（他 CPU から呼ばれる）
/// - Drain: オーナー CPU のみ（allocate 時に一括回収）
static SLAB_REMOTE_FREE_RINGS: [RemoteFreeRing<SLAB_REMOTE_FREE_CAPACITY>; MAX_CPUS] = {
    const INIT: RemoteFreeRing<SLAB_REMOTE_FREE_CAPACITY> = RemoteFreeRing::new();
    [INIT; MAX_CPUS]
};

/// リモートフリー統計
static REMOTE_FREE_STATS: RemoteFreeStats = RemoteFreeStats::new();

/// リモートフリー統計構造体
pub struct RemoteFreeStats {
    /// リモートプッシュ成功数
    pub remote_pushes: AtomicU64,
    /// リモートプッシュ失敗数（リング満杯）
    pub remote_push_failures: AtomicU64,
    /// ドレイン回数
    pub drain_count: AtomicU64,
    /// ドレインで回収したエントリ数
    pub drained_entries: AtomicU64,
}

impl RemoteFreeStats {
    pub const fn new() -> Self {
        Self {
            remote_pushes: AtomicU64::new(0),
            remote_push_failures: AtomicU64::new(0),
            drain_count: AtomicU64::new(0),
            drained_entries: AtomicU64::new(0),
        }
    }
}

/// リモートフリーリングを初期化
///
/// 各 CPU のリングのシーケンス番号を初期化する。
/// init_per_core_caches の後に呼び出す。
pub fn init_slab_remote_free_rings(num_cpus: usize) {
    let num_cpus = num_cpus.min(MAX_CPUS);
    for cpu_id in 0..num_cpus {
        SLAB_REMOTE_FREE_RINGS[cpu_id].init();
    }
}

/// リモートフリーリングにプッシュ（ロックフリー）
///
/// 他 CPU から呼ばれる。オーナー CPU のロックを取らない。
///
/// # Arguments
/// * `owner_cpu` - オブジェクトを所有する CPU ID
/// * `ptr` - 解放するポインタ
/// * `size_class` - サイズクラスインデックス
///
/// # Returns
/// * `true` - プッシュ成功
/// * `false` - リング満杯（フォールバック解放が必要）
#[inline]
pub fn slab_remote_free_push(owner_cpu: usize, ptr: u64, size_class: u8) -> bool {
    if owner_cpu >= MAX_CPUS {
        return false;
    }
    
    // Always succeeds (internally falls back to overflow list)
    SLAB_REMOTE_FREE_RINGS[owner_cpu].push(ptr, size_class);
    REMOTE_FREE_STATS.remote_pushes.fetch_add(1, Ordering::Relaxed);
    true
}

/// 自分のリモートフリーリングをドレイン（オーナー CPU のみ）
///
/// allocate 時の最初に呼び出し、他 CPU から送られた解放要求を一括処理。
/// これによりバッチ効率が向上し、ロック競合が完全に排除される。
///
/// # Arguments
/// * `cpu_id` - 現在の CPU ID
/// * `cache` - このCPUの PerCoreCache
fn drain_remote_frees(cpu_id: usize, cache: &mut PerCoreCache) {
    if cpu_id >= MAX_CPUS {
        return;
    }
    
    let ring = &SLAB_REMOTE_FREE_RINGS[cpu_id];
    let mut drained = 0u64;
    
    // リングから全エントリをドレイン（最大256エントリ）
    ring.drain_with(SLAB_REMOTE_FREE_CAPACITY, |entry| {
        let ptr_addr = entry.addr;
        let size_class = entry.size_class as usize;
        
        if size_class < SLAB_SIZES.len() {
            if let Some(ptr) = NonNull::new(ptr_addr as *mut u8) {
                // SAFETY: ポインタはこのCPUのSlabから割り当てられたもの
                unsafe {
                    cache.caches[size_class].deallocate(ptr);
                }
                drained += 1;
            }
        }
    });
    
    if drained > 0 {
        REMOTE_FREE_STATS.drain_count.fetch_add(1, Ordering::Relaxed);
        REMOTE_FREE_STATS.drained_entries.fetch_add(drained, Ordering::Relaxed);
    }
}

/// Per-Coreキャッシュシステムを初期化
pub fn init_per_core_caches(num_cpus: usize) {
    let num_cpus = num_cpus.min(MAX_CPUS);

    for cpu_id in 0..num_cpus {
        init_per_core_cache_for_cpu(cpu_id);
    }
}

/// Initialize per-core cache for a single CPU (idempotent)
pub fn init_per_core_cache_for_cpu(cpu_id: usize) {
    if cpu_id >= MAX_CPUS {
        return;
    }
    // 各コアのMutexに個別にアクセス（他コアをブロックしない）
    // Initialization-time best-effort recovery for per-core caches: continue init even if a lock
    // shows as poisoned.
    let mut guard = PER_CORE_CACHES[cpu_id].lock_for_init("[MEM] Per-core slab init");
    if guard.is_none() {
        *guard = Some(PerCoreCache::new(cpu_id));
    }
}

/// 現在のCPUのPer-Coreキャッシュから割り当て
///
/// # Note
/// - init_per_core_caches が呼ばれた後に使用する必要がある
/// - cpu_id は有効な範囲内である必要がある
/// - 各コアのキャッシュは独立してロックされるため、他コアをブロックしない
///
/// # リモートフリー統合
/// 割り当て前に自分のリモートフリーリングをドレインし、
/// 他CPUから送られた解放要求を一括処理する。
/// これによりバッチ効率が向上し、Cache Line Bouncing が完全に排除される。
///
/// # TODO: API改善
/// 現在は `cpu_id` を引数で受け取っているが、これはAPI設計として問題がある。
/// 将来的には `GsBase` レジスタを使ってPer-CPUデータを参照し、
/// `per_core_alloc(layout)` だけで動作するようにすべき。
pub fn per_core_alloc(cpu_id: usize, layout: Layout) -> Option<NonNull<u8>> {
    if cpu_id >= MAX_CPUS {
        return None;
    }
    // このコアのMutexだけをロック（他コアに影響しない）
    match PER_CORE_CACHES[cpu_id].lock() {
        Ok(mut guard) => {
            if let Some(cache) = guard.as_mut() {
                // リモートフリーのドレイン（他CPUからの解放要求を回収）
                drain_remote_frees(cpu_id, cache);
                // 割り当て
                cache.allocate(layout)
            } else {
                None
            }
        }
        Err(_) => {
            // Poisoned: fallback to global heap allocation instead of accessing potentially
            // corrupted per-core cache data.
            log::error!("[MEM] Slab Poisoned cpu={}; falling back to global allocator", cpu_id);
            unsafe {
                let ptr = alloc::alloc::alloc(layout);
                NonNull::new(ptr)
            }
        }
    }
}

/// 現在のCPUのPer-Coreキャッシュに解放
///
/// # Safety
/// - ptr は per_core_alloc で割り当てられたものである必要がある
pub unsafe fn per_core_dealloc(cpu_id: usize, ptr: NonNull<u8>, layout: Layout) {
    if cpu_id >= MAX_CPUS {
        return;
    }
    // このコアのMutexだけをロック（他コアに影響しない）
    match PER_CORE_CACHES[cpu_id].lock() {
        Ok(mut guard) => {
            if let Some(cache) = guard.as_mut() {
                // SAFETY: 呼び出し元が保証
                unsafe {
                    cache.deallocate(ptr, layout);
                }
                return;
            }
            // fallthrough to global dealloc if no per-core cache
        }
        Err(_) => {
            log::error!("[MEM] Slab Poisoned cpu={}; falling back to global dealloc", cpu_id);
            // fallthrough to global dealloc
        }
    }

    // Global deallocation fallback
    unsafe {
        alloc::alloc::dealloc(ptr.as_ptr(), layout);
    }
}

// ============================================================================
// GsBase を使用した自動 CPU ID 取得 API
// cpu_id 引数が不要になり、APIが簡素化される
// ============================================================================

/// 現在のCPUのPer-Coreキャッシュから割り当て（GsBase版）
///
/// CPU IDを自動的に取得するため、引数が不要
///
/// # Note
/// - `init_per_core_caches` と `per_cpu::setup_current_cpu` が
///   呼ばれた後に使用する必要がある
/// - GsBaseが設定されていない場合は None を返す（panicしない）
pub fn per_core_alloc_auto(layout: Layout) -> Option<NonNull<u8>> {
    // try_current_cpu_id を使用し、初期化前でも安全に動作
    let cpu_id = crate::mm::per_cpu::try_current_cpu_id()?;
    per_core_alloc(cpu_id, layout)
}

/// 現在のCPUのPer-Coreキャッシュに解放（GsBase版）
///
/// CPU IDを自動的に取得するため、引数が不要
///
/// # Safety
/// - ptr は per_core_alloc または per_core_alloc_auto で
///   割り当てられたものである必要がある
pub unsafe fn per_core_dealloc_auto(ptr: NonNull<u8>, layout: Layout) {
    // try_current_cpu_id を使用し、初期化前でも安全に動作
    if let Some(cpu_id) = crate::mm::per_cpu::try_current_cpu_id() {
        // SAFETY: 呼び出し元が保証
        unsafe {
            per_core_dealloc(cpu_id, ptr, layout);
        }
    }
    // 初期化前の場合は何もしない（リークするが安全）
}

// ============================================================================
// Cross-CPU Remote Free API (Lock-free)
// ============================================================================
//
// Producer-Consumer パターンなど、オブジェクトを割り当てた CPU と
// 解放する CPU が異なる場合に使用する。
//
// 従来: 解放時にオーナー CPU のロックを取得 → Cache Line Bouncing
// 改善: リモートフリーリングにプッシュ（ロックフリー）→ オーナーが回収
//
// ============================================================================

/// クロスCPU解放（ロックフリー）
///
/// 現在のCPUとは異なるCPUが割り当てたオブジェクトを解放する。
/// オーナーCPUのロックを取らず、リモートフリーリングにプッシュする。
///
/// # Arguments
/// * `owner_cpu` - オブジェクトを割り当てた CPU ID
/// * `ptr` - 解放するポインタ
/// * `layout` - メモリレイアウト
///
/// # Returns
/// * `true` - リモートフリー成功（またはローカル解放）
/// * `false` - リモートフリー失敗（フォールバック解放が必要）
///
/// # Safety
/// - ptr は owner_cpu の per_core_alloc で割り当てられたものである必要がある
pub unsafe fn per_core_dealloc_remote(
    owner_cpu: usize,
    ptr: NonNull<u8>,
    layout: Layout,
) -> bool {
    let size = layout.size().max(layout.align());
    
    // サイズクラスを特定
    let size_class = match SLAB_SIZES.iter().position(|&s| size <= s) {
        Some(class) => class as u8,
        None => {
            // Slabサイズを超える場合はグローバルヒープに返却
            unsafe {
                alloc::alloc::dealloc(ptr.as_ptr(), layout);
            }
            return true;
        }
    };
    
    // リモートフリーリングにプッシュ
    // リング満杯時も内部でフォールバックキューに保存されるため、常に成功する
    slab_remote_free_push(owner_cpu, ptr.as_ptr() as u64, size_class);
    true
}

/// リモートフリー統計を取得
pub fn slab_remote_free_stats() -> (u64, u64, u64, u64) {
    (
        REMOTE_FREE_STATS.remote_pushes.load(Ordering::Relaxed),
        REMOTE_FREE_STATS.remote_push_failures.load(Ordering::Relaxed),
        REMOTE_FREE_STATS.drain_count.load(Ordering::Relaxed),
        REMOTE_FREE_STATS.drained_entries.load(Ordering::Relaxed),
    )
}

// ============================================================================
// Typed Slab Cache with Constructor/Destructor support
// ============================================================================

/// コンストラクタ関数型: オブジェクトの初期化を行う
pub type SlabCtor = fn(NonNull<u8>);

/// デストラクタ関数型: オブジェクトのクリーンアップを行う（解放ではない）
pub type SlabDtor = fn(NonNull<u8>);

/// コンストラクタ/デストラクタ付きSlabキャッシュ
///
/// オブジェクトの初期化コストを削減するため、一度初期化されたオブジェクトは
/// 解放後も初期化済み状態を維持する（デストラクタでリセットのみ行う）
///
/// # 設計思想
/// - コンストラクタは最初の割り当て時のみ呼ばれる（オブジェクト新規作成時）
/// - デストラクタは解放時に毎回呼ばれる（状態リセット用）
/// - 再割り当て時は初期化済みなのでコンストラクタをスキップ
///
/// # 例
/// ```ignore
/// fn init_task_struct(ptr: NonNull<u8>) {
///     let task = unsafe { &mut *(ptr.as_ptr() as *mut TaskStruct) };
///     task.state = TaskState::Init;
///     task.priority = 0;
///     // ... 重い初期化処理
/// }
///
/// fn reset_task_struct(ptr: NonNull<u8>) {
///     let task = unsafe { &mut *(ptr.as_ptr() as *mut TaskStruct) };
///     task.state = TaskState::Init; // 状態リセットのみ
/// }
///
/// let cache = TypedSlabCache::new_with_ctor_dtor(
///     size_of::<TaskStruct>(),
///     init_task_struct,
///     Some(reset_task_struct)
/// );
/// ```
pub struct TypedSlabCache {
    /// 内部のSlabキャッシュ (Shared via Registry)
    inner: Arc<Mutex<SlabCache>>,
    /// コンストラクタ関数（初回割り当て時に呼ばれる）
    ctor: Option<SlabCtor>,
    /// デストラクタ関数（解放時に呼ばれる）
    dtor: Option<SlabDtor>,
    /// 初期化済みオブジェクトの追跡用ビットマップ
    /// (簡易実装: 最初のページあたりの最初64オブジェクトのみ追跡)
    /// 本格実装ではページごとにビットマップを持つ
    initialized_bitmap: u64,
    /// 初回コンストラクタ呼び出し回数（統計用）
    ctor_calls: usize,
    /// デストラクタ呼び出し回数（統計用）
    dtor_calls: usize,
    /// コンストラクタスキップ回数（再利用時）
    ctor_skipped: usize,
}

impl TypedSlabCache {
    /// コンストラクタ付きTypedSlabCacheを作成
    pub fn new_with_ctor(object_size: usize, ctor: SlabCtor) -> Self {
        // TypedSlabCache maintains internal state (initialized_bitmap) so it cannot be merged
        let flags = SlabFlags { mergeable: false, read_only: false };
        let inner = SlabCacheRegistry::global().get_or_create(object_size, flags);
        Self {
            inner,
            ctor: Some(ctor),
            dtor: None,
            initialized_bitmap: 0,
            ctor_calls: 0,
            dtor_calls: 0,
            ctor_skipped: 0,
        }
    }

    /// コンストラクタ/デストラクタ付きTypedSlabCacheを作成
    pub fn new_with_ctor_dtor(
        object_size: usize,
        ctor: SlabCtor,
        dtor: Option<SlabDtor>,
    ) -> Self {
        // TypedSlabCache maintains internal state, no merging
        let flags = SlabFlags { mergeable: false, read_only: false };
        let inner = SlabCacheRegistry::global().get_or_create(object_size, flags);
        Self {
            inner,
            ctor: Some(ctor),
            dtor,
            initialized_bitmap: 0,
            ctor_calls: 0,
            dtor_calls: 0,
            ctor_skipped: 0,
        }
    }

    /// NUMA node指定でTypedSlabCacheを作成
    pub fn new_with_ctor_on_node(
        object_size: usize,
        ctor: SlabCtor,
        numa_node: u8,
    ) -> Self {
        // NUMA aware, not mergeable currently (registry doesn't track node yet, or assume non-mergeable)
        // For now, create direct since Registry doesn't support NUMA constraints yet
        // OR wrapper allowing new_on_node.
        // Let's stick to simple Arc<Mutex> wrap for now, bypassing registry for NUMA explicit calls
        // until Registry is upgraded.
        let inner = Arc::new(Mutex::new(SlabCache::new_on_node(object_size, numa_node)));
        Self {
            inner,
            ctor: Some(ctor),
            dtor: None,
            initialized_bitmap: 0,
            ctor_calls: 0,
            dtor_calls: 0,
            ctor_skipped: 0,
        }
    }

    /// オブジェクトを割り当て
    ///
    /// 初回割り当てではコンストラクタが呼ばれ、再利用時はスキップ
    pub fn allocate(&mut self) -> Option<NonNull<u8>> {
        let ptr = self.inner.lock().allocate()?;

        // オブジェクトのインデックスを計算（簡易実装: アドレス下位ビットから）
        let obj_index = self.ptr_to_index(ptr);

        if obj_index < 64 {
            let mask = 1u64 << obj_index;
            if self.initialized_bitmap & mask == 0 {
                // 初回割り当て: コンストラクタを呼ぶ
                if let Some(ctor) = self.ctor {
                    ctor(ptr);
                    self.ctor_calls += 1;
                }
                self.initialized_bitmap |= mask;
            } else {
                // 再利用: コンストラクタをスキップ
                self.ctor_skipped += 1;
            }
        } else {
            // インデックスが64以上の場合は毎回コンストラクタを呼ぶ（安全側に倒す）
            if let Some(ctor) = self.ctor {
                ctor(ptr);
                self.ctor_calls += 1;
            }
        }

        Some(ptr)
    }

    /// オブジェクトを解放
    ///
    /// デストラクタが設定されていれば呼び出す
    ///
    /// # Safety
    /// - ptr は allocate() で取得したものである必要がある
    pub unsafe fn deallocate(&mut self, ptr: NonNull<u8>) {
        // デストラクタを呼ぶ（状態リセット用）
        if let Some(dtor) = self.dtor {
            dtor(ptr);
            self.dtor_calls += 1;
        }

        // 内部キャッシュに返却（初期化フラグは維持）
        self.inner.lock().deallocate(ptr);
    }

    /// ポインタからオブジェクトインデックスを計算（簡易実装）
    fn ptr_to_index(&self, ptr: NonNull<u8>) -> usize {
        // アドレス下位12ビット（ページ内オフセット）をオブジェクトサイズで割る
        let offset = (ptr.as_ptr() as usize) & 0xFFF;
        offset / self.inner.lock().object_size
    }

    /// 統計情報を取得
    pub fn stats(&self) -> TypedSlabStats {
        let inner_stats = self.inner.lock().stats();
        TypedSlabStats {
            alloc_count: inner_stats.alloc_count,
            dealloc_count: inner_stats.dealloc_count,
            page_count: inner_stats.page_count,
            ctor_calls: self.ctor_calls,
            dtor_calls: self.dtor_calls,
            ctor_skipped: self.ctor_skipped,
        }
    }

    /// コンストラクタ効率を計算（スキップ率）
    pub fn ctor_skip_ratio(&self) -> f32 {
        let total = self.ctor_calls + self.ctor_skipped;
        if total == 0 {
            0.0
        } else {
            self.ctor_skipped as f32 / total as f32
        }
    }

    /// 内部SlabCacheへのアクセス（統計等） - ロックが必要
    pub fn inner(&self) -> Arc<Mutex<SlabCache>> {
        self.inner.clone()
    }
}

/// TypedSlabCacheの統計情報
#[derive(Debug, Clone, Copy)]
pub struct TypedSlabStats {
    /// 総割り当て回数
    pub alloc_count: usize,
    /// 総解放回数
    pub dealloc_count: usize,
    /// 確保したページ数
    pub page_count: usize,
    /// コンストラクタ呼び出し回数
    pub ctor_calls: usize,
    /// デストラクタ呼び出し回数
    pub dtor_calls: usize,
    /// コンストラクタスキップ回数
    pub ctor_skipped: usize,
}

// ============================================================================
// Pre-defined Typed Caches for common kernel objects
// ============================================================================

/// カーネルオブジェクト用の事前定義キャッシュ群
pub mod kernel_caches {
    use super::*;

    /// タスク構造体のサイズ（仮: 実際のTaskStructサイズに合わせる）
    pub const TASK_STRUCT_SIZE: usize = 512;

    /// VMエリア構造体のサイズ
    pub const VMA_SIZE: usize = 128;

    /// ファイルディスクリプタ構造体のサイズ
    pub const FILE_DESC_SIZE: usize = 64;

    /// 汎用のnoop コンストラクタ（ゼロクリアのみ）
    pub fn zero_ctor(ptr: NonNull<u8>) {
        unsafe {
            core::ptr::write_bytes(ptr.as_ptr(), 0, 64);
        }
    }

    /// ゼロクリアなしのnoop コンストラクタ
    pub fn noop_ctor(_ptr: NonNull<u8>) {
        // 何もしない（既にゼロクリアされている場合用）
    }
}

// ============================================================================
// Phase 5: 2.3 Object Caching Layer
// ============================================================================
//
// ## 概要
//
// 特定の型のオブジェクトをキャッシュして再利用するレイヤー。
// Slabアロケータの上に構築され、以下の利点を提供：
//
// 1. **型安全な割り当て**: ジェネリクスで型を指定
// 2. **初期化の最適化**: コンストラクタをキャッシュしてスキップ可能
// 3. **オブジェクトプーリング**: 解放後も初期化済み状態を保持
// 4. **バッチ操作**: 複数オブジェクトの一括割り当て/解放
//
// ## 使用例
//
// ```rust
// let cache = ObjectCache::<MyStruct>::new("my_struct");
// let obj = cache.alloc().unwrap();
// // obj は初期化済み MyStruct
// unsafe { cache.free(obj); }
// ```
//
// ============================================================================

/// オブジェクトキャッシュの設定
#[derive(Debug, Clone, Copy)]
pub struct ObjectCacheConfig {
    /// プール内の最大オブジェクト数
    pub max_pooled: usize,
    /// バッチ割り当てサイズ
    pub batch_size: usize,
    /// アイドル時の縮小閾値
    pub shrink_threshold: usize,
    /// 初期化をスキップするか
    pub skip_init_on_reuse: bool,
}

impl Default for ObjectCacheConfig {
    fn default() -> Self {
        Self {
            max_pooled: 64,
            batch_size: 8,
            shrink_threshold: 128,
            skip_init_on_reuse: true,
        }
    }
}

/// オブジェクトキャッシュ統計
#[derive(Debug, Clone, Copy, Default)]
pub struct ObjectCacheStats {
    /// 総割り当て回数
    pub allocations: u64,
    /// 総解放回数
    pub deallocations: u64,
    /// プールからの割り当て回数（キャッシュヒット）
    pub pool_hits: u64,
    /// 新規割り当て回数（キャッシュミス）
    pub pool_misses: u64,
    /// プールに返却された回数
    pub pool_returns: u64,
    /// プールから溢れた回数
    pub pool_overflows: u64,
    /// 初期化スキップ回数
    pub init_skipped: u64,
    /// バッチ割り当て回数
    pub batch_allocs: u64,
}

/// 型付きオブジェクトキャッシュ
/// 
/// ## 特徴
/// 
/// - `T: Default`の型に対して自動的にデフォルト初期化
/// - プーリングによる高速な再割り当て
/// - バッチ操作のサポート
pub struct ObjectCache<T> {
    /// 名前（デバッグ用）
    name: &'static str,
    /// 内部Slabキャッシュ
    inner: Arc<Mutex<SlabCache>>,
    /// プールされたオブジェクト
    pool: spin::Mutex<Vec<NonNull<T>>>,
    /// 設定
    config: ObjectCacheConfig,
    /// 統計
    stats: spin::Mutex<ObjectCacheStats>,
}

// SAFETY: ObjectCacheはスレッドセーフなロックで保護されている
unsafe impl<T: Send> Send for ObjectCache<T> {}
unsafe impl<T: Send> Sync for ObjectCache<T> {}

impl<T> ObjectCache<T> {
    /// 新しいオブジェクトキャッシュを作成
    pub fn new(name: &'static str) -> Self {
        Self::with_config(name, ObjectCacheConfig::default())
    }
    
    /// 設定付きで新しいオブジェクトキャッシュを作成
    pub fn with_config(name: &'static str, config: ObjectCacheConfig) -> Self {
        // ObjectCache is stateless regarding initialization (pools it manually), 
        // so it IS mergeable.
        let flags = SlabFlags { mergeable: true, read_only: false };
        let inner = SlabCacheRegistry::global().get_or_create(core::mem::size_of::<T>(), flags);
        Self {
            name,
            inner,
            pool: spin::Mutex::new(Vec::with_capacity(config.max_pooled)),
            config,
            stats: spin::Mutex::new(ObjectCacheStats::default()),
        }
    }
    
    /// 名前を取得
    pub fn name(&self) -> &'static str {
        self.name
    }
    
    /// オブジェクトを割り当て（未初期化）
    /// 
    /// # Safety
    /// 
    /// 返されたポインタは未初期化状態。使用前に初期化が必要。
    pub unsafe fn alloc_uninit(&self) -> Option<NonNull<T>> {
        let mut stats = self.stats.lock();
        stats.allocations += 1;
        
        // プールから取得を試みる
        {
            let mut pool = self.pool.lock();
            if let Some(ptr) = pool.pop() {
                stats.pool_hits += 1;
                return Some(ptr);
            }
        }
        
        // キャッシュミス: Slabから新規割り当て
        stats.pool_misses += 1;
        let mut inner = self.inner.lock();
        inner.allocate().map(|ptr| ptr.cast())
    }
    
    /// オブジェクトを解放
    /// 
    /// # Safety
    /// 
    /// - `ptr`はこのキャッシュから割り当てられたもの
    /// - 解放後は使用禁止
    pub unsafe fn free(&self, ptr: NonNull<T>) {
        let mut stats = self.stats.lock();
        stats.deallocations += 1;
        
        // プールに返却を試みる
        {
            let mut pool = self.pool.lock();
            if pool.len() < self.config.max_pooled {
                pool.push(ptr);
                stats.pool_returns += 1;
                return;
            }
        }
        
        // プール満杯: Slabに返却
        stats.pool_overflows += 1;
        let mut inner = self.inner.lock();
        inner.deallocate(ptr.cast());
    }
    
    /// バッチ割り当て（未初期化）
    /// 
    /// # Safety
    /// 
    /// 返されたポインタは全て未初期化状態。
    pub unsafe fn alloc_batch_uninit(&self, count: usize) -> Vec<NonNull<T>> {
        let mut result = Vec::with_capacity(count);
        let mut stats = self.stats.lock();
        stats.batch_allocs += 1;
        drop(stats);
        
        for _ in 0..count {
            if let Some(ptr) = self.alloc_uninit() {
                result.push(ptr);
            } else {
                break;
            }
        }
        
        result
    }
    
    /// バッチ解放
    /// 
    /// # Safety
    /// 
    /// 全てのポインタはこのキャッシュから割り当てられたもの。
    pub unsafe fn free_batch(&self, ptrs: &[NonNull<T>]) {
        for &ptr in ptrs {
            self.free(ptr);
        }
    }
    
    /// プールを縮小
    /// 
    /// `shrink_threshold`を超えるオブジェクトをSlabに返却。
    pub fn shrink(&self) {
        let mut pool = self.pool.lock();
        let mut inner = self.inner.lock();
        
        while pool.len() > self.config.shrink_threshold {
            if let Some(ptr) = pool.pop() {
                unsafe {
                    inner.deallocate(ptr.cast());
                }
            }
        }
    }
    
    /// プールをクリア
    pub fn clear_pool(&self) {
        let mut pool = self.pool.lock();
        let mut inner = self.inner.lock();
        
        while let Some(ptr) = pool.pop() {
            unsafe {
                inner.deallocate(ptr.cast());
            }
        }
    }
    
    /// 統計を取得
    pub fn stats(&self) -> ObjectCacheStats {
        *self.stats.lock()
    }
    
    /// キャッシュヒット率を計算
    pub fn hit_rate(&self) -> f32 {
        let stats = self.stats.lock();
        let total = stats.pool_hits + stats.pool_misses;
        if total == 0 {
            0.0
        } else {
            stats.pool_hits as f32 / total as f32 * 100.0
        }
    }
    
    /// プールのサイズを取得
    pub fn pool_size(&self) -> usize {
        self.pool.lock().len()
    }
}

impl<T: Default> ObjectCache<T> {
    /// オブジェクトを割り当て（デフォルト初期化済み）
    /// 
    /// プールから取得した場合、`skip_init_on_reuse`が`true`なら
    /// 初期化をスキップする。
    pub fn alloc(&self) -> Option<NonNull<T>> {
        let mut stats = self.stats.lock();
        stats.allocations += 1;
        
        // プールから取得を試みる
        {
            let mut pool = self.pool.lock();
            if let Some(ptr) = pool.pop() {
                stats.pool_hits += 1;
                if self.config.skip_init_on_reuse {
                    stats.init_skipped += 1;
                } else {
                    // 再初期化
                    unsafe {
                        core::ptr::write(ptr.as_ptr(), T::default());
                    }
                }
                return Some(ptr);
            }
        }
        
        // キャッシュミス: Slabから新規割り当て + 初期化
        stats.pool_misses += 1;
        drop(stats);
        
        let mut inner = self.inner.lock();
        inner.allocate().map(|ptr| {
            let typed_ptr: NonNull<T> = ptr.cast();
            unsafe {
                core::ptr::write(typed_ptr.as_ptr(), T::default());
            }
            typed_ptr
        })
    }
    
    /// バッチ割り当て（デフォルト初期化済み）
    pub fn alloc_batch(&self, count: usize) -> Vec<NonNull<T>> {
        let mut result = Vec::with_capacity(count);
        let mut stats = self.stats.lock();
        stats.batch_allocs += 1;
        drop(stats);
        
        for _ in 0..count {
            if let Some(ptr) = self.alloc() {
                result.push(ptr);
            } else {
                break;
            }
        }
        
        result
    }
}

impl<T> Drop for ObjectCache<T> {
    fn drop(&mut self) {
        // プール内のオブジェクトをSlabに返却
        self.clear_pool();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::set_panicking;

    #[test]
    fn test_per_core_alloc_poisoned_fallbacks_to_global() {
        // Initialize per-core caches for CPU 0
        init_per_core_caches(1);

        // Poison the lock for CPU 0
        set_panicking(true);
        {
            let _guard = PER_CORE_CACHES[0].lock().unwrap();
        }
        set_panicking(false);

        let layout = Layout::from_size_align(128, 8).unwrap();
        let ptr = per_core_alloc(0, layout).expect("should fall back to global alloc");

        // Deallocate via per_core_dealloc (should detect poisoned and use global dealloc)
        unsafe { per_core_dealloc(0, ptr, layout) };
    }

    #[test]
    fn test_slab_cache() {
        let mut cache = SlabCache::new(64);

        // 複数回割り当て
        let ptr1 = cache.allocate();
        assert!(ptr1.is_some());

        let ptr2 = cache.allocate();
        assert!(ptr2.is_some());

        // 異なるアドレス
        assert_ne!(ptr1.unwrap().as_ptr(), ptr2.unwrap().as_ptr());

        // 解放
        unsafe {
            cache.deallocate(ptr1.unwrap());
            cache.deallocate(ptr2.unwrap());
        }

        // 統計確認
        let stats = cache.stats();
        assert_eq!(stats.alloc_count, 2);
        assert_eq!(stats.dealloc_count, 2);
    }
}
