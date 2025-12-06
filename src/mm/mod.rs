// ============================================================================
// Memory Management Module
// 設計書 5: メモリ管理戦略 - 階層型アロケータ設計
// ============================================================================
pub mod buddy_allocator;
pub mod exchange_heap;
pub mod frame_allocator;
pub mod higher_half;
pub mod mapping;
pub mod mmap;
pub mod per_cpu;
pub mod slab_cache;

#[allow(unused_imports)]
pub use buddy_allocator::{
    BuddyAllocatorStats, buddy_alloc_frame, buddy_alloc_frame_1g, buddy_alloc_frame_2m,
    buddy_allocator_stats, buddy_dealloc_frame, buddy_dealloc_frame_1g, buddy_dealloc_frame_2m,
    init_buddy_allocator,
};
#[allow(unused_imports)]
pub use exchange_heap::{
    ExchangeHeap,
    HeapStats,
    allocate_on_exchange,
    allocate_slice_default,
    allocate_slice_with,
    allocate_uninit_slice,
    // 安全なスライス割り当てAPI
    allocate_zeroed_slice,
    deallocate_on_exchange,
    deallocate_raw,
    deallocate_slice,
    exchange_heap_stats,
    init_exchange_heap,
};
#[allow(unused_imports)]
pub use frame_allocator::{
    PAGE_SIZE_1G, PAGE_SIZE_2M, PAGE_SIZE_4K, alloc_frame, alloc_frame_1g, alloc_frame_2m,
    dealloc_frame, frame_allocator_stats, init_frame_allocator,
};
#[allow(unused_imports)]
pub use higher_half::{
    // 既存のエクスポート
    HigherHalfManager, MapError, PageFlags, PageSize, PageTable, PageTableEntry,
    PageTableManager, PageTableWalker, PhysAddr, PhysicalMemoryMapper, VirtAddr,
    flush_tlb, get_cr3, global_map_page, global_translate, global_unmap_page, init,
    init_page_table_manager, invalidate_page, phys_to_virt, set_cr3, virt_to_phys,
};
#[allow(unused_imports)]
pub use mapping::{PHYSICAL_MEMORY_OFFSET, phys_to_virt as mapping_phys_to_virt, virt_to_phys as mapping_virt_to_phys};
#[allow(unused_imports)]
pub use mmap::{
    MappedAddress, MappingFlags, MappingSize, MemoryMapping, MmapError, MmapManager, Protection,
    mmap, mmap_manager, mprotect, msync, munmap,
};
#[allow(unused_imports)]
pub use per_cpu::{
    MAX_CPUS, PerCpuData, active_cpu_count, current_cpu_id, current_per_cpu, current_per_cpu_mut,
    enable_fsgsbase, get_per_cpu, init_per_cpu, is_fsgsbase_enabled, setup_current_cpu,
    try_current_cpu_id,
};
#[allow(unused_imports)]
pub use slab_cache::{
    PerCoreCache,
    SLAB_SIZES,
    SlabCache,
    SlabStats,
    init_per_core_caches,
    per_core_alloc,
    // GsBaseを使った自動CPU ID取得API
    per_core_alloc_auto,
    per_core_dealloc,
    per_core_dealloc_auto,
};

// ============================================================================
// 統一フレームアロケータインターフェース
// P3完了: ビットマップ/バディアロケータの統合
// 
// 設計方針:
// - BuddyAllocator を優先使用（O(log n)、連続領域確保が効率的）
// - BitmapAllocator はフォールバック/レガシー用途
// - 新規コードは UnifiedFrameAllocator を使用すること
// ============================================================================

use x86_64::structures::paging::{PhysFrame, Size4KiB, Size2MiB, Size1GiB};

/// フレームアロケータの種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameAllocatorType {
    /// ビットマップベースのシンプルなアロケータ
    Bitmap,
    /// バディシステムベースの高効率アロケータ
    Buddy,
}

/// 統一フレームアロケータAPI
/// 
/// 設計書 5.1: 物理メモリは4KBページ単位で管理
/// ビットマップとバディの両方を透過的に使用可能
pub struct UnifiedFrameAllocator;

impl UnifiedFrameAllocator {
    /// 4KBフレームを割り当て
    /// 
    /// デフォルトでBuddyを優先し、失敗時にBitmapにフォールバック
    pub fn alloc_4k() -> Option<PhysFrame<Size4KiB>> {
        // まずBuddyを試す（高効率）
        if let Some(frame) = buddy_alloc_frame() {
            return Some(frame);
        }
        // フォールバック
        alloc_frame()
    }

    /// 2MBフレームを割り当て
    pub fn alloc_2m() -> Option<PhysFrame<Size2MiB>> {
        if let Some(frame) = buddy_alloc_frame_2m() {
            return Some(frame);
        }
        alloc_frame_2m()
    }

    /// 1GBフレームを割り当て
    pub fn alloc_1g() -> Option<PhysFrame<Size1GiB>> {
        if let Some(frame) = buddy_alloc_frame_1g() {
            return Some(frame);
        }
        alloc_frame_1g()
    }

    /// 4KBフレームを解放
    /// 
    /// アドレスを両方のアロケータで試みる
    pub fn dealloc_4k(frame: PhysFrame<Size4KiB>) {
        // Buddyで管理されているかチェック
        if buddy_allocator::is_managed_by_buddy(frame.start_address()) {
            buddy_dealloc_frame(frame);
        } else {
            dealloc_frame(frame);
        }
    }

    /// 2MBフレームを解放
    pub fn dealloc_2m(frame: PhysFrame<Size2MiB>) {
        if buddy_allocator::is_managed_by_buddy(frame.start_address()) {
            buddy_dealloc_frame_2m(frame);
        } else {
            // Bitmapでは2MB解放は512x4KBとして処理
            for i in 0..512 {
                let offset = i * 4096;
                let addr = x86_64::PhysAddr::new(frame.start_address().as_u64() + offset);
                if let Some(small_frame) = PhysFrame::<Size4KiB>::from_start_address(addr).ok() {
                    dealloc_frame(small_frame);
                }
            }
        }
    }

    /// 1GBフレームを解放
    pub fn dealloc_1g(frame: PhysFrame<Size1GiB>) {
        if buddy_allocator::is_managed_by_buddy(frame.start_address()) {
            buddy_dealloc_frame_1g(frame);
        }
        // Bitmapでは1GB解放は複雑すぎるため非サポート
    }

    /// 統計を取得
    pub fn stats() -> UnifiedAllocatorStats {
        let (bitmap_free, bitmap_total_usize) = frame_allocator_stats();
        let buddy = buddy_allocator_stats();
        
        UnifiedAllocatorStats {
            bitmap_total: bitmap_total_usize as u64,
            bitmap_used: bitmap_total_usize as u64 - bitmap_free,
            buddy_total: buddy.total_frames as u64,
            buddy_used: buddy.total_frames as u64 - buddy.free_frames,
        }
    }
}

/// 統一アロケータ統計
#[derive(Debug, Clone, Copy)]
pub struct UnifiedAllocatorStats {
    /// Bitmapアロケータの総フレーム数
    pub bitmap_total: u64,
    /// Bitmapアロケータの使用フレーム数
    pub bitmap_used: u64,
    /// Buddyアロケータの総フレーム数
    pub buddy_total: u64,
    /// Buddyアロケータの使用フレーム数
    pub buddy_used: u64,
}

impl UnifiedAllocatorStats {
    /// 総フレーム数
    pub fn total_frames(&self) -> u64 {
        self.bitmap_total + self.buddy_total
    }

    /// 使用フレーム数
    pub fn used_frames(&self) -> u64 {
        self.bitmap_used + self.buddy_used
    }

    /// 空きフレーム数
    pub fn free_frames(&self) -> u64 {
        self.total_frames() - self.used_frames()
    }
}
