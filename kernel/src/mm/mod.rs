// ============================================================================
// Memory Management Module
// 設計書 5: メモリ管理戦略 - 階層型アロケータ設計
// ============================================================================
pub mod atomic_utils; // アトミック操作ユーティリティ（AtomicU8, AtomicU16）
pub mod bitmap; // 階層ビットマップ（IOVA_MM_MIGRATION_PLAN Phase 1.2）
pub mod magazine; // ジェネリックマガジンキャッシュ（IOVA_MM_MIGRATION_PLAN Phase 1.1）
pub mod remote_free; // リモートフリーリング（IOVA_MM_MIGRATION_PLAN Phase 1.3）
pub mod types; // 共通型定義（FrameIndex, NumaNodeId, AddressUnit）
pub mod buddy_allocator;
pub mod buddy_freelist; // 新: フリーリストベースBuddy + ページモビリティ
pub mod domain_ownership; // 新: ドメインオーナーシップ追跡 (設計書 5.4, 8.1)
pub mod exchange_heap;
pub mod frame_allocator;
pub mod higher_half;
pub mod huge_pages; // 新: 1GB Huge Page サポート (設計書 11.1.1)
pub mod mapping;
pub mod mmap;
pub mod numa;
pub mod per_cpu;
pub mod slab_cache;
pub mod thp_promotion; // 新: Transparent Huge Page Promotion - 自動THP昇格
pub mod zeroed_pool; // 新: PMM Idle Zeroing - バックグラウンドゼロクリア
pub mod per_node_buddy; // 新: Per-NUMA-Node Buddy Allocator - ノードごとの独立ロック
pub mod frame_magazine; // 新: Per-CPU Frame Magazine (PCP) - ロックフリーフレームキャッシュ
pub mod memory_compaction; // 新: Memory Compaction - 断片化解消
pub mod page_table_cache; // 新: Page Table Quicklist - TLB安全なPTページキャッシュ
pub mod rcu; // 新: RCU (Read-Copy-Update) - 読み取り優位の同期プリミティブ
pub mod zero_page; // 新: Non-Temporal ゼロクリア + バックグラウンドスクラビング
pub mod autonuma; // 新: AutoNUMA - 自動ページマイグレーション
pub mod page_reclaim; // 新: Page Reclaim + LRU - メモリ回収とActive/Inactive管理
pub mod tlb_batch; // 新: TLB Shootdown Batching - バッチ化IPIフラッシュ
pub mod huge_page; // 新: Huge Page Direct Allocation - Direct Compaction付き
pub mod rcu_vma; // 新: RCU VMA/PageTable Walk - ロックフリーVMA検索
pub mod ksm; // 新: KSM (Kernel Same-page Merging) - 重複ページ統合
pub mod hotplug; // 新: Memory Hotplug - 動的メモリ追加/削除
pub mod balloon; // 新: Memory Ballooning - 仮想環境メモリ動的調整
pub mod memcg; // 新: Memory Cgroup - メモリリソース制限とアカウンティング
pub mod frame_backing; // 新: Frame backing tracker (frame -> inode/page) for targeted writeback
#[allow(unused_imports)]
pub use frame_backing::{FrameBackingInfo, track_frame_backing, untrack_frame_backing, get_frame_backing};
pub mod async_swapout; // 新: 非同期スワップアウトと書き戻し合流
pub mod zswap; // 新: ZSWAP - スワップ前メモリ圧縮キャッシュ
pub mod shrinker; // 新: Shrinker Framework - キャッシュ縮小とメモリ圧力通知
pub mod arena; // 新: Single-Writer Arena - ロックフリーPer-CPU割り当て最適化
pub mod fast_allocator; // 新: High-Performance Bitmap Allocator - IOVA/PMM共通アロケータ
pub mod fault_handler; // 新: Page Fault Handler - Demand Paging/CoW/Stack Growth統合
pub mod cow; // 新: Copy-on-Write - ページ参照カウント管理とフォルト時複製
pub mod demand_paging; // 新: Demand Paging - 遅延ページ割り当て
pub mod stack_growth; // 新: Stack Growth - 自動スタック拡張
pub mod address_space; // 新: Process Address Space - プロセスアドレス空間管理


// 共通型を再エクスポート
pub use types::{NumaNodeId, PAGE_SIZE_4K};
// Huge Page 共通定数

// Page Reclaim / LRU API
#[allow(unused_imports)]
pub use page_reclaim::{
    // LRU API
    lru_add_page,
    lru_add_page_on_node,
    lru_mark_accessed,
    // Page types
    PageType as LruPageType,
    // Memory pressure
    MemoryPressure,
    check_memory_pressure,
    try_to_free_pages,
    init_page_reclaim,
};
// アトミックユーティリティを再エクスポート

#[allow(unused_imports)]
pub use buddy_allocator::{
    BuddyAllocatorStats, buddy_alloc_frame, buddy_alloc_frame_1g, buddy_alloc_frame_2m,
    buddy_alloc_contiguous_frames, buddy_alloc_frame_on_node, buddy_alloc_frame_2m_on_node,
    buddy_alloc_frame_1g_on_node,
    buddy_register_numa_region, buddy_allocator_stats, buddy_dealloc_frame, buddy_dealloc_frame_1g, buddy_dealloc_frame_2m,
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
    alloc_frame, alloc_frame_1g, alloc_frame_2m,
    alloc_frame_local, alloc_frame_on_numa_node, dealloc_frame, dealloc_frame_1g, dealloc_frame_2m, frame_allocator_stats,
    init_frame_allocator, init_numa_frame_allocator, init_numa_frame_allocator_from_info,
    is_range_managed_by_pmm, pmm_managed_end, pmm_maintenance_tick, pmm_reconfigure_for_cpu_ids,
    pmm_reconfigure_for_online_cpus, pmm_release_range,
    // Contiguous frame helpers
    alloc_contiguous_frames, dealloc_contiguous_frames,
};
#[allow(unused_imports)]
pub use higher_half::{
    // 既存のエクスポート
    HigherHalfManager,
    MapError,
    PageFlags,
    PageSize,
    PageTable,
    PageTableEntry,
    PageTableManager,
    PageTableWalker,
    PhysAddr,
    PhysicalMemoryMapper,
    VirtAddr,
    flush_tlb,
    get_cr3,
    global_map_page,
    global_translate,
    global_unmap_page,
    global_update_flags,
    init,
    init_page_table_manager,
    invalidate_page,
    phys_to_virt,
    set_cr3,
    virt_to_phys,
};
#[allow(unused_imports)]
pub use mapping::{
    PHYSICAL_MEMORY_OFFSET, phys_to_virt as mapping_phys_to_virt,
    virt_to_phys as mapping_virt_to_phys,
};
#[allow(unused_imports)]
pub use mmap::{
    MappedAddress, MappingFlags, MappingSize, MemoryMapping, MmapError, MmapManager, Protection,
    mmap, mmap_manager, mprotect, msync, munmap,
};
#[allow(unused_imports)]
pub use per_cpu::{
    MAX_CPUS, PerCpuData, active_cpu_count, current_cpu_id, current_per_cpu, current_per_cpu_mut,
    enable_fsgsbase, enter_interrupt, exit_interrupt, get_per_cpu, in_interrupt_context,
    init_per_cpu, is_fsgsbase_enabled, mark_cpu_online, online_cpu_ids, setup_current_cpu,
    try_current_cpu_id,
};
#[allow(unused_imports)]
pub use slab_cache::{
    PerCoreCache,
    SLAB_SIZES,
    SlabCache,
    SlabStats,
    init_per_core_caches,
    init_per_core_cache_for_cpu,
    per_core_alloc,
    // GsBaseを使った自動CPU ID取得API
    per_core_alloc_auto,
    per_core_dealloc,
    per_core_dealloc_auto,
    // コンストラクタ/デストラクタ付きTyped Slab Cache
    TypedSlabCache,
    TypedSlabStats,
    SlabCtor,
    SlabDtor,
};

// RCU (Read-Copy-Update) 同期プリミティブ
#[allow(unused_imports)]
pub use rcu::{
    // Read-side API
    RcuReadGuard,
    rcu_read_lock,
    rcu_read_active,
    // Write-side / Grace period API
    rcu_current_epoch,
    rcu_advance_epoch,
    rcu_note_context_switch,
    synchronize_rcu,
    // Deferred callback API
    call_rcu,
    rcu_process_callbacks,
    rcu_pending_callbacks,
    // RCU-protected pointer
    RcuPtr,
    // Per-CPU state
    PerCpuRcuState,
    // Statistics
    RcuStats,
    rcu_stats,
};

// Page Table Quicklist (TLB-safe page table page cache)
#[allow(unused_imports)]
pub use page_table_cache::{
    alloc_page_table_page,
    free_page_table_page,
    page_table_cache_stats,
};

// ============================================================================
// 統一フレームアロケータインターフェース
//
// 設計方針:
// - PMM fast allocator（bitmap + per-CPU magazine）を主経路
// - 旧Buddy/Bitmapは後方互換/非常用
// - 新規コードは UnifiedFrameAllocator を使用すること
// ============================================================================

use x86_64::structures::paging::{PhysFrame, Size1GiB, Size2MiB, Size4KiB};

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
    /// デフォルトでPMM fastを使用（後方互換フォールバックあり）
    pub fn alloc_4k() -> Option<PhysFrame<Size4KiB>> {
        alloc_frame()
    }

    /// 2MBフレームを割り当て
    pub fn alloc_2m() -> Option<PhysFrame<Size2MiB>> {
        alloc_frame_2m()
    }

    /// 1GBフレームを割り当て
    pub fn alloc_1g() -> Option<PhysFrame<Size1GiB>> {
        alloc_frame_1g()
    }

    /// 4KBフレームを解放
    ///
    /// PMM fast へ返却
    pub fn dealloc_4k(frame: PhysFrame<Size4KiB>) {
        dealloc_frame(frame);
    }

    /// 2MBフレームを解放
    pub fn dealloc_2m(frame: PhysFrame<Size2MiB>) {
        dealloc_frame_2m(frame);
    }

    /// 1GBフレームを解放
    pub fn dealloc_1g(frame: PhysFrame<Size1GiB>) {
        dealloc_frame_1g(frame);
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

// ============================================================================
// Memory Pressure Detection
// ============================================================================

/// Get the current memory pressure level (0-100).
///
/// Returns:
/// - 0-25: Low pressure (plenty of free memory)
/// - 25-50: Medium pressure (consider cleanup)
/// - 50-75: High pressure (aggressive cleanup needed)
/// - 75-100: Critical pressure (emergency measures)
///
/// The pressure is calculated based on the percentage of used physical frames
/// from the buddy allocator, with adjustments for free page count thresholds.
pub fn memory_pressure_level() -> u8 {
    let stats = buddy_allocator_stats();

    if stats.total_frames == 0 {
        return 0; // No memory tracked yet
    }

    // Calculate usage percentage
    let used = stats.total_frames.saturating_sub(stats.free_frames as usize);
    let usage_percent = (used * 100 / stats.total_frames) as u8;

    // Apply thresholds for more nuanced pressure detection
    // If we have less than 1GB free (262144 4KB frames), increase pressure
    const LOW_FREE_THRESHOLD: u64 = 262144; // ~1GB
    const CRITICAL_FREE_THRESHOLD: u64 = 65536; // ~256MB

    let pressure = if stats.free_frames < CRITICAL_FREE_THRESHOLD {
        // Critical: less than 256MB free
        core::cmp::max(usage_percent, 80)
    } else if stats.free_frames < LOW_FREE_THRESHOLD {
        // Low free memory: apply mild boost
        core::cmp::min(usage_percent.saturating_add(10), 100)
    } else {
        usage_percent
    };

    pressure
}

// ============================================================================
// Address Space Management API
// ============================================================================

#[allow(unused_imports)]
pub use address_space::{
    // Core types
    ProcessAddressSpace,
    AddressSpaceManager,
    AddressSpaceError,
    AddressSpaceStats,
    // Region types
    MemoryRegion,
    RegionType,
    Protection as AddressSpaceProtection,
    FileBackingInfo,
    // Constants
    USER_SPACE_START,
    USER_SPACE_END,
    KERNEL_SPACE_START,
    DEFAULT_HEAP_START,
    DEFAULT_STACK_TOP,
    DEFAULT_MMAP_BASE,
    // Global API
    address_space_manager,
    create_address_space,
    destroy_address_space,
    switch_address_space,
    current_asid,
};
