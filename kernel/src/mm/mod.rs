#![allow(dead_code)]
// ============================================================================
// Memory Management Module
// 設計書 5: メモリ管理戦略 - 階層型アロケータ設計
// ============================================================================

// === Foundation (共通型・ユーティリティ) ===
pub mod types;        // 共通型定義（FrameIndex, NumaNodeId, AddressUnit）
pub mod atomic_utils; // アトミック操作ユーティリティ（AtomicU8, AtomicU16）
pub mod bitmap;       // 階層ビットマップ（IOVA_MM_MIGRATION_PLAN Phase 1.2）
pub mod remote_free;  // リモートフリーリング（IOVA_MM_MIGRATION_PLAN Phase 1.3）
pub mod per_cpu;      // Per-CPUデータ管理

// === Physical Frame Allocators (物理フレームアロケータ) ===
pub mod buddy_allocator;  // O(log n) バディシステム
pub mod buddy_freelist;   // フリーリストベースBuddy + ページモビリティ（feature-gated）
pub mod fast_allocator;   // High-Performance Bitmap Allocator
pub mod frame_allocator;  // PMM物理フレーム管理（主インターフェース）
pub mod per_node_buddy;   // Per-NUMA-Node Buddy Allocator
pub mod frame_magazine;   // Per-CPU Frame Magazine (PCP)
pub mod unified_alloc;    // 統一フレームアロケータAPI

// === Cache & Optimization (キャッシュ・最適化レイヤー) ===
pub mod arena;          // Single-Writer Arena
pub mod exchange_heap;  // ゼロコピーIPC用ヒープ
pub mod magazine;       // ジェネリックマガジンキャッシュ
pub mod slab_cache;     // Per-Core Slabキャッシュ
pub mod slab_registry;  // Slab Merging Registry
pub mod zeroed_pool;    // PMM Idle Zeroing
pub mod zero_page;      // Non-Temporal ゼロクリア + スクラビング

// === Virtual Memory (仮想メモリ管理) ===
pub mod higher_half;    // ページテーブル管理
pub mod mapping;        // 物理↔仮想アドレス変換
pub mod mmap;           // メモリマッピングAPI
pub mod address_space;  // プロセスアドレス空間管理
pub mod fault_handler;  // Page Fault Handler
pub mod rcu_vma;        // RCU VMA/PageTable Walk
pub mod cow;            // Copy-on-Write
pub mod demand_paging;  // Demand Paging
pub mod stack_growth;   // 自動スタック拡張

// === Page Reclamation (ページ回収・圧力管理) ===
pub mod page_reclaim;   // Page Reclaim + LRU + MGLRU
pub mod shrinker;       // Shrinker Framework
pub mod workingset;     // Workingset Refault Detection
pub mod zswap;          // ZSWAP - スワップ前メモリ圧縮キャッシュ
pub mod async_swapout;  // 非同期スワップアウト

// === NUMA ===
pub mod numa;              // NUMAトポロジ
pub mod autonuma;          // AutoNUMA - 自動ページマイグレーション
pub mod domain_ownership;  // ドメインオーナーシップ追跡

// === Synchronization (同期プリミティブ) ===
pub mod rcu;              // RCU (Read-Copy-Update)
pub mod tlb_batch;        // TLB Shootdown Batching
pub mod page_table_cache; // Page Table Quicklist
pub mod pcid;             // PCID (Process Context ID) Management

// === Page Metadata (ページメタデータ・アカウンティング) ===
pub mod page_flags;     // ページメタデータフラグ
pub mod folio;          // Folio (Compound Page) support
pub mod frame_backing;  // Frame backing tracker
pub mod memcg;          // Memory Cgroup

// === Advanced Features (高度な機能) ===
pub mod thp_promotion;       // Transparent Huge Page Promotion
pub mod memory_compaction;   // Memory Compaction - 断片化解消
pub mod huge_page;           // Huge Page Direct Allocation
pub mod hotplug;             // Memory Hotplug
pub mod balloon;             // Memory Ballooning
pub mod ksm;                 // KSM (Kernel Same-page Merging)

// === Grouping Facades (グループファサード) ===
// 新規コードは facade 経由のアクセスを推奨: mm::allocator::frame_allocator::alloc_frame()
pub mod allocator;  // 物理フレームアロケータ群
pub mod cache;      // キャッシュ・最適化レイヤー
pub mod virt;       // 仮想メモリ管理
pub mod reclaim;    // ページ回収・圧力管理
pub mod numa_group; // NUMAサポート
pub mod sync_group; // MM同期プリミティブ
pub mod page_meta;  // ページメタデータ・アカウンティング

// ============================================================================
// 後方互換: Re-exports (既存コードの crate::mm::foo パスを維持)
// ============================================================================

// --- Foundation ---
pub use types::{NumaNodeId, PAGE_SIZE_4K, PAGE_SIZE_2M, PAGE_SIZE_1G};
#[allow(unused_imports)]
pub use types::{MappedAddress, MappingOffset, MappingSize};

// --- Allocators ---
#[allow(unused_imports)]
pub use buddy_allocator::{
    BuddyAllocatorStats, buddy_alloc_frame, buddy_alloc_frame_1g, buddy_alloc_frame_2m,
    buddy_alloc_contiguous_frames, buddy_alloc_frame_on_node, buddy_alloc_frame_2m_on_node,
    buddy_alloc_frame_1g_on_node,
    buddy_register_numa_region, buddy_allocator_stats, buddy_dealloc_frame, buddy_dealloc_frame_1g, buddy_dealloc_frame_2m,
    init_buddy_allocator,
};
#[cfg(feature = "buddy_freelist")]
#[allow(unused_imports)]
pub use buddy_freelist::{
    freelist_alloc_frame, freelist_alloc_frame_2m, freelist_alloc_frame_1g,
    freelist_dealloc_frame, freelist_dealloc_frame_2m, freelist_dealloc_frame_1g,
    freelist_buddy_stats, init_freelist_buddy,
    FreeListBuddyStats, MigrateType, AllocFlags,
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
pub use unified_alloc::{
    FrameAllocatorType, UnifiedFrameAllocator, UnifiedAllocatorStats,
    memory_pressure_level,
};

// --- Cache ---
#[allow(unused_imports)]
pub use exchange_heap::{
    ExchangeHeap,
    HeapStats,
    allocate_on_exchange,
    allocate_slice_default,
    allocate_slice_with,
    allocate_uninit_slice,
    allocate_zeroed_slice,
    deallocate_on_exchange,
    deallocate_raw,
    deallocate_slice,
    exchange_heap_stats,
    init_exchange_heap,
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
    per_core_alloc_auto,
    per_core_dealloc,
    per_core_dealloc_auto,
    TypedSlabCache,
    TypedSlabStats,
    SlabCtor,
    SlabDtor,
};

// --- Virtual Memory ---
#[allow(unused_imports)]
pub use higher_half::{
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
    physical_memory_offset, phys_to_virt as mapping_phys_to_virt,
    virt_to_phys as mapping_virt_to_phys,
};
#[allow(unused_imports)]
pub use mmap::{
    MappingFlags, MemoryMapping, MmapError, MmapManager,
    mmap, mmap_manager, mprotect, msync, munmap,
};
#[allow(unused_imports)]
pub use address_space::{
    ProcessAddressSpace,
    AddressSpaceManager,
    AddressSpaceError,
    AddressSpaceStats,
    MemoryRegion,
    RegionType,
    Protection,
    Protection as AddressSpaceProtection,
    FileBackingInfo,
    USER_SPACE_START,
    USER_SPACE_END,
    KERNEL_SPACE_START,
    DEFAULT_HEAP_START,
    DEFAULT_STACK_TOP,
    DEFAULT_MMAP_BASE,
    address_space_manager,
    create_address_space,
    destroy_address_space,
    switch_address_space,
    current_asid,
};

// --- Reclamation ---
#[allow(unused_imports)]
pub use page_reclaim::{
    lru_add_page,
    lru_add_page_on_node,
    lru_mark_accessed,
    PageType as LruPageType,
    MemoryPressure,
    check_memory_pressure,
    try_to_free_pages,
    init_page_reclaim,
};

// --- Per-CPU ---
#[allow(unused_imports)]
pub use per_cpu::{
    MAX_CPUS, PerCpuData, active_cpu_count, current_cpu_id, current_per_cpu, current_per_cpu_mut,
    enable_fsgsbase, enter_interrupt, exit_interrupt, get_per_cpu, in_interrupt_context,
    init_per_cpu, is_fsgsbase_enabled, mark_cpu_online, online_cpu_ids, setup_current_cpu,
    try_current_cpu_id,
};

// --- Synchronization ---
#[allow(unused_imports)]
pub use rcu::{
    RcuReadGuard,
    rcu_read_lock,
    rcu_read_active,
    rcu_current_epoch,
    rcu_advance_epoch,
    rcu_note_context_switch,
    synchronize_rcu,
    call_rcu,
    rcu_process_callbacks,
    rcu_pending_callbacks,
    RcuPointer,
    RcuPtr,
    PerCpuRcuState,
    RcuStats,
    rcu_stats,
};
#[allow(unused_imports)]
pub use page_table_cache::{
    alloc_page_table_page,
    free_page_table_page,
    page_table_cache_stats,
};

// --- Page Metadata ---
#[allow(unused_imports)]
pub use frame_backing::{FrameBackingInfo, track_frame_backing, untrack_frame_backing, get_frame_backing};
