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
