// ============================================================================
// Memory Management Module
// 設計書 5: メモリ管理戦略 - 階層型アロケータ設計
// ============================================================================
pub mod mapping;
pub mod exchange_heap;
pub mod frame_allocator;
pub mod buddy_allocator;
pub mod slab_cache;
pub mod per_cpu;

#[allow(unused_imports)]
pub use mapping::{phys_to_virt, virt_to_phys, PHYSICAL_MEMORY_OFFSET};
#[allow(unused_imports)]
pub use exchange_heap::{
    init_exchange_heap, ExchangeHeap, HeapStats,
    allocate_on_exchange, deallocate_on_exchange, deallocate_raw,
    exchange_heap_stats,
    // 安全なスライス割り当てAPI
    allocate_zeroed_slice, allocate_uninit_slice,
    allocate_slice_with, allocate_slice_default, deallocate_slice,
};
#[allow(unused_imports)]
pub use frame_allocator::{
    init_frame_allocator, alloc_frame, alloc_frame_2m, alloc_frame_1g,
    dealloc_frame, frame_allocator_stats,
    PAGE_SIZE_4K, PAGE_SIZE_2M, PAGE_SIZE_1G,
};
#[allow(unused_imports)]
pub use buddy_allocator::{
    init_buddy_allocator,
    buddy_alloc_frame, buddy_alloc_frame_2m, buddy_alloc_frame_1g,
    buddy_dealloc_frame, buddy_dealloc_frame_2m, buddy_dealloc_frame_1g,
    buddy_allocator_stats, BuddyAllocatorStats,
};
#[allow(unused_imports)]
pub use slab_cache::{
    init_per_core_caches, per_core_alloc, per_core_dealloc,
    // GsBaseを使った自動CPU ID取得API
    per_core_alloc_auto, per_core_dealloc_auto,
    PerCoreCache, SlabCache, SlabStats, SLAB_SIZES,
};
#[allow(unused_imports)]
pub use per_cpu::{
    init_per_cpu, setup_current_cpu, current_cpu_id, try_current_cpu_id,
    current_per_cpu, current_per_cpu_mut, get_per_cpu,
    active_cpu_count, enable_fsgsbase, is_fsgsbase_enabled,
    PerCpuData, MAX_CPUS,
};
