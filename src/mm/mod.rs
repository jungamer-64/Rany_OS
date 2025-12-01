// ============================================================================
// Memory Management Module
// 設計書 5: メモリ管理戦略 - 階層型アロケータ設計
// ============================================================================
pub mod mapping;
pub mod exchange_heap;
pub mod frame_allocator;
pub mod slab_cache;

pub use mapping::{phys_to_virt, virt_to_phys, PHYSICAL_MEMORY_OFFSET};
pub use exchange_heap::{
    init_exchange_heap, ExchangeHeap, HeapStats,
    allocate_on_exchange, deallocate_on_exchange, deallocate_raw,
    exchange_heap_stats,
};
pub use frame_allocator::{
    init_frame_allocator, alloc_frame, alloc_frame_2m, alloc_frame_1g,
    dealloc_frame, frame_allocator_stats,
    PAGE_SIZE_4K, PAGE_SIZE_2M, PAGE_SIZE_1G,
};
pub use slab_cache::{
    init_per_core_caches, per_core_alloc, per_core_dealloc,
    PerCoreCache, SlabCache, SlabStats, SLAB_SIZES,
};
