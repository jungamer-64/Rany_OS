//! Canonical heap and allocator namespace.

mod allocator;

pub use allocator::{
    ALLOCATOR, EXCHANGE_HEAP_SIZE, HEAP_SIZE, ensure_global_heap_ready, free_memory_kb, heap_stats,
    init, is_initialized, oom, set_heap_deallocation_enabled, total_memory_kb, used_memory_kb,
    verify_buddy_integrity,
};

pub(crate) use allocator::{
    LockedBuddyHeap, checked_store_usize, checked_volatile_write_usize, exchange_heap_start,
    get_default_memory_regions, physical_memory_offset, print_memory_stats,
    reclaim_acpi_reclaimable, set_physical_memory_offset,
};
