//! Canonical heap and allocator namespace.

mod allocator;
mod exchange_blocks;
mod exchange_cache;
mod memory;
pub(crate) use exchange_blocks::ExchangeBlocks;
pub use exchange_blocks::ExtendedHeapStats;
pub(crate) use exchange_cache::{CacheClass, CachedAllocation, ExchangeCache};
pub(crate) use memory::{BootstrapHeaps, HeapMemory};

pub use allocator::{
    ALLOCATOR, free_memory_kb, heap_stats, is_initialized, oom, total_memory_kb, used_memory_kb,
    verify_buddy_integrity,
};

pub(crate) use allocator::{init, physical_memory_offset, set_physical_memory_offset};

#[cfg(test)]
mod exchange_blocks_tests;
#[cfg(test)]
mod exchange_tests;
