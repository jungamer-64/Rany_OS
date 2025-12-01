// ============================================================================
// Memory Management Module
// ============================================================================
pub mod mapping;
pub mod exchange_heap;

pub use mapping::{phys_to_virt, virt_to_phys, PHYSICAL_MEMORY_OFFSET};
pub use exchange_heap::{init_exchange_heap, ExchangeHeap, HeapStats};
