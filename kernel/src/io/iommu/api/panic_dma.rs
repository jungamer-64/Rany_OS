// ============================================================================
// kernel/src/io/iommu/api/panic_dma.rs
// ============================================================================

pub use crate::io::iommu::runtime::panic::{
    PanicDmaRecordInfo, init_panic_dma_pool, init_panic_dma_pool_default, last_panic_record,
    last_panic_record_message, write_panic_record,
};
