// ============================================================================
// kernel/src/io/iommu/core/mod.rs
// ============================================================================

pub(crate) use crate::io::iommu::domain;
pub(crate) use crate::io::iommu::interface;
pub(crate) use crate::io::iommu::tables;
pub(crate) use crate::io::iommu::types;

pub(crate) mod dma {
    pub(crate) use crate::io::iommu::cache;
    pub(crate) use crate::io::iommu::dma_handle as handle;
    pub(crate) use crate::io::iommu::flush;
    pub(crate) use crate::io::iommu::iova_allocator;
    pub(crate) use crate::io::iommu::mapping_slab;
    pub(crate) use crate::io::iommu::page_table_pool;
}
