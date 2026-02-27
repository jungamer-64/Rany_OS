// ============================================================================
// kernel/src/io/iommu/tests/qemu/mod.rs
// ============================================================================

use alloc::sync::Arc;

pub(crate) use crate::io::iommu::amd;
pub(crate) use crate::io::iommu::cmdqueue;
pub(crate) use crate::io::iommu::domain;
pub(crate) use crate::io::iommu::fault_log;
pub(crate) use crate::io::iommu::groups;
pub(crate) use crate::io::iommu::intel;
pub(crate) use crate::io::iommu::mapping_slab;
pub(crate) use crate::io::iommu::page_table_pool;
pub(crate) use crate::io::iommu::security;
pub(crate) use crate::io::iommu::tables;
pub(crate) use crate::io::iommu::types;

mod amd;
mod wave2;
mod wave3;

pub use amd::*;
pub use wave2::*;
pub use wave3::*;
