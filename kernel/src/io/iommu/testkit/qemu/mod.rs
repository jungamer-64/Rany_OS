// ============================================================================
// kernel/src/io/iommu/testkit/qemu/mod.rs
// ============================================================================

use alloc::sync::Arc;

pub(crate) use crate::io::iommu::vendors::amd as amd_backend;
pub(crate) use crate::io::iommu::runtime::command::queue as cmdqueue;
pub(crate) use crate::io::iommu::common::domain;
pub(crate) use crate::io::iommu::runtime::fault_log;
pub(crate) use crate::io::iommu::runtime::groups;
pub(crate) use crate::io::iommu::vendors::intel;
pub(crate) use crate::io::iommu::common::dma::mapping_slab;
pub(crate) use crate::io::iommu::common::dma::page_table_pool;
pub(crate) use crate::io::iommu::runtime::security;
pub(crate) use crate::io::iommu::common::tables;
pub(crate) use crate::io::iommu::types;

pub mod amd;
pub mod wave2;
pub mod wave3;
pub mod group_tests;
