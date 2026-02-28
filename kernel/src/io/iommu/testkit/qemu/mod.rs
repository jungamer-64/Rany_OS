// ============================================================================
// kernel/src/io/iommu/tests/qemu/mod.rs
// ============================================================================

use alloc::sync::Arc;

pub(crate) use crate::io::iommu::backends::amd as amd_backend;
pub(crate) use crate::io::iommu::runtime::command::queue as cmdqueue;
pub(crate) use crate::io::iommu::core::domain;
pub(crate) use crate::io::iommu::runtime::fault_log;
pub(crate) use crate::io::iommu::runtime::groups;
pub(crate) use crate::io::iommu::backends::intel;
pub(crate) use crate::io::iommu::core::dma::mapping_slab;
pub(crate) use crate::io::iommu::core::dma::page_table_pool;
pub(crate) use crate::io::iommu::runtime::security;
pub(crate) use crate::io::iommu::core::tables;
pub(crate) use crate::io::iommu::core::types;

pub mod amd;
pub mod wave2;
pub mod wave3;
pub mod group_tests;
