// ============================================================================
// kernel/src/io/iommu/runtime/mod.rs
// ============================================================================

pub(crate) mod backend;
pub(crate) mod config;
pub(crate) mod fault_log;
pub(crate) mod groups;
pub(crate) mod irq;
pub(crate) mod panic;
#[cfg(not(test))]
pub(crate) mod pci;
pub(crate) mod registry;
pub(crate) mod security;
pub(crate) mod stats;

pub(crate) mod command;
pub(crate) mod quarantine;
pub(crate) mod zombie;
