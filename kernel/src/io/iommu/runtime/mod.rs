// ============================================================================
// kernel/src/io/iommu/runtime/mod.rs
// ============================================================================

pub(crate) use crate::io::iommu::backend;
pub(crate) use crate::io::iommu::config;
pub(crate) use crate::io::iommu::fault_log;
pub(crate) use crate::io::iommu::groups;
pub(crate) use crate::io::iommu::irq;
pub(crate) use crate::io::iommu::panic;
#[cfg(not(test))]
pub(crate) use crate::io::iommu::pci;
pub(crate) use crate::io::iommu::registry;
pub(crate) use crate::io::iommu::security;
pub(crate) use crate::io::iommu::stats;

pub(crate) mod command {
    pub(crate) use crate::io::iommu::cmdqueue as queue;
}

pub(crate) mod quarantine {
    pub(crate) use crate::io::iommu::quarantine;
}

pub(crate) mod zombie {
    pub(crate) use crate::io::iommu::zombie_queue;
}
