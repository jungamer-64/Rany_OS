// ============================================================================
// kernel/src/io/iommu/api/pci.rs
// ============================================================================

#[cfg(not(test))]
pub use crate::io::iommu::runtime::pci::{
    setup_iommu_for_all_pci_devices, setup_iommu_for_pci_device,
};
