// ============================================================================
// src/io/pci/mod.rs - PCI/PCIe Module (Re-exports from pci_driver crate)
// ============================================================================
//!
//! # PCI/PCIe Module
//!
//! This module now re-exports from the `pci_driver` crate.
//! All implementation has been moved to `drivers/pci/`.
pub use pci_driver::*;

// Convenience re-exports for common types
pub use pci_driver::{
    AerCapability,
    AerController,
    Bar,
    // Types
    BdfAddress,
    CapabilityId,
    ClassCode,
    // Traits
    ConfigSpaceAccessor,
    CorrectableErrors,
    DeliveryMode,
    DeviceId,
    HotPlugController,
    HotPlugEvent,
    MsiCapability,
    // MSI/MSI-X
    MsiConfig,
    MsixCapability,
    MsixTableEntry,
    PCIE_CONFIG_SIZE,
    PCIE_EXT_CAP_START,
    // Bus scanning
    PciBusScanner,
    PciDeviceInfo,
    PcieBdf,
    PcieConfig,
    PcieError,
    PcieExtDevice,
    PcieExtManager,
    PcieMsixController,
    PcieMsixTableEntry,
    PciePowerManager,
    PciePowerState,
    PcieResult,
    SriovCapability,
    SriovController,
    TriggerMode,
    UncorrectableErrors,
    VendorId,
    allocate_vector,
    allocate_vectors,
    // PCIe extensions
    cap_id,
    command_bits,
    config_regs,
    disable_intx,
    enable_intx,
    ext_cap_id,
    find_by_class,
    find_by_id,
    init,
    init_pcie_ext,
    pcie_ext_config,
    pcie_ext_manager,
    scan_all_devices,
    setup_msi,
    setup_msix,
    status_bits,
};
