// ============================================================================
// src/io/pci/mod.rs - PCI/PCIe Module (Re-exports from pci_driver crate)
// ============================================================================
//!
//! # PCI/PCIe Module
//!
//! This module now re-exports from the `pci_driver` crate.
//! All implementation has been moved to `drivers/pci/`.

#![allow(unused_imports)]

// Re-export everything from pci_driver crate
pub use pci_driver::*;

// Convenience re-exports for common types
pub use pci_driver::{
    // Traits
    ConfigSpaceAccessor,
    // Types
    BdfAddress, Bar, ClassCode, VendorId, DeviceId,
    // Legacy access
    LegacyPciAccessor, pci_read, pci_write, pci_read16, pci_read8, get_legacy_accessor,
    // ECAM
    EcamAccess, EcamManager,
    // Bus scanning
    PciBusScanner, PciDeviceInfo, CapabilityId, config_regs, command_bits, status_bits,
    scan_all_devices, find_by_class, find_by_id, find_virtio_devices, init,
    // MSI/MSI-X
    MsiConfig, MsiCapability, MsixCapability, MsixTableEntry,
    DeliveryMode, TriggerMode,
    allocate_vector, allocate_vectors, setup_msi, setup_msix,
    disable_intx, enable_intx,
    // PCIe extensions
    cap_id, ext_cap_id,
    PCIE_CONFIG_SIZE, PCIE_EXT_CAP_START,
    PcieError, PcieResult, PcieBdf, PcieConfig,
    SriovCapability, SriovController,
    CorrectableErrors, UncorrectableErrors, AerCapability, AerController,
    PciePowerState, PciePowerManager,
    PcieMsixTableEntry, PcieMsixController,
    HotPlugEvent, HotPlugController,
    PcieExtDevice, PcieExtManager,
    init_pcie_ext, pcie_ext_manager, pcie_ext_config,
};
