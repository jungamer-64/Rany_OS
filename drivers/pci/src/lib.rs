// ============================================================================
// drivers/pci/src/lib.rs - PCI/PCIe Driver
// ============================================================================
//!
//! # PCI/PCIe Driver
//!
//! Standalone PCI/PCIe driver with:
//! - Type-safe BDF (Bus/Device/Function) addressing
//! - Configuration space access traits
//! - Legacy I/O and ECAM support
//! - MSI/MSI-X interrupt support
//! - PCIe extended capabilities (`SR-IOV`, AER, hotplug)

#![no_std]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(clippy::unreadable_literal)] // PCI class codes and addresses are standard constants

extern crate alloc;

// Core modules
pub mod traits;
pub mod types;

// Access methods
pub mod ecam;
pub mod legacy;

// Bus scanning
pub mod bus;

// MSI/MSI-X support
pub mod msi;

// PCIe extended features
pub mod pcie_ext;

// Re-export core types
pub use types::{
    Bar, BarInfo, BarType, BdfAddress, BusNumber, CapabilityId, ClassCode, DeviceId, DeviceNumber,
    ExtendedCapabilityId, FunctionNumber, PciClass, VendorId, command_bits, config_regs,
    status_bits,
};

pub use traits::{ConfigSpaceAccessor, ExtendedConfigSpaceAccessor};

// Re-export convenience APIs from internal modules for kernel-level usage
pub use bus::{
    PciBusScanner, PciDeviceInfo, find_by_class, find_by_id, find_virtio_devices, init,
    scan_all_devices,
};
pub use ecam::{EcamAccess, EcamManager};
pub use legacy::{
    LegacyPciAccessor, get_legacy_accessor, pci_read, pci_read8, pci_read16, pci_write,
};
pub use msi::{
    DeliveryMode, MsiCapability, MsiConfig, MsixCapability, MsixTableEntry, TriggerMode,
    allocate_vector, allocate_vectors, disable_intx, enable_intx, setup_msi, setup_msix,
};
pub use pcie_ext::{
    AerCapability, AerController, CorrectableErrors, HotPlugController, HotPlugEvent,
    PCIE_CONFIG_SIZE, PCIE_EXT_CAP_START, PcieBdf, PcieConfig, PcieError, PcieExtDevice,
    PcieExtManager, PcieMsixController, PcieMsixTableEntry, PciePowerManager, PciePowerState,
    PcieResult, SriovCapability, SriovController, UncorrectableErrors, cap_id, ext_cap_id,
    init_pcie_ext, pcie_ext_config, pcie_ext_manager,
};
