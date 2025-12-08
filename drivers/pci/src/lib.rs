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
//! - PCIe extended capabilities (SR-IOV, AER, hotplug)

#![no_std]
#![allow(dead_code)]
#![allow(unused_variables)]

extern crate alloc;

// Core modules
pub mod types;
pub mod traits;

// Access methods
pub mod legacy;
pub mod ecam;

// Bus scanning
pub mod bus;

// MSI/MSI-X support
pub mod msi;

// PCIe extended features
pub mod pcie_ext;

// Re-export core types
pub use types::{
    BdfAddress, BusNumber, DeviceNumber, FunctionNumber,
    VendorId, DeviceId, ClassCode,
    Bar, BarInfo, BarType,
    CapabilityId, ExtendedCapabilityId,
    PciClass,
    config_regs, command_bits, status_bits,
};

pub use traits::{ConfigSpaceAccessor, ExtendedConfigSpaceAccessor};

// Re-export convenience APIs from internal modules for kernel-level usage
pub use legacy::{LegacyPciAccessor, pci_read, pci_write, pci_read16, pci_read8, get_legacy_accessor};
pub use ecam::{EcamAccess, EcamManager};
pub use bus::{PciBusScanner, PciDeviceInfo, scan_all_devices, find_by_class, find_by_id, find_virtio_devices, init};
pub use msi::{MsiConfig, MsiCapability, MsixCapability, MsixTableEntry, DeliveryMode, TriggerMode, allocate_vector, allocate_vectors, setup_msi, setup_msix, disable_intx, enable_intx};
pub use pcie_ext::{
    init_pcie_ext,
    pcie_ext_manager,
    PcieExtManager,
    PcieConfig,
    PcieError,
    PcieResult,
    PcieBdf,
    CorrectableErrors,
    UncorrectableErrors,
    AerCapability,
    AerController,
    PciePowerState,
    PciePowerManager,
    PcieMsixTableEntry,
    PcieMsixController,
    HotPlugController,
    HotPlugEvent,
    PcieExtDevice,
    pcie_ext_config,
    cap_id,
    ext_cap_id,
    PCIE_CONFIG_SIZE,
    PCIE_EXT_CAP_START,
    SriovCapability,
    SriovController,
};
