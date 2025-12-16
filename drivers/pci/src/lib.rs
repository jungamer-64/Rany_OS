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
//! - `MSI`/`MSI-X` interrupt support
//! - `PCIe` extended capabilities (`SR-IOV`, AER, hotplug)

#![no_std]
#![allow(dead_code)]
#![allow(unused_variables)]
// PCI driver crate-level allows for hardware-specific patterns
#![allow(clippy::unreadable_literal)] // PCI class codes and addresses are standard constants
#![allow(clippy::must_use_candidate)] // PCI accessor methods
#![allow(clippy::missing_const_for_fn)] // Many functions use sync primitives or allocation
#![allow(clippy::cast_lossless)] // u8->u16, u16->u32, u32->u64 are safe for PCI registers
#![allow(clippy::cast_possible_truncation)] // 64-bit kernel, u64->usize is safe
#![allow(clippy::doc_markdown)] // PCIe, MSI-X, SR-IOV, ECAM format names
#![allow(clippy::use_self)] // Explicit type names for clarity in match arms
#![allow(clippy::semicolon_if_nothing_returned)] // Chained method calls
#![allow(clippy::match_same_arms)] // Intentional for extensibility
#![allow(clippy::type_complexity)] // Complex return types for capability scanning
#![allow(clippy::unused_self)] // Trait consistency
#![allow(clippy::trivially_copy_pass_by_ref)] // API consistency for accessors
#![allow(clippy::map_unwrap_or)] // Kept for readability
#![allow(clippy::collapsible_if)] // Kept for readability
#![allow(clippy::elidable_lifetime_names)] // Explicit lifetimes for clarity

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
