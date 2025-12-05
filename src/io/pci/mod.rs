// ============================================================================
// src/io/pci/mod.rs - PCI/PCIe Common Module
// ============================================================================
//!
//! # PCI/PCIe 共通モジュール
//!
//! PCI と PCIe の両方で使用される共通トレイトと定義を提供。
//!
//! ## モジュール構成
//! - `traits`: ConfigSpaceAccessor トレイト
//! - `types`: BDF、レジスタオフセットなどの型定義
//! - `legacy`: 従来のI/Oポートベースのアクセス
//! - `ecam`: ECAM (Enhanced Configuration Access Mechanism)
//! - `bus`: PCIバス列挙

#![allow(dead_code)]

pub mod traits;
pub mod types;
pub mod legacy;
pub mod ecam;
pub mod bus;
pub mod msi;

// Re-exports for convenient access
pub use traits::ConfigSpaceAccessor;
pub use types::{BdfAddress, Bar, ClassCode, VendorId, DeviceId};
pub use legacy::{LegacyPciAccessor, pci_read, pci_write, pci_read16, pci_read8, get_legacy_accessor};
pub use ecam::{EcamAccess, EcamManager};
pub use bus::{
    PciBusScanner, PciDeviceInfo, CapabilityId, config_regs, command_bits, status_bits,
    scan_all_devices, find_by_class, find_by_id, find_virtio_devices, init,
};
pub use msi::{
    MsiConfig, MsiCapability, MsixCapability, MsixTableEntry,
    DeliveryMode, TriggerMode,
    allocate_vector, allocate_vectors, setup_msi, setup_msix,
    disable_intx, enable_intx,
};
