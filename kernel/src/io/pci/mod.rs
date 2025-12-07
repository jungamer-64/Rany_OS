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
//! - `pcie_ext`: PCIe拡張機能 (SR-IOV, AER, 電源管理, ホットプラグ)

#![allow(dead_code)]

pub mod traits;
pub mod types;
pub mod legacy;
pub mod ecam;
pub mod bus;
pub mod msi;
pub mod pcie_ext;

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

// PCIe拡張機能のエクスポート
pub use pcie_ext::{
    // 定数
    cap_id, ext_cap_id,
    PCIE_CONFIG_SIZE, PCIE_EXT_CAP_START,
    // エラー型
    PcieError, PcieResult,
    // BDF
    PcieBdf,
    // コンフィグアクセス
    PcieConfig,
    // SR-IOV
    SriovCapability, SriovController,
    // AER
    CorrectableErrors, UncorrectableErrors, AerCapability, AerController,
    // 電源管理
    PciePowerState, PciePowerManager,
    // MSI-X拡張
    PcieMsixTableEntry, PcieMsixController,
    // ホットプラグ
    HotPlugEvent, HotPlugController,
    // マネージャ
    PcieExtDevice, PcieExtManager,
    // 初期化
    init_pcie_ext, pcie_ext_manager, pcie_ext_config,
};

