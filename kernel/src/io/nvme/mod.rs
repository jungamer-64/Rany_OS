// ============================================================================
// src/io/nvme/mod.rs - NVMe Kernel Integration (Minimal)
// ============================================================================
//!
//! # NVMe Kernel統合モジュール (最小化版)
//!
//! kernel内部で必要な機能のみを再エクスポート。
//! ドライバ実装は `nvme_driver` クレートを参照。
//!
//! ## 関連モジュール
//!
//! - [`crate::task::io`] — テスト/ドライバ未初期化時用のNVMe stubモジュール
//! - `drivers/nvme/` — 外部NVMeドライバセル実装

#![allow(dead_code)]

use crate::io::iommu::types::DeviceId as IommuDeviceId;
use crate::sync::PoisonLock;

// Kernel-local modules
pub mod block_io;
pub(crate) mod dma;
pub mod ns_mount;
pub mod scheduler;

// ============================================================================
// IOMMU Device Registration (Kernel-only)
// ============================================================================

static NVME_IOMMU_DEVICE: PoisonLock<Option<IommuDeviceId>> = PoisonLock::new(None);

/// Register NVMe device ID for IOMMU mapping
pub fn set_iommu_device(device: IommuDeviceId) {
    *NVME_IOMMU_DEVICE.lock().unwrap_or_else(|e| e.into_inner()) = Some(device);
}

/// Get NVMe device ID for IOMMU mapping
pub fn iommu_device() -> IommuDeviceId {
    (*NVME_IOMMU_DEVICE.lock().unwrap_or_else(|e| e.into_inner()))
        .expect("NVMe IOMMU device must be registered before DMA use")
}

// ============================================================================
// Minimal Re-exports (only items actually used by kernel)
// ============================================================================

// Global driver access
pub use nvme_driver::global;
pub use nvme_driver::global::{init as init_nvme_polling, with_driver, with_driver_mut};

// Per-core queue management
pub use nvme_driver::per_core;

// Polling driver type
pub use nvme_driver::polling_driver::NvmePollingDriver;

// Error types (used by kernel error conversions)
pub use nvme_driver::defs;
pub use nvme_driver::defs::NvmeError;
pub use nvme_driver::defs::SglDescriptor;

// Scheduler integration (kernel-local)
pub use scheduler::{NvmePollHandler, register_with_io_scheduler};

// NVMe Namespace FS integration
pub use block_io::NvmeBlockIoAdapter;
pub use ns_mount::{mount_nvme_ns_fs, nvme_ns_fs, unmount_nvme_ns_fs};
