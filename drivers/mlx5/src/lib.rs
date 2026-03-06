// ============================================================================
// drivers/mlx5/src/lib.rs - NVIDIA/Mellanox ConnectX Family (mlx5) Ethernet Driver
// ============================================================================
//!
//! # ConnectX Family (mlx5) Ethernet Driver
//!
//! NVIDIA/Mellanox ConnectX ファミリ NIC ドライバ。
//! ConnectX-4 / 4 Lx / 5 / 5 Ex / 6 / 6 Dx / 6 Lx / 7 をサポート。
//!
//! ## Architecture
//!
//! - **Command Interface**: メールボックス経由の初期化コマンド
//! - **Event Queue (EQ)**: MSI-X割り込みに対応するイベント通知
//! - **Completion Queue (CQ)**: 送受信完了通知
//! - **Send Queue (SQ)**: 送信リングバッファ
//! - **Receive Queue (RQ)**: 受信リングバッファ
//!
//! ## ExoRust Design
//!
//! - Safe Rustで実装（FFI境界のunsafeはFramework層に集約）
//! - ゼロコピーパスを維持（バッファ所有権の移動で管理）
//! - Async-First: 将来的にFutureベースのI/Oに移行可能

#![no_std]
#![allow(dead_code)]
#![allow(unsafe_op_in_unsafe_fn)] // HWレジスタ操作: Rust 2024移行は段階的に実施
#![allow(clippy::unreadable_literal)] // PCIレジスタ定数
#![allow(clippy::cast_possible_truncation)] // 64-bit kernel, u64->usize safe
#![allow(clippy::cast_lossless)] // u8->u32 etc
#![allow(clippy::doc_markdown)] // ConnectX, MSI-X 等のフォーマット名
#![allow(clippy::missing_safety_doc)]

extern crate alloc;

#[cfg(feature = "standalone")]
kernel_api::register_cell_runtime!();

pub mod bootstrap;
pub mod cmd;
pub mod cq;
pub mod defs;
pub mod device;
pub mod eq;
pub mod error;
pub mod ffi;
pub mod flow;
pub mod fw;
pub mod health;
pub mod pages;
pub mod polling;
pub mod port;
pub mod regs;
pub mod resources;
mod structs; // low‑level layout helpers used internally
pub mod wq;

#[inline]
pub(crate) fn mmio_read_be32(addr: usize) -> u32 {
    u32::from_be(hal::mmio::mmio_read_u32(addr))
}

#[inline]
pub(crate) fn mmio_write_be32(addr: usize, value: u32) {
    hal::mmio::mmio_write_u32(addr, value.to_be());
}

// Re-export core types
pub use defs::{
    CONNECTX4_DEVICE_ID, CONNECTX4_LX_DEVICE_ID, CONNECTX4_LX_VF_DEVICE_ID, CONNECTX5_DEVICE_ID,
    CONNECTX5_EX_DEVICE_ID, CONNECTX6_DEVICE_ID, CONNECTX6_DX_DEVICE_ID, CONNECTX6_LX_DEVICE_ID,
    CONNECTX7_DEVICE_ID, ConnectXVariant, MELLANOX_VENDOR_ID, MLX5_MAX_PORTS, SUPPORTED_DEVICE_IDS,
};
pub use bootstrap::{
    Mlx5AllocatedResources, Mlx5BootstrapConfig, Mlx5BootstrapPlan, Mlx5DmaRegion,
    Mlx5PciIdentity, Mlx5QueueDmaRegion, Mlx5QueueProfile,
};
pub use device::Mlx5Device;
pub use error::Mlx5Error;
pub use health::HealthMonitor;
pub use polling::{AdaptivePollingState, PollingMode};
pub use port::Mlx5Port;
pub use resources::{MkeyInfo, TirInfo, TisInfo};

#[cfg(feature = "export_driver_entry")]
kernel_api::export_async_driver!(
    type: crate::ffi::Mlx5AsyncDriver,
    constructor: crate::ffi::Mlx5AsyncDriver::new(),
    name: crate::ffi::mlx5_driver_name,
    driver_type: kernel_api::driver::DriverType::Network,
    version: kernel_api::driver_abi::pack_version(0, 1, 0)
);
