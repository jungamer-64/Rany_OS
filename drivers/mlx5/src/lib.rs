// ============================================================================
// drivers/mlx5/src/lib.rs - Mellanox ConnectX-4 Lx (mlx5) Ethernet Driver
// ============================================================================
//!
//! # ConnectX-4 Lx (mlx5) Ethernet Driver
//!
//! NVIDIA/Mellanox ConnectX-4 Lx 25GbE NIC ドライバ。
//! MCX4421A-ACQN 等の ConnectX-4 Lx ファミリをサポート。
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

pub mod regs;
pub mod defs;
pub mod cmd;
pub mod eq;
pub mod cq;
pub mod wq;
pub mod port;
pub mod fw;
pub mod device;
pub mod error;

// Re-export core types
pub use defs::{
    MELLANOX_VENDOR_ID, CONNECTX4_LX_DEVICE_ID,
    CONNECTX4_LX_VF_DEVICE_ID, MLX5_MAX_PORTS,
};
pub use error::Mlx5Error;
pub use device::Mlx5Device;
pub use port::Mlx5Port;
