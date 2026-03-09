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

pub(crate) fn boot_trace(msg: &str) {
    if let Some(serial) = kernel_api::service::serial::try_instance() {
        let _ = serial.write(0, msg.as_bytes());
    }
}

pub(crate) fn boot_trace_cmd(opcode: defs::CmdOpcode, stage: &str, uid: u16) {
    if let Some(name) = boot_opcode_name(opcode) {
        if let Some(serial) = kernel_api::service::serial::try_instance() {
            let _ = serial.write(0, b"[MLX5_CMD] ");
            let _ = serial.write(0, name.as_bytes());
            let _ = serial.write(0, b" ");
            let _ = serial.write(0, stage.as_bytes());
            let _ = serial.write(0, b" uid=0x");
            let mut uid_hex = [0u8; 4];
            encode_hex_u16(uid, &mut uid_hex);
            let _ = serial.write(0, &uid_hex);
            let _ = serial.write(0, b"\n");
        }
    }
}

#[inline]
fn encode_hex_u16(mut value: u16, out: &mut [u8; 4]) {
    for i in (0..4).rev() {
        let nibble = (value & 0x0f) as u8;
        out[i] = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + (nibble - 10)
        };
        value >>= 4;
    }
}

fn boot_opcode_name(opcode: defs::CmdOpcode) -> Option<&'static str> {
    match opcode {
        defs::CmdOpcode::EnableHca => Some("enable_hca"),
        defs::CmdOpcode::QueryIssi => Some("query_issi"),
        defs::CmdOpcode::SetIssi => Some("set_issi"),
        defs::CmdOpcode::QueryHcaCap => Some("query_hca_cap"),
        defs::CmdOpcode::SetHcaCap => Some("set_hca_cap"),
        defs::CmdOpcode::InitHca => Some("init_hca"),
        defs::CmdOpcode::QueryPages => Some("query_pages"),
        defs::CmdOpcode::ManagePages => Some("manage_pages"),
        defs::CmdOpcode::QueryAdapter => Some("query_adapter"),
        defs::CmdOpcode::QueryVhcaState => Some("query_vhca_state"),
        defs::CmdOpcode::QueryNicVportContext => Some("query_nic_vport_context"),
        defs::CmdOpcode::CreateMkey => Some("create_mkey"),
        defs::CmdOpcode::CreateEq => Some("create_eq"),
        defs::CmdOpcode::CreateCq => Some("create_cq"),
        defs::CmdOpcode::CreateTis => Some("create_tis"),
        defs::CmdOpcode::CreateSq => Some("create_sq"),
        defs::CmdOpcode::CreateRq => Some("create_rq"),
        defs::CmdOpcode::ModifyRq => Some("modify_rq"),
        defs::CmdOpcode::CreateRqt => Some("create_rqt"),
        defs::CmdOpcode::CreateTir => Some("create_tir"),
        _ => None,
    }
}

#[inline]
pub(crate) fn mmio_read_be32(addr: usize) -> u32 {
    u32::from_be(hal::mmio::mmio_read_u32(addr))
}

#[inline]
pub(crate) fn mmio_write_be32(addr: usize, value: u32) {
    hal::mmio::mmio_write_u32(addr, value.to_be());
}

// Re-export core types
pub use bootstrap::{
    Mlx5AllocatedResources, Mlx5BootstrapConfig, Mlx5BootstrapPlan, Mlx5DmaRegion, Mlx5PciIdentity,
    Mlx5QueueDmaRegion, Mlx5QueueProfile,
};
pub use defs::{
    CONNECTX4_DEVICE_ID, CONNECTX4_LX_DEVICE_ID, CONNECTX4_LX_VF_DEVICE_ID, CONNECTX5_DEVICE_ID,
    CONNECTX5_EX_DEVICE_ID, CONNECTX6_DEVICE_ID, CONNECTX6_DX_DEVICE_ID, CONNECTX6_LX_DEVICE_ID,
    CONNECTX7_DEVICE_ID, ConnectXVariant, MELLANOX_VENDOR_ID, MLX5_MAX_PORTS, SUPPORTED_DEVICE_IDS,
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
    version: kernel_api::abi::driver::pack_version(0, 1, 0)
);
