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

pub(crate) fn boot_trace_cmd_error(opcode: defs::CmdOpcode, uid: u16, status: u8, syndrome: u32) {
    if let Some(name) = boot_opcode_name(opcode) {
        if let Some(serial) = kernel_api::service::serial::try_instance() {
            let _ = serial.write(0, b"[MLX5_CMD] ");
            let _ = serial.write(0, name.as_bytes());
            let _ = serial.write(0, b" status_err uid=0x");
            let mut uid_hex = [0u8; 4];
            encode_hex_u16(uid, &mut uid_hex);
            let _ = serial.write(0, &uid_hex);
            let _ = serial.write(0, b" status=0x");
            let mut status_hex = [0u8; 2];
            encode_hex_u8(status, &mut status_hex);
            let _ = serial.write(0, &status_hex);
            let _ = serial.write(0, b" syndrome=0x");
            let mut syndrome_hex = [0u8; 8];
            encode_hex_u32(syndrome, &mut syndrome_hex);
            let _ = serial.write(0, &syndrome_hex);
            let _ = serial.write(0, b"\n");
        }
    }
}

pub(crate) fn boot_trace_sq_state(
    sqn: u32,
    min_inline_mode: u8,
    tis_lst_sz: u16,
    tis_num_0: u32,
    wq_type: u8,
    effective_tisn: u32,
) {
    if let Some(serial) = kernel_api::service::serial::try_instance() {
        let _ = serial.write(0, b"[MLX5_SQ] sqn=0x");
        let mut sqn_hex = [0u8; 8];
        encode_hex_u32(sqn, &mut sqn_hex);
        let _ = serial.write(0, &sqn_hex);
        let _ = serial.write(0, b" inl=0x");
        let mut inl_hex = [0u8; 2];
        encode_hex_u8(min_inline_mode, &mut inl_hex);
        let _ = serial.write(0, &inl_hex);
        let _ = serial.write(0, b" tis_lst=0x");
        let mut lst_hex = [0u8; 4];
        encode_hex_u16(tis_lst_sz, &mut lst_hex);
        let _ = serial.write(0, &lst_hex);
        let _ = serial.write(0, b" tis0=0x");
        let mut tis_hex = [0u8; 8];
        encode_hex_u32(tis_num_0, &mut tis_hex);
        let _ = serial.write(0, &tis_hex);
        let _ = serial.write(0, b" wq=0x");
        let mut wq_hex = [0u8; 2];
        encode_hex_u8(wq_type, &mut wq_hex);
        let _ = serial.write(0, &wq_hex);
        let _ = serial.write(0, b" eff=0x");
        let mut eff_hex = [0u8; 8];
        encode_hex_u32(effective_tisn, &mut eff_hex);
        let _ = serial.write(0, &eff_hex);
        let _ = serial.write(0, b"\n");
    }
}

pub(crate) fn boot_trace_tis_choice(label: &str, tisn: u32) {
    if let Some(serial) = kernel_api::service::serial::try_instance() {
        let _ = serial.write(0, b"[MLX5_TIS] ");
        let _ = serial.write(0, label.as_bytes());
        let _ = serial.write(0, b" tisn=0x");
        let mut tis_hex = [0u8; 8];
        encode_hex_u32(tisn, &mut tis_hex);
        let _ = serial.write(0, &tis_hex);
        let _ = serial.write(0, b"\n");
    }
}

pub(crate) fn boot_trace_tis_attempt(
    label: &str,
    attempt_name: &str,
    td: u32,
    pd: u32,
    include_pd: bool,
    port: u8,
    prio: u8,
    underlay_qpn: u32,
    op_mod: u16,
    lag_port: u8,
    strict_lag: bool,
) {
    if let Some(serial) = kernel_api::service::serial::try_instance() {
        let _ = serial.write(0, b"[MLX5_TIS] ");
        let _ = serial.write(0, label.as_bytes());
        let _ = serial.write(0, b" ");
        let _ = serial.write(0, attempt_name.as_bytes());
        let _ = serial.write(0, b" td=0x");
        let mut td_hex = [0u8; 8];
        encode_hex_u32(td, &mut td_hex);
        let _ = serial.write(0, &td_hex);
        let _ = serial.write(0, b" pd=0x");
        let mut pd_hex = [0u8; 8];
        encode_hex_u32(pd, &mut pd_hex);
        let _ = serial.write(0, &pd_hex);
        let _ = serial.write(0, b" use_pd=");
        let _ = serial.write(0, if include_pd { b"1" } else { b"0" });
        let _ = serial.write(0, b" port=0x");
        let mut port_hex = [0u8; 2];
        encode_hex_u8(port, &mut port_hex);
        let _ = serial.write(0, &port_hex);
        let _ = serial.write(0, b" prio=0x");
        let mut prio_hex = [0u8; 2];
        encode_hex_u8(prio, &mut prio_hex);
        let _ = serial.write(0, &prio_hex);
        let _ = serial.write(0, b" underlay=0x");
        let mut underlay_hex = [0u8; 8];
        encode_hex_u32(underlay_qpn, &mut underlay_hex);
        let _ = serial.write(0, &underlay_hex);
        let _ = serial.write(0, b" opmod=0x");
        let mut op_mod_hex = [0u8; 4];
        encode_hex_u16(op_mod, &mut op_mod_hex);
        let _ = serial.write(0, &op_mod_hex);
        let _ = serial.write(0, b" lag=0x");
        let mut lag_hex = [0u8; 2];
        encode_hex_u8(lag_port, &mut lag_hex);
        let _ = serial.write(0, &lag_hex);
        let _ = serial.write(0, b" strict=");
        let _ = serial.write(0, if strict_lag { b"1" } else { b"0" });
        let _ = serial.write(0, b"\n");
    }
}

pub(crate) fn boot_trace_tis_attempt_result(
    label: &str,
    attempt_name: &str,
    status: u8,
    syndrome: u32,
) {
    if let Some(serial) = kernel_api::service::serial::try_instance() {
        let _ = serial.write(0, b"[MLX5_TIS] ");
        let _ = serial.write(0, label.as_bytes());
        let _ = serial.write(0, b" ");
        let _ = serial.write(0, attempt_name.as_bytes());
        let _ = serial.write(0, b" status=0x");
        let mut status_hex = [0u8; 2];
        encode_hex_u8(status, &mut status_hex);
        let _ = serial.write(0, &status_hex);
        let _ = serial.write(0, b" syndrome=0x");
        let mut syndrome_hex = [0u8; 8];
        encode_hex_u32(syndrome, &mut syndrome_hex);
        let _ = serial.write(0, &syndrome_hex);
        let _ = serial.write(0, b"\n");
    }
}

pub(crate) fn boot_trace_tis_query(label: &str, tisn: u32, info: &crate::cmd::res::QueryTisInfo) {
    if let Some(serial) = kernel_api::service::serial::try_instance() {
        let _ = serial.write(0, b"[MLX5_TIS] ");
        let _ = serial.write(0, label.as_bytes());
        let _ = serial.write(0, b" tisn=0x");
        let mut tis_hex = [0u8; 8];
        encode_hex_u32(tisn, &mut tis_hex);
        let _ = serial.write(0, &tis_hex);
        let _ = serial.write(0, b" td=0x");
        let mut td_hex = [0u8; 8];
        encode_hex_u32(info.transport_domain, &mut td_hex);
        let _ = serial.write(0, &td_hex);
        let _ = serial.write(0, b" pd=0x");
        let mut pd_hex = [0u8; 8];
        encode_hex_u32(info.pd, &mut pd_hex);
        let _ = serial.write(0, &pd_hex);
        let _ = serial.write(0, b" prio=0x");
        let mut prio_hex = [0u8; 2];
        encode_hex_u8(info.prio, &mut prio_hex);
        let _ = serial.write(0, &prio_hex);
        let _ = serial.write(0, b" underlay=0x");
        let mut underlay_hex = [0u8; 8];
        encode_hex_u32(info.underlay_qpn, &mut underlay_hex);
        let _ = serial.write(0, &underlay_hex);
        let _ = serial.write(0, b" lag=0x");
        let mut lag_hex = [0u8; 2];
        encode_hex_u8(info.lag_tx_port_affinity, &mut lag_hex);
        let _ = serial.write(0, &lag_hex);
        let _ = serial.write(0, b" strict=");
        let _ = serial.write(
            0,
            if info.strict_lag_tx_port_affinity {
                b"1"
            } else {
                b"0"
            },
        );
        let _ = serial.write(0, b" tls=");
        let _ = serial.write(0, if info.tls_en { b"1" } else { b"0" });
        let _ = serial.write(0, b"\n");
    }
}

pub(crate) fn boot_trace_tis_compare(
    label: &str,
    requested: &crate::resources::TisParams,
    include_pd: bool,
    adopted_tisn: u32,
    adopted: &crate::cmd::res::QueryTisInfo,
) {
    if let Some(serial) = kernel_api::service::serial::try_instance() {
        let _ = serial.write(0, b"[MLX5_TIS] ");
        let _ = serial.write(0, label.as_bytes());
        let _ = serial.write(0, b" req_td=0x");
        let mut req_td_hex = [0u8; 8];
        encode_hex_u32(requested.td, &mut req_td_hex);
        let _ = serial.write(0, &req_td_hex);
        let _ = serial.write(0, b" req_pd=0x");
        let mut req_pd_hex = [0u8; 8];
        encode_hex_u32(requested.pd, &mut req_pd_hex);
        let _ = serial.write(0, &req_pd_hex);
        let _ = serial.write(0, b" req_use_pd=");
        let _ = serial.write(0, if include_pd { b"1" } else { b"0" });
        let _ = serial.write(0, b" req_port=0x");
        let mut req_port_hex = [0u8; 2];
        encode_hex_u8(requested.port, &mut req_port_hex);
        let _ = serial.write(0, &req_port_hex);
        let _ = serial.write(0, b" req_prio=0x");
        let mut req_prio_hex = [0u8; 2];
        encode_hex_u8(requested.prio, &mut req_prio_hex);
        let _ = serial.write(0, &req_prio_hex);
        let _ = serial.write(0, b" adopted=0x");
        let mut tis_hex = [0u8; 8];
        encode_hex_u32(adopted_tisn, &mut tis_hex);
        let _ = serial.write(0, &tis_hex);
        let _ = serial.write(0, b" td=0x");
        let mut td_hex = [0u8; 8];
        encode_hex_u32(adopted.transport_domain, &mut td_hex);
        let _ = serial.write(0, &td_hex);
        let _ = serial.write(0, b" pd=0x");
        let mut pd_hex = [0u8; 8];
        encode_hex_u32(adopted.pd, &mut pd_hex);
        let _ = serial.write(0, &pd_hex);
        let _ = serial.write(0, b" prio=0x");
        let mut prio_hex = [0u8; 2];
        encode_hex_u8(adopted.prio, &mut prio_hex);
        let _ = serial.write(0, &prio_hex);
        let _ = serial.write(0, b" underlay=0x");
        let mut underlay_hex = [0u8; 8];
        encode_hex_u32(adopted.underlay_qpn, &mut underlay_hex);
        let _ = serial.write(0, &underlay_hex);
        let _ = serial.write(0, b" lag=0x");
        let mut lag_hex = [0u8; 2];
        encode_hex_u8(adopted.lag_tx_port_affinity, &mut lag_hex);
        let _ = serial.write(0, &lag_hex);
        let _ = serial.write(0, b" strict=");
        let _ = serial.write(
            0,
            if adopted.strict_lag_tx_port_affinity {
                b"1"
            } else {
                b"0"
            },
        );
        let _ = serial.write(0, b" tls=");
        let _ = serial.write(0, if adopted.tls_en { b"1" } else { b"0" });
        let _ = serial.write(0, b"\n");
    }
}

pub(crate) fn boot_trace_mailbox_range(
    tag: &str,
    mbox: &crate::cmd::CmdMailbox,
    start: usize,
    dwords: usize,
) {
    let aligned_start = start & !0x3;
    let max_bytes = crate::defs::MLX5_CMD_MBOX_SIZE.saturating_sub(aligned_start);
    let count = dwords.min(max_bytes / 4).min(128);

    if let Some(serial) = kernel_api::service::serial::try_instance() {
        for i in 0..count {
            let off = aligned_start + i * 4;
            let _ = serial.write(0, b"[MLX5_DUMP] ");
            let _ = serial.write(0, tag.as_bytes());
            let _ = serial.write(0, b"[0x");
            let mut off_hex = [0u8; 4];
            encode_hex_u16(off as u16, &mut off_hex);
            let _ = serial.write(0, &off_hex);
            let _ = serial.write(0, b"]=0x");
            let mut val_hex = [0u8; 8];
            encode_hex_u32(mbox.read_be32(off), &mut val_hex);
            let _ = serial.write(0, &val_hex);
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

#[inline]
fn encode_hex_u8(mut value: u8, out: &mut [u8; 2]) {
    for i in (0..2).rev() {
        let nibble = value & 0x0f;
        out[i] = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + (nibble - 10)
        };
        value >>= 4;
    }
}

#[inline]
fn encode_hex_u32(mut value: u32, out: &mut [u8; 8]) {
    for i in (0..8).rev() {
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
        defs::CmdOpcode::QueryMkey => Some("query_mkey"),
        defs::CmdOpcode::CreateEq => Some("create_eq"),
        defs::CmdOpcode::CreateCq => Some("create_cq"),
        defs::CmdOpcode::CreateQp => Some("create_qp"),
        defs::CmdOpcode::CreateTis => Some("create_tis"),
        defs::CmdOpcode::CreateSq => Some("create_sq"),
        defs::CmdOpcode::ModifySq => Some("modify_sq"),
        defs::CmdOpcode::QuerySq => Some("query_sq"),
        defs::CmdOpcode::CreateRq => Some("create_rq"),
        defs::CmdOpcode::QueryRq => Some("query_rq"),
        defs::CmdOpcode::ModifyRq => Some("modify_rq"),
        defs::CmdOpcode::CreateRmp => Some("create_rmp"),
        defs::CmdOpcode::ModifyRmp => Some("modify_rmp"),
        defs::CmdOpcode::CreateRqt => Some("create_rqt"),
        defs::CmdOpcode::CreateTir => Some("create_tir"),
        defs::CmdOpcode::CreateFlowTable => Some("create_flow_table"),
        defs::CmdOpcode::CreateFlowGroup => Some("create_flow_group"),
        defs::CmdOpcode::SetFlowTableEntry => Some("set_flow_table_entry"),
        defs::CmdOpcode::ModifyVportState => Some("modify_vport_state"),
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

kernel_api::export_async_driver!(
    type: crate::ffi::Mlx5AsyncDriver,
    constructor: crate::ffi::Mlx5AsyncDriver::new(),
    name: crate::ffi::mlx5_driver_name,
    driver_type: kernel_api::driver::DriverType::Network,
    version: kernel_api::abi::driver::pack_version(0, 1, 0)
);
