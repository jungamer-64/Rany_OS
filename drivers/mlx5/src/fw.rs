// ============================================================================
// drivers/mlx5/src/fw.rs - Firmware initialization
// ============================================================================
//! ファームウェア初期化とヘルスチェック
//!
//! HCA (Host Channel Adapter) のブートシーケンス:
//! 1. FW状態ポーリング（ドライバレディ待ち）
//! 2. ENABLE_HCA コマンド
//! 3. QUERY_ISSI → SET_ISSI
//! 4. QUERY_HCA_CAP
//! 5. MANAGE_PAGES（FW要求ページの提供）
//! 6. INIT_HCA
//! 7. リソース作成（EQ, CQ, WQ, etc.）

use crate::defs::HcaCaps;
use crate::error::{Mlx5Error, Mlx5Result};
use crate::regs::{fw_state, init_seg};

/// ファームウェアの状態情報
#[derive(Debug, Clone)]
pub struct FwInfo {
    /// メジャーバージョン
    pub major: u16,
    /// マイナーバージョン
    pub minor: u16,
    /// サブマイナーバージョン
    pub subminor: u16,
    /// コマンドIFリビジョン
    pub cmd_if_rev: u16,
}

impl FwInfo {
    /// BAR0からFW情報を読み取る
    ///
    /// # Safety
    /// - `bar0_base` が有効なMMIOマッピングであること
    pub unsafe fn read_from_bar0(bar0_base: u64) -> Self {
        let base = bar0_base as usize;
        let fw_rev_raw = crate::mmio_read_be32(base + init_seg::FW_REV);
        let cmdif_rev_fw_sub = crate::mmio_read_be32(base + init_seg::CMDIF_REV_FW_SUB);

        Self {
            major: (fw_rev_raw >> 16) as u16,
            minor: (fw_rev_raw & 0xFFFF) as u16,
            subminor: (cmdif_rev_fw_sub & 0xFFFF) as u16,
            cmd_if_rev: (cmdif_rev_fw_sub >> 16) as u16,
        }
    }
}

/// FWがドライバレディになるまでポーリングで待つ
///
/// # Safety
/// - `bar0_base` が有効なMMIOマッピングであること
///
/// # Returns
/// - `Ok(FwInfo)`: FW準備完了
/// - `Err(Mlx5Error)`: タイムアウト
pub unsafe fn wait_fw_ready(bar0_base: u64) -> Mlx5Result<FwInfo> {
    let base = bar0_base as usize;

    // ポーリング: INITIALIZING(bit31) が 0 になるまで待機
    // NOTE:
    //   This runs inside an async executor task context in the kernel.
    //   Large unbounded spin loops can stall the whole executor and block boot.
    //   Keep the budget tight and fail fast when FW does not become ready.
    let max_iters = 200_000u64;
    let mut invalid_reads = 0u64;

    for _ in 0..max_iters {
        let initializing = crate::mmio_read_be32(base + init_seg::INITIALIZING);
        let cmdif_rev_fw_sub = crate::mmio_read_be32(base + init_seg::CMDIF_REV_FW_SUB);

        // MMIO read returning all-zeros/all-ones on both registers repeatedly
        // indicates inaccessible BAR or not-ready VF path.
        if (initializing == 0 || initializing == u32::MAX)
            && (cmdif_rev_fw_sub == 0 || cmdif_rev_fw_sub == u32::MAX)
        {
            invalid_reads = invalid_reads.saturating_add(1);
            if invalid_reads >= 4096 {
                return Err(Mlx5Error::DeviceNotReady);
            }
            core::hint::spin_loop();
            continue;
        }
        invalid_reads = 0;

        if (initializing & fw_state::INITIALIZING_BIT) == 0 {
            // ヘルスチェック
            let health = crate::mmio_read_be32(base + init_seg::HEALTH_COUNTER);
            if health == fw_state::HEALTH_FATAL {
                return Err(Mlx5Error::FirmwareInitFailed);
            }

            let fw_info = FwInfo::read_from_bar0(bar0_base);
            return Ok(fw_info);
        }

        core::hint::spin_loop();
    }

    Err(Mlx5Error::DeviceNotReady)
}

/// FW健全性バッファを確認
///
/// # Safety
/// - `bar0_base` が有効なMMIOマッピングであること
pub unsafe fn check_health(bar0_base: u64) -> bool {
    let health = crate::mmio_read_be32(bar0_base as usize + init_seg::HEALTH_COUNTER);
    health != fw_state::HEALTH_FATAL
}

/// QUERY_HCA_CAP 出力からHcaCapsを解析
pub fn parse_hca_caps(out_data: &[u8]) -> HcaCaps {
    log::info!(target: "mlx5", "QUERY_HCA_CAP decoding start (Offset 0x10):");
    
    let rd_be32 = |data: &[u8], off: usize| -> u32 {
        if off + 4 > data.len() { 0 }
        else { u32::from_be_bytes([data[off], data[off+1], data[off+2], data[off+3]]) }
    };

    // Comparative diagnostics
    for &base_off in &[0x00, 0x10] {
        let dw3 = rd_be32(out_data, base_off + 0x0C);
        let dw6 = rd_be32(out_data, base_off + 0x18);
        log::info!(target: "mlx5", "  Offset {:#x}: num_ports={} log_max_cq={}", base_off, (dw6 >> 24) & 0xFF, (dw3 >> 24) & 0xFF);
    }

    // Standard mlx5 IFC: capability data starts at offset 0x10 in the mailbox
    let cap_base = 0x10usize;
    let rd = |off: usize| -> u32 { rd_be32(out_data, cap_base + off) };

    let dw0 = rd(0x00);
    let vport_group_manager = (dw0 & 0x4000_0000) != 0;

    let dw1 = rd(0x04);
    let log_max_mkey = ((dw1 >> 25) & 0x7F) as u8;

    let dw2 = rd(0x08);
    let log_max_qp_sz = ((dw2 >> 24) & 0xFF) as u8;

    let dw3 = rd(0x0C);
    let log_max_cq = ((dw3 >> 24) & 0xFF) as u8;
    let log_max_cq_sz = ((dw3 >> 16) & 0xFF) as u8;

    let dw4 = rd(0x10);
    let log_max_eq = ((dw4 >> 24) & 0xFF) as u8;
    let log_max_eq_sz = ((dw4 >> 16) & 0xFF) as u8;

    let dw6 = rd(0x18);
    let num_ports = ((dw6 >> 24) & 0xFF) as u8;

    let dw12 = rd(0x30);
    let cqe_version = ((dw12 >> 4) & 0x0F) as u8;

    let dw13 = rd(0x34);
    let eth_net_offloads = (dw13 & 0x0008_0000) != 0;
    let vlan_strip = (dw13 & 0x0004_0000) != 0;
    let scatter_fcs = (dw13 & 0x0002_0000) != 0;

    let dw17 = rd(0x44);
    let tis_tir_td_order = (dw17 & 0x0020_0000) != 0;
    let log_max_transport_domain = (dw17 & 0x1F) as u8;

    let dw20 = rd(0x50);
    let log_max_tir = ((dw20 >> 8) & 0x1F) as u8;
    let log_max_tis = (dw20 & 0x1F) as u8;

    log::info!(target: "mlx5", "Decoded HCA caps: ports={} log_cq={} log_qp={} log_tis={} csum={} vport_mgr={}",
        num_ports, log_max_cq, log_max_qp_sz, log_max_tis, eth_net_offloads, vport_group_manager);

    // VFs might report 0 ports in general caps; assume 1 logically.
    let actual_ports = if num_ports == 0 { 1 } else { num_ports.min(2) };
    let max_cq = 1u32.checked_shl(log_max_cq.min(20) as u32).unwrap_or(64);
    let max_sq_rq = 1u32.checked_shl(log_max_qp_sz.min(20) as u32).unwrap_or(64);

    HcaCaps {
        max_cq,
        max_sq: max_sq_rq,
        max_rq: max_sq_rq,
        max_eq: 1u32.checked_shl(log_max_eq.min(20) as u32).unwrap_or(16),
        max_mkey: 1u32.checked_shl(log_max_mkey.min(20) as u32).unwrap_or(1024),
        max_mtu: 1500,
        num_ports: actual_ports,
        log_max_cq_sz,
        log_max_sq_sz: log_max_qp_sz,
        log_max_rq_sz: log_max_qp_sz,
        log_max_tir,
        log_max_tis,
        log_max_tis_per_sq: 0,
        log_max_transport_domain,
        log_max_eq_sz,
        scatter_fcs,
        vlan_strip,
        csum_cap: eth_net_offloads,
        cqe_compression: false,
        cqe_version,
        tis_tir_td_order,
        vport_group_manager,
        eswitch_manager: false,
        num_vhca_ports: 0,
    }
}
