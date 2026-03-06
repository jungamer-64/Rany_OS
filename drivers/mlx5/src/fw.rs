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
    // The capability data starts at offset 0x10 in the mailbox output
    let cap = &out_data[0x10..];

    // Helper to read a big-endian 32-bit word from a byte offset
    let rd = |off: usize| -> u32 {
        if off + 4 > cap.len() {
            return 0;
        }
        u32::from_be_bytes([cap[off], cap[off+1], cap[off+2], cap[off+3]])
    };

    // DW0 [0x00]: [reserved(1)|vport_group_manager(1)|eswitch_manager(1)|...]
    let dw0 = rd(0x00);
    let vport_group_manager = (dw0 & 0x4000_0000) != 0;
    let eswitch_manager = (dw0 & 0x2000_0000) != 0;

    // DW1 [0x04]: [log_max_mkey(7)|reserved(1)|...]
    let dw1 = rd(0x04);
    let log_max_mkey = ((dw1 >> 25) & 0x7F) as u8;

    // DW2 [0x08]: [log_max_qp(8)|...]
    let dw2 = rd(0x08);
    let log_max_qp_sz = ((dw2 >> 24) & 0xFF).max(8) as u8;

    // DW3 [0x0C]: [log_max_cq(8)|log_max_cq_sz(8)|...]
    let dw3 = rd(0x0C);
    let log_max_cq = ((dw3 >> 24) & 0xFF).max(8) as u8;
    let log_max_cq_sz = ((dw3 >> 16) & 0xFF).max(12) as u8;

    // DW4 [0x10]: [log_max_eq(8)|log_max_eq_sz(8)|...]
    let dw4 = rd(0x10);
    let log_max_eq = ((dw4 >> 24) & 0xFF).max(4) as u8;
    let log_max_eq_sz = ((dw4 >> 16) & 0xFF).max(12) as u8;

    // DW6 [0x18]: [num_ports(8)|...]
    let dw6 = rd(0x18);
    let num_ports = ((dw6 >> 24) & 0xFF) as u8;

    // DW7 [0x1C]: [num_vhca_ports(8)|...]
    let dw7 = rd(0x1C);
    let num_vhca_ports = ((dw7 >> 24) & 0xFF) as u16;

    // DW12 [0x30]: [..., cqe_version(4)]
    let dw12 = rd(0x30);
    let cqe_version = ((dw12 >> 4) & 0x0F) as u8;

    // DW13 [0x34]: [..., eth_net_offloads(1)|vlan_strip(1)|scatter_fcs(1)|...]
    let dw13 = rd(0x34);
    let eth_net_offloads = (dw13 & 0x0008_0000) != 0;
    let vlan_strip = (dw13 & 0x0004_0000) != 0;
    let scatter_fcs = (dw13 & 0x0002_0000) != 0;

    // DW17 [0x44]: [..., tis_tir_td_order(1), ..., log_max_transport_domain(5)]
    let dw17 = rd(0x44);
    let tis_tir_td_order = (dw17 & 0x0020_0000) != 0;
    let log_max_transport_domain = (dw17 & 0x1F) as u8;

    // DW20 [0x50]: [..., log_max_tir(5), ..., log_max_tis(5)]
    let dw20 = rd(0x50);
    let log_max_tir = ((dw20 >> 8) & 0x1F) as u8;
    let log_max_tis = (dw20 & 0x1F) as u8;

    // DW22 [0x58]: [..., log_max_tis_per_sq(5)]
    let dw22 = rd(0x58);
    let log_max_tis_per_sq = (dw22 & 0x1F) as u8;

    let max_cq = 1u32.checked_shl(log_max_cq as u32).unwrap_or(0);
    let max_eq = 1u32.checked_shl(log_max_eq as u32).unwrap_or(0);
    let max_sq_rq = 1u32.checked_shl(log_max_qp_sz as u32).unwrap_or(0);
    let max_mkey = 1u32.checked_shl(log_max_mkey as u32).unwrap_or(0);

    HcaCaps {
        max_cq,
        max_sq: max_sq_rq,
        max_rq: max_sq_rq,
        max_eq,
        max_mkey,
        max_mtu: 1500,
        num_ports,
        log_max_cq_sz,
        log_max_sq_sz: log_max_qp_sz,
        log_max_rq_sz: log_max_qp_sz,
        log_max_tir,
        log_max_tis,
        log_max_tis_per_sq,
        log_max_transport_domain,
        log_max_eq_sz,
        scatter_fcs,
        vlan_strip,
        csum_cap: eth_net_offloads,
        cqe_compression: false,
        cqe_version,
        tis_tir_td_order,
        vport_group_manager,
        eswitch_manager,
        num_vhca_ports,
    }
}
