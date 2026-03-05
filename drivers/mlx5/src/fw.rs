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
///
/// 出力メールボックスのレイアウト（General Device Capabilities）:
/// - offset 0x10: max_cqe
/// - offset 0x14: max_sq
/// - offset 0x18: max_rq
/// - etc.
pub fn parse_hca_caps(out_data: &[u8]) -> HcaCaps {
    // QUERY_HCA_CAP out layout:
    // [0x00..0x10): status/syndrome/reserved
    // [0x10..): capability union (cmd_hca_cap for op_mod=0)
    let cap = out_data.get(0x10..).unwrap_or(&[]);

    let read_bits = |bit_off: usize, bit_len: usize| -> u32 {
        let mut v = 0u32;
        for i in 0..bit_len {
            let bit = bit_off + i;
            let byte_idx = bit / 8;
            let bit_in_byte = 7 - (bit % 8);
            let b = cap
                .get(byte_idx)
                .map(|byte| (byte >> bit_in_byte) & 0x1)
                .unwrap_or(0);
            v = (v << 1) | (b as u32);
        }
        v
    };

    // mlx5_ifc_cmd_hca_cap_bits bit fields (Linux mlx5_ifc.h).
    let log_max_qp_sz = read_bits(0x88, 0x8) as u8;
    let log_max_cq_sz = read_bits(0xC8, 0x8) as u8;
    let log_max_eq_sz = read_bits(0xE0, 0x8) as u8;
    let log_max_mkey = read_bits(0xEA, 0x6) as u8;
    let log_max_cq = read_bits(0xDB, 0x5) as u8;
    let log_max_eq = read_bits(0xFC, 0x4) as u8;
    let log_max_transport_domain = read_bits(0x323, 0x5) as u8;
    let log_max_tir = read_bits(0x373, 0x5) as u8;
    let log_max_tis = read_bits(0x37B, 0x5) as u8;
    let log_max_tis_per_sq = read_bits(0x39B, 0x5) as u8;
    let tis_tir_td_order = read_bits(0x2A9, 0x1) != 0;
    let num_ports = read_bits(0x1B8, 0x8) as u8;
    let vport_group_manager = read_bits(0x1B0, 0x1) != 0;
    let eswitch_manager = read_bits(0x1B1, 0x1) != 0;
    let num_vhca_ports = read_bits(0x1C0, 0x8) as u16;

    let cqe_version = read_bits(0x1FC, 0x4) as u8;
    let csum_cap = read_bits(0x21D, 0x1) != 0; // eth_net_offloads

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
        scatter_fcs: false,
        vlan_strip: false,
        csum_cap,
        cqe_compression: false,
        cqe_version,
        tis_tir_td_order,
        vport_group_manager,
        eswitch_manager,
        num_vhca_ports,
    }
}
