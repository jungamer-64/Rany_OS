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
        let fw_rev_raw = hal::mmio::mmio_read_u32(base + init_seg::FW_REV_MAJOR);

        Self {
            major: (fw_rev_raw >> 16) as u16,
            minor: fw_rev_raw as u16,
            subminor: hal::mmio::mmio_read_u32(base + init_seg::FW_REV_SUBMINOR) as u16,
            cmd_if_rev: hal::mmio::mmio_read_u32(base + init_seg::CMD_IF_REV) as u16,
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

    // ポーリング: NIC_INTERFACE のブート完了を待つ
    // FW_STATE レジスタの健全性をチェック
    // NOTE:
    //   This runs inside an async executor task context in the kernel.
    //   Large unbounded spin loops can stall the whole executor and block boot.
    //   Keep the budget tight and fail fast when FW does not become ready.
    let max_iters = 200_000u64;
    let mut invalid_reads = 0u64;

    for _ in 0..max_iters {
        let nic_iface = hal::mmio::mmio_read_u32(base + init_seg::NIC_INTERFACE);

        // MMIO read returning all-zeros/all-ones repeatedly indicates inaccessible BAR
        // or not-ready VF path; fail fast instead of stalling the executor.
        if nic_iface == 0 || nic_iface == u32::MAX {
            invalid_reads = invalid_reads.saturating_add(1);
            if invalid_reads >= 4096 {
                return Err(Mlx5Error::DeviceNotReady);
            }
            core::hint::spin_loop();
            continue;
        } else {
            invalid_reads = 0;
        }

        // ブートフェーズ確認
        let boot_phase = nic_iface & 0x03;
        if boot_phase == fw_state::BOOT_PHASE_DRIVER_READY {
            // ヘルスチェック
            let health = hal::mmio::mmio_read_u32(base + init_seg::HEALTH_COUNTER);
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
    let health = hal::mmio::mmio_read_u32(bar0_base as usize + init_seg::HEALTH_COUNTER);
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
    let read_be32 = |off: usize| -> u32 {
        if off + 4 <= out_data.len() {
            u32::from_be_bytes([
                out_data[off],
                out_data[off + 1],
                out_data[off + 2],
                out_data[off + 3],
            ])
        } else {
            0
        }
    };

    let read_u8 = |off: usize| -> u8 {
        if off < out_data.len() {
            out_data[off]
        } else {
            0
        }
    };

    HcaCaps {
        max_cq: read_be32(0x10) & 0x00FF_FFFF,
        max_sq: read_be32(0x14) & 0x00FF_FFFF,
        max_rq: read_be32(0x18) & 0x00FF_FFFF,
        max_eq: read_be32(0x1C) & 0x00FF_FFFF,
        max_mkey: read_be32(0x20) & 0x00FF_FFFF,
        max_mtu: read_be32(0x28),
        num_ports: read_u8(0x2C),
        log_max_cq_sz: read_u8(0x30) & 0x1F,
        log_max_sq_sz: read_u8(0x31) & 0x1F,
        log_max_rq_sz: read_u8(0x32) & 0x1F,
        log_max_eq_sz: read_u8(0x33) & 0x1F,
        scatter_fcs: (read_u8(0x38) & 0x01) != 0,
        vlan_strip: (read_u8(0x38) & 0x02) != 0,
        csum_cap: (read_u8(0x38) & 0x04) != 0,
        cqe_compression: (read_u8(0x38) & 0x08) != 0,
        cqe_version: read_u8(0x3A),
    }
}
