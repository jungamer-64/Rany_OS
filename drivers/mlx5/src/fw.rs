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

use crate::error::{Mlx5Error, Mlx5Result};
use crate::regs::{fw_state, init_seg};
use crate::structs::health::HealthLayout;

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
pub unsafe fn wait_fw_ready(bar0_base: u64, timeout_ms: u32) -> Mlx5Result<FwInfo> {
    let base = bar0_base as usize;
    let start_ms = kernel_api::service::kernel::instance().current_tick();

    let mut invalid_reads = 0u64;
    let mut last_inaccessible_log = 0u64;

    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while kernel_api::service::kernel::instance().current_tick() - start_ms < timeout_ms as u64 {
        let initializing = crate::mmio_read_be32(base + init_seg::INITIALIZING);
        let cmdif_rev_fw_sub = crate::mmio_read_be32(base + init_seg::CMDIF_REV_FW_SUB);

        // BAR inaccessible check (often seen on VFs when PF is initializing)
        if (initializing == 0 || initializing == u32::MAX)
            && (cmdif_rev_fw_sub == 0 || cmdif_rev_fw_sub == u32::MAX)
        {
            invalid_reads = invalid_reads.saturating_add(1);
            let now = kernel_api::service::kernel::instance().current_tick();

            // Log every 2 seconds if BAR is still inaccessible
            if now - last_inaccessible_log > 2000 {
                log::warn!(target: "mlx5", "BAR0 still inaccessible (PF might be initializing the device), retrying...");
                last_inaccessible_log = now;
            }

            if invalid_reads >= 100000 {
                log::error!(target: "mlx5", "BAR0 remains inaccessible after multiple retries");
                return Err(Mlx5Error::DeviceNotReady);
            }

            // 小さなディレイを入れて CPU 負荷を下げる
            for _ in 0..1000 {
                core::hint::spin_loop();
            }
            continue;
        }
        invalid_reads = 0;

        if (initializing & fw_state::INITIALIZING_BIT) == 0 {
            // Health fatal check
            let health = crate::mmio_read_be32(base + init_seg::HEALTH_COUNTER);
            if health == fw_state::HEALTH_FATAL {
                // Read detailed health buffer for diagnostics
                let mut h_buf = [0u8; 64];
                for (i, dword) in h_buf.chunks_exact_mut(4).enumerate() {
                    let val = crate::mmio_read_be32(base + init_seg::HEALTH_BUFFER + i * 4);
                    dword.copy_from_slice(&val.to_be_bytes());
                }
                let layout = HealthLayout::new(&h_buf);
                log::error!(
                    target: "mlx5",
                    "FW FATAL error detected: syndrome={:#x}, ext_syndrome={:#x}, full_reset={}",
                    layout.syndrome(),
                    layout.ext_syndrome(),
                    layout.full_reset_required()
                );
                return Err(Mlx5Error::FirmwareInitFailed);
            }

            let fw_info = FwInfo::read_from_bar0(bar0_base);
            return Ok(fw_info);
        }

        core::hint::spin_loop();
    }

    log::error!(target: "mlx5", "FW wait timeout ({}ms)", timeout_ms);
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
