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

#![forbid(unsafe_code)]

use crate::error::{Mlx5Error, Mlx5Result};
use crate::registers::InitializationRegisters;
use crate::regs::fw_state;
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
    /// Decodes the integer representation published by firmware.
    pub(crate) fn from_revision_words(revision: u32, interface: u32) -> Self {
        Self {
            major: (revision >> 16) as u16,
            minor: revision as u16,
            subminor: interface as u16,
            cmd_if_rev: (interface >> 16) as u16,
        }
    }
}

/// Polls only the retained initialization aperture. Neither readiness nor
/// elapsed time proves that prior DMA ownership has been revoked.
pub(crate) fn wait_fw_ready(
    registers: &InitializationRegisters,
    timeout_ms: u32,
) -> Mlx5Result<FwInfo> {
    let clock = kernel_api::service::kernel::instance();
    let start_ms = clock.current_tick();
    let mut invalid_reads = 0u32;
    // The clock can stop during early boot. A finite read budget independently
    // terminates this polling path instead of relying on interrupt delivery.
    for _ in 0..100_000_000u32 {
        if clock.current_tick().saturating_sub(start_ms) >= u64::from(timeout_ms) {
            break;
        }
        let initializing = registers.initializing()?;
        let interface = registers.command_revision()?;
        if (initializing == 0 || initializing == u32::MAX)
            && (interface == 0 || interface == u32::MAX)
        {
            invalid_reads += 1;
            if invalid_reads >= 100_000 {
                return Err(Mlx5Error::DeviceNotReady);
            }
            for _ in 0..1000 {
                core::hint::spin_loop();
            }
            continue;
        }
        invalid_reads = 0;
        if initializing & fw_state::INITIALIZING_BIT == 0 {
            if registers.health_counter()? == fw_state::HEALTH_FATAL {
                let bytes = registers.health_buffer()?;
                let layout = HealthLayout::new(&bytes);
                log::error!(target: "mlx5", "FW fatal: syndrome={:#x}, ext_syndrome={:#x}, full_reset={}",
                    layout.syndrome(), layout.ext_syndrome(), layout.full_reset_required());
                return Err(Mlx5Error::FirmwareInitFailed);
            }
            let (revision, interface) = registers.revisions()?;
            return Ok(FwInfo::from_revision_words(revision, interface));
        }
        core::hint::spin_loop();
    }
    Err(Mlx5Error::DeviceNotReady)
}

#[cfg(test)]
mod tests {
    use super::FwInfo;
    #[test]
    fn revision_words_preserve_all_four_integer_fields() {
        let info = FwInfo::from_revision_words(0x1234_abcd, 0xffff_5678);
        assert_eq!(
            (info.major, info.minor, info.subminor, info.cmd_if_rev),
            (0x1234, 0xabcd, 0x5678, 0xffff)
        );
    }
}
