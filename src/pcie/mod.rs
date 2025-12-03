//! PCIe拡張機能
//!
//! PCIe高度な機能の実装
//! - SR-IOV (Single Root I/O Virtualization)
//! - AER (Advanced Error Reporting)
//! - 電源管理
//! - MSI-X
//! - ホットプラグ

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::RwLock;

// =============================================================================
// 定数
// =============================================================================

/// PCIeコンフィグ空間サイズ
const PCIE_CONFIG_SIZE: usize = 4096;

/// PCIe拡張ケイパビリティオフセット
const PCIE_EXT_CAP_START: u16 = 0x100;

/// ケイパビリティID
mod cap_id {
    pub const PM: u8 = 0x01; // Power Management
    pub const MSI: u8 = 0x05; // MSI
    pub const PCIE: u8 = 0x10; // PCI Express
    pub const MSIX: u8 = 0x11; // MSI-X
}

/// 拡張ケイパビリティID
mod ext_cap_id {
    pub const AER: u16 = 0x0001; // Advanced Error Reporting
    pub const SRIOV: u16 = 0x0010; // SR-IOV
    pub const ACS: u16 = 0x000D; // Access Control Services
    pub const ARI: u16 = 0x000E; // Alternative Routing-ID
    pub const LTR: u16 = 0x0018; // Latency Tolerance Reporting
    pub const DPC: u16 = 0x001D; // Downstream Port Containment
}

// =============================================================================
// PCIeエラー
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcieError {
    /// デバイスが見つからない
    DeviceNotFound,
    /// ケイパビリティが見つからない
    CapabilityNotFound,
    /// サポートされていない
    NotSupported,
    /// 設定エラー
    ConfigError,
    /// リソース不足
    ResourceExhausted,
    /// VF割り当て失敗
    VfAllocationFailed,
    /// AERエラー
    AerError,
}

pub type PcieResult<T> = Result<T, PcieError>;

// =============================================================================
// PCIe BDF (Bus/Device/Function)
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PcieBdf {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PcieBdf {
    pub const fn new(bus: u8, device: u8, function: u8) -> Self {
        Self {
            bus,
            device,
            function,
        }
    }

    pub const fn to_u32(&self) -> u32 {
        ((self.bus as u32) << 8) | ((self.device as u32) << 3) | (self.function as u32)
    }

    pub const fn from_u32(value: u32) -> Self {
        Self {
            bus: ((value >> 8) & 0xFF) as u8,
            device: ((value >> 3) & 0x1F) as u8,
            function: (value & 0x07) as u8,
        }
    }
}

// =============================================================================
// PCIeコンフィグ空間アクセス
// =============================================================================

/// PCIe MMIO コンフィグ空間ベース
pub struct PcieConfig {
    base_addr: u64,
    segment: u16,
    start_bus: u8,
    end_bus: u8,
}

impl PcieConfig {
    pub const fn new(base_addr: u64, segment: u16, start_bus: u8, end_bus: u8) -> Self {
        Self {
            base_addr,
            segment,
            start_bus,
            end_bus,
        }
    }

    fn get_config_addr(&self, bdf: PcieBdf, offset: u16) -> Option<*mut u32> {
        if bdf.bus < self.start_bus || bdf.bus > self.end_bus {
            return None;
        }

        let addr = self.base_addr
            + ((bdf.bus as u64) << 20)
            + ((bdf.device as u64) << 15)
            + ((bdf.function as u64) << 12)
            + (offset as u64);

        Some(addr as *mut u32)
    }

    /// コンフィグ空間から読み取り
    pub fn read32(&self, bdf: PcieBdf, offset: u16) -> Option<u32> {
        let addr = self.get_config_addr(bdf, offset)?;
        unsafe { Some(core::ptr::read_volatile(addr)) }
    }

    pub fn read16(&self, bdf: PcieBdf, offset: u16) -> Option<u16> {
        let word_offset = offset & !1;
        let value = self.read32(bdf, word_offset & !3)?;
        let shift = ((offset & 2) * 8) as u32;
        Some(((value >> shift) & 0xFFFF) as u16)
    }

    pub fn read8(&self, bdf: PcieBdf, offset: u16) -> Option<u8> {
        let value = self.read32(bdf, offset & !3)?;
        let shift = ((offset & 3) * 8) as u32;
        Some(((value >> shift) & 0xFF) as u8)
    }

    /// コンフィグ空間に書き込み
    pub fn write32(&self, bdf: PcieBdf, offset: u16, value: u32) -> Option<()> {
        let addr = self.get_config_addr(bdf, offset)?;
        unsafe { core::ptr::write_volatile(addr, value) };
        Some(())
    }

    pub fn write16(&self, bdf: PcieBdf, offset: u16, value: u16) -> Option<()> {
        let dword_offset = offset & !3;
        let shift = ((offset & 2) * 8) as u32;
        let mask = !(0xFFFFu32 << shift);

        let current = self.read32(bdf, dword_offset)?;
        let new_value = (current & mask) | ((value as u32) << shift);
        self.write32(bdf, dword_offset, new_value)
    }

    pub fn write8(&self, bdf: PcieBdf, offset: u16, value: u8) -> Option<()> {
        let dword_offset = offset & !3;
        let shift = ((offset & 3) * 8) as u32;
        let mask = !(0xFFu32 << shift);

        let current = self.read32(bdf, dword_offset)?;
        let new_value = (current & mask) | ((value as u32) << shift);
        self.write32(bdf, dword_offset, new_value)
    }

    /// ケイパビリティを検索
    pub fn find_capability(&self, bdf: PcieBdf, cap_id: u8) -> Option<u8> {
        // Status レジスタのCapabilities Listビットをチェック
        let status = self.read16(bdf, 0x06)?;
        if (status & 0x10) == 0 {
            return None;
        }

        // Capabilities Pointerから開始
        let mut ptr = self.read8(bdf, 0x34)? & 0xFC;

        while ptr != 0 {
            let id = self.read8(bdf, ptr as u16)?;
            if id == cap_id {
                return Some(ptr);
            }
            ptr = self.read8(bdf, (ptr + 1) as u16)? & 0xFC;
        }

        None
    }

    /// 拡張ケイパビリティを検索
    pub fn find_ext_capability(&self, bdf: PcieBdf, ext_cap_id: u16) -> Option<u16> {
        let mut offset = PCIE_EXT_CAP_START;

        while offset != 0 {
            let header = self.read32(bdf, offset)?;
            let id = (header & 0xFFFF) as u16;
            let next = ((header >> 20) & 0xFFF) as u16;

            if id == ext_cap_id {
                return Some(offset);
            }

            offset = next;
        }

        None
    }
}

// =============================================================================
// SR-IOV (Single Root I/O Virtualization)
// =============================================================================

/// SR-IOVケイパビリティ構造
#[derive(Debug, Clone)]
pub struct SriovCapability {
    pub offset: u16,
    pub total_vfs: u16,
    pub num_vfs: u16,
    pub first_vf_offset: u16,
    pub vf_stride: u16,
    pub vf_device_id: u16,
    pub supported_page_sizes: u32,
    pub system_page_size: u32,
}

/// SR-IOVコントローラ
pub struct SriovController {
    config: &'static PcieConfig,
    pf_bdf: PcieBdf,
    capability: Option<SriovCapability>,
    enabled: AtomicBool,
    active_vfs: AtomicU32,
}

impl SriovController {
    pub fn new(config: &'static PcieConfig, pf_bdf: PcieBdf) -> PcieResult<Self> {
        // SR-IOV拡張ケイパビリティを検索
        let offset = config
            .find_ext_capability(pf_bdf, ext_cap_id::SRIOV)
            .ok_or(PcieError::CapabilityNotFound)?;

        // ケイパビリティを読み取り
        let cap = Self::read_capability(config, pf_bdf, offset)?;

        Ok(Self {
            config,
            pf_bdf,
            capability: Some(cap),
            enabled: AtomicBool::new(false),
            active_vfs: AtomicU32::new(0),
        })
    }

    fn read_capability(
        config: &PcieConfig,
        bdf: PcieBdf,
        offset: u16,
    ) -> PcieResult<SriovCapability> {
        let total_vfs = config
            .read16(bdf, offset + 0x0E)
            .ok_or(PcieError::ConfigError)?;
        let num_vfs = config
            .read16(bdf, offset + 0x10)
            .ok_or(PcieError::ConfigError)?;
        let first_vf_offset = config
            .read16(bdf, offset + 0x14)
            .ok_or(PcieError::ConfigError)?;
        let vf_stride = config
            .read16(bdf, offset + 0x16)
            .ok_or(PcieError::ConfigError)?;
        let vf_device_id = config
            .read16(bdf, offset + 0x1A)
            .ok_or(PcieError::ConfigError)?;
        let supported_page_sizes = config
            .read32(bdf, offset + 0x1C)
            .ok_or(PcieError::ConfigError)?;
        let system_page_size = config
            .read32(bdf, offset + 0x20)
            .ok_or(PcieError::ConfigError)?;

        Ok(SriovCapability {
            offset,
            total_vfs,
            num_vfs,
            first_vf_offset,
            vf_stride,
            vf_device_id,
            supported_page_sizes,
            system_page_size,
        })
    }

    /// VFを有効化
    pub fn enable_vfs(&self, num_vfs: u16) -> PcieResult<()> {
        let cap = self
            .capability
            .as_ref()
            .ok_or(PcieError::CapabilityNotFound)?;

        if num_vfs > cap.total_vfs {
            return Err(PcieError::ResourceExhausted);
        }

        let offset = cap.offset;

        // NumVFsを設定
        self.config
            .write16(self.pf_bdf, offset + 0x10, num_vfs)
            .ok_or(PcieError::ConfigError)?;

        // VF Enableビットをセット
        let control = self
            .config
            .read16(self.pf_bdf, offset + 0x08)
            .ok_or(PcieError::ConfigError)?;
        self.config
            .write16(self.pf_bdf, offset + 0x08, control | 0x01)
            .ok_or(PcieError::ConfigError)?;

        // MSE (Memory Space Enable)を設定
        self.config
            .write16(self.pf_bdf, offset + 0x08, control | 0x09)
            .ok_or(PcieError::ConfigError)?;

        self.enabled.store(true, Ordering::SeqCst);
        self.active_vfs.store(num_vfs as u32, Ordering::SeqCst);

        Ok(())
    }

    /// VFを無効化
    pub fn disable_vfs(&self) -> PcieResult<()> {
        let cap = self
            .capability
            .as_ref()
            .ok_or(PcieError::CapabilityNotFound)?;
        let offset = cap.offset;

        // VF Enableビットをクリア
        let control = self
            .config
            .read16(self.pf_bdf, offset + 0x08)
            .ok_or(PcieError::ConfigError)?;
        self.config
            .write16(self.pf_bdf, offset + 0x08, control & !0x01)
            .ok_or(PcieError::ConfigError)?;

        // NumVFsを0に
        self.config
            .write16(self.pf_bdf, offset + 0x10, 0)
            .ok_or(PcieError::ConfigError)?;

        self.enabled.store(false, Ordering::SeqCst);
        self.active_vfs.store(0, Ordering::SeqCst);

        Ok(())
    }

    /// VFのBDFを取得
    pub fn get_vf_bdf(&self, vf_index: u16) -> PcieResult<PcieBdf> {
        let cap = self
            .capability
            .as_ref()
            .ok_or(PcieError::CapabilityNotFound)?;

        if vf_index >= self.active_vfs.load(Ordering::Relaxed) as u16 {
            return Err(PcieError::VfAllocationFailed);
        }

        let pf_rid = self.pf_bdf.to_u32() as u16;
        let vf_rid = pf_rid + cap.first_vf_offset + (vf_index * cap.vf_stride);

        Ok(PcieBdf::from_u32(vf_rid as u32))
    }

    /// ケイパビリティ情報を取得
    pub fn capability(&self) -> Option<&SriovCapability> {
        self.capability.as_ref()
    }

    /// 有効なVF数を取得
    pub fn active_vf_count(&self) -> u32 {
        self.active_vfs.load(Ordering::Relaxed)
    }
}

// =============================================================================
// AER (Advanced Error Reporting)
// =============================================================================

/// 訂正可能エラー
#[derive(Debug, Clone, Copy)]
pub struct CorrectableErrors {
    pub receiver_error: bool,
    pub bad_tlp: bool,
    pub bad_dllp: bool,
    pub replay_num_rollover: bool,
    pub replay_timer_timeout: bool,
    pub advisory_non_fatal: bool,
    pub corrected_internal: bool,
    pub header_log_overflow: bool,
}

/// 訂正不能エラー
#[derive(Debug, Clone, Copy)]
pub struct UncorrectableErrors {
    pub data_link_protocol: bool,
    pub surprise_down: bool,
    pub poisoned_tlp: bool,
    pub flow_control_protocol: bool,
    pub completion_timeout: bool,
    pub completer_abort: bool,
    pub unexpected_completion: bool,
    pub receiver_overflow: bool,
    pub malformed_tlp: bool,
    pub ecrc_error: bool,
    pub unsupported_request: bool,
    pub acs_violation: bool,
    pub uncorrectable_internal: bool,
    pub mc_blocked_tlp: bool,
    pub atomicop_egress_blocked: bool,
    pub tlp_prefix_blocked: bool,
}

/// AERケイパビリティ
#[derive(Debug)]
pub struct AerCapability {
    pub offset: u16,
}

/// AERコントローラ
pub struct AerController {
    config: &'static PcieConfig,
    bdf: PcieBdf,
    capability: Option<AerCapability>,

    // 統計
    correctable_count: AtomicU32,
    uncorrectable_count: AtomicU32,
    fatal_count: AtomicU32,
}

impl AerController {
    pub fn new(config: &'static PcieConfig, bdf: PcieBdf) -> PcieResult<Self> {
        let offset = config
            .find_ext_capability(bdf, ext_cap_id::AER)
            .ok_or(PcieError::CapabilityNotFound)?;

        Ok(Self {
            config,
            bdf,
            capability: Some(AerCapability { offset }),
            correctable_count: AtomicU32::new(0),
            uncorrectable_count: AtomicU32::new(0),
            fatal_count: AtomicU32::new(0),
        })
    }

    /// 訂正可能エラーを読み取り
    pub fn read_correctable_errors(&self) -> PcieResult<CorrectableErrors> {
        let cap = self
            .capability
            .as_ref()
            .ok_or(PcieError::CapabilityNotFound)?;
        let status = self
            .config
            .read32(self.bdf, cap.offset + 0x10)
            .ok_or(PcieError::ConfigError)?;

        Ok(CorrectableErrors {
            receiver_error: (status & (1 << 0)) != 0,
            bad_tlp: (status & (1 << 6)) != 0,
            bad_dllp: (status & (1 << 7)) != 0,
            replay_num_rollover: (status & (1 << 8)) != 0,
            replay_timer_timeout: (status & (1 << 12)) != 0,
            advisory_non_fatal: (status & (1 << 13)) != 0,
            corrected_internal: (status & (1 << 14)) != 0,
            header_log_overflow: (status & (1 << 15)) != 0,
        })
    }

    /// 訂正不能エラーを読み取り
    pub fn read_uncorrectable_errors(&self) -> PcieResult<UncorrectableErrors> {
        let cap = self
            .capability
            .as_ref()
            .ok_or(PcieError::CapabilityNotFound)?;
        let status = self
            .config
            .read32(self.bdf, cap.offset + 0x04)
            .ok_or(PcieError::ConfigError)?;

        Ok(UncorrectableErrors {
            data_link_protocol: (status & (1 << 4)) != 0,
            surprise_down: (status & (1 << 5)) != 0,
            poisoned_tlp: (status & (1 << 12)) != 0,
            flow_control_protocol: (status & (1 << 13)) != 0,
            completion_timeout: (status & (1 << 14)) != 0,
            completer_abort: (status & (1 << 15)) != 0,
            unexpected_completion: (status & (1 << 16)) != 0,
            receiver_overflow: (status & (1 << 17)) != 0,
            malformed_tlp: (status & (1 << 18)) != 0,
            ecrc_error: (status & (1 << 19)) != 0,
            unsupported_request: (status & (1 << 20)) != 0,
            acs_violation: (status & (1 << 21)) != 0,
            uncorrectable_internal: (status & (1 << 22)) != 0,
            mc_blocked_tlp: (status & (1 << 23)) != 0,
            atomicop_egress_blocked: (status & (1 << 24)) != 0,
            tlp_prefix_blocked: (status & (1 << 25)) != 0,
        })
    }

    /// 訂正可能エラーをクリア
    pub fn clear_correctable_errors(&self) -> PcieResult<()> {
        let cap = self
            .capability
            .as_ref()
            .ok_or(PcieError::CapabilityNotFound)?;
        let status = self
            .config
            .read32(self.bdf, cap.offset + 0x10)
            .ok_or(PcieError::ConfigError)?;

        // Write-1-to-clear
        self.config
            .write32(self.bdf, cap.offset + 0x10, status)
            .ok_or(PcieError::ConfigError)?;

        self.correctable_count
            .fetch_add(status.count_ones(), Ordering::Relaxed);
        Ok(())
    }

    /// 訂正不能エラーをクリア
    pub fn clear_uncorrectable_errors(&self) -> PcieResult<()> {
        let cap = self
            .capability
            .as_ref()
            .ok_or(PcieError::CapabilityNotFound)?;
        let status = self
            .config
            .read32(self.bdf, cap.offset + 0x04)
            .ok_or(PcieError::ConfigError)?;

        // 重大度をチェック
        let severity = self
            .config
            .read32(self.bdf, cap.offset + 0x0C)
            .ok_or(PcieError::ConfigError)?;
        let fatal = status & severity;

        // Write-1-to-clear
        self.config
            .write32(self.bdf, cap.offset + 0x04, status)
            .ok_or(PcieError::ConfigError)?;

        self.uncorrectable_count
            .fetch_add(status.count_ones(), Ordering::Relaxed);
        if fatal != 0 {
            self.fatal_count
                .fetch_add(fatal.count_ones(), Ordering::Relaxed);
        }

        Ok(())
    }

    /// ヘッダーログを読み取り
    pub fn read_header_log(&self) -> PcieResult<[u32; 4]> {
        let cap = self
            .capability
            .as_ref()
            .ok_or(PcieError::CapabilityNotFound)?;

        let mut log = [0u32; 4];
        for i in 0..4 {
            log[i] = self
                .config
                .read32(self.bdf, cap.offset + 0x1C + (i as u16 * 4))
                .ok_or(PcieError::ConfigError)?;
        }

        Ok(log)
    }

    /// エラーマスクを設定
    pub fn set_correctable_mask(&self, mask: u32) -> PcieResult<()> {
        let cap = self
            .capability
            .as_ref()
            .ok_or(PcieError::CapabilityNotFound)?;
        self.config
            .write32(self.bdf, cap.offset + 0x14, mask)
            .ok_or(PcieError::ConfigError)
    }

    pub fn set_uncorrectable_mask(&self, mask: u32) -> PcieResult<()> {
        let cap = self
            .capability
            .as_ref()
            .ok_or(PcieError::CapabilityNotFound)?;
        self.config
            .write32(self.bdf, cap.offset + 0x08, mask)
            .ok_or(PcieError::ConfigError)
    }

    /// 統計を取得
    pub fn stats(&self) -> (u32, u32, u32) {
        (
            self.correctable_count.load(Ordering::Relaxed),
            self.uncorrectable_count.load(Ordering::Relaxed),
            self.fatal_count.load(Ordering::Relaxed),
        )
    }
}

// =============================================================================
// 電源管理
// =============================================================================

/// PCIe電源状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciePowerState {
    D0,     // Fully On
    D1,     // Light Sleep
    D2,     // Deeper Sleep
    D3Hot,  // Software controlled off
    D3Cold, // Hardware controlled off
}

/// 電源管理コントローラ
pub struct PciePowerManager {
    config: &'static PcieConfig,
    bdf: PcieBdf,
    pm_offset: Option<u8>,
}

impl PciePowerManager {
    pub fn new(config: &'static PcieConfig, bdf: PcieBdf) -> PcieResult<Self> {
        let pm_offset = config.find_capability(bdf, cap_id::PM);

        Ok(Self {
            config,
            bdf,
            pm_offset,
        })
    }

    /// 現在の電源状態を取得
    pub fn current_state(&self) -> PcieResult<PciePowerState> {
        let offset = self.pm_offset.ok_or(PcieError::CapabilityNotFound)?;
        let pmcsr = self
            .config
            .read16(self.bdf, offset as u16 + 4)
            .ok_or(PcieError::ConfigError)?;

        match pmcsr & 0x03 {
            0 => Ok(PciePowerState::D0),
            1 => Ok(PciePowerState::D1),
            2 => Ok(PciePowerState::D2),
            3 => Ok(PciePowerState::D3Hot),
            _ => unreachable!(),
        }
    }

    /// 電源状態を設定
    pub fn set_state(&self, state: PciePowerState) -> PcieResult<()> {
        let offset = self.pm_offset.ok_or(PcieError::CapabilityNotFound)?;

        // サポートされる状態をチェック
        let pmcap = self
            .config
            .read16(self.bdf, offset as u16 + 2)
            .ok_or(PcieError::ConfigError)?;

        let state_bits = match state {
            PciePowerState::D0 => 0,
            PciePowerState::D1 => {
                if (pmcap & (1 << 9)) == 0 {
                    return Err(PcieError::NotSupported);
                }
                1
            }
            PciePowerState::D2 => {
                if (pmcap & (1 << 10)) == 0 {
                    return Err(PcieError::NotSupported);
                }
                2
            }
            PciePowerState::D3Hot => 3,
            PciePowerState::D3Cold => return Err(PcieError::NotSupported),
        };

        // PMCSR を更新
        let pmcsr = self
            .config
            .read16(self.bdf, offset as u16 + 4)
            .ok_or(PcieError::ConfigError)?;
        let new_pmcsr = (pmcsr & !0x03) | state_bits;
        self.config
            .write16(self.bdf, offset as u16 + 4, new_pmcsr)
            .ok_or(PcieError::ConfigError)
    }

    /// PMEを有効化
    pub fn enable_pme(&self) -> PcieResult<()> {
        let offset = self.pm_offset.ok_or(PcieError::CapabilityNotFound)?;
        let pmcsr = self
            .config
            .read16(self.bdf, offset as u16 + 4)
            .ok_or(PcieError::ConfigError)?;

        // PME_En ビットをセット
        self.config
            .write16(self.bdf, offset as u16 + 4, pmcsr | (1 << 8))
            .ok_or(PcieError::ConfigError)
    }

    /// PMEステータスをクリア
    pub fn clear_pme_status(&self) -> PcieResult<()> {
        let offset = self.pm_offset.ok_or(PcieError::CapabilityNotFound)?;
        let pmcsr = self
            .config
            .read16(self.bdf, offset as u16 + 4)
            .ok_or(PcieError::ConfigError)?;

        // PME_Status ビットをクリア（write-1-to-clear）
        self.config
            .write16(self.bdf, offset as u16 + 4, pmcsr | (1 << 15))
            .ok_or(PcieError::ConfigError)
    }
}

// =============================================================================
// MSI-X
// =============================================================================

/// MSI-Xテーブルエントリ
#[derive(Debug, Clone, Copy)]
pub struct MsixTableEntry {
    pub msg_addr_lo: u32,
    pub msg_addr_hi: u32,
    pub msg_data: u32,
    pub vector_ctrl: u32,
}

/// MSI-Xコントローラ
pub struct MsixController {
    config: &'static PcieConfig,
    bdf: PcieBdf,
    msix_offset: Option<u8>,
    table_size: u16,
    table_bir: u8,
    table_offset: u32,
    pba_bir: u8,
    pba_offset: u32,
}

impl MsixController {
    pub fn new(config: &'static PcieConfig, bdf: PcieBdf) -> PcieResult<Self> {
        let offset = config
            .find_capability(bdf, cap_id::MSIX)
            .ok_or(PcieError::CapabilityNotFound)?;

        // Message Control を読み取り
        let msg_ctrl = config
            .read16(bdf, offset as u16 + 2)
            .ok_or(PcieError::ConfigError)?;
        let table_size = (msg_ctrl & 0x07FF) + 1;

        // Table Offset/BIR
        let table_offset_bir = config
            .read32(bdf, offset as u16 + 4)
            .ok_or(PcieError::ConfigError)?;
        let table_bir = (table_offset_bir & 0x07) as u8;
        let table_offset = table_offset_bir & !0x07;

        // PBA Offset/BIR
        let pba_offset_bir = config
            .read32(bdf, offset as u16 + 8)
            .ok_or(PcieError::ConfigError)?;
        let pba_bir = (pba_offset_bir & 0x07) as u8;
        let pba_offset = pba_offset_bir & !0x07;

        Ok(Self {
            config,
            bdf,
            msix_offset: Some(offset),
            table_size,
            table_bir,
            table_offset,
            pba_bir,
            pba_offset,
        })
    }

    /// MSI-Xを有効化
    pub fn enable(&self) -> PcieResult<()> {
        let offset = self.msix_offset.ok_or(PcieError::CapabilityNotFound)?;
        let msg_ctrl = self
            .config
            .read16(self.bdf, offset as u16 + 2)
            .ok_or(PcieError::ConfigError)?;

        // MSI-X Enable ビットをセット、Function Maskをクリア
        self.config
            .write16(self.bdf, offset as u16 + 2, (msg_ctrl | 0x8000) & !0x4000)
            .ok_or(PcieError::ConfigError)
    }

    /// MSI-Xを無効化
    pub fn disable(&self) -> PcieResult<()> {
        let offset = self.msix_offset.ok_or(PcieError::CapabilityNotFound)?;
        let msg_ctrl = self
            .config
            .read16(self.bdf, offset as u16 + 2)
            .ok_or(PcieError::ConfigError)?;

        // MSI-X Enable ビットをクリア
        self.config
            .write16(self.bdf, offset as u16 + 2, msg_ctrl & !0x8000)
            .ok_or(PcieError::ConfigError)
    }

    /// テーブルサイズを取得
    pub fn table_size(&self) -> u16 {
        self.table_size
    }

    /// テーブル情報を取得
    pub fn table_info(&self) -> (u8, u32) {
        (self.table_bir, self.table_offset)
    }

    /// PBA情報を取得
    pub fn pba_info(&self) -> (u8, u32) {
        (self.pba_bir, self.pba_offset)
    }
}

// =============================================================================
// ホットプラグ
// =============================================================================

/// ホットプラグイベント
#[derive(Debug, Clone, Copy)]
pub enum HotPlugEvent {
    PresenceChange,
    AttentionButton,
    PowerFault,
    MrlSensorChange,
    CommandComplete,
    DataLinkLayerChange,
}

/// ホットプラグコントローラ
pub struct HotPlugController {
    config: &'static PcieConfig,
    bdf: PcieBdf,
    pcie_offset: Option<u8>,
    slot_implemented: bool,
}

impl HotPlugController {
    pub fn new(config: &'static PcieConfig, bdf: PcieBdf) -> PcieResult<Self> {
        let offset = config
            .find_capability(bdf, cap_id::PCIE)
            .ok_or(PcieError::CapabilityNotFound)?;

        // PCIe Capabilities を読み取り
        let pcie_caps = config
            .read16(bdf, offset as u16 + 2)
            .ok_or(PcieError::ConfigError)?;
        let slot_implemented = (pcie_caps & 0x0100) != 0;

        Ok(Self {
            config,
            bdf,
            pcie_offset: Some(offset),
            slot_implemented,
        })
    }

    /// ホットプラグがサポートされているか
    pub fn is_supported(&self) -> bool {
        self.slot_implemented
    }

    /// スロットステータスを読み取り
    pub fn slot_status(&self) -> PcieResult<u16> {
        if !self.slot_implemented {
            return Err(PcieError::NotSupported);
        }

        let offset = self.pcie_offset.ok_or(PcieError::CapabilityNotFound)?;
        self.config
            .read16(self.bdf, offset as u16 + 0x1A)
            .ok_or(PcieError::ConfigError)
    }

    /// 電源をオン
    pub fn power_on(&self) -> PcieResult<()> {
        if !self.slot_implemented {
            return Err(PcieError::NotSupported);
        }

        let offset = self.pcie_offset.ok_or(PcieError::CapabilityNotFound)?;
        let slot_ctrl = self
            .config
            .read16(self.bdf, offset as u16 + 0x18)
            .ok_or(PcieError::ConfigError)?;

        // Power Controller Control = 0 (Power On)
        self.config
            .write16(self.bdf, offset as u16 + 0x18, slot_ctrl & !0x0400)
            .ok_or(PcieError::ConfigError)
    }

    /// 電源をオフ
    pub fn power_off(&self) -> PcieResult<()> {
        if !self.slot_implemented {
            return Err(PcieError::NotSupported);
        }

        let offset = self.pcie_offset.ok_or(PcieError::CapabilityNotFound)?;
        let slot_ctrl = self
            .config
            .read16(self.bdf, offset as u16 + 0x18)
            .ok_or(PcieError::ConfigError)?;

        // Power Controller Control = 1 (Power Off)
        self.config
            .write16(self.bdf, offset as u16 + 0x18, slot_ctrl | 0x0400)
            .ok_or(PcieError::ConfigError)
    }

    /// イベントをクリア
    pub fn clear_events(&self) -> PcieResult<()> {
        if !self.slot_implemented {
            return Err(PcieError::NotSupported);
        }

        let offset = self.pcie_offset.ok_or(PcieError::CapabilityNotFound)?;
        let status = self.slot_status()?;

        // Write-1-to-clear
        self.config
            .write16(self.bdf, offset as u16 + 0x1A, status)
            .ok_or(PcieError::ConfigError)
    }
}

// =============================================================================
// PCIeマネージャ
// =============================================================================

/// PCIeデバイス情報
#[derive(Debug, Clone)]
pub struct PcieDevice {
    pub bdf: PcieBdf,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u32,
    pub has_sriov: bool,
    pub has_aer: bool,
    pub has_msix: bool,
}

/// PCIeマネージャ
pub struct PcieManager {
    config: &'static PcieConfig,
    devices: RwLock<Vec<PcieDevice>>,
}

impl PcieManager {
    pub fn new(config: &'static PcieConfig) -> Self {
        Self {
            config,
            devices: RwLock::new(Vec::new()),
        }
    }

    /// バスをスキャン
    pub fn scan_bus(&self, bus: u8) {
        for device in 0..32 {
            self.scan_device(bus, device);
        }
    }

    fn scan_device(&self, bus: u8, device: u8) {
        let bdf = PcieBdf::new(bus, device, 0);

        // Vendor IDを読み取り
        let vendor_id = match self.config.read16(bdf, 0x00) {
            Some(v) if v != 0xFFFF => v,
            _ => return,
        };

        let device_id = self.config.read16(bdf, 0x02).unwrap_or(0);
        let class_code = self.config.read32(bdf, 0x08).unwrap_or(0) >> 8;

        // ケイパビリティをチェック
        let has_sriov = self
            .config
            .find_ext_capability(bdf, ext_cap_id::SRIOV)
            .is_some();
        let has_aer = self
            .config
            .find_ext_capability(bdf, ext_cap_id::AER)
            .is_some();
        let has_msix = self.config.find_capability(bdf, cap_id::MSIX).is_some();

        let pcie_device = PcieDevice {
            bdf,
            vendor_id,
            device_id,
            class_code,
            has_sriov,
            has_aer,
            has_msix,
        };

        self.devices.write().push(pcie_device);

        // マルチファンクションをチェック
        let header_type = self.config.read8(bdf, 0x0E).unwrap_or(0);
        if (header_type & 0x80) != 0 {
            for function in 1..8 {
                self.scan_function(bus, device, function);
            }
        }
    }

    fn scan_function(&self, bus: u8, device: u8, function: u8) {
        let bdf = PcieBdf::new(bus, device, function);

        let vendor_id = match self.config.read16(bdf, 0x00) {
            Some(v) if v != 0xFFFF => v,
            _ => return,
        };

        let device_id = self.config.read16(bdf, 0x02).unwrap_or(0);
        let class_code = self.config.read32(bdf, 0x08).unwrap_or(0) >> 8;

        let has_sriov = self
            .config
            .find_ext_capability(bdf, ext_cap_id::SRIOV)
            .is_some();
        let has_aer = self
            .config
            .find_ext_capability(bdf, ext_cap_id::AER)
            .is_some();
        let has_msix = self.config.find_capability(bdf, cap_id::MSIX).is_some();

        let pcie_device = PcieDevice {
            bdf,
            vendor_id,
            device_id,
            class_code,
            has_sriov,
            has_aer,
            has_msix,
        };

        self.devices.write().push(pcie_device);
    }

    /// 全デバイスを取得
    pub fn devices(&self) -> Vec<PcieDevice> {
        self.devices.read().clone()
    }

    /// 特定のデバイスを検索
    pub fn find_device(&self, vendor_id: u16, device_id: u16) -> Option<PcieDevice> {
        self.devices
            .read()
            .iter()
            .find(|d| d.vendor_id == vendor_id && d.device_id == device_id)
            .cloned()
    }

    /// コンフィグを取得
    pub fn config(&self) -> &'static PcieConfig {
        self.config
    }
}

// =============================================================================
// 初期化
// =============================================================================

static PCIE_CONFIG: spin::Once<PcieConfig> = spin::Once::new();
static PCIE_MANAGER: spin::Once<PcieManager> = spin::Once::new();

/// PCIeを初期化
pub fn init(base_addr: u64) -> PcieResult<()> {
    let config = PCIE_CONFIG.call_once(|| PcieConfig::new(base_addr, 0, 0, 255));

    PCIE_MANAGER.call_once(|| {
        let manager = PcieManager::new(config);
        // バス0をスキャン
        manager.scan_bus(0);
        manager
    });

    Ok(())
}

/// PCIeマネージャを取得
pub fn manager() -> Option<&'static PcieManager> {
    PCIE_MANAGER.get()
}

/// コンフィグを取得
pub fn config() -> Option<&'static PcieConfig> {
    PCIE_CONFIG.get()
}
