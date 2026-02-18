use super::*;


// ============================================================================
// 電源管理
// ============================================================================

/// PCIe電源状態
mod acs_capability;
pub use acs_capability::*;
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

// ============================================================================
// MSI-X (拡張機能)
// ============================================================================

/// MSI-Xテーブルエントリ
#[derive(Debug, Clone, Copy)]
pub struct PcieMsixTableEntry {
    pub msg_addr_lo: u32,
    pub msg_addr_hi: u32,
    pub msg_data: u32,
    pub vector_ctrl: u32,
}

/// MSI-X拡張コントローラ
pub struct PcieMsixController {
    config: &'static PcieConfig,
    bdf: PcieBdf,
    msix_offset: Option<u8>,
    table_size: u16,
    table_bir: u8,
    table_offset: u32,
    pba_bir: u8,
    pba_offset: u32,
}

impl PcieMsixController {
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

// ============================================================================
// ホットプラグ
// ============================================================================

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

// ============================================================================
// PCIe拡張マネージャ
// ============================================================================

/// PCIe拡張デバイス情報
#[derive(Debug, Clone)]
pub struct PcieExtDevice {
    pub bdf: PcieBdf,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u32,
    pub has_sriov: bool,
    pub has_aer: bool,
    pub has_msix: bool,
}

/// PCIe拡張マネージャ
pub struct PcieExtManager {
    config: &'static PcieConfig,
    devices: RwLock<Vec<PcieExtDevice>>,
}

impl PcieExtManager {
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

    pub(super) fn scan_device(&self, bus: u8, device: u8) {
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

        let pcie_device = PcieExtDevice {
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

    pub(super) fn scan_function(&self, bus: u8, device: u8, function: u8) {
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

        let pcie_device = PcieExtDevice {
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
    pub fn devices(&self) -> Vec<PcieExtDevice> {
        self.devices.read().clone()
    }

    /// 特定のデバイスを検索
    pub fn find_device(&self, vendor_id: u16, device_id: u16) -> Option<PcieExtDevice> {
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

// ============================================================================
// 初期化
// ============================================================================

pub(crate) static PCIE_EXT_CONFIG: spin::Once<PcieConfig> = spin::Once::new();
pub(crate) static PCIE_EXT_MANAGER: spin::Once<PcieExtManager> = spin::Once::new();

/// PCIe拡張機能を初期化
pub fn init_pcie_ext(base_addr: u64) -> PcieResult<()> {
    let config = PCIE_EXT_CONFIG.call_once(|| PcieConfig::new(base_addr, 0, 0, 255));

    PCIE_EXT_MANAGER.call_once(|| {
        let manager = PcieExtManager::new(config);
        // バス0をスキャン
        manager.scan_bus(0);
        manager
    });

    Ok(())
}

/// PCIe拡張マネージャを取得
pub fn pcie_ext_manager() -> Option<&'static PcieExtManager> {
    PCIE_EXT_MANAGER.get()
}

/// PCIe拡張コンフィグを取得
pub fn pcie_ext_config() -> Option<&'static PcieConfig> {
    PCIE_EXT_CONFIG.get()
}

// ============================================================================
// ATS (Address Translation Services)
// ============================================================================

/// ATS Capability register offsets (relative to capability base)
mod ats_regs {
    pub const CAP: u16 = 0x04; // ATS Capability Register
    pub const CTRL: u16 = 0x06; // ATS Control Register
}

/// ATS Capability structure
#[derive(Debug, Clone)]
pub struct AtsCapability {
    /// Offset of the ATS Extended Capability in config space
    pub offset: u16,
    /// Invalidate Queue Depth (number of outstanding invalidate requests - 1)
    pub invalidate_queue_depth: u8,
    /// Page Aligned Request supported
    pub page_aligned_request: bool,
    /// Global Invalidate supported
    pub global_invalidate: bool,
    /// Relaxed Ordering supported
    pub relaxed_ordering: bool,
    /// Smallest Translation Unit (log2, 0 = 4KB)
    pub stu: u8,
}

/// ATS Controller for a single device
pub struct AtsController {
    config: &'static PcieConfig,
    bdf: PcieBdf,
    capability: Option<AtsCapability>,
    enabled: AtomicBool,
}

impl AtsController {
    /// Create a new ATS controller for a device
    pub fn new(config: &'static PcieConfig, bdf: PcieBdf) -> PcieResult<Self> {
        let offset = config
            .find_ext_capability(bdf, ext_cap_id::ATS)
            .ok_or(PcieError::CapabilityNotFound)?;

        let cap = Self::read_capability(config, bdf, offset)?;

        Ok(Self {
            config,
            bdf,
            capability: Some(cap),
            enabled: AtomicBool::new(false),
        })
    }

    pub(super) fn read_capability(
        config: &PcieConfig,
        bdf: PcieBdf,
        offset: u16,
    ) -> PcieResult<AtsCapability> {
        let cap_reg = config
            .read16(bdf, offset + ats_regs::CAP)
            .ok_or(PcieError::ConfigError)?;

        let invalidate_queue_depth = (cap_reg & 0x1F) as u8;
        let page_aligned_request = (cap_reg & (1 << 5)) != 0;
        let global_invalidate = (cap_reg & (1 << 6)) != 0;
        let relaxed_ordering = (cap_reg & (1 << 7)) != 0;

        let ctrl_reg = config
            .read16(bdf, offset + ats_regs::CTRL)
            .ok_or(PcieError::ConfigError)?;

        let stu = (ctrl_reg & 0x1F) as u8;

        Ok(AtsCapability {
            offset,
            invalidate_queue_depth,
            page_aligned_request,
            global_invalidate,
            relaxed_ordering,
            stu,
        })
    }

    /// Enable ATS for this device
    ///
    /// After enabling, the device may cache address translations from the IOMMU.
    pub fn enable_ats(&self, stu: u8) -> PcieResult<()> {
        let cap = self
            .capability
            .as_ref()
            .ok_or(PcieError::CapabilityNotFound)?;
        let offset = cap.offset;

        // Read current control register
        let mut ctrl = self
            .config
            .read16(self.bdf, offset + ats_regs::CTRL)
            .ok_or(PcieError::ConfigError)?;

        // Set STU (Smallest Translation Unit) - bits 4:0
        ctrl = (ctrl & !0x1F) | ((stu as u16) & 0x1F);

        // Set Enable bit (bit 15)
        ctrl |= 1 << 15;

        self.config
            .write16(self.bdf, offset + ats_regs::CTRL, ctrl)
            .ok_or(PcieError::ConfigError)?;

        self.enabled.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Disable ATS for this device
    pub fn disable_ats(&self) -> PcieResult<()> {
        let cap = self
            .capability
            .as_ref()
            .ok_or(PcieError::CapabilityNotFound)?;
        let offset = cap.offset;

        let mut ctrl = self
            .config
            .read16(self.bdf, offset + ats_regs::CTRL)
            .ok_or(PcieError::ConfigError)?;

        // Clear Enable bit (bit 15)
        ctrl &= !(1 << 15);

        self.config
            .write16(self.bdf, offset + ats_regs::CTRL, ctrl)
            .ok_or(PcieError::ConfigError)?;

        self.enabled.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Check if ATS is currently enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Get the ATS capability information
    pub fn capability(&self) -> Option<&AtsCapability> {
        self.capability.as_ref()
    }

    /// Get the BDF address of this device
    pub fn bdf(&self) -> PcieBdf {
        self.bdf
    }
}

/// Check if a device supports ATS
pub fn device_supports_ats(config: &PcieConfig, bdf: PcieBdf) -> bool {
    config.find_ext_capability(bdf, ext_cap_id::ATS).is_some()
}

// ============================================================================
// ACS (Access Control Services)
// ============================================================================

/// ACS Capability register offsets
mod acs_regs {
    pub const CAP: u16 = 0x04; // ACS Capability Register
    pub const CTRL: u16 = 0x06; // ACS Control Register
}
