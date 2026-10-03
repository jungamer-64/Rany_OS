use super::{PcieBdf, PcieConfig, PcieError, PcieResult, cap_id, ext_cap_id};
use alloc::vec::Vec;
use exorust_sync::PoisonRwLock;

// ============================================================================
// 電源管理
// ============================================================================

mod acs_capability;
pub use acs_capability::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciePowerState {
    D0,
    D1,
    D2,
    D3Hot,
    D3Cold,
}

pub struct PciePowerManager {
    config: &'static PcieConfig,
    bdf: PcieBdf,
    pm_offset: Option<u8>,
}

impl PciePowerManager {
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
    pub fn new(config: &'static PcieConfig, bdf: PcieBdf) -> PcieResult<Self> {
        let pm_offset = config.find_capability(bdf, cap_id::PM);
        Ok(Self {
            config,
            bdf,
            pm_offset,
        })
    }

    /// # Errors
    ///
    /// Returns an error if the request is invalid or the required device state cannot be read.
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

    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or rejected by the device.
    pub fn set_state(&self, state: PciePowerState) -> PcieResult<()> {
        let offset = self.pm_offset.ok_or(PcieError::CapabilityNotFound)?;
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
        let pmcsr = self
            .config
            .read16(self.bdf, offset as u16 + 4)
            .ok_or(PcieError::ConfigError)?;
        let new_pmcsr = (pmcsr & !0x03) | state_bits;
        self.config
            .write16(self.bdf, offset as u16 + 4, new_pmcsr)
            .ok_or(PcieError::ConfigError)
    }

    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or rejected by the device.
    pub fn enable_pme(&self) -> PcieResult<()> {
        let offset = self.pm_offset.ok_or(PcieError::CapabilityNotFound)?;
        let pmcsr = self
            .config
            .read16(self.bdf, offset as u16 + 4)
            .ok_or(PcieError::ConfigError)?;
        self.config
            .write16(self.bdf, offset as u16 + 4, pmcsr | (1 << 8))
            .ok_or(PcieError::ConfigError)
    }

    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or rejected by the device.
    pub fn clear_pme_status(&self) -> PcieResult<()> {
        let offset = self.pm_offset.ok_or(PcieError::CapabilityNotFound)?;
        let pmcsr = self
            .config
            .read16(self.bdf, offset as u16 + 4)
            .ok_or(PcieError::ConfigError)?;
        self.config
            .write16(self.bdf, offset as u16 + 4, pmcsr | (1 << 15))
            .ok_or(PcieError::ConfigError)
    }
}

// ============================================================================
// MSI-X (拡張機能)
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct PcieMsixTableEntry {
    pub msg_addr_lo: u32,
    pub msg_addr_hi: u32,
    pub msg_data: u32,
    pub vector_ctrl: u32,
}

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
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
    pub fn new(config: &'static PcieConfig, bdf: PcieBdf) -> PcieResult<Self> {
        let offset = config
            .find_capability(bdf, cap_id::MSIX)
            .ok_or(PcieError::CapabilityNotFound)?;
        let msg_ctrl = config
            .read16(bdf, offset as u16 + 2)
            .ok_or(PcieError::ConfigError)?;
        let table_size = (msg_ctrl & 0x07FF) + 1;
        let table_offset_bir = config
            .read32(bdf, offset as u16 + 4)
            .ok_or(PcieError::ConfigError)?;
        let table_bir = (table_offset_bir & 0x07) as u8;
        let table_offset = table_offset_bir & !0x07;
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

    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or rejected by the device.
    pub fn enable(&self) -> PcieResult<()> {
        let offset = self.msix_offset.ok_or(PcieError::CapabilityNotFound)?;
        let msg_ctrl = self
            .config
            .read16(self.bdf, offset as u16 + 2)
            .ok_or(PcieError::ConfigError)?;
        self.config
            .write16(self.bdf, offset as u16 + 2, (msg_ctrl | 0x8000) & !0x4000)
            .ok_or(PcieError::ConfigError)
    }

    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or rejected by the device.
    pub fn disable(&self) -> PcieResult<()> {
        let offset = self.msix_offset.ok_or(PcieError::CapabilityNotFound)?;
        let msg_ctrl = self
            .config
            .read16(self.bdf, offset as u16 + 2)
            .ok_or(PcieError::ConfigError)?;
        self.config
            .write16(self.bdf, offset as u16 + 2, msg_ctrl & !0x8000)
            .ok_or(PcieError::ConfigError)
    }

    pub fn table_size(&self) -> u16 {
        self.table_size
    }
    pub fn table_info(&self) -> (u8, u32) {
        (self.table_bir, self.table_offset)
    }
    pub fn pba_info(&self) -> (u8, u32) {
        (self.pba_bir, self.pba_offset)
    }
}

// ============================================================================
// ホットプラグ
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub enum HotPlugEvent {
    PresenceChange,
    AttentionButton,
    PowerFault,
    MrlSensorChange,
    CommandComplete,
    DataLinkLayerChange,
}

pub struct HotPlugController {
    config: &'static PcieConfig,
    bdf: PcieBdf,
    pcie_offset: Option<u8>,
    slot_implemented: bool,
}

impl HotPlugController {
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
    pub fn new(config: &'static PcieConfig, bdf: PcieBdf) -> PcieResult<Self> {
        let offset = config
            .find_capability(bdf, cap_id::PCIE)
            .ok_or(PcieError::CapabilityNotFound)?;
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

    pub fn is_supported(&self) -> bool {
        self.slot_implemented
    }
    pub fn is_hotplug_capable(&self) -> bool {
        if !self.slot_implemented {
            return false;
        }
        let Some(offset) = self.pcie_offset else {
            return false;
        };
        let slot_caps = self
            .config
            .read32(self.bdf, offset as u16 + 0x14)
            .unwrap_or(0);
        (slot_caps & (1 << 6)) != 0
    }

    /// # Errors
    ///
    /// Returns an error if the request is invalid or the required device state cannot be read.
    pub fn slot_status(&self) -> PcieResult<u16> {
        if !self.slot_implemented {
            return Err(PcieError::NotSupported);
        }
        let offset = self.pcie_offset.ok_or(PcieError::CapabilityNotFound)?;
        self.config
            .read16(self.bdf, offset as u16 + 0x1A)
            .ok_or(PcieError::ConfigError)
    }

    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or rejected by the device.
    pub fn power_on(&self) -> PcieResult<()> {
        if !self.slot_implemented {
            return Err(PcieError::NotSupported);
        }
        let offset = self.pcie_offset.ok_or(PcieError::CapabilityNotFound)?;
        let slot_ctrl = self
            .config
            .read16(self.bdf, offset as u16 + 0x18)
            .ok_or(PcieError::ConfigError)?;
        self.config
            .write16(self.bdf, offset as u16 + 0x18, slot_ctrl & !0x0400)
            .ok_or(PcieError::ConfigError)
    }

    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or rejected by the device.
    pub fn power_off(&self) -> PcieResult<()> {
        if !self.slot_implemented {
            return Err(PcieError::NotSupported);
        }
        let offset = self.pcie_offset.ok_or(PcieError::CapabilityNotFound)?;
        let slot_ctrl = self
            .config
            .read16(self.bdf, offset as u16 + 0x18)
            .ok_or(PcieError::ConfigError)?;
        self.config
            .write16(self.bdf, offset as u16 + 0x18, slot_ctrl | 0x0400)
            .ok_or(PcieError::ConfigError)
    }

    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or rejected by the device.
    pub fn clear_events(&self) -> PcieResult<()> {
        if !self.slot_implemented {
            return Err(PcieError::NotSupported);
        }
        let offset = self.pcie_offset.ok_or(PcieError::CapabilityNotFound)?;
        let status = self.slot_status()?;
        self.config
            .write16(self.bdf, offset as u16 + 0x1A, status)
            .ok_or(PcieError::ConfigError)
    }
}

// ============================================================================
// PCIe拡張マネージャ
// ============================================================================

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

pub struct PcieExtManager {
    config: &'static PcieConfig,
    devices: PoisonRwLock<Vec<PcieExtDevice>>,
}

impl PcieExtManager {
    pub fn new(config: &'static PcieConfig) -> Self {
        Self {
            config,
            devices: PoisonRwLock::new(Vec::new()),
        }
    }

    pub fn scan_bus(&self, bus: u8) {
        for device in 0..32 {
            self.scan_device(bus, device);
        }
    }

    pub(super) fn scan_device(&self, bus: u8, device: u8) {
        let bdf = PcieBdf::new(bus, device, 0);
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
        self.devices
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .push(pcie_device);
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
        self.devices
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .push(pcie_device);
    }

    pub fn devices(&self) -> Vec<PcieExtDevice> {
        self.devices
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    pub fn find_device(&self, vendor_id: u16, device_id: u16) -> Option<PcieExtDevice> {
        self.devices
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|d| d.vendor_id == vendor_id && d.device_id == device_id)
            .cloned()
    }
    pub fn config(&self) -> &'static PcieConfig {
        self.config
    }
}

// ============================================================================
// 初期化
// ============================================================================

pub static PCIE_EXT_CONFIG: exorust_sync::InitOnce<PcieConfig> = exorust_sync::InitOnce::new();
pub static PCIE_EXT_MANAGER: exorust_sync::InitOnce<PcieExtManager> = exorust_sync::InitOnce::new();

/// Publishes an owned, validated ECAM window before enumerating its buses.
pub fn init_pcie_ext(config: PcieConfig) {
    let config = PCIE_EXT_CONFIG.call_once(|| config);
    PCIE_EXT_MANAGER.call_once(|| {
        let manager = PcieExtManager::new(config);
        for bus in config.buses.first..=config.buses.last {
            manager.scan_bus(bus);
        }
        manager
    });
}

pub fn pcie_ext_manager() -> Option<&'static PcieExtManager> {
    PCIE_EXT_MANAGER.get()
}
pub fn pcie_ext_config() -> Option<&'static PcieConfig> {
    PCIE_EXT_CONFIG.get()
}

// ============================================================================
// ATS (Address Translation Services)
// ============================================================================

mod ats_regs {
    pub const CAP: u16 = 0x04;
    pub const CTRL: u16 = 0x06;
}

#[derive(Debug, Clone)]
pub struct AtsCapability {
    pub offset: u16,
    pub invalidate_queue_depth: u8,
    pub page_aligned_request: bool,
    pub global_invalidate: bool,
    pub relaxed_ordering: bool,
    pub stu: u8,
}

pub struct AtsController {
    config: &'static PcieConfig,
    bdf: PcieBdf,
    capability: AtsCapability,
}

#[derive(Clone, Copy)]
enum AtsControlRequest {
    Enable { stu: u8 },
    Disable,
}

impl AtsControlRequest {
    fn prepare(self, current: u16) -> PcieResult<u16> {
        if current == u16::MAX {
            return Err(PcieError::DeviceNotFound);
        }
        match self {
            Self::Enable { stu } if stu <= 0x1f => {
                Ok((current & !0x1f) | u16::from(stu) | (1 << 15))
            }
            Self::Enable { .. } => Err(PcieError::ConfigError),
            Self::Disable => Ok(current & !(1 << 15)),
        }
    }

    fn check_readback(self, observed: u16) -> PcieResult<()> {
        if observed == u16::MAX {
            return Err(PcieError::DeviceNotFound);
        }
        let matches = match self {
            Self::Enable { stu } => observed & ((1 << 15) | 0x1f) == (1 << 15) | u16::from(stu),
            Self::Disable => observed & (1 << 15) == 0,
        };
        if matches {
            Ok(())
        } else {
            Err(PcieError::ConfigError)
        }
    }
}

impl AtsController {
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
    pub fn new(config: &'static PcieConfig, bdf: PcieBdf) -> PcieResult<Self> {
        let offset = config
            .find_ext_capability(bdf, ext_cap_id::ATS)
            .ok_or(PcieError::CapabilityNotFound)?;
        let cap = Self::read_capability(config, bdf, offset)?;
        Ok(Self {
            config,
            bdf,
            capability: cap,
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

    /// # Errors
    ///
    /// Invalid STU or configuration/readback failure leaves the resource with
    /// the caller. A failure after the write may still have enabled hardware;
    /// the translation-cache owner must retain it until explicit shutdown.
    pub fn enable_ats(&self, stu: u8) -> PcieResult<()> {
        self.transition(AtsControlRequest::Enable { stu })
    }

    /// # Errors
    ///
    /// Failure does not establish disablement. Even success confirms only the
    /// PCI control bit, not Device-TLB invalidation or outstanding DMA completion.
    pub fn disable_ats(&self) -> PcieResult<()> {
        self.transition(AtsControlRequest::Disable)
    }

    fn transition(&self, request: AtsControlRequest) -> PcieResult<()> {
        let offset = self.capability.offset;
        let ctrl = request.prepare(self.read_control()?)?;
        self.config
            .write16(self.bdf, offset + ats_regs::CTRL, ctrl)
            .ok_or(PcieError::ConfigError)?;
        request.check_readback(self.read_control()?)
    }

    fn read_control(&self) -> PcieResult<u16> {
        match self
            .config
            .read16(self.bdf, self.capability.offset + ats_regs::CTRL)
        {
            Some(u16::MAX) => Err(PcieError::DeviceNotFound),
            Some(value) => Ok(value),
            None => Err(PcieError::ConfigError),
        }
    }

    pub fn capability(&self) -> &AtsCapability {
        &self.capability
    }
    pub const fn segment(&self) -> u16 {
        self.config.segment()
    }
    pub fn bdf(&self) -> PcieBdf {
        self.bdf
    }
}

#[cfg(test)]
mod ats_control_tests {
    use super::*;

    #[test]
    fn control_update_preserves_reserved_fields_without_truncating_stu() {
        assert_eq!(
            AtsControlRequest::Enable { stu: 3 }.prepare(0x4260),
            Ok(0xc263)
        );
        assert_eq!(AtsControlRequest::Disable.prepare(0xc263), Ok(0x4263));
        assert_eq!(
            AtsControlRequest::Enable { stu: 32 }.prepare(0),
            Err(PcieError::ConfigError)
        );
    }

    #[test]
    fn lost_device_is_not_a_successful_enable_or_disable_readback() {
        assert_eq!(
            AtsControlRequest::Enable { stu: 31 }.check_readback(u16::MAX),
            Err(PcieError::DeviceNotFound)
        );
        assert_eq!(
            AtsControlRequest::Disable.check_readback(u16::MAX),
            Err(PcieError::DeviceNotFound)
        );
    }

    #[test]
    fn readback_must_confirm_requested_enablement_and_translation_unit() {
        let enable = AtsControlRequest::Enable { stu: 3 };
        assert_eq!(enable.check_readback(0x8003), Ok(()));
        assert_eq!(enable.check_readback(0x0003), Err(PcieError::ConfigError));
        assert_eq!(enable.check_readback(0x8002), Err(PcieError::ConfigError));
        assert_eq!(AtsControlRequest::Disable.check_readback(0x0003), Ok(()));
        assert_eq!(
            AtsControlRequest::Disable.check_readback(0x8003),
            Err(PcieError::ConfigError)
        );
    }
}

pub fn device_supports_ats(config: &PcieConfig, bdf: PcieBdf) -> bool {
    config.find_ext_capability(bdf, ext_cap_id::ATS).is_some()
}

mod acs_regs {
    pub const CAP: u16 = 0x04;
    pub const CTRL: u16 = 0x06;
}
