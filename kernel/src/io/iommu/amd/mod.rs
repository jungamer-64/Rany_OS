//! AMD-Vi backend driver (skeleton).

pub mod cmd;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use x86_64::PhysAddr;

use crate::io::acpi::ivrs::{IvhdDeviceEntry, IvmdInfo};

use super::interface::{IommuDriver, IommuFuture};
use super::registry::{get_iommu_driver, init_driver};
use super::{DeviceId, IommuConfig, IommuDomainType, IommuError};

#[derive(Debug, Clone)]
pub struct AmdIommuUnit {
    pub segment: u16,
    pub base_addr: u64,
    pub flags: u8,
    pub device_id: u16,
    pub iommu_info: u16,
    pub iommu_feature: u32,
    pub device_entries: Vec<IvhdDeviceEntry>,
}

#[derive(Debug, Clone, Copy)]
pub struct AmdIvmdRange {
    pub segment: u16,
    pub devid_start: u16,
    pub devid_end: u16,
    pub range_start: u64,
    /// End address (exclusive), computed as start + length.
    pub range_end: u64,
    pub unity_map: bool,
    pub read: bool,
    pub write: bool,
    pub exclusion: bool,
}

impl AmdIvmdRange {
    fn from_ivmd(ivmd: IvmdInfo) -> Option<Self> {
        const IVMD_TYPE_ALL: u8 = 0x20;
        const IVMD_TYPE: u8 = 0x21;
        const IVMD_TYPE_RANGE: u8 = 0x22;
        const IVMD_FLAG_UNITY_MAP: u8 = 0x01;
        const IVMD_FLAG_IR: u8 = 0x02;
        const IVMD_FLAG_IW: u8 = 0x04;
        const IVMD_FLAG_EXCL_RANGE: u8 = 0x08;

        let (devid_start, devid_end) = match ivmd.block_type {
            IVMD_TYPE_ALL => (0, u16::MAX),
            IVMD_TYPE => (ivmd.device_id, ivmd.device_id),
            IVMD_TYPE_RANGE => (ivmd.device_id, ivmd.aux),
            _ => return None,
        };

        if devid_end < devid_start {
            return None;
        }

        let exclusion = (ivmd.flags & IVMD_FLAG_EXCL_RANGE) != 0;
        let mut read = (ivmd.flags & IVMD_FLAG_IR) != 0;
        let mut write = (ivmd.flags & IVMD_FLAG_IW) != 0;
        if exclusion {
            read = true;
            write = true;
        }
        let unity_map = (ivmd.flags & IVMD_FLAG_UNITY_MAP) != 0 || exclusion;

        Some(Self {
            segment: ivmd.pci_segment,
            devid_start,
            devid_end,
            range_start: ivmd.range_start,
            range_end: ivmd.range_start.saturating_add(ivmd.range_length),
            unity_map,
            read,
            write,
            exclusion,
        })
    }

    fn applies_to_devid(&self, devid: u16) -> bool {
        devid >= self.devid_start && devid <= self.devid_end
    }
}

pub struct AmdIommuDriver {
    units: Vec<AmdIommuUnit>,
    ivmd_ranges: Vec<AmdIvmdRange>,
}

impl AmdIommuDriver {
    pub fn new(units: Vec<AmdIommuUnit>, ivmd_ranges: Vec<AmdIvmdRange>) -> Self {
        Self {
            units,
            ivmd_ranges,
        }
    }

    pub fn register_driver(
        units: Vec<AmdIommuUnit>,
        ivmd_ranges: Vec<AmdIvmdRange>,
    ) -> Result<(), IommuError> {
        if get_iommu_driver().is_some() {
            return Err(IommuError::AlreadyInitialized);
        }
        init_driver(Arc::new(AmdIommuDriver::new(units, ivmd_ranges)));
        Ok(())
    }

    pub fn find_unit_for_device(&self, device: DeviceId) -> Option<&AmdIommuUnit> {
        let devid = device.requester_id();
        self.units
            .iter()
            .find(|unit| unit.segment == device.segment && unit.covers_devid(devid))
    }

    pub fn ivmd_ranges_for_device(&self, device: DeviceId) -> Vec<AmdIvmdRange> {
        let devid = device.requester_id();
        self.ivmd_ranges
            .iter()
            .copied()
            .filter(|range| range.segment == device.segment && range.applies_to_devid(devid))
            .collect()
    }
}

impl AmdIommuUnit {
    fn covers_devid(&self, devid: u16) -> bool {
        self.device_entries.iter().any(|entry| match entry {
            IvhdDeviceEntry::All { .. } => true,
            IvhdDeviceEntry::Select { devid: entry_devid, .. } => *entry_devid == devid,
            IvhdDeviceEntry::Range { start, end, .. } => devid >= *start && devid <= *end,
            IvhdDeviceEntry::Alias { devid: entry_devid, alias, .. } => {
                *entry_devid == devid || *alias == devid
            }
            IvhdDeviceEntry::AliasRange {
                start, end, alias, ..
            } => (devid >= *start && devid <= *end) || *alias == devid,
            IvhdDeviceEntry::ExtSelect { devid: entry_devid, .. } => *entry_devid == devid,
            IvhdDeviceEntry::ExtRange { start, end, .. } => devid >= *start && devid <= *end,
            IvhdDeviceEntry::Special { devid: entry_devid, .. } => *entry_devid == devid,
            IvhdDeviceEntry::AcpiHid { devid: entry_devid, .. } => *entry_devid == devid,
        })
    }
}

impl IommuDriver for AmdIommuDriver {
    fn is_enabled(&self) -> bool {
        false
    }

    fn enable(&self) -> Result<(), IommuError> {
        Err(IommuError::NotSupported)
    }

    fn disable(&self) -> Result<(), IommuError> {
        Err(IommuError::NotSupported)
    }

    fn handle_fault(&self) {}

    fn wake_invalidation_waiters(&self) {}

    fn map_interrupt(
        &self,
        _segment: u16,
        _bus: u8,
        _device: u8,
        _function: u8,
        _vector: u8,
        _dest_id: u32,
        _logical: bool,
    ) -> Result<u16, IommuError> {
        Err(IommuError::NotSupported)
    }

    fn get_remap_msi_message(&self, _handle: u16) -> (u64, u32) {
        (0, 0)
    }

    unsafe fn map_for_dma(&self, _phys_addr: PhysAddr, _size: u64) -> Result<u64, IommuError> {
        Err(IommuError::NotSupported)
    }

    fn unmap_dma(&self, _iova: u64, _size: u64) -> Result<(), IommuError> {
        Err(IommuError::NotSupported)
    }

    unsafe fn map_for_device(
        &self,
        _device: &DeviceId,
        _phys_addr: PhysAddr,
        _size: u64,
    ) -> Result<u64, IommuError> {
        Err(IommuError::NotSupported)
    }

    unsafe fn map_for_device_async<'a>(
        &'a self,
        _device: &'a DeviceId,
        _phys_addr: PhysAddr,
        _size: u64,
    ) -> IommuFuture<'a, Result<u64, IommuError>> {
        Box::pin(async { Err(IommuError::NotSupported) })
    }

    fn unmap_for_device(
        &self,
        _device: &DeviceId,
        _iova: u64,
        _size: u64,
    ) -> Result<(), IommuError> {
        Err(IommuError::NotSupported)
    }

    fn unmap_for_device_async<'a>(
        &'a self,
        _device: &'a DeviceId,
        _iova: u64,
        _size: u64,
    ) -> IommuFuture<'a, Result<(), IommuError>> {
        Box::pin(async { Err(IommuError::NotSupported) })
    }

    fn create_domain(
        &self,
        _numa_node: Option<usize>,
        _domain_type: IommuDomainType,
    ) -> Result<u16, IommuError> {
        Err(IommuError::NotSupported)
    }

    fn attach_device(&self, _device: DeviceId, _domain_id: u16) -> Result<(), IommuError> {
        Err(IommuError::NotSupported)
    }

    fn detach_device(&self, _device: DeviceId) -> Result<(), IommuError> {
        Err(IommuError::NotSupported)
    }

    fn set_domain_numa(&self, _domain_id: u16, _numa_node: Option<usize>) -> Result<(), IommuError> {
        Err(IommuError::NotSupported)
    }

    fn get_domain_numa(&self, _domain_id: u16) -> Result<Option<usize>, IommuError> {
        Err(IommuError::NotSupported)
    }
}

/// Initialize AMD-Vi using ACPI IVRS table at `ivrs_addr`.
pub unsafe fn init_iommu_from_ivrs(
    ivrs_addr: usize,
    config: IommuConfig,
) -> Result<(), IommuError> {
    if !config.enabled {
        log::info!("IOMMU disabled by kernel configuration");
        return Err(IommuError::NotPresent);
    }

    let ivrs_info = match unsafe { crate::io::acpi::ivrs::parse_ivrs(ivrs_addr) } {
        Ok(info) => info,
        Err(e) => {
            log::error!("Failed to parse IVRS: {}", e);
            return Err(IommuError::HardwareError);
        }
    };

    let mut units = Vec::new();
    for ivhd in ivrs_info.ivhds {
        units.push(AmdIommuUnit {
            segment: ivhd.pci_segment,
            base_addr: ivhd.iommu_base,
            flags: ivhd.flags,
            device_id: ivhd.device_id,
            iommu_info: ivhd.iommu_info,
            iommu_feature: ivhd.iommu_feature,
            device_entries: ivhd.device_entries,
        });
    }

    if units.is_empty() {
        return Err(IommuError::NotPresent);
    }

    let mut ivmd_ranges = Vec::new();
    for ivmd in ivrs_info.ivmds {
        if let Some(range) = AmdIvmdRange::from_ivmd(ivmd) {
            ivmd_ranges.push(range);
        }
    }

    let unit_count = units.len();
    let ivmd_count = ivmd_ranges.len();
    AmdIommuDriver::register_driver(units, ivmd_ranges)?;
    log::info!(
        "AMD-Vi IVRS parsed ({} unit(s), {} IVMD range(s))",
        unit_count,
        ivmd_count
    );

    Ok(())
}
