//! AMD-Vi backend driver (skeleton).

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use x86_64::PhysAddr;

use crate::io::acpi::ivrs::IvhdDeviceEntry;

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

pub struct AmdIommuDriver {
    units: Vec<AmdIommuUnit>,
}

impl AmdIommuDriver {
    pub fn new(units: Vec<AmdIommuUnit>) -> Self {
        Self { units }
    }

    pub fn register_driver(units: Vec<AmdIommuUnit>) -> Result<(), IommuError> {
        if get_iommu_driver().is_some() {
            return Err(IommuError::AlreadyInitialized);
        }
        init_driver(Arc::new(AmdIommuDriver::new(units)));
        Ok(())
    }

    pub fn find_unit_for_device(&self, device: DeviceId) -> Option<&AmdIommuUnit> {
        let devid = device.requester_id();
        self.units
            .iter()
            .find(|unit| unit.segment == device.segment && unit.covers_devid(devid))
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

    let unit_count = units.len();
    AmdIommuDriver::register_driver(units)?;
    log::info!("AMD-Vi IVRS parsed ({} unit(s))", unit_count);

    Ok(())
}
