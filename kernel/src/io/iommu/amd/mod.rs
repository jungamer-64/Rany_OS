// ============================================================================
// kernel/src/io/iommu/amd/mod.rs
// ============================================================================

//! AMD-Vi backend driver (skeleton).

pub mod cmd;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

use x86_64::PhysAddr;

use crate::io::acpi::ivrs::{IvhdDeviceEntry, IvmdInfo};
use crate::io::iommu::tables::phys_to_virt_usize;
use crate::mm::buddy_alloc_contiguous_frames;
use crate::mm::mapping::phys_to_virt;
use crate::sync::PoisonLock;
use hashbrown::HashMap;

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
    cmd_states: Vec<Option<PoisonLock<AmdCommandState>>>,
    domains: PoisonLock<HashMap<u16, AmdDomainInfo>>,
    device_domains: PoisonLock<HashMap<DeviceId, u16>>,
    next_domain_id: AtomicU64,
}

#[derive(Debug, Clone, Copy)]
struct AmdDomainInfo {
    domain_type: IommuDomainType,
    numa_node: Option<usize>,
}

impl AmdIommuDriver {
    pub fn new(
        units: Vec<AmdIommuUnit>,
        ivmd_ranges: Vec<AmdIvmdRange>,
        cmd_states: Vec<Option<PoisonLock<AmdCommandState>>>,
    ) -> Self {
        Self {
            units,
            ivmd_ranges,
            cmd_states,
            domains: PoisonLock::new(HashMap::new()),
            device_domains: PoisonLock::new(HashMap::new()),
            next_domain_id: AtomicU64::new(1),
        }
    }

    pub fn register_driver(
        units: Vec<AmdIommuUnit>,
        ivmd_ranges: Vec<AmdIvmdRange>,
        cmd_states: Vec<Option<PoisonLock<AmdCommandState>>>,
    ) -> Result<(), IommuError> {
        if get_iommu_driver().is_some() {
            return Err(IommuError::AlreadyInitialized);
        }
        init_driver(Arc::new(AmdIommuDriver::new(
            units,
            ivmd_ranges,
            cmd_states,
        )));
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

    fn find_unit_index_for_device(&self, device: DeviceId) -> Option<usize> {
        let devid = device.requester_id();
        self.units.iter().enumerate().find_map(|(idx, unit)| {
            if unit.segment == device.segment && unit.covers_devid(devid) {
                Some(idx)
            } else {
                None
            }
        })
    }

    fn with_cmd_state<F, R>(&self, unit_idx: usize, f: F) -> Result<R, IommuError>
    where
        F: FnOnce(&mut AmdCommandState) -> Result<R, IommuError>,
    {
        let state = self
            .cmd_states
            .get(unit_idx)
            .and_then(|state| state.as_ref())
            .ok_or(IommuError::NotSupported)?;

        let mut guard = match state.lock() {
            Ok(guard) => guard,
            Err(_) => return Err(IommuError::Poisoned),
        };
        f(&mut *guard)
    }

    fn invalidate_device_entry(&self, device: DeviceId) -> Result<(), IommuError> {
        let unit_idx = self
            .find_unit_index_for_device(device)
            .ok_or(IommuError::DeviceNotFound)?;
        let devid = device.requester_id();
        self.with_cmd_state(unit_idx, |state| {
            state.submit_and_wait(cmd::AmdCommand::invalidate_device_entry(devid))
        })
    }

    fn invalidate_iotlb_pages(&self, device: DeviceId, iova: u64, size: u64) -> Result<(), IommuError> {
        let unit_idx = self
            .find_unit_index_for_device(device)
            .ok_or(IommuError::DeviceNotFound)?;
        let devid = device.requester_id();
        self.with_cmd_state(unit_idx, |state| {
            state.submit_and_wait(cmd::AmdCommand::invalidate_iotlb_pages(
                devid,
                0,
                iova,
                size,
                None,
            ))
        })
    }

    fn invalidate_iommu_pages(
        &self,
        device: DeviceId,
        domain_id: u16,
        iova: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        let unit_idx = self
            .find_unit_index_for_device(device)
            .ok_or(IommuError::DeviceNotFound)?;
        self.with_cmd_state(unit_idx, |state| {
            state.submit_and_wait(cmd::AmdCommand::invalidate_iommu_pages(
                domain_id,
                iova,
                size,
                None,
            ))
        })
    }
}

impl AmdIommuUnit {
    fn covers_devid(&self, devid: u16) -> bool {
        self.device_entries.iter().any(|entry| match entry {
            IvhdDeviceEntry::All { .. } => true,
            IvhdDeviceEntry::Select {
                devid: entry_devid, ..
            } => *entry_devid == devid,
            IvhdDeviceEntry::Range { start, end, .. } => devid >= *start && devid <= *end,
            IvhdDeviceEntry::Alias {
                devid: entry_devid,
                alias,
                ..
            } => *entry_devid == devid || *alias == devid,
            IvhdDeviceEntry::AliasRange {
                start, end, alias, ..
            } => (devid >= *start && devid <= *end) || *alias == devid,
            IvhdDeviceEntry::ExtSelect {
                devid: entry_devid, ..
            } => *entry_devid == devid,
            IvhdDeviceEntry::ExtRange { start, end, .. } => devid >= *start && devid <= *end,
            IvhdDeviceEntry::Special {
                devid: entry_devid, ..
            } => *entry_devid == devid,
            IvhdDeviceEntry::AcpiHid {
                devid: entry_devid, ..
            } => *entry_devid == devid,
        })
    }
}

struct AmdCommandState {
    buffer: cmd::AmdCommandBuffer,
    sync_ptr: NonNull<u64>,
    sync_phys: u64,
    seq: AtomicU64,
}

impl AmdCommandState {
    fn submit(&mut self, cmd: cmd::AmdCommand) -> Result<(), IommuError> {
        let _ = self.buffer.submit(cmd)?;
        Ok(())
    }

    fn submit_and_wait(&mut self, cmd: cmd::AmdCommand) -> Result<(), IommuError> {
        #[cfg(test)]
        {
            self.submit(cmd)?;
            return Ok(());
        }

        #[cfg(not(test))]
        {
            let next_seq = self.seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
            unsafe {
                self.sync_ptr.as_ptr().write_volatile(0);
            }

            self.submit(cmd)?;
            self.submit(cmd::AmdCommand::completion_wait(
                self.sync_phys,
                next_seq,
                false,
            ))?;

            let mut spins = 0u64;
            while unsafe { self.sync_ptr.as_ptr().read_volatile() } != next_seq {
                spins += 1;
                if spins > 1_000_000 {
                    return Err(IommuError::Timeout);
                }
                core::hint::spin_loop();
            }

            Ok(())
        }
    }
}

fn init_command_state(unit: &AmdIommuUnit) -> Result<AmdCommandState, IommuError> {
    let frame_count = cmd::CMD_BUFFER_BYTES / crate::mm::PAGE_SIZE_4K;
    let phys_base = buddy_alloc_contiguous_frames(frame_count).ok_or(IommuError::OutOfMemory)?;
    let virt_base = phys_to_virt(PhysAddr::new(phys_base.as_u64()));
    let buffer_ptr = NonNull::new(virt_base.as_u64() as *mut cmd::AmdCommand)
        .ok_or(IommuError::HardwareError)?;

    // Zero the command buffer to satisfy hardware expectations.
    unsafe {
        core::ptr::write_bytes(virt_base.as_u64() as *mut u8, 0, cmd::CMD_BUFFER_BYTES);
    }

    let sync_phys = buddy_alloc_contiguous_frames(1).ok_or(IommuError::OutOfMemory)?;
    let sync_virt = phys_to_virt(PhysAddr::new(sync_phys.as_u64()));
    let sync_ptr =
        NonNull::new(sync_virt.as_u64() as *mut u64).ok_or(IommuError::HardwareError)?;
    unsafe {
        sync_ptr.as_ptr().write_volatile(0);
    }

    let mmio_base = phys_to_virt_usize(unit.base_addr) as u64;
    let mut buffer = unsafe {
        cmd::AmdCommandBuffer::new(
            mmio_base,
            phys_base.as_u64(),
            buffer_ptr,
            cmd::CMD_BUFFER_ENTRIES,
        )?
    };

    unsafe {
        buffer.program()?;
        buffer.enable();
    }

    let mut state = AmdCommandState {
        buffer,
        sync_ptr,
        sync_phys: sync_phys.as_u64(),
        seq: AtomicU64::new(0),
    };

    if let Err(err) = state.submit_and_wait(cmd::AmdCommand::invalidate_all()) {
        log::warn!(
            "AMD-Vi command buffer invalidate_all failed for unit @ {:#x}: {:?}",
            unit.base_addr,
            err
        );
    }

    Ok(state)
}

fn init_command_states(units: &[AmdIommuUnit]) -> Vec<Option<PoisonLock<AmdCommandState>>> {
    let mut states = Vec::with_capacity(units.len());
    for unit in units {
        match init_command_state(unit) {
            Ok(state) => {
                log::info!(
                    "AMD-Vi command buffer enabled for unit @ {:#x}",
                    unit.base_addr
                );
                states.push(Some(PoisonLock::new(state)));
            }
            Err(err) => {
                log::warn!(
                    "AMD-Vi command buffer init failed for unit @ {:#x}: {:?}",
                    unit.base_addr,
                    err
                );
                states.push(None);
            }
        }
    }
    states
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
        numa_node: Option<usize>,
        domain_type: IommuDomainType,
    ) -> Result<u16, IommuError> {
        let raw_id = self.next_domain_id.fetch_add(1, Ordering::Relaxed);
        if raw_id > u16::MAX as u64 {
            return Err(IommuError::OutOfMemory);
        }
        let domain_id = raw_id as u16;
        let info = AmdDomainInfo {
            domain_type,
            numa_node,
        };

        let mut domains = self.domains.lock().map_err(|_| IommuError::Poisoned)?;
        domains.insert(domain_id, info);
        Ok(domain_id)
    }

    fn attach_device(&self, device: DeviceId, domain_id: u16) -> Result<(), IommuError> {
        if self.find_unit_for_device(device).is_none() {
            return Err(IommuError::DeviceNotFound);
        }
        {
            let domains = self.domains.lock().map_err(|_| IommuError::Poisoned)?;
            if !domains.contains_key(&domain_id) {
                return Err(IommuError::DomainNotFound);
            }
        }

        let previous = {
            let mut device_domains = self
                .device_domains
                .lock()
                .map_err(|_| IommuError::Poisoned)?;
            if let Some(existing) = device_domains.get(&device) {
                if *existing == domain_id {
                    return Ok(());
                }
            }
            device_domains.insert(device, domain_id)
        };

        if let Err(err) = self.invalidate_device_entry(device) {
            let mut device_domains = self
                .device_domains
                .lock()
                .map_err(|_| IommuError::Poisoned)?;
            match previous {
                Some(prev_id) => {
                    device_domains.insert(device, prev_id);
                }
                None => {
                    device_domains.remove(&device);
                }
            }
            return Err(err);
        }

        Ok(())
    }

    fn detach_device(&self, device: DeviceId) -> Result<(), IommuError> {
        if self.find_unit_for_device(device).is_none() {
            return Err(IommuError::DeviceNotFound);
        }

        let previous = {
            let mut device_domains = self
                .device_domains
                .lock()
                .map_err(|_| IommuError::Poisoned)?;
            device_domains.remove(&device)
        };

        let previous_domain = previous.ok_or(IommuError::DeviceNotFound)?;

        if let Err(err) = self.invalidate_device_entry(device) {
            let mut device_domains = self
                .device_domains
                .lock()
                .map_err(|_| IommuError::Poisoned)?;
            device_domains.insert(device, previous_domain);
            return Err(err);
        }

        Ok(())
    }

    fn set_domain_numa(
        &self,
        domain_id: u16,
        numa_node: Option<usize>,
    ) -> Result<(), IommuError> {
        let mut domains = self.domains.lock().map_err(|_| IommuError::Poisoned)?;
        let domain = domains.get_mut(&domain_id).ok_or(IommuError::DomainNotFound)?;
        domain.numa_node = numa_node;
        Ok(())
    }

    fn get_domain_numa(&self, domain_id: u16) -> Result<Option<usize>, IommuError> {
        let domains = self.domains.lock().map_err(|_| IommuError::Poisoned)?;
        let domain = domains.get(&domain_id).ok_or(IommuError::DomainNotFound)?;
        Ok(domain.numa_node)
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

    let cmd_states = init_command_states(&units);
    let cmd_ready = cmd_states.iter().filter(|buf| buf.is_some()).count();

    let unit_count = units.len();
    let ivmd_count = ivmd_ranges.len();
    AmdIommuDriver::register_driver(units, ivmd_ranges, cmd_states)?;
    log::info!(
        "AMD-Vi IVRS parsed ({} unit(s), {} IVMD range(s), {} cmd buffer(s) ready)",
        unit_count,
        ivmd_count,
        cmd_ready
    );

    Ok(())
}
