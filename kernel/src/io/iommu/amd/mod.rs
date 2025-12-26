// ============================================================================
// kernel/src/io/iommu/amd/mod.rs
// ============================================================================

//! AMD-Vi backend driver (skeleton).

pub mod cmd;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use x86_64::PhysAddr;

use crate::io::acpi::ivrs::{IvhdDeviceEntry, IvmdInfo};
use crate::io::iommu::tables::{phys_to_virt_usize, virt_ptr_to_phys};
use crate::io::mmio::{mmio_read_u64, mmio_write_u64};
use crate::mm::buddy_alloc_contiguous_frames;
use crate::mm::mapping::phys_to_virt;
// Use PAGE_SIZE_4K from local IOMMU iova_allocator instead
use crate::sync::PoisonLock;
use hashbrown::HashMap;

use super::interface::{IommuDriver, IommuFuture};
use super::registry::{get_iommu_driver, init_driver};
use super::{DeviceId, IommuConfig, IommuDomainType, IommuError, PageTablePool};
use super::domain::IommuDomain as DomainState;

const MMIO_DEV_TABLE_OFFSET: u64 = 0x0000;
const MMIO_CONTROL_OFFSET: u64 = 0x0018;

const CONTROL_IOMMU_EN: u64 = 1 << 0;
const CONTROL_CMDBUF_EN: u64 = 1 << 12;

const DEV_ENTRY_MODE_SHIFT: u64 = 9;
const PAGE_MODE_4_LEVEL: u64 = 0x04;
const PM_ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;

const DTE_FLAG_V: u64 = 1 << 0;
const DTE_FLAG_TV: u64 = 1 << 1;
const DTE_FLAG_IR: u64 = 1 << 61;
const DTE_FLAG_IW: u64 = 1 << 62;

const DEV_TABLE_ENTRY_SIZE: usize = 32;

const IVHD_INIT_PASS: u8 = 1 << 0;
const IVHD_EINT_PASS: u8 = 1 << 1;
const IVHD_NMI_PASS: u8 = 1 << 2;
const IVHD_SYSMGT1: u8 = 1 << 4;
const IVHD_SYSMGT2: u8 = 1 << 5;
const IVHD_LINT0_PASS: u8 = 1 << 6;
const IVHD_LINT1_PASS: u8 = 1 << 7;

const DEV_ENTRY_INIT_PASS: u8 = 0xb8;
const DEV_ENTRY_EINT_PASS: u8 = 0xb9;
const DEV_ENTRY_NMI_PASS: u8 = 0xba;
const DEV_ENTRY_SYSMGT1: u8 = 0x68;
const DEV_ENTRY_SYSMGT2: u8 = 0x69;
const DEV_ENTRY_LINT0_PASS: u8 = 0xbe;
const DEV_ENTRY_LINT1_PASS: u8 = 0xbf;

fn set_dte_bit(entry: &mut AmdDeviceTableEntry, bit: u8) {
    let idx = (bit >> 6) & 0x03;
    let shift = bit & 0x3f;
    entry.data[idx as usize] |= 1u64 << shift;
}

fn apply_ivhd_flags(entry: &mut AmdDeviceTableEntry, flags: u8) {
    if (flags & IVHD_INIT_PASS) != 0 {
        set_dte_bit(entry, DEV_ENTRY_INIT_PASS);
    }
    if (flags & IVHD_EINT_PASS) != 0 {
        set_dte_bit(entry, DEV_ENTRY_EINT_PASS);
    }
    if (flags & IVHD_NMI_PASS) != 0 {
        set_dte_bit(entry, DEV_ENTRY_NMI_PASS);
    }
    if (flags & IVHD_SYSMGT1) != 0 {
        set_dte_bit(entry, DEV_ENTRY_SYSMGT1);
    }
    if (flags & IVHD_SYSMGT2) != 0 {
        set_dte_bit(entry, DEV_ENTRY_SYSMGT2);
    }
    if (flags & IVHD_LINT0_PASS) != 0 {
        set_dte_bit(entry, DEV_ENTRY_LINT0_PASS);
    }
    if (flags & IVHD_LINT1_PASS) != 0 {
        set_dte_bit(entry, DEV_ENTRY_LINT1_PASS);
    }
}

#[repr(C, align(32))]
#[derive(Clone, Copy)]
struct AmdDeviceTableEntry {
    data: [u64; 4],
}

impl Default for AmdDeviceTableEntry {
    fn default() -> Self {
        Self { data: [0; 4] }
    }
}

struct AmdDeviceTable {
    segment: u16,
    phys_base: u64,
    virt_base: NonNull<AmdDeviceTableEntry>,
    size_bytes: u64,
    entry_count: usize,
    lock: PoisonLock<()>,
}

// SAFETY: AmdDeviceTable contains raw pointers to a contiguous region of kernel memory
// which is accessed with proper synchronization using `lock`. It is therefore safe to
// treat the structure as `Send` and `Sync` across threads.
unsafe impl Send for AmdDeviceTable {}
unsafe impl Sync for AmdDeviceTable {}

impl AmdDeviceTable {
    fn new(segment: u16, entry_count: usize) -> Result<Self, IommuError> {
        if entry_count == 0 {
            return Err(IommuError::InvalidAddress);
        }

        debug_assert_eq!(size_of::<AmdDeviceTableEntry>(), DEV_TABLE_ENTRY_SIZE);

        let entry_bytes = size_of::<AmdDeviceTableEntry>() as u64;
        let mut size_bytes = (entry_count as u64)
            .checked_mul(entry_bytes)
            .ok_or(IommuError::InvalidAddress)?;
        if size_bytes < crate::io::iommu::iova_allocator::PAGE_SIZE_4K {
            size_bytes = crate::io::iommu::iova_allocator::PAGE_SIZE_4K;
        }
        size_bytes = size_bytes.next_power_of_two();

        let frame_count = (size_bytes / crate::io::iommu::iova_allocator::PAGE_SIZE_4K) as usize;
        let phys_base = buddy_alloc_contiguous_frames(frame_count).ok_or(IommuError::OutOfMemory)?;
        let virt_base = phys_to_virt(PhysAddr::new(phys_base.as_u64()));
        let entry_ptr =
            NonNull::new(virt_base.as_u64() as *mut AmdDeviceTableEntry)
                .ok_or(IommuError::HardwareError)?;

        unsafe {
            ptr::write_bytes(virt_base.as_u64() as *mut u8, 0, size_bytes as usize);
        }

        Ok(Self {
            segment,
            phys_base: phys_base.as_u64(),
            virt_base: entry_ptr,
            size_bytes,
            entry_count: (size_bytes / entry_bytes) as usize,
            lock: PoisonLock::new(()),
        })
    }

    fn program(&self, unit: &AmdIommuUnit) -> Result<(), IommuError> {
        if (self.phys_base & 0xfff) != 0 {
            return Err(IommuError::InvalidAlignment);
        }

        let size_field = (self.size_bytes >> 12).saturating_sub(1);
        let entry = (self.phys_base & !0xfff) | size_field;
        let mmio_base = phys_to_virt_usize(unit.base_addr);
        mmio_write_u64(mmio_base + MMIO_DEV_TABLE_OFFSET as usize, entry);
        Ok(())
    }

    fn write_entry(&self, devid: u16, entry: AmdDeviceTableEntry) -> Result<(), IommuError> {
        let _guard = self.lock.lock().map_err(|_| IommuError::Poisoned)?;
        let index = devid as usize;
        if index >= self.entry_count {
            return Err(IommuError::DeviceNotFound);
        }
        unsafe {
            self.virt_base.as_ptr().add(index).write_volatile(entry);
        }
        Ok(())
    }

    fn clear_entry(&self, devid: u16) -> Result<(), IommuError> {
        self.write_entry(devid, AmdDeviceTableEntry::default())
    }

    fn fill(&self, entry: AmdDeviceTableEntry) -> Result<(), IommuError> {
        let _guard = self.lock.lock().map_err(|_| IommuError::Poisoned)?;
        for idx in 0..self.entry_count {
            unsafe {
                self.virt_base.as_ptr().add(idx).write_volatile(entry);
            }
        }
        Ok(())
    }
}

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
    device_tables: HashMap<u16, AmdDeviceTable>,
    domains: PoisonLock<HashMap<u16, AmdDomainInfo>>,
    device_domains: PoisonLock<HashMap<DeviceId, u16>>,
    next_domain_id: AtomicU64,
    page_table_pool: Arc<PageTablePool>,
    enabled: AtomicBool,
}

#[derive(Clone)]
struct AmdDomainInfo {
    domain: Arc<PoisonLock<DomainState>>,
}

impl AmdIommuDriver {
    pub fn new(
        units: Vec<AmdIommuUnit>,
        ivmd_ranges: Vec<AmdIvmdRange>,
        cmd_states: Vec<Option<PoisonLock<AmdCommandState>>>,
        device_tables: HashMap<u16, AmdDeviceTable>,
    ) -> Self {
        let page_table_pool =
            PageTablePool::new(crate::mm::numa::num_nodes().max(1), 32);
        let mut domain_map = HashMap::new();
        let default_domain = DomainState::new(
            0,
            None,
            false,
            false,
            IommuDomainType::Translated,
            page_table_pool.clone(),
        );
        let default_domain = Arc::new(PoisonLock::new(default_domain));
        domain_map.insert(0, AmdDomainInfo { domain: default_domain });

        Self {
            units,
            ivmd_ranges,
            cmd_states,
            device_tables,
            domains: PoisonLock::new(domain_map),
            device_domains: PoisonLock::new(HashMap::new()),
            next_domain_id: AtomicU64::new(1),
            page_table_pool,
            enabled: AtomicBool::new(false),
        }
    }

    pub fn register_driver(
        units: Vec<AmdIommuUnit>,
        ivmd_ranges: Vec<AmdIvmdRange>,
        cmd_states: Vec<Option<PoisonLock<AmdCommandState>>>,
        device_tables: HashMap<u16, AmdDeviceTable>,
    ) -> Result<(), IommuError> {
        if get_iommu_driver().is_some() {
            return Err(IommuError::AlreadyInitialized);
        }
        let driver = Arc::new(AmdIommuDriver::new(
            units,
            ivmd_ranges,
            cmd_states,
            device_tables,
        ));
        driver.populate_default_entries()?;
        init_driver(driver);
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

    fn ivhd_flags_for_device(&self, device: DeviceId) -> u8 {
        let mut flags = 0u8;
        let devid = device.requester_id();
        let unit = match self.find_unit_for_device(device) {
            Some(unit) => unit,
            None => return flags,
        };

        for entry in &unit.device_entries {
            match entry {
                IvhdDeviceEntry::All { flags: entry_flags } => flags |= *entry_flags,
                IvhdDeviceEntry::Select { devid: entry_devid, flags: entry_flags } => {
                    if *entry_devid == devid {
                        flags |= *entry_flags;
                    }
                }
                IvhdDeviceEntry::Range { start, end, flags: entry_flags } => {
                    if devid >= *start && devid <= *end {
                        flags |= *entry_flags;
                    }
                }
                IvhdDeviceEntry::Alias {
                    devid: entry_devid,
                    alias,
                    flags: entry_flags,
                } => {
                    if *entry_devid == devid || *alias == devid {
                        flags |= *entry_flags;
                    }
                }
                IvhdDeviceEntry::AliasRange {
                    start,
                    end,
                    alias,
                    flags: entry_flags,
                } => {
                    if (devid >= *start && devid <= *end) || *alias == devid {
                        flags |= *entry_flags;
                    }
                }
                IvhdDeviceEntry::ExtSelect { devid: entry_devid, flags: entry_flags, .. } => {
                    if *entry_devid == devid {
                        flags |= *entry_flags;
                    }
                }
                IvhdDeviceEntry::ExtRange { start, end, flags: entry_flags, .. } => {
                    if devid >= *start && devid <= *end {
                        flags |= *entry_flags;
                    }
                }
                IvhdDeviceEntry::Special { devid: entry_devid, flags: entry_flags, .. } => {
                    if *entry_devid == devid {
                        flags |= *entry_flags;
                    }
                }
                IvhdDeviceEntry::AcpiHid { devid: entry_devid, flags: entry_flags } => {
                    if *entry_devid == devid {
                        flags |= *entry_flags;
                    }
                }
            }
        }

        flags
    }

    fn ivhd_global_flags(&self, segment: u16) -> u8 {
        let mut flags = 0u8;
        for unit in &self.units {
            if unit.segment != segment {
                continue;
            }
            for entry in &unit.device_entries {
                if let IvhdDeviceEntry::All { flags: entry_flags } = entry {
                    flags |= *entry_flags;
                }
            }
        }
        flags
    }

    fn domain_for_id(&self, domain_id: u16) -> Result<Arc<PoisonLock<DomainState>>, IommuError> {
        let domains = self.domains.lock().map_err(|_| IommuError::Poisoned)?;
        let info = domains.get(&domain_id).ok_or(IommuError::DomainNotFound)?;
        Ok(info.domain.clone())
    }

    fn device_table_for_segment(&self, segment: u16) -> Result<&AmdDeviceTable, IommuError> {
        self.device_tables
            .get(&segment)
            .ok_or(IommuError::NotPresent)
    }

    fn build_dte_entry(
        &self,
        domain_id: u16,
        domain: &DomainState,
        ivhd_flags: u8,
    ) -> Result<AmdDeviceTableEntry, IommuError> {
        let mut entry = AmdDeviceTableEntry::default();
        entry.data[0] |= DTE_FLAG_V | DTE_FLAG_TV | DTE_FLAG_IR | DTE_FLAG_IW;

        if domain.domain_type != IommuDomainType::Passthrough {
            let root_phys = virt_ptr_to_phys(domain.page_table as *const u8)?;
            if (root_phys & 0xfff) != 0 {
                return Err(IommuError::InvalidAlignment);
            }
            entry.data[0] |= (root_phys & PM_ADDR_MASK) | (PAGE_MODE_4_LEVEL << DEV_ENTRY_MODE_SHIFT);
        }

        if ivhd_flags != 0 {
            apply_ivhd_flags(&mut entry, ivhd_flags);
        }

        entry.data[1] |= domain_id as u64;
        Ok(entry)
    }

    fn alias_devids_for_device(&self, device: DeviceId) -> Vec<u16> {
        let mut aliases = Vec::new();
        let devid = device.requester_id();
        let unit = match self.find_unit_for_device(device) {
            Some(unit) => unit,
            None => return aliases,
        };

        for entry in &unit.device_entries {
            match entry {
                IvhdDeviceEntry::Alias {
                    devid: entry_devid,
                    alias,
                    ..
                } => {
                    if *entry_devid == devid && *alias != devid {
                        aliases.push(*alias);
                    }
                }
                IvhdDeviceEntry::AliasRange { start, end, alias, .. } => {
                    if devid >= *start && devid <= *end && *alias != devid {
                        aliases.push(*alias);
                    }
                }
                _ => {}
            }
        }

        aliases.sort_unstable();
        aliases.dedup();
        aliases
    }

    fn map_ivmd_ranges_for_device(
        &self,
        device: DeviceId,
        domain_id: u16,
    ) -> Result<(), IommuError> {
        let ranges = self.ivmd_ranges_for_device(device);
        if ranges.is_empty() {
            return Ok(());
        }

        let domain = self.domain_for_id(domain_id)?;
        let mut guard = domain.lock().map_err(|_| IommuError::Poisoned)?;
        map_ivmd_ranges(&mut guard, &ranges)
    }

    fn device_id_from_devid(segment: u16, devid: u16) -> DeviceId {
        let bus = (devid >> 8) as u8;
        let devfn = (devid & 0xff) as u8;
        let device = (devfn >> 3) & 0x1f;
        let function = devfn & 0x07;
        DeviceId::new(segment, bus, device, function)
    }

    fn invalidate_device_entry_by_devid(
        &self,
        segment: u16,
        devid: u16,
    ) -> Result<(), IommuError> {
        let device = Self::device_id_from_devid(segment, devid);
        self.invalidate_device_entry(device)
    }

    fn write_device_entries_for_domain(
        &self,
        device: DeviceId,
        aliases: &[u16],
        domain_id: Option<u16>,
    ) -> Result<(), IommuError> {
        let table = self.device_table_for_segment(device.segment)?;
        let devid = device.requester_id();
        match domain_id {
            Some(domain_id) => {
                let domain = self.domain_for_id(domain_id)?;
                let guard = domain.lock().map_err(|_| IommuError::Poisoned)?;
                let flags = AmdIommuDriver::ivhd_flags_for_device(self, device);
                let entry = self.build_dte_entry(domain_id, &guard, flags)?;
                table.write_entry(devid, entry)?;
                for alias in aliases {
                    table.write_entry(*alias, entry)?;
                }
            }
            None => {
                table.clear_entry(devid)?;
                for alias in aliases {
                    table.clear_entry(*alias)?;
                }
            }
        }
        Ok(())
    }

    fn domain_id_for_device(&self, device: DeviceId) -> Result<u16, IommuError> {
        let device_domains = self
            .device_domains
            .lock()
            .map_err(|_| IommuError::Poisoned)?;
        device_domains
            .get(&device)
            .copied()
            .ok_or(IommuError::DomainNotFound)
    }

    fn populate_default_entries(&self) -> Result<(), IommuError> {
        let default_domain = self.domain_for_id(0)?;
        let mut domain = default_domain.lock().map_err(|_| IommuError::Poisoned)?;
        map_ivmd_ranges(&mut domain, &self.ivmd_ranges)?;
        drop(domain);

        for (segment, table) in &self.device_tables {
            let flags = AmdIommuDriver::ivhd_global_flags(self, *segment);
            let domain = self.domain_for_id(0)?;
            let guard = domain.lock().map_err(|_| IommuError::Poisoned)?;
            let entry = self.build_dte_entry(0, &guard, flags)?;
            drop(guard);
            table.fill(entry)?;
        }

        if let Err(err) = self.invalidate_all_entries() {
            if err != IommuError::NotSupported {
                return Err(err);
            }
        }
        Ok(())
    }

    fn invalidate_all_entries(&self) -> Result<(), IommuError> {
        let mut has_state = false;
        for idx in 0..self.cmd_states.len() {
            if self.cmd_states[idx].is_none() {
                continue;
            }
            has_state = true;
            self.with_cmd_state(idx, |state| {
                state.submit_and_wait(cmd::AmdCommand::invalidate_all())
            })?;
        }

        if !has_state {
            return Err(IommuError::NotSupported);
        }
        Ok(())
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

    fn invalidate_domain_pages(&self, domain_id: u16, iova: u64, size: u64) -> Result<(), IommuError> {
        let mut has_state = false;
        for idx in 0..self.cmd_states.len() {
            if self.cmd_states[idx].is_none() {
                continue;
            }
            has_state = true;
            self.with_cmd_state(idx, |state| {
                state.submit_and_wait(cmd::AmdCommand::invalidate_iommu_pages(
                    domain_id,
                    iova,
                    size,
                    None,
                ))
            })?;
        }

        if !has_state {
            return Err(IommuError::NotSupported);
        }
        Ok(())
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

// SAFETY: `AmdCommandState` contains raw pointers to memory used for command buffer
// completion synchronization (`sync_ptr`). Access to this state is synchronized by
// PoisonLock wrappers when used in `cmd_states`, ensuring safe concurrent access.
unsafe impl Send for AmdCommandState {}
unsafe impl Sync for AmdCommandState {}

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
    let frame_count = cmd::CMD_BUFFER_BYTES / (crate::io::iommu::iova_allocator::PAGE_SIZE_4K as usize);
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

fn max_devid_for_entries(entries: &[IvhdDeviceEntry]) -> u16 {
    let mut max = 0;
    for entry in entries {
        let entry_max = match entry {
            IvhdDeviceEntry::All { .. } => return u16::MAX,
            IvhdDeviceEntry::Select { devid, .. } => *devid,
            IvhdDeviceEntry::Range { start, end, .. } => (*start).max(*end),
            IvhdDeviceEntry::Alias { devid, alias, .. } => (*devid).max(*alias),
            IvhdDeviceEntry::AliasRange { start, end, alias, .. } => {
                (*start).max(*end).max(*alias)
            }
            IvhdDeviceEntry::ExtSelect { devid, .. } => *devid,
            IvhdDeviceEntry::ExtRange { start, end, .. } => (*start).max(*end),
            IvhdDeviceEntry::Special { devid, .. } => *devid,
            IvhdDeviceEntry::AcpiHid { devid, .. } => *devid,
        };

        if entry_max > max {
            max = entry_max;
        }
    }
    max
}

fn init_device_tables(
    units: &[AmdIommuUnit],
) -> Result<HashMap<u16, AmdDeviceTable>, IommuError> {
    let mut max_by_segment = HashMap::<u16, u16>::new();
    for unit in units {
        let max_devid = max_devid_for_entries(&unit.device_entries);
        max_by_segment
            .entry(unit.segment)
            .and_modify(|current| {
                if max_devid > *current {
                    *current = max_devid;
                }
            })
            .or_insert(max_devid);
    }

    let mut tables = HashMap::new();
    for (segment, max_devid) in max_by_segment {
        let entry_count = (max_devid as usize).saturating_add(1);
        let table = AmdDeviceTable::new(segment, entry_count)?;
        tables.insert(segment, table);
    }
    Ok(tables)
}

fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

fn map_ivmd_ranges(domain: &mut DomainState, ranges: &[AmdIvmdRange]) -> Result<(), IommuError> {
    let page_size = crate::io::iommu::iova_allocator::PAGE_SIZE_4K;

    for range in ranges {
        if !range.unity_map {
            continue;
        }

        let start = align_down(range.range_start, page_size);
        let end = align_up(range.range_end, page_size);
        if end <= start {
            continue;
        }

        let size = end - start;
        match domain.map(start, start, size, range.read, range.write) {
            Ok(()) => {}
            Err(IommuError::AlreadyMapped) => {}
            Err(err) => return Err(err),
        }
    }

    Ok(())
}

impl IommuDriver for AmdIommuDriver {
    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    fn enable(&self) -> Result<(), IommuError> {
        for (idx, unit) in self.units.iter().enumerate() {
            let table = self
                .device_tables
                .get(&unit.segment)
                .ok_or(IommuError::NotPresent)?;
            table.program(unit)?;

            let mmio_base = phys_to_virt_usize(unit.base_addr);
            let mut control = mmio_read_u64(mmio_base + MMIO_CONTROL_OFFSET as usize);
            control |= CONTROL_IOMMU_EN;
            if self
                .cmd_states
                .get(idx)
                .and_then(|state| state.as_ref())
                .is_some()
            {
                control |= CONTROL_CMDBUF_EN;
            } else {
                control &= !CONTROL_CMDBUF_EN;
            }
            mmio_write_u64(mmio_base + MMIO_CONTROL_OFFSET as usize, control);
        }
        self.enabled.store(true, Ordering::Release);
        Ok(())
    }

    fn disable(&self) -> Result<(), IommuError> {
        for unit in &self.units {
            let mmio_base = phys_to_virt_usize(unit.base_addr);
            let mut control = mmio_read_u64(mmio_base + MMIO_CONTROL_OFFSET as usize);
            control &= !(CONTROL_IOMMU_EN | CONTROL_CMDBUF_EN);
            mmio_write_u64(mmio_base + MMIO_CONTROL_OFFSET as usize, control);
        }
        self.enabled.store(false, Ordering::Release);
        Ok(())
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

    unsafe fn map_for_dma(&self, phys_addr: PhysAddr, size: u64) -> Result<u64, IommuError> {
        let iova = phys_addr.as_u64();
        let domain = self.domain_for_id(0)?;
        {
            let mut guard = domain.lock().map_err(|_| IommuError::Poisoned)?;
            guard.map(iova, phys_addr.as_u64(), size, true, true)?;
        }
        if let Err(err) = self.invalidate_domain_pages(0, iova, size) {
            if err != IommuError::NotSupported {
                return Err(err);
            }
        }
        Ok(iova)
    }

    fn unmap_dma(&self, iova: u64, _size: u64) -> Result<(), IommuError> {
        let domain = self.domain_for_id(0)?;
        let mapped_size = {
            let mut guard = domain.lock().map_err(|_| IommuError::Poisoned)?;
            let mapping = guard.unmap(iova)?;
            mapping.size
        };
        if let Err(err) = self.invalidate_domain_pages(0, iova, mapped_size) {
            if err != IommuError::NotSupported {
                return Err(err);
            }
        }
        Ok(())
    }

    unsafe fn map_for_device(
        &self,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
    ) -> Result<u64, IommuError> {
        crate::task::block_on(async {
            unsafe { self.map_for_device_async(device, phys_addr, size).await }
        })
    }

    unsafe fn map_for_device_async<'a>(
        &'a self,
        device: &'a DeviceId,
        phys_addr: PhysAddr,
        size: u64,
    ) -> IommuFuture<'a, Result<u64, IommuError>> {
        Box::pin(async move {
            let domain_id = self.domain_id_for_device(*device)?;
            let domain = self.domain_for_id(domain_id)?;
            let iova = phys_addr.as_u64();

            {
                let mut guard = domain.lock().map_err(|_| IommuError::Poisoned)?;
                guard.map(iova, phys_addr.as_u64(), size, true, true)?;
            }

            self.invalidate_iommu_pages(*device, domain_id, iova, size)?;
            self.invalidate_iotlb_pages(*device, iova, size)?;
            Ok(iova)
        })
    }

    fn unmap_for_device(
        &self,
        device: &DeviceId,
        iova: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        crate::task::block_on(async { self.unmap_for_device_async(device, iova, size).await })
    }

    fn unmap_for_device_async<'a>(
        &'a self,
        device: &'a DeviceId,
        iova: u64,
        _size: u64,
    ) -> IommuFuture<'a, Result<(), IommuError>> {
        Box::pin(async move {
            let domain_id = self.domain_id_for_device(*device)?;
            let domain = self.domain_for_id(domain_id)?;
            let mapping = {
                let mut guard = domain.lock().map_err(|_| IommuError::Poisoned)?;
                guard.unmap(iova)?
            };

            self.invalidate_iommu_pages(*device, domain_id, iova, mapping.size)?;
            self.invalidate_iotlb_pages(*device, iova, mapping.size)?;
            Ok(())
        })
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
        let domain = DomainState::new(
            domain_id,
            numa_node,
            false,
            false,
            domain_type,
            self.page_table_pool.clone(),
        );
        let info = AmdDomainInfo {
            domain: Arc::new(PoisonLock::new(domain)),
        };

        let mut domains = self.domains.lock().map_err(|_| IommuError::Poisoned)?;
        if domains.insert(domain_id, info).is_some() {
            return Err(IommuError::HardwareError);
        }
        Ok(domain_id)
    }

    fn attach_device(&self, device: DeviceId, domain_id: u16) -> Result<(), IommuError> {
        if self.find_unit_for_device(device).is_none() {
            return Err(IommuError::DeviceNotFound);
        }
        let _domain = self.domain_for_id(domain_id)?;
        let aliases = self.alias_devids_for_device(device);

        let existing = {
            let mut device_domains = self
                .device_domains
                .lock()
                .map_err(|_| IommuError::Poisoned)?;
            if let Some(existing) = device_domains.get(&device) {
                Some(*existing)
            } else {
                None
            }
        };

        if existing == Some(domain_id) {
            self.map_ivmd_ranges_for_device(device, domain_id)?;
            return Ok(());
        }

        self.map_ivmd_ranges_for_device(device, domain_id)?;

        let previous = {
            let mut device_domains = self
                .device_domains
                .lock()
                .map_err(|_| IommuError::Poisoned)?;
            device_domains.insert(device, domain_id)
        };

        if let Err(err) = self.write_device_entries_for_domain(device, &aliases, Some(domain_id)) {
            let mut device_domains = self
                .device_domains
                .lock()
                .map_err(|_| IommuError::Poisoned)?;
            match previous {
                Some(prev_id) => {
                    device_domains.insert(device, prev_id);
                    let _ = self.write_device_entries_for_domain(device, &aliases, Some(prev_id));
                }
                None => {
                    device_domains.remove(&device);
                    let _ = self.write_device_entries_for_domain(device, &aliases, None);
                }
            }
            return Err(err);
        }

        if let Err(err) = self.invalidate_device_entry(device) {
            let mut device_domains = self
                .device_domains
                .lock()
                .map_err(|_| IommuError::Poisoned)?;
            match previous {
                Some(prev_id) => {
                    device_domains.insert(device, prev_id);
                    let _ = self.write_device_entries_for_domain(device, &aliases, Some(prev_id));
                }
                None => {
                    device_domains.remove(&device);
                    let _ = self.write_device_entries_for_domain(device, &aliases, None);
                }
            }
            return Err(err);
        }

        for alias in &aliases {
            if let Err(err) = self.invalidate_device_entry_by_devid(device.segment, *alias) {
                let mut device_domains = self
                    .device_domains
                    .lock()
                    .map_err(|_| IommuError::Poisoned)?;
                match previous {
                    Some(prev_id) => {
                        device_domains.insert(device, prev_id);
                        let _ =
                            self.write_device_entries_for_domain(device, &aliases, Some(prev_id));
                    }
                    None => {
                        device_domains.remove(&device);
                        let _ = self.write_device_entries_for_domain(device, &aliases, None);
                    }
                }
                return Err(err);
            }
        }

        Ok(())
    }

    fn detach_device(&self, device: DeviceId) -> Result<(), IommuError> {
        if self.find_unit_for_device(device).is_none() {
            return Err(IommuError::DeviceNotFound);
        }
        let aliases = self.alias_devids_for_device(device);

        let previous = {
            let mut device_domains = self
                .device_domains
                .lock()
                .map_err(|_| IommuError::Poisoned)?;
            device_domains.remove(&device)
        };

        let previous_domain = previous.ok_or(IommuError::DeviceNotFound)?;

        if let Err(err) = self.write_device_entries_for_domain(device, &aliases, None) {
            let mut device_domains = self
                .device_domains
                .lock()
                .map_err(|_| IommuError::Poisoned)?;
            device_domains.insert(device, previous_domain);
            let _ = self.write_device_entries_for_domain(device, &aliases, Some(previous_domain));
            return Err(err);
        }

        if let Err(err) = self.invalidate_device_entry(device) {
            let mut device_domains = self
                .device_domains
                .lock()
                .map_err(|_| IommuError::Poisoned)?;
            device_domains.insert(device, previous_domain);
            let _ = self.write_device_entries_for_domain(device, &aliases, Some(previous_domain));
            return Err(err);
        }

        for alias in &aliases {
            if let Err(err) = self.invalidate_device_entry_by_devid(device.segment, *alias) {
                let mut device_domains = self
                    .device_domains
                    .lock()
                    .map_err(|_| IommuError::Poisoned)?;
                device_domains.insert(device, previous_domain);
                let _ =
                    self.write_device_entries_for_domain(device, &aliases, Some(previous_domain));
                return Err(err);
            }
        }

        Ok(())
    }

    fn set_domain_numa(
        &self,
        domain_id: u16,
        numa_node: Option<usize>,
    ) -> Result<(), IommuError> {
        let domain = self.domain_for_id(domain_id)?;
        let mut guard = domain.lock().map_err(|_| IommuError::Poisoned)?;
        guard.numa_node = numa_node;
        Ok(())
    }

    fn get_domain_numa(&self, domain_id: u16) -> Result<Option<usize>, IommuError> {
        let domain = self.domain_for_id(domain_id)?;
        let guard = domain.lock().map_err(|_| IommuError::Poisoned)?;
        Ok(guard.numa_node)
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

    let device_tables = init_device_tables(&units)?;
    for unit in &units {
        let table = device_tables
            .get(&unit.segment)
            .ok_or(IommuError::NotPresent)?;
        table.program(unit)?;
    }

    let unit_count = units.len();
    let ivmd_count = ivmd_ranges.len();
    let table_count = device_tables.len();
    AmdIommuDriver::register_driver(units, ivmd_ranges, cmd_states, device_tables)?;
    log::info!(
        "AMD-Vi IVRS parsed ({} unit(s), {} IVMD range(s), {} cmd buffer(s) ready, {} device table(s))",
        unit_count,
        ivmd_count,
        cmd_ready,
        table_count
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_driver(entries: Vec<IvhdDeviceEntry>) -> AmdIommuDriver {
        let unit = AmdIommuUnit {
            segment: 0,
            base_addr: 0,
            flags: 0,
            device_id: 0,
            iommu_info: 0,
            iommu_feature: 0,
            device_entries: entries,
        };

        AmdIommuDriver {
            units: alloc::vec![unit],
            ivmd_ranges: Vec::new(),
            cmd_states: Vec::new(),
            device_tables: HashMap::new(),
            domains: PoisonLock::new(HashMap::new()),
            device_domains: PoisonLock::new(HashMap::new()),
            next_domain_id: AtomicU64::new(1),
            page_table_pool: PageTablePool::new(1, 1),
            enabled: AtomicBool::new(false),
        }
    }

    #[test]
    fn test_alias_devids_for_device_dedup() {
        let device = DeviceId::new(0, 1, 0, 0);
        let devid = device.requester_id();
        let driver = make_driver(alloc::vec![
            IvhdDeviceEntry::Select { devid, flags: 0 },
            IvhdDeviceEntry::Alias {
                devid,
                alias: 0x0200,
                flags: 0,
            },
            IvhdDeviceEntry::AliasRange {
                start: devid,
                end: devid + 3,
                alias: 0x0300,
                flags: 0,
            },
            IvhdDeviceEntry::Alias {
                devid,
                alias: 0x0200,
                flags: 0,
            },
            IvhdDeviceEntry::Alias {
                devid,
                alias: devid,
                flags: 0,
            },
        ]);

        let aliases = driver.alias_devids_for_device(device);
        assert_eq!(aliases, alloc::vec![0x0200, 0x0300]);
    }

    #[test]
    fn test_alias_devids_for_device_no_match() {
        let driver = make_driver(alloc::vec![IvhdDeviceEntry::Select {
            devid: 0x0100,
            flags: 0,
        }]);
        let device = DeviceId::new(0, 2, 0, 0);
        let aliases = driver.alias_devids_for_device(device);
        assert!(aliases.is_empty());
    }

    #[test]
    fn test_ivhd_flags_for_device_combined() {
        let device = DeviceId::new(0, 2, 0, 0);
        let devid = device.requester_id();
        let driver = make_driver(alloc::vec![
            IvhdDeviceEntry::All { flags: 0x01 },
            IvhdDeviceEntry::Select { devid, flags: 0x02 },
            IvhdDeviceEntry::Range {
                start: devid,
                end: devid + 0x0f,
                flags: 0x04,
            },
            IvhdDeviceEntry::Alias {
                devid: 0x0100,
                alias: devid,
                flags: 0x08,
            },
            IvhdDeviceEntry::AliasRange {
                start: 0x0300,
                end: 0x030f,
                alias: devid,
                flags: 0x10,
            },
            IvhdDeviceEntry::ExtSelect {
                devid,
                flags: 0x20,
                ext_flags: 0,
            },
            IvhdDeviceEntry::ExtRange {
                start: devid,
                end: devid,
                flags: 0x40,
                ext_flags: 0,
            },
            IvhdDeviceEntry::Special {
                devid,
                flags: 0x80,
                handle: 0,
                variety: 0,
            },
        ]);

        let flags = driver.ivhd_flags_for_device(device);
        assert_eq!(flags, 0xff);
    }

    #[test]
    fn test_ivhd_flags_for_device_acpi_hid() {
        let device = DeviceId::new(0, 2, 0, 0);
        let devid = device.requester_id();
        let driver = make_driver(alloc::vec![IvhdDeviceEntry::AcpiHid {
            devid,
            flags: 0x03,
        }]);

        let flags = driver.ivhd_flags_for_device(device);
        assert_eq!(flags, 0x03);
    }
}
