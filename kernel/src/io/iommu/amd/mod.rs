// ============================================================================
// kernel/src/io/iommu/amd/mod.rs
// ============================================================================

//! AMD-Vi backend driver.

pub mod cmd;
pub mod driver;
pub mod tables;

pub(super) mod registers;
pub(super) mod device_table;
pub(super) mod event_log;
pub(super) mod fault;
pub(super) mod invalidation;
pub(super) mod domain;
pub(super) mod dma;
pub(super) mod init;

#[cfg(test)]
mod tests;
#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests;

// Re-exports for external callers (driver.rs, backend.rs, etc.)
pub use self::init::init_iommu_from_ivrs;
#[allow(unused_imports)]
pub use self::fault::{drain_deferred_faults, fault_handler_task, spawn_fault_handler_task};

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::io::acpi::ivrs::{IvhdDeviceEntry, IvmdInfo};
use crate::io::iommu::cmdqueue::CommandQueue;
use crate::io::iommu::tables::phys_to_virt_usize;
use crate::io::mmio::{mmio_read_u64, mmio_write_u64};
use crate::io::iommu::{IovaAllocatorFast, PAGE_SIZE_4K};
use crate::io::iommu::security::{SecurityEvent, SecurityNotifier};
use crate::sync::PoisonLock;
use hashbrown::HashMap;

use super::domain::IommuDomain as DomainState;
use super::IommuBackend;
use super::page_table_pool::PageTablePool;
use super::registry::{get_iommu_driver, init_driver};
use super::types::{DeviceId, IommuDomainType, IommuError, PteFormat};

use self::device_table::AmdDeviceTable;
use self::domain::align_down;
use self::domain::align_up;
use self::event_log::AmdEventLog;
use self::invalidation::AmdCommandState;
use self::registers::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(super) fn devid_to_bdf(devid: u16) -> (u8, u8, u8) {
    let bus = (devid >> 8) as u8;
    let devfn = (devid & 0xff) as u8;
    let device = (devfn >> 3) & 0x1f;
    let function = devfn & 0x07;
    (bus, device, function)
}

// ---------------------------------------------------------------------------
// IOMMU Unit descriptor (parsed from IVHD)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AmdIommuUnit {
    pub segment: u16,
    pub base_addr: u64,
    pub flags: u8,
    pub device_id: u16,
    pub iommu_info: u16,
    pub iommu_feature: u32,
    pub device_entries: Vec<IvhdDeviceEntry>,
    pub max_addr_bits: u8,
}

impl AmdIommuUnit {
    pub(super) fn covers_devid(&self, devid: u16) -> bool {
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

// ---------------------------------------------------------------------------
// IVMD range descriptor
// ---------------------------------------------------------------------------

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
    pub(super) fn from_ivmd(ivmd: IvmdInfo) -> Option<Self> {
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
        let read = (ivmd.flags & IVMD_FLAG_IR) != 0;
        let write = (ivmd.flags & IVMD_FLAG_IW) != 0;
        let unity_map = (ivmd.flags & IVMD_FLAG_UNITY_MAP) != 0;

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

    pub(super) fn applies_to_devid(&self, devid: u16) -> bool {
        devid >= self.devid_start && devid <= self.devid_end
    }
}

// ---------------------------------------------------------------------------
// Driver struct
// ---------------------------------------------------------------------------

pub struct AmdIommuDriver {
    pub(super) units: Vec<AmdIommuUnit>,
    pub(super) ivmd_ranges: Vec<AmdIvmdRange>,
    pub(super) cmd_states: Vec<Option<PoisonLock<AmdCommandState>>>,
    pub(super) event_logs: Vec<Option<AmdEventLog>>,
    pub(super) device_tables: HashMap<u16, AmdDeviceTable>,
    pub(super) domains: PoisonLock<HashMap<u16, AmdDomainInfo>>,
    pub(super) device_domains: PoisonLock<HashMap<DeviceId, u16>>,
    pub(super) next_domain_id: AtomicU64,
    pub(super) page_table_pool: Arc<PageTablePool>,
    pub(super) command_queue: Option<CommandQueue>,
    pub(super) iova_allocator: IovaAllocatorFast,
    pub(super) enabled: AtomicBool,
    pub(super) security_notifier: spin::Once<Arc<dyn SecurityNotifier>>,
    pub(super) max_addr_bits: u8,
}

#[derive(Clone)]
pub(super) struct AmdDomainInfo {
    pub(super) domain: Arc<DomainState>,
}

// ---------------------------------------------------------------------------
// Core driver methods
// ---------------------------------------------------------------------------

impl AmdIommuDriver {
    pub(crate) fn new(
        units: Vec<AmdIommuUnit>,
        ivmd_ranges: Vec<AmdIvmdRange>,
        cmd_states: Vec<Option<PoisonLock<AmdCommandState>>>,
        event_logs: Vec<Option<AmdEventLog>>,
        device_tables: HashMap<u16, AmdDeviceTable>,
    ) -> Self {
        let page_table_pool = PageTablePool::new(crate::mm::numa::num_nodes().max(1), 32);
        let max_addr_bits = units
            .iter()
            .map(|u| u.max_addr_bits)
            .min()
            .unwrap_or(AMD_DEFAULT_MAX_ADDR_BITS)
            .min(57)
            .max(12);
        let iova_bits = max_addr_bits.min(48).max(12);
        let iova_base: u64 = PAGE_SIZE_4K as u64;
        let iova_limit = 1u64 << iova_bits;
        let iova_size = iova_limit.saturating_sub(iova_base);
        let iova_allocator = IovaAllocatorFast::new(iova_base, iova_size);
        let alloc_base = iova_allocator.base();
        let alloc_end = alloc_base.saturating_add(iova_allocator.size());

        // Reserve IVMD unity-mapped ranges
        for range in &ivmd_ranges {
            if !range.unity_map || range.exclusion {
                continue;
            }

            let start = align_down(range.range_start, PAGE_SIZE_4K);
            let end = align_up(range.range_end, PAGE_SIZE_4K);
            if end <= start {
                continue;
            }

            let clamped_start = start.max(alloc_base);
            let clamped_end = end.min(alloc_end);
            if clamped_end <= clamped_start {
                continue;
            }

            let reserve_size = clamped_end - clamped_start;
            match iova_allocator.reserve(clamped_start, reserve_size) {
                Ok(()) | Err(IommuError::AlreadyMapped) => {}
                Err(IommuError::InvalidAddress) => {
                    log::warn!(
                        "AMD-Vi IVMD reservation outside IOVA window: range={:#x}-{:#x}",
                        clamped_start,
                        clamped_end
                    );
                }
                Err(err) => {
                    log::warn!("AMD-Vi IVMD IOVA reservation failed: {:?}", err);
                }
            }
        }
        let mut domain_map = HashMap::new();
        let default_domain = DomainState::new(
            0,
            None,
            false,
            false,
            max_addr_bits,
            IommuDomainType::Translated,
            page_table_pool.clone(),
            PteFormat::Amd,
        );
        let default_domain = Arc::new(default_domain);
        domain_map.insert(
            0,
            AmdDomainInfo {
                domain: default_domain,
            },
        );

        Self {
            units,
            ivmd_ranges,
            cmd_states,
            event_logs,
            device_tables,
            domains: PoisonLock::new(domain_map),
            device_domains: PoisonLock::new(HashMap::new()),
            next_domain_id: AtomicU64::new(1),
            page_table_pool,
            command_queue: Some(CommandQueue::new_with_numa(None)),
            iova_allocator,
            enabled: AtomicBool::new(false),
            security_notifier: spin::Once::new(),
            max_addr_bits,
        }
    }

    pub(crate) fn register_driver(
        units: Vec<AmdIommuUnit>,
        ivmd_ranges: Vec<AmdIvmdRange>,
        cmd_states: Vec<Option<PoisonLock<AmdCommandState>>>,
        event_logs: Vec<Option<AmdEventLog>>,
        device_tables: HashMap<u16, AmdDeviceTable>,
    ) -> Result<(), IommuError> {
        if get_iommu_driver().is_some() {
            return Err(IommuError::AlreadyInitialized);
        }
        let driver = AmdIommuDriver::new(
            units,
            ivmd_ranges,
            cmd_states,
            event_logs,
            device_tables,
        );
        driver.populate_default_entries()?;
        init_driver(Arc::new(IommuBackend::Amd(driver)));
        Ok(())
    }

    pub fn set_security_notifier(&self, notifier: Arc<dyn SecurityNotifier>) -> bool {
        let mut set = false;
        self.security_notifier.call_once(|| {
            set = true;
            notifier
        });

        if set {
            if let Some(notifier) = self.security_notifier.get() {
                match self.domains.lock() {
                    Ok(domains) => {
                        for info in domains.values() {
                            let _ = info.domain.set_security_notifier(Arc::clone(notifier));
                        }
                    }
                    Err(_) => {
                        log::error!(
                            "[IOMMU][AMD-Vi] Domains map poisoned while propagating security notifier"
                        );
                    }
                }
            }
        }

        set
    }

    pub(super) fn notify_security(&self, event: SecurityEvent) {
        if let Some(notifier) = self.security_notifier.get() {
            notifier.notify(event);
        }
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

// ---------------------------------------------------------------------------
// Lifecycle (enable / disable / interrupt mapping)
// ---------------------------------------------------------------------------

impl AmdIommuDriver {
    pub(crate) fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    pub(crate) fn enable(&self) -> Result<(), IommuError> {
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
            if self
                .event_logs
                .get(idx)
                .and_then(|log| log.as_ref())
                .is_some()
            {
                if let Err(err) = self.program_event_log_interrupt(unit) {
                    log::warn!(
                        "AMD-Vi event log interrupt init failed for unit @ {:#x}: {:?}",
                        unit.base_addr,
                        err
                    );
                    control &= !CONTROL_EVT_INT_EN;
                } else {
                    control |= CONTROL_EVT_INT_EN;
                }
                control |= CONTROL_EVT_LOG_EN;
            } else {
                control &= !CONTROL_EVT_LOG_EN;
                control &= !CONTROL_EVT_INT_EN;
            }
            mmio_write_u64(mmio_base + MMIO_CONTROL_OFFSET as usize, control);
        }
        self.enabled.store(true, Ordering::Release);
        Ok(())
    }

    pub(crate) fn disable(&self) -> Result<(), IommuError> {
        for unit in &self.units {
            let mmio_base = phys_to_virt_usize(unit.base_addr);
            let mut control = mmio_read_u64(mmio_base + MMIO_CONTROL_OFFSET as usize);
            control &=
                !(CONTROL_IOMMU_EN | CONTROL_CMDBUF_EN | CONTROL_EVT_LOG_EN | CONTROL_EVT_INT_EN);
            mmio_write_u64(mmio_base + MMIO_CONTROL_OFFSET as usize, control);
        }
        self.enabled.store(false, Ordering::Release);
        Ok(())
    }

    pub(crate) fn map_interrupt(
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

    pub(crate) fn get_remap_msi_message(&self, _handle: u16) -> (u64, u32) {
        (0, 0)
    }
}

// ---------------------------------------------------------------------------
// IommuHardwareContext trait impl
// ---------------------------------------------------------------------------

impl super::interface::IommuHardwareContext for AmdIommuDriver {
    fn allocate_iova_aligned(&self, size: u64, alignment: u64) -> Result<u64, IommuError> {
        if alignment <= PAGE_SIZE_4K as u64 {
            return self
                .iova_allocator
                .allocate_contiguous(size, PAGE_SIZE_4K as u64)
                .ok_or(IommuError::OutOfIova);
        }

        let align = if alignment >= 1024 * 1024 * 1024 {
            1024 * 1024 * 1024
        } else if alignment >= 2 * 1024 * 1024 {
            2 * 1024 * 1024
        } else {
            PAGE_SIZE_4K as u64
        };

        self.iova_allocator
            .allocate_contiguous(size, align)
            .ok_or(IommuError::OutOfIova)
    }

    fn allocate_iova_masked(
        &self,
        size: u64,
        _alignment: u64,
        mask: u64,
    ) -> Result<u64, IommuError> {
        self.iova_allocator
            .allocate_with_limit(size, crate::io::iommu::IovaGranularity::Page4K, mask)
            .ok_or(IommuError::OutOfIova)
    }

    fn free_iova(&self, iova: u64, size: u64) -> Result<(), IommuError> {
        self.iova_allocator.free(iova, size)
    }
}
