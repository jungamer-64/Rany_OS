// ============================================================================
// kernel/src/io/iommu/vendors/amd/mod.rs
// ============================================================================

//! AMD-Vi backend driver.

pub mod cmd;
pub mod driver;
pub mod tables;

pub(super) mod device_table;
pub(super) mod dma;
pub(super) mod domain;
pub(super) mod event_log;
pub(super) mod fault;
pub(super) mod init;
pub(super) mod invalidation;
pub(super) mod irt;
pub(super) mod registers;

#[cfg(test)]
mod tests;

// Re-exports for external callers (driver.rs, backend.rs, etc.)
#[cfg(all(test, feature = "qemu-test-export"))]
pub(crate) use self::domain::map_ivmd_ranges;
pub(crate) use self::fault::{fault_handler_task, poll_firmware_event_logs};
pub(crate) use self::init::command_queue_worker;
pub use self::init::init_iommu_from_ivrs;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::io::iommu::common::dma::iova_allocator::IovaAllocator;
use crate::io::iommu::runtime::command::queue::CommandQueue;
use crate::io::iommu::runtime::security::{SecurityEvent, SecurityNotifier};
use crate::mm::types::PAGE_SIZE_4K;
use crate::sync::PoisonLock;
use acpi_driver::ivrs::{IvhdDeviceEntry, IvmdInfo};
use hashbrown::HashMap;

use crate::io::iommu::common::dma::page_table_pool::PageTablePool;
use crate::io::iommu::common::domain::IommuDomain as DomainState;
use crate::io::iommu::runtime::backend::IommuBackend;
use crate::io::iommu::runtime::registry::{get_iommu_driver, init_driver};
use crate::io::iommu::types::{DeviceId, IommuDomainType, IommuError, PteFormat};

use self::device_table::AmdDeviceTable;
use self::domain::AmdDeviceBinding;
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

#[derive(Clone)]
pub struct AmdIommuUnit {
    pub segment: u16,
    pub base_addr: u64,
    registers: Arc<registers::AmdRegisters>,
    pub(super) pci: Arc<pci_driver::resource::FunctionResources>,
    pub flags: u8,
    pub device_id: u16,
    pub iommu_info: u16,
    pub iommu_feature: u32,
    pub device_entries: Vec<IvhdDeviceEntry>,
    pub max_addr_bits: u8,
}

impl core::fmt::Debug for AmdIommuUnit {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AmdIommuUnit")
            .field("segment", &self.segment)
            .field("base_addr", &self.base_addr)
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
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

#[derive(Debug)]
pub struct AmdIommuDriver {
    pub(super) units: Vec<AmdIommuUnit>,
    pub(super) ivmd_ranges: Vec<AmdIvmdRange>,
    pub(super) cmd_states: Vec<PoisonLock<AmdCommandState>>,
    pub(super) event_logs: Vec<Option<AmdEventLog>>,
    pub(super) device_tables: HashMap<u16, AmdDeviceTable>,
    pub(super) domains: PoisonLock<HashMap<u16, AmdDomainInfo>>,
    device_bindings: PoisonLock<HashMap<DeviceId, AmdDeviceBinding>>,
    requester_aliases: HashMap<DeviceId, DeviceId>,
    pub(super) next_domain_id: AtomicU64,
    pub(super) page_table_pool: Arc<PageTablePool>,
    pub command_queue: Option<CommandQueue>,
    pub(super) iova_allocator: Arc<IovaAllocator>,
    pub(super) enabled: AtomicBool,
    pub(super) security_notifier: crate::sync::InitOnce<Arc<dyn SecurityNotifier>>,
    pub(super) max_addr_bits: u8,
    interrupt_mode: irt::InterruptMode,
}

#[derive(Clone, Debug)]
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
        cmd_states: Vec<PoisonLock<AmdCommandState>>,
        event_logs: Vec<Option<AmdEventLog>>,
        device_tables: HashMap<u16, AmdDeviceTable>,
    ) -> Result<Self, IommuError> {
        let requester_aliases = domain::requester_aliases(&units)?;
        let page_table_pool = PageTablePool::new(crate::mm::numa::topology::num_nodes().max(1), 32);
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
        let iova_allocator = Arc::new(
            IovaAllocator::new(iova_base, iova_size)
                .expect("AMD controller cannot operate without its IOVA pool"),
        );
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
            4,
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

        let x2apic = crate::drivers::apic::local_apic()
            .is_ok_and(|apic| apic.mode() == crate::drivers::apic::ApicMode::X2Apic);
        let interrupt_mode = if x2apic
            && units
                .iter()
                .all(|unit| unit.registers.extended_features() & EFR_XT_SUP != 0)
        {
            irt::InterruptMode::X2Apic
        } else {
            irt::InterruptMode::Basic
        };

        Ok(Self {
            units,
            ivmd_ranges,
            cmd_states,
            event_logs,
            device_tables,
            domains: PoisonLock::new(domain_map),
            device_bindings: PoisonLock::new(HashMap::new()),
            requester_aliases,
            next_domain_id: AtomicU64::new(1),
            page_table_pool,
            command_queue: Some(CommandQueue::new(None)?),
            iova_allocator,
            enabled: AtomicBool::new(false),
            security_notifier: crate::sync::InitOnce::new(),
            max_addr_bits,
            interrupt_mode,
        })
    }

    pub(crate) fn register_driver(
        units: Vec<AmdIommuUnit>,
        ivmd_ranges: Vec<AmdIvmdRange>,
        cmd_states: Vec<PoisonLock<AmdCommandState>>,
        event_logs: Vec<Option<AmdEventLog>>,
        device_tables: HashMap<u16, AmdDeviceTable>,
    ) -> Result<(), IommuError> {
        if get_iommu_driver().is_some() {
            return Err(IommuError::AlreadyInitialized);
        }
        #[cfg(not(test))]
        if crate::task::scheduler_snapshot().is_none() {
            return Err(IommuError::RuntimeUnavailable);
        }
        let driver =
            AmdIommuDriver::new(units, ivmd_ranges, cmd_states, event_logs, device_tables)?;
        driver.populate_default_entries()?;
        init_driver(Arc::new(IommuBackend::Amd(Arc::new(driver))));
        #[cfg(not(test))]
        crate::services::start_amd_services()?;
        Ok(())
    }

    pub fn set_security_notifier(&self, notifier: Arc<dyn SecurityNotifier>) -> bool {
        let mut set = false;
        self.security_notifier.call_once(|| {
            set = true;
            notifier
        });

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

    /// Program only a stopped unit. Boot retains the registered driver and
    /// its backing through command completion and any startup failure.
    pub(crate) fn enable(&self) -> Result<(), IommuError> {
        if self.is_enabled() {
            return Ok(());
        }
        for unit in &self.units {
            if unit.registers.control()
                & (CONTROL_IOMMU_EN | CONTROL_CMDBUF_EN | CONTROL_EVT_LOG_EN)
                != 0
            {
                return Err(IommuError::InUse);
            }
        }
        for (idx, unit) in self.units.iter().enumerate() {
            let table = self.device_table_for_segment(unit.segment)?;
            table.program(unit)?;
            const MANAGED: u64 = CONTROL_IOMMU_EN
                | CONTROL_CMDBUF_EN
                | CONTROL_EVT_LOG_EN
                | CONTROL_EVT_INT_EN
                | CONTROL_COM_WAIT_INT_EN
                | CONTROL_GUEST_APIC_EN
                | CONTROL_GUEST_APIC_MODE_MASK
                | CONTROL_XT_EN
                | CONTROL_XT_INTERRUPT_EN;
            self.with_cmd_state(idx, |state| {
                // SAFETY: the unit is stopped, and the registered driver owns
                // the command buffer and completion page through shutdown.
                unsafe { state.buffer.program()? };
                let mut control = CONTROL_IOMMU_EN | CONTROL_CMDBUF_EN;
                if matches!(self.interrupt_mode, irt::InterruptMode::X2Apic) {
                    control |= CONTROL_XT_EN | CONTROL_GUEST_APIC_EN;
                }
                if let Some(log) = &self.event_logs[idx] {
                    log.program(unit)?;
                    control |= CONTROL_EVT_LOG_EN;
                    if self.program_event_log_interrupt(unit).is_ok() {
                        control |= CONTROL_EVT_INT_EN | CONTROL_COM_WAIT_INT_EN;
                    }
                }
                unit.registers
                    .update_control(|previous| (previous & !MANAGED) | control);
                // COMPLETION_WAIT is valid independently of IASup. A cold
                // unit has no previous translation cache to invalidate.
                state.completion(false)?.wait_blocking()
            })?;
        }
        self.enabled.store(true, Ordering::Release);
        Ok(())
    }

    pub(crate) fn disable(&self) -> Result<(), IommuError> {
        for unit in &self.units {
            unit.registers.update_control(|control| {
                control
                    & !(CONTROL_IOMMU_EN
                        | CONTROL_CMDBUF_EN
                        | CONTROL_EVT_LOG_EN
                        | CONTROL_EVT_INT_EN
                        | CONTROL_COM_WAIT_INT_EN)
            });
        }
        self.enabled.store(false, Ordering::Release);
        Ok(())
    }
}
