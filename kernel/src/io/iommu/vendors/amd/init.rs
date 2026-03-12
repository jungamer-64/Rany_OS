// ============================================================================
// kernel/src/io/iommu/vendors/amd/init.rs
// ============================================================================

//! AMD-Vi hardware initialization and IVRS table parsing.

use alloc::vec::Vec;
use core::ptr::NonNull;
use core::sync::atomic::AtomicU64;

use x86_64::PhysAddr;

use hashbrown::HashMap;

use crate::io::acpi::ivrs::IvhdDeviceEntry;
use crate::io::iommu::common::tables::phys_to_virt_usize;
use crate::io::iommu::runtime::backend::IommuBackend;
use crate::io::iommu::runtime::config::IommuConfig;
use crate::io::iommu::runtime::registry::get_iommu_driver;
use crate::io::iommu::types::IommuError;
use crate::mm::phys::frame_allocator::alloc_contiguous_frames;
use crate::mm::types::PAGE_SIZE_4K;
use crate::mm::virt::mapping::phys_to_virt;
use crate::sync::PoisonLock;

use super::cmd;
use super::device_table::AmdDeviceTable;
use super::event_log::AmdEventLog;
use super::invalidation::AmdCommandState;
use super::{AmdIommuDriver, AmdIommuUnit, AmdIvmdRange};

// ---------------------------------------------------------------------------
// Command queue worker
// ---------------------------------------------------------------------------

#[cfg(not(test))]
const AMD_COMMAND_QUEUE_BATCH: usize = 64;

#[cfg(not(test))]
async fn command_queue_worker() {
    // LOOP_PROOF: mode=event; reason=Worker exits if AMD backend or command queue disappears and otherwise waits after each finite batch.;
    loop {
        let driver = get_iommu_driver().and_then(|backend| match backend.as_ref() {
            IommuBackend::Amd(driver) => Some(driver),
            _ => None,
        });

        let Some(driver) = driver else {
            break;
        };

        let Some(cq) = driver.command_queue.as_ref() else {
            break;
        };

        let processed = cq.process_up_to(
            |kind| driver.handle_command_queue_entry(kind).map_err(|_| ()),
            AMD_COMMAND_QUEUE_BATCH,
        );

        if processed == 0 {
            cq.wait_for_work().await;
            if cq.is_poisoned() {
                break;
            }
        }
    }
}

#[cfg(not(test))]
pub(super) fn spawn_command_queue_worker() {
    let _ = crate::task::spawn_detached(command_queue_worker());
}

// ---------------------------------------------------------------------------
// Initialization helpers
// ---------------------------------------------------------------------------

pub(super) fn init_command_state(unit: &AmdIommuUnit) -> Result<AmdCommandState, IommuError> {
    let frame_count = cmd::CMD_BUFFER_BYTES / (PAGE_SIZE_4K as usize);
    let phys_base = alloc_contiguous_frames(frame_count).ok_or(IommuError::OutOfMemory)?;
    let virt_base = phys_to_virt(PhysAddr::new(phys_base.as_u64()));
    let buffer_ptr = NonNull::new(virt_base.as_u64() as *mut cmd::AmdCommand)
        .ok_or(IommuError::HardwareError)?;

    // Zero the command buffer to satisfy hardware expectations.
    unsafe {
        core::ptr::write_bytes(virt_base.as_u64() as *mut u8, 0, cmd::CMD_BUFFER_BYTES);
    }

    let sync_phys = alloc_contiguous_frames(1).ok_or(IommuError::OutOfMemory)?;
    let sync_virt = phys_to_virt(PhysAddr::new(sync_phys.as_u64()));
    let sync_ptr = NonNull::new(sync_virt.as_u64() as *mut u64).ok_or(IommuError::HardwareError)?;
    unsafe {
        sync_ptr.as_ptr().write_volatile(0);
    }

    let mmio_base = phys_to_virt_usize(unit.base_addr) as u64;
    let buffer = unsafe {
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

    // Security: Register command buffer and sync page as protected from DMA.
    // This prevents malicious devices from tampering with invalidation commands
    // or spoofing completion status.
    crate::io::iommu::runtime::security::register_protected_region(
        phys_base.as_u64(),
        (frame_count * PAGE_SIZE_4K as usize) as u64,
        "AMD-Vi Command Buffer",
    );
    crate::io::iommu::runtime::security::register_protected_region(
        sync_phys.as_u64(),
        PAGE_SIZE_4K as u64,
        "AMD-Vi Sync Page",
    );

    let mut state = AmdCommandState {
        buffer,
        sync_ptr,
        sync_phys: sync_phys.as_u64(),
        frame_count,
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

pub(super) fn init_command_states(
    units: &[AmdIommuUnit],
) -> Vec<Option<PoisonLock<AmdCommandState>>> {
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

pub(super) fn init_event_logs(units: &[AmdIommuUnit]) -> Vec<Option<AmdEventLog>> {
    let mut logs = Vec::with_capacity(units.len());
    for unit in units {
        match AmdEventLog::new() {
            Ok(log) => {
                if let Err(err) = log.program(unit) {
                    log::warn!(
                        "AMD-Vi event log program failed for unit @ {:#x}: {:?}",
                        unit.base_addr,
                        err
                    );
                    logs.push(None);
                } else {
                    logs.push(Some(log));
                }
            }
            Err(err) => {
                log::warn!(
                    "AMD-Vi event log alloc failed for unit @ {:#x}: {:?}",
                    unit.base_addr,
                    err
                );
                logs.push(None);
            }
        }
    }
    logs
}

pub(super) fn max_devid_for_entries(entries: &[IvhdDeviceEntry]) -> u16 {
    let mut max = 0;
    for entry in entries {
        let entry_max = match entry {
            IvhdDeviceEntry::All { .. } => return u16::MAX,
            IvhdDeviceEntry::Select { devid, .. } => *devid,
            IvhdDeviceEntry::Range { start, end, .. } => (*start).max(*end),
            IvhdDeviceEntry::Alias { devid, alias, .. } => (*devid).max(*alias),
            IvhdDeviceEntry::AliasRange {
                start, end, alias, ..
            } => (*start).max(*end).max(*alias),
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

pub(super) fn init_device_tables(
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

// ---------------------------------------------------------------------------
// Main initialization entry point
// ---------------------------------------------------------------------------

/// Initialize AMD-Vi using ACPI IVRS table at `ivrs_addr`.

/// Collect AmdIommuUnit entries from parsed IVRS IVHD structures.
fn collect_ivhd_units(ivrs_info: &crate::io::acpi::ivrs::IvrsInfo) -> Vec<AmdIommuUnit> {
    ivrs_info
        .ivhds
        .iter()
        .map(|ivhd| {
            let max_addr_bits = {
                let mmio_base = phys_to_virt_usize(ivhd.iommu_base);
                super::registers::read_max_addr_bits(mmio_base)
            };
            AmdIommuUnit {
                segment: ivhd.pci_segment,
                base_addr: ivhd.iommu_base,
                flags: ivhd.flags,
                device_id: ivhd.device_id,
                iommu_info: ivhd.iommu_info,
                iommu_feature: ivhd.iommu_feature,
                device_entries: ivhd.device_entries.clone(),
                max_addr_bits,
            }
        })
        .collect()
}

/// Collect IVMD ranges from parsed IVRS.
fn collect_ivmd_ranges(ivrs_info: &crate::io::acpi::ivrs::IvrsInfo) -> Vec<AmdIvmdRange> {
    ivrs_info
        .ivmds
        .iter()
        .filter_map(|ivmd| AmdIvmdRange::from_ivmd(ivmd.clone()))
        .collect()
}

pub unsafe fn init_iommu_from_ivrs(
    ivrs_addr: usize,
    config: IommuConfig,
) -> Result<(), IommuError> {
    if !config.enabled {
        log::error!("IOMMU disable request rejected: translated IOMMU protection is mandatory");
        return Err(IommuError::NotSupported);
    }

    // Initialize security subsystem (protected regions like APIC)
    crate::io::iommu::runtime::security::init();

    let ivrs_info = match unsafe { crate::io::acpi::ivrs::parse_ivrs(ivrs_addr) } {
        Ok(info) => info,
        Err(e) => {
            log::error!("Failed to parse IVRS: {}", e);
            return Err(IommuError::HardwareError);
        }
    };

    let units = collect_ivhd_units(&ivrs_info);
    if units.is_empty() {
        return Err(IommuError::NotPresent);
    }

    // Security: Register IOMMU register ranges as protected
    for unit in &units {
        crate::io::iommu::runtime::security::register_protected_region(
            unit.base_addr,
            0x10000, // AMD-Vi registers are 64KB
            "AMD-Vi IOMMU",
        );
    }

    let ivmd_ranges = collect_ivmd_ranges(&ivrs_info);

    let cmd_states = init_command_states(&units);
    let cmd_ready = cmd_states.iter().filter(|buf| buf.is_some()).count();
    let event_logs = init_event_logs(&units);
    let evt_ready = event_logs.iter().filter(|log| log.is_some()).count();

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
    AmdIommuDriver::register_driver(units, ivmd_ranges, cmd_states, event_logs, device_tables)?;
    #[cfg(not(test))]
    spawn_command_queue_worker();
    log::info!(
        "AMD-Vi IVRS parsed ({} unit(s), {} IVMD range(s), {} cmd buffer(s) ready, {} event log(s) ready, {} device table(s))",
        unit_count,
        ivmd_count,
        cmd_ready,
        evt_ready,
        table_count
    );

    Ok(())
}
