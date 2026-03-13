//! SMP Module
//!
//! Symmetric Multi-Processing support including:
//! - AP bootstrap (INIT-SIPI-SIPI)
//! - Per-CPU data structures
//! - Inter-processor interrupts

#![allow(dead_code)]

use boot_proto::ExoBootInfo;

pub mod bootstrap;
mod routing;
mod runtime;
pub use bootstrap::{init, online_aps, start_aps};
pub use routing::{apic_id_for_cpu, cpu_for_apic_id};
pub use runtime::{release_runtime_workers, runtime_worker_stage, runtime_workers_released, wait_for_runtime_workers};
pub(crate) use routing::{register_cpu_apic_mapping, reset_cpu_routing};
pub(crate) use runtime::{RuntimeWorkerStage, reset_runtime_state, set_runtime_worker_stage};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SmpBootReport {
    pub detected: u32,
    pub started: u32,
}

/// Get total CPU count (BSP + APs)
pub fn cpu_count() -> u32 {
    1 + online_aps()
}

/// Get current logical CPU ID.
pub fn current_cpu() -> u32 {
    if let Some(cpu_id) = crate::per_cpu::try_current_cpu_id() {
        return cpu_id as u32;
    }

    #[cfg(not(test))]
    {
        let apic_id = crate::io::apic::local_apic().id() as u32;
        if let Some(cpu_id) = cpu_for_apic_id(apic_id) {
            return cpu_id as u32;
        }
    }

    0
}

/// Get current CPU index (0-based contiguous index for array access)
///
/// This mirrors `current_cpu()`'s logical CPU numbering and remains safe for
/// array access in range [0, cpu_count()).
/// Falls back to 0 if per-CPU data isn't initialized.
pub fn cpu_index() -> usize {
    if let Some(cpu_id) = crate::per_cpu::try_current_cpu_id() {
        return cpu_id as usize;
    }
    cpu_for_apic_id(crate::io::apic::local_apic().id() as u32).unwrap_or(0)
}

#[cfg(test)]
pub(crate) fn reset_runtime_workers_for_tests() {
    reset_runtime_state();
}

#[cfg(test)]
pub(crate) fn reset_cpu_routing_for_tests() {
    reset_cpu_routing();
}

/// Initialize SMP for the system using bootloader-provided AP boot metadata.
pub fn init_smp(boot_info: &ExoBootInfo) -> Result<SmpBootReport, &'static str> {
    reset_cpu_routing();
    reset_runtime_state();

    // Get LAPIC address from ACPI
    let lapic_base = crate::platform::acpi::local_apic_address().unwrap_or(0xFEE00000); // Default LAPIC address

    // Get list of APs from ACPI
    let local_apics = crate::platform::acpi::local_apics();
    let bsp_apic_id = crate::io::apic::local_apic().id() as u32;
    register_cpu_apic_mapping(0, bsp_apic_id);

    // Filter out BSP, get only AP APIC IDs
    let ap_apic_ids: alloc::vec::Vec<u32> = local_apics
        .iter()
        .filter(|a| a.enabled && a.apic_id as u32 != bsp_apic_id)
        .map(|a| a.apic_id as u32)
        .collect();

    let detected = ap_apic_ids.len() as u32;
    let requested = core::cmp::min(
        detected,
        core::cmp::min(
            boot_info.ap_boot.ap_count as u32,
            boot_info.ap_boot.stack_count as u32,
        ),
    );

    if requested == 0 {
        log::info!("[SMP] No APs detected, running uniprocessor\n");
        apply_online_cpu_count(1);
        return Ok(SmpBootReport {
            detected,
            started: 0,
        });
    }

    log::info!(
        "[SMP] Detected {} AP(s), preparing bootstrap metadata\n",
        detected
    );
    crate::per_cpu::finalize_cpu_topology((requested + 1) as usize);

    if let Err(err) = unsafe { init(lapic_base, boot_info, requested) } {
        log::warn!(
            "[SMP] Shared trampoline handoff invalid, falling back to BSP only: {}",
            err
        );
        apply_online_cpu_count(1);
        return Ok(SmpBootReport {
            detected,
            started: 0,
        });
    }

    let started = start_aps(&ap_apic_ids[..requested as usize]);

    log::info!("[SMP] Started {}/{} APs\n", started, detected);
    apply_online_cpu_count((started + 1) as usize);

    unsafe {
        crate::mm::phys::frame_allocator::pmm_reconfigure_for_online_cpus();
    }

    Ok(SmpBootReport { detected, started })
}

fn apply_online_cpu_count(count: usize) {
    let count = count.max(1);
    crate::mm::cache::slab_cache::init_per_core_caches(count);
    crate::mm::sync::page_table_cache::set_active_cpu_count(count);
    crate::loader::live_update::set_active_cores(count as u64);
    crate::task::init_executors(count);
}
