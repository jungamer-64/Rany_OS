//! SMP Module
//!
//! Symmetric Multi-Processing support including:
//! - AP bootstrap (INIT-SIPI-SIPI)
//! - Per-CPU data structures
//! - Inter-processor interrupts

#![allow(dead_code)]

use boot_proto::ExoBootInfo;

pub mod bootstrap;
mod lifecycle;
mod routing;
mod runtime;
pub mod runtime_handoff;
pub mod topology;
#[allow(unused_imports)]
pub use bootstrap::{init, online_aps, start_aps};
#[allow(unused_imports)]
pub use lifecycle::{CpuLifecycleSnapshot, CpuLifecycleStage};
pub(crate) use lifecycle::{
    mark_boot_prepared, mark_launching, set_cpu_stage as set_cpu_lifecycle_stage,
};
pub use routing::{apic_id_for_cpu, cpu_for_apic_id};
#[allow(unused_imports)]
pub(crate) use routing::{register_cpu_apic_mapping, reset_cpu_routing};
pub(crate) use runtime::{RuntimeWorkerStage, reset_runtime_state, set_runtime_worker_stage};
#[allow(unused_imports)]
pub use runtime::{
    release_runtime_workers, runtime_worker_stage, runtime_workers_released,
    wait_for_runtime_workers,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SmpBootReport {
    pub detected: u32,
    pub started: u32,
}

/// Get total CPU count (BSP + APs)
pub fn cpu_count() -> u32 {
    lifecycle::online_cpu_count() as u32
}

pub fn detected_cpu_count() -> usize {
    topology::detected_cpu_count()
}

pub fn bootable_cpu_count() -> usize {
    topology::bootable_cpu_count()
}

/// Get current logical CPU ID.
pub fn current_cpu() -> u32 {
    topology::resolve_current_cpu_id().unwrap_or(0) as u32
}

/// Get current CPU index (0-based contiguous index for array access)
///
/// This mirrors `current_cpu()`'s logical CPU numbering and remains safe for
/// array access in range [0, cpu_count()).
/// Falls back to 0 if per-CPU data isn't initialized.
pub fn cpu_index() -> usize {
    topology::resolve_current_cpu_id().unwrap_or(0)
}

#[cfg(test)]
pub(crate) fn reset_runtime_workers_for_tests() {
    reset_runtime_state();
}

#[cfg(test)]
pub(crate) fn reset_cpu_routing_for_tests() {
    topology::reset();
    reset_cpu_routing();
}

/// Initialize SMP for the system using bootloader-provided AP boot metadata.
pub fn init_smp(boot_info: &ExoBootInfo) -> Result<SmpBootReport, &'static str> {
    topology::reset();
    reset_cpu_routing();
    reset_runtime_state();

    // Get LAPIC address from ACPI
    let lapic_base = crate::platform::acpi::local_apic_address().unwrap_or(0xFEE00000); // Default LAPIC address

    let bsp_apic_id = crate::io::apic::local_apic().id() as u32;
    let topology = topology::CpuTopology::from_boot_info(boot_info, bsp_apic_id);
    self::topology::install(topology.clone());
    routing::install_topology_routes(&topology);
    lifecycle::initialize_from_topology(&topology);
    lifecycle::set_cpu_stage(0, lifecycle::CpuLifecycleStage::PerCpuReady);
    log_topology_summary(&topology);

    let detected = topology.detected_ap_count() as u32;
    let requested = topology.bootable_ap_count() as u32;

    if requested == 0 {
        log::info!("[SMP] No bootable APs detected, running uniprocessor");
        apply_online_cpu_count(1);
        log_online_summary("uniprocessor");
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
    for cpu_id in 1..topology.bootable_cpu_count() {
        mark_boot_prepared(cpu_id);
    }

    if let Err(err) = unsafe { init(lapic_base, boot_info, requested) } {
        log::warn!(
            "[SMP] Shared trampoline handoff invalid, falling back to BSP only: {}",
            err
        );
        for cpu_id in 1..topology.bootable_cpu_count() {
            lifecycle::set_cpu_stage(cpu_id, lifecycle::CpuLifecycleStage::Failed);
        }
        apply_online_cpu_count(1);
        log_online_summary("handoff_fallback");
        return Ok(SmpBootReport {
            detected,
            started: 0,
        });
    }

    let ap_apic_ids = topology.bootable_apic_ids();
    let started = start_aps(&ap_apic_ids[..requested as usize]);

    log::info!("[SMP] Started {}/{} APs\n", started, detected);
    apply_online_cpu_count(lifecycle::online_cpu_count());
    log_online_summary("bootstrap_complete");

    unsafe {
        crate::mm::phys::frame_allocator::pmm_reconfigure_for_online_cpus();
    }

    Ok(SmpBootReport { detected, started })
}

fn apply_online_cpu_count(count: usize) {
    runtime_handoff::runtime_handoff_coordinator().apply_online_cpu_count(count);
}

fn log_topology_summary(topology: &topology::CpuTopology) {
    let tracked = topology.records().len();
    let unbootable = topology
        .records()
        .iter()
        .filter(|record| !record.bootable)
        .count();
    let truncated = topology.detected_cpu_count().saturating_sub(tracked);

    log::info!(
        "[SMP][TOPOLOGY] detected_total={} tracked={} bootable={} unbootable={} max_cpus={} truncated={}",
        topology.detected_cpu_count(),
        tracked,
        topology.bootable_cpu_count(),
        unbootable,
        crate::per_cpu::MAX_CPUS,
        truncated
    );
}

fn log_online_summary(context: &str) {
    let snapshot = lifecycle::snapshot();
    log::info!(
        "[SMP][ONLINE] context={} detected={} bootable={} online={} released={} mask={:#018x}",
        context,
        snapshot.detected_cpu_count,
        snapshot.bootable_cpu_count,
        snapshot.online_cpu_count,
        snapshot.runtime_workers_released as u8,
        snapshot.online_cpu_mask
    );
}
