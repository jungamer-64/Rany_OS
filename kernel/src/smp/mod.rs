//! SMP Module
//!
//! Symmetric Multi-Processing support including:
//! - AP bootstrap (INIT-SIPI-SIPI)
//! - Per-CPU data structures
//! - Inter-processor interrupts

#![allow(dead_code)]

use boot_proto::ExoBootInfo;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicUsize, Ordering};

pub mod bootstrap;
pub use bootstrap::{init, online_aps, start_aps};

const MAX_ROUTED_CPUS: usize = crate::per_cpu::MAX_CPUS;
const MAX_APIC_IDS: usize = 256;
const INVALID_APIC_ID: u32 = u32::MAX;
const INVALID_CPU_ID: usize = usize::MAX;

static CPU_TO_APIC_ID: [AtomicU32; MAX_ROUTED_CPUS] = {
    const INIT: AtomicU32 = AtomicU32::new(INVALID_APIC_ID);
    [INIT; MAX_ROUTED_CPUS]
};
static APIC_ID_TO_CPU: [AtomicUsize; MAX_APIC_IDS] = {
    const INIT: AtomicUsize = AtomicUsize::new(INVALID_CPU_ID);
    [INIT; MAX_APIC_IDS]
};
static BSP_APIC_ID: AtomicU32 = AtomicU32::new(INVALID_APIC_ID);
static RUNTIME_WORKERS_RELEASED: AtomicBool = AtomicBool::new(false);
static RUNTIME_WORKER_STAGE: [AtomicU8; MAX_ROUTED_CPUS] = {
    const INIT: AtomicU8 = AtomicU8::new(RuntimeWorkerStage::Unknown as u8);
    [INIT; MAX_ROUTED_CPUS]
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum RuntimeWorkerStage {
    Unknown = 0,
    BootstrapReady = 1,
    Parked = 2,
    ReleaseObserved = 3,
    HandoffIrqsMasked = 4,
    Registered = 5,
    LazyTlbExited = 6,
    ColdStartHelper = 7,
    ExecutorConstructed = 8,
    ExecutorRun = 9,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SmpBootReport {
    pub detected: u32,
    pub started: u32,
}

/// Get total CPU count (BSP + APs)
pub fn cpu_count() -> u32 {
    1 + online_aps()
}

/// Get current CPU ID
pub fn current_cpu() -> u32 {
    if let Some(cpu_id) = crate::per_cpu::try_current_cpu_id() {
        return cpu_id as u32;
    }
    let apic_id = crate::io::apic::local_apic().id() as u32;
    cpu_for_apic_id(apic_id)
        .map(|cpu_id| cpu_id as u32)
        .unwrap_or(apic_id)
}

/// Get current CPU index (0-based contiguous index for array access)
///
/// Unlike `current_cpu()` which may return APIC IDs (potentially non-contiguous),
/// this returns a safe 0-based index in range [0, cpu_count()).
/// Falls back to 0 if per-CPU data isn't initialized.
pub fn cpu_index() -> usize {
    if let Some(cpu_id) = crate::per_cpu::try_current_cpu_id() {
        return cpu_id as usize;
    }
    cpu_for_apic_id(crate::io::apic::local_apic().id() as u32).unwrap_or(0)
}

pub fn apic_id_for_cpu(cpu_id: usize) -> Option<u32> {
    if cpu_id >= MAX_ROUTED_CPUS {
        return None;
    }

    let apic_id = CPU_TO_APIC_ID[cpu_id].load(Ordering::Acquire);
    (apic_id != INVALID_APIC_ID).then_some(apic_id)
}

pub fn cpu_for_apic_id(apic_id: u32) -> Option<usize> {
    let apic_index = usize::try_from(apic_id).ok()?;
    if apic_index >= MAX_APIC_IDS {
        return None;
    }

    let cpu_id = APIC_ID_TO_CPU[apic_index].load(Ordering::Acquire);
    (cpu_id != INVALID_CPU_ID).then_some(cpu_id)
}

pub fn runtime_workers_released() -> bool {
    RUNTIME_WORKERS_RELEASED.load(Ordering::Acquire)
}

pub(crate) fn set_runtime_worker_stage(cpu_id: usize, stage: RuntimeWorkerStage) {
    if cpu_id < MAX_ROUTED_CPUS {
        RUNTIME_WORKER_STAGE[cpu_id].store(stage as u8, Ordering::Release);
    }
}

pub fn runtime_worker_stage(cpu_id: usize) -> Option<&'static str> {
    if cpu_id >= MAX_ROUTED_CPUS {
        return None;
    }

    match RUNTIME_WORKER_STAGE[cpu_id].load(Ordering::Acquire) {
        x if x == RuntimeWorkerStage::Unknown as u8 => Some("unknown"),
        x if x == RuntimeWorkerStage::BootstrapReady as u8 => Some("bootstrap_ready"),
        x if x == RuntimeWorkerStage::Parked as u8 => Some("parked"),
        x if x == RuntimeWorkerStage::ReleaseObserved as u8 => Some("release_observed"),
        x if x == RuntimeWorkerStage::HandoffIrqsMasked as u8 => Some("handoff_irqs_masked"),
        x if x == RuntimeWorkerStage::Registered as u8 => Some("registered"),
        x if x == RuntimeWorkerStage::LazyTlbExited as u8 => Some("lazy_tlb_exited"),
        x if x == RuntimeWorkerStage::ColdStartHelper as u8 => Some("cold_start_helper"),
        x if x == RuntimeWorkerStage::ExecutorConstructed as u8 => Some("executor_constructed"),
        x if x == RuntimeWorkerStage::ExecutorRun as u8 => Some("executor_run"),
        _ => None,
    }
}

pub fn release_runtime_workers() {
    RUNTIME_WORKERS_RELEASED.store(true, Ordering::Release);
}

pub fn wait_for_runtime_workers() {
    loop {
        if runtime_workers_released() {
            #[cfg(not(test))]
            x86_64::instructions::interrupts::disable();
            return;
        }

        #[cfg(test)]
        core::hint::spin_loop();

        #[cfg(not(test))]
        {
            // Keep the wake-up path entirely within this function so the AP
            // does not return through the tiny `sti; hlt; ret` helper while a
            // wake IPI is unwinding. Returning to the next inlined instruction
            // (`cli`) avoids consuming a stack return slot on the parked AP.
            unsafe {
                core::arch::asm!("sti", "hlt", "cli", options(nomem, nostack));
            }
        }
    }
}

pub(crate) fn register_cpu_apic_mapping(cpu_id: usize, apic_id: u32) {
    if cpu_id >= MAX_ROUTED_CPUS {
        log::warn!(
            "[SMP] Ignoring logical CPU {} outside routing table (max {})",
            cpu_id,
            MAX_ROUTED_CPUS
        );
        return;
    }

    let apic_index = match usize::try_from(apic_id) {
        Ok(index) if index < MAX_APIC_IDS => index,
        _ => {
            log::warn!(
                "[SMP] Ignoring APIC ID {} outside routing table (max {})",
                apic_id,
                MAX_APIC_IDS
            );
            return;
        }
    };

    CPU_TO_APIC_ID[cpu_id].store(apic_id, Ordering::Release);
    APIC_ID_TO_CPU[apic_index].store(cpu_id, Ordering::Release);

    if cpu_id == 0 {
        BSP_APIC_ID.store(apic_id, Ordering::Release);
    }
}

fn reset_cpu_routing() {
    for entry in &CPU_TO_APIC_ID {
        entry.store(INVALID_APIC_ID, Ordering::Relaxed);
    }
    for entry in &APIC_ID_TO_CPU {
        entry.store(INVALID_CPU_ID, Ordering::Relaxed);
    }

    BSP_APIC_ID.store(INVALID_APIC_ID, Ordering::Relaxed);
    RUNTIME_WORKERS_RELEASED.store(false, Ordering::Relaxed);
    for entry in &RUNTIME_WORKER_STAGE {
        entry.store(RuntimeWorkerStage::Unknown as u8, Ordering::Relaxed);
    }
}

#[cfg(test)]
pub(crate) fn reset_runtime_workers_for_tests() {
    RUNTIME_WORKERS_RELEASED.store(false, Ordering::Relaxed);
}

#[cfg(test)]
pub(crate) fn reset_cpu_routing_for_tests() {
    reset_cpu_routing();
}

/// Initialize SMP for the system using bootloader-provided AP boot metadata.
pub fn init_smp(boot_info: &ExoBootInfo) -> Result<SmpBootReport, &'static str> {
    reset_cpu_routing();

    // Get LAPIC address from ACPI
    let lapic_base = crate::io::acpi::local_apic_address().unwrap_or(0xFEE00000); // Default LAPIC address

    // Get list of APs from ACPI
    let local_apics = crate::io::acpi::local_apics();
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
    crate::task::set_executor_active_cpu_count(count);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn cpu_routing_tracks_bsp_and_ap_round_trip() {
        reset_cpu_routing();

        register_cpu_apic_mapping(0, 3);
        register_cpu_apic_mapping(1, 17);

        assert_eq!(apic_id_for_cpu(0), Some(3));
        assert_eq!(apic_id_for_cpu(1), Some(17));
        assert_eq!(cpu_for_apic_id(3), Some(0));
        assert_eq!(cpu_for_apic_id(17), Some(1));
    }

    #[test_case]
    fn cpu_routing_handles_sparse_apic_ids() {
        reset_cpu_routing();

        register_cpu_apic_mapping(0, 2);
        register_cpu_apic_mapping(1, 41);
        register_cpu_apic_mapping(2, 199);

        assert_eq!(apic_id_for_cpu(2), Some(199));
        assert_eq!(cpu_for_apic_id(41), Some(1));
        assert_eq!(cpu_for_apic_id(199), Some(2));
    }

    #[test_case]
    fn cpu_routing_returns_none_for_unregistered_entries() {
        reset_cpu_routing();

        assert_eq!(apic_id_for_cpu(7), None);
        assert_eq!(cpu_for_apic_id(88), None);
    }

    #[test_case]
    fn runtime_worker_release_flag_is_observable() {
        reset_cpu_routing();

        assert!(!runtime_workers_released());
        release_runtime_workers();
        assert!(runtime_workers_released());
    }
}
