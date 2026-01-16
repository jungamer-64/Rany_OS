//! SMP Module
//!
//! Symmetric Multi-Processing support including:
//! - AP bootstrap (INIT-SIPI-SIPI)
//! - Per-CPU data structures
//! - Inter-processor interrupts

#![allow(dead_code)]

pub mod bootstrap;
pub use bootstrap::{init, online_aps, start_aps};

/// Get total CPU count (BSP + APs)
pub fn cpu_count() -> u32 {
    1 + online_aps()
}

/// Get current CPU ID
pub fn current_cpu() -> u32 {
    if let Some(cpu_id) = crate::mm::try_current_cpu_id() {
        return cpu_id as u32;
    }
    // Fallback to LAPIC ID when per-CPU data isn't ready yet
    crate::io::apic::local_apic().id() as u32
}

/// Get current CPU index (0-based contiguous index for array access)
///
/// Unlike `current_cpu()` which may return APIC IDs (potentially non-contiguous),
/// this returns a safe 0-based index in range [0, cpu_count()).
/// Falls back to 0 if per-CPU data isn't initialized.
pub fn cpu_index() -> usize {
    if let Some(cpu_id) = crate::mm::try_current_cpu_id() {
        // Per-CPU data stores 0-based logical ID
        return cpu_id as usize;
    }
    // Early boot: assumed to be BSP (index 0)
    0
}

/// Initialize SMP for the system
pub fn init_smp() -> Result<(), &'static str> {
    // Get LAPIC address from ACPI
    let lapic_base = crate::io::acpi::local_apic_address().unwrap_or(0xFEE00000); // Default LAPIC address

    // Get list of APs from ACPI
    let local_apics = crate::io::acpi::local_apics();
    let bsp_apic_id = 0; // BSP is usually APIC ID 0

    // Filter out BSP, get only AP APIC IDs
    let ap_apic_ids: alloc::vec::Vec<u32> = local_apics
        .iter()
        .filter(|a| a.enabled && a.apic_id as u32 != bsp_apic_id)
        .map(|a| a.apic_id as u32)
        .collect();

    let num_aps = ap_apic_ids.len() as u32;

    if num_aps == 0 {
        log::info!("[SMP] No APs detected, running uniprocessor\n");
        return Ok(());
    }

    log::info!("[SMP] Detected {} AP(s), starting bootstrap\n", num_aps);

    // Initialize bootstrap
    unsafe {
        init(lapic_base, num_aps)?;
    }

    // Start all APs
    let started = start_aps(&ap_apic_ids);

    log::info!("[SMP] Started {}/{} APs\n", started, num_aps);

    // Reconfigure PMM arenas for the CPUs that actually came online.
    unsafe {
        crate::mm::pmm_reconfigure_for_online_cpus();
    }

    Ok(())
}
