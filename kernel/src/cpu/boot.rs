use boot_proto::ExoBootInfo;

use super::directory;
use super::runtime::{self, CpuBootReport, CpuStage};

pub fn initialize(boot_info: &ExoBootInfo) -> Result<CpuBootReport, &'static str> {
    directory::reset();
    runtime::reset();
    crate::smp::reset_runtime_state();

    let lapic_base = crate::platform::acpi::local_apic_address().unwrap_or(0xFEE00000);
    let bsp_apic_id = crate::drivers::apic::local_apic().id() as u32;
    let topology = directory::from_boot_info(boot_info, bsp_apic_id);
    directory::install(topology.clone());
    runtime::initialize_from_topology(&topology);
    runtime::set_stage(0, CpuStage::PerCpuReady);
    directory::log_topology_summary(&topology);

    let detected = topology.detected_ap_count() as u32;
    let requested = topology.bootable_ap_count() as u32;

    if requested == 0 {
        log::info!("[SMP] No bootable APs detected, running uniprocessor");
        provision_runtime(1);
        runtime::log_online_summary("uniprocessor");
        return Ok(CpuBootReport {
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
        runtime::mark_boot_prepared(cpu_id);
    }

    if let Err(err) = unsafe { crate::smp::bootstrap::init(lapic_base, boot_info, requested) } {
        log::warn!(
            "[SMP] Shared trampoline handoff invalid, falling back to BSP only: {}",
            err
        );
        for cpu_id in 1..topology.bootable_cpu_count() {
            runtime::set_stage(cpu_id, CpuStage::Failed);
        }
        provision_runtime(1);
        runtime::log_online_summary("handoff_fallback");
        return Ok(CpuBootReport {
            detected,
            started: 0,
        });
    }

    let ap_apic_ids = directory::bootable_apic_ids();
    let started = crate::smp::bootstrap::start_aps(&ap_apic_ids[..requested as usize]);

    log::info!("[SMP] Started {}/{} APs\n", started, detected);
    provision_runtime(runtime::count());
    runtime::log_online_summary("bootstrap_complete");

    unsafe {
        crate::mm::phys::frame_allocator::pmm_reconfigure_for_online_cpus();
    }

    Ok(CpuBootReport { detected, started })
}

pub fn release_workers() {
    runtime::mark_workers_released();
    runtime::set_stage(0, CpuStage::Released);
    let snapshot = runtime::snapshot();
    log::info!(
        "[SMP][HANDOFF] runtime_workers_released=1 detected={} bootable={} online={} mask={:#018x}",
        snapshot.detected_cpu_count,
        snapshot.bootable_cpu_count,
        snapshot.online_cpu_count,
        snapshot.online_cpu_mask
    );
    if snapshot.online_cpu_count > 1 {
        crate::cpu::broadcast_ipi(crate::cpu::IpiKind::ExecutorWake);
    }
}

pub(crate) fn provision_runtime(count: usize) {
    let count = count.max(1).min(crate::per_cpu::MAX_CPUS);
    crate::mm::cache::slab_cache::init_per_core_caches(count);
    crate::mm::sync::page_table_cache::set_active_cpu_count(count);
    crate::loader::live_update::set_active_cores(count as u64);
    crate::task::provision_executors(count);
}
