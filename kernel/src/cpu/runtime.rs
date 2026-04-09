use alloc::vec::Vec;

pub type CpuBootReport = crate::smp::SmpBootReport;
pub type CpuSnapshot = crate::smp::lifecycle::CpuLifecycleSnapshot;
pub type CpuStage = crate::smp::lifecycle::CpuLifecycleStage;

pub fn count() -> usize {
    crate::smp::lifecycle::online_cpu_count()
}

pub fn snapshot() -> CpuSnapshot {
    crate::smp::lifecycle::snapshot()
}

pub fn stage(cpu_id: usize) -> Option<CpuStage> {
    crate::smp::lifecycle::stage(cpu_id)
}

pub fn stage_name(cpu_id: usize) -> Option<&'static str> {
    crate::smp::lifecycle::stage_name(cpu_id)
}

pub fn workers_released() -> bool {
    crate::smp::lifecycle::runtime_workers_released()
}

pub fn active_ids() -> Vec<usize> {
    let snapshot = snapshot();
    let mut ids = Vec::new();
    for cpu_id in 0..crate::per_cpu::MAX_CPUS {
        if (snapshot.online_cpu_mask & (1u64 << cpu_id)) != 0 {
            ids.push(cpu_id);
        }
    }
    if ids.is_empty() {
        ids.push(0);
    }
    ids
}

pub(crate) fn set_stage(cpu_id: usize, stage: CpuStage) {
    crate::smp::lifecycle::set_cpu_stage(cpu_id, stage);
}

pub(crate) fn mark_boot_prepared(cpu_id: usize) {
    crate::smp::lifecycle::mark_boot_prepared(cpu_id);
}

pub(crate) fn reset() {
    crate::smp::lifecycle::reset_state();
}

pub(crate) fn initialize_from_topology(topology: &crate::cpu::directory::CpuTopology) {
    crate::smp::lifecycle::initialize_from_topology(topology);
}

pub(crate) fn mark_workers_released() {
    crate::smp::lifecycle::mark_runtime_workers_released();
}

pub(crate) fn log_online_summary(context: &str) {
    let snapshot = snapshot();
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
