use boot_proto::ExoBootInfo;

mod boot;
mod directory;
mod ipi;
mod runtime;

pub use directory::{CpuRecord, apic_id, bootable_count, cpu_for_apic, detected_count, numa_node};
pub use ipi::{IpiKind, broadcast_ipi, current_apic_id, send_eoi_current_cpu, send_ipi};
pub use runtime::{
    CpuBootReport, CpuSnapshot, CpuStage, active_ids, count, snapshot, stage, stage_name,
};

pub fn initialize(boot_info: &ExoBootInfo) -> Result<CpuBootReport, &'static str> {
    boot::initialize(boot_info)
}

pub fn current_id() -> usize {
    crate::per_cpu::current_cpu_id()
}

pub fn try_current_id() -> Option<usize> {
    crate::per_cpu::try_current_cpu_id()
}

pub fn workers_released() -> bool {
    runtime::workers_released()
}

pub fn release_workers() {
    boot::release_workers();
}

pub(crate) fn provision_runtime(count: usize) {
    boot::provision_runtime(count);
}

pub(crate) fn log_online_summary(context: &str) {
    runtime::log_online_summary(context);
}

pub(crate) fn set_stage(cpu_id: usize, stage: CpuStage) {
    runtime::set_stage(cpu_id, stage);
}

pub(crate) fn mark_runtime_worker_stage(cpu_id: usize, stage: CpuStage) {
    runtime::set_stage(cpu_id, stage);
}
