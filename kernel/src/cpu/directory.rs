use boot_proto::ExoBootInfo;

pub use crate::smp::topology::CpuRecord;
pub(crate) use crate::smp::topology::CpuTopology;

pub(crate) fn reset() {
    crate::smp::topology::reset();
}

pub(crate) fn install(topology: CpuTopology) {
    crate::smp::topology::install(topology);
}

pub(crate) fn from_boot_info(boot_info: &ExoBootInfo, bsp_apic_id: u32) -> CpuTopology {
    CpuTopology::from_boot_info(boot_info, bsp_apic_id)
}

pub fn detected_count() -> usize {
    crate::smp::topology::detected_cpu_count()
}

pub fn bootable_count() -> usize {
    crate::smp::topology::bootable_cpu_count()
}

pub fn apic_id(cpu_id: usize) -> Option<u32> {
    crate::smp::topology::apic_id_for_cpu(cpu_id)
}

pub fn cpu_for_apic(apic_id: u32) -> Option<usize> {
    crate::smp::topology::cpu_for_apic_id(apic_id)
}

pub fn numa_node(cpu_id: usize) -> Option<usize> {
    crate::smp::topology::numa_node_for_cpu(cpu_id)
}

pub(crate) fn bootable_apic_ids() -> alloc::vec::Vec<u32> {
    crate::smp::topology::bootable_apic_ids()
}

pub(crate) fn log_topology_summary(topology: &CpuTopology) {
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
