use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

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

pub fn apic_id_for_cpu(cpu_id: usize) -> Option<u32> {
    if let Some(apic_id) = crate::smp::topology::apic_id_for_cpu(cpu_id) {
        return Some(apic_id);
    }
    if cpu_id >= MAX_ROUTED_CPUS {
        return None;
    }

    let apic_id = CPU_TO_APIC_ID[cpu_id].load(Ordering::Acquire);
    (apic_id != INVALID_APIC_ID).then_some(apic_id)
}

pub fn cpu_for_apic_id(apic_id: u32) -> Option<usize> {
    if let Some(cpu_id) = crate::smp::topology::cpu_for_apic_id(apic_id) {
        return Some(cpu_id);
    }
    let apic_index = usize::try_from(apic_id).ok()?;
    if apic_index >= MAX_APIC_IDS {
        return None;
    }

    let cpu_id = APIC_ID_TO_CPU[apic_index].load(Ordering::Acquire);
    (cpu_id != INVALID_CPU_ID).then_some(cpu_id)
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
}

pub(crate) fn install_topology_routes(topology: &crate::smp::topology::CpuTopology) {
    reset_cpu_routing();
    for record in topology.records() {
        register_cpu_apic_mapping(record.logical_cpu_id, record.apic_id);
    }
}

pub(crate) fn reset_cpu_routing() {
    for entry in &CPU_TO_APIC_ID {
        entry.store(INVALID_APIC_ID, Ordering::Relaxed);
    }
    for entry in &APIC_ID_TO_CPU {
        entry.store(INVALID_CPU_ID, Ordering::Relaxed);
    }
}

#[cfg(test)]
pub(crate) fn reset_cpu_routing_for_tests() {
    reset_cpu_routing();
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
}
