pub fn apic_id_for_cpu(cpu_id: usize) -> Option<u32> {
    crate::smp::topology::apic_id_for_cpu(cpu_id)
}

pub fn cpu_for_apic_id(apic_id: u32) -> Option<usize> {
    crate::smp::topology::cpu_for_apic_id(apic_id)
}

pub(crate) fn register_cpu_apic_mapping(_cpu_id: usize, _apic_id: u32) {}

pub(crate) fn install_topology_routes(_topology: &crate::smp::topology::CpuTopology) {}

pub(crate) fn reset_cpu_routing() {}

#[cfg(test)]
pub(crate) fn reset_cpu_routing_for_tests() {
    reset_cpu_routing();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn install_cpu_topology(apics: &[u8]) {
        let mut snapshot = boot_proto::AcpiBootSnapshot::default();
        snapshot.local_apic_count = apics.len() as u16;
        for (index, apic_id) in apics.iter().copied().enumerate() {
            snapshot.local_apics[index].apic_id = apic_id;
            snapshot.local_apics[index].processor_id = apic_id;
            snapshot.local_apics[index].flags = boot_proto::acpi_local_apic_flags::ENABLED;
        }

        let mut ap_boot = boot_proto::ApBootInfo::default();
        let bootable_aps = apics.len().saturating_sub(1) as u16;
        ap_boot.ap_count = bootable_aps;
        ap_boot.stack_count = bootable_aps;

        crate::smp::topology::reset();
        let topology = crate::smp::topology::CpuTopology::from_sources(
            &snapshot,
            &boot_proto::NumaInfo::default(),
            &ap_boot,
            apics.first().copied().unwrap_or(0) as u32,
        );
        crate::smp::topology::install(topology);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn cpu_routing_tracks_bsp_and_ap_round_trip() {
        reset_cpu_routing();
        install_cpu_topology(&[3, 17]);

        assert_eq!(apic_id_for_cpu(0), Some(3));
        assert_eq!(apic_id_for_cpu(1), Some(17));
        assert_eq!(cpu_for_apic_id(3), Some(0));
        assert_eq!(cpu_for_apic_id(17), Some(1));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn cpu_routing_handles_sparse_apic_ids() {
        reset_cpu_routing();
        install_cpu_topology(&[2, 41, 199]);

        assert_eq!(apic_id_for_cpu(2), Some(199));
        assert_eq!(cpu_for_apic_id(41), Some(1));
        assert_eq!(cpu_for_apic_id(199), Some(2));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn cpu_routing_returns_none_for_unregistered_entries() {
        reset_cpu_routing();

        assert_eq!(apic_id_for_cpu(7), None);
        assert_eq!(cpu_for_apic_id(88), None);
    }
}
