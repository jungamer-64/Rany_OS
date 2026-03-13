use crate::sync::PoisonLock;
use alloc::vec::Vec;
use boot_proto::{AcpiBootSnapshot, ApBootInfo, ExoBootInfo, NumaInfo};

const MAX_CPUS: usize = crate::per_cpu::MAX_CPUS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuRecord {
    pub logical_cpu_id: usize,
    pub apic_id: u32,
    pub is_bsp: bool,
    pub numa_node: Option<usize>,
    pub boot_slot: Option<usize>,
    pub bootable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuTopology {
    detected_total: usize,
    bootable_cpu_count: usize,
    records: Vec<CpuRecord>,
}

impl CpuTopology {
    pub fn from_boot_info(boot_info: &ExoBootInfo, bsp_apic_id: u32) -> Self {
        Self::from_sources(
            &boot_info.acpi_snapshot,
            &boot_info.numa_info,
            &boot_info.ap_boot,
            bsp_apic_id,
        )
    }

    pub fn from_sources(
        snapshot: &AcpiBootSnapshot,
        numa_info: &NumaInfo,
        ap_boot: &ApBootInfo,
        bsp_apic_id: u32,
    ) -> Self {
        let mut records = Vec::with_capacity(MAX_CPUS);
        let mut detected_total = 0usize;
        let mut seen_apics = Vec::new();

        push_record(
            &mut records,
            &mut seen_apics,
            &mut detected_total,
            numa_info,
            ap_boot,
            bsp_apic_id,
            true,
        );

        for local_apic in snapshot
            .local_apics()
            .iter()
            .filter(|entry| entry.enabled())
        {
            let apic_id = local_apic.apic_id as u32;
            if apic_id == bsp_apic_id {
                continue;
            }
            push_record(
                &mut records,
                &mut seen_apics,
                &mut detected_total,
                numa_info,
                ap_boot,
                apic_id,
                false,
            );
        }

        if records.is_empty() {
            push_record(
                &mut records,
                &mut seen_apics,
                &mut detected_total,
                numa_info,
                ap_boot,
                bsp_apic_id,
                true,
            );
        }

        let bootable_cpu_count = records
            .iter()
            .filter(|record| record.bootable)
            .count()
            .max(1);

        Self {
            detected_total: detected_total.max(1),
            bootable_cpu_count,
            records,
        }
    }

    pub fn detected_cpu_count(&self) -> usize {
        self.detected_total.max(1)
    }

    pub fn detected_ap_count(&self) -> usize {
        self.detected_cpu_count().saturating_sub(1)
    }

    pub fn bootable_cpu_count(&self) -> usize {
        self.bootable_cpu_count.max(1)
    }

    pub fn bootable_ap_count(&self) -> usize {
        self.bootable_cpu_count().saturating_sub(1)
    }

    pub fn records(&self) -> &[CpuRecord] {
        &self.records
    }

    pub fn cpu_record(&self, cpu_id: usize) -> Option<&CpuRecord> {
        self.records.get(cpu_id)
    }

    pub fn apic_id_for_cpu(&self, cpu_id: usize) -> Option<u32> {
        self.cpu_record(cpu_id).map(|record| record.apic_id)
    }

    pub fn cpu_for_apic_id(&self, apic_id: u32) -> Option<usize> {
        self.records
            .iter()
            .find(|record| record.apic_id == apic_id)
            .map(|record| record.logical_cpu_id)
    }

    pub fn bootable_apic_ids(&self) -> Vec<u32> {
        self.records
            .iter()
            .filter(|record| !record.is_bsp && record.bootable)
            .map(|record| record.apic_id)
            .collect()
    }
}

fn push_record(
    records: &mut Vec<CpuRecord>,
    seen_apics: &mut Vec<u32>,
    detected_total: &mut usize,
    numa_info: &NumaInfo,
    ap_boot: &ApBootInfo,
    apic_id: u32,
    is_bsp: bool,
) {
    if seen_apics.contains(&apic_id) {
        return;
    }
    seen_apics.push(apic_id);
    *detected_total += 1;

    if records.len() >= MAX_CPUS {
        return;
    }

    let logical_cpu_id = records.len();
    let boot_slot = (!is_bsp).then_some(logical_cpu_id.saturating_sub(1));
    let boot_capacity = usize::from(ap_boot.ap_count).min(usize::from(ap_boot.stack_count));
    let bootable = if is_bsp {
        true
    } else {
        boot_slot.is_some_and(|slot| slot < boot_capacity)
    };

    records.push(CpuRecord {
        logical_cpu_id,
        apic_id,
        is_bsp,
        numa_node: numa_node_for_apic(numa_info, apic_id),
        boot_slot,
        bootable,
    });
}

static CPU_TOPOLOGY: PoisonLock<Option<CpuTopology>> = PoisonLock::new(None);

pub(crate) fn install(topology: CpuTopology) {
    *CPU_TOPOLOGY.lock().unwrap_or_else(|e| e.into_inner()) = Some(topology);
}

pub(crate) fn reset() {
    *CPU_TOPOLOGY.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

pub fn snapshot() -> Option<CpuTopology> {
    CPU_TOPOLOGY
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

pub fn detected_cpu_count() -> usize {
    snapshot()
        .map(|topology| topology.detected_cpu_count())
        .unwrap_or(1)
}

pub fn bootable_cpu_count() -> usize {
    snapshot()
        .map(|topology| topology.bootable_cpu_count())
        .unwrap_or(1)
}

pub fn cpu_record(cpu_id: usize) -> Option<CpuRecord> {
    snapshot().and_then(|topology| topology.cpu_record(cpu_id).copied())
}

pub fn apic_id_for_cpu(cpu_id: usize) -> Option<u32> {
    snapshot().and_then(|topology| topology.apic_id_for_cpu(cpu_id))
}

pub fn cpu_for_apic_id(apic_id: u32) -> Option<usize> {
    snapshot().and_then(|topology| topology.cpu_for_apic_id(apic_id))
}

pub fn numa_node_for_cpu(cpu_id: usize) -> Option<usize> {
    cpu_record(cpu_id).and_then(|record| record.numa_node)
}

pub fn bootable_apic_ids() -> Vec<u32> {
    snapshot()
        .map(|topology| topology.bootable_apic_ids())
        .unwrap_or_default()
}

pub fn resolve_current_cpu_id() -> Option<usize> {
    if let Some(cpu_id) = crate::cpu::try_current_id() {
        return Some(cpu_id);
    }

    #[cfg(not(test))]
    {
        let apic_id = crate::io::apic::local_apic().id() as u32;
        return cpu_for_apic_id(apic_id);
    }

    #[cfg(test)]
    {
        None
    }
}

fn numa_node_for_apic(numa_info: &NumaInfo, apic_id: u32) -> Option<usize> {
    let node_count = usize::from(numa_info.node_count);
    for node_idx in 0..node_count.min(numa_info.nodes.len()) {
        let node = &numa_info.nodes[node_idx];
        let present = if apic_id < 64 {
            (node.cpu_apic_mask_low & (1u64 << apic_id)) != 0
        } else if apic_id < 128 {
            (node.cpu_apic_mask_high & (1u64 << (apic_id - 64))) != 0
        } else {
            false
        };
        if present {
            return Some(node_idx);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ap_boot_with(stack_count: u16) -> ApBootInfo {
        ApBootInfo {
            ap_count: 8,
            stack_count,
            _reserved: [0; 4],
            flags: 0,
            trampoline_layout_version: 0,
            trampoline_mailbox_offset: 0,
            _reserved2: [0; 4],
            trampoline_addr: 0,
            trampoline_size: 0,
            stack_base: 0,
            stack_size: 0,
        }
    }

    fn snapshot_with(apics: &[(u8, bool)]) -> AcpiBootSnapshot {
        let mut snapshot = AcpiBootSnapshot::default();
        snapshot.local_apic_count = apics.len() as u16;
        for (idx, (apic_id, enabled)) in apics.iter().copied().enumerate() {
            snapshot.local_apics[idx].apic_id = apic_id;
            snapshot.local_apics[idx].processor_id = apic_id;
            snapshot.local_apics[idx].flags = if enabled {
                boot_proto::acpi_local_apic_flags::ENABLED
            } else {
                0
            };
        }
        snapshot
    }

    fn numa_info_for(apic_to_node: &[(u32, usize)]) -> NumaInfo {
        let mut info = NumaInfo::default();
        let mut max_node = 0usize;
        for &(apic_id, node_id) in apic_to_node {
            max_node = max_node.max(node_id);
            if apic_id < 64 {
                info.nodes[node_id].cpu_apic_mask_low |= 1u64 << apic_id;
            } else {
                info.nodes[node_id].cpu_apic_mask_high |= 1u64 << (apic_id - 64);
            }
        }
        info.node_count = (max_node + 1) as u8;
        info
    }

    #[test_case]
    fn assigns_bsp_and_aps_in_acpi_order() {
        let topology = CpuTopology::from_sources(
            &snapshot_with(&[(7, true), (3, true), (9, true)]),
            &NumaInfo::default(),
            &ap_boot_with(4),
            3,
        );

        assert_eq!(topology.detected_cpu_count(), 3);
        assert_eq!(topology.cpu_record(0).map(|record| record.apic_id), Some(3));
        assert_eq!(topology.cpu_record(1).map(|record| record.apic_id), Some(7));
        assert_eq!(topology.cpu_record(2).map(|record| record.apic_id), Some(9));
        assert_eq!(
            topology.cpu_record(1).and_then(|record| record.boot_slot),
            Some(0)
        );
        assert_eq!(
            topology.cpu_record(2).and_then(|record| record.boot_slot),
            Some(1)
        );
    }

    #[test_case]
    fn marks_stack_exhausted_aps_as_unbootable() {
        let topology = CpuTopology::from_sources(
            &snapshot_with(&[(3, true), (5, true), (7, true), (9, true)]),
            &NumaInfo::default(),
            &ap_boot_with(2),
            3,
        );

        assert_eq!(topology.bootable_cpu_count(), 3);
        assert_eq!(
            topology.cpu_record(1).map(|record| record.bootable),
            Some(true)
        );
        assert_eq!(
            topology.cpu_record(2).map(|record| record.bootable),
            Some(true)
        );
        assert_eq!(
            topology.cpu_record(3).map(|record| record.bootable),
            Some(false)
        );
    }

    #[test_case]
    fn records_numa_node_from_apic_masks() {
        let topology = CpuTopology::from_sources(
            &snapshot_with(&[(3, true), (5, true), (7, true)]),
            &numa_info_for(&[(3, 0), (5, 1), (7, 1)]),
            &ap_boot_with(4),
            3,
        );

        assert_eq!(
            topology.cpu_record(0).and_then(|record| record.numa_node),
            Some(0)
        );
        assert_eq!(
            topology.cpu_record(1).and_then(|record| record.numa_node),
            Some(1)
        );
        assert_eq!(
            topology.cpu_record(2).and_then(|record| record.numa_node),
            Some(1)
        );
    }

    #[test_case]
    fn tracks_detected_total_even_when_cpu_limit_is_exceeded() {
        let mut apics = Vec::new();
        for apic_id in 0..80u8 {
            apics.push((apic_id, true));
        }
        let topology = CpuTopology::from_sources(
            &snapshot_with(&apics),
            &NumaInfo::default(),
            &ap_boot_with(80),
            0,
        );

        assert_eq!(topology.detected_cpu_count(), 80);
        assert_eq!(topology.records().len(), MAX_CPUS);
        assert_eq!(
            topology
                .cpu_record(MAX_CPUS - 1)
                .map(|record| record.logical_cpu_id),
            Some(MAX_CPUS - 1)
        );
    }
}
