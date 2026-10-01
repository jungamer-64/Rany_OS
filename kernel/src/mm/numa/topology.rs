// ============================================================================
// src/mm/numa.rs - NUMA-Aware Memory Allocation
// ============================================================================
//! NUMA-aware memory allocation APIs for kernel subsystems.
//!
//! ## 設計書 5.3: NUMAアーキテクチャへの対応
//!
//! 大規模サーバーではNUMA（Non-Uniform Memory Access）アーキテクチャが一般的です。
//! NUMAノード間のメモリアクセスは、ローカルノードへのアクセスと比較して
//! 2〜3倍のレイテンシが発生します。
//!
//! ## 実装方針
//!
//! 1. **ノードローカルアロケーション**: タスクが実行中のCPUコアが属するNUMAノードから
//!    メモリを割り当てる（First-Touch Policy）
//! 2. **明示的なノード指定**: `alloc_on_numa_node(node_id, layout)` でノードを指定可能
//! 3. **フォールバック**: 指定ノードにメモリがない場合は他のノードから割り当て
use crate::sync::PoisonLock;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::cpu::{ApicId, CpuId, CpuSnapshot};
use crate::mm::types::NumaNodeId;

/// 最大NUMAノード数
pub const MAX_NUMA_NODES: usize = 8;

#[derive(Debug)]
struct CpuLocalityTopology {
    cpu_to_node: BTreeMap<CpuId, NumaNodeId>,
    node_cpus: Vec<Vec<CpuId>>,
}

impl CpuLocalityTopology {
    fn single_node(snapshot: &CpuSnapshot) -> Self {
        let cpus = snapshot.possible().iter().collect::<Vec<_>>();
        let cpu_to_node = cpus
            .iter()
            .copied()
            .map(|cpu| (cpu, NumaNodeId::NODE_0))
            .collect();
        Self {
            cpu_to_node,
            node_cpus: alloc::vec![cpus],
        }
    }

    fn from_firmware(
        catalog: &acpi_driver::TableCatalog,
        snapshot: &CpuSnapshot,
    ) -> Result<Self, NumaTopologyError> {
        let cpu_affinities = catalog.numa_cpu_affinity()?;
        if cpu_affinities.is_empty() {
            return Ok(Self::single_node(snapshot));
        }
        let memory_affinities = catalog.numa_memory_affinity()?;

        let mut affinity_by_apic = BTreeMap::new();
        let mut domains = BTreeSet::new();
        for affinity in cpu_affinities
            .into_iter()
            .filter(|affinity| affinity.enabled)
        {
            let apic = ApicId::new(affinity.apic_id);
            if affinity_by_apic
                .insert(apic, affinity.proximity_domain)
                .is_some()
            {
                return Err(NumaTopologyError::DuplicateCpuAffinity { apic_id: apic });
            }
            domains.insert(affinity.proximity_domain);
        }
        for affinity in memory_affinities
            .into_iter()
            .filter(|affinity| affinity.enabled)
        {
            domains.insert(affinity.proximity_domain);
        }
        if domains.len() > MAX_NUMA_NODES {
            return Err(NumaTopologyError::TooManyNodes {
                discovered: domains.len(),
                supported: MAX_NUMA_NODES,
            });
        }

        let domain_to_node = domains
            .into_iter()
            .enumerate()
            .map(|(index, domain)| (domain, NumaNodeId::new(index as u8)))
            .collect::<BTreeMap<_, _>>();
        let mut topology = Self {
            cpu_to_node: BTreeMap::new(),
            node_cpus: alloc::vec![Vec::new(); domain_to_node.len()],
        };

        for slot in snapshot.slots() {
            let apic_id = slot.firmware.apic_id;
            let proximity_domain = affinity_by_apic
                .get(&apic_id)
                .copied()
                .or(slot.firmware.proximity_domain)
                .ok_or(NumaTopologyError::MissingCpuAffinity {
                    cpu_id: slot.id,
                    apic_id,
                })?;
            if let Some(slot_domain) = slot.firmware.proximity_domain
                && slot_domain != proximity_domain
            {
                return Err(NumaTopologyError::ConflictingCpuAffinity {
                    cpu_id: slot.id,
                    madt_domain: proximity_domain,
                    namespace_domain: slot_domain,
                });
            }
            let node = domain_to_node
                .get(&proximity_domain)
                .copied()
                .ok_or(NumaTopologyError::UnknownProximityDomain { proximity_domain })?;
            topology.cpu_to_node.insert(slot.id, node);
            topology.node_cpus[node.as_usize()].push(slot.id);
        }
        Ok(topology)
    }

    fn node_for_cpu(&self, cpu_id: CpuId) -> Option<NumaNodeId> {
        self.cpu_to_node.get(&cpu_id).copied()
    }

    fn cpus_in_node(&self, node_id: NumaNodeId) -> &[CpuId] {
        self.node_cpus
            .get(node_id.as_usize())
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    fn steal_candidates_for(&self, cpu_id: CpuId) -> Vec<CpuId> {
        let mut order = Vec::new();
        let Some(my_node) = self.node_for_cpu(cpu_id) else {
            return order;
        };

        for &candidate in self.cpus_in_node(my_node) {
            if candidate == cpu_id || order.contains(&candidate) {
                continue;
            }
            order.push(candidate);
        }

        for node in 0..self.node_cpus.len() {
            let node = NumaNodeId::new(node as u8);
            if node == my_node {
                continue;
            }
            for &candidate in self.cpus_in_node(node) {
                if candidate != cpu_id && !order.contains(&candidate) {
                    order.push(candidate);
                }
            }
        }

        order
    }
}

#[derive(Debug)]
pub enum NumaTopologyError {
    Acpi(acpi_driver::AcpiError),
    CpuSet(crate::cpu::CpuSetError),
    TooManyNodes {
        discovered: usize,
        supported: usize,
    },
    DuplicateCpuAffinity {
        apic_id: ApicId,
    },
    MissingCpuAffinity {
        cpu_id: CpuId,
        apic_id: ApicId,
    },
    ConflictingCpuAffinity {
        cpu_id: CpuId,
        madt_domain: u32,
        namespace_domain: u32,
    },
    UnknownProximityDomain {
        proximity_domain: u32,
    },
}

impl From<acpi_driver::AcpiError> for NumaTopologyError {
    fn from(error: acpi_driver::AcpiError) -> Self {
        Self::Acpi(error)
    }
}

impl From<crate::cpu::CpuSetError> for NumaTopologyError {
    fn from(error: crate::cpu::CpuSetError) -> Self {
        Self::CpuSet(error)
    }
}

static CPU_LOCALITY_TOPOLOGY: PoisonLock<Option<CpuLocalityTopology>> = PoisonLock::new(None);

fn publish_cpu_locality(topology: &CpuLocalityTopology) {
    for cpu_id in crate::cpu::snapshot().possible() {
        if let Some(local) = crate::cpu::runtime().cpu_local(cpu_id) {
            local.remote().set_numa_node(None);
        }
    }

    for (&cpu_id, &node_id) in &topology.cpu_to_node {
        set_cpu_to_node(cpu_id, node_id.as_u8());
    }
}

fn with_cpu_locality<R>(f: impl FnOnce(&CpuLocalityTopology) -> R) -> R {
    let mut guard = CPU_LOCALITY_TOPOLOGY
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let topology =
        guard.get_or_insert_with(|| CpuLocalityTopology::single_node(&crate::cpu::snapshot()));
    f(topology)
}

/// Publishes the CPU-to-NUMA mapping derived from SRAT and the CPU snapshot.
///
/// # Errors
///
/// Returns a typed topology error when firmware affinities are duplicated,
/// incomplete, conflicting, or exceed the supported NUMA node count.
pub fn configure_from_firmware(
    catalog: Option<&acpi_driver::TableCatalog>,
    snapshot: &CpuSnapshot,
) -> Result<(), NumaTopologyError> {
    let topology = match catalog {
        Some(catalog) => CpuLocalityTopology::from_firmware(catalog, snapshot)?,
        None => CpuLocalityTopology::single_node(snapshot),
    };
    publish_cpu_locality(&topology);

    let mut guard = CPU_LOCALITY_TOPOLOGY
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    *guard = Some(topology);
    Ok(())
}

pub fn apply_current_cpu_locality() {
    let Some(current) = crate::cpu::CurrentCpu::acquire() else {
        return;
    };
    let cpu_id = current.id();

    let Some(local_node) = node_for_cpu(cpu_id) else {
        return;
    };
    set_cpu_to_node(cpu_id, local_node.as_u8());
}

pub fn node_for_cpu(cpu_id: CpuId) -> Option<NumaNodeId> {
    with_cpu_locality(|topology| topology.node_for_cpu(cpu_id))
}

pub fn steal_candidates_for_cpu(cpu_id: CpuId) -> Vec<CpuId> {
    with_cpu_locality(|topology| topology.steal_candidates_for(cpu_id))
}

pub fn num_nodes() -> usize {
    with_cpu_locality(|topology| topology.node_cpus.len())
}

pub fn current_node() -> usize {
    crate::cpu::CurrentCpu::acquire().and_then(|cpu| cpu.memory_node())
        .map(NumaNodeId::as_usize).unwrap_or(0)
}

// ============================================================================
// RCU-Protected NUMA Topology Access
// ============================================================================

#[inline]
pub fn cpu_to_node_rcu(cpu_id: CpuId) -> Option<u8> {
    crate::cpu::runtime()
        .cpu_local(cpu_id)
        .and_then(|local| local.remote().numa_node())
}

pub fn set_cpu_to_node(cpu_id: CpuId, node_id: u8) {
    if let Some(local) = crate::cpu::runtime().cpu_local(cpu_id) {
        local.remote().set_numa_node(Some(node_id));
    }
}

#[inline]
pub fn current_numa_node_fast() -> Option<u8> {
    crate::cpu::CurrentCpu::acquire().and_then(|cpu| cpu_to_node_rcu(cpu.id()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpu(value: usize) -> CpuId {
        CpuId::try_from(value).unwrap()
    }

    #[test]
    fn steal_candidates_keep_sparse_ids_and_prefer_local_node() {
        let topology = CpuLocalityTopology {
            cpu_to_node: BTreeMap::from([
                (cpu(0), NumaNodeId::new(0)),
                (cpu(2), NumaNodeId::new(0)),
                (cpu(9), NumaNodeId::new(1)),
            ]),
            node_cpus: alloc::vec![alloc::vec![cpu(0), cpu(2)], alloc::vec![cpu(9)]],
        };

        assert_eq!(
            topology.steal_candidates_for(cpu(0)),
            alloc::vec![cpu(2), cpu(9)]
        );
        assert_eq!(
            topology.steal_candidates_for(cpu(9)),
            alloc::vec![cpu(0), cpu(2)]
        );
    }

    #[test]
    fn unknown_cpu_has_no_implicit_node_zero_mapping() {
        let topology = CpuLocalityTopology {
            cpu_to_node: BTreeMap::from([(cpu(0), NumaNodeId::new(0))]),
            node_cpus: alloc::vec![alloc::vec![cpu(0)]],
        };
        assert_eq!(topology.node_for_cpu(cpu(1)), None);
    }
}

pub fn with_numa_topology_rcu<F, R>(f: F) -> R
where
    F: FnOnce(&RcuReadGuard) -> R,
{
    let guard = rcu_read_lock();
    f(&guard)
}
