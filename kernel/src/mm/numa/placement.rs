//! Validated locality coordinates shared by CPU placement and physical RAM
//! admission. Firmware decoding belongs to the platform boundary. Sparse
//! proximity domains are normalized once, including nodes with no usable RAM.

use crate::cpu::ApicId;
use crate::mm::types::NumaNodeId;
use alloc::vec::Vec;
use x86_64::PhysAddr;

#[derive(Debug, Clone, Copy)]
pub struct CpuAffinity {
    pub apic_id: ApicId,
    pub proximity_domain: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct MemoryAffinity {
    pub base: PhysAddr,
    pub bytes: u64,
    pub proximity_domain: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlacementError {
    MetadataAllocation,
    TooManyNodes { discovered: usize, supported: usize },
    DuplicateCpuAffinity { apic_id: ApicId },
    InvalidMemoryRange,
    OverlappingMemory,
    MissingDistance { from_domain: u32, to_domain: u32 },
    InvalidDistance { from_domain: u32, to_domain: u32 },
}

/// CPU discovery must resolve its memory node before publishing a slot. A
/// namespace proximity domain may describe a hot-added APIC absent from SRAT,
/// but cannot contradict an existing affinity or introduce a new memory node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuPlacementError {
    MissingAffinity {
        apic_id: ApicId,
    },
    ConflictingAffinity {
        apic_id: ApicId,
        proximity_domain: u32,
    },
    UnknownProximityDomain {
        proximity_domain: u32,
    },
}

#[derive(Debug)]
pub struct NumaPlacement {
    domains: Vec<u32>,
    cpus: Vec<(ApicId, NumaNodeId)>,
    memory: Vec<(PhysAddr, u64, NumaNodeId)>,
    distances: [[u8; NumaNodeId::MAX_NODES]; NumaNodeId::MAX_NODES],
    node_order: [[NumaNodeId; NumaNodeId::MAX_NODES]; NumaNodeId::MAX_NODES],
}

impl NumaPlacement {
    /// Admit enabled affinities and normalize their coordinate space. `distance`
    /// observes firmware coordinates only during construction; no allocator or
    /// CPU lookup subsequently decodes or renumbers them.
    pub fn try_new(
        cpus: &[CpuAffinity],
        memory: &[MemoryAffinity],
        mut distance: impl FnMut(u32, u32) -> Option<u8>,
    ) -> Result<Self, PlacementError> {
        let mut domains = Vec::new();
        domains
            .try_reserve_exact(
                cpus.len()
                    .checked_add(memory.len())
                    .and_then(|n| n.checked_add(1))
                    .ok_or(PlacementError::MetadataAllocation)?,
            )
            .map_err(|_| PlacementError::MetadataAllocation)?;
        domains.extend(cpus.iter().map(|cpu| cpu.proximity_domain));
        domains.extend(memory.iter().map(|region| region.proximity_domain));
        domains.sort_unstable();
        domains.dedup();
        if domains.is_empty() {
            domains.push(0);
        }
        if domains.len() > NumaNodeId::MAX_NODES {
            return Err(PlacementError::TooManyNodes {
                discovered: domains.len(),
                supported: NumaNodeId::MAX_NODES,
            });
        }
        let node_for = |domain| {
            NumaNodeId::new(
                domains
                    .binary_search(&domain)
                    .expect("affinity domain was admitted") as u8,
            )
        };
        let mut cpu_nodes = Vec::new();
        cpu_nodes
            .try_reserve_exact(cpus.len())
            .map_err(|_| PlacementError::MetadataAllocation)?;
        cpu_nodes.extend(
            cpus.iter()
                .map(|cpu| (cpu.apic_id, node_for(cpu.proximity_domain))),
        );
        cpu_nodes.sort_unstable_by_key(|&(apic, _)| apic);
        if let Some(pair) = cpu_nodes.windows(2).find(|pair| pair[0].0 == pair[1].0) {
            return Err(PlacementError::DuplicateCpuAffinity { apic_id: pair[0].0 });
        }
        let mut memory_nodes = Vec::new();
        memory_nodes
            .try_reserve_exact(memory.len())
            .map_err(|_| PlacementError::MetadataAllocation)?;
        for region in memory {
            if region.bytes == 0
                || region
                    .base
                    .as_u64()
                    .checked_add(region.bytes)
                    .is_none_or(|end| end > 1 << 52)
            {
                return Err(PlacementError::InvalidMemoryRange);
            }
            memory_nodes.push((region.base, region.bytes, node_for(region.proximity_domain)));
        }
        memory_nodes.sort_unstable_by_key(|region| region.0);
        if memory_nodes
            .windows(2)
            .any(|pair| pair[0].0.as_u64() + pair[0].1 > pair[1].0.as_u64())
        {
            return Err(PlacementError::OverlappingMemory);
        }
        let mut distances = [[u8::MAX; NumaNodeId::MAX_NODES]; NumaNodeId::MAX_NODES];
        for (from, &from_domain) in domains.iter().enumerate() {
            for (to, &to_domain) in domains.iter().enumerate() {
                let value =
                    distance(from_domain, to_domain).ok_or(PlacementError::MissingDistance {
                        from_domain,
                        to_domain,
                    })?;
                if value < 10 || (from == to && value != 10) {
                    return Err(PlacementError::InvalidDistance {
                        from_domain,
                        to_domain,
                    });
                }
                distances[from][to] = value;
            }
        }
        let mut node_order =
            core::array::from_fn(|_| core::array::from_fn(|node| NumaNodeId::new(node as u8)));
        for (from, order) in node_order.iter_mut().enumerate().take(domains.len()) {
            order[..domains.len()].sort_unstable_by_key(|node| {
                (
                    node.as_usize() != from,
                    distances[from][node.as_usize()],
                    node.as_usize(),
                )
            });
        }
        Ok(Self {
            node_order,
            domains,
            cpus: cpu_nodes,
            memory: memory_nodes,
            distances,
        })
    }

    pub fn node_count(&self) -> usize {
        self.domains.len()
    }
    pub fn node_for_domain(&self, domain: u32) -> Option<NumaNodeId> {
        self.domains
            .binary_search(&domain)
            .ok()
            .map(|index| NumaNodeId::new(index as u8))
    }
    pub fn node_for_apic(&self, apic: ApicId) -> Option<NumaNodeId> {
        self.cpus
            .binary_search_by_key(&apic, |&(id, _)| id)
            .ok()
            .map(|index| self.cpus[index].1)
    }
    /// Resolve one firmware CPU identity in the already admitted coordinate
    /// space. Missing affinity is accepted only for a single-node machine.
    pub fn resolve_cpu(
        &self,
        apic_id: ApicId,
        proximity_domain: Option<u32>,
    ) -> Result<NumaNodeId, CpuPlacementError> {
        let affinity = self.node_for_apic(apic_id);
        let namespace = proximity_domain
            .map(|domain| {
                self.node_for_domain(domain)
                    .ok_or(CpuPlacementError::UnknownProximityDomain {
                        proximity_domain: domain,
                    })
            })
            .transpose()?;
        if let (Some(affinity), Some(namespace), Some(domain)) =
            (affinity, namespace, proximity_domain)
            && affinity != namespace
        {
            return Err(CpuPlacementError::ConflictingAffinity {
                apic_id,
                proximity_domain: domain,
            });
        }
        affinity
            .or(namespace)
            .or_else(|| (self.node_count() == 1).then_some(NumaNodeId::NODE_0))
            .ok_or(CpuPlacementError::MissingAffinity { apic_id })
    }
    /// Distance order is derived once; unreachable nodes are excluded by the
    /// consumer's admission policy rather than becoming a new distance authority.
    pub fn node_order(&self, node: NumaNodeId) -> Option<&[NumaNodeId]> {
        (node.as_usize() < self.node_count())
            .then(|| &self.node_order[node.as_usize()][..self.node_count()])
    }
    pub fn memory(&self) -> &[(PhysAddr, u64, NumaNodeId)] {
        &self.memory
    }
    pub fn distances(&self) -> &[[u8; NumaNodeId::MAX_NODES]; NumaNodeId::MAX_NODES] {
        &self.distances
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn default_distance(a: u32, b: u32) -> Option<u8> {
        Some(if a == b { 10 } else { 20 })
    }
    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn full_node_capacity_admits_the_last_sparse_domain_and_orders_it_locally() {
        let cpus: Vec<_> = (0..NumaNodeId::MAX_NODES as u32)
            .map(|id| CpuAffinity {
                apic_id: ApicId::new(id),
                proximity_domain: 1000 + 7 * id,
            })
            .collect();
        let last = cpus.last().unwrap();
        let placement = NumaPlacement::try_new(
            &cpus,
            &[MemoryAffinity {
                base: PhysAddr::new(0x200000),
                bytes: 0x5000,
                proximity_domain: last.proximity_domain,
            }],
            default_distance,
        )
        .unwrap();
        let node = placement.node_for_apic(last.apic_id).unwrap();
        assert_eq!(placement.node_count(), NumaNodeId::MAX_NODES);
        assert_eq!(node.as_usize(), NumaNodeId::MAX_NODES - 1);
        assert!(node.is_valid());
        assert_eq!(placement.memory()[0].2, node);
        let order = placement.node_order(node).unwrap();
        assert_eq!(order.len(), NumaNodeId::MAX_NODES);
        assert_eq!(order[0], node);
        for (index, &candidate) in order[1..].iter().enumerate() {
            assert_eq!(candidate.as_usize(), index);
        }
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn namespace_only_cpu_uses_existing_coordinates_and_rejects_conflicts() {
        let placement = NumaPlacement::try_new(
            &[
                CpuAffinity {
                    apic_id: ApicId::new(1),
                    proximity_domain: 2,
                },
                CpuAffinity {
                    apic_id: ApicId::new(42),
                    proximity_domain: 9,
                },
            ],
            &[],
            default_distance,
        )
        .unwrap();
        assert_eq!(
            placement.resolve_cpu(ApicId::new(77), Some(9)),
            Ok(NumaNodeId::new(1))
        );
        assert_eq!(
            placement.resolve_cpu(ApicId::new(77), None),
            Err(CpuPlacementError::MissingAffinity {
                apic_id: ApicId::new(77)
            })
        );
        assert_eq!(
            placement.resolve_cpu(ApicId::new(1), Some(9)),
            Err(CpuPlacementError::ConflictingAffinity {
                apic_id: ApicId::new(1),
                proximity_domain: 9
            })
        );
        assert_eq!(
            placement.resolve_cpu(ApicId::new(77), Some(8)),
            Err(CpuPlacementError::UnknownProximityDomain {
                proximity_domain: 8
            })
        );
        assert_eq!(
            placement.node_order(NumaNodeId::new(1)),
            Some(&[NumaNodeId::new(1), NumaNodeId::NODE_0][..])
        );
        assert_eq!(placement.node_order(NumaNodeId::new(2)), None);
        let single = NumaPlacement::try_new(&[], &[], default_distance).unwrap();
        assert_eq!(
            single.resolve_cpu(ApicId::new(77), None),
            Ok(NumaNodeId::NODE_0)
        );
    }
    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn sparse_domains_share_cpu_memory_and_distance_coordinates() {
        let placement = NumaPlacement::try_new(
            &[CpuAffinity {
                apic_id: ApicId::new(42),
                proximity_domain: 9,
            }],
            &[MemoryAffinity {
                base: PhysAddr::new(0x3000),
                bytes: 0x5000,
                proximity_domain: 2,
            }],
            |a, b| {
                Some(if a == b {
                    10
                } else if a == 9 {
                    31
                } else {
                    255
                })
            },
        )
        .unwrap();
        assert_eq!(placement.node_count(), 2);
        assert_eq!(
            placement.node_for_apic(ApicId::new(42)),
            Some(NumaNodeId::new(1))
        );
        assert_eq!(placement.memory()[0].2, NumaNodeId::NODE_0);
        assert_eq!(placement.distances()[1][0], 31);
        assert_eq!(placement.distances()[0][1], 255);
        assert_eq!(placement.node_for_domain(8), None);
    }
    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn invalid_affinities_and_incomplete_distances_are_rejected() {
        let cpu = CpuAffinity {
            apic_id: ApicId::new(8),
            proximity_domain: 7,
        };
        assert!(matches!(
            NumaPlacement::try_new(&[cpu, cpu], &[], default_distance),
            Err(PlacementError::DuplicateCpuAffinity { .. })
        ));
        let region = MemoryAffinity {
            base: PhysAddr::new(0x3000),
            bytes: 0x5000,
            proximity_domain: 2,
        };
        assert!(matches!(
            NumaPlacement::try_new(&[], &[region, region], default_distance),
            Err(PlacementError::OverlappingMemory)
        ));
        assert!(matches!(
            NumaPlacement::try_new(&[cpu], &[region], |_, _| None),
            Err(PlacementError::MissingDistance { .. })
        ));
        assert!(matches!(
            NumaPlacement::try_new(
                &[],
                &[MemoryAffinity {
                    bytes: u64::MAX,
                    ..region
                }],
                default_distance
            ),
            Err(PlacementError::InvalidMemoryRange)
        ));
        assert!(matches!(
            NumaPlacement::try_new(&[cpu], &[], |_, _| Some(11)),
            Err(PlacementError::InvalidDistance { .. })
        ));
        let cpus: Vec<_> = (0..NumaNodeId::MAX_NODES as u32 + 1)
            .map(|id| CpuAffinity {
                apic_id: ApicId::new(id),
                proximity_domain: id,
            })
            .collect();
        assert!(matches!(
            NumaPlacement::try_new(&cpus, &[], default_distance),
            Err(PlacementError::TooManyNodes { discovered, supported })
                if discovered == NumaNodeId::MAX_NODES + 1 && supported == NumaNodeId::MAX_NODES
        ));
    }
}
