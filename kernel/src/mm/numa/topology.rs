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
//! 3. **フォールバック**: 通常の物理割り当ては PMM の距離順、明示指定は指定ノードのみ
use crate::cpu::CpuId;
use crate::mm::types::NumaNodeId;
use alloc::vec::Vec;

/// Remote observation belongs to cold placement/reclaim paths. Allocation
/// reads the bound CPU-local node directly and never acquires the runtime lock.
pub fn node_for_cpu(cpu_id: CpuId) -> Option<NumaNodeId> {
    crate::cpu::try_runtime()?
        .cpu_local(cpu_id)?
        .remote()
        .numa_node()
        .map(NumaNodeId::new)
}

/// Scheduling candidates are built when an executor is provisioned. CPU
/// membership comes from the current runtime, including namespace-only CPUs;
/// the immutable placement owns distance order, not a second membership map.
pub fn steal_candidates_for_cpu(cpu_id: CpuId) -> Vec<CpuId> {
    let Some(node) = node_for_cpu(cpu_id) else {
        return Vec::new();
    };
    let Ok(placement) = crate::platform::firmware::numa_placement() else {
        return Vec::new();
    };
    let snapshot = crate::cpu::snapshot();
    let mut candidates = Vec::new();
    if let Some(nodes) = placement.node_order(node) {
        for candidate_node in nodes {
            if placement.distances()[node.as_usize()][candidate_node.as_usize()] == u8::MAX {
                continue;
            }
            for slot in snapshot.slots() {
                if slot.id != cpu_id && node_for_cpu(slot.id) == Some(*candidate_node) {
                    candidates.push(slot.id);
                }
            }
        }
    }
    candidates
}

pub fn num_nodes() -> usize {
    crate::platform::firmware::numa_placement().map_or(1, |placement| placement.node_count())
}

pub fn current_node() -> usize {
    crate::cpu::CurrentCpu::acquire()
        .and_then(|cpu| cpu.memory_node())
        .map(NumaNodeId::as_usize)
        .unwrap_or(0)
}

#[inline]
pub fn current_numa_node_fast() -> Option<u8> {
    crate::cpu::CurrentCpu::acquire()
        .and_then(|cpu| cpu.memory_node())
        .map(NumaNodeId::as_u8)
}
