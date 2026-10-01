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
use super::placement::NumaPlacement;
use crate::cpu::{ApicId, CpuId, CpuSnapshot, MAX_POSSIBLE_CPUS};
use crate::mm::types::NumaNodeId;
use alloc::vec::Vec;

pub const MAX_NUMA_NODES: usize = 8;

pub fn current_node() -> usize {
    crate::cpu::CurrentCpu::acquire()
        .and_then(|cpu| cpu.memory_node())
        .map(NumaNodeId::as_usize)
        .unwrap_or(0)
}

