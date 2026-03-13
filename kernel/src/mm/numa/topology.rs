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
#![allow(dead_code)]

use crate::sync::PoisonLock;
use alloc::alloc::Layout;
use alloc::vec::Vec;
use boot_proto::NumaInfo;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::mm::types::NumaNodeId;

/// 最大NUMAノード数
pub const MAX_NUMA_NODES: usize = 8;

#[derive(Debug)]
struct CpuLocalityTopology {
    core_to_node: [u8; crate::per_cpu::MAX_CPUS],
    node_cores: [Vec<usize>; MAX_NUMA_NODES],
    llc_siblings: [Vec<usize>; crate::per_cpu::MAX_CPUS],
    node_count: usize,
    core_count: usize,
}

impl CpuLocalityTopology {
    fn detect(core_count: usize) -> Self {
        let core_count = core_count.min(crate::per_cpu::MAX_CPUS).max(1);
        let mut topology = Self::default();
        topology.core_count = core_count;
        topology.node_count = 1;

        for cpu_id in 0..core_count {
            topology.core_to_node[cpu_id] = 0;
            topology.node_cores[0].push(cpu_id);
            topology.llc_siblings[cpu_id].push(cpu_id);
        }

        topology
    }

    fn from_boot_info(numa_info: &NumaInfo, core_count: usize) -> Self {
        let node_count = (numa_info.node_count as usize).min(MAX_NUMA_NODES);
        if node_count == 0 {
            return Self::detect(core_count);
        }

        let core_count = core_count.min(crate::per_cpu::MAX_CPUS).max(1);
        let mut topology = Self::default();
        let mut assigned = [false; crate::per_cpu::MAX_CPUS];
        topology.node_count = node_count.max(1);
        topology.core_count = core_count;

        for node_idx in 0..node_count {
            let node = &numa_info.nodes[node_idx];

            for apic_id in 0..128u32 {
                let present = if apic_id < 64 {
                    (node.cpu_apic_mask_low & (1u64 << apic_id)) != 0
                } else {
                    (node.cpu_apic_mask_high & (1u64 << (apic_id - 64))) != 0
                };
                if !present {
                    continue;
                }

                let Some(cpu_id) = crate::smp::cpu_for_apic_id(apic_id) else {
                    continue;
                };
                if cpu_id >= core_count || assigned[cpu_id] {
                    continue;
                }

                topology.core_to_node[cpu_id] = node_idx as u8;
                topology.node_cores[node_idx].push(cpu_id);
                topology.llc_siblings[cpu_id].push(cpu_id);
                assigned[cpu_id] = true;
            }
        }

        if topology
            .node_cores
            .iter()
            .take(node_count)
            .all(|cores| cores.is_empty())
        {
            return Self::detect(core_count);
        }

        for cpu_id in 0..core_count {
            if assigned[cpu_id] {
                continue;
            }
            topology.core_to_node[cpu_id] = 0;
            topology.node_cores[0].push(cpu_id);
            topology.llc_siblings[cpu_id].push(cpu_id);
        }

        topology
    }

    fn node_for_cpu(&self, cpu_id: usize) -> usize {
        self.core_to_node.get(cpu_id).copied().unwrap_or(0) as usize
    }

    fn cores_in_node(&self, node_id: usize) -> &[usize] {
        self.node_cores
            .get(node_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    fn steal_candidates_for(&self, cpu_id: usize) -> Vec<usize> {
        let mut order = Vec::new();
        let my_node = self.node_for_cpu(cpu_id);

        for &candidate in self
            .llc_siblings
            .get(cpu_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            if candidate != cpu_id && !order.contains(&candidate) {
                order.push(candidate);
            }
        }

        for &candidate in self.cores_in_node(my_node) {
            if candidate == cpu_id || order.contains(&candidate) {
                continue;
            }
            order.push(candidate);
        }

        for node in 0..self.node_count {
            if node == my_node {
                continue;
            }
            for &candidate in self.cores_in_node(node) {
                if candidate != cpu_id && !order.contains(&candidate) {
                    order.push(candidate);
                }
            }
        }

        order
    }
}

impl Default for CpuLocalityTopology {
    fn default() -> Self {
        Self {
            core_to_node: [0; crate::per_cpu::MAX_CPUS],
            node_cores: core::array::from_fn(|_| Vec::new()),
            llc_siblings: core::array::from_fn(|_| Vec::new()),
            node_count: 1,
            core_count: 1,
        }
    }
}

static CPU_LOCALITY_TOPOLOGY: PoisonLock<Option<CpuLocalityTopology>> = PoisonLock::new(None);

fn current_core_count() -> usize {
    (crate::smp::cpu_count() as usize).clamp(1, crate::per_cpu::MAX_CPUS)
}

fn publish_cpu_locality(topology: &CpuLocalityTopology) {
    update_numa_node_count(topology.node_count);

    for cpu_id in 0..CPU_TO_NODE_MAP.len() {
        CPU_TO_NODE_MAP[cpu_id].store(u8::MAX, Ordering::Release);
    }

    for cpu_id in 0..topology.core_count {
        set_cpu_to_node(cpu_id, topology.node_for_cpu(cpu_id) as u8);
    }
}

fn with_cpu_locality<R>(f: impl FnOnce(&CpuLocalityTopology) -> R) -> R {
    let mut guard = CPU_LOCALITY_TOPOLOGY
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let topology = guard.get_or_insert_with(|| CpuLocalityTopology::detect(current_core_count()));
    publish_cpu_locality(topology);
    f(topology)
}

pub fn configure_from_boot_info(numa_info: &NumaInfo) {
    let topology = CpuLocalityTopology::from_boot_info(numa_info, current_core_count());
    publish_cpu_locality(&topology);

    let mut guard = CPU_LOCALITY_TOPOLOGY
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    *guard = Some(topology);
}

pub fn apply_current_cpu_locality() {
    let Some(cpu_id) = crate::per_cpu::try_current_cpu_id() else {
        return;
    };

    let local_node = NumaNodeId::new(node_for_cpu(cpu_id) as u8);
    let node_count = with_cpu_locality(|topology| topology.node_count);
    let mut sorted_nodes = [NumaNodeId::new(0); MAX_NUMA_NODES];
    let mut count = 0usize;

    sorted_nodes[count] = local_node;
    count += 1;

    for node_idx in 0..node_count {
        let node = NumaNodeId::new(node_idx as u8);
        if node == local_node || count >= sorted_nodes.len() {
            continue;
        }
        sorted_nodes[count] = node;
        count += 1;
    }

    let _ = crate::per_cpu::with_current_cold_mut(|cold| {
        cold.setup_numa_zonelist(local_node, &sorted_nodes, count);
        cold.pt_magazine.set_preferred_node(local_node.as_u8());
    });

    set_cpu_to_node(cpu_id, local_node.as_u8());
}

pub fn node_for_cpu(cpu_id: usize) -> usize {
    crate::smp::topology::numa_node_for_cpu(cpu_id)
        .unwrap_or_else(|| with_cpu_locality(|topology| topology.node_for_cpu(cpu_id)))
}

pub fn steal_candidates_for_cpu(cpu_id: usize) -> Vec<usize> {
    with_cpu_locality(|topology| topology.steal_candidates_for(cpu_id))
}

/// NUMAノードごとのアロケータ統計
#[derive(Debug, Default)]
pub struct NumaNodeStats {
    /// 割り当て回数
    pub allocations: AtomicU64,
    /// 解放回数
    pub deallocations: AtomicU64,
    /// 現在の使用バイト数
    pub used_bytes: AtomicU64,
    /// ピーク使用バイト数
    pub peak_bytes: AtomicU64,
    /// フォールバック発生回数（他ノードからの割り当て）
    pub fallback_count: AtomicU64,
}

impl NumaNodeStats {
    pub const fn new() -> Self {
        Self {
            allocations: AtomicU64::new(0),
            deallocations: AtomicU64::new(0),
            used_bytes: AtomicU64::new(0),
            peak_bytes: AtomicU64::new(0),
            fallback_count: AtomicU64::new(0),
        }
    }

    fn record_allocation(&self, size: usize) {
        self.allocations.fetch_add(1, Ordering::Relaxed);
        let new_used = self.used_bytes.fetch_add(size as u64, Ordering::Relaxed) + size as u64;
        // ピーク値を更新（CASループ）
        // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
        loop {
            let peak = self.peak_bytes.load(Ordering::Relaxed);
            if new_used <= peak {
                break;
            }
            if self
                .peak_bytes
                .compare_exchange_weak(peak, new_used, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
    }

    fn record_deallocation(&self, size: usize) {
        self.deallocations.fetch_add(1, Ordering::Relaxed);
        self.used_bytes.fetch_sub(size as u64, Ordering::Relaxed);
    }

    fn record_fallback(&self) {
        self.fallback_count.fetch_add(1, Ordering::Relaxed);
    }
}

/// NUMAノード情報
#[derive(Debug)]
pub struct NumaNode {
    /// ノードID
    pub id: NumaNodeId,
    /// このノードのメモリ範囲（開始アドレス、サイズ）
    pub memory_ranges: [(u64, u64); 4],
    /// 有効なメモリ範囲数
    pub range_count: usize,
    /// このノードに属するCPUコアのビットマスク
    pub cpu_mask: u64,
    /// 総メモリサイズ（バイト）
    pub total_memory: u64,
    /// 統計情報
    pub stats: NumaNodeStats,
}

impl NumaNode {
    /// 空のNUMAノードを作成
    pub const fn empty(id: NumaNodeId) -> Self {
        Self {
            id,
            memory_ranges: [(0, 0); 4],
            range_count: 0,
            cpu_mask: 0,
            total_memory: 0,
            stats: NumaNodeStats::new(),
        }
    }

    pub fn new(id: NumaNodeId) -> Self {
        Self::empty(id)
    }

    /// メモリ範囲を追加
    pub fn add_memory_range(&mut self, start: u64, size: u64) {
        if self.range_count < self.memory_ranges.len() {
            self.memory_ranges[self.range_count] = (start, size);
            self.range_count += 1;
            self.total_memory += size;
        }
    }

    /// CPUコアを追加
    pub fn add_cpu(&mut self, cpu_id: u8) {
        if cpu_id < 64 {
            self.cpu_mask |= 1u64 << cpu_id;
        }
    }

    /// 指定アドレスがこのノードに属するか判定
    pub fn contains_address(&self, addr: u64) -> bool {
        for i in 0..self.range_count {
            let (start, size) = self.memory_ranges[i];
            if addr >= start && addr < start + size {
                return true;
            }
        }
        false
    }

    /// このノードの総メモリサイズを取得
    pub fn total_memory(&self) -> u64 {
        self.total_memory
    }
}

/// NUMAトポロジ情報
#[derive(Debug)]
pub struct NumaTopology {
    /// 各NUMAノードの情報
    pub(crate) nodes: [NumaNode; MAX_NUMA_NODES],
    /// 有効なノード数
    pub(crate) node_count: usize,
    /// ノード間距離行列
    distance_matrix: [[u8; MAX_NUMA_NODES]; MAX_NUMA_NODES],
    /// 距離キャッシュ
    distance_cache: [[NumaNodeId; MAX_NUMA_NODES]; MAX_NUMA_NODES],
    /// 距離キャッシュが初期化済みか
    distance_cache_valid: bool,
}

impl NumaTopology {
    /// 空のトポロジを作成
    pub const fn new() -> Self {
        let nodes = [
            NumaNode::empty(NumaNodeId::new(0)),
            NumaNode::empty(NumaNodeId::new(1)),
            NumaNode::empty(NumaNodeId::new(2)),
            NumaNode::empty(NumaNodeId::new(3)),
            NumaNode::empty(NumaNodeId::new(4)),
            NumaNode::empty(NumaNodeId::new(5)),
            NumaNode::empty(NumaNodeId::new(6)),
            NumaNode::empty(NumaNodeId::new(7)),
        ];

        let distance_matrix = [
            [10, 20, 20, 20, 20, 20, 20, 20],
            [20, 10, 20, 20, 20, 20, 20, 20],
            [20, 20, 10, 20, 20, 20, 20, 20],
            [20, 20, 20, 10, 20, 20, 20, 20],
            [20, 20, 20, 20, 10, 20, 20, 20],
            [20, 20, 20, 20, 20, 10, 20, 20],
            [20, 20, 20, 20, 20, 20, 10, 20],
            [20, 20, 20, 20, 20, 20, 20, 10],
        ];

        let distance_cache = [
            [
                NumaNodeId::new(0),
                NumaNodeId::new(1),
                NumaNodeId::new(2),
                NumaNodeId::new(3),
                NumaNodeId::new(4),
                NumaNodeId::new(5),
                NumaNodeId::new(6),
                NumaNodeId::new(7),
            ],
            [
                NumaNodeId::new(1),
                NumaNodeId::new(0),
                NumaNodeId::new(2),
                NumaNodeId::new(3),
                NumaNodeId::new(4),
                NumaNodeId::new(5),
                NumaNodeId::new(6),
                NumaNodeId::new(7),
            ],
            [
                NumaNodeId::new(2),
                NumaNodeId::new(0),
                NumaNodeId::new(1),
                NumaNodeId::new(3),
                NumaNodeId::new(4),
                NumaNodeId::new(5),
                NumaNodeId::new(6),
                NumaNodeId::new(7),
            ],
            [
                NumaNodeId::new(3),
                NumaNodeId::new(0),
                NumaNodeId::new(1),
                NumaNodeId::new(2),
                NumaNodeId::new(4),
                NumaNodeId::new(5),
                NumaNodeId::new(6),
                NumaNodeId::new(7),
            ],
            [
                NumaNodeId::new(4),
                NumaNodeId::new(0),
                NumaNodeId::new(1),
                NumaNodeId::new(2),
                NumaNodeId::new(3),
                NumaNodeId::new(5),
                NumaNodeId::new(6),
                NumaNodeId::new(7),
            ],
            [
                NumaNodeId::new(5),
                NumaNodeId::new(0),
                NumaNodeId::new(1),
                NumaNodeId::new(2),
                NumaNodeId::new(3),
                NumaNodeId::new(4),
                NumaNodeId::new(6),
                NumaNodeId::new(7),
            ],
            [
                NumaNodeId::new(6),
                NumaNodeId::new(0),
                NumaNodeId::new(1),
                NumaNodeId::new(2),
                NumaNodeId::new(3),
                NumaNodeId::new(4),
                NumaNodeId::new(5),
                NumaNodeId::new(7),
            ],
            [
                NumaNodeId::new(7),
                NumaNodeId::new(0),
                NumaNodeId::new(1),
                NumaNodeId::new(2),
                NumaNodeId::new(3),
                NumaNodeId::new(4),
                NumaNodeId::new(5),
                NumaNodeId::new(6),
            ],
        ];

        Self {
            nodes,
            node_count: 1,
            distance_matrix,
            distance_cache,
            distance_cache_valid: false,
        }
    }

    pub fn precompute_distance_cache(&mut self) {
        for from in 0..self.node_count {
            let mut pairs: [(usize, u8); MAX_NUMA_NODES] = [(0, 255); MAX_NUMA_NODES];
            for to in 0..self.node_count {
                pairs[to] = (to, self.distance_matrix[from][to]);
            }

            for i in 1..self.node_count {
                let mut j = i;
                // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
                while j > 0 && pairs[j - 1].1 > pairs[j].1 {
                    pairs.swap(j - 1, j);
                    j -= 1;
                }
            }

            for (i, &(node_idx, _)) in pairs.iter().enumerate().take(MAX_NUMA_NODES) {
                self.distance_cache[from][i] = NumaNodeId::new(node_idx as u8);
            }
        }

        self.distance_cache_valid = true;
    }

    #[inline]
    pub fn node_count(&self) -> usize {
        self.node_count
    }

    pub fn get_node(&self, id: NumaNodeId) -> Option<&NumaNode> {
        let idx = id.as_usize();
        if idx < self.node_count {
            Some(&self.nodes[idx])
        } else {
            None
        }
    }

    pub fn cpu_to_node(&self, cpu_id: u8) -> NumaNodeId {
        for i in 0..self.node_count {
            if (self.nodes[i].cpu_mask & (1u64 << cpu_id)) != 0 {
                return NumaNodeId::new(i as u8);
            }
        }
        NumaNodeId::new(0)
    }

    pub fn addr_to_node(&self, addr: u64) -> NumaNodeId {
        for i in 0..self.node_count {
            if self.nodes[i].contains_address(addr) {
                return NumaNodeId::new(i as u8);
            }
        }
        NumaNodeId::new(0)
    }

    #[inline]
    pub fn distance(&self, from: NumaNodeId, to: NumaNodeId) -> u8 {
        self.distance_matrix[from.as_usize()][to.as_usize()]
    }

    #[inline]
    pub fn nodes_by_distance(&self, from: NumaNodeId) -> [NumaNodeId; MAX_NUMA_NODES] {
        if self.distance_cache_valid {
            return self.distance_cache[from.as_usize()];
        }
        self.compute_nodes_by_distance_slow(from)
    }

    fn compute_nodes_by_distance_slow(&self, from: NumaNodeId) -> [NumaNodeId; MAX_NUMA_NODES] {
        let mut result = [NumaNodeId::new(0); MAX_NUMA_NODES];
        let mut indices: [usize; MAX_NUMA_NODES] = [0, 1, 2, 3, 4, 5, 6, 7];

        for i in 0..self.node_count {
            for j in (i + 1)..self.node_count {
                let dist_i = self.distance(from, NumaNodeId::new(indices[i] as u8));
                let dist_j = self.distance(from, NumaNodeId::new(indices[j] as u8));
                if dist_i > dist_j {
                    indices.swap(i, j);
                }
            }
        }

        for (i, &idx) in indices.iter().enumerate() {
            result[i] = NumaNodeId::new(idx as u8);
        }
        result
    }
}

/// グローバルNUMAアロケータ
pub struct NumaAllocator {
    nodes: [Option<NumaNode>; MAX_NUMA_NODES],
    node_count: AtomicUsize,
    initialized: AtomicUsize,
}

impl NumaAllocator {
    pub const fn new() -> Self {
        const NONE: Option<NumaNode> = None;
        Self {
            nodes: [NONE; MAX_NUMA_NODES],
            node_count: AtomicUsize::new(1),
            initialized: AtomicUsize::new(0),
        }
    }

    pub fn register_node(&mut self, node: NumaNode) {
        let id = node.id.as_usize();
        if id < MAX_NUMA_NODES {
            self.nodes[id] = Some(node);
            let current = self.node_count.load(Ordering::Relaxed);
            if id >= current {
                self.node_count.store(id + 1, Ordering::Release);
            }
        }
    }

    pub fn mark_initialized(&self) {
        self.initialized.store(1, Ordering::Release);
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire) != 0
    }

    pub fn node_count(&self) -> usize {
        self.node_count.load(Ordering::Acquire)
    }

    pub fn get_node(&self, node_id: usize) -> Option<&NumaNode> {
        if node_id < MAX_NUMA_NODES {
            self.nodes[node_id].as_ref()
        } else {
            None
        }
    }

    pub fn allocate(
        &self,
        layout: Layout,
        preferred_node: Option<usize>,
    ) -> Option<(NonNull<u8>, usize)> {
        let target_node = preferred_node.unwrap_or_else(current_node);

        if let Some(ptr) = self.try_allocate_from_node(layout, target_node) {
            if let Some(node) = self.get_node(target_node) {
                node.stats.record_allocation(layout.size());
            }
            return Some((ptr, target_node));
        }

        let node_count = self.node_count();
        for fallback_node in 0..node_count {
            if fallback_node == target_node {
                continue;
            }
            if let Some(ptr) = self.try_allocate_from_node(layout, fallback_node) {
                if let Some(node) = self.get_node(fallback_node) {
                    node.stats.record_allocation(layout.size());
                    node.stats.record_fallback();
                }
                log::trace!(
                    "[NUMA] Fallback allocation: requested node {} -> actual node {}",
                    target_node,
                    fallback_node
                );
                return Some((ptr, fallback_node));
            }
        }

        crate::util::allocate_zeroed(layout).map(|ptr| {
            log::trace!("[NUMA] Global fallback allocation for node {}", target_node);
            (ptr, target_node)
        })
    }

    fn try_allocate_from_node(&self, layout: Layout, _node_id: usize) -> Option<NonNull<u8>> {
        crate::util::allocate_zeroed(layout)
    }

    pub fn deallocate(&self, ptr: NonNull<u8>, layout: Layout, node_hint: Option<usize>) {
        let node_id = node_hint.unwrap_or(0);
        if let Some(node) = self.get_node(node_id) {
            node.stats.record_deallocation(layout.size());
        }
        unsafe { alloc::alloc::dealloc(ptr.as_ptr(), layout) }
    }
}

/// グローバルNUMAアロケータインスタンス
static NUMA_ALLOCATOR: PoisonLock<NumaAllocator> = PoisonLock::new(NumaAllocator::new());

pub fn init_numa_allocator() {
    let mut allocator = NUMA_ALLOCATOR.lock().unwrap_or_else(|e| e.into_inner());
    let num_nodes = with_cpu_locality(|topology| topology.node_count);

    for node_id in 0..num_nodes {
        let mut node = NumaNode::new(NumaNodeId::new(node_id as u8));
        with_cpu_locality(|topology| {
            for &cpu in topology.cores_in_node(node_id) {
                node.add_cpu(cpu as u8);
            }
        });

        allocator.register_node(node);
    }

    allocator.mark_initialized();
    log::info!("[NUMA] Initialized with {} nodes", num_nodes);
}

// ============================================================================
// Public API
// ============================================================================

pub fn num_nodes() -> usize {
    with_cpu_locality(|topology| topology.node_count)
}

pub fn current_node() -> usize {
    if let Some(cpu) = crate::per_cpu::try_current_cpu_id() {
        node_for_cpu(cpu)
    } else {
        0
    }
}

pub fn allocate_zeroed_on_node(layout: Layout, node: Option<usize>) -> Option<NonNull<u8>> {
    let allocator = NUMA_ALLOCATOR.lock().unwrap_or_else(|e| e.into_inner());
    if allocator.is_initialized() {
        allocator.allocate(layout, node).map(|(ptr, _)| ptr)
    } else {
        crate::util::allocate_zeroed(layout)
    }
}

pub fn allocate_zeroed_on_node_with_info(
    layout: Layout,
    node: Option<usize>,
) -> Option<(NonNull<u8>, usize)> {
    let allocator = NUMA_ALLOCATOR.lock().unwrap_or_else(|e| e.into_inner());
    if allocator.is_initialized() {
        allocator.allocate(layout, node)
    } else {
        crate::util::allocate_zeroed(layout).map(|ptr| (ptr, 0))
    }
}

pub fn deallocate_on_node(ptr: NonNull<u8>, layout: Layout, node: Option<usize>) {
    let allocator = NUMA_ALLOCATOR.lock().unwrap_or_else(|e| e.into_inner());
    if allocator.is_initialized() {
        allocator.deallocate(ptr, layout, node);
    } else {
        unsafe { alloc::alloc::dealloc(ptr.as_ptr(), layout) }
    }
}

pub fn get_node_stats(node_id: usize) -> Option<(u64, u64, u64)> {
    let allocator = NUMA_ALLOCATOR.lock().unwrap_or_else(|e| e.into_inner());
    allocator.get_node(node_id).map(|node| {
        (
            node.stats.allocations.load(Ordering::Relaxed),
            node.stats.used_bytes.load(Ordering::Relaxed),
            node.stats.fallback_count.load(Ordering::Relaxed),
        )
    })
}

pub fn get_total_stats() -> (u64, u64, u64) {
    let allocator = NUMA_ALLOCATOR.lock().unwrap_or_else(|e| e.into_inner());
    let mut total_allocs = 0u64;
    let mut total_used = 0u64;
    let mut total_fallbacks = 0u64;

    for node_id in 0..allocator.node_count() {
        if let Some(node) = allocator.get_node(node_id) {
            total_allocs += node.stats.allocations.load(Ordering::Relaxed);
            total_used += node.stats.used_bytes.load(Ordering::Relaxed);
            total_fallbacks += node.stats.fallback_count.load(Ordering::Relaxed);
        }
    }

    (total_allocs, total_used, total_fallbacks)
}

// ============================================================================
// RCU-Protected NUMA Topology Access
// ============================================================================

use crate::mm::sync::rcu::{RcuReadGuard, rcu_read_lock};

#[inline]
pub fn numa_node_count_rcu() -> usize {
    NUMA_ALLOCATOR_NODE_COUNT.load(Ordering::Acquire)
}

static NUMA_ALLOCATOR_NODE_COUNT: AtomicUsize = AtomicUsize::new(1);

pub fn update_numa_node_count(count: usize) {
    NUMA_ALLOCATOR_NODE_COUNT.store(count, Ordering::Release);
}

#[inline]
pub fn cpu_to_node_rcu(cpu_id: usize) -> Option<u8> {
    if cpu_id < CPU_TO_NODE_MAP.len() {
        let node = CPU_TO_NODE_MAP[cpu_id].load(Ordering::Acquire);
        if node != u8::MAX {
            return Some(node);
        }
    }
    None
}

static CPU_TO_NODE_MAP: [core::sync::atomic::AtomicU8; 256] = {
    const INIT: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(u8::MAX);
    [INIT; 256]
};

pub fn set_cpu_to_node(cpu_id: usize, node_id: u8) {
    if cpu_id < CPU_TO_NODE_MAP.len() {
        CPU_TO_NODE_MAP[cpu_id].store(node_id, Ordering::Release);
    }
}

#[inline]
pub fn current_numa_node_fast() -> Option<u8> {
    if let Some(cpu_id) = crate::per_cpu::try_current_cpu_id() {
        cpu_to_node_rcu(cpu_id)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reset_cpu_locality_for_tests() {
        *CPU_LOCALITY_TOPOLOGY
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        for entry in &CPU_TO_NODE_MAP {
            entry.store(u8::MAX, Ordering::Relaxed);
        }
        update_numa_node_count(1);
    }

    fn numa_info_with_nodes(masks: &[(u64, u64)]) -> NumaInfo {
        let mut info = NumaInfo::default();
        info.node_count = masks.len() as u8;
        for (node_idx, (low, high)) in masks.iter().copied().enumerate() {
            info.nodes[node_idx].cpu_apic_mask_low = low;
            info.nodes[node_idx].cpu_apic_mask_high = high;
        }
        info
    }

    #[test_case]
    fn boot_info_topology_maps_apic_masks_to_registered_cpus() {
        crate::smp::reset_cpu_routing_for_tests();
        reset_cpu_locality_for_tests();
        crate::smp::register_cpu_apic_mapping(0, 2);
        crate::smp::register_cpu_apic_mapping(1, 9);
        crate::smp::register_cpu_apic_mapping(2, 41);
        crate::smp::register_cpu_apic_mapping(3, 44);

        let topology = CpuLocalityTopology::from_boot_info(
            &numa_info_with_nodes(&[
                ((1u64 << 2) | (1u64 << 9), 0),
                ((1u64 << 41) | (1u64 << 44), 0),
            ]),
            4,
        );

        assert_eq!(topology.node_for_cpu(0), 0);
        assert_eq!(topology.node_for_cpu(1), 0);
        assert_eq!(topology.node_for_cpu(2), 1);
        assert_eq!(topology.node_for_cpu(3), 1);
    }

    #[test_case]
    fn steal_candidates_prefer_same_node_before_remote_nodes() {
        crate::smp::reset_cpu_routing_for_tests();
        reset_cpu_locality_for_tests();
        crate::smp::register_cpu_apic_mapping(0, 2);
        crate::smp::register_cpu_apic_mapping(1, 9);
        crate::smp::register_cpu_apic_mapping(2, 41);
        crate::smp::register_cpu_apic_mapping(3, 44);

        let topology = CpuLocalityTopology::from_boot_info(
            &numa_info_with_nodes(&[
                ((1u64 << 2) | (1u64 << 9), 0),
                ((1u64 << 41) | (1u64 << 44), 0),
            ]),
            4,
        );
        publish_cpu_locality(&topology);
        *CPU_LOCALITY_TOPOLOGY
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(topology);

        assert_eq!(steal_candidates_for_cpu(0), alloc::vec![1, 2, 3]);
        assert_eq!(steal_candidates_for_cpu(2), alloc::vec![3, 0, 1]);
    }

    #[test_case]
    fn apply_current_cpu_locality_updates_per_cpu_cold_state() {
        crate::smp::reset_cpu_routing_for_tests();
        reset_cpu_locality_for_tests();
        crate::smp::register_cpu_apic_mapping(0, 2);

        configure_from_boot_info(&numa_info_with_nodes(&[(0, 0), (1u64 << 2, 0)]));
        apply_current_cpu_locality();

        assert_eq!(node_for_cpu(0), 1);
        assert_eq!(cpu_to_node_rcu(0), Some(1));
        assert_eq!(
            crate::per_cpu::with_current_cold(|cold| cold.get_local_numa_node().as_u8()),
            Some(1)
        );
    }
}

pub fn with_numa_topology_rcu<F, R>(f: F) -> R
where
    F: FnOnce(&RcuReadGuard) -> R,
{
    let guard = rcu_read_lock();
    f(&guard)
}
