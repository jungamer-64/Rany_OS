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
use alloc::alloc::Layout;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

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
    update_numa_node_count(topology.node_cpus.len());

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
    publish_cpu_locality(topology);
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
    let assignments = topology
        .cpu_to_node
        .iter()
        .map(|(&cpu_id, &node_id)| (cpu_id, node_id))
        .collect::<Vec<_>>();
    crate::mm::phys::frame_allocator::configure_numa_cpu_affinity(
        snapshot.possible().capacity(),
        &assignments,
    )?;
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
    let node_count = with_cpu_locality(|topology| topology.node_cpus.len());
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

pub fn node_for_cpu(cpu_id: CpuId) -> Option<NumaNodeId> {
    with_cpu_locality(|topology| topology.node_for_cpu(cpu_id))
}

pub fn steal_candidates_for_cpu(cpu_id: CpuId) -> Vec<CpuId> {
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
    pub memory_ranges: Vec<(u64, u64)>,
    /// 有効なメモリ範囲数
    /// このノードに属するCPUコアのビットマスク
    pub cpus: crate::cpu::CpuSet,
    /// 総メモリサイズ（バイト）
    pub total_memory: u64,
    /// 統計情報
    pub stats: NumaNodeStats,
}

impl NumaNode {
    /// 空のNUMAノードを作成
    pub fn new(id: NumaNodeId, cpu_capacity: usize) -> Self {
        Self {
            id,
            memory_ranges: Vec::new(),
            cpus: crate::cpu::CpuSet::new(cpu_capacity)
                .expect("CPU runtime capacity is bounded by CpuId"),
            total_memory: 0,
            stats: NumaNodeStats::new(),
        }
    }

    /// メモリ範囲を追加
    pub fn add_memory_range(&mut self, start: u64, size: u64) {
        self.memory_ranges.push((start, size));
        self.total_memory += size;
    }

    /// CPUコアを追加
    pub fn add_cpu(&mut self, cpu_id: CpuId) {
        self.cpus
            .insert(cpu_id)
            .expect("CPU slot must fit the node topology capacity");
    }

    /// 指定アドレスがこのノードに属するか判定
    pub fn contains_address(&self, addr: u64) -> bool {
        for &(start, size) in &self.memory_ranges {
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
    pub fn new(cpu_capacity: usize) -> Self {
        let nodes =
            core::array::from_fn(|index| NumaNode::new(NumaNodeId::new(index as u8), cpu_capacity));

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

    pub fn cpu_to_node(&self, cpu_id: CpuId) -> NumaNodeId {
        for i in 0..self.node_count {
            if self.nodes[i].cpus.contains(cpu_id) {
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
    let num_nodes = with_cpu_locality(|topology| topology.node_cpus.len());

    for node_id in 0..num_nodes {
        let mut node = NumaNode::new(
            NumaNodeId::new(node_id as u8),
            crate::cpu::snapshot().possible().capacity(),
        );
        with_cpu_locality(|topology| {
            for &cpu in topology.cpus_in_node(NumaNodeId::new(node_id as u8)) {
                node.add_cpu(cpu);
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
    with_cpu_locality(|topology| topology.node_cpus.len())
}

pub fn current_node() -> usize {
    crate::cpu::CurrentCpu::acquire()
        .and_then(|cpu| node_for_cpu(cpu.id()))
        .map(NumaNodeId::as_usize)
        .unwrap_or(0)
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
