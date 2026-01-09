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

use alloc::alloc::Layout;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::Mutex;

use super::types::NumaNodeId;
use crate::task::work_stealing_advanced::NumaTopology as SchedulerNumaTopology;

/// 最大NUMAノード数
pub const MAX_NUMA_NODES: usize = 8;

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
/// 設計書 5.3.1: 起動時にACPI SRATから検出
pub struct NumaTopology {
    /// 各NUMAノードの情報
    pub(crate) nodes: [NumaNode; MAX_NUMA_NODES],
    /// 有効なノード数
    pub(crate) node_count: usize,
    /// ノード間距離行列（キャッシュライン考慮）
    /// 値が大きいほど遠い（レイテンシが高い）
    distance_matrix: [[u8; MAX_NUMA_NODES]; MAX_NUMA_NODES],
    /// プリコンピュートされた距離順ノードリスト
    /// distance_cache[from_node] = 距離順にソートされたノードID配列
    distance_cache: [[NumaNodeId; MAX_NUMA_NODES]; MAX_NUMA_NODES],
    /// 距離キャッシュが初期化済みか
    distance_cache_valid: bool,
}

impl NumaTopology {
    /// 空のトポロジを作成（シングルノードとして初期化）
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

        // デフォルトの距離行列（ローカル=10、リモート=20）
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

        // デフォルトの距離キャッシュ（自ノードが最初、他は番号順）
        let distance_cache = [
            [NumaNodeId::new(0), NumaNodeId::new(1), NumaNodeId::new(2), NumaNodeId::new(3),
             NumaNodeId::new(4), NumaNodeId::new(5), NumaNodeId::new(6), NumaNodeId::new(7)],
            [NumaNodeId::new(1), NumaNodeId::new(0), NumaNodeId::new(2), NumaNodeId::new(3),
             NumaNodeId::new(4), NumaNodeId::new(5), NumaNodeId::new(6), NumaNodeId::new(7)],
            [NumaNodeId::new(2), NumaNodeId::new(0), NumaNodeId::new(1), NumaNodeId::new(3),
             NumaNodeId::new(4), NumaNodeId::new(5), NumaNodeId::new(6), NumaNodeId::new(7)],
            [NumaNodeId::new(3), NumaNodeId::new(0), NumaNodeId::new(1), NumaNodeId::new(2),
             NumaNodeId::new(4), NumaNodeId::new(5), NumaNodeId::new(6), NumaNodeId::new(7)],
            [NumaNodeId::new(4), NumaNodeId::new(0), NumaNodeId::new(1), NumaNodeId::new(2),
             NumaNodeId::new(3), NumaNodeId::new(5), NumaNodeId::new(6), NumaNodeId::new(7)],
            [NumaNodeId::new(5), NumaNodeId::new(0), NumaNodeId::new(1), NumaNodeId::new(2),
             NumaNodeId::new(3), NumaNodeId::new(4), NumaNodeId::new(6), NumaNodeId::new(7)],
            [NumaNodeId::new(6), NumaNodeId::new(0), NumaNodeId::new(1), NumaNodeId::new(2),
             NumaNodeId::new(3), NumaNodeId::new(4), NumaNodeId::new(5), NumaNodeId::new(7)],
            [NumaNodeId::new(7), NumaNodeId::new(0), NumaNodeId::new(1), NumaNodeId::new(2),
             NumaNodeId::new(3), NumaNodeId::new(4), NumaNodeId::new(5), NumaNodeId::new(6)],
        ];

        Self {
            nodes,
            node_count: 1, // デフォルトは1ノード
            distance_matrix,
            distance_cache,
            distance_cache_valid: false,
        }
    }

    /// 距離キャッシュを事前計算（起動時に一度だけ呼び出し）
    ///
    /// 各ノードからの距離順にノードをソートしてキャッシュに格納。
    /// これにより `nodes_by_distance()` が O(1) で動作する。
    pub fn precompute_distance_cache(&mut self) {
        for from in 0..self.node_count {
            // (node_id, distance) のペアを作成
            let mut pairs: [(usize, u8); MAX_NUMA_NODES] = [(0, 255); MAX_NUMA_NODES];
            for to in 0..self.node_count {
                pairs[to] = (to, self.distance_matrix[from][to]);
            }

            // 距離でソート（insertion sort、小配列なので十分）
            for i in 1..self.node_count {
                let mut j = i;
                while j > 0 && pairs[j - 1].1 > pairs[j].1 {
                    pairs.swap(j - 1, j);
                    j -= 1;
                }
            }

            // 結果をキャッシュに格納
            for (i, &(node_idx, _)) in pairs.iter().enumerate().take(MAX_NUMA_NODES) {
                self.distance_cache[from][i] = NumaNodeId::new(node_idx as u8);
            }
        }

        self.distance_cache_valid = true;
    }

    /// ノード数を取得
    #[inline]
    pub fn node_count(&self) -> usize {
        self.node_count
    }

    /// ノード情報を取得
    pub fn get_node(&self, id: NumaNodeId) -> Option<&NumaNode> {
        let idx = id.as_usize();
        if idx < self.node_count {
            Some(&self.nodes[idx])
        } else {
            None
        }
    }

    /// CPUコアが属するNUMAノードを取得
    pub fn cpu_to_node(&self, cpu_id: u8) -> NumaNodeId {
        for i in 0..self.node_count {
            if (self.nodes[i].cpu_mask & (1u64 << cpu_id)) != 0 {
                return NumaNodeId::new(i as u8);
            }
        }
        // 見つからない場合はノード0
        NumaNodeId::new(0)
    }

    /// 物理アドレスが属するNUMAノードを取得
    pub fn addr_to_node(&self, addr: u64) -> NumaNodeId {
        for i in 0..self.node_count {
            if self.nodes[i].contains_address(addr) {
                return NumaNodeId::new(i as u8);
            }
        }
        NumaNodeId::new(0)
    }

    /// ノード間の距離を取得
    #[inline]
    pub fn distance(&self, from: NumaNodeId, to: NumaNodeId) -> u8 {
        self.distance_matrix[from.as_usize()][to.as_usize()]
    }

    /// 指定ノードからの優先順位でノードをソート
    /// 近いノードが先頭に来る
    ///
    /// ## 最適化
    ///
    /// `precompute_distance_cache()` が呼ばれていれば O(1) で返却。
    /// キャッシュ無効時はフォールバックでソートを実行。
    #[inline]
    pub fn nodes_by_distance(&self, from: NumaNodeId) -> [NumaNodeId; MAX_NUMA_NODES] {
        // 高速パス: プリコンピュート済みキャッシュを返す
        if self.distance_cache_valid {
            return self.distance_cache[from.as_usize()];
        }

        // フォールバック: 動的にソート（起動初期のみ）
        self.compute_nodes_by_distance_slow(from)
    }

    /// 動的に距離順ソートを実行（フォールバック用）
    fn compute_nodes_by_distance_slow(&self, from: NumaNodeId) -> [NumaNodeId; MAX_NUMA_NODES] {
        let mut result = [NumaNodeId::new(0); MAX_NUMA_NODES];
        let mut indices: [usize; MAX_NUMA_NODES] = [0, 1, 2, 3, 4, 5, 6, 7];

        // 距離でソート（バブルソート）
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
///
/// 設計書 5.3.2: NUMA-Awareメモリアロケータ
pub struct NumaAllocator {
    /// 各NUMAノードの情報
    nodes: [Option<NumaNode>; MAX_NUMA_NODES],
    /// 有効なNUMAノード数
    node_count: AtomicUsize,
    /// 初期化完了フラグ
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

    /// NUMAノードを登録
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

    /// 初期化完了をマーク
    pub fn mark_initialized(&self) {
        self.initialized.store(1, Ordering::Release);
    }

    /// 初期化が完了しているかチェック
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire) != 0
    }

    /// ノード数を取得
    pub fn node_count(&self) -> usize {
        self.node_count.load(Ordering::Acquire)
    }

    /// 指定ノードの情報を取得
    pub fn get_node(&self, node_id: usize) -> Option<&NumaNode> {
        if node_id < MAX_NUMA_NODES {
            self.nodes[node_id].as_ref()
        } else {
            None
        }
    }

    /// 指定ノードからメモリを割り当て
    ///
    /// # Arguments
    /// * `layout` - 割り当てるメモリのレイアウト
    /// * `preferred_node` - 優先するNUMAノード（Noneの場合は現在のCPUのノード）
    ///
    /// # Returns
    /// 割り当てられたメモリへのポインタと実際のノードID
    pub fn allocate(&self, layout: Layout, preferred_node: Option<usize>) -> Option<(NonNull<u8>, usize)> {
        let target_node = preferred_node.unwrap_or_else(current_node);
        
        // 1. 優先ノードから割り当てを試みる
        if let Some(ptr) = self.try_allocate_from_node(layout, target_node) {
            if let Some(node) = self.get_node(target_node) {
                node.stats.record_allocation(layout.size());
            }
            return Some((ptr, target_node));
        }

        // 2. フォールバック: 他のノードから割り当て
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

        // 3. 最終フォールバック: グローバルアロケータ
        crate::util::allocate_zeroed(layout).map(|ptr| {
            log::trace!("[NUMA] Global fallback allocation for node {}", target_node);
            (ptr, target_node)
        })
    }

    /// 特定ノードからの割り当てを試みる（内部用）
    fn try_allocate_from_node(&self, layout: Layout, _node_id: usize) -> Option<NonNull<u8>> {
        // TODO: 実際のNUMA対応Buddyアロケータとの統合
        // 現在はグローバルアロケータへのフォールバック
        // 将来的には各ノードごとのBuddyアロケータインスタンスを使用
        crate::util::allocate_zeroed(layout)
    }

    /// メモリを解放
    pub fn deallocate(&self, ptr: NonNull<u8>, layout: Layout, node_hint: Option<usize>) {
        let node_id = node_hint.unwrap_or(0);
        if let Some(node) = self.get_node(node_id) {
            node.stats.record_deallocation(layout.size());
        }
        unsafe { alloc::alloc::dealloc(ptr.as_ptr(), layout) }
    }
}

/// グローバルNUMAアロケータインスタンス
static NUMA_ALLOCATOR: Mutex<NumaAllocator> = Mutex::new(NumaAllocator::new());

/// NUMAアロケータを初期化
///
/// ACPI SRATテーブルからNUMAトポロジを検出し、ノードを登録する
pub fn init_numa_allocator() {
    let mut allocator = NUMA_ALLOCATOR.lock();
    
    // NumaTopologyから情報を取得
    let topology = SchedulerNumaTopology::get();
    let num_nodes = topology.num_nodes();
    
    for node_id in 0..num_nodes {
        let mut node = NumaNode::new(NumaNodeId::new(node_id as u8));
        
        // このノードに属するCPUコアを登録
        for &cpu in topology.get_cores_in_node(node_id) {
            node.add_cpu(cpu as u8);
        }
        
        allocator.register_node(node);
    }
    
    allocator.mark_initialized();
    log::info!("[NUMA] Initialized with {} nodes", num_nodes);
}

// ============================================================================
// Public API
// ============================================================================

/// Return the number of NUMA nodes in the system (1 for single-node)
pub fn num_nodes() -> usize {
    SchedulerNumaTopology::get().num_nodes()
}

/// Return the NUMA node for the current CPU if available
pub fn current_node() -> usize {
    if let Some(cpu) = crate::mm::per_cpu::try_current_cpu_id() {
        SchedulerNumaTopology::get()
            .get_numa_node(cpu as u32)
    } else {
        0
    }
}

/// Allocate a zeroed block with an optional NUMA node hint.
///
/// # 設計書 5.3.2: NUMA-Awareメモリアロケータ
///
/// デフォルトでは「そのタスクが実行中のCPUコアが属するNUMAノード」からメモリを割り当てます。
/// 明示的にノードを指定することも可能です。
///
/// # Arguments
/// * `layout` - 割り当てるメモリのレイアウト
/// * `node` - 優先するNUMAノード（Noneの場合は現在のCPUのノード）
///
/// # Returns
/// 割り当てられたメモリへのポインタ（失敗時はNone）
pub fn allocate_zeroed_on_node(layout: Layout, node: Option<usize>) -> Option<NonNull<u8>> {
    crate::io::log::early_print("[NUMA] allocate_zeroed_on_node size=");
    crate::io::log::early_print_dec(layout.size() as u64);
    crate::io::log::early_print("\n");
    let allocator = NUMA_ALLOCATOR.lock();
    if allocator.is_initialized() {
        allocator.allocate(layout, node).map(|(ptr, _)| ptr)
    } else {
        // 初期化前はグローバルアロケータを使用
        crate::util::allocate_zeroed(layout)
    }
}

/// Allocate a zeroed block and return the actual NUMA node used.
///
/// This is useful for tracking memory locality.
pub fn allocate_zeroed_on_node_with_info(
    layout: Layout,
    node: Option<usize>,
) -> Option<(NonNull<u8>, usize)> {
    let allocator = NUMA_ALLOCATOR.lock();
    if allocator.is_initialized() {
        allocator.allocate(layout, node)
    } else {
        crate::util::allocate_zeroed(layout).map(|ptr| (ptr, 0))
    }
}

/// Deallocate a block previously returned by `allocate_zeroed_on_node`.
pub fn deallocate_on_node(ptr: NonNull<u8>, layout: Layout, node: Option<usize>) {
    let allocator = NUMA_ALLOCATOR.lock();
    if allocator.is_initialized() {
        allocator.deallocate(ptr, layout, node);
    } else {
        unsafe { alloc::alloc::dealloc(ptr.as_ptr(), layout) }
    }
}

/// Get NUMA statistics for a specific node
pub fn get_node_stats(node_id: usize) -> Option<(u64, u64, u64)> {
    let allocator = NUMA_ALLOCATOR.lock();
    allocator.get_node(node_id).map(|node| {
        (
            node.stats.allocations.load(Ordering::Relaxed),
            node.stats.used_bytes.load(Ordering::Relaxed),
            node.stats.fallback_count.load(Ordering::Relaxed),
        )
    })
}

/// Get total NUMA statistics across all nodes
pub fn get_total_stats() -> (u64, u64, u64) {
    let allocator = NUMA_ALLOCATOR.lock();
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
//
// NUMAトポロジ情報は頻繁に参照されるが、更新は稀（ホットプラグ時のみ）。
// RCUを使用することで、参照側はロックフリーになり、
// ページフォールト処理などのクリティカルパスでの性能が向上する。
//
// ============================================================================

use super::rcu::{rcu_read_lock, RcuReadGuard};

/// RCU保護されたNUMAノード数の読み取り
///
/// ロックを取らずにノード数を取得する。
/// ホットプラグによる更新中でも安全に読み取れる。
#[inline]
pub fn numa_node_count_rcu() -> usize {
    // NUMA_ALLOCATOR.node_count は AtomicUsize なので
    // ロックなしで読み取り可能
    NUMA_ALLOCATOR_NODE_COUNT.load(Ordering::Acquire)
}

/// グローバルなノード数（ロックフリー参照用）
static NUMA_ALLOCATOR_NODE_COUNT: AtomicUsize = AtomicUsize::new(1);

/// ノード数を更新（初期化時に呼び出す）
pub fn update_numa_node_count(count: usize) {
    NUMA_ALLOCATOR_NODE_COUNT.store(count, Ordering::Release);
}

/// RCU保護されたCPU→ノードマッピングの読み取り
///
/// 指定されたCPU IDが属するNUMAノードIDを返す。
/// ロックフリーで高速。
#[inline]
pub fn cpu_to_node_rcu(cpu_id: usize) -> Option<u8> {
    // 事前に構築されたマッピングテーブルを参照
    if cpu_id < CPU_TO_NODE_MAP.len() {
        let node = CPU_TO_NODE_MAP[cpu_id].load(Ordering::Acquire);
        if node != u8::MAX {
            return Some(node);
        }
    }
    None
}

/// CPU→ノードマッピングテーブル（ロックフリー参照用）
/// u8::MAX = 未設定
static CPU_TO_NODE_MAP: [core::sync::atomic::AtomicU8; 256] = {
    const INIT: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(u8::MAX);
    [INIT; 256]
};

/// CPU→ノードマッピングを更新
pub fn set_cpu_to_node(cpu_id: usize, node_id: u8) {
    if cpu_id < CPU_TO_NODE_MAP.len() {
        CPU_TO_NODE_MAP[cpu_id].store(node_id, Ordering::Release);
    }
}

/// 現在のCPUのNUMAノードIDをロックフリーで取得
///
/// GsBaseからCPU IDを取得し、マッピングテーブルを参照。
/// ページフォールトハンドラなどの高頻度パスで使用。
#[inline]
pub fn current_numa_node_fast() -> Option<u8> {
    if let Some(cpu_id) = crate::mm::per_cpu::try_current_cpu_id() {
        cpu_to_node_rcu(cpu_id)
    } else {
        None
    }
}

/// RCU読み取りセクション内でNUMAトポロジを参照
///
/// 複数の読み取りを行う場合、一度だけrcu_read_lockを取得し、
/// そのガード内で全ての読み取りを行うことで効率化。
///
/// # Example
/// ```ignore
/// let topology = with_numa_topology_rcu(|guard| {
///     let node_count = numa_node_count_rcu();
///     let my_node = current_numa_node_fast();
///     (node_count, my_node)
/// });
/// ```
pub fn with_numa_topology_rcu<F, R>(f: F) -> R
where
    F: FnOnce(&RcuReadGuard) -> R,
{
    let guard = rcu_read_lock();
    f(&guard)
}
