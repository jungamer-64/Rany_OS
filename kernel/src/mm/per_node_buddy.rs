// ============================================================================
// src/mm/per_node_buddy.rs - Per-NUMA-Node Buddy Allocator
//
// 各NUMAノードごとに独立したBuddyアロケータを持つことで、
// ノード間のロック競合を排除し、スケーラビリティを向上させる。
//
// ## 設計
//
// - 各ノードは独自のIrqMutexで保護されたBuddyFrameAllocatorを持つ
// - CPUは自ノードのアロケータを優先的に使用
// - メモリ不足時のみ他ノードにフォールバック
// - ノード間のロック競合がゼロになる
//
// ## 階層構造
//
// 1. Per-CPU Frame Magazine (L1) - ロックフリー、Order 0専用
// 2. Per-Node Buddy Allocator (L2) - ノードローカルロック
// 3. Remote Node Fallback (L3) - 他ノードからの借用
// ============================================================================
#![allow(dead_code)]

use crate::sync::IrqMutex;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use x86_64::structures::paging::{PhysFrame, Size4KiB, Size2MiB, Size1GiB};
use x86_64::PhysAddr;

use super::buddy_allocator::{BuddyFrameAllocator, BuddyAllocatorStats, MAX_ORDER};
use super::types::NumaNodeId;
use super::numa::MAX_NUMA_NODES;

// ============================================================================
// Per-Node Allocator Statistics
// ============================================================================

/// Per-Node統計
#[derive(Debug, Default)]
pub struct PerNodeStats {
    /// ローカル割り当て成功数
    pub local_allocs: AtomicU64,
    /// リモートフォールバック数
    pub remote_fallbacks: AtomicU64,
    /// 割り当て失敗数
    pub alloc_failures: AtomicU64,
    /// 解放数
    pub deallocs: AtomicU64,
}

impl PerNodeStats {
    pub const fn new() -> Self {
        Self {
            local_allocs: AtomicU64::new(0),
            remote_fallbacks: AtomicU64::new(0),
            alloc_failures: AtomicU64::new(0),
            deallocs: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// Per-Node Buddy Allocator Wrapper
// ============================================================================

/// ノードごとのBuddyアロケータラッパー
pub struct NodeBuddyAllocator {
    /// Buddyアロケータ本体
    allocator: IrqMutex<BuddyFrameAllocator>,
    /// ノードID
    node_id: NumaNodeId,
    /// 初期化済みフラグ
    initialized: AtomicBool,
    /// 統計情報
    stats: PerNodeStats,
}

impl NodeBuddyAllocator {
    /// 新しいノードアロケータを作成
    pub const fn new(node_id: u8) -> Self {
        Self {
            allocator: IrqMutex::new(BuddyFrameAllocator::new()),
            node_id: NumaNodeId::new(node_id),
            initialized: AtomicBool::new(false),
            stats: PerNodeStats::new(),
        }
    }

    /// メモリ領域を登録して初期化
    ///
    /// # Safety
    /// - 指定された領域が有効で、他のアロケータと重複しないこと
    pub unsafe fn init(&self, regions: &[(PhysAddr, u64)]) {
        if self.initialized.load(Ordering::Acquire) {
            return; // 既に初期化済み
        }

        let mut allocator = self.allocator.lock();
        unsafe {
            allocator.init(regions);
        }
        self.initialized.store(true, Ordering::Release);
    }

    /// このノードが初期化済みかどうか
    #[inline]
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }

    /// 4KiBフレームを割り当て
    pub fn allocate_4k(&self) -> Option<PhysFrame<Size4KiB>> {
        if !self.is_initialized() {
            return None;
        }
        
        let result = self.allocator.lock().allocate_4k_frame();
        if result.is_some() {
            self.stats.local_allocs.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// 2MiBフレームを割り当て
    pub fn allocate_2m(&self) -> Option<PhysFrame<Size2MiB>> {
        if !self.is_initialized() {
            return None;
        }
        
        let result = self.allocator.lock().allocate_2m_frame();
        if result.is_some() {
            self.stats.local_allocs.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// 1GiBフレームを割り当て
    pub fn allocate_1g(&self) -> Option<PhysFrame<Size1GiB>> {
        if !self.is_initialized() {
            return None;
        }
        
        let result = self.allocator.lock().allocate_1g_frame();
        if result.is_some() {
            self.stats.local_allocs.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// 4KiBフレームを解放
    pub fn deallocate_4k(&self, frame: PhysFrame<Size4KiB>) {
        if !self.is_initialized() {
            return;
        }
        
        self.allocator.lock().deallocate_4k_frame(frame);
        self.stats.deallocs.fetch_add(1, Ordering::Relaxed);
    }

    /// 2MiBフレームを解放
    pub fn deallocate_2m(&self, frame: PhysFrame<Size2MiB>) {
        if !self.is_initialized() {
            return;
        }
        
        self.allocator.lock().deallocate_2m_frame(frame);
        self.stats.deallocs.fetch_add(1, Ordering::Relaxed);
    }

    /// 1GiBフレームを解放
    pub fn deallocate_1g(&self, frame: PhysFrame<Size1GiB>) {
        if !self.is_initialized() {
            return;
        }
        
        self.allocator.lock().deallocate_1g_frame(frame);
        self.stats.deallocs.fetch_add(1, Ordering::Relaxed);
    }

    /// 統計情報を取得
    pub fn stats(&self) -> BuddyAllocatorStats {
        if !self.is_initialized() {
            return BuddyAllocatorStats {
                total_frames: 0,
                free_frames: 0,
                split_count: 0,
                coalesce_count: 0,
                order_stats: [(0, 0); MAX_ORDER + 1],
            };
        }
        self.allocator.lock().stats()
    }

    /// ノードIDを取得
    #[inline]
    pub fn node_id(&self) -> NumaNodeId {
        self.node_id
    }

    /// 空きフレーム数を取得
    pub fn free_frames(&self) -> u64 {
        if !self.is_initialized() {
            return 0;
        }
        self.allocator.lock().stats().free_frames
    }
}

// ============================================================================
// Global Per-Node Allocator Array
// ============================================================================

/// 各NUMAノードのBuddyアロケータ
static PER_NODE_ALLOCATORS: [NodeBuddyAllocator; MAX_NUMA_NODES] = [
    NodeBuddyAllocator::new(0),
    NodeBuddyAllocator::new(1),
    NodeBuddyAllocator::new(2),
    NodeBuddyAllocator::new(3),
    NodeBuddyAllocator::new(4),
    NodeBuddyAllocator::new(5),
    NodeBuddyAllocator::new(6),
    NodeBuddyAllocator::new(7),
];

/// グローバル初期化フラグ
static INITIALIZED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Public API
// ============================================================================

/// Per-Node Buddyアロケータを初期化
///
/// # Safety
/// - カーネル初期化時に一度だけ呼ばれること
/// - regions_by_nodeは各ノードの有効なメモリ領域を示すこと
pub unsafe fn init_per_node_allocators(regions_by_node: &[Vec<(PhysAddr, u64)>]) {
    for (node_id, regions) in regions_by_node.iter().enumerate() {
        if node_id >= MAX_NUMA_NODES || regions.is_empty() {
            continue;
        }
        
        unsafe {
            PER_NODE_ALLOCATORS[node_id].init(regions);
        }
        log::info!(
            "[PerNodeBuddy] Node {} initialized with {} regions",
            node_id,
            regions.len()
        );
    }
    
    INITIALIZED.store(true, Ordering::Release);
}

/// Per-Node Buddyが初期化済みかどうか
#[inline]
pub fn is_per_node_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

/// 指定ノードのアロケータを取得
#[inline]
pub fn get_node_allocator(node: NumaNodeId) -> Option<&'static NodeBuddyAllocator> {
    let idx = node.as_usize();
    if idx < MAX_NUMA_NODES && PER_NODE_ALLOCATORS[idx].is_initialized() {
        Some(&PER_NODE_ALLOCATORS[idx])
    } else {
        None
    }
}

/// 4KiBフレームを割り当て（ローカルノード優先）
///
/// # フォールバック順序
/// 1. 現在のCPUのローカルノード
/// 2. 距離順で近いノード
/// 3. グローバルBuddyアロケータ
pub fn alloc_frame_local_first() -> Option<PhysFrame<Size4KiB>> {
    if !is_per_node_initialized() {
        // Per-Node未初期化時はグローバルにフォールバック
        return super::buddy_allocator::buddy_alloc_frame();
    }

    // 1. ローカルノードを試行
    let local_node = super::numa::current_node();
    if let Some(allocator) = get_node_allocator(NumaNodeId::new(local_node as u8)) {
        if let Some(frame) = allocator.allocate_4k() {
            return Some(frame);
        }
    }

    // 2. 他ノードをフォールバック（距離順にするべきだがここでは単純にループ）
    for node_id in 0..MAX_NUMA_NODES {
        if node_id == local_node {
            continue;
        }
        if let Some(allocator) = get_node_allocator(NumaNodeId::new(node_id as u8)) {
            if let Some(frame) = allocator.allocate_4k() {
                allocator.stats.remote_fallbacks.fetch_add(1, Ordering::Relaxed);
                return Some(frame);
            }
        }
    }

    // 3. グローバルにフォールバック
    super::buddy_allocator::buddy_alloc_frame()
}

/// 指定ノードから4KiBフレームを割り当て
pub fn alloc_frame_on_node(node: NumaNodeId) -> Option<PhysFrame<Size4KiB>> {
    if !is_per_node_initialized() {
        return super::buddy_allocator::buddy_alloc_frame_on_node(node);
    }

    // 指定ノードを試行
    if let Some(allocator) = get_node_allocator(node) {
        if let Some(frame) = allocator.allocate_4k() {
            return Some(frame);
        }
    }

    // フォールバック: グローバルBuddy（ノード指定あり）
    super::buddy_allocator::buddy_alloc_frame_on_node(node)
}

/// 2MiBフレームを割り当て（ローカルノード優先）
pub fn alloc_frame_2m_local_first() -> Option<PhysFrame<Size2MiB>> {
    if !is_per_node_initialized() {
        return super::buddy_allocator::buddy_alloc_frame_2m();
    }

    let local_node = super::numa::current_node();
    if let Some(allocator) = get_node_allocator(NumaNodeId::new(local_node as u8)) {
        if let Some(frame) = allocator.allocate_2m() {
            return Some(frame);
        }
    }

    // フォールバック
    for node_id in 0..MAX_NUMA_NODES {
        if node_id == local_node {
            continue;
        }
        if let Some(allocator) = get_node_allocator(NumaNodeId::new(node_id as u8)) {
            if let Some(frame) = allocator.allocate_2m() {
                return Some(frame);
            }
        }
    }

    super::buddy_allocator::buddy_alloc_frame_2m()
}

/// 1GiBフレームを割り当て（ローカルノード優先）
pub fn alloc_frame_1g_local_first() -> Option<PhysFrame<Size1GiB>> {
    if !is_per_node_initialized() {
        return super::buddy_allocator::buddy_alloc_frame_1g();
    }

    let local_node = super::numa::current_node();
    if let Some(allocator) = get_node_allocator(NumaNodeId::new(local_node as u8)) {
        if let Some(frame) = allocator.allocate_1g() {
            return Some(frame);
        }
    }

    for node_id in 0..MAX_NUMA_NODES {
        if node_id == local_node {
            continue;
        }
        if let Some(allocator) = get_node_allocator(NumaNodeId::new(node_id as u8)) {
            if let Some(frame) = allocator.allocate_1g() {
                return Some(frame);
            }
        }
    }

    super::buddy_allocator::buddy_alloc_frame_1g()
}

/// 4KiBフレームを解放
///
/// フレームの物理アドレスからノードを推測し、適切なアロケータに返却。
pub fn dealloc_frame_auto(frame: PhysFrame<Size4KiB>) {
    if !is_per_node_initialized() {
        super::buddy_allocator::buddy_dealloc_frame(frame);
        return;
    }

    // フレームアドレスからノードを推測
    let phys_addr = frame.start_address().as_u64();
    if let Some(node_id) = find_node_for_address(phys_addr) {
        if let Some(allocator) = get_node_allocator(node_id) {
            allocator.deallocate_4k(frame);
            return;
        }
    }

    // フォールバック: グローバルに返却
    super::buddy_allocator::buddy_dealloc_frame(frame);
}

/// 2MiBフレームを解放
pub fn dealloc_frame_2m_auto(frame: PhysFrame<Size2MiB>) {
    if !is_per_node_initialized() {
        super::buddy_allocator::buddy_dealloc_frame_2m(frame);
        return;
    }

    let phys_addr = frame.start_address().as_u64();
    if let Some(node_id) = find_node_for_address(phys_addr) {
        if let Some(allocator) = get_node_allocator(node_id) {
            allocator.deallocate_2m(frame);
            return;
        }
    }

    super::buddy_allocator::buddy_dealloc_frame_2m(frame);
}

/// 1GiBフレームを解放
pub fn dealloc_frame_1g_auto(frame: PhysFrame<Size1GiB>) {
    if !is_per_node_initialized() {
        super::buddy_allocator::buddy_dealloc_frame_1g(frame);
        return;
    }

    let phys_addr = frame.start_address().as_u64();
    if let Some(node_id) = find_node_for_address(phys_addr) {
        if let Some(allocator) = get_node_allocator(node_id) {
            allocator.deallocate_1g(frame);
            return;
        }
    }

    super::buddy_allocator::buddy_dealloc_frame_1g(frame);
}

/// 物理アドレスからノードIDを推測
///
/// TODO: ACPI SRATテーブルからのメモリ→ノードマッピングを使用
fn find_node_for_address(_phys_addr: u64) -> Option<NumaNodeId> {
    // プレースホルダ: 将来的にはSRATベースのルックアップを実装
    // 現時点ではノード0を仮定
    Some(NumaNodeId::new(0))
}

/// 全ノードの統計情報を取得
pub fn get_all_node_stats() -> [(BuddyAllocatorStats, u64, u64); MAX_NUMA_NODES] {
    // 空の統計を作成するヘルパー
    const fn empty_stats() -> BuddyAllocatorStats {
        BuddyAllocatorStats {
            total_frames: 0,
            free_frames: 0,
            split_count: 0,
            coalesce_count: 0,
            order_stats: [(0, 0); MAX_ORDER + 1],
        }
    }
    
    let mut stats = [(empty_stats(), 0u64, 0u64); MAX_NUMA_NODES];
    
    for (i, allocator) in PER_NODE_ALLOCATORS.iter().enumerate() {
        if allocator.is_initialized() {
            stats[i] = (
                allocator.stats(),
                allocator.stats.local_allocs.load(Ordering::Relaxed),
                allocator.stats.remote_fallbacks.load(Ordering::Relaxed),
            );
        }
    }
    
    stats
}

/// 全ノードの空きフレーム合計を取得
pub fn total_free_frames() -> u64 {
    PER_NODE_ALLOCATORS
        .iter()
        .filter(|a| a.is_initialized())
        .map(|a| a.free_frames())
        .sum()
}
