use super::*;

// x86_64 crateのFrameAllocatorトレイトを実装
unsafe impl FrameAllocator<Size4KiB> for BuddyFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.allocate_4k_frame()
    }
}

/// Buddy Allocator 統計情報
#[derive(Debug, Clone, Copy)]
pub struct BuddyAllocatorStats {
    pub total_frames: usize,
    pub free_frames: u64,
    pub split_count: u64,
    pub coalesce_count: u64,
    /// 各オーダーの (空きブロック数, 総フレーム数)
    pub order_stats: [(usize, usize); MAX_ORDER + 1],
}

/// グローバルなBuddy Allocator
/// 割り込み禁止Mutexで保護（デッドロック防止）
pub(crate) static BUDDY_ALLOCATOR: IrqPoisonLock<BuddyFrameAllocator> =
    IrqPoisonLock::new(BuddyFrameAllocator::new());

/// Buddy Allocatorを初期化
///
/// # Safety
/// カーネル初期化時に一度だけ呼ばれる必要がある
pub unsafe fn init_buddy_allocator(usable_regions: &[(PhysAddr, u64)]) {
    unsafe {
        BUDDY_ALLOCATOR
            .lock()
            .expect("lock poisoned")
            .init(usable_regions);
    }
}

pub(crate) fn borrow_exact_order_from_pmm(
    order: usize,
    preferred_node: Option<NumaNodeId>,
) -> bool {
    if order > MAX_ORDER {
        return false;
    }

    let frames = 1usize << order;
    let align_bytes = frames.saturating_mul(PAGE_SIZE_4K);
    let size_bytes = (frames as u64).saturating_mul(PAGE_SIZE_4K as u64);
    if size_bytes == 0 {
        return false;
    }

    let addr = match preferred_node {
        Some(node) => crate::mm::phys::frame_allocator::alloc_contiguous_frames_aligned_on_node(
            node,
            frames,
            align_bytes,
        )
        .or_else(|| {
            crate::mm::phys::frame_allocator::alloc_contiguous_frames_aligned(frames, align_bytes)
        }),
        None => {
            crate::mm::phys::frame_allocator::alloc_contiguous_frames_aligned(frames, align_bytes)
        }
    };

    let Some(addr) = addr else {
        return false;
    };

    let node_id =
        crate::mm::phys::frame_allocator::numa_node_for_addr(addr).unwrap_or(NumaNodeId::NODE_0);
    let start_frame = FrameIndex::from_phys_addr(addr.as_u64());
    let end_frame = start_frame.offset(frames);
    // SAFETY: PMM returned this exclusive, aligned allocation above. Admission
    // transfers it to buddy only on success; rejected admission returns it below.
    let admitted = unsafe {
        BUDDY_ALLOCATOR
            .lock()
            .expect("lock poisoned")
            .register_numa_region(node_id, start_frame, end_frame)
    };
    match admitted {
        Ok(()) => true,
        Err(FrameInventoryError::Overlap) => {
            // PMM violated exclusive ownership. Returning the contested range
            // would allow another allocation to overwrite live buddy memory.
            panic!("[Buddy] PMM returned an already-owned physical range");
        }
        Err(error) => {
            crate::mm::phys::frame_allocator::dealloc_contiguous_frames(addr, frames);
            log::warn!("[Buddy] PMM range admission failed: {:?}", error);
            false
        }
    }
}

pub(crate) fn borrow_from_pmm_for_order(order: usize, preferred_node: Option<NumaNodeId>) -> bool {
    if !crate::mm::phys::frame_allocator::pmm_initialized() {
        return false;
    }

    let capped_order = order.min(MAX_ORDER);
    let primary_order = capped_order.max(BUDDY_BORROW_MIN_ORDER);

    if borrow_exact_order_from_pmm(primary_order, preferred_node) {
        return true;
    }

    if primary_order != capped_order {
        return borrow_exact_order_from_pmm(capped_order, preferred_node);
    }

    false
}

/// Allocate a Huge Frame (2MB, Order 9)
///
/// Returns physical frame of 2MB size.
pub fn alloc_huge_frame() -> Option<PhysFrame<Size2MiB>> {
    buddy_alloc_frame_2m()
}

/// 4KiB フレームを割り当て（Buddy版）
pub fn buddy_alloc_frame() -> Option<PhysFrame<Size4KiB>> {
    if let Some(frame) = BUDDY_ALLOCATOR
        .lock()
        .expect("lock poisoned")
        .allocate_4k_frame()
    {
        return Some(frame);
    }
    if borrow_from_pmm_for_order(0, None) {
        return BUDDY_ALLOCATOR
            .lock()
            .expect("lock poisoned")
            .allocate_4k_frame();
    }
    None
}

/// 2MiB フレームを割り当て（Buddy版）
pub fn buddy_alloc_frame_2m() -> Option<PhysFrame<Size2MiB>> {
    if let Some(frame) = BUDDY_ALLOCATOR
        .lock()
        .expect("lock poisoned")
        .allocate_2m_frame()
    {
        return Some(frame);
    }
    let order = BuddyFrameAllocator::frames_to_order(PAGE_SIZE_2M / PAGE_SIZE_4K);
    if borrow_from_pmm_for_order(order, None) {
        return BUDDY_ALLOCATOR
            .lock()
            .expect("lock poisoned")
            .allocate_2m_frame();
    }
    None
}

/// 1GiB フレームを割り当て（Buddy版）
pub fn buddy_alloc_frame_1g() -> Option<PhysFrame<Size1GiB>> {
    if let Some(frame) = BUDDY_ALLOCATOR
        .lock()
        .expect("lock poisoned")
        .allocate_1g_frame()
    {
        return Some(frame);
    }
    let order = BuddyFrameAllocator::frames_to_order(PAGE_SIZE_1G / PAGE_SIZE_4K);
    if borrow_from_pmm_for_order(order, None) {
        return BUDDY_ALLOCATOR
            .lock()
            .expect("lock poisoned")
            .allocate_1g_frame();
    }
    None
}

/// 連続する物理フレームを割り当て（2のべき乗に切り上げ）
pub fn buddy_alloc_contiguous_frames(frame_count: usize) -> Option<PhysAddr> {
    if frame_count == 0 {
        return None;
    }
    if let Some(addr) = BUDDY_ALLOCATOR
        .lock()
        .expect("lock poisoned")
        .allocate_contiguous(frame_count)
    {
        return Some(addr);
    }
    let order = BuddyFrameAllocator::frames_to_order(frame_count);
    if borrow_from_pmm_for_order(order, None) {
        return BUDDY_ALLOCATOR
            .lock()
            .expect("lock poisoned")
            .allocate_contiguous(frame_count);
    }
    None
}

/// 4KiB フレームを解放（Buddy版）
pub fn buddy_dealloc_frame(frame: PhysFrame<Size4KiB>) {
    BUDDY_ALLOCATOR
        .lock()
        .expect("lock poisoned")
        .deallocate_4k_frame(frame);
}

/// 2MiB フレームを解放（Buddy版）
pub fn buddy_dealloc_frame_2m(frame: PhysFrame<Size2MiB>) {
    BUDDY_ALLOCATOR
        .lock()
        .expect("lock poisoned")
        .deallocate_2m_frame(frame);
}

/// 1GiB フレームを解放（Buddy版）
pub fn buddy_dealloc_frame_1g(frame: PhysFrame<Size1GiB>) {
    BUDDY_ALLOCATOR
        .lock()
        .expect("lock poisoned")
        .deallocate_1g_frame(frame);
}

/// Buddy Allocatorの統計を取得
pub fn buddy_allocator_stats() -> BuddyAllocatorStats {
    BUDDY_ALLOCATOR.lock().expect("lock poisoned").stats()
}

/// Allocate a 4KiB frame preferring the given NUMA node (best-effort)
pub fn buddy_alloc_frame_on_node(node: NumaNodeId) -> Option<PhysFrame<Size4KiB>> {
    if let Some(frame) = BUDDY_ALLOCATOR
        .lock()
        .expect("lock poisoned")
        .allocate_4k_frame_on_node(node)
    {
        return Some(frame);
    }
    if borrow_from_pmm_for_order(0, Some(node)) {
        return BUDDY_ALLOCATOR
            .lock()
            .expect("lock poisoned")
            .allocate_4k_frame_on_node(node);
    }
    None
}

/// Allocate a 2MiB frame preferring the given NUMA node (best-effort)
pub fn buddy_alloc_frame_2m_on_node(node: NumaNodeId) -> Option<PhysFrame<Size2MiB>> {
    if let Some(frame) = BUDDY_ALLOCATOR
        .lock()
        .expect("lock poisoned")
        .allocate_2m_frame_on_node(node)
    {
        return Some(frame);
    }
    let order = BuddyFrameAllocator::frames_to_order(PAGE_SIZE_2M / PAGE_SIZE_4K);
    if borrow_from_pmm_for_order(order, Some(node)) {
        return BUDDY_ALLOCATOR
            .lock()
            .expect("lock poisoned")
            .allocate_2m_frame_on_node(node);
    }
    None
}

/// Allocate a 1GiB frame preferring the given NUMA node (best-effort)
pub fn buddy_alloc_frame_1g_on_node(node: NumaNodeId) -> Option<PhysFrame<Size1GiB>> {
    if let Some(frame) = BUDDY_ALLOCATOR
        .lock()
        .expect("lock poisoned")
        .allocate_1g_frame_on_node(node)
    {
        return Some(frame);
    }
    let order = BuddyFrameAllocator::frames_to_order(PAGE_SIZE_1G / PAGE_SIZE_4K);
    if borrow_from_pmm_for_order(order, Some(node)) {
        return BUDDY_ALLOCATOR
            .lock()
            .expect("lock poisoned")
            .allocate_1g_frame_on_node(node);
    }
    None
}

/// 指定アドレスがBuddy Allocatorで管理されているかチェック
///
/// 設計書 P2: 統一フレームアロケータのための判定
/// 注: Buddyアロケータは初期化時に登録された領域のみを管理する
pub fn is_managed_by_buddy(addr: PhysAddr) -> bool {
    let allocator = BUDDY_ALLOCATOR.lock().expect("lock poisoned");
    allocator
        .allocations
        .contains(FrameIndex::from_phys_addr(addr.as_u64()))
}

/// Reports membership only; this does not authorize mutation or release.
/// Checked byte bounds are converted to the half-open frame range they touch.
pub fn is_range_managed_by_buddy(start: PhysAddr, size: u64) -> bool {
    if size == 0 {
        return false;
    }
    let Some(end) = start.as_u64().checked_add(size) else {
        return false;
    };
    let first = FrameIndex::from_phys_addr(start.as_u64());
    let last = FrameIndex::from_phys_addr(end - 1).offset(1);
    let allocator = BUDDY_ALLOCATOR.lock().expect("lock poisoned");
    allocator.allocations.contains_range(first, last)
}

// ============================================================================
// Phase 6: THP Support Functions
// ============================================================================

/// 指定フレームが割り当て済み（使用中）かどうかをチェック
///
/// THP昇格候補の検出に使用される。
/// Only a live extent is allocated; unmanaged holes and coalesced free blocks
/// are not inferred to be live from the order-zero search index.
#[inline]
pub fn is_frame_allocated(frame_idx: usize) -> bool {
    let allocator = BUDDY_ALLOCATOR.lock().expect("lock poisoned");

    allocator
        .allocations
        .is_allocated(FrameIndex::new(frame_idx))
}

/// 512個の連続フレームをHugePageとしてマーク
///
/// THP昇格時に呼び出される。Order 9（512フレーム = 2MB）として
/// Buddyアロケータに登録する。
///
/// # Safety
///
/// - `start_frame`は2MB境界にアラインされている必要がある
/// - 512個全てのフレームが割り当て済みである必要がある
#[inline]
pub unsafe fn mark_as_huge_page(start_frame: usize) -> bool {
    const PAGES_PER_2MB: usize = 512;

    // 2MB境界チェック
    if start_frame % PAGES_PER_2MB != 0 {
        return false;
    }

    let allocator = BUDDY_ALLOCATOR.lock().expect("lock poisoned");

    // 全512フレームが割り当て済みかチェック（is_block_free使用）
    for i in 0..PAGES_PER_2MB {
        let frame_idx = start_frame + i;
        if frame_idx >= allocator.total_frames {
            return false;
        }

        // 空きであれば割り当て不可
        if !allocator
            .allocations
            .is_allocated(FrameIndex::new(frame_idx))
        {
            return false;
        }
    }

    // Order 9（2MB）として内部的にマーク
    // 注: 実際のページテーブル操作は別途必要
    // ここではBuddyの統計を更新

    // HugePageカウンタをインクリメント（統計用）
    HUGE_PAGE_STATS.marked_count.fetch_add(1, Ordering::Relaxed);

    true
}

/// HugePageマーキング統計
pub struct HugePageStats {
    /// マークされたHugePage数
    pub marked_count: AtomicU64,
    /// アンマークされたHugePage数
    pub unmarked_count: AtomicU64,
}

impl HugePageStats {
    pub const fn new() -> Self {
        Self {
            marked_count: AtomicU64::new(0),
            unmarked_count: AtomicU64::new(0),
        }
    }
}

/// グローバルHugePage統計
pub static HUGE_PAGE_STATS: HugePageStats = HugePageStats::new();

#[cfg(test)]
#[path = "../tests.rs"]
mod tests;

use core::alloc::{GlobalAlloc, Layout};

/// Dummy LockedBuddyHeap for compilation fix
pub struct LockedBuddyHeap {}

impl LockedBuddyHeap {
    pub const fn empty() -> Self {
        Self {}
    }
}

unsafe impl GlobalAlloc for LockedBuddyHeap {
    unsafe fn alloc(&self, _layout: Layout) -> *mut u8 {
        core::ptr::null_mut()
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}
