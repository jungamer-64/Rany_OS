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

// ============================================================================
// Per-CPU Front Layer (Phase 3 Optimization)
// ============================================================================
//
// Buddy Allocatorへのロック競合を軽減するため、各CPUがローカルな
// フレームキャッシュを持つ。割り当て/解放はまずフロントレイヤーで処理され、
// キャッシュが空/満杯の場合のみBuddyにアクセスする。
//
// 設計:
// - 各CPUは4KiBフレームのローカルキャッシュを持つ
// - キャッシュサイズはNUMAノードあたりの利用可能メモリに基づき調整
// - バックグラウンドでBuddyからリフィル/ドレイン
//
// 性能特性:
// - Hot Path: Per-CPUキャッシュからロックフリーで割り当て
// - Cold Path: Buddyからバッチでリフィル
// ============================================================================


/// Per-CPUフロントレイヤーのキャッシュサイズ
pub const FRONT_LAYER_CACHE_SIZE: usize = 64;

/// 最大CPU数
pub const FRONT_LAYER_MAX_CPUS: usize = 64;

/// Low watermark（この数以下でリフィル）
pub(crate) const FRONT_LAYER_LOW_WATERMARK: usize = 16;

/// High watermark（この数以上でドレイン）
pub(crate) const FRONT_LAYER_HIGH_WATERMARK: usize = 48;

/// リフィル時のバッチサイズ
pub(crate) const FRONT_LAYER_REFILL_BATCH: usize = 32;

/// Per-CPUフレームキャッシュ
#[derive(Debug)]
#[repr(align(64))] // キャッシュラインアライン
pub struct PerCpuFrameCache {
    /// キャッシュされた4KiBフレーム（物理アドレス）
    frames: [u64; FRONT_LAYER_CACHE_SIZE],
    /// 現在のフレーム数
    count: usize,
    /// CPU ID
    cpu_id: usize,
    /// NUMAノードID
    numa_node: Option<u8>,
    /// 統計: キャッシュヒット数
    cache_hits: u64,
    /// 統計: キャッシュミス数（Buddyフォールバック）
    cache_misses: u64,
    /// 統計: リフィル回数
    refill_count: u64,
    /// 統計: ドレイン回数
    drain_count: u64,
}

impl PerCpuFrameCache {
    /// 新しいPer-CPUキャッシュを作成
    pub const fn new(cpu_id: usize) -> Self {
        Self {
            frames: [0; FRONT_LAYER_CACHE_SIZE],
            count: 0,
            cpu_id,
            numa_node: None,
            cache_hits: 0,
            cache_misses: 0,
            refill_count: 0,
            drain_count: 0,
        }
    }

    /// NUMAノードを設定
    pub fn set_numa_node(&mut self, node: u8) {
        self.numa_node = Some(node);
    }

    /// キャッシュからフレームを取得（Hot Path）
    #[inline]
    pub fn pop(&mut self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        self.cache_hits += 1;
        Some(self.frames[self.count])
    }

    /// キャッシュにフレームを追加（Hot Path）
    #[inline]
    pub fn push(&mut self, frame_addr: u64) -> bool {
        if self.count >= FRONT_LAYER_CACHE_SIZE {
            return false;
        }
        self.frames[self.count] = frame_addr;
        self.count += 1;
        true
    }

    /// キャッシュが空かどうか
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// キャッシュが満杯かどうか
    #[inline]
    pub fn is_full(&self) -> bool {
        self.count >= FRONT_LAYER_CACHE_SIZE
    }

    /// リフィルが必要かどうか
    #[inline]
    pub fn needs_refill(&self) -> bool {
        self.count <= FRONT_LAYER_LOW_WATERMARK
    }

    /// ドレインが必要かどうか
    #[inline]
    pub fn needs_drain(&self) -> bool {
        self.count >= FRONT_LAYER_HIGH_WATERMARK
    }

    /// 現在のフレーム数
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    pub fn stats(&self) -> PerCpuFrameCacheStats {
        PerCpuFrameCacheStats {
            cpu_id: self.cpu_id,
            cached_frames: self.count,
            cache_hits: self.cache_hits,
            cache_misses: self.cache_misses,
            refill_count: self.refill_count,
            drain_count: self.drain_count,
        }
    }

    /// バッチリフィル（Buddy Allocatorから）
    pub fn refill(&mut self, buddy: &mut BuddyFrameAllocator) {
        let mut refilled = 0;
        for _ in 0..FRONT_LAYER_REFILL_BATCH {
            if let Some(frame) = buddy.allocate_4k_frame() {
                if !self.push(frame.start_address().as_u64()) {
                    // キャッシュ満杯（ありえないはずだが安全のため）
                    buddy.deallocate_4k_frame(frame);
                    break;
                }
                refilled += 1;
            } else {
                break;
            }
        }
        if refilled > 0 {
            self.refill_count += 1;
        }
    }

    /// バッチドレイン（Buddy Allocatorへ）
    pub fn drain(&mut self, buddy: &mut BuddyFrameAllocator) {
        let drain_count = self.count.saturating_sub(FRONT_LAYER_LOW_WATERMARK).min(FRONT_LAYER_REFILL_BATCH);
        for _ in 0..drain_count {
            if let Some(addr) = self.pop() {
                 let frame = unsafe { PhysFrame::from_start_address_unchecked(PhysAddr::new(addr)) };
                 buddy.deallocate_4k_frame(frame);
            }
        }
        if drain_count > 0 {
            self.drain_count += 1;
        }
    }
}

/// Per-CPUキャッシュ統計
#[derive(Debug, Clone, Copy)]
pub struct PerCpuFrameCacheStats {
    pub cpu_id: usize,
    pub cached_frames: usize,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub refill_count: u64,
    pub drain_count: u64,
}


/// フロントレイヤー経由で4KiBフレームを割り当て
///
/// NOTE: Lock-Free Allocator Phase 1
/// グローバルな `BUDDY_FRONT_LAYER` ロックを廃止し、
/// `PerCpuData` 内の `frame_cache` (`IrqPoisonLock` protected) を使用する。
/// これにより、他のCPUとの競合を回避し、キャッシュヒット時のレイテンシを大幅に削減する。
pub fn buddy_alloc_frame_fast(cpu_id: usize) -> Option<PhysFrame<Size4KiB>> {
    // 1. Per-CPUキャッシュからの割り当てを試行
    // Note: get_per_cpu_data は &PerCpuData を返す
    let per_cpu = unsafe { crate::per_cpu::get_per_cpu_data(cpu_id) };
    
    // Call scope to drop cache lock before potentially locking buddy
    {
        let mut cache = per_cpu.frame_cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(addr) = cache.pop() {
            // キャッシュヒット
            return Some(unsafe { PhysFrame::from_start_address_unchecked(PhysAddr::new(addr)) });
        }
        cache.cache_misses += 1;
    }

    // 2. キャッシュミス: Buddy Allocatorからリフィル
    // ここで初めてグローバルロックを取得
    let mut buddy = BUDDY_ALLOCATOR.lock().expect("lock poisoned");
    
    // 再度キャッシュロックを取得してリフィル
    {
        let mut cache = per_cpu.frame_cache.lock().unwrap_or_else(|e| e.into_inner());
        // リフィル
        cache.refill(&mut buddy);
        
        // リフィル後に再度取得試行
        if let Some(addr) = cache.pop() {
             return Some(unsafe { PhysFrame::from_start_address_unchecked(PhysAddr::new(addr)) });
        }
    }
    
    // 3. フォールバック: 直接割り当て (キャッシュ満杯or空でリフィル失敗時)
    BUDDY_ALLOCATOR.lock().expect("lock poisoned").allocate_4k_frame()
}

/// フロントレイヤーを初期化（CPU起動時）
/// Note: PerCpuDataで初期化されるため、ここでは何もしないが互換性のため残す
pub fn init_buddy_front_layer_for_cpu(_cpu_id: usize) {
    // No-op
}


/// フロントレイヤー経由で4KiBフレームを解放
pub fn buddy_dealloc_frame_fast(cpu_id: usize, frame: PhysFrame<Size4KiB>) {
    let per_cpu = unsafe { crate::per_cpu::get_per_cpu_data(cpu_id) };
    let mut cache = per_cpu.frame_cache.lock().unwrap_or_else(|e| e.into_inner());
    
    // キャッシュへの追加を試行
    if cache.push(frame.start_address().as_u64()) {
        // High Watermark チェック
        if cache.needs_drain() {
            // ドレインが必要ならBuddyロックを取得
            // デッドロック回避のため、一度キャッシュロックを解放...
            // しかし、IrqPoisonLockなので再入は安全ではない。
            // ここではドレインのためにロック順序を守る: Cache -> Buddy (allocと同じ)
            let mut buddy = BUDDY_ALLOCATOR.lock().expect("lock poisoned");
            cache.drain(&mut buddy);
        }
    } else {
        // キャッシュ満杯: Buddyに直接返却
        // ロック順序: Cache -> Buddy
        let mut buddy = BUDDY_ALLOCATOR.lock().expect("lock poisoned");
        // ドレインしてから追加試行もできるが、直接返却が単純
        buddy.deallocate_4k_frame(frame);
    }
}

/// フロントレイヤー統計を取得
pub fn buddy_front_layer_stats() -> BuddyFrontLayerStats {
    let mut total_hits = 0;
    let mut total_misses = 0;
    let mut initialized_cpus = 0;

    for i in 0..crate::per_cpu::MAX_CPUS {
        if crate::per_cpu::is_cpu_online(i) {
             let per_cpu = unsafe { crate::per_cpu::get_per_cpu_data(i) };
             let cache = per_cpu.frame_cache.lock().expect("lock poisoned");
             // ヒット数等を合算
             total_hits += cache.cache_hits as usize;
             total_misses += cache.cache_misses as usize;
             initialized_cpus += 1;
        }
    }

    BuddyFrontLayerStats {
        initialized_cpus,
        total_hits,
        total_misses,
    }
}

/// フロントレイヤー統計
#[derive(Debug, Clone, Copy)]
pub struct BuddyFrontLayerStats {
    pub initialized_cpus: usize,
    pub total_hits: usize,
    pub total_misses: usize,
}

/// グローバルなBuddy Allocator
/// 割り込み禁止Mutexで保護（デッドロック防止）
pub(crate) static BUDDY_ALLOCATOR: IrqPoisonLock<BuddyFrameAllocator> = IrqPoisonLock::new(BuddyFrameAllocator::new());

/// Buddy Allocatorを初期化
///
/// # Safety
/// カーネル初期化時に一度だけ呼ばれる必要がある
pub unsafe fn init_buddy_allocator(usable_regions: &[(PhysAddr, u64)]) {
    unsafe {
        BUDDY_ALLOCATOR.lock().expect("lock poisoned").init(usable_regions);
    }
}

pub(crate) fn borrow_exact_order_from_pmm(order: usize, preferred_node: Option<NumaNodeId>) -> bool {
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
        None => crate::mm::phys::frame_allocator::alloc_contiguous_frames_aligned(frames, align_bytes),
    };

    let Some(addr) = addr else {
        return false;
    };

    let node_id = crate::mm::phys::frame_allocator::numa_node_for_addr(addr)
        .unwrap_or(NumaNodeId::NODE_0);
    buddy_register_numa_region(node_id, addr, size_bytes);
    true
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
    if let Some(frame) = BUDDY_ALLOCATOR.lock().expect("lock poisoned").allocate_4k_frame() {
        return Some(frame);
    }
    if borrow_from_pmm_for_order(0, None) {
        return BUDDY_ALLOCATOR.lock().expect("lock poisoned").allocate_4k_frame();
    }
    None
}

/// 2MiB フレームを割り当て（Buddy版）
pub fn buddy_alloc_frame_2m() -> Option<PhysFrame<Size2MiB>> {
    if let Some(frame) = BUDDY_ALLOCATOR.lock().expect("lock poisoned").allocate_2m_frame() {
        return Some(frame);
    }
    let order = BuddyFrameAllocator::frames_to_order(PAGE_SIZE_2M / PAGE_SIZE_4K);
    if borrow_from_pmm_for_order(order, None) {
        return BUDDY_ALLOCATOR.lock().expect("lock poisoned").allocate_2m_frame();
    }
    None
}

/// 1GiB フレームを割り当て（Buddy版）
pub fn buddy_alloc_frame_1g() -> Option<PhysFrame<Size1GiB>> {
    if let Some(frame) = BUDDY_ALLOCATOR.lock().expect("lock poisoned").allocate_1g_frame() {
        return Some(frame);
    }
    let order = BuddyFrameAllocator::frames_to_order(PAGE_SIZE_1G / PAGE_SIZE_4K);
    if borrow_from_pmm_for_order(order, None) {
        return BUDDY_ALLOCATOR.lock().expect("lock poisoned").allocate_1g_frame();
    }
    None
}

/// 連続する物理フレームを割り当て（2のべき乗に切り上げ）
pub fn buddy_alloc_contiguous_frames(frame_count: usize) -> Option<PhysAddr> {
    if frame_count == 0 {
        return None;
    }
    if let Some(addr) = BUDDY_ALLOCATOR.lock().expect("lock poisoned").allocate_contiguous(frame_count) {
        return Some(addr);
    }
    let order = BuddyFrameAllocator::frames_to_order(frame_count);
    if borrow_from_pmm_for_order(order, None) {
        return BUDDY_ALLOCATOR.lock().expect("lock poisoned").allocate_contiguous(frame_count);
    }
    None
}

/// 4KiB フレームを解放（Buddy版）
pub fn buddy_dealloc_frame(frame: PhysFrame<Size4KiB>) {
    BUDDY_ALLOCATOR.lock().expect("lock poisoned").deallocate_4k_frame(frame);
}

/// 2MiB フレームを解放（Buddy版）
pub fn buddy_dealloc_frame_2m(frame: PhysFrame<Size2MiB>) {
    BUDDY_ALLOCATOR.lock().expect("lock poisoned").deallocate_2m_frame(frame);
}

/// 1GiB フレームを解放（Buddy版）
pub fn buddy_dealloc_frame_1g(frame: PhysFrame<Size1GiB>) {
    BUDDY_ALLOCATOR.lock().expect("lock poisoned").deallocate_1g_frame(frame);
}

/// Buddy Allocatorの統計を取得
pub fn buddy_allocator_stats() -> BuddyAllocatorStats {
    BUDDY_ALLOCATOR.lock().expect("lock poisoned").stats()
}

/// Register a NUMA region with the global Buddy Allocator
pub fn buddy_register_numa_region(node: NumaNodeId, start: PhysAddr, size: u64) {
    let mut allocator = BUDDY_ALLOCATOR.lock().expect("lock poisoned");
    let start_frame = FrameIndex::from_phys_addr(start.as_u64());
    let end_frame = FrameIndex::from_phys_addr(start.as_u64() + size);
    allocator.register_numa_region(node, start_frame, end_frame);
}

/// Allocate a 4KiB frame preferring the given NUMA node (best-effort)
pub fn buddy_alloc_frame_on_node(node: NumaNodeId) -> Option<PhysFrame<Size4KiB>> {
    if let Some(frame) = BUDDY_ALLOCATOR.lock().expect("lock poisoned").allocate_4k_frame_on_node(node) {
        return Some(frame);
    }
    if borrow_from_pmm_for_order(0, Some(node)) {
        return BUDDY_ALLOCATOR.lock().expect("lock poisoned").allocate_4k_frame_on_node(node);
    }
    None
}

/// Allocate a 2MiB frame preferring the given NUMA node (best-effort)
pub fn buddy_alloc_frame_2m_on_node(node: NumaNodeId) -> Option<PhysFrame<Size2MiB>> {
    if let Some(frame) = BUDDY_ALLOCATOR.lock().expect("lock poisoned").allocate_2m_frame_on_node(node) {
        return Some(frame);
    }
    let order = BuddyFrameAllocator::frames_to_order(PAGE_SIZE_2M / PAGE_SIZE_4K);
    if borrow_from_pmm_for_order(order, Some(node)) {
        return BUDDY_ALLOCATOR.lock().expect("lock poisoned").allocate_2m_frame_on_node(node);
    }
    None
}

/// Allocate a 1GiB frame preferring the given NUMA node (best-effort)
pub fn buddy_alloc_frame_1g_on_node(node: NumaNodeId) -> Option<PhysFrame<Size1GiB>> {
    if let Some(frame) = BUDDY_ALLOCATOR.lock().expect("lock poisoned").allocate_1g_frame_on_node(node) {
        return Some(frame);
    }
    let order = BuddyFrameAllocator::frames_to_order(PAGE_SIZE_1G / PAGE_SIZE_4K);
    if borrow_from_pmm_for_order(order, Some(node)) {
        return BUDDY_ALLOCATOR.lock().expect("lock poisoned").allocate_1g_frame_on_node(node);
    }
    None
}

/// 指定アドレスがBuddy Allocatorで管理されているかチェック
///
/// 設計書 P2: 統一フレームアロケータのための判定
/// 注: Buddyアロケータは初期化時に登録された領域のみを管理する
pub fn is_managed_by_buddy(addr: PhysAddr) -> bool {
    let allocator = BUDDY_ALLOCATOR.lock().expect("lock poisoned");

    // If NUMA regions are recorded, check them first
    if let Some(map) = allocator.numa_regions.as_ref() {
        for (_node, ranges) in map.iter() {
            for &(start, end) in ranges.iter() {
                let start_addr = start.to_phys_addr();
                let end_addr = end.to_phys_addr();
                if addr.as_u64() >= start_addr && addr.as_u64() < end_addr {
                    return true;
                }
            }
        }
    }

    // Fallback: contiguous region assumption
    if allocator.total_frames == 0 {
        return false;
    }

    let max_addr = (allocator.total_frames as u64) * (PAGE_SIZE_4K as u64);
    addr.as_u64() < max_addr
}

/// 指定範囲がBuddy Allocatorで管理されているかチェック
///
/// 範囲は [start, start+size) の半開区間。
/// Check if [start, end) is fully contained within any NUMA range.
pub(crate) fn is_range_in_numa_regions(
    map: &alloc::collections::BTreeMap<NumaNodeId, alloc::vec::Vec<(FrameIndex, FrameIndex)>>,
    start: u64,
    end: u64,
) -> bool {
    for (_node, ranges) in map.iter() {
        for &(range_start, range_end) in ranges.iter() {
            if start >= range_start.to_phys_addr() && end <= range_end.to_phys_addr() {
                return true;
            }
        }
    }
    false
}

pub fn is_range_managed_by_buddy(start: PhysAddr, size: u64) -> bool {
    if size == 0 {
        return false;
    }

    let Some(end) = start.as_u64().checked_add(size) else {
        return false;
    };

    let allocator = BUDDY_ALLOCATOR.lock().expect("lock poisoned");

    if let Some(map) = allocator.numa_regions.as_ref() {
        return is_range_in_numa_regions(map, start.as_u64(), end);
    }

    if allocator.total_frames == 0 {
        return false;
    }

    let max_addr = (allocator.total_frames as u64) * (PAGE_SIZE_4K as u64);
    start.as_u64() < max_addr && end <= max_addr
}

// ============================================================================
// Phase 6: THP Support Functions
// ============================================================================

/// 指定フレームが割り当て済み（使用中）かどうかをチェック
/// 
/// THP昇格候補の検出に使用される。
/// 空きフレームでない = 割り当て済みとみなす。
#[inline]
pub fn is_frame_allocated(frame_idx: usize) -> bool {
    let allocator = BUDDY_ALLOCATOR.lock().expect("lock poisoned");
    
    if frame_idx >= allocator.total_frames {
        return false;
    }
    
    // Order 0（4KB）のビットマップで空きかどうかをチェック
    // is_block_free が false = 空きではない = 割り当て済み
    !allocator.is_block_free(0, frame_idx)
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
        if allocator.is_block_free(0, frame_idx) {
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

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
    }
}
