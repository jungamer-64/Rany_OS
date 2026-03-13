use super::*;

/// 回収統計
mod clock_pro_stats;
pub use clock_pro_stats::*;
mod clock_pro_impl;
#[derive(Debug)]
pub struct ReclaimStats {
    pub direct_reclaim_count: u64,
    pub background_reclaim_count: u64,
    /// Total reclaimed pages (synchronous frees + async completion successes).
    pub total_reclaimed: u64,
    pub pressure: MemoryPressure,
    /// Requeue count caused by actual writeback I/O failure.
    pub writeback_skipped: u64,
    pub unsafe_eviction_enabled: bool,
    pub pending_async: u64,
    pub async_enqueued: u64,
    pub async_success: u64,
    pub async_fail: u64,
    pub requeued: u64,
    pub blocked_unsafe: u64,
    pub lru_stats: [MglruStats; 8],
}

// ============================================================================
// Global Instance
// ============================================================================

/// グローバルページ回収コントローラ
pub static PAGE_RECLAIM: PageReclaimController = PageReclaimController::new();

/// ページ回収を初期化
pub fn init_page_reclaim(total_pages: usize) {
    let watermarks = Watermarks::calculate(total_pages);
    log::info!(
        "[PageReclaim] Initialized: high={}, low={}, min={}, critical={}",
        watermarks.high,
        watermarks.low,
        watermarks.min,
        watermarks.critical
    );
}

// ============================================================================
// LRU Page API (fault_handler/cow/demand_paging/stack_growth から使用)
// ============================================================================

/// ページをLRUリストに追加（公開API）
pub fn lru_add_page(frame: x86_64::structures::paging::PhysFrame, page_type: PageType) {
    let frame_index = FrameIndex::from_phys_addr(frame.start_address().as_u64());
    let numa_node = numa_node_for_phys_addr(frame.start_address().as_u64());
    let timestamp = crate::time::current_time_ns();

    use crate::mm::reclaim::workingset::{
        RefaultResult, workingset_advance_clock, workingset_refault,
    };

    let refault_result = workingset_refault(frame_index);
    workingset_advance_clock();

    let mut entry = PageVecEntry::new(frame_index, page_type, numa_node as u8, timestamp);

    match refault_result {
        RefaultResult::WorkingSet { .. } => {
            entry.target_list = 0; // Active
        }
        RefaultResult::NotWorkingSet => {
            entry.target_list = 1; // Inactive
        }
        RefaultResult::NoShadow => {
            entry.target_list = 0; // Active
        }
    }

    let cpu_id = crate::cpu::current_id();

    unsafe {
        if pagevec_is_full(cpu_id) {
            pagevec_lru_add_flush(cpu_id);
        }
        pagevec_add(cpu_id, entry);
    }
}

/// ページをLRUリストに追加（NUMAノード指定版）
pub fn lru_add_page_on_node(
    frame: x86_64::structures::paging::PhysFrame,
    page_type: PageType,
    numa_node: usize,
) {
    let frame_index = FrameIndex::from_phys_addr(frame.start_address().as_u64());
    let timestamp = crate::time::current_time_ns();
    PAGE_RECLAIM.add_page(frame_index, page_type, numa_node, timestamp);
}

/// ページアクセスを記録（参照ビットをセット）
pub fn lru_mark_accessed(frame: x86_64::structures::paging::PhysFrame) {
    let frame_index = FrameIndex::from_phys_addr(frame.start_address().as_u64());
    let numa_node = numa_node_for_phys_addr(frame.start_address().as_u64());
    PAGE_RECLAIM.mark_accessed(frame_index, numa_node);
}

/// 物理アドレスからNUMAノードIDを取得
#[inline]
pub(crate) fn numa_node_for_phys_addr(phys_addr: u64) -> usize {
    let addr = x86_64::PhysAddr::new(phys_addr);
    crate::mm::phys::frame_allocator::numa_node_for_addr(addr)
        .map(|node| node.as_usize())
        .unwrap_or(0)
}

/// 空きメモリチェック（割り当て前に呼ぶ）
pub fn check_memory_pressure(free_pages: usize) -> MemoryPressure {
    PAGE_RECLAIM.update_free_pages(free_pages)
}

/// 必要に応じて直接回収を実行
pub fn try_to_free_pages(needed: usize) -> usize {
    PAGE_RECLAIM.direct_reclaim(needed)
}

/// Enable or disable unsafe reclaim eviction paths.
pub fn set_unsafe_eviction_enabled(enabled: bool) {
    PAGE_RECLAIM.set_unsafe_eviction_enabled(enabled);
}

/// Return whether unsafe reclaim eviction paths are enabled.
pub fn unsafe_eviction_enabled() -> bool {
    PAGE_RECLAIM.unsafe_eviction_enabled()
}

/// Notify page reclaim that async swapout/writeback completed successfully.
pub fn notify_async_swapout_success(frame: FrameIndex) {
    PAGE_RECLAIM.on_async_swapout_complete(frame, true);
}

/// Notify page reclaim that async swapout/writeback failed.
pub fn notify_async_swapout_failure(frame: FrameIndex) {
    PAGE_RECLAIM.on_async_swapout_complete(frame, false);
}

#[cfg(test)]
pub fn set_test_sync_page_writeback_override(result: Option<bool>) {
    TEST_SYNC_PAGE_WRITEBACK_OVERRIDE
        .store(encode_test_writeback_override(result), Ordering::Release);
}

#[cfg(test)]
pub fn set_test_sync_all_writeback_override(result: Option<bool>) {
    TEST_SYNC_ALL_WRITEBACK_OVERRIDE
        .store(encode_test_writeback_override(result), Ordering::Release);
}

#[cfg(test)]
pub fn clear_test_writeback_overrides() {
    TEST_SYNC_PAGE_WRITEBACK_OVERRIDE.store(TEST_WRITEBACK_OVERRIDE_NONE, Ordering::Release);
    TEST_SYNC_ALL_WRITEBACK_OVERRIDE.store(TEST_WRITEBACK_OVERRIDE_NONE, Ordering::Release);
}

#[cfg(feature = "qemu-test-export")]
pub fn qemu_test_set_sync_page_writeback_override(value: Option<bool>) {
    TEST_SYNC_PAGE_WRITEBACK_OVERRIDE
        .store(encode_test_writeback_override(value), Ordering::Release);
}

#[cfg(feature = "qemu-test-export")]
pub fn qemu_test_set_sync_all_writeback_override(value: Option<bool>) {
    TEST_SYNC_ALL_WRITEBACK_OVERRIDE
        .store(encode_test_writeback_override(value), Ordering::Release);
}

#[cfg(feature = "qemu-test-export")]
pub fn qemu_test_clear_writeback_overrides() {
    TEST_SYNC_PAGE_WRITEBACK_OVERRIDE.store(TEST_WRITEBACK_OVERRIDE_NONE, Ordering::Release);
    TEST_SYNC_ALL_WRITEBACK_OVERRIDE.store(TEST_WRITEBACK_OVERRIDE_NONE, Ordering::Release);
}

#[cfg(test)]
pub fn test_register_pending_async(frame: FrameIndex, page_type: PageType, node_idx: usize) {
    let mut entry = MglruEntry::new(frame, page_type, 0);
    entry.generation = MglruGen::Gen3;
    PAGE_RECLAIM.enqueue_pending_async(&entry, node_idx);
}

// ============================================================================
// kswapd (Background Reclaim Thread)
// ============================================================================

/// kswapd相当のバックグラウンド回収タスク
pub fn kswapd_cycle() {
    if !PAGE_RECLAIM.should_wake_kswapd() {
        return;
    }

    pagevec_flush_all();

    let target = 64;
    let reclaimed = PAGE_RECLAIM.background_reclaim(target);

    if reclaimed > 0 {
        log::trace!("[kswapd] Reclaimed {} pages", reclaimed);
    }
}

// ============================================================================
// Phase 2 最適化: Memory Pressure Notifier
// ============================================================================

use crate::sync::PoisonLock;

/// メモリ圧力レベル（詳細版）
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum PressureLevel {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl PressureLevel {
    pub fn from_memory_pressure(mp: MemoryPressure) -> Self {
        match mp {
            MemoryPressure::None => PressureLevel::Low,
            MemoryPressure::Background => PressureLevel::Medium,
            MemoryPressure::Direct => PressureLevel::High,
            MemoryPressure::Critical => PressureLevel::Critical,
        }
    }
}

pub type PressureCallback = fn(PressureLevel);
pub(crate) const MAX_PRESSURE_CALLBACKS: usize = 16;

pub struct MemoryPressureNotifier {
    /// 登録されたコールバック
    callbacks: PoisonLock<[Option<PressureCallback>; MAX_PRESSURE_CALLBACKS]>,
    callback_count: AtomicUsize,
    current_level: AtomicU64,
    previous_level: AtomicU64,
    notification_count: AtomicU64,
    level_change_count: AtomicU64,
    suppression_threshold_ms: AtomicU64,
    last_notification_tsc: AtomicU64,
}

impl MemoryPressureNotifier {
    pub const fn new() -> Self {
        Self {
            callbacks: PoisonLock::new([None; MAX_PRESSURE_CALLBACKS]),
            callback_count: AtomicUsize::new(0),
            current_level: AtomicU64::new(PressureLevel::Low as u64),
            previous_level: AtomicU64::new(PressureLevel::Low as u64),
            notification_count: AtomicU64::new(0),
            level_change_count: AtomicU64::new(0),
            suppression_threshold_ms: AtomicU64::new(100),
            last_notification_tsc: AtomicU64::new(0),
        }
    }

    pub fn register(&self, callback: PressureCallback) -> Option<usize> {
        let mut callbacks = self.callbacks.lock().unwrap_or_else(|e| e.into_inner());

        for (i, slot) in callbacks.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(callback);
                self.callback_count.fetch_add(1, Ordering::Relaxed);
                return Some(i);
            }
        }
        None
    }

    pub fn unregister(&self, id: usize) {
        if id >= MAX_PRESSURE_CALLBACKS {
            return;
        }

        let mut callbacks = self.callbacks.lock().unwrap_or_else(|e| e.into_inner());
        if callbacks[id].is_some() {
            callbacks[id] = None;
            self.callback_count.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn update_pressure(&self, new_level: PressureLevel) {
        let old = self.current_level.swap(new_level as u64, Ordering::AcqRel);
        let old_level = match old {
            0 => PressureLevel::Low,
            1 => PressureLevel::Medium,
            2 => PressureLevel::High,
            _ => PressureLevel::Critical,
        };

        if new_level != old_level {
            self.previous_level.store(old, Ordering::Relaxed);
            self.level_change_count.fetch_add(1, Ordering::Relaxed);

            if new_level > old_level {
                self.notify_all(new_level);
            } else {
                let current_tsc = read_tsc();
                let last_tsc = self.last_notification_tsc.load(Ordering::Relaxed);
                let threshold = self.suppression_threshold_ms.load(Ordering::Relaxed);
                let elapsed_ms = (current_tsc.saturating_sub(last_tsc)) / 3_000_000;

                if elapsed_ms >= threshold {
                    self.notify_all(new_level);
                }
            }
        }
    }

    pub(super) fn notify_all(&self, level: PressureLevel) {
        let callbacks = self.callbacks.lock().unwrap_or_else(|e| e.into_inner());

        for slot in callbacks.iter() {
            if let Some(callback) = slot {
                callback(level);
            }
        }

        self.notification_count.fetch_add(1, Ordering::Relaxed);
        self.last_notification_tsc
            .store(read_tsc(), Ordering::Relaxed);
    }

    #[inline]
    pub fn current_level(&self) -> PressureLevel {
        match self.current_level.load(Ordering::Acquire) {
            0 => PressureLevel::Low,
            1 => PressureLevel::Medium,
            2 => PressureLevel::High,
            _ => PressureLevel::Critical,
        }
    }

    pub fn is_pressure_rising(&self) -> bool {
        let current = self.current_level.load(Ordering::Relaxed);
        let previous = self.previous_level.load(Ordering::Relaxed);
        current > previous
    }

    pub fn set_suppression_threshold(&self, ms: u64) {
        self.suppression_threshold_ms.store(ms, Ordering::Relaxed);
    }

    pub fn stats(&self) -> PressureNotifierStats {
        PressureNotifierStats {
            registered_callbacks: self.callback_count.load(Ordering::Relaxed),
            notification_count: self.notification_count.load(Ordering::Relaxed),
            level_change_count: self.level_change_count.load(Ordering::Relaxed),
            current_level: self.current_level(),
        }
    }
}

#[inline]
pub(crate) fn read_tsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

#[derive(Debug, Clone)]
pub struct PressureNotifierStats {
    pub registered_callbacks: usize,
    pub notification_count: u64,
    pub level_change_count: u64,
    pub current_level: PressureLevel,
}

pub static PRESSURE_NOTIFIER: MemoryPressureNotifier = MemoryPressureNotifier::new();

pub fn register_pressure_callback(callback: PressureCallback) -> Option<usize> {
    PRESSURE_NOTIFIER.register(callback)
}

pub fn update_memory_pressure(free_pages: usize, total_pages: usize) {
    let free_percent = if total_pages > 0 {
        (free_pages * 100) / total_pages
    } else {
        0
    };

    let level = if free_percent <= 2 {
        PressureLevel::Critical
    } else if free_percent <= 5 {
        PressureLevel::High
    } else if free_percent <= 15 {
        PressureLevel::Medium
    } else {
        PressureLevel::Low
    };

    PRESSURE_NOTIFIER.update_pressure(level);
}

// ============================================================================
// Clock-Pro Algorithm (Phase 3 Optimization)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClockProState {
    Cold = 0,
    Hot = 1,
    Test = 2,
}

#[derive(Debug)]
pub struct ClockProEntry {
    pub frame: FrameIndex,
    pub state: ClockProState,
    pub referenced: AtomicBool,
    pub promoted_from_test: bool,
    pub timestamp: u64,
}

impl ClockProEntry {
    pub fn new(frame: FrameIndex, state: ClockProState, timestamp: u64) -> Self {
        Self {
            frame,
            state,
            referenced: AtomicBool::new(false),
            promoted_from_test: false,
            timestamp,
        }
    }

    #[inline]
    pub fn test_clear_referenced(&self) -> bool {
        self.referenced.swap(false, Ordering::AcqRel)
    }

    #[inline]
    pub fn set_referenced(&self) {
        self.referenced.store(true, Ordering::Release);
    }
}

pub struct ClockProList {
    /// 循環リスト（Cold + Hot + Test）
    pages: PoisonLock<VecDeque<ClockProEntry>>,

    hand_cold: AtomicUsize,
    hand_hot: AtomicUsize,
    hand_test: AtomicUsize,

    cold_count: AtomicUsize,
    hot_count: AtomicUsize,
    test_count: AtomicUsize,

    target_cold: AtomicUsize,

    cold_evictions: AtomicU64,
    hot_demotions: AtomicU64,
    test_promotions: AtomicU64,
    target_adjustments: AtomicU64,
}
