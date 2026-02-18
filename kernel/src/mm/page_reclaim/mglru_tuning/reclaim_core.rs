use super::*;


/// 回収統計
mod clock_pro_stats;
pub use clock_pro_stats::*;
mod clock_pro_impl;
pub use clock_pro_impl::*;
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
///
/// 新しく割り当てられたページをLRUに追加する。
/// ページフォルトハンドラ、CoW、demand paging、stack growthから呼び出される。
///
/// # Arguments
/// * `frame` - 追加する物理フレーム
/// * `page_type` - ページタイプ (Anonymous, FileBacked, etc.)
///
/// # Example
/// ```ignore
/// use crate::mm::page_reclaim::{lru_add_page, PageType};
///
/// // 匿名ページをLRUに追加
/// lru_add_page(frame, PageType::Anonymous);
/// ```
pub fn lru_add_page(frame: x86_64::structures::paging::PhysFrame, page_type: PageType) {
    // フレームアドレスからFrameIndexに変換
    let frame_index = FrameIndex::from_phys_addr(frame.start_address().as_u64());
    
    // NUMA ノードIDを取得
    let numa_node = numa_node_for_phys_addr(frame.start_address().as_u64());
    
    // タイムスタンプ（ナノ秒精度）
    let timestamp = crate::time::current_time_ns();
    
    // Workingset refault detection: evict 後に再度 fault したページかチェック
    use crate::mm::workingset::{workingset_refault, workingset_advance_clock, RefaultResult};
    
    let refault_result = workingset_refault(frame_index);
    workingset_advance_clock();
    
    // PageVecエントリを作成
    let mut entry = PageVecEntry::new(frame_index, page_type, numa_node as u8, timestamp);
    
    // Refault の結果に応じて追加先を決定
    match refault_result {
        RefaultResult::WorkingSet { .. } => {
            // Working set 内: Active リストに追加
            entry.target_list = 0; // Active
        }
        RefaultResult::NotWorkingSet => {
            // Working set 外: Inactive リストに追加
            entry.target_list = 1; // Inactive
        }
        RefaultResult::NoShadow => {
            // 初回 fault: デフォルトで Active リストに追加
            entry.target_list = 0; // Active
        }
    }
    
    // 現在のCPU IDを取得（割り込み禁止状態を想定）
    let cpu_id = crate::mm::per_cpu::current_cpu_id();
    
    unsafe {
        // PageVecが満杯ならまずフラッシュ
        if pagevec_is_full(cpu_id) {
            pagevec_lru_add_flush(cpu_id);
        }
        
        // エントリを追加
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
/// 
/// 簡易実装: 単一ノード環境では常に0を返す
/// 将来的にはACPI SRATテーブルを参照して正確なマッピングを行う
#[inline]
pub(crate) fn numa_node_for_phys_addr(phys_addr: u64) -> usize {
    let addr = x86_64::PhysAddr::new(phys_addr);
    super::frame_allocator::numa_node_for_addr(addr)
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
    TEST_SYNC_PAGE_WRITEBACK_OVERRIDE.store(
        encode_test_writeback_override(result),
        Ordering::Release,
    );
}

#[cfg(test)]
pub fn set_test_sync_all_writeback_override(result: Option<bool>) {
    TEST_SYNC_ALL_WRITEBACK_OVERRIDE.store(
        encode_test_writeback_override(result),
        Ordering::Release,
    );
}

#[cfg(test)]
pub fn clear_test_writeback_overrides() {
    TEST_SYNC_PAGE_WRITEBACK_OVERRIDE.store(TEST_WRITEBACK_OVERRIDE_NONE, Ordering::Release);
    TEST_SYNC_ALL_WRITEBACK_OVERRIDE.store(TEST_WRITEBACK_OVERRIDE_NONE, Ordering::Release);
}

#[cfg(feature = "qemu-test-export")]
pub fn qemu_test_set_sync_page_writeback_override(value: Option<bool>) {
    TEST_SYNC_PAGE_WRITEBACK_OVERRIDE.store(encode_test_writeback_override(value), Ordering::Release);
}

#[cfg(feature = "qemu-test-export")]
pub fn qemu_test_set_sync_all_writeback_override(value: Option<bool>) {
    TEST_SYNC_ALL_WRITEBACK_OVERRIDE.store(encode_test_writeback_override(value), Ordering::Release);
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
/// 
/// この関数はカーネルスレッドから定期的に呼び出される想定
pub fn kswapd_cycle() {
    if !PAGE_RECLAIM.should_wake_kswapd() {
        return;
    }
    
    // 回収前に全CPUのPageVecをフラッシュ（保留中のLRU追加を確定）
    pagevec_flush_all();
    
    // Watermark高まで回収
    let target = 64; // 1サイクルの回収目標
    let reclaimed = PAGE_RECLAIM.background_reclaim(target);
    
    if reclaimed > 0 {
        log::trace!("[kswapd] Reclaimed {} pages", reclaimed);
    }
}

// ============================================================================
// Phase 2 最適化: Memory Pressure Notifier
// ============================================================================

/// メモリ圧力レベル（詳細版）
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum PressureLevel {
    /// 十分な空きあり（通常動作）
    Low = 0,
    /// やや逼迫（キャッシュ縮小推奨）
    Medium = 1,
    /// 高負荷（積極的な解放が必要）
    High = 2,
    /// 危機的（OOM間近）
    Critical = 3,
}

impl PressureLevel {
    /// MemoryPressureから変換
    pub fn from_memory_pressure(mp: MemoryPressure) -> Self {
        match mp {
            MemoryPressure::None => PressureLevel::Low,
            MemoryPressure::Background => PressureLevel::Medium,
            MemoryPressure::Direct => PressureLevel::High,
            MemoryPressure::Critical => PressureLevel::Critical,
        }
    }
}

/// 圧力通知コールバックの型
pub type PressureCallback = fn(PressureLevel);

/// 最大コールバック登録数
pub(crate) const MAX_PRESSURE_CALLBACKS: usize = 16;

/// Memory Pressure Notifier
/// 
/// メモリ圧力が変化したときにサブシステムに通知する仕組み。
/// Slabキャッシュ、バッファキャッシュ、ページキャッシュなどが
/// 圧力に応じてメモリを解放できる。
pub struct MemoryPressureNotifier {
    /// 登録されたコールバック
    callbacks: spin::Mutex<[Option<PressureCallback>; MAX_PRESSURE_CALLBACKS]>,
    /// 登録済みコールバック数
    callback_count: AtomicUsize,
    /// 現在の圧力レベル
    current_level: AtomicU64,
    /// 前回の圧力レベル
    previous_level: AtomicU64,
    /// 通知回数（統計）
    notification_count: AtomicU64,
    /// レベル変更回数（統計）
    level_change_count: AtomicU64,
    /// 通知を抑制する閾値（連続通知防止、ミリ秒）
    suppression_threshold_ms: AtomicU64,
    /// 最後の通知時刻（TSC）
    last_notification_tsc: AtomicU64,
}

impl MemoryPressureNotifier {
    pub const fn new() -> Self {
        Self {
            callbacks: spin::Mutex::new([None; MAX_PRESSURE_CALLBACKS]),
            callback_count: AtomicUsize::new(0),
            current_level: AtomicU64::new(PressureLevel::Low as u64),
            previous_level: AtomicU64::new(PressureLevel::Low as u64),
            notification_count: AtomicU64::new(0),
            level_change_count: AtomicU64::new(0),
            suppression_threshold_ms: AtomicU64::new(100), // 100ms
            last_notification_tsc: AtomicU64::new(0),
        }
    }
    
    /// コールバックを登録
    /// 
    /// # Returns
    /// 登録成功時はコールバックID（解除用）、失敗時はNone
    pub fn register(&self, callback: PressureCallback) -> Option<usize> {
        let mut callbacks = self.callbacks.lock();
        
        for (i, slot) in callbacks.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(callback);
                self.callback_count.fetch_add(1, Ordering::Relaxed);
                return Some(i);
            }
        }
        
        None // 満杯
    }
    
    /// コールバックを解除
    pub fn unregister(&self, id: usize) {
        if id >= MAX_PRESSURE_CALLBACKS {
            return;
        }
        
        let mut callbacks = self.callbacks.lock();
        if callbacks[id].is_some() {
            callbacks[id] = None;
            self.callback_count.fetch_sub(1, Ordering::Relaxed);
        }
    }
    
    /// 圧力レベルを更新し、必要なら通知を発行
    /// 
    /// 圧力が上昇した場合は即座に通知。
    /// 圧力が低下した場合は抑制閾値後に通知（チャタリング防止）。
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
            
            // 圧力上昇は即座に通知（緊急性が高い）
            if new_level > old_level {
                self.notify_all(new_level);
            } else {
                // 圧力低下は抑制閾値を確認
                let current_tsc = read_tsc();
                let last_tsc = self.last_notification_tsc.load(Ordering::Relaxed);
                let threshold = self.suppression_threshold_ms.load(Ordering::Relaxed);
                
                // TSCをms概算変換（3GHz想定）
                let elapsed_ms = (current_tsc.saturating_sub(last_tsc)) / 3_000_000;
                
                if elapsed_ms >= threshold {
                    self.notify_all(new_level);
                }
            }
        }
    }
    
    /// 全コールバックに通知
    pub(super) fn notify_all(&self, level: PressureLevel) {
        let callbacks = self.callbacks.lock();
        
        for slot in callbacks.iter() {
            if let Some(callback) = slot {
                callback(level);
            }
        }
        
        self.notification_count.fetch_add(1, Ordering::Relaxed);
        self.last_notification_tsc.store(read_tsc(), Ordering::Relaxed);
    }
    
    /// 現在の圧力レベルを取得
    #[inline]
    pub fn current_level(&self) -> PressureLevel {
        match self.current_level.load(Ordering::Acquire) {
            0 => PressureLevel::Low,
            1 => PressureLevel::Medium,
            2 => PressureLevel::High,
            _ => PressureLevel::Critical,
        }
    }
    
    /// 圧力上昇中かどうか
    pub fn is_pressure_rising(&self) -> bool {
        let current = self.current_level.load(Ordering::Relaxed);
        let previous = self.previous_level.load(Ordering::Relaxed);
        current > previous
    }
    
    /// 通知抑制閾値を設定（ミリ秒）
    pub fn set_suppression_threshold(&self, ms: u64) {
        self.suppression_threshold_ms.store(ms, Ordering::Relaxed);
    }
    
    /// 統計を取得
    pub fn stats(&self) -> PressureNotifierStats {
        PressureNotifierStats {
            registered_callbacks: self.callback_count.load(Ordering::Relaxed),
            notification_count: self.notification_count.load(Ordering::Relaxed),
            level_change_count: self.level_change_count.load(Ordering::Relaxed),
            current_level: self.current_level(),
        }
    }
}


// Legacy tests removed.



/// TSCを読み取る
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

/// 圧力通知統計
#[derive(Debug, Clone)]
pub struct PressureNotifierStats {
    pub registered_callbacks: usize,
    pub notification_count: u64,
    pub level_change_count: u64,
    pub current_level: PressureLevel,
}

/// グローバル Memory Pressure Notifier
pub static PRESSURE_NOTIFIER: MemoryPressureNotifier = MemoryPressureNotifier::new();

/// 圧力通知コールバックを登録
/// 
/// # Example
/// 
/// ```ignore
/// fn my_pressure_handler(level: PressureLevel) {
///     match level {
///         PressureLevel::High | PressureLevel::Critical => {
///             // キャッシュを縮小
///             shrink_my_cache();
///         }
///         _ => {}
///     }
/// }
/// 
/// register_pressure_callback(my_pressure_handler);
/// ```
pub fn register_pressure_callback(callback: PressureCallback) -> Option<usize> {
    PRESSURE_NOTIFIER.register(callback)
}

/// 圧力レベルを更新（PMM/Buddyから呼び出し）
pub fn update_memory_pressure(free_pages: usize, total_pages: usize) {
    // 空き率から圧力レベルを計算
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
//
// Clock-Proは、従来のClock（Second Chance）アルゴリズムを改良した
// 高度なページ置換アルゴリズム。3つのハンド（Clock Hand）を使用して
// ページの「使用頻度」と「最近性」の両方を考慮する。
//
// 特徴:
// - Cold/Hot ページの区別
// - ワンタイムアクセスページの迅速な追い出し
// - ワーキングセットサイズの適応的推定
//
// 設計:
// - Hand Cold: 非参照Coldページを回収
// - Hand Hot: 非参照Hotページを降格
// - Hand Test: Testページを管理
//
// 参考: USENIX ATC'05 "CLOCK-Pro: An Effective Improvement of the CLOCK Replacement"
// ============================================================================

/// Clock-Pro ページ状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClockProState {
    /// Cold: 最近追加されたページ（回収候補）
    Cold = 0,
    /// Hot: 頻繁にアクセスされるページ（保護）
    Hot = 1,
    /// Test: 回収されたが履歴を保持（再アクセス検知用）
    Test = 2,
}

/// Clock-Pro ページエントリ
#[derive(Debug)]
pub struct ClockProEntry {
    /// フレームインデックス
    pub frame: FrameIndex,
    /// ページ状態
    pub state: ClockProState,
    /// 参照ビット
    pub referenced: AtomicBool,
    /// Testからの昇格フラグ
    pub promoted_from_test: bool,
    /// 追加時刻（TSC）
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

    /// 参照ビットをテストしてクリア
    #[inline]
    pub fn test_clear_referenced(&self) -> bool {
        self.referenced.swap(false, Ordering::AcqRel)
    }

    /// 参照ビットをセット
    #[inline]
    pub fn set_referenced(&self) {
        self.referenced.store(true, Ordering::Release);
    }
}

/// Clock-Pro アルゴリズム実装
pub struct ClockProList {
    /// 循環リスト（Cold + Hot + Test）
    /// VecDequeを循環バッファとして使用
    pages: spin::Mutex<VecDeque<ClockProEntry>>,
    
    /// Hand Cold位置
    hand_cold: AtomicUsize,
    /// Hand Hot位置
    hand_hot: AtomicUsize,
    /// Hand Test位置
    hand_test: AtomicUsize,
    
    /// Cold ページ数
    cold_count: AtomicUsize,
    /// Hot ページ数
    hot_count: AtomicUsize,
    /// Test ページ数（メタデータのみ）
    test_count: AtomicUsize,
    
    /// ターゲット Cold ページ数（適応的に調整）
    target_cold: AtomicUsize,
    
    /// 統計: Cold回収数
    cold_evictions: AtomicU64,
    /// 統計: Hot降格数
    hot_demotions: AtomicU64,
    /// 統計: Test昇格数
    test_promotions: AtomicU64,
    /// 統計: ターゲット調整回数
    target_adjustments: AtomicU64,
}
