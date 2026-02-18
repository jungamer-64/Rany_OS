use super::*;


mod reclaim_core;
pub use reclaim_core::*;
mod controller_impl;
pub use controller_impl::*;
impl MglruTuningController {
    /// デフォルト aging interval: 2秒
    pub(super) const DEFAULT_INTERVAL_NS: u64 = 2_000_000_000;
    /// 最小 interval: 100ms
    pub(super) const MIN_INTERVAL_NS: u64 = 100_000_000;
    /// 最大 interval: 10秒
    pub(super) const MAX_INTERVAL_NS: u64 = 10_000_000_000;
    /// 調整ステップ (10%)
    pub(super) const ADJUSTMENT_STEP_PERCENT: u64 = 10;
    /// 高 refault 率の閾値
    pub(super) const HIGH_REFAULT_THRESHOLD: f32 = 0.4;
    /// 低 refault 率の閾値
    pub(super) const LOW_REFAULT_THRESHOLD: f32 = 0.1;

    /// 新しいコントローラを作成
    pub const fn new() -> Self {
        Self {
            aging_interval_ns: AtomicU64::new(Self::DEFAULT_INTERVAL_NS),
            min_interval_ns: Self::MIN_INTERVAL_NS,
            max_interval_ns: Self::MAX_INTERVAL_NS,
            last_aging_time_ns: AtomicU64::new(0),
            last_workingset_refaults: AtomicU64::new(0),
            last_normal_refaults: AtomicU64::new(0),
            adjustments: AtomicU64::new(0),
            interval_increases: AtomicU64::new(0),
            interval_decreases: AtomicU64::new(0),
        }
    }

    /// 現在の aging interval を取得 (ナノ秒)
    #[inline]
    pub fn aging_interval_ns(&self) -> u64 {
        self.aging_interval_ns.load(Ordering::Relaxed)
    }

    /// aging を実行すべきか判定
    ///
    /// 前回の aging から interval 以上経過していれば true
    pub fn should_run_aging(&self, current_time_ns: u64) -> bool {
        let last = self.last_aging_time_ns.load(Ordering::Relaxed);
        let interval = self.aging_interval_ns.load(Ordering::Relaxed);
        
        current_time_ns.saturating_sub(last) >= interval
    }

    /// aging 実行時刻を更新
    pub fn mark_aging_run(&self, current_time_ns: u64) {
        self.last_aging_time_ns.store(current_time_ns, Ordering::Relaxed);
    }

    /// Workingset refault 統計に基づいて interval を調整
    ///
    /// # Arguments
    /// * `workingset_refaults` - working set 内の refault 数
    /// * `normal_refaults` - 通常の refault 数
    /// * `pressure` - 現在のメモリ圧
    pub fn adjust_interval(
        &self,
        workingset_refaults: u64,
        normal_refaults: u64,
        pressure: MemoryPressure,
    ) {
        let total = workingset_refaults + normal_refaults;
        if total < 10 {
            return; // サンプル不足
        }

        let refault_rate = workingset_refaults as f32 / total as f32;
        let current = self.aging_interval_ns.load(Ordering::Relaxed);
        
        let new_interval = if pressure >= MemoryPressure::Direct {
            // 高メモリ圧: interval を強制的に短縮
            (current / 2).max(self.min_interval_ns)
        } else if refault_rate >= Self::HIGH_REFAULT_THRESHOLD {
            // 高 refault rate: interval を延長（ページを長く保持）
            let step = current * Self::ADJUSTMENT_STEP_PERCENT / 100;
            (current + step).min(self.max_interval_ns)
        } else if refault_rate <= Self::LOW_REFAULT_THRESHOLD {
            // 低 refault rate: interval を短縮（より積極的に回収）
            let step = current * Self::ADJUSTMENT_STEP_PERCENT / 100;
            (current - step).max(self.min_interval_ns)
        } else {
            current // 変更なし
        };

        if new_interval != current {
            self.aging_interval_ns.store(new_interval, Ordering::Relaxed);
            self.adjustments.fetch_add(1, Ordering::Relaxed);
            
            if new_interval > current {
                self.interval_increases.fetch_add(1, Ordering::Relaxed);
            } else {
                self.interval_decreases.fetch_add(1, Ordering::Relaxed);
            }
        }

        // 統計を更新
        self.last_workingset_refaults.store(workingset_refaults, Ordering::Relaxed);
        self.last_normal_refaults.store(normal_refaults, Ordering::Relaxed);
    }

    /// 統計を取得
    pub fn stats(&self) -> MglruTuningStats {
        MglruTuningStats {
            current_interval_ns: self.aging_interval_ns.load(Ordering::Relaxed),
            adjustments: self.adjustments.load(Ordering::Relaxed),
            interval_increases: self.interval_increases.load(Ordering::Relaxed),
            interval_decreases: self.interval_decreases.load(Ordering::Relaxed),
        }
    }
}

impl Default for MglruTuningController {
    fn default() -> Self {
        Self::new()
    }
}

/// MGLRU チューニング統計
#[derive(Debug, Clone, Copy)]
pub struct MglruTuningStats {
    /// 現在の aging interval (ナノ秒)
    pub current_interval_ns: u64,
    /// 調整回数
    pub adjustments: u64,
    /// interval 増加回数
    pub interval_increases: u64,
    /// interval 減少回数
    pub interval_decreases: u64,
}

impl MglruTuningStats {
    /// 現在の interval を秒で取得
    pub fn interval_secs(&self) -> f32 {
        self.current_interval_ns as f32 / 1_000_000_000.0
    }
}

// Legacy LruList removed.


// ============================================================================
// Page Reclaim Controller
// ============================================================================

/// ページ回収コントローラ
pub struct PageReclaimController {
    /// NUMAノードごとのLRUリスト
    /// インデックス = NUMAノードID
    pub(crate) lru_lists: [MglruList; 8],
    
    /// ウォーターマーク
    watermarks: Watermarks,
    
    /// kswapd起動フラグ
    kswapd_wake: AtomicBool,
    
    /// 現在のメモリ圧迫レベル
    pressure: AtomicU64,
    
    /// MGLRU 動的チューニングコントローラ
    mglru_tuning: MglruTuningController,
    
    /// 統計: 直接回収の回数
    direct_reclaim_count: AtomicU64,
    
    /// 統計: バックグラウンド回収の回数
    background_reclaim_count: AtomicU64,
    
    /// 統計: 回収したページ数（合計）
    total_reclaimed: AtomicU64,

    /// 統計: 実際のライトバックI/Oが失敗して再キューした回数
    writeback_skipped: AtomicU64,

    /// Safety gate for potentially unsafe reclaim actions.
    unsafe_eviction_enabled: AtomicBool,

    /// Pending async reclaim completions (frame -> metadata).
    pending_async: IrqMutex<BTreeMap<FrameIndex, PendingAsyncMeta>>,
    pending_async_count: AtomicU64,
    async_enqueued: AtomicU64,
    async_success: AtomicU64,
    async_fail: AtomicU64,
    requeued: AtomicU64,
    blocked_unsafe: AtomicU64,
    
    /// スキャン比率（Active:Inactive）
    scan_ratio: AtomicU64,
}

pub(crate) const fn lru_list_array() -> [MglruList; 8] {
    const LRU: MglruList = MglruList::new();
    [LRU; 8]
}

#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) const TEST_WRITEBACK_OVERRIDE_NONE: u8 = 0;
#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) const TEST_WRITEBACK_OVERRIDE_SUCCESS: u8 = 1;
#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) const TEST_WRITEBACK_OVERRIDE_FAILURE: u8 = 2;

#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) static TEST_SYNC_PAGE_WRITEBACK_OVERRIDE: AtomicU8 =
    AtomicU8::new(TEST_WRITEBACK_OVERRIDE_NONE);
#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) static TEST_SYNC_ALL_WRITEBACK_OVERRIDE: AtomicU8 =
    AtomicU8::new(TEST_WRITEBACK_OVERRIDE_NONE);

#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) fn decode_test_writeback_override(raw: u8) -> Option<bool> {
    match raw {
        TEST_WRITEBACK_OVERRIDE_SUCCESS => Some(true),
        TEST_WRITEBACK_OVERRIDE_FAILURE => Some(false),
        _ => None,
    }
}

#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) fn encode_test_writeback_override(result: Option<bool>) -> u8 {
    match result {
        Some(true) => TEST_WRITEBACK_OVERRIDE_SUCCESS,
        Some(false) => TEST_WRITEBACK_OVERRIDE_FAILURE,
        None => TEST_WRITEBACK_OVERRIDE_NONE,
    }
}
