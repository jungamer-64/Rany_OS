use super::*;
use crate::sync::IrqPoisonLock;

/// Clock-Pro統計
#[derive(Debug, Clone, Copy)]
pub struct ClockProStats {
    /// Cold ページ数
    pub cold_pages: usize,
    /// Hot ページ数
    pub hot_pages: usize,
    /// Test エントリ数
    pub test_pages: usize,
    /// ターゲット Cold 数
    pub target_cold: usize,
    /// Cold 回収数
    pub cold_evictions: u64,
    /// Hot 降格数
    pub hot_demotions: u64,
    /// Test 昇格数
    pub test_promotions: u64,
}

/// グローバル Clock-Pro リスト（NUMAノードごと）
pub static CLOCK_PRO_LISTS: [ClockProList; 8] = {
    const INIT: ClockProList = ClockProList::new();
    [INIT; 8]
};

/// Clock-Proにページを追加
pub fn clock_pro_add_page(frame: FrameIndex, node: usize) {
    let node_idx = node.min(7);
    CLOCK_PRO_LISTS[node_idx].add_page(frame, read_tsc());
}

/// Clock-Proでページアクセスを記録
pub fn clock_pro_access_page(frame: FrameIndex, node: usize) {
    let node_idx = node.min(7);
    CLOCK_PRO_LISTS[node_idx].access_page(frame);
}

/// Clock-Proで回収対象ページを取得
pub fn clock_pro_reclaim(node: usize, target_count: usize) -> Vec<FrameIndex> {
    let node_idx = node.min(7);

    // まずHand Hotでスキャン
    CLOCK_PRO_LISTS[node_idx].run_hand_hot(target_count * 2);

    // Hand Coldで回収
    CLOCK_PRO_LISTS[node_idx].run_hand_cold(target_count)
}

/// Clock-Pro統計を取得
pub fn clock_pro_stats(node: usize) -> ClockProStats {
    let node_idx = node.min(7);
    CLOCK_PRO_LISTS[node_idx].stats()
}

// ============================================================================
// Phase 5: 6.3 Swap Prefetch 基盤
// ============================================================================

/// スワップ先読みヒント
#[derive(Debug, Clone, Copy)]
pub struct SwapPrefetchHint {
    pub fault_addr: u64,
    pub prefetch_start: u64,
    pub prefetch_count: usize,
    pub priority: u8,
    pub reason: PrefetchReason,
}

/// 先読みの理由
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PrefetchReason {
    SpatialLocality = 0,
    TemporalLocality = 1,
    WorkingSetPrediction = 2,
    ExplicitHint = 3,
}

pub(crate) const PREFETCH_WINDOW_SIZE: usize = 8;
pub(crate) const PREFETCH_HISTORY_SIZE: usize = 32;

/// スワップ先読み器
pub struct SwapPrefetcher {
    fault_history: IrqPoisonLock<VecDeque<u64>>,
    hits: AtomicU64,
    misses: AtomicU64,
    total_prefetched: AtomicU64,
    enabled: AtomicBool,
    default_prefetch_count: AtomicUsize,
}

impl SwapPrefetcher {
    pub const fn new() -> Self {
        Self {
            fault_history: IrqPoisonLock::new(VecDeque::new()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            total_prefetched: AtomicU64::new(0),
            enabled: AtomicBool::new(true),
            default_prefetch_count: AtomicUsize::new(PREFETCH_WINDOW_SIZE),
        }
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Release);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    pub fn set_default_prefetch_count(&self, count: usize) {
        self.default_prefetch_count
            .store(count.min(32).max(1), Ordering::Release);
    }

    pub fn generate_hint(&self, fault_addr: u64, is_sequential: bool) -> Option<SwapPrefetchHint> {
        if !self.is_enabled() {
            return None;
        }

        let page_addr = fault_addr & !0xFFF;
        let page_num = page_addr >> 12;

        {
            let mut history = self.fault_history.lock().unwrap_or_else(|e| e.into_inner());
            history.push_back(page_addr);
            if history.len() > PREFETCH_HISTORY_SIZE {
                history.pop_front();
            }
        }

        let prefetch_count = self.default_prefetch_count.load(Ordering::Relaxed);

        if is_sequential {
            return Some(SwapPrefetchHint {
                fault_addr,
                prefetch_start: page_num + 1,
                prefetch_count,
                priority: 200,
                reason: PrefetchReason::SpatialLocality,
            });
        }

        if let Some(hint) = self.detect_access_pattern(page_addr) {
            return Some(hint);
        }

        Some(SwapPrefetchHint {
            fault_addr,
            prefetch_start: page_num.saturating_sub((prefetch_count / 2) as u64),
            prefetch_count,
            priority: 100,
            reason: PrefetchReason::TemporalLocality,
        })
    }

    pub(super) fn detect_access_pattern(&self, current_addr: u64) -> Option<SwapPrefetchHint> {
        let history = self.fault_history.lock().unwrap_or_else(|e| e.into_inner());

        if history.len() < 3 {
            return None;
        }

        let recent: Vec<u64> = history.iter().rev().take(4).cloned().collect();
        if recent.len() >= 3 {
            let stride1 = recent[0].wrapping_sub(recent[1]) as i64;
            let stride2 = recent[1].wrapping_sub(recent[2]) as i64;

            if stride1 == stride2 && stride1.abs() <= 16 * 4096 {
                let next_addr = if stride1 >= 0 {
                    current_addr.wrapping_add(stride1 as u64)
                } else {
                    current_addr.wrapping_sub((-stride1) as u64)
                };

                return Some(SwapPrefetchHint {
                    fault_addr: current_addr,
                    prefetch_start: next_addr >> 12,
                    prefetch_count: 4,
                    priority: 180,
                    reason: PrefetchReason::WorkingSetPrediction,
                });
            }
        }

        None
    }

    pub fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_prefetch(&self, page_count: usize) {
        self.total_prefetched
            .fetch_add(page_count as u64, Ordering::Relaxed);
    }

    pub fn stats(&self) -> SwapPrefetchStats {
        SwapPrefetchStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            total_prefetched: self.total_prefetched.load(Ordering::Relaxed),
            enabled: self.is_enabled(),
        }
    }

    pub fn hit_rate(&self) -> f32 {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        if total == 0 { 0.0 } else { (hits as f32 / total as f32) * 100.0 }
    }
}

/// スワップ先読み統計
#[derive(Debug, Clone, Copy)]
pub struct SwapPrefetchStats {
    pub hits: u64,
    pub misses: u64,
    pub total_prefetched: u64,
    pub enabled: bool,
}

pub static SWAP_PREFETCHER: SwapPrefetcher = SwapPrefetcher::new();

pub fn prefetch_hint_on_fault(fault_addr: u64, is_sequential: bool) -> Option<SwapPrefetchHint> {
    SWAP_PREFETCHER.generate_hint(fault_addr, is_sequential)
}

pub fn swap_prefetch_stats() -> SwapPrefetchStats {
    SWAP_PREFETCHER.stats()
}

#[cfg(feature = "qemu-test-export")]
#[path = "../../qemu_tests.rs"]
pub mod qemu_tests;

#[cfg(test)]
#[path = "../../tests.rs"]
mod tests;
