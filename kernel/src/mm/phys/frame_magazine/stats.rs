use super::*;


impl Default for PerCpuMagazineSet {
    fn default() -> Self {
        Self::new(NumaNodeId::new(0))
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// マガジン統計
#[derive(Debug, Default, Clone, Copy)]
pub struct MagazineStats {
    /// Active magazine frame count
    pub active_count: usize,
    /// Spare magazine frame count
    pub spare_count: usize,
    /// Sub-magazine remaining frame count (claimed word)
    pub sub_magazine_count: usize,
    /// Zeroed cache frame count
    pub zeroed_cache_count: usize,
    /// Total allocations
    pub alloc_count: u64,
    /// Total frees
    pub free_count: u64,
    /// Buddy refill count
    pub refill_count: u64,
    /// Buddy drain count
    pub drain_count: u64,
    /// SubMagazine hit count (64x more efficient than regular alloc)
    pub sub_magazine_hits: u64,
    /// Zeroed cache hit count
    pub zeroed_cache_hits: u64,
    /// Detailed zeroed cache statistics
    pub zeroed_cache_stats: ZeroedCacheStats,
}

// ============================================================================
// Global Statistics
// ============================================================================

/// グローバル統計
pub(crate) static GLOBAL_ALLOCS: AtomicU64 = AtomicU64::new(0);
pub(crate) static GLOBAL_FREES: AtomicU64 = AtomicU64::new(0);
pub(crate) static GLOBAL_REFILLS: AtomicU64 = AtomicU64::new(0);
pub(crate) static GLOBAL_DRAINS: AtomicU64 = AtomicU64::new(0);

/// グローバル統計を取得
pub fn global_stats() -> (u64, u64, u64, u64) {
    (
        GLOBAL_ALLOCS.load(Ordering::Relaxed),
        GLOBAL_FREES.load(Ordering::Relaxed),
        GLOBAL_REFILLS.load(Ordering::Relaxed),
        GLOBAL_DRAINS.load(Ordering::Relaxed),
    )
}

// ============================================================================
// Integration with Per-CPU Data
// ============================================================================

/// Per-CPU DataにFrameMagazineを統合するためのヘルパー
pub mod integration {
    use super::*;

    /// per_cpu.rsに追加するフィールド用の型エイリアス
    pub type CpuFrameMagazine = PerCpuMagazineSet;

    /// CPUローカルのマガジンから割り当て
    ///
    /// # Safety
    /// 割り込み禁止状態で呼び出すこと
    #[inline]
    pub unsafe fn alloc_from_local_magazine(magazine: &mut PerCpuMagazineSet) -> Option<PhysFrame<Size4KiB>> {
        magazine.alloc()
    }

    /// CPUローカルのマガジンへ解放
    ///
    /// # Safety
    /// 割り込み禁止状態で呼び出すこと
    #[inline]
    pub unsafe fn free_to_local_magazine(magazine: &mut PerCpuMagazineSet, frame: PhysFrame<Size4KiB>) {
        magazine.free(frame);
    }
}
