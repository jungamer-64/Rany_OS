// ============================================================================
// 統一フレームアロケータインターフェース
//
// 設計方針:
// - PMM fast allocator（bitmap + per-CPU magazine）を主経路
// - BuddyはPMMから借りたプールとして動作（別管理はしない）
// - 新規コードは UnifiedFrameAllocator を使用すること
// ============================================================================

use x86_64::structures::paging::{PhysFrame, Size1GiB, Size2MiB, Size4KiB};

use super::frame_allocator::{
    alloc_frame, alloc_frame_1g, alloc_frame_2m,
    dealloc_frame, dealloc_frame_1g, dealloc_frame_2m,
    frame_allocator_stats,
};
use super::buddy_allocator::buddy_allocator_stats;
use crate::loader::type_id::{TypeIdHash, TypeHash, SemVer, const_hash};

/// フレームアロケータの種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameAllocatorType {
    /// ビットマップベースのシンプルなアロケータ
    Bitmap,
    /// バディシステムベースの高効率アロケータ
    Buddy,
}

/// 統一フレームアロケータAPI
///
/// 設計書 5.1: 物理メモリは4KBページ単位で管理
/// ビットマップとバディの両方を透過的に使用可能
pub struct UnifiedFrameAllocator;

impl UnifiedFrameAllocator {
    /// 4KBフレームを割り当て
    ///
    /// デフォルトでPMM fastを使用（後方互換フォールバックあり）
    pub fn alloc_4k() -> Option<PhysFrame<Size4KiB>> {
        alloc_frame()
    }

    /// 2MBフレームを割り当て
    pub fn alloc_2m() -> Option<PhysFrame<Size2MiB>> {
        alloc_frame_2m()
    }

    /// 1GBフレームを割り当て
    pub fn alloc_1g() -> Option<PhysFrame<Size1GiB>> {
        alloc_frame_1g()
    }

    /// 4KBフレームを解放
    ///
    /// PMM fast へ返却
    pub fn dealloc_4k(frame: PhysFrame<Size4KiB>) {
        dealloc_frame(frame);
    }

    /// 2MBフレームを解放
    pub fn dealloc_2m(frame: PhysFrame<Size2MiB>) {
        dealloc_frame_2m(frame);
    }

    /// 1GBフレームを解放
    pub fn dealloc_1g(frame: PhysFrame<Size1GiB>) {
        dealloc_frame_1g(frame);
    }

    // ====================================================================
    // ユーザーページ用 API（buddy_freelist feature 有効時に専用パスを使用）
    // ====================================================================

    /// 4KBフレームを割り当て（ユーザーページ用）
    ///
    /// buddy_freelist feature 有効時はページモビリティ対応の
    /// FreeListBuddyAllocator を使用。無効時・枯渇時は PMM にフォールバック。
    pub fn alloc_4k_user() -> Option<PhysFrame<Size4KiB>> {
        #[cfg(feature = "buddy_freelist")]
        {
            if let Some(frame) = super::buddy_freelist::freelist_alloc_frame() {
                return Some(frame);
            }
        }
        alloc_frame()
    }

    /// 2MBフレームを割り当て（ユーザーページ用）
    ///
    /// buddy_freelist feature 有効時はページモビリティによる断片化防止の恩恵を受ける。
    pub fn alloc_2m_user() -> Option<PhysFrame<Size2MiB>> {
        #[cfg(feature = "buddy_freelist")]
        {
            if let Some(frame) = super::buddy_freelist::freelist_alloc_frame_2m() {
                return Some(frame);
            }
        }
        alloc_frame_2m()
    }

    /// 4KBフレームを解放（ユーザーページ用）
    ///
    /// buddy_freelist feature 有効時は FreeListBuddyAllocator へ返却。
    pub fn dealloc_4k_user(frame: PhysFrame<Size4KiB>) {
        #[cfg(feature = "buddy_freelist")]
        {
            super::buddy_freelist::freelist_dealloc_frame(frame);
            return;
        }
        #[cfg(not(feature = "buddy_freelist"))]
        dealloc_frame(frame);
    }

    /// 2MBフレームを解放（ユーザーページ用）
    pub fn dealloc_2m_user(frame: PhysFrame<Size2MiB>) {
        #[cfg(feature = "buddy_freelist")]
        {
            super::buddy_freelist::freelist_dealloc_frame_2m(frame);
            return;
        }
        #[cfg(not(feature = "buddy_freelist"))]
        dealloc_frame_2m(frame);
    }

    /// 統計を取得
    pub fn stats() -> UnifiedAllocatorStats {
        let (pmm_free, pmm_total_usize) = frame_allocator_stats();
        let buddy = buddy_allocator_stats();

        #[cfg(feature = "buddy_freelist")]
        let (fl_total, fl_free) = {
            let s = super::buddy_freelist::freelist_buddy_stats();
            (s.total_frames as u64, s.free_frames)
        };
        #[cfg(not(feature = "buddy_freelist"))]
        let (fl_total, fl_free) = (0u64, 0u64);

        UnifiedAllocatorStats {
            pmm_total: pmm_total_usize as u64,
            pmm_free,
            buddy_pool_total: buddy.total_frames as u64,
            buddy_pool_free: buddy.free_frames as u64,
            freelist_total: fl_total,
            freelist_free: fl_free,
        }
    }
}

impl TypeIdHash for UnifiedFrameAllocator {
    fn type_id_hash() -> TypeHash {
        const_hash(b"UnifiedFrameAllocator:v1:alloc_4k,alloc_2m,alloc_1g,dealloc_4k,dealloc_2m,dealloc_1g")
    }

    fn type_name() -> &'static str {
        "UnifiedFrameAllocator"
    }

    fn type_version() -> SemVer {
        SemVer::new(1, 0, 0)
    }
}

/// 統一アロケータ統計
#[derive(Debug, Clone, Copy)]
pub struct UnifiedAllocatorStats {
    /// PMM fast の総フレーム数
    pub pmm_total: u64,
    /// PMM fast の空きフレーム数
    pub pmm_free: u64,
    /// Buddyプールの総フレーム数（PMMから借りているサブセット）
    pub buddy_pool_total: u64,
    /// Buddyプールの空きフレーム数
    pub buddy_pool_free: u64,
    /// FreeListBuddy の総フレーム数（buddy_freelist feature 有効時のみ非ゼロ）
    pub freelist_total: u64,
    /// FreeListBuddy の空きフレーム数
    pub freelist_free: u64,
}

impl UnifiedAllocatorStats {
    /// 総フレーム数（PMMベース）
    pub fn total_frames(&self) -> u64 {
        self.pmm_total
    }

    /// PMM使用フレーム数
    pub fn pmm_used_frames(&self) -> u64 {
        self.pmm_total.saturating_sub(self.pmm_free)
    }

    /// PMM空きフレーム数
    pub fn free_frames(&self) -> u64 {
        self.pmm_free
    }

    /// Buddyプール使用フレーム数
    pub fn buddy_pool_used_frames(&self) -> u64 {
        self.buddy_pool_total.saturating_sub(self.buddy_pool_free)
    }

    /// FreeListBuddy使用フレーム数
    pub fn freelist_used_frames(&self) -> u64 {
        self.freelist_total.saturating_sub(self.freelist_free)
    }
}

// ============================================================================
// Memory Pressure Detection
// ============================================================================

/// Get the current memory pressure level (0-100).
///
/// Returns:
/// - 0-25: Low pressure (plenty of free memory)
/// - 25-50: Medium pressure (consider cleanup)
/// - 50-75: High pressure (aggressive cleanup needed)
/// - 75-100: Critical pressure (emergency measures)
///
/// The pressure is calculated based on the percentage of used physical frames
/// from the buddy allocator, with adjustments for free page count thresholds.
pub fn memory_pressure_level() -> u8 {
    let stats = buddy_allocator_stats();

    if stats.total_frames == 0 {
        return 0; // No memory tracked yet
    }

    // Calculate usage percentage
    let used = stats.total_frames.saturating_sub(stats.free_frames as usize);
    let usage_percent = (used * 100 / stats.total_frames) as u8;

    // Apply thresholds for more nuanced pressure detection
    // If we have less than 1GB free (262144 4KB frames), increase pressure
    const LOW_FREE_THRESHOLD: u64 = 262144; // ~1GB
    const CRITICAL_FREE_THRESHOLD: u64 = 65536; // ~256MB

    let pressure = if stats.free_frames < CRITICAL_FREE_THRESHOLD {
        // Critical: less than 256MB free
        core::cmp::max(usage_percent, 80)
    } else if stats.free_frames < LOW_FREE_THRESHOLD {
        // Low free memory: apply mild boost
        core::cmp::min(usage_percent.saturating_add(10), 100)
    } else {
        usage_percent
    };

    pressure
}
