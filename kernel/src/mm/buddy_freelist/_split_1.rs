use super::*;


/// FreeListBuddy統計情報
#[derive(Debug, Clone, Copy)]
pub struct FreeListBuddyStats {
    pub total_frames: usize,
    pub free_frames: u64,
    pub split_count: u64,
    pub coalesce_count: u64,
    pub fallback_count: u64,
    /// 各オーダーの (空きブロック数, 総フレーム数)
    pub order_stats: [(usize, usize); MAX_ORDER + 1],
    /// モビリティタイプ別の割り当て数
    pub migrate_stats: [u64; MigrateType::COUNT],
}

// x86_64 crateのFrameAllocatorトレイトを実装
unsafe impl FrameAllocator<Size4KiB> for FreeListBuddyAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.allocate_4k_frame()
    }
}

// ============================================================================
// ページ割り当てフラグ（GFP相当）
// ============================================================================

/// ページ割り当てフラグ
#[derive(Debug, Clone, Copy)]
pub struct AllocFlags(u32);

impl AllocFlags {
    /// 通常のカーネル割り当て（Unmovable）
    pub const KERNEL: Self = Self(0);
    /// ユーザー空間用（Movable）
    pub const USER: Self = Self(1 << 0);
    /// ハイメモリ許可
    pub const HIGHMEM: Self = Self(1 << 1);
    /// DMA用（低メモリ必須）
    pub const DMA: Self = Self(1 << 2);
    /// ゼロクリア済みを要求
    pub const ZERO: Self = Self(1 << 3);
    /// 待機可能（スリープ許可）
    pub const WAIT: Self = Self(1 << 4);
    /// 高優先度（予約から借用可）
    pub const HIGH: Self = Self(1 << 5);
    /// Reclaimable
    pub const RECLAIMABLE: Self = Self(1 << 6);
    
    #[inline]
    pub fn migrate_type(self) -> MigrateType {
        if self.0 & Self::USER.0 != 0 {
            MigrateType::Movable
        } else if self.0 & Self::RECLAIMABLE.0 != 0 {
            MigrateType::Reclaimable
        } else if self.0 & Self::HIGH.0 != 0 {
            MigrateType::HighAtomic
        } else {
            MigrateType::Unmovable
        }
    }
}

// ============================================================================
// QEMU smoke tests
// ============================================================================

#[cfg(feature = "qemu-test-export")]
#[path = "qemu_tests.rs"]
pub mod qemu_tests;

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

// ============================================================================
// ロック付きラッパー
// ============================================================================

/// スピンロック（割り込み禁止）で保護されたBuddy Allocator
/// 
/// `FreeListBuddyAllocator` は内部可変性を持たない（`&mut self`を要求する）ため、
/// マルチコア環境で共有するにはロックが必要。
/// カーネルアロケータとして使用する場合、割り込みコンテキストからの呼び出しも
/// 考慮して `IrqMutex` を使用する。
pub struct LockedFreeListBuddyAllocator(IrqMutex<FreeListBuddyAllocator>);

impl LockedFreeListBuddyAllocator {
    /// 新しいロック付きアロケータを作成
    pub const fn new() -> Self {
        Self(IrqMutex::new(FreeListBuddyAllocator::new()))
    }

    /// メモリマップに基づいて初期化
    ///
    /// # Safety
    /// - `usable_regions` は正しい使用可能メモリ領域を示す必要がある
    /// - カーネル初期化時に一度だけ呼ばれること
    pub unsafe fn init_from_regions(&self, usable_regions: &[(PhysAddr, u64)]) {
        unsafe { self.0.lock().init(usable_regions); }
    }

    /// ページ記述子配列を設定（初期化）
    ///
    /// # Safety
    /// `FreeListBuddyAllocator::set_page_descriptors` を参照
    pub unsafe fn init(
        &self,
        descriptors: &'static mut [PageDescriptor],
        total_frames: usize,
    ) {
        self.0.lock().set_page_descriptors(descriptors, total_frames);
    }

    /// フレームを割り当て
    pub fn allocate(
        &self,
        order: usize,
        migrate_type: MigrateType,
    ) -> Option<FrameIndex> {
        self.0.lock().allocate(order, migrate_type)
    }

    /// フレームを解放
    pub fn deallocate(&self, frame: FrameIndex, order: usize) {
        self.0.lock().deallocate(frame, order)
    }

    /// カラーリング対応割り当て
    pub fn allocate_with_color(
        &self,
        order: usize,
        migrate_type: MigrateType,
        preferred_color: u8,
    ) -> Option<FrameIndex> {
        self.0.lock().allocate_with_color(order, migrate_type, preferred_color)
    }

    /// 4KiBフレームを割り当て
    pub fn allocate_4k_frame(&self) -> Option<PhysFrame<Size4KiB>> {
        self.0.lock().allocate_4k_frame()
    }

    /// 2MiBフレームを割り当て
    pub fn allocate_2m_frame(&self) -> Option<PhysFrame<Size2MiB>> {
        self.0.lock().allocate_2m_frame()
    }

    /// 1GiBフレームを割り当て
    pub fn allocate_1g_frame(&self) -> Option<PhysFrame<Size1GiB>> {
        self.0.lock().allocate_1g_frame()
    }

    /// 4KiBフレームを解放
    pub fn deallocate_4k_frame(&self, frame: PhysFrame<Size4KiB>) {
        self.0.lock().deallocate_4k_frame(frame);
    }

    /// 2MiBフレームを解放
    pub fn deallocate_2m_frame(&self, frame: PhysFrame<Size2MiB>) {
        self.0.lock().deallocate_2m_frame(frame);
    }

    /// 1GiBフレームを解放
    pub fn deallocate_1g_frame(&self, frame: PhysFrame<Size1GiB>) {
        self.0.lock().deallocate_1g_frame(frame);
    }

    /// 統計: 空きフレーム数
    pub fn free_count(&self) -> u64 {
        self.0.lock().free_count()
    }

    /// 統計: 総フレーム数
    pub fn total_count(&self) -> usize {
        self.0.lock().total_count()
    }

    /// 詳細統計情報を取得
    pub fn stats(&self) -> FreeListBuddyStats {
        self.0.lock().stats()
    }
}

// ============================================================================
// グローバルインスタンスとモジュールレベルAPI
// ============================================================================

/// グローバルなFreeListBuddy Allocator
pub(crate) static FREELIST_BUDDY: LockedFreeListBuddyAllocator = LockedFreeListBuddyAllocator::new();

/// FreeListBuddy Allocatorを初期化
///
/// # Safety
/// - `usable_regions` は正しい使用可能メモリ領域を示すこと
/// - カーネル初期化時に一度だけ呼ばれること
pub unsafe fn init_freelist_buddy(usable_regions: &[(PhysAddr, u64)]) {
    unsafe { FREELIST_BUDDY.init_from_regions(usable_regions); }
}

/// 4KiBフレームを割り当て
pub fn freelist_alloc_frame() -> Option<PhysFrame<Size4KiB>> {
    FREELIST_BUDDY.allocate_4k_frame()
}

/// 2MiBフレームを割り当て
pub fn freelist_alloc_frame_2m() -> Option<PhysFrame<Size2MiB>> {
    FREELIST_BUDDY.allocate_2m_frame()
}

/// 1GiBフレームを割り当て
pub fn freelist_alloc_frame_1g() -> Option<PhysFrame<Size1GiB>> {
    FREELIST_BUDDY.allocate_1g_frame()
}

/// 4KiBフレームを解放
pub fn freelist_dealloc_frame(frame: PhysFrame<Size4KiB>) {
    FREELIST_BUDDY.deallocate_4k_frame(frame);
}

/// 2MiBフレームを解放
pub fn freelist_dealloc_frame_2m(frame: PhysFrame<Size2MiB>) {
    FREELIST_BUDDY.deallocate_2m_frame(frame);
}

/// 1GiBフレームを解放
pub fn freelist_dealloc_frame_1g(frame: PhysFrame<Size1GiB>) {
    FREELIST_BUDDY.deallocate_1g_frame(frame);
}

/// 統計情報を取得
pub fn freelist_buddy_stats() -> FreeListBuddyStats {
    FREELIST_BUDDY.stats()
}
