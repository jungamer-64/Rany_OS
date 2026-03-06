// ============================================================================
// src/mm/page_table_cache.rs - Page Table Quicklist Cache
//
// ページテーブルページ専用のキャッシュ（Quicklist）。
// 頻繁なプロセス生成/破棄でページテーブルの確保・解放がボトルネックに
// なることを防ぐ。
//
// ## 設計
//
// 1. **Quicklist**: CPUローカルのゼロクリア済みページキャッシュ
// 2. **RCU遅延再利用**: TLB Shootdown問題を回避するための遅延キュー
// 3. **バッチ処理**: まとめて解放してロックオーバーヘッドを削減
//
// ## ページテーブルページの特性
//
// - 常に4KiB
// - 初期状態は全て0（全エントリがNotPresent）
// - 解放後も再利用時にゼロクリア不要（RCU猶予期間後）
//
// ## TLB Shootdown問題
//
// ページテーブルページを解放しても、他CPUのTLBにキャッシュされている
// 可能性がある。即座に再利用すると、古いTLBエントリが新しいデータを
// 参照してしまう危険がある。
//
// 解決策: RCU的なアプローチで、全CPUのコンテキストスイッチを待ってから
// 再利用リストに加える。
// ============================================================================
#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use x86_64::PhysAddr;
use x86_64::structures::paging::{PhysFrame, Size4KiB};

use crate::mm::phys::buddy_allocator;
use crate::mm::types::NumaNodeId;

// ============================================================================
// Configuration
// ============================================================================

/// CPUローカルQuicklistの容量
pub const QUICKLIST_CAPACITY: usize = 64;

/// RCU猶予期間の近似値（コンテキストスイッチ回数）
/// この回数のスイッチを待ってから再利用する
pub const RCU_GRACE_PERIOD_SWITCHES: u64 = 2;

/// バッチ返却のトリガー閾値
pub const BATCH_RETURN_THRESHOLD: usize = QUICKLIST_CAPACITY / 2;

// ============================================================================
// Quicklist Entry
// ============================================================================

/// Quicklistエントリ
#[derive(Clone, Copy)]
struct QuicklistEntry {
    /// ページの物理アドレス
    frame_addr: u64,
    /// 解放時のグローバルカウンタ値（RCU猶予期間用）
    release_epoch: u64,
}

impl QuicklistEntry {
    const fn empty() -> Self {
        Self {
            frame_addr: 0,
            release_epoch: 0,
        }
    }

    fn new(frame: PhysFrame<Size4KiB>, epoch: u64) -> Self {
        Self {
            frame_addr: frame.start_address().as_u64(),
            release_epoch: epoch,
        }
    }

    fn is_empty(&self) -> bool {
        self.frame_addr == 0
    }

    fn to_frame(&self) -> PhysFrame<Size4KiB> {
        unsafe { PhysFrame::from_start_address_unchecked(PhysAddr::new(self.frame_addr)) }
    }
}

// ============================================================================
// Per-CPU Quicklist
// ============================================================================

/// CPUごとのページテーブルQuicklist
pub struct PtQuicklist {
    /// 即座に再利用可能なページ（RCU猶予期間経過済み）
    ready: [QuicklistEntry; QUICKLIST_CAPACITY],
    /// RCU猶予期間待ちのページ
    pending: [QuicklistEntry; QUICKLIST_CAPACITY],
    /// readyリストの有効エントリ数
    ready_count: usize,
    /// pendingリストの有効エントリ数
    pending_count: usize,
    /// 所属NUMAノード
    numa_node: NumaNodeId,
    /// 統計: 割り当て回数
    alloc_count: u64,
    /// 統計: 解放回数
    free_count: u64,
    /// 統計: Buddyへの返却回数
    buddy_returns: u64,
}

impl PtQuicklist {
    /// 新しいQuicklistを作成
    pub const fn new(numa_node: NumaNodeId) -> Self {
        Self {
            ready: [QuicklistEntry::empty(); QUICKLIST_CAPACITY],
            pending: [QuicklistEntry::empty(); QUICKLIST_CAPACITY],
            ready_count: 0,
            pending_count: 0,
            numa_node,
            alloc_count: 0,
            free_count: 0,
            buddy_returns: 0,
        }
    }

    /// ゼロクリア済みページを割り当て
    ///
    /// Quicklistから取得できればそれを返し、なければBuddyから新規割り当て。
    pub fn alloc(&mut self) -> Option<PhysFrame<Size4KiB>> {
        // 1. readyリストから取得（最速）
        if self.ready_count > 0 {
            self.ready_count -= 1;
            let entry = self.ready[self.ready_count];
            self.ready[self.ready_count] = QuicklistEntry::empty();
            self.alloc_count += 1;
            return Some(entry.to_frame());
        }

        // 2. pendingをチェックしてreadyに移動
        self.process_pending();
        if self.ready_count > 0 {
            self.ready_count -= 1;
            let entry = self.ready[self.ready_count];
            self.ready[self.ready_count] = QuicklistEntry::empty();
            self.alloc_count += 1;
            return Some(entry.to_frame());
        }

        // 3. Buddyから新規割り当て
        // prefer_zeroed APIを使用（存在しなければ通常版）
        buddy_allocator::buddy_alloc_frame().map(|frame| {
            // ゼロクリア
            unsafe {
                // 物理アドレスから直接マッピング経由で仮想アドレスを取得
                let phys = frame.start_address().as_u64();
                // HigherHalfのオフセットを使用
                let virt = phys + crate::mm::virt::mapping::physical_memory_offset();
                core::ptr::write_bytes(virt as *mut u8, 0, 4096);
            }
            self.alloc_count += 1;
            frame
        })
    }

    /// ページテーブルページを解放
    ///
    /// 即座に再利用せず、RCU猶予期間を設けてpendingに追加。
    pub fn free(&mut self, frame: PhysFrame<Size4KiB>) {
        let epoch = global_epoch();

        // pendingが満杯ならBuddyに返却
        if self.pending_count >= QUICKLIST_CAPACITY {
            self.flush_oldest_pending();
        }

        // pendingに追加
        self.pending[self.pending_count] = QuicklistEntry::new(frame, epoch);
        self.pending_count += 1;
        self.free_count += 1;

        // 定期的にpendingを処理
        if self.pending_count >= BATCH_RETURN_THRESHOLD {
            self.process_pending();
        }
    }

    /// pending -> ready の移動処理
    ///
    /// RCU猶予期間が経過したエントリをreadyに移動。
    fn process_pending(&mut self) {
        let mut i = 0;

        while i < self.pending_count {
            let entry = self.pending[i];

            // 強化されたRCUチェック：quiescent epochを使用
            if is_safe_to_reuse(entry.release_epoch) {
                // readyに移動
                if self.ready_count < QUICKLIST_CAPACITY {
                    self.ready[self.ready_count] = entry;
                    self.ready_count += 1;
                } else {
                    // readyも満杯ならBuddyに返却
                    buddy_allocator::buddy_dealloc_frame(entry.to_frame());
                    self.buddy_returns += 1;
                }

                // pendingから削除（最後のエントリで置き換え）
                self.pending_count -= 1;
                if i < self.pending_count {
                    self.pending[i] = self.pending[self.pending_count];
                }
                self.pending[self.pending_count] = QuicklistEntry::empty();
            } else {
                i += 1;
            }
        }
    }

    /// 最も古いpendingエントリをBuddyに返却
    fn flush_oldest_pending(&mut self) {
        if self.pending_count == 0 {
            return;
        }

        // 最も古いエントリを見つける
        let mut oldest_idx = 0;
        let mut oldest_epoch = self.pending[0].release_epoch;
        for i in 1..self.pending_count {
            if self.pending[i].release_epoch < oldest_epoch {
                oldest_epoch = self.pending[i].release_epoch;
                oldest_idx = i;
            }
        }

        // Buddyに返却
        let entry = self.pending[oldest_idx];
        buddy_allocator::buddy_dealloc_frame(entry.to_frame());
        self.buddy_returns += 1;

        // 削除
        self.pending_count -= 1;
        if oldest_idx < self.pending_count {
            self.pending[oldest_idx] = self.pending[self.pending_count];
        }
        self.pending[self.pending_count] = QuicklistEntry::empty();
    }

    /// 全てのキャッシュをBuddyに返却
    pub fn flush_all(&mut self) {
        // readyを返却
        for i in 0..self.ready_count {
            let entry = self.ready[i];
            if !entry.is_empty() {
                buddy_allocator::buddy_dealloc_frame(entry.to_frame());
                self.buddy_returns += 1;
            }
            self.ready[i] = QuicklistEntry::empty();
        }
        self.ready_count = 0;

        // pendingを返却
        for i in 0..self.pending_count {
            let entry = self.pending[i];
            if !entry.is_empty() {
                buddy_allocator::buddy_dealloc_frame(entry.to_frame());
                self.buddy_returns += 1;
            }
            self.pending[i] = QuicklistEntry::empty();
        }
        self.pending_count = 0;
    }

    /// 統計情報を取得
    pub fn stats(&self) -> QuicklistStats {
        QuicklistStats {
            ready_count: self.ready_count,
            pending_count: self.pending_count,
            alloc_count: self.alloc_count,
            free_count: self.free_count,
            buddy_returns: self.buddy_returns,
        }
    }
}

impl Default for PtQuicklist {
    fn default() -> Self {
        Self::new(NumaNodeId::new(0))
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Quicklist統計
#[derive(Debug, Default, Clone, Copy)]
pub struct QuicklistStats {
    pub ready_count: usize,
    pub pending_count: usize,
    pub alloc_count: u64,
    pub free_count: u64,
    pub buddy_returns: u64,
}

// ============================================================================
// Global Epoch Counter (Enhanced RCU)
// ============================================================================

/// グローバルエポックカウンタ
///
/// コンテキストスイッチごとにインクリメントされる。
/// 簡易的なRCU猶予期間の計測に使用。
static GLOBAL_EPOCH: AtomicU64 = AtomicU64::new(0);

/// 最後に全CPUが静止状態だったエポック
static QUIESCENT_EPOCH: AtomicU64 = AtomicU64::new(0);

/// 各CPU（最大64）が最後に静止状態を通過したエポック
static CPU_EPOCHS: [AtomicU64; 64] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; 64]
};

/// アクティブCPU数
static ACTIVE_CPU_COUNT: AtomicUsize = AtomicUsize::new(1);

/// 現在のグローバルエポックを取得
#[inline]
pub fn global_epoch() -> u64 {
    GLOBAL_EPOCH.load(Ordering::Acquire)
}

/// 確定した静止エポックを取得
/// この値以前にリリースされたリソースは安全に再利用可能
#[inline]
pub fn quiescent_epoch() -> u64 {
    QUIESCENT_EPOCH.load(Ordering::Acquire)
}

/// グローバルエポックを進める
///
/// コンテキストスイッチ時に呼び出す。
#[inline]
pub fn advance_epoch() {
    GLOBAL_EPOCH.fetch_add(1, Ordering::Release);
}

/// CPUが静止状態を通過したことを記録
///
/// コンテキストスイッチ時に各CPUから呼び出す。
/// これによりRCUグレースピリオドが確定する。
#[inline]
pub fn cpu_pass_quiescent_state(cpu_id: usize) {
    if cpu_id >= 64 {
        return;
    }

    let current = global_epoch();
    CPU_EPOCHS[cpu_id].store(current, Ordering::Release);

    // 全CPUの最小エポックを計算してquiescent epochを更新
    update_quiescent_epoch();
}

/// アクティブCPU数を設定
pub fn set_active_cpu_count(count: usize) {
    ACTIVE_CPU_COUNT.store(count.min(64), Ordering::Release);
}

/// 全CPUの静止エポックから最小値を計算
fn update_quiescent_epoch() {
    let mut min_epoch = u64::MAX;
    let current = global_epoch();
    let cpu_count = ACTIVE_CPU_COUNT.load(Ordering::Acquire);

    // アクティブCPUの最小エポックを取得
    for i in 0..cpu_count.min(64) {
        let cpu_epoch = CPU_EPOCHS[i].load(Ordering::Acquire);
        if cpu_epoch > 0 && cpu_epoch < min_epoch {
            min_epoch = cpu_epoch;
        }
    }

    // 有効な値がない場合は現在値-1を使用
    if min_epoch == u64::MAX {
        min_epoch = current.saturating_sub(RCU_GRACE_PERIOD_SWITCHES);
    }

    // 最小値が増加した場合のみ更新（monotonic）
    let old = QUIESCENT_EPOCH.load(Ordering::Relaxed);
    if min_epoch > old {
        let _ =
            QUIESCENT_EPOCH.compare_exchange(old, min_epoch, Ordering::Release, Ordering::Relaxed);
    }
}

/// リソースが安全に再利用可能かチェック
///
/// release_epochがquiescent_epoch以下なら安全
#[inline]
pub fn is_safe_to_reuse(release_epoch: u64) -> bool {
    release_epoch <= quiescent_epoch()
}

// ============================================================================
// Global Page Table Cache Manager
// ============================================================================

/// グローバルページテーブルキャッシュマネージャ
///
/// 複数のQuicklistを管理し、グローバルな統計を提供。
pub struct PageTableCacheManager {
    /// 統計: 総割り当て数
    total_allocs: AtomicU64,
    /// 統計: 総解放数
    total_frees: AtomicU64,
}

impl PageTableCacheManager {
    pub const fn new() -> Self {
        Self {
            total_allocs: AtomicU64::new(0),
            total_frees: AtomicU64::new(0),
        }
    }

    /// 割り当てを記録
    pub fn record_alloc(&self) {
        self.total_allocs.fetch_add(1, Ordering::Relaxed);
    }

    /// 解放を記録
    pub fn record_free(&self) {
        self.total_frees.fetch_add(1, Ordering::Relaxed);
    }

    /// グローバル統計を取得
    pub fn global_stats(&self) -> (u64, u64) {
        (
            self.total_allocs.load(Ordering::Relaxed),
            self.total_frees.load(Ordering::Relaxed),
        )
    }
}

/// グローバルマネージャ
static PT_CACHE_MANAGER: PageTableCacheManager = PageTableCacheManager::new();

/// グローバル統計を取得
pub fn page_table_cache_stats() -> (u64, u64) {
    PT_CACHE_MANAGER.global_stats()
}

// ============================================================================
// Public API
// ============================================================================

/// ページテーブルページを割り当て（ゼロクリア済み）
///
/// CPUローカルのQuicklistがない場合、直接Buddyから割り当て。
pub fn alloc_page_table_page() -> Option<PhysFrame<Size4KiB>> {
    // 現時点ではBuddyから直接割り当て
    // 将来的にはPer-CPU Quicklistを使用
    let frame = buddy_allocator::buddy_alloc_frame()?;

    // ゼロクリア
    unsafe {
        let phys = frame.start_address().as_u64();
        let virt = phys + crate::mm::virt::mapping::physical_memory_offset();
        core::ptr::write_bytes(virt as *mut u8, 0, 4096);
    }

    PT_CACHE_MANAGER.record_alloc();
    Some(frame)
}

/// ページテーブルページを解放
///
/// RCU猶予期間後に再利用可能になる。
pub fn free_page_table_page(frame: PhysFrame<Size4KiB>) {
    // 解放前にDMA保護を解除
    crate::security::dma::unregister_protected_page(frame.start_address().as_u64());

    // 現時点ではBuddyに直接返却
    // 将来的にはPer-CPU Quicklistに追加
    buddy_allocator::buddy_dealloc_frame(frame);
    PT_CACHE_MANAGER.record_free();
}
