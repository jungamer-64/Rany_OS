// ============================================================================
// src/mm/frame_magazine.rs - Per-CPU Frame Magazine (PCP)
//
// CPUごとの物理フレームキャッシュ（マガジン）を実装。
// Order 0 (4KiB) フレームをロックフリーでCPUローカルにキャッシュし、
// 高頻度のalloc/free操作をBuddyアロケータへのアクセスなしで処理する。
//
// ## 設計
//
// - 各CPUは2つのマガジンを持つ: Active (使用中) と Spare (予備)
// - Activeが空になったらSpareと交換
// - 両方空ならBuddyから補充
// - 両方満杯ならBuddyへ返却
//
// ## パフォーマンス特性
//
// - Hot Path (マガジンあり): ロックなし、数十サイクル
// - Cold Path (補充/返却): Per-Node Buddyロック取得、数百サイクル
//
// ## 参考
//
// - Linux PCP (Per-CPU Pageset)
// - FreeBSD UMA Magazine layer
// ============================================================================
use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::PhysAddr;
use x86_64::structures::paging::{PhysFrame, Size4KiB};

use super::buddy_allocator;
use super::per_node_buddy;
use crate::mm::types::NumaNodeId;

// ============================================================================
// Configuration
// ============================================================================

/// マガジンの容量（フレーム数）
mod stats;
pub use stats::*;
pub const MAGAZINE_CAPACITY: usize = 32;

/// バッチ補充時のフレーム数
pub const REFILL_BATCH: usize = 16;

/// バッチ返却のトリガー閾値
pub const DRAIN_THRESHOLD: usize = MAGAZINE_CAPACITY - 4;

/// Per-CPU ゼロクリア済みフレームキャッシュ容量
/// グローバルプールへのロック頻度を減らすため、各CPUがローカルにキャッシュ
pub const ZEROED_CACHE_CAPACITY: usize = 16;

/// ゼロクリア済みキャッシュのバッチ補充サイズ
pub const ZEROED_REFILL_BATCH: usize = 8;

/// 4KiBページサイズ
const PAGE_SIZE_4K: u64 = 4096;

// ============================================================================
// Adaptive Batch Size
// ============================================================================

/// Adaptive Batch Size - 最小値
const ADAPTIVE_BATCH_MIN: usize = 8;

/// Adaptive Batch Size - 最大値
const ADAPTIVE_BATCH_MAX: usize = 32;

/// Adaptive Batch Size - 調整間隔（割り当て回数）
const ADAPTIVE_ADJUST_INTERVAL: u64 = 64;

/// Adaptive Batch Size - 高頻度判定閾値（調整間隔内でのrefill回数）
const ADAPTIVE_HIGH_FREQUENCY_THRESHOLD: u64 = 4;

/// Adaptive batch configuration for dynamic refill/drain sizing
///
/// Adjusts batch size based on allocation frequency:
/// - High frequency allocation → larger batches (reduce Buddy lock contention)
/// - Low frequency allocation → smaller batches (reduce memory waste)
#[derive(Debug, Clone, Copy)]
pub struct AdaptiveBatchConfig {
    /// Current batch size (range: ADAPTIVE_BATCH_MIN..=ADAPTIVE_BATCH_MAX)
    pub current_batch: usize,
    /// Refill count in current adjustment window
    refills_in_window: u64,
    /// Allocations since last adjustment
    allocs_since_adjust: u64,
}

impl AdaptiveBatchConfig {
    /// Create new adaptive config with default batch size
    pub const fn new() -> Self {
        Self {
            current_batch: REFILL_BATCH, // Start with default
            refills_in_window: 0,
            allocs_since_adjust: 0,
        }
    }

    /// Record an allocation and potentially adjust batch size
    #[inline]
    pub fn record_alloc(&mut self) {
        self.allocs_since_adjust += 1;

        if self.allocs_since_adjust >= ADAPTIVE_ADJUST_INTERVAL {
            self.adjust();
        }
    }

    /// Record a refill event
    #[inline]
    pub fn record_refill(&mut self) {
        self.refills_in_window += 1;
    }

    /// Adjust batch size based on recent activity
    fn adjust(&mut self) {
        if self.refills_in_window >= ADAPTIVE_HIGH_FREQUENCY_THRESHOLD {
            // High frequency: increase batch size (fewer Buddy accesses)
            self.current_batch = (self.current_batch + 4).min(ADAPTIVE_BATCH_MAX);
        } else if self.refills_in_window <= 1 {
            // Low frequency: decrease batch size (less memory waste)
            self.current_batch = self.current_batch.saturating_sub(2).max(ADAPTIVE_BATCH_MIN);
        }
        // else: moderate frequency, keep current batch size

        // Reset window
        self.refills_in_window = 0;
        self.allocs_since_adjust = 0;
    }

    /// Get current effective batch size
    #[inline]
    pub fn batch_size(&self) -> usize {
        self.current_batch
    }
}

impl Default for AdaptiveBatchConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Sub-Frame Magazine (Claimed Word Optimization)
// ============================================================================

/// Sub-magazine for claimed word optimization
///
/// Instead of doing per-frame atomic operations, a CPU can "claim" an entire
/// word (64 frames) using a single `swap(0)` atomic operation, then allocate
/// from that word locally without any synchronization.
///
/// # Benefits
/// - **64 allocations per atomic op**: One swap claims 64 frames
/// - **Zero contention**: Local allocation is pure arithmetic (no CAS loops)
/// - **Perfect for burst allocation**: Common in network packet buffers
///
/// # Lifecycle
/// 1. CPU claims a word via `swap(0)` - word is now "owned" locally
/// 2. Allocate frames by finding set bits in `bits` (local tzcnt)
/// 3. When `bits == 0`, claim another word or fall back to magazine
/// 4. On CPU idle/shutdown, return remaining bits to bitmap
#[repr(C)]
#[derive(Debug)]
pub struct SubFrameMagazine {
    /// Bit mask of available frames (1 = free, 0 = allocated)
    /// When empty (0), need to claim a new word
    bits: u64,
    /// Word index in the source bitmap that this sub-magazine owns
    /// Only valid when bits != 0
    word_idx: usize,
    /// Base physical address for this word (cached for fast address calculation)
    /// Only valid when bits != 0
    base_addr: u64,
}

impl SubFrameMagazine {
    /// Create an empty sub-magazine
    pub const fn new() -> Self {
        Self {
            bits: 0,
            word_idx: 0,
            base_addr: 0,
        }
    }

    /// Check if sub-magazine has available frames
    #[inline]
    pub fn has_frames(&self) -> bool {
        self.bits != 0
    }

    /// Allocate a single frame from the sub-magazine (O(1), no atomics!)
    ///
    /// Returns Some(frame) if successful, None if sub-magazine is empty.
    #[inline]
    pub fn allocate(&mut self) -> Option<PhysFrame<Size4KiB>> {
        if self.bits == 0 {
            return None;
        }

        // Find first set bit (free frame) using tzcnt
        let bit_idx = self.bits.trailing_zeros() as usize;

        // Clear the bit (mark as allocated) - NO ATOMIC!
        self.bits &= !(1u64 << bit_idx);

        // Calculate physical address
        let addr = self.base_addr + (bit_idx as u64) * PAGE_SIZE_4K;

        // Safety check: address must be 4KiB aligned
        debug_assert_eq!(
            addr % PAGE_SIZE_4K,
            0,
            "SubFrameMagazine address is not aligned"
        );

        Some(unsafe { PhysFrame::from_start_address_unchecked(PhysAddr::new(addr)) })
    }

    /// Claim a word from an external source
    ///
    /// # Arguments
    /// * `bits` - The claimed bits (from swap(0))
    /// * `word_idx` - Word index in source bitmap
    /// * `base_addr` - Base physical address for this word
    ///
    /// # Returns
    /// The number of frames claimed (popcount of bits)
    #[inline]
    pub fn claim(&mut self, bits: u64, word_idx: usize, base_addr: u64) -> usize {
        self.bits = bits;
        self.word_idx = word_idx;
        self.base_addr = base_addr;
        bits.count_ones() as usize
    }

    /// Return remaining frames info for giving back to bitmap
    ///
    /// Returns (word_idx, bits) if there are remaining frames, None otherwise.
    #[inline]
    pub fn return_remaining(&mut self) -> Option<(usize, u64)> {
        if self.bits == 0 {
            return None;
        }
        let result = (self.word_idx, self.bits);
        self.bits = 0;
        Some(result)
    }

    /// Get remaining frame count
    #[inline]
    pub fn remaining_count(&self) -> usize {
        self.bits.count_ones() as usize
    }

    /// Get the word index (only valid when has_frames())
    #[inline]
    pub fn word_idx(&self) -> usize {
        self.word_idx
    }
}

impl Default for SubFrameMagazine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Local Free Word Stack (O(1) Non-Empty Word Lookup)
// ============================================================================

/// Per-CPU stack of non-empty word indices
///
/// When a word transitions from empty (0) to non-empty (has free frames),
/// its index is pushed here. On allocation, pop and validate before using.
///
/// # Benefits
/// - **O(1) word discovery**: No need to scan summary hierarchy
/// - **Cache-local**: Indices stay hot in L1/L2
/// - **Lock-free**: Per-CPU, no synchronization needed
///
/// # Capacity
/// 32 entries is sufficient for burst patterns. If full, fall back to
/// normal summary scan.
const LOCAL_FREE_WORD_STACK_CAPACITY: usize = 32;

#[repr(C)]
#[derive(Debug)]
pub struct LocalFreeWordStack {
    /// Word indices (LIFO order)
    entries: [usize; LOCAL_FREE_WORD_STACK_CAPACITY],
    /// Current stack top (next push position)
    top: usize,
}

impl LocalFreeWordStack {
    /// Create an empty stack
    pub const fn new() -> Self {
        Self {
            entries: [0; LOCAL_FREE_WORD_STACK_CAPACITY],
            top: 0,
        }
    }

    /// Check if stack is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.top == 0
    }

    /// Check if stack is full
    #[inline]
    pub fn is_full(&self) -> bool {
        self.top >= LOCAL_FREE_WORD_STACK_CAPACITY
    }

    /// Push a word index (returns false if full)
    #[inline]
    pub fn push(&mut self, word_idx: usize) -> bool {
        if self.is_full() {
            return false;
        }
        self.entries[self.top] = word_idx;
        self.top += 1;
        true
    }

    /// Pop a word index (returns None if empty)
    #[inline]
    pub fn pop(&mut self) -> Option<usize> {
        if self.is_empty() {
            return None;
        }
        self.top -= 1;
        Some(self.entries[self.top])
    }

    /// Clear all entries
    #[inline]
    pub fn clear(&mut self) {
        self.top = 0;
    }

    /// Get current count
    #[inline]
    pub fn len(&self) -> usize {
        self.top
    }
}

impl Default for LocalFreeWordStack {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Zeroed Frame Cache (Per-CPU Cache for Pre-Zeroed Pages)
// ============================================================================

/// Per-CPU ゼロクリア済みフレームキャッシュ
///
/// グローバルな `ZeroedFramePool` へのロック取得を減らすため、
/// 各CPUが少量のゼロクリア済みフレームをローカルにキャッシュする。
///
/// ## 用途
///
/// - ユーザー空間へのページ割り当て（COW、mmap、スタック拡張等）
/// - ページテーブルの割り当て
///
/// ## 動作
///
/// 1. `alloc_zeroed` で要求時、まずローカルキャッシュから取得
/// 2. キャッシュが空なら `ZeroedFramePool` からバッチ補充
/// 3. プールも空ならオンデマンドでゼロクリア
#[repr(C)]
pub struct ZeroedFrameCache {
    /// ゼロクリア済みフレームのアドレス配列
    frames: [u64; ZEROED_CACHE_CAPACITY],
    /// 現在のフレーム数
    count: usize,
    /// 統計: ヒット回数
    hit_count: u64,
    /// 統計: ミス回数（グローバルプールにフォールバック）
    miss_count: u64,
    /// 統計: リフィル回数
    refill_count: u64,
}

impl ZeroedFrameCache {
    /// 空のキャッシュを作成
    pub const fn new() -> Self {
        Self {
            frames: [0; ZEROED_CACHE_CAPACITY],
            count: 0,
            hit_count: 0,
            miss_count: 0,
            refill_count: 0,
        }
    }

    /// キャッシュが空かどうか
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// キャッシュが満杯かどうか
    #[inline]
    pub fn is_full(&self) -> bool {
        self.count >= ZEROED_CACHE_CAPACITY
    }

    /// 現在のフレーム数
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    /// ゼロクリア済みフレームを取得
    #[inline]
    pub fn pop(&mut self) -> Option<PhysFrame<Size4KiB>> {
        if self.count == 0 {
            self.miss_count += 1;
            return None;
        }

        self.count -= 1;
        let addr = self.frames[self.count];
        self.frames[self.count] = 0;
        self.hit_count += 1;

        Some(unsafe { PhysFrame::from_start_address_unchecked(PhysAddr::new(addr)) })
    }

    /// ゼロクリア済みフレームをキャッシュに追加
    #[inline]
    pub fn push(&mut self, frame: PhysFrame<Size4KiB>) -> bool {
        if self.count >= ZEROED_CACHE_CAPACITY {
            return false;
        }

        self.frames[self.count] = frame.start_address().as_u64();
        self.count += 1;
        true
    }

    /// グローバルプールからバッチ補充
    pub fn refill_from_global(&mut self, numa_node: usize) {
        use crate::mm::cache::zeroed_pool;

        for _ in 0..ZEROED_REFILL_BATCH {
            if self.is_full() {
                break;
            }

            if let Some(frame) = zeroed_pool::allocate_zeroed_frame(numa_node) {
                self.push(frame);
            } else {
                break;
            }
        }

        if self.count > 0 {
            self.refill_count += 1;
        }
    }

    /// 統計情報を取得
    pub fn stats(&self) -> ZeroedCacheStats {
        ZeroedCacheStats {
            current_count: self.count,
            hit_count: self.hit_count,
            miss_count: self.miss_count,
            refill_count: self.refill_count,
            hit_rate_percent: if self.hit_count + self.miss_count > 0 {
                (self.hit_count * 100) / (self.hit_count + self.miss_count)
            } else {
                0
            },
        }
    }
}

impl Default for ZeroedFrameCache {
    fn default() -> Self {
        Self::new()
    }
}

/// ゼロクリア済みキャッシュ統計
#[derive(Debug, Default, Clone, Copy)]
pub struct ZeroedCacheStats {
    pub current_count: usize,
    pub hit_count: u64,
    pub miss_count: u64,
    pub refill_count: u64,
    pub hit_rate_percent: u64,
}

// ============================================================================
// Frame Magazine
// ============================================================================

/// 物理フレームのマガジン（スタック構造）
#[repr(C)]
pub struct FrameMagazine {
    /// フレームアドレスの配列（u64で格納、0は空スロット）
    frames: [u64; MAGAZINE_CAPACITY],
    /// 現在の格納数
    count: usize,
}

impl FrameMagazine {
    /// 空のマガジンを作成
    pub const fn new() -> Self {
        Self {
            frames: [0; MAGAZINE_CAPACITY],
            count: 0,
        }
    }

    /// マガジンが空かどうか
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// マガジンが満杯かどうか
    #[inline]
    pub fn is_full(&self) -> bool {
        self.count >= MAGAZINE_CAPACITY
    }

    /// 現在の格納数
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    /// フレームをpush（満杯時はNone）
    #[inline]
    pub fn push(&mut self, frame: PhysFrame<Size4KiB>) -> Result<(), PhysFrame<Size4KiB>> {
        if self.is_full() {
            return Err(frame);
        }
        self.frames[self.count] = frame.start_address().as_u64();
        self.count += 1;
        Ok(())
    }

    /// フレームをpop（空時はNone）
    #[inline]
    pub fn pop(&mut self) -> Option<PhysFrame<Size4KiB>> {
        if self.is_empty() {
            return None;
        }
        self.count -= 1;
        let addr = self.frames[self.count];
        self.frames[self.count] = 0;
        Some(unsafe { PhysFrame::from_start_address_unchecked(PhysAddr::new(addr)) })
    }

    /// 複数フレームを一括pop
    pub fn pop_batch(&mut self, count: usize) -> impl Iterator<Item = PhysFrame<Size4KiB>> + '_ {
        let actual_count = count.min(self.count);
        (0..actual_count).filter_map(move |_| self.pop())
    }
}

impl Default for FrameMagazine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Per-CPU Magazine Set
// ============================================================================

/// CPUごとのマガジンセット（Active + Spare）
///
/// Double-Buffering方式を採用:
/// - Activeが空になったらSpareと即座にswap
/// - バックグラウンドでSpareを非同期リフィル
/// - ホットパスでのBuddyロック競合を最小化
///
/// ## ゼロクリア済みキャッシュ
///
/// ユーザー空間へのページ割り当て（常にゼロクリアが必要）の高速化のため、
/// Per-CPU の zeroed_cache を保持。グローバル ZeroedFramePool へのロック取得を削減。
#[repr(C)]
pub struct PerCpuMagazineSet {
    /// Activeマガジン（通常のalloc/freeで使用）
    active: FrameMagazine,
    /// Spareマガジン（Activeが空/満杯時に交換）
    spare: FrameMagazine,
    /// Sub-magazine for claimed word optimization (64x atomic reduction)
    /// Highest priority in allocation hot path
    sub_magazine: SubFrameMagazine,
    /// ゼロクリア済みフレームのPer-CPUキャッシュ
    /// ユーザー空間ページ割り当て用
    zeroed_cache: ZeroedFrameCache,
    /// 所属NUMAノード
    numa_node: NumaNodeId,
    /// バックグラウンドリフィル要求フラグ
    /// trueの場合、アイドルループでSpareを補充する
    pub refill_pending: core::sync::atomic::AtomicBool,
    /// 統計: 割り当て回数
    alloc_count: u64,
    /// 統計: 解放回数
    free_count: u64,
    /// 統計: 補充回数
    refill_count: u64,
    /// 統計: 返却回数
    drain_count: u64,
    /// 統計: バックグラウンドリフィル回数
    bg_refill_count: u64,
    /// 統計: SubMagazineからの割り当て回数
    sub_magazine_hits: u64,
    /// 統計: ゼロクリア済みキャッシュからの割り当て回数
    zeroed_cache_hits: u64,
    /// Adaptive batch sizing configuration
    adaptive_batch: AdaptiveBatchConfig,
}

impl PerCpuMagazineSet {
    /// 新しいマガジンセットを作成
    pub const fn new(numa_node: NumaNodeId) -> Self {
        Self {
            active: FrameMagazine::new(),
            spare: FrameMagazine::new(),
            sub_magazine: SubFrameMagazine::new(),
            zeroed_cache: ZeroedFrameCache::new(),
            numa_node,
            refill_pending: core::sync::atomic::AtomicBool::new(false),
            alloc_count: 0,
            free_count: 0,
            refill_count: 0,
            drain_count: 0,
            bg_refill_count: 0,
            sub_magazine_hits: 0,
            zeroed_cache_hits: 0,
            adaptive_batch: AdaptiveBatchConfig::new(),
        }
    }

    /// フレームを割り当て（ロックフリー fast path）
    ///
    /// Priority (optimized for burst allocation):
    /// 1. **Fastest**: SubMagazine - 64 allocs per atomic, pure arithmetic
    /// 2. **Fast**: Active magazine pop
    /// 3. **Medium**: Spare <-> Active swap, then pop
    /// 4. **Slow**: Buddy refill
    #[inline]
    pub fn alloc(&mut self) -> Option<PhysFrame<Size4KiB>> {
        // Fastest path: SubMagazine (64 allocs per 1 atomic)
        if let Some(frame) = self.sub_magazine.allocate() {
            self.sub_magazine_hits += 1;
            self.alloc_count += 1;
            self.adaptive_batch.record_alloc();
            return Some(frame);
        }

        // Fast path: Activeから取得
        if let Some(frame) = self.active.pop() {
            self.alloc_count += 1;
            self.adaptive_batch.record_alloc();
            return Some(frame);
        }

        // Medium path: Spareと交換
        if !self.spare.is_empty() {
            core::mem::swap(&mut self.active, &mut self.spare);
            if let Some(frame) = self.active.pop() {
                self.alloc_count += 1;
                self.adaptive_batch.record_alloc();
                // バックグラウンドリフィルをスケジュール（Spareが空になった）
                self.refill_pending
                    .store(true, core::sync::atomic::Ordering::Release);
                return Some(frame);
            }
        }

        // Slow path: Buddyから同期的に補充
        self.refill();
        self.active.pop().map(|frame| {
            self.alloc_count += 1;
            self.adaptive_batch.record_alloc();
            frame
        })
    }

    /// ゼロクリア済みフレームを割り当て（ユーザー空間向け）
    ///
    /// Priority:
    /// 1. **Fastest**: Per-CPU zeroed cache (ロックなし)
    /// 2. **Fast**: グローバル ZeroedFramePool からバッチ補充してから取得
    /// 3. **Slow**: 通常フレームを取得してオンデマンドゼロクリア
    #[inline]
    pub fn alloc_zeroed(&mut self) -> Option<PhysFrame<Size4KiB>> {
        // Fastest path: Per-CPU zeroed cache
        if let Some(frame) = self.zeroed_cache.pop() {
            self.zeroed_cache_hits += 1;
            self.alloc_count += 1;
            return Some(frame);
        }

        // Medium path: グローバルプールからバッチ補充
        self.zeroed_cache
            .refill_from_global(self.numa_node.as_u8() as usize);
        if let Some(frame) = self.zeroed_cache.pop() {
            self.zeroed_cache_hits += 1;
            self.alloc_count += 1;
            return Some(frame);
        }

        // Slow path: 通常フレームを取得してオンデマンドゼロクリア
        if let Some(frame) = self.alloc() {
            // Note: alloc() already incremented alloc_count
            let virt_addr = crate::mm::virt::mapping::phys_to_virt(frame.start_address());
            unsafe {
                // 即座に使うのでキャッシュに載せる標準ゼロクリアを使用
                crate::mm::cache::zeroed_pool::zero_page_standard(virt_addr.as_u64());
            }
            return Some(frame);
        }

        None
    }

    /// フレームを解放（ロックフリー fast path）
    #[inline]
    pub fn free(&mut self, frame: PhysFrame<Size4KiB>) {
        // Fast path: Activeにpush
        if self.active.push(frame).is_ok() {
            self.free_count += 1;
            return;
        }

        // Active満杯: Spareにpush試行
        if let Err(frame) = self.spare.push(frame) {
            // 両方満杯: Buddyへ返却してからpush
            self.drain();
            // drain後は必ず空きがある
            let _ = self.active.push(frame);
            self.free_count += 1;
        } else {
            self.free_count += 1;
        }
    }

    /// Buddyアロケータから補充
    /// Try to fill the active magazine from the given allocator closure.
    fn refill_from<F>(&mut self, mut alloc_fn: F)
    where
        F: FnMut() -> Option<PhysFrame<Size4KiB>>,
    {
        let batch_size = self.adaptive_batch.batch_size();
        for _ in 0..batch_size {
            if let Some(frame) = alloc_fn() {
                if self.active.push(frame).is_err() {
                    break;
                }
            } else {
                break;
            }
        }
    }

    fn refill(&mut self) {
        self.refill_count += 1;
        self.adaptive_batch.record_refill();

        // Per-Node Buddyを優先使用
        if per_node_buddy::is_per_node_initialized() {
            if let Some(allocator) = per_node_buddy::get_node_allocator(self.numa_node) {
                self.refill_from(|| allocator.allocate_4k());
                return;
            }
        }

        // フォールバック: グローバルBuddy
        self.refill_from(buddy_allocator::buddy_alloc_frame);
    }

    /// Buddyアロケータへ返却
    fn drain(&mut self) {
        self.drain_count += 1;

        // Spareの半分を返却
        let drain_count = self.spare.len() / 2;

        if per_node_buddy::is_per_node_initialized() {
            if let Some(allocator) = per_node_buddy::get_node_allocator(self.numa_node) {
                for frame in self.spare.pop_batch(drain_count) {
                    allocator.deallocate_4k(frame);
                }
                return;
            }
        }

        // フォールバック: グローバルBuddy
        for frame in self.spare.pop_batch(drain_count) {
            buddy_allocator::buddy_dealloc_frame(frame);
        }
    }

    /// 統計情報を取得
    pub fn stats(&self) -> MagazineStats {
        MagazineStats {
            active_count: self.active.len(),
            spare_count: self.spare.len(),
            sub_magazine_count: self.sub_magazine.remaining_count(),
            zeroed_cache_count: self.zeroed_cache.len(),
            alloc_count: self.alloc_count,
            free_count: self.free_count,
            refill_count: self.refill_count,
            drain_count: self.drain_count,
            sub_magazine_hits: self.sub_magazine_hits,
            zeroed_cache_hits: self.zeroed_cache_hits,
            zeroed_cache_stats: self.zeroed_cache.stats(),
        }
    }

    /// Get access to sub-magazine for external claiming
    #[inline]
    pub fn sub_magazine_mut(&mut self) -> &mut SubFrameMagazine {
        &mut self.sub_magazine
    }

    /// NUMAノードを設定
    pub fn set_numa_node(&mut self, node: NumaNodeId) {
        self.numa_node = node;
    }
}
