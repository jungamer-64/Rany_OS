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
#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::structures::paging::{PhysFrame, Size4KiB};
use x86_64::PhysAddr;

use super::types::NumaNodeId;
use super::per_node_buddy;
use super::buddy_allocator;

// ============================================================================
// Configuration
// ============================================================================

/// マガジンの容量（フレーム数）
pub const MAGAZINE_CAPACITY: usize = 32;

/// バッチ補充時のフレーム数
pub const REFILL_BATCH: usize = 16;

/// バッチ返却のトリガー閾値
pub const DRAIN_THRESHOLD: usize = MAGAZINE_CAPACITY - 4;

/// 4KiBページサイズ
const PAGE_SIZE_4K: u64 = 4096;

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
        (0..actual_count).map(move |_| self.pop().unwrap())
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
#[repr(C)]
pub struct PerCpuMagazineSet {
    /// Activeマガジン（通常のalloc/freeで使用）
    active: FrameMagazine,
    /// Spareマガジン（Activeが空/満杯時に交換）
    spare: FrameMagazine,
    /// Sub-magazine for claimed word optimization (64x atomic reduction)
    /// Highest priority in allocation hot path
    sub_magazine: SubFrameMagazine,
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
}

impl PerCpuMagazineSet {
    /// 新しいマガジンセットを作成
    pub const fn new(numa_node: NumaNodeId) -> Self {
        Self {
            active: FrameMagazine::new(),
            spare: FrameMagazine::new(),
            sub_magazine: SubFrameMagazine::new(),
            numa_node,
            refill_pending: core::sync::atomic::AtomicBool::new(false),
            alloc_count: 0,
            free_count: 0,
            refill_count: 0,
            drain_count: 0,
            bg_refill_count: 0,
            sub_magazine_hits: 0,
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
            return Some(frame);
        }

        // Fast path: Activeから取得
        if let Some(frame) = self.active.pop() {
            self.alloc_count += 1;
            return Some(frame);
        }

        // Medium path: Spareと交換
        if !self.spare.is_empty() {
            core::mem::swap(&mut self.active, &mut self.spare);
            if let Some(frame) = self.active.pop() {
                self.alloc_count += 1;
                // バックグラウンドリフィルをスケジュール（Spareが空になった）
                self.refill_pending.store(true, core::sync::atomic::Ordering::Release);
                return Some(frame);
            }
        }

        // Slow path: Buddyから同期的に補充
        self.refill();
        self.active.pop().map(|frame| {
            self.alloc_count += 1;
            frame
        })
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
    fn refill(&mut self) {
        self.refill_count += 1;

        // Per-Node Buddyを優先使用
        if per_node_buddy::is_per_node_initialized() {
            if let Some(allocator) = per_node_buddy::get_node_allocator(self.numa_node) {
                for _ in 0..REFILL_BATCH {
                    if let Some(frame) = allocator.allocate_4k() {
                        if self.active.push(frame).is_err() {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                return;
            }
        }

        // フォールバック: グローバルBuddy
        for _ in 0..REFILL_BATCH {
            if let Some(frame) = buddy_allocator::buddy_alloc_frame() {
                if self.active.push(frame).is_err() {
                    break;
                }
            } else {
                break;
            }
        }
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
            alloc_count: self.alloc_count,
            free_count: self.free_count,
            refill_count: self.refill_count,
            drain_count: self.drain_count,
            sub_magazine_hits: self.sub_magazine_hits,
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
}

// ============================================================================
// Global Statistics
// ============================================================================

/// グローバル統計
static GLOBAL_ALLOCS: AtomicU64 = AtomicU64::new(0);
static GLOBAL_FREES: AtomicU64 = AtomicU64::new(0);
static GLOBAL_REFILLS: AtomicU64 = AtomicU64::new(0);
static GLOBAL_DRAINS: AtomicU64 = AtomicU64::new(0);

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
