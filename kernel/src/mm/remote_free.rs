//! Remote Free Ring and Quarantine Ring for Lock-Free Cross-CPU Memory Reclamation
//!
//! # Overview
//!
//! This module provides generic lock-free ring buffers for deferred memory reclamation:
//!
//! - **RemoteFreeRing**: Lock-free MPSC (Multi-Producer Single-Consumer) ring for
//!   cross-CPU free requests. When a CPU frees memory owned by another CPU's allocator,
//!   it pushes to the owner's ring instead of directly modifying the bitmap.
//!
//! - **QuarantineRing**: Per-CPU ring buffer for epoch-based delayed reclamation.
//!   Memory is quarantined until a certain epoch passes (e.g., after IOTLB flush).
//!
//! # Design Goals
//!
//! - **Generic**: Works for both IOVA and physical frame allocators
//! - **Lock-free push**: Multiple CPUs can push concurrently without locks
//! - **Single-consumer drain**: Only the owner CPU drains its ring
//! - **Range-based entries**: Single entry can represent multiple contiguous pages
//! - **No holes**: Uses Vyukov MPSC protocol to ensure data integrity
//!
//! # Usage
//!
//! ```ignore
//! // IOVA allocator usage
//! type IovaRemoteFreeRing = RemoteFreeRing<512>;
//! type IovaQuarantineRing = QuarantineRing<256>;
//!
//! // Physical frame allocator usage  
//! type FrameRemoteFreeRing = RemoteFreeRing<1024>;
//! type FrameQuarantineRing = QuarantineRing<512>;
//! ```
#![allow(dead_code)]

use spin::Mutex;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::atomic_utils::{AtomicU8, AtomicU16};
use super::types::{FixedVec, PAGE_SIZE_4K, PAGE_SIZE_2M, PAGE_SIZE_1G};

// ============================================================================
// Constants
// ============================================================================

/// Default capacity for RemoteFreeRing
mod _split_1;
use _split_1::*;
pub const DEFAULT_REMOTE_FREE_CAPACITY: usize = 256;

/// Default capacity for quarantine ring
pub const DEFAULT_QUARANTINE_CAPACITY: usize = 256;

/// Maximum overflow entries (fallback when ring is full)
const MAX_OVERFLOW_ENTRIES: usize = 128;

// ============================================================================
// Remote Free Entry (Range-based for batch efficiency)
// ============================================================================

/// Entry in the remote free ring
///
/// # Range-based Free
///
/// Instead of storing one entry per page, we can store a contiguous range:
/// - Single page: `addr = base, count = 1`
/// - Range: `addr = start, count = N` (frees N contiguous pages)
///
/// This dramatically reduces ring push/drain overhead for scatter-gather
/// buffer releases and batch DMA unmaps.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RemoteFreeEntry {
    /// Address to be freed (start of range) - could be IOVA or physical address
    pub addr: u64,
    /// Number of contiguous pages/blocks (1 = single, N = contiguous range)
    /// For 2MB/1GB (size_class 1/2), this is the count of 2MB/1GB blocks
    pub count: u16,
    /// Size class: 0 = 4KB, 1 = 2MB, 2 = 1GB
    pub size_class: u8,
}

impl RemoteFreeEntry {
    /// Create an empty/invalid entry
    #[inline]
    pub const fn empty() -> Self {
        Self {
            addr: 0,
            count: 0,
            size_class: 0,
        }
    }
    
    /// Create a single-page entry
    #[inline]
    pub const fn single(addr: u64, size_class: u8) -> Self {
        Self {
            addr,
            count: 1,
            size_class,
        }
    }
    
    /// Create a range entry for multiple contiguous pages
    #[inline]
    pub const fn range(addr: u64, count: u16, size_class: u8) -> Self {
        Self {
            addr,
            count,
            size_class,
        }
    }
    
    /// Check if this is an empty/invalid entry
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
    
    /// Get the page size for this entry's size class
    #[inline]
    pub const fn page_size(&self) -> u64 {
        match self.size_class {
            0 => PAGE_SIZE_4K as u64,
            1 => PAGE_SIZE_2M as u64,
            2 => PAGE_SIZE_1G as u64,
            _ => PAGE_SIZE_4K as u64,
        }
    }
    
    /// Get total bytes covered by this entry
    #[inline]
    pub fn total_bytes(&self) -> u64 {
        self.page_size() * (self.count as u64)
    }
    
    /// Get the end address (exclusive)
    #[inline]
    pub fn end_addr(&self) -> u64 {
        self.addr.saturating_add(self.total_bytes())
    }
}

impl Default for RemoteFreeEntry {
    fn default() -> Self {
        Self::empty()
    }
}

// ============================================================================
// Remote Free Ring (Lock-free MPSC Vyukov Protocol)
// ============================================================================

/// Lock-free MPSC (Multi-Producer Single-Consumer) ring for remote frees
///
/// When a CPU frees memory that belongs to another CPU's allocator, it pushes
/// the address to the owner CPU's remote free ring. The owner CPU periodically
/// drains this ring and updates its allocator state.
///
/// # Design (Vyukov MPSC with Sequences)
///
/// Uses sequence numbers to avoid the "hole" problem where producers reserve
/// slots but haven't written yet:
/// - `seq == pos`: slot is ready for producer at position `pos`
/// - `seq == pos + 1`: slot contains committed data for consumer
/// - Producer: CAS head to reserve → write data → update seq (commit)
/// - Consumer: check seq to verify data is committed before reading
///
/// # Type Parameter
///
/// - `N`: Ring capacity (must be power of 2 for efficient modulo)
///
/// # Cache Line Alignment
///
/// The struct is aligned to 128 bytes to avoid false sharing between
/// the producer-hot `head` and consumer-hot `tail`.
#[repr(C, align(128))]
pub struct RemoteFreeRing<const N: usize = DEFAULT_REMOTE_FREE_CAPACITY> {
    /// Ring buffer entries - addresses (lock-free, written by pushers)
    entries: [AtomicU64; N],
    /// Size classes packed separately (to keep entries as simple u64)
    size_classes: [AtomicU8; N],
    /// Page counts for range-based free
    /// count = 0 means empty, count = N means N contiguous pages/blocks
    counts: [AtomicU16; N],
    /// Sequence numbers for each slot (Vyukov protocol)
    sequences: [AtomicUsize; N],
    /// Write position (head), incremented by pushers via CAS
    head: AtomicUsize,
    // --- Cache line boundary (64 bytes typically) ---
    /// Padding to separate producer and consumer fields
    _pad: [u8; 64 - core::mem::size_of::<AtomicUsize>()],
    /// Read position (tail), only modified by owner CPU
    tail: AtomicUsize,
    /// Overflow counter (pushes that failed due to full ring)
    overflow_count: AtomicU64,
    /// Total pages freed via range entries (for statistics)
    range_pages_freed: AtomicU64,
    
    /// Fallback overflow list (protected by lock, used when ring is full)
    /// This prevents extensive spinning or falling back to the main allocator lock.
    /// Uses fixed capacity to avoid heap allocation.
    overflow: Mutex<FixedVec<RemoteFreeEntry, MAX_OVERFLOW_ENTRIES>>,
}

impl<const N: usize> RemoteFreeRing<N> {
    /// Create a new empty remote free ring (Vyukov MPSC)
    ///
    /// # Panics
    ///
    /// Debug-asserts that N is a power of 2.
    pub const fn new() -> Self {
        debug_assert!(N.is_power_of_two(), "RemoteFreeRing capacity must be power of 2");
        
        const EMPTY_ENTRY: AtomicU64 = AtomicU64::new(0);
        const EMPTY_SIZE: AtomicU8 = AtomicU8::new(0);
        const EMPTY_COUNT: AtomicU16 = AtomicU16::new(0);
        const INIT_SEQ: AtomicUsize = AtomicUsize::new(0);
        
        Self {
            entries: [EMPTY_ENTRY; N],
            size_classes: [EMPTY_SIZE; N],
            counts: [EMPTY_COUNT; N],
            sequences: [INIT_SEQ; N],
            head: AtomicUsize::new(0),
            _pad: [0; 64 - core::mem::size_of::<AtomicUsize>()],
            tail: AtomicUsize::new(0),
            overflow_count: AtomicU64::new(0),
            range_pages_freed: AtomicU64::new(0),
            overflow: Mutex::new(FixedVec::new()),
        }
    }
    
    /// Initialize sequence numbers (call once after construction)
    ///
    /// Each slot i starts with sequence = i, meaning "ready for producer at pos i".
    /// This is required for the Vyukov protocol to work correctly.
    pub fn init(&self) {
        for i in 0..N {
            self.sequences[i].store(i, Ordering::Relaxed);
        }
    }
    
    /// Get the ring capacity
    #[inline]
    pub const fn capacity(&self) -> usize {
        N
    }
    
    /// Try to push a single entry (lock-free Vyukov MPSC)
    ///
    /// Returns true if pushed successfully, false if ring is full.
    #[inline]
    pub fn try_push(&self, addr: u64, size_class: u8) -> bool {
        self.try_push_range(addr, 1, size_class)
    }
    
    /// Try to push a range entry (multiple contiguous pages)
    ///
    /// # Arguments
    /// * `addr` - Start address of the range
    /// * `count` - Number of contiguous pages/blocks to free
    /// * `size_class` - 0 = 4KB, 1 = 2MB, 2 = 1GB
    ///
    /// # Returns
    /// * `true` if pushed successfully
    /// * `false` if ring is full (caller should retry or fallback)
    ///
    /// # Benefits
    /// - Single ring entry for N pages → reduces push/drain overhead
    /// - Better cache utilization (fewer ring traversals)
    #[inline]
    pub fn try_push_range(&self, addr: u64, count: u16, size_class: u8) -> bool {
        if count == 0 {
            return true; // Nothing to free
        }
        
        let mut pos = self.head.load(Ordering::Relaxed);
        
        loop {
            let idx = pos & (N - 1); // Fast modulo for power-of-2
            let seq = self.sequences[idx].load(Ordering::Acquire);
            let diff = seq as isize - pos as isize;
            
            if diff == 0 {
                // Slot is ready for this position, try to claim it
                match self.head.compare_exchange_weak(
                    pos,
                    pos.wrapping_add(1),
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        // Successfully reserved slot, write data
                        self.size_classes[idx].store(size_class, Ordering::Relaxed);
                        self.counts[idx].store(count, Ordering::Relaxed);
                        self.entries[idx].store(addr, Ordering::Relaxed);
                        
                        // Update range statistics
                        if count > 1 {
                            self.range_pages_freed.fetch_add(count as u64, Ordering::Relaxed);
                        }
                        
                        // Commit: set seq = pos + 1 to signal consumer
                        self.sequences[idx].store(pos.wrapping_add(1), Ordering::Release);
                        return true;
                    }
                    Err(new_pos) => {
                        pos = new_pos; // Retry with updated head
                    }
                }
            } else if diff < 0 {
                // Ring is full (consumer hasn't caught up)
                self.overflow_count.fetch_add(1, Ordering::Relaxed);
                return false;
            } else {
                // Another producer is still writing to this slot, reload head
                pos = self.head.load(Ordering::Relaxed);
            }
            core::hint::spin_loop();
        }
    }
    

    /// Push a single entry, using fallback if ring is full
    /// Always succeeds (unless OOM in fallback Vec, which is unlikely/panic)
    #[inline]
    pub fn push(&self, addr: u64, size_class: u8) {
        self.push_range(addr, 1, size_class)
    }

    /// Push a range entry, using fallback if ring is full
    pub fn push_range(&self, addr: u64, count: u16, size_class: u8) {
         if !self.try_push_range(addr, count, size_class) {
             // Ring full, use fallback
             let mut lock = self.overflow.lock();
             lock.push(RemoteFreeEntry { addr, count, size_class });
         }
    }

    /// Drain entries from the ring AND the overflow fallback
    ///
    /// # Arguments
    /// * `out` - Output buffer to write drained entries
    ///
    /// # Returns
    /// Number of entries drained
    /// overflowリストからエントリをドレインする
    fn drain_overflow(&self, out: &mut [RemoteFreeEntry], start: usize) -> usize {
        let mut drained = start;
        if !self.overflow.lock().is_empty() {
             let mut lock = self.overflow.lock();
             while drained < out.len() {
                 if let Some(entry) = lock.pop() {
                     out[drained] = entry;
                     drained += 1;
                 } else {
                     break;
                 }
             }
        }
        drained
    }

    pub fn drain(&self, out: &mut [RemoteFreeEntry]) -> usize {
        let mut drained = self.drain_overflow(out, 0);

        if drained >= out.len() {
            return drained;
        }

        // 2. Drain from ring
        let mut pos = self.tail.load(Ordering::Relaxed);
        
        while drained < out.len() {
            let idx = pos & (N - 1);
            let seq = self.sequences[idx].load(Ordering::Acquire);
            let expected_seq = pos.wrapping_add(1);
            
            if seq != expected_seq {
                // Slot not ready (either empty or producer still writing)
                break;
            }
            
            // Read data (order doesn't matter, seq acquire already synchronized)
            let addr = self.entries[idx].load(Ordering::Relaxed);
            let size_class = self.size_classes[idx].load(Ordering::Relaxed);
            let count = self.counts[idx].load(Ordering::Relaxed);
            
            // Reset sequence for next producer: seq = pos + N
            self.sequences[idx].store(pos.wrapping_add(N), Ordering::Release);
            
            out[drained] = RemoteFreeEntry { addr, count, size_class };
            drained += 1;
            pos = pos.wrapping_add(1);
        }
        
        // Update tail if we drained anything from the ring
        if drained > 0 {
             // We can't distinguish easily how many came from ring vs overflow here due to single `drained` counter
             // But we only updated `pos` for ring entries.
             // Wait, current logic: `pos` is local var, updated only in loop.
             // We should only store `pos` if it changed.
             
             // Check if we advanced pos
             let old_tail = self.tail.load(Ordering::Relaxed);
             if pos != old_tail {
                 self.tail.store(pos, Ordering::Release);
             }
        }
        
        drained
    }
    
    /// Drain entries and merge contiguous ranges for batch free
    /// 
    /// This method drains entries, sorts them by address, and merges
    /// contiguous entries into larger ranges. This reduces overhead
    /// when freeing memory back to the allocator.
    /// 
    /// # Algorithm
    /// 
    /// 1. Drain up to `out.len()` entries from ring
    /// 2. Sort by (size_class, addr) - same size class entries together
    /// 3. Merge adjacent entries with same size_class into larger ranges
    /// 
    /// # Arguments
    /// * `out` - Output buffer for merged entries (reused for efficiency)
    /// 
    /// # Returns
    /// Number of merged entries (≤ original drain count)
    /// 
    /// # Example
    /// 
    /// Input (drained): [0x1000, 0x2000, 0x3000] (size_class=0, count=1 each)
    /// Output (merged): [0x1000] (size_class=0, count=3)
    pub fn drain_and_merge(&self, out: &mut [RemoteFreeEntry]) -> usize {
        // Step 1: Drain entries
        let drained = self.drain(out);
        if drained <= 1 {
            return drained;
        }
        
        // Step 2: Sort by (size_class, addr) for efficient merging
        // Use simple insertion sort for small arrays (typical case)
        let entries = &mut out[..drained];
        for i in 1..entries.len() {
            let mut j = i;
            while j > 0 && Self::entry_cmp(&entries[j - 1], &entries[j]) == core::cmp::Ordering::Greater {
                entries.swap(j - 1, j);
                j -= 1;
            }
        }
        
        // Step 3: Merge adjacent entries with same size_class
        Self::merge_sorted_entries(entries)
    }
    
    /// Compare entries for sorting: (size_class, addr)
    #[inline]
    fn entry_cmp(a: &RemoteFreeEntry, b: &RemoteFreeEntry) -> core::cmp::Ordering {
        match a.size_class.cmp(&b.size_class) {
            core::cmp::Ordering::Equal => a.addr.cmp(&b.addr),
            other => other,
        }
    }
    
    /// Drain all entries, calling a closure for each
    ///
    /// More efficient than `drain()` when you don't need to store entries.
    ///
    /// # Arguments
    /// * `max` - Maximum entries to drain
    /// * `f` - Closure called for each entry
    ///
    /// # Returns
    /// Number of entries drained
    pub fn drain_with<F>(&self, max: usize, mut f: F) -> usize
    where
        F: FnMut(RemoteFreeEntry),
    {
        let mut drained = 0;
        let mut pos = self.tail.load(Ordering::Relaxed);
        
        while drained < max {
            let idx = pos & (N - 1);
            let seq = self.sequences[idx].load(Ordering::Acquire);
            let expected_seq = pos.wrapping_add(1);
            
            if seq != expected_seq {
                break;
            }
            
            let addr = self.entries[idx].load(Ordering::Relaxed);
            let size_class = self.size_classes[idx].load(Ordering::Relaxed);
            let count = self.counts[idx].load(Ordering::Relaxed);
            
            self.sequences[idx].store(pos.wrapping_add(N), Ordering::Release);
            
            f(RemoteFreeEntry { addr, count, size_class });
            drained += 1;
            pos = pos.wrapping_add(1);
        }
        
        if drained > 0 {
            self.tail.store(pos, Ordering::Release);
        }
        
        drained
    }
    
    /// Get approximate number of pending entries
    ///
    /// This is approximate because head and tail are read non-atomically.
    #[inline]
    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        head.wrapping_sub(tail).min(N)
    }
    
    /// Check if ring appears empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Relaxed) == self.tail.load(Ordering::Relaxed)
    }
    
    /// Check if ring appears full
    #[inline]
    pub fn is_full(&self) -> bool {
        self.len() >= N
    }
    
    /// Get overflow count (failed pushes due to full ring)
    #[inline]
    pub fn overflow_count(&self) -> u64 {
        self.overflow_count.load(Ordering::Relaxed)
    }
    
    /// Get total pages freed via range entries (statistics)
    #[inline]
    pub fn range_pages_freed(&self) -> u64 {
        self.range_pages_freed.load(Ordering::Relaxed)
    }
    
    /// Reset statistics counters
    pub fn reset_stats(&self) {
        self.overflow_count.store(0, Ordering::Relaxed);
        self.range_pages_freed.store(0, Ordering::Relaxed);
    }
}

// ============================================================================
// Phase 1 最適化: Adaptive Batching
// ============================================================================

/// 適応的バッチ処理の設定パラメータ
pub struct AdaptiveBatchConfig {
    /// 最小バッチサイズ（低負荷時）
    pub min_batch: usize,
    /// 最大バッチサイズ（高負荷時）
    pub max_batch: usize,
    /// 負荷閾値（この充填率を超えたら高負荷）
    pub load_threshold_percent: usize,
    /// 緊急閾値（この充填率を超えたら全ドレイン）
    pub urgent_threshold_percent: usize,
}

impl Default for AdaptiveBatchConfig {
    fn default() -> Self {
        Self {
            min_batch: 8,
            max_batch: 64,
            load_threshold_percent: 50,
            urgent_threshold_percent: 80,
        }
    }
}

impl AdaptiveBatchConfig {
    /// デフォルト設定を生成
    pub const fn new() -> Self {
        Self {
            min_batch: 8,
            max_batch: 64,
            load_threshold_percent: 50,
            urgent_threshold_percent: 80,
        }
    }
}

/// グローバルAdaptive Batch設定
pub static ADAPTIVE_BATCH_CONFIG: AdaptiveBatchConfig = AdaptiveBatchConfig::new();

/// Adaptive Batch統計
pub struct AdaptiveBatchStats {
    /// 低負荷ドレイン回数
    pub low_load_drains: AtomicU64,
    /// 高負荷ドレイン回数
    pub high_load_drains: AtomicU64,
    /// 緊急ドレイン回数（全ドレイン）
    pub urgent_drains: AtomicU64,
    /// 平均バッチサイズ（x100で格納）
    pub avg_batch_size_x100: AtomicU64,
    /// 合計ドレインエントリ数
    pub total_drained: AtomicU64,
}

impl AdaptiveBatchStats {
    pub const fn new() -> Self {
        Self {
            low_load_drains: AtomicU64::new(0),
            high_load_drains: AtomicU64::new(0),
            urgent_drains: AtomicU64::new(0),
            avg_batch_size_x100: AtomicU64::new(0),
            total_drained: AtomicU64::new(0),
        }
    }
    
    /// 平均バッチサイズを取得（小数点2桁）
    pub fn avg_batch_size(&self) -> f64 {
        let total = self.total_drained.load(Ordering::Relaxed);
        let drains = self.low_load_drains.load(Ordering::Relaxed)
            + self.high_load_drains.load(Ordering::Relaxed)
            + self.urgent_drains.load(Ordering::Relaxed);
        
        if drains == 0 {
            0.0
        } else {
            total as f64 / drains as f64
        }
    }
}

/// グローバルAdaptive Batch統計
pub static ADAPTIVE_BATCH_STATS: AdaptiveBatchStats = AdaptiveBatchStats::new();

impl<const N: usize> RemoteFreeRing<N> {
    /// 負荷に応じた適応的バッチドレイン
    /// 
    /// ## アルゴリズム
    /// 
    /// リングの充填率に応じてバッチサイズを動的に調整：
    /// 
    /// | 充填率           | バッチサイズ | 理由                       |
    /// |------------------|--------------|----------------------------|
    /// | < 50%            | min_batch    | 低負荷：CPU消費を抑える    |
    /// | 50% - 80%        | 補間         | 中負荷：徐々にバッチ増加   |
    /// | > 80%            | 全ドレイン   | 高負荷：オーバーフロー防止 |
    /// 
    /// ## 利点
    /// 
    /// - 低負荷時: 不要なドレインを減らしCPUオーバーヘッド削減
    /// - 高負荷時: オーバーフローを防ぎデータロスを回避
    /// - スムーズな遷移: 急激な動作変更を避ける
    /// 
    /// ## 戻り値
    /// 
    /// ドレインされたエントリ数
    pub fn adaptive_drain(&self, out: &mut [RemoteFreeEntry]) -> usize {
        let current_len = self.len();
        let capacity = self.capacity();
        
        if current_len == 0 || out.is_empty() {
            return 0;
        }
        
        // 充填率計算（0-100%）
        let fill_percent = (current_len * 100) / capacity;
        
        // 適応的バッチサイズ決定
        let config = &ADAPTIVE_BATCH_CONFIG;
        let batch_size = if fill_percent >= config.urgent_threshold_percent {
            // 緊急: 全てドレイン
            ADAPTIVE_BATCH_STATS.urgent_drains.fetch_add(1, Ordering::Relaxed);
            out.len().min(current_len)
        } else if fill_percent >= config.load_threshold_percent {
            // 高負荷: 線形補間でバッチサイズ増加
            // batch = min + (max - min) * (fill% - load_threshold) / (urgent - load_threshold)
            let range = config.urgent_threshold_percent - config.load_threshold_percent;
            let progress = fill_percent - config.load_threshold_percent;
            let scaled = config.min_batch 
                + ((config.max_batch - config.min_batch) * progress) / range.max(1);
            ADAPTIVE_BATCH_STATS.high_load_drains.fetch_add(1, Ordering::Relaxed);
            out.len().min(scaled).min(current_len)
        } else {
            // 低負荷: 最小バッチ
            ADAPTIVE_BATCH_STATS.low_load_drains.fetch_add(1, Ordering::Relaxed);
            out.len().min(config.min_batch).min(current_len)
        };
        
        // 実際のドレイン実行
        let drained = self.drain(&mut out[..batch_size]);
        ADAPTIVE_BATCH_STATS.total_drained.fetch_add(drained as u64, Ordering::Relaxed);
        
        drained
    }
    
    /// 負荷に応じたバッチサイズを計算する
    fn compute_adaptive_batch_size(&self, current_len: usize, capacity: usize, max_out: usize) -> usize {
        let fill_percent = (current_len * 100) / capacity;
        let config = &ADAPTIVE_BATCH_CONFIG;

        if fill_percent >= config.urgent_threshold_percent {
            ADAPTIVE_BATCH_STATS.urgent_drains.fetch_add(1, Ordering::Relaxed);
            max_out.min(current_len)
        } else if fill_percent >= config.load_threshold_percent {
            let range = config.urgent_threshold_percent - config.load_threshold_percent;
            let progress = fill_percent - config.load_threshold_percent;
            let scaled = config.min_batch 
                + ((config.max_batch - config.min_batch) * progress) / range.max(1);
            ADAPTIVE_BATCH_STATS.high_load_drains.fetch_add(1, Ordering::Relaxed);
            max_out.min(scaled).min(current_len)
        } else {
            ADAPTIVE_BATCH_STATS.low_load_drains.fetch_add(1, Ordering::Relaxed);
            max_out.min(config.min_batch).min(current_len)
        }
    }

    /// ソート済みエントリの連続アドレスをマージする
    fn merge_sorted_entries(entries: &mut [RemoteFreeEntry]) -> usize {
        if entries.len() <= 1 {
            return entries.len();
        }
        let mut write_idx = 0;
        let mut read_idx = 1;

        while read_idx < entries.len() {
            let current = &entries[write_idx];
            let next = &entries[read_idx];

            if current.size_class == next.size_class {
                let page_size = current.page_size();
                let current_end = current.addr.saturating_add(page_size * (current.count as u64));

                if current_end == next.addr {
                    let new_count = current.count.saturating_add(next.count);
                    entries[write_idx] = RemoteFreeEntry {
                        addr: current.addr,
                        count: new_count,
                        size_class: current.size_class,
                    };
                    read_idx += 1;
                    continue;
                }
            }

            write_idx += 1;
            if write_idx != read_idx {
                entries[write_idx] = entries[read_idx];
            }
            read_idx += 1;
        }

        write_idx + 1
    }

    /// 適応的バッチドレイン + マージ
    /// 
    /// `adaptive_drain` + `drain_and_merge` の組み合わせ。
    /// 負荷適応バッチサイズで取得後、連続アドレスをマージ。
    pub fn adaptive_drain_and_merge(&self, out: &mut [RemoteFreeEntry]) -> usize {
        let current_len = self.len();
        let capacity = self.capacity();
        
        if current_len == 0 || out.is_empty() {
            return 0;
        }
        
        let batch_size = self.compute_adaptive_batch_size(current_len, capacity, out.len());
        
        // ドレイン
        let drained = self.drain(&mut out[..batch_size]);
        if drained <= 1 {
            ADAPTIVE_BATCH_STATS.total_drained.fetch_add(drained as u64, Ordering::Relaxed);
            return drained;
        }
        
        // ソート（insertion sort for small arrays）
        let entries = &mut out[..drained];
        for i in 1..entries.len() {
            let mut j = i;
            while j > 0 && Self::entry_cmp(&entries[j - 1], &entries[j]) == core::cmp::Ordering::Greater {
                entries.swap(j - 1, j);
                j -= 1;
            }
        }
        
        let merged_count = Self::merge_sorted_entries(entries);
        ADAPTIVE_BATCH_STATS.total_drained.fetch_add(merged_count as u64, Ordering::Relaxed);
        merged_count
    }
    
    /// 充填率を取得（0-100）
    #[inline]
    pub fn fill_percent(&self) -> usize {
        let len = self.len();
        if N == 0 {
            return 0;
        }
        (len * 100) / N
    }
    
    /// 高負荷状態かどうか
    #[inline]
    pub fn is_high_load(&self) -> bool {
        self.fill_percent() >= ADAPTIVE_BATCH_CONFIG.load_threshold_percent
    }
    
    /// 緊急状態かどうか（オーバーフロー危険）
    #[inline]
    pub fn is_urgent(&self) -> bool {
        self.fill_percent() >= ADAPTIVE_BATCH_CONFIG.urgent_threshold_percent
    }
}

impl<const N: usize> Default for RemoteFreeRing<N> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Quarantine Entry (Epoch-based delayed reclamation)
// ============================================================================

/// Entry in the quarantine ring buffer
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct QuarantineEntry {
    /// Address to be freed (IOVA or physical)
    pub addr: u64,
    /// Size class: 0 = 4KB, 1 = 2MB, 2 = 1GB
    pub size_class: u8,
    /// Epoch when this entry was quarantined
    pub epoch: u32,
}
