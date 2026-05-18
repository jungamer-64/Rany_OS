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
use crate::sync::IrqPoisonLock;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::atomic_utils::{AtomicU8, AtomicU16};
use super::types::{FixedVec, PAGE_SIZE_1G, PAGE_SIZE_2M, PAGE_SIZE_4K};

// ============================================================================
// Constants
// ============================================================================

mod quarantine;
pub use quarantine::*;
pub const DEFAULT_REMOTE_FREE_CAPACITY: usize = 256;

/// Default capacity for quarantine ring
pub const DEFAULT_QUARANTINE_CAPACITY: usize = 256;

/// Maximum overflow entries (fallback when ring is full)
const MAX_OVERFLOW_ENTRIES: usize = 128;

// ============================================================================
// Remote Free Entry (Range-based for batch efficiency)
// ============================================================================

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RemoteFreeEntry {
    pub addr: u64,
    pub count: u16,
    pub size_class: u8,
}

impl RemoteFreeEntry {
    #[inline]
    pub const fn empty() -> Self {
        Self {
            addr: 0,
            count: 0,
            size_class: 0,
        }
    }

    #[inline]
    pub const fn single(addr: u64, size_class: u8) -> Self {
        Self {
            addr,
            count: 1,
            size_class,
        }
    }

    #[inline]
    pub const fn range(addr: u64, count: u16, size_class: u8) -> Self {
        Self {
            addr,
            count,
            size_class,
        }
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    #[inline]
    pub const fn page_size(&self) -> u64 {
        match self.size_class {
            0 => PAGE_SIZE_4K as u64,
            1 => PAGE_SIZE_2M as u64,
            2 => PAGE_SIZE_1G as u64,
            _ => PAGE_SIZE_4K as u64,
        }
    }

    #[inline]
    pub fn total_bytes(&self) -> u64 {
        self.page_size() * (self.count as u64)
    }

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

#[repr(C, align(128))]
pub struct RemoteFreeRing<const N: usize = DEFAULT_REMOTE_FREE_CAPACITY> {
    entries: [AtomicU64; N],
    size_classes: [AtomicU8; N],
    counts: [AtomicU16; N],
    sequences: [AtomicUsize; N],
    head: AtomicUsize,
    _pad: [u8; 64 - core::mem::size_of::<AtomicUsize>()],
    tail: AtomicUsize,
    overflow_count: AtomicU64,
    range_pages_freed: AtomicU64,
    overflow: IrqPoisonLock<FixedVec<RemoteFreeEntry, MAX_OVERFLOW_ENTRIES>>,
}

impl<const N: usize> core::fmt::Debug for RemoteFreeRing<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RemoteFreeRing")
            .field("capacity", &N)
            .field("head", &self.head.load(Ordering::Relaxed))
            .field("tail", &self.tail.load(Ordering::Relaxed))
            .field(
                "overflow_count",
                &self.overflow_count.load(Ordering::Relaxed),
            )
            .finish()
    }
}

impl<const N: usize> RemoteFreeRing<N> {
    pub const fn new() -> Self {
        debug_assert!(
            N.is_power_of_two(),
            "RemoteFreeRing capacity must be power of 2"
        );

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
            overflow: IrqPoisonLock::new(FixedVec::new()),
        }
    }

    pub fn init(&self) {
        for i in 0..N {
            self.sequences[i].store(i, Ordering::Relaxed);
        }
    }

    #[inline]
    pub const fn capacity(&self) -> usize {
        N
    }

    #[inline]
    pub fn try_push(&self, addr: u64, size_class: u8) -> bool {
        self.try_push_range(addr, 1, size_class)
    }

    #[inline]
    pub fn try_push_range(&self, addr: u64, count: u16, size_class: u8) -> bool {
        if count == 0 {
            return true;
        }
        let mut pos = self.head.load(Ordering::Relaxed);
        loop {
            let idx = pos & (N - 1);
            let seq = self.sequences[idx].load(Ordering::Acquire);
            let diff = seq as isize - pos as isize;
            if diff == 0 {
                match self.head.compare_exchange_weak(
                    pos,
                    pos.wrapping_add(1),
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        self.size_classes[idx].store(size_class, Ordering::Relaxed);
                        self.counts[idx].store(count, Ordering::Relaxed);
                        self.entries[idx].store(addr, Ordering::Relaxed);
                        if count > 1 {
                            self.range_pages_freed
                                .fetch_add(count as u64, Ordering::Relaxed);
                        }
                        self.sequences[idx].store(pos.wrapping_add(1), Ordering::Release);
                        return true;
                    }
                    Err(new_pos) => {
                        pos = new_pos;
                    }
                }
            } else if diff < 0 {
                self.overflow_count.fetch_add(1, Ordering::Relaxed);
                return false;
            } else {
                pos = self.head.load(Ordering::Relaxed);
            }
            core::hint::spin_loop();
        }
    }

    #[inline]
    pub fn push(&self, addr: u64, size_class: u8) {
        self.push_range(addr, 1, size_class)
    }

    pub fn push_range(&self, addr: u64, count: u16, size_class: u8) {
        if !self.try_push_range(addr, count, size_class) {
            let mut lock = self.overflow.lock().unwrap_or_else(|e| e.into_inner());
            lock.push(RemoteFreeEntry {
                addr,
                count,
                size_class,
            });
        }
    }

    fn drain_overflow(&self, out: &mut [RemoteFreeEntry], start: usize) -> usize {
        let mut drained = start;
        {
            let mut lock = self.overflow.lock().unwrap_or_else(|e| e.into_inner());
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
        let mut pos = self.tail.load(Ordering::Relaxed);
        while drained < out.len() {
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
            out[drained] = RemoteFreeEntry {
                addr,
                count,
                size_class,
            };
            drained += 1;
            pos = pos.wrapping_add(1);
        }
        if drained > 0 {
            let old_tail = self.tail.load(Ordering::Relaxed);
            if pos != old_tail {
                self.tail.store(pos, Ordering::Release);
            }
        }
        drained
    }

    pub fn drain_and_merge(&self, out: &mut [RemoteFreeEntry]) -> usize {
        let drained = self.drain(out);
        if drained <= 1 {
            return drained;
        }
        let entries = &mut out[..drained];
        for i in 1..entries.len() {
            let mut j = i;
            while j > 0
                && Self::entry_cmp(&entries[j - 1], &entries[j]) == core::cmp::Ordering::Greater
            {
                entries.swap(j - 1, j);
                j -= 1;
            }
        }
        Self::merge_sorted_entries(entries)
    }

    #[inline]
    fn entry_cmp(a: &RemoteFreeEntry, b: &RemoteFreeEntry) -> core::cmp::Ordering {
        match a.size_class.cmp(&b.size_class) {
            core::cmp::Ordering::Equal => a.addr.cmp(&b.addr),
            other => other,
        }
    }

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
            f(RemoteFreeEntry {
                addr,
                count,
                size_class,
            });
            drained += 1;
            pos = pos.wrapping_add(1);
        }
        if drained > 0 {
            self.tail.store(pos, Ordering::Release);
        }
        drained
    }

    #[inline]
    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        head.wrapping_sub(tail).min(N)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Relaxed) == self.tail.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn is_full(&self) -> bool {
        self.len() >= N
    }

    #[inline]
    pub fn overflow_count(&self) -> u64 {
        self.overflow_count.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn range_pages_freed(&self) -> u64 {
        self.range_pages_freed.load(Ordering::Relaxed)
    }

    pub fn reset_stats(&self) {
        self.overflow_count.store(0, Ordering::Relaxed);
        self.range_pages_freed.store(0, Ordering::Relaxed);
    }
}

// ============================================================================
// Phase 1 最適化: Adaptive Batching
// ============================================================================

pub struct AdaptiveBatchConfig {
    pub min_batch: usize,
    pub max_batch: usize,
    pub load_threshold_percent: usize,
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
    pub const fn new() -> Self {
        Self {
            min_batch: 8,
            max_batch: 64,
            load_threshold_percent: 50,
            urgent_threshold_percent: 80,
        }
    }
}

pub static ADAPTIVE_BATCH_CONFIG: AdaptiveBatchConfig = AdaptiveBatchConfig::new();

pub struct AdaptiveBatchStats {
    pub low_load_drains: AtomicU64,
    pub high_load_drains: AtomicU64,
    pub urgent_drains: AtomicU64,
    pub avg_batch_size_x100: AtomicU64,
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

pub static ADAPTIVE_BATCH_STATS: AdaptiveBatchStats = AdaptiveBatchStats::new();

impl<const N: usize> RemoteFreeRing<N> {
    pub fn adaptive_drain(&self, out: &mut [RemoteFreeEntry]) -> usize {
        let current_len = self.len();
        let capacity = self.capacity();
        if current_len == 0 || out.is_empty() {
            return 0;
        }
        let fill_percent = (current_len * 100) / capacity;
        let config = &ADAPTIVE_BATCH_CONFIG;
        let batch_size = if fill_percent >= config.urgent_threshold_percent {
            ADAPTIVE_BATCH_STATS
                .urgent_drains
                .fetch_add(1, Ordering::Relaxed);
            out.len().min(current_len)
        } else if fill_percent >= config.load_threshold_percent {
            let range = config.urgent_threshold_percent - config.load_threshold_percent;
            let progress = fill_percent - config.load_threshold_percent;
            let scaled = config.min_batch
                + ((config.max_batch - config.min_batch) * progress) / range.max(1);
            ADAPTIVE_BATCH_STATS
                .high_load_drains
                .fetch_add(1, Ordering::Relaxed);
            out.len().min(scaled).min(current_len)
        } else {
            ADAPTIVE_BATCH_STATS
                .low_load_drains
                .fetch_add(1, Ordering::Relaxed);
            out.len().min(config.min_batch).min(current_len)
        };
        let drained = self.drain(&mut out[..batch_size]);
        ADAPTIVE_BATCH_STATS
            .total_drained
            .fetch_add(drained as u64, Ordering::Relaxed);
        drained
    }

    fn compute_adaptive_batch_size(
        &self,
        current_len: usize,
        capacity: usize,
        max_out: usize,
    ) -> usize {
        let fill_percent = (current_len * 100) / capacity;
        let config = &ADAPTIVE_BATCH_CONFIG;
        if fill_percent >= config.urgent_threshold_percent {
            ADAPTIVE_BATCH_STATS
                .urgent_drains
                .fetch_add(1, Ordering::Relaxed);
            max_out.min(current_len)
        } else if fill_percent >= config.load_threshold_percent {
            let range = config.urgent_threshold_percent - config.load_threshold_percent;
            let progress = fill_percent - config.load_threshold_percent;
            let scaled = config.min_batch
                + ((config.max_batch - config.min_batch) * progress) / range.max(1);
            ADAPTIVE_BATCH_STATS
                .high_load_drains
                .fetch_add(1, Ordering::Relaxed);
            max_out.min(scaled).min(current_len)
        } else {
            ADAPTIVE_BATCH_STATS
                .low_load_drains
                .fetch_add(1, Ordering::Relaxed);
            max_out.min(config.min_batch).min(current_len)
        }
    }

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
                let current_end = current
                    .addr
                    .saturating_add(page_size * (current.count as u64));
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

    pub fn adaptive_drain_and_merge(&self, out: &mut [RemoteFreeEntry]) -> usize {
        let current_len = self.len();
        let capacity = self.capacity();
        if current_len == 0 || out.is_empty() {
            return 0;
        }
        let batch_size = self.compute_adaptive_batch_size(current_len, capacity, out.len());
        let drained = self.drain(&mut out[..batch_size]);
        if drained <= 1 {
            ADAPTIVE_BATCH_STATS
                .total_drained
                .fetch_add(drained as u64, Ordering::Relaxed);
            return drained;
        }
        let entries = &mut out[..drained];
        for i in 1..entries.len() {
            let mut j = i;
            while j > 0
                && Self::entry_cmp(&entries[j - 1], &entries[j]) == core::cmp::Ordering::Greater
            {
                entries.swap(j - 1, j);
                j -= 1;
            }
        }
        let merged_count = Self::merge_sorted_entries(entries);
        ADAPTIVE_BATCH_STATS
            .total_drained
            .fetch_add(merged_count as u64, Ordering::Relaxed);
        merged_count
    }

    #[inline]
    pub fn fill_percent(&self) -> usize {
        let len = self.len();
        if N == 0 {
            return 0;
        }
        (len * 100) / N
    }

    #[inline]
    pub fn is_high_load(&self) -> bool {
        self.fill_percent() >= ADAPTIVE_BATCH_CONFIG.load_threshold_percent
    }

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

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct QuarantineEntry {
    pub addr: u64,
    pub size_class: u8,
    pub epoch: u32,
}
