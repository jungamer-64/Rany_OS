// SPDX-License-Identifier: MIT
// ExoRust Kernel - Async Page Swapout & Buffer Management
// 設計書 5.2: Tier2/Tier3 統合, 設計書 10.4: 非同期I/Oとスワップアウト
#![allow(dead_code)]

use crate::mm::phys::buddy_allocator;
use crate::mm::types::FrameIndex;
use crate::sync::IrqPoisonLock;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering as AtomicOrdering};
use x86_64::structures::paging::{PageSize, PhysFrame, Size1GiB, Size2MiB, Size4KiB};

// ... (skipping imports and types assumed present in the module)

// Per-CPU cache enables lock-free buffer access for the common case.
// Each CPU has a local cache slot; overflow goes to the global pool.

const BUFFER_POOL_4K_DEFAULT_CAPACITY: usize = 128;
const MAX_CPUS: usize = 64;
const PER_CPU_CACHE_SIZE: usize = 4; // Number of buffers cached per CPU

// Global pool (overflow/underflow)
static BUFFER_POOL_4K_POOL: IrqPoisonLock<Vec<Vec<u8>>> = IrqPoisonLock::new(Vec::new());
static BUFFER_POOL_4K_HITS: AtomicUsize = AtomicUsize::new(0);
static BUFFER_POOL_4K_MISSES: AtomicUsize = AtomicUsize::new(0);
static BUFFER_POOL_4K_CAPACITY: AtomicUsize = AtomicUsize::new(BUFFER_POOL_4K_DEFAULT_CAPACITY);

// Per-CPU local cache statistics
static BUFFER_POOL_4K_LOCAL_HITS: AtomicUsize = AtomicUsize::new(0);

// Per-CPU cache structure
struct PerCpuBufferCache4K {
    // Each slot is an Option<Vec<u8>> wrapped in UnsafeCell
    // Access is safe because each CPU only accesses its own slots
    slots: [core::cell::UnsafeCell<Option<Vec<u8>>>; PER_CPU_CACHE_SIZE],
    // Track how many slots are used
    count: AtomicUsize,
}

impl PerCpuBufferCache4K {
    const fn new() -> Self {
        const EMPTY: core::cell::UnsafeCell<Option<Vec<u8>>> = core::cell::UnsafeCell::new(None);
        Self {
            slots: [EMPTY; PER_CPU_CACHE_SIZE],
            count: AtomicUsize::new(0),
        }
    }

    /// Try to get a buffer from local cache (lock-free)
    /// SAFETY: Caller must ensure this is only called from the owning CPU
    #[inline]
    unsafe fn try_get(&self) -> Option<Vec<u8>> {
        let count = self.count.load(AtomicOrdering::Acquire);
        if count == 0 {
            return None;
        }

        // Find a non-empty slot
        for slot in &self.slots {
            let ptr = slot.get();
            if (*ptr).is_some() {
                let buf = (*ptr).take();
                if buf.is_some() {
                    self.count.fetch_sub(1, AtomicOrdering::Release);
                    return buf;
                }
            }
        }
        None
    }

    /// Try to put a buffer into local cache (lock-free)
    /// SAFETY: Caller must ensure this is only called from the owning CPU
    /// Returns the buffer if cache is full
    #[inline]
    unsafe fn try_put(&self, buf: Vec<u8>) -> Option<Vec<u8>> {
        let count = self.count.load(AtomicOrdering::Acquire);
        if count >= PER_CPU_CACHE_SIZE {
            return Some(buf);
        }

        // Find an empty slot
        for slot in &self.slots {
            let ptr = slot.get();
            if (*ptr).is_none() {
                *ptr = Some(buf);
                self.count.fetch_add(1, AtomicOrdering::Release);
                return None;
            }
        }
        Some(buf)
    }
}

// SAFETY: Each CPU only accesses its own PerCpuBufferCache4K
unsafe impl Send for PerCpuBufferCache4K {}
unsafe impl Sync for PerCpuBufferCache4K {}

// Per-CPU cache array
static PER_CPU_BUFFER_CACHE_4K: [PerCpuBufferCache4K; MAX_CPUS] = {
    const CACHE: PerCpuBufferCache4K = PerCpuBufferCache4K::new();
    [CACHE; MAX_CPUS]
};

/// Get current CPU ID for cache access
#[inline]
fn current_cpu_for_cache() -> usize {
    #[cfg(not(any(test, feature = "std")))]
    {
        crate::smp::current_cpu() as usize % MAX_CPUS
    }
    #[cfg(any(test, feature = "std"))]
    {
        0 // Single CPU for tests
    }
}

pub fn buffer_pool_get_4k() -> Vec<u8> {
    let cpu = current_cpu_for_cache();

    // Fast path: try local cache first (lock-free)
    if let Some(mut buf) = unsafe { PER_CPU_BUFFER_CACHE_4K[cpu].try_get() } {
        BUFFER_POOL_4K_LOCAL_HITS.fetch_add(1, AtomicOrdering::Relaxed);
        if buf.len() != crate::mm::types::PAGE_SIZE_4K {
            buf.resize(crate::mm::types::PAGE_SIZE_4K, 0);
        }
        return buf;
    }

    // Slow path: try global pool
    let mut pool = BUFFER_POOL_4K_POOL
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(mut buf) = pool.pop() {
        BUFFER_POOL_4K_HITS.fetch_add(1, AtomicOrdering::AcqRel);
        if buf.len() != crate::mm::types::PAGE_SIZE_4K {
            buf.resize(crate::mm::types::PAGE_SIZE_4K, 0);
        }
        buf
    } else {
        drop(pool);
        BUFFER_POOL_4K_MISSES.fetch_add(1, AtomicOrdering::AcqRel);
        alloc::vec![0u8; crate::mm::types::PAGE_SIZE_4K]
    }
}

pub fn buffer_pool_put_4k(mut buf: Vec<u8>) {
    if buf.len() != crate::mm::types::PAGE_SIZE_4K {
        buf.resize(crate::mm::types::PAGE_SIZE_4K, 0);
    }

    let cpu = current_cpu_for_cache();

    // Fast path: try local cache first (lock-free)
    let overflow = unsafe { PER_CPU_BUFFER_CACHE_4K[cpu].try_put(buf) };

    if let Some(buf) = overflow {
        // Local cache full, put in global pool
        let cap = BUFFER_POOL_4K_CAPACITY.load(AtomicOrdering::Acquire);
        let mut pool = BUFFER_POOL_4K_POOL
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if pool.len() < cap {
            pool.push(buf);
        }
    }
}

pub fn buffer_pool_4k_stats() -> (usize, usize, usize) {
    (
        BUFFER_POOL_4K_HITS.load(AtomicOrdering::Acquire),
        BUFFER_POOL_4K_MISSES.load(AtomicOrdering::Acquire),
        BUFFER_POOL_4K_POOL
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len(),
    )
}

/// Extended stats including local cache hits
pub fn buffer_pool_4k_extended_stats() -> (usize, usize, usize, usize) {
    (
        BUFFER_POOL_4K_LOCAL_HITS.load(AtomicOrdering::Acquire),
        BUFFER_POOL_4K_HITS.load(AtomicOrdering::Acquire),
        BUFFER_POOL_4K_MISSES.load(AtomicOrdering::Acquire),
        BUFFER_POOL_4K_POOL
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len(),
    )
}

pub fn buffer_pool_4k_set_capacity(n: usize) {
    BUFFER_POOL_4K_CAPACITY.store(n, AtomicOrdering::Release);
    let mut pool = BUFFER_POOL_4K_POOL
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while pool.len() > n {
        pool.pop();
    }
}

pub fn buffer_pool_4k_clear() {
    BUFFER_POOL_4K_HITS.store(0, AtomicOrdering::Release);
    BUFFER_POOL_4K_MISSES.store(0, AtomicOrdering::Release);
    BUFFER_POOL_4K_LOCAL_HITS.store(0, AtomicOrdering::Release);
    BUFFER_POOL_4K_POOL
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();

    // Clear per-CPU caches too
    for cpu in 0..MAX_CPUS {
        unsafe {
            for slot in &PER_CPU_BUFFER_CACHE_4K[cpu].slots {
                *slot.get() = None;
            }
            PER_CPU_BUFFER_CACHE_4K[cpu]
                .count
                .store(0, AtomicOrdering::Release);
        }
    }
}

// ---------------------------
// 2MiB Buffer Pool
// ---------------------------
const BUFFER_POOL_2M_DEFAULT_CAPACITY: usize = 16;
static BUFFER_POOL_2M_POOL: IrqPoisonLock<Vec<Vec<u8>>> = IrqPoisonLock::new(Vec::new());
static BUFFER_POOL_2M_HITS: AtomicUsize = AtomicUsize::new(0);
static BUFFER_POOL_2M_MISSES: AtomicUsize = AtomicUsize::new(0);
static BUFFER_POOL_2M_CAPACITY: AtomicUsize = AtomicUsize::new(BUFFER_POOL_2M_DEFAULT_CAPACITY);

pub fn buffer_pool_get_2m() -> Vec<u8> {
    let mut pool = BUFFER_POOL_2M_POOL
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(mut buf) = pool.pop() {
        BUFFER_POOL_2M_HITS.fetch_add(1, AtomicOrdering::AcqRel);
        if buf.len() != crate::mm::types::PAGE_SIZE_2M as usize {
            buf.resize(crate::mm::types::PAGE_SIZE_2M as usize, 0);
        }
        buf
    } else {
        BUFFER_POOL_2M_MISSES.fetch_add(1, AtomicOrdering::AcqRel);
        alloc::vec![0u8; crate::mm::types::PAGE_SIZE_2M as usize]
    }
}

pub fn buffer_pool_put_2m(mut buf: Vec<u8>) {
    if buf.len() != crate::mm::types::PAGE_SIZE_2M as usize {
        buf.resize(crate::mm::types::PAGE_SIZE_2M as usize, 0);
    }
    let cap = BUFFER_POOL_2M_CAPACITY.load(AtomicOrdering::Acquire);
    let mut pool = BUFFER_POOL_2M_POOL
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if pool.len() < cap {
        pool.push(buf);
    }
}

pub fn buffer_pool_2m_stats() -> (usize, usize, usize) {
    (
        BUFFER_POOL_2M_HITS.load(AtomicOrdering::Acquire),
        BUFFER_POOL_2M_MISSES.load(AtomicOrdering::Acquire),
        BUFFER_POOL_2M_POOL
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len(),
    )
}

pub fn buffer_pool_2m_set_capacity(n: usize) {
    BUFFER_POOL_2M_CAPACITY.store(n, AtomicOrdering::Release);
    let mut pool = BUFFER_POOL_2M_POOL
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while pool.len() > n {
        pool.pop();
    }
}

pub fn buffer_pool_2m_clear() {
    BUFFER_POOL_2M_HITS.store(0, AtomicOrdering::Release);
    BUFFER_POOL_2M_MISSES.store(0, AtomicOrdering::Release);
    BUFFER_POOL_2M_POOL
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
}

// ---------------------------
// 1GiB Buffer Pool
// ---------------------------
const BUFFER_POOL_1G_DEFAULT_CAPACITY: usize = 1;
static BUFFER_POOL_1G_POOL: IrqPoisonLock<Vec<Vec<u8>>> = IrqPoisonLock::new(Vec::new());
static BUFFER_POOL_1G_HITS: AtomicUsize = AtomicUsize::new(0);
static BUFFER_POOL_1G_MISSES: AtomicUsize = AtomicUsize::new(0);
static BUFFER_POOL_1G_CAPACITY: AtomicUsize = AtomicUsize::new(BUFFER_POOL_1G_DEFAULT_CAPACITY);
static TOKEN_BUCKET_CAPACITY: AtomicUsize = AtomicUsize::new(0);
static TOKEN_REFILL_PER_BATCH: AtomicUsize = AtomicUsize::new(0);
static RESERVED_FILE_SLOTS: AtomicUsize = AtomicUsize::new(0);
static TOKEN_COUNT: AtomicUsize = AtomicUsize::new(0);
static ZSWAP_FAIL_COUNT: AtomicUsize = AtomicUsize::new(0);
static ASYNC_DEALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
static HUGE_2M_SKIP_COUNT: AtomicUsize = AtomicUsize::new(0);
static WORKER_RUNNING: AtomicBool = AtomicBool::new(false);

pub fn buffer_pool_get_1g() -> Vec<u8> {
    let mut pool = BUFFER_POOL_1G_POOL
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(mut buf) = pool.pop() {
        BUFFER_POOL_1G_HITS.fetch_add(1, AtomicOrdering::AcqRel);
        if buf.len() != crate::mm::types::PAGE_SIZE_1G as usize {
            buf.resize(crate::mm::types::PAGE_SIZE_1G as usize, 0);
        }
        buf
    } else {
        BUFFER_POOL_1G_MISSES.fetch_add(1, AtomicOrdering::AcqRel);
        alloc::vec![0u8; crate::mm::types::PAGE_SIZE_1G as usize]
    }
}

pub fn buffer_pool_put_1g(mut buf: Vec<u8>) {
    if buf.len() != crate::mm::types::PAGE_SIZE_1G as usize {
        buf.resize(crate::mm::types::PAGE_SIZE_1G as usize, 0);
    }
    let cap = BUFFER_POOL_1G_CAPACITY.load(AtomicOrdering::Acquire);
    let mut pool = BUFFER_POOL_1G_POOL
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if pool.len() < cap {
        pool.push(buf);
    }
}

pub fn buffer_pool_1g_stats() -> (usize, usize, usize) {
    (
        BUFFER_POOL_1G_HITS.load(AtomicOrdering::Acquire),
        BUFFER_POOL_1G_MISSES.load(AtomicOrdering::Acquire),
        BUFFER_POOL_1G_POOL
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len(),
    )
}

pub fn buffer_pool_1g_set_capacity(n: usize) {
    BUFFER_POOL_1G_CAPACITY.store(n, AtomicOrdering::Release);
    let mut pool = BUFFER_POOL_1G_POOL
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while pool.len() > n {
        pool.pop();
    }
}

pub fn buffer_pool_1g_clear() {
    BUFFER_POOL_1G_HITS.store(0, AtomicOrdering::Release);
    BUFFER_POOL_1G_MISSES.store(0, AtomicOrdering::Release);
    BUFFER_POOL_1G_POOL
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
}

// ... (rest of helper functions unchanged)

#[derive(Debug, Clone, Copy)]
pub enum SwapKind {
    Anon,
    File { ino: u64, page_num: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapError {
    AlreadyPending,
    QueueFull,
    NotSupported,
}

#[derive(Debug, Clone, Copy)]
pub struct SwapEnqueueHandle;

pub fn try_enqueue_swapout(
    _frame: FrameIndex,
    _kind: SwapKind,
) -> Result<SwapEnqueueHandle, SwapError> {
    Err(SwapError::NotSupported)
}

pub fn queued_counts() -> (usize, usize) {
    (0, 0)
}

pub fn token_count() -> usize {
    TOKEN_COUNT.load(AtomicOrdering::Relaxed)
}

pub fn token_bucket_capacity() -> usize {
    TOKEN_BUCKET_CAPACITY.load(AtomicOrdering::Relaxed)
}

pub fn token_refill_per_batch() -> usize {
    TOKEN_REFILL_PER_BATCH.load(AtomicOrdering::Relaxed)
}

pub fn reserved_file_slots() -> usize {
    RESERVED_FILE_SLOTS.load(AtomicOrdering::Relaxed)
}

pub fn is_worker_running() -> bool {
    WORKER_RUNNING.load(AtomicOrdering::Relaxed)
}

pub fn stats_zswap_fail_count() -> usize {
    ZSWAP_FAIL_COUNT.load(AtomicOrdering::Relaxed)
}

pub fn stats_async_dealloc_count() -> usize {
    ASYNC_DEALLOC_COUNT.load(AtomicOrdering::Relaxed)
}

pub fn stats_huge_2m_skip_count() -> usize {
    HUGE_2M_SKIP_COUNT.load(AtomicOrdering::Relaxed)
}

pub fn set_token_bucket_capacity(v: usize) {
    TOKEN_BUCKET_CAPACITY.store(v, AtomicOrdering::Relaxed);
}

pub fn set_token_refill_per_batch(v: usize) {
    TOKEN_REFILL_PER_BATCH.store(v, AtomicOrdering::Relaxed);
}

pub fn set_reserved_file_slots(v: usize) {
    RESERVED_FILE_SLOTS.store(v, AtomicOrdering::Relaxed);
}
