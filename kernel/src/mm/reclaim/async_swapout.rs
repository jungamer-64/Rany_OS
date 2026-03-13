// SPDX-License-Identifier: MIT
// ExoRust Kernel - Async Page Swapout & Buffer Management
// 設計書 5.2: Tier2/Tier3 統合, 設計書 10.4: 非同期I/Oとスワップアウト
#![allow(dead_code)]

use crate::mm::types::FrameIndex;
use crate::sync::IrqPoisonLock;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};
use x86_64::PhysAddr;
use x86_64::structures::paging::{PhysFrame, Size1GiB, Size2MiB, Size4KiB};

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests;
#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
mod worker;

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
        crate::cpu::current_id() % MAX_CPUS
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
static GLOBAL_HUGE_2M_SKIPPED: AtomicUsize = AtomicUsize::new(0);
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

pub type Buffer4K = Vec<u8>;

#[derive(Debug, Clone)]
pub struct SwapHandle {
    #[cfg(all(test, feature = "std"))]
    done: alloc::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
}

impl SwapHandle {
    #[cfg(all(test, feature = "std"))]
    pub fn wait(&self) {
        let (lock, cvar) = &*self.done;
        let mut done = lock.lock().unwrap();
        while !*done {
            done = cvar.wait(done).unwrap();
        }
    }

    #[cfg(not(all(test, feature = "std")))]
    pub fn wait(&self) {}
}

#[derive(Debug, Clone)]
pub struct SwapEntry {
    frame: FrameIndex,
    kind: SwapKind,
    #[cfg(all(test, feature = "std"))]
    completion: alloc::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
}

fn atomic_saturating_decrement(counter: &AtomicUsize) {
    let mut current = counter.load(AtomicOrdering::Acquire);
    loop {
        if current == 0 {
            return;
        }
        match counter.compare_exchange(
            current,
            current - 1,
            AtomicOrdering::AcqRel,
            AtomicOrdering::Acquire,
        ) {
            Ok(_) => return,
            Err(next) => current = next,
        }
    }
}

fn release_frame_and_untrack(frame: FrameIndex) {
    let order = crate::mm::meta::page_flags::get_order(frame) as usize;
    let head = frame.align_down(order);
    let pages = 1u64 << order.min(63);

    crate::mm::meta::memcg::memcg_untrack_and_uncharge(head, pages);
    let _ = crate::mm::meta::frame_backing::untrack_frame_backing(head);

    // SAFETY: `head` is a buddy-allocator frame head obtained from page metadata,
    // and the page order selects the matching deallocation routine.
    unsafe {
        let phys = PhysAddr::new(head.to_phys_addr());
        if order >= crate::mm::types::HUGE_PAGE_ORDER_1GB {
            crate::mm::phys::buddy_allocator::buddy_dealloc_frame_1g(
                PhysFrame::<Size1GiB>::from_start_address_unchecked(phys),
            );
        } else if order >= crate::mm::types::HUGE_PAGE_ORDER_2MB {
            crate::mm::phys::buddy_allocator::buddy_dealloc_frame_2m(
                PhysFrame::<Size2MiB>::from_start_address_unchecked(phys),
            );
        } else {
            crate::mm::phys::buddy_allocator::buddy_dealloc_frame(
                PhysFrame::<Size4KiB>::from_start_address_unchecked(phys),
            );
        }
    }
}

fn try_zswap_store_and_dealloc_any(frame: FrameIndex, reuse_buf: &mut Buffer4K) -> bool {
    let order = crate::mm::meta::page_flags::get_order(frame) as usize;
    let size = if order >= crate::mm::types::HUGE_PAGE_ORDER_1GB {
        GLOBAL_HUGE_2M_SKIPPED.fetch_add(1, AtomicOrdering::AcqRel);
        return false;
    } else if order >= crate::mm::types::HUGE_PAGE_ORDER_2MB {
        crate::mm::types::PAGE_SIZE_2M
    } else {
        crate::mm::types::PAGE_SIZE_4K
    };

    if reuse_buf.len() != size {
        reuse_buf.resize(size, 0);
    }

    let virt = crate::mm::virt::mapping::phys_to_virt(PhysAddr::new(frame.to_phys_addr()));
    // SAFETY: the caller owns the frame while it is swap-pending, and the higher-half
    // direct map provides a valid contiguous mapping for the selected page size.
    unsafe {
        let src = core::slice::from_raw_parts(virt.as_ptr::<u8>(), size);
        reuse_buf[..size].copy_from_slice(src);
    }

    match crate::mm::reclaim::zswap::zswap_store_auto(&reuse_buf[..size]) {
        Ok(_) => {
            release_frame_and_untrack(frame);
            ASYNC_DEALLOC_COUNT.fetch_add(1, AtomicOrdering::AcqRel);
            true
        }
        Err(_) => {
            ZSWAP_FAIL_COUNT.fetch_add(1, AtomicOrdering::AcqRel);
            false
        }
    }
}

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

pub type SwapEnqueueHandle = SwapHandle;

pub fn try_enqueue_swapout(
    frame: FrameIndex,
    kind: SwapKind,
) -> Result<SwapEnqueueHandle, SwapError> {
    #[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
    {
        worker::try_enqueue_swapout(frame, kind)
    }

    #[cfg(all(
        test,
        not(feature = "full_mm_tests"),
        not(feature = "qemu-test-export")
    ))]
    {
        let _ = (frame, kind);
        Err(SwapError::NotSupported)
    }
}

pub fn queued_counts() -> (usize, usize) {
    #[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
    {
        worker::queued_counts()
    }

    #[cfg(all(
        test,
        not(feature = "full_mm_tests"),
        not(feature = "qemu-test-export")
    ))]
    {
        (0, 0)
    }
}

pub fn token_count() -> usize {
    #[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
    {
        worker::token_count()
    }

    #[cfg(all(
        test,
        not(feature = "full_mm_tests"),
        not(feature = "qemu-test-export")
    ))]
    {
        TOKEN_COUNT.load(AtomicOrdering::Relaxed)
    }
}

pub fn token_bucket_capacity() -> usize {
    #[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
    {
        worker::token_bucket_capacity()
    }

    #[cfg(all(
        test,
        not(feature = "full_mm_tests"),
        not(feature = "qemu-test-export")
    ))]
    {
        TOKEN_BUCKET_CAPACITY.load(AtomicOrdering::Relaxed)
    }
}

pub fn token_refill_per_batch() -> usize {
    #[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
    {
        worker::token_refill_per_batch()
    }

    #[cfg(all(
        test,
        not(feature = "full_mm_tests"),
        not(feature = "qemu-test-export")
    ))]
    {
        TOKEN_REFILL_PER_BATCH.load(AtomicOrdering::Relaxed)
    }
}

pub fn reserved_file_slots() -> usize {
    #[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
    {
        worker::reserved_file_slots()
    }

    #[cfg(all(
        test,
        not(feature = "full_mm_tests"),
        not(feature = "qemu-test-export")
    ))]
    {
        RESERVED_FILE_SLOTS.load(AtomicOrdering::Relaxed)
    }
}

pub fn is_worker_running() -> bool {
    #[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
    {
        worker::is_worker_running()
    }

    #[cfg(all(
        test,
        not(feature = "full_mm_tests"),
        not(feature = "qemu-test-export")
    ))]
    {
        WORKER_RUNNING.load(AtomicOrdering::Relaxed)
    }
}

pub fn stats_zswap_fail_count() -> usize {
    ZSWAP_FAIL_COUNT.load(AtomicOrdering::Relaxed)
}

pub fn stats_async_dealloc_count() -> usize {
    ASYNC_DEALLOC_COUNT.load(AtomicOrdering::Relaxed)
}

pub fn stats_huge_2m_skip_count() -> usize {
    GLOBAL_HUGE_2M_SKIPPED.load(AtomicOrdering::Relaxed)
}

pub fn set_token_bucket_capacity(v: usize) {
    #[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
    {
        worker::set_token_bucket_capacity(v);
    }

    #[cfg(all(
        test,
        not(feature = "full_mm_tests"),
        not(feature = "qemu-test-export")
    ))]
    {
        TOKEN_BUCKET_CAPACITY.store(v, AtomicOrdering::Relaxed);
    }
}

pub fn set_token_refill_per_batch(v: usize) {
    #[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
    {
        worker::set_token_refill_per_batch(v);
    }

    #[cfg(all(
        test,
        not(feature = "full_mm_tests"),
        not(feature = "qemu-test-export")
    ))]
    {
        TOKEN_REFILL_PER_BATCH.store(v, AtomicOrdering::Relaxed);
    }
}

pub fn set_reserved_file_slots(v: usize) {
    #[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
    {
        worker::set_reserved_file_slots(v);
    }

    #[cfg(all(
        test,
        not(feature = "full_mm_tests"),
        not(feature = "qemu-test-export")
    ))]
    {
        RESERVED_FILE_SLOTS.store(v, AtomicOrdering::Relaxed);
    }
}

pub fn set_token_count(v: usize) {
    #[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
    {
        worker::set_token_count(v);
    }

    #[cfg(all(
        test,
        not(feature = "full_mm_tests"),
        not(feature = "qemu-test-export")
    ))]
    {
        TOKEN_COUNT.store(v, AtomicOrdering::Relaxed);
    }
}

pub fn add_tokens(v: usize) {
    #[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
    {
        worker::add_tokens(v);
    }

    #[cfg(all(
        test,
        not(feature = "full_mm_tests"),
        not(feature = "qemu-test-export")
    ))]
    {
        let current = TOKEN_COUNT.load(AtomicOrdering::Acquire);
        let cap = TOKEN_BUCKET_CAPACITY.load(AtomicOrdering::Acquire);
        TOKEN_COUNT.store(current.saturating_add(v).min(cap), AtomicOrdering::Release);
    }
}

pub fn start_worker() {
    #[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
    {
        worker::start_worker();
    }

    #[cfg(all(
        test,
        not(feature = "full_mm_tests"),
        not(feature = "qemu-test-export")
    ))]
    {
        WORKER_RUNNING.store(true, AtomicOrdering::Relaxed);
    }
}

pub fn stop_worker() {
    #[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
    {
        worker::stop_worker();
    }

    #[cfg(all(
        test,
        not(feature = "full_mm_tests"),
        not(feature = "qemu-test-export")
    ))]
    {
        WORKER_RUNNING.store(false, AtomicOrdering::Relaxed);
    }
}

#[cfg(test)]
pub fn set_test_enqueue_override(value: Option<SwapError>) {
    #[cfg(feature = "qemu-test-export")]
    {
        worker::qemu_test_set_enqueue_override(value);
        return;
    }

    #[cfg(not(feature = "qemu-test-export"))]
    {
        worker::set_test_enqueue_override(value);
    }
}

#[cfg(feature = "qemu-test-export")]
pub fn qemu_test_set_enqueue_override(value: Option<SwapError>) {
    worker::qemu_test_set_enqueue_override(value);
}

#[cfg(feature = "qemu-test-export")]
pub fn qemu_test_clear_enqueue_override() {
    worker::qemu_test_clear_enqueue_override();
}

#[cfg(feature = "qemu-test-export")]
pub fn qemu_test_drain_until_idle(max_rounds: usize) -> bool {
    worker::qemu_test_drain_until_idle(max_rounds)
}

#[cfg(feature = "qemu-test-export")]
pub fn qemu_test_reset_worker_runtime_state() {
    worker::qemu_test_reset_worker_runtime_state();
}
