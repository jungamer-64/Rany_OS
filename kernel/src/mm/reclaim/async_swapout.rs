// ============================================================================
// kernel/src/mm/async_swapout.rs
// ============================================================================
//! 非同期スワップアウト / 書き戻し合流モジュール
//!
//! - テスト時は std スレッドを使ったワーカを起動し非同期処理をシミュレートする
//! - 非テスト（カーネル実装）ではフォールバックとして同期処理を行う
//!
#![allow(dead_code)]

use x86_64::structures::paging::{PhysFrame, Size1GiB, Size2MiB};

use crate::mm::meta::frame_backing;
use crate::mm::phys::buddy_allocator;
use crate::mm::types::FrameIndex;

// ファイルシステム型（Inode）
use crate::fs::fs_abstraction::InodeNum;

/// スワップアウト種別
mod worker;
pub use worker::*;
#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapKind {
    File { ino: InodeNum, page_num: u64 },
    Anon,
}

/// エラー種別
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapError {
    QueueFull,
    AlreadyPending,
    NotSupported,
}

// Completion handle (テスト用に簡易実装)
#[cfg(all(test, feature = "std"))]
use alloc::sync::Arc;

#[cfg(all(test, feature = "std"))]
#[derive(Debug)]
pub struct SwapHandle {
    done: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
}

#[cfg(not(all(test, feature = "std")))]
pub struct SwapHandle;

#[cfg(all(test, feature = "std"))]
impl SwapHandle {
    pub fn wait(&self) {
        let (lock, cvar) = &*self.done;
        let mut done = lock.lock().unwrap();
        while !*done {
            done = cvar.wait(done).unwrap();
        }
    }

    pub fn is_done(&self) -> bool {
        let (lock, _) = &*self.done;
        *lock.lock().unwrap()
    }
}

// 内部エントリ（テスト用）
// 内部エントリ（テスト用）
#[cfg(all(test, feature = "std"))]
struct SwapEntry {
    frame: FrameIndex,
    kind: SwapKind,
    completion: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
}

#[cfg(any(
    all(test, not(feature = "full_mm_tests")),
    feature = "qemu-test-export"
))]
use core::sync::atomic::AtomicU8;
use core::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

#[cfg(any(
    all(test, not(feature = "full_mm_tests")),
    feature = "qemu-test-export"
))]
const TEST_ENQUEUE_OVERRIDE_NONE: u8 = 0;
#[cfg(any(
    all(test, not(feature = "full_mm_tests")),
    feature = "qemu-test-export"
))]
const TEST_ENQUEUE_OVERRIDE_QUEUE_FULL: u8 = 1;
#[cfg(any(
    all(test, not(feature = "full_mm_tests")),
    feature = "qemu-test-export"
))]
const TEST_ENQUEUE_OVERRIDE_ALREADY_PENDING: u8 = 2;
#[cfg(any(
    all(test, not(feature = "full_mm_tests")),
    feature = "qemu-test-export"
))]
const TEST_ENQUEUE_OVERRIDE_NOT_SUPPORTED: u8 = 3;

#[cfg(all(test, not(feature = "full_mm_tests")))]
static TEST_ENQUEUE_OVERRIDE: AtomicU8 = AtomicU8::new(TEST_ENQUEUE_OVERRIDE_NONE);

#[cfg(feature = "qemu-test-export")]
static QEMU_TEST_ENQUEUE_OVERRIDE: AtomicU8 = AtomicU8::new(TEST_ENQUEUE_OVERRIDE_NONE);

#[cfg(any(
    all(test, not(feature = "full_mm_tests")),
    feature = "qemu-test-export"
))]
fn decode_test_enqueue_override(raw: u8) -> Option<SwapError> {
    match raw {
        TEST_ENQUEUE_OVERRIDE_QUEUE_FULL => Some(SwapError::QueueFull),
        TEST_ENQUEUE_OVERRIDE_ALREADY_PENDING => Some(SwapError::AlreadyPending),
        TEST_ENQUEUE_OVERRIDE_NOT_SUPPORTED => Some(SwapError::NotSupported),
        _ => None,
    }
}

#[cfg(any(
    all(test, not(feature = "full_mm_tests")),
    feature = "qemu-test-export"
))]
fn encode_test_enqueue_override(value: Option<SwapError>) -> u8 {
    match value {
        Some(SwapError::QueueFull) => TEST_ENQUEUE_OVERRIDE_QUEUE_FULL,
        Some(SwapError::AlreadyPending) => TEST_ENQUEUE_OVERRIDE_ALREADY_PENDING,
        Some(SwapError::NotSupported) => TEST_ENQUEUE_OVERRIDE_NOT_SUPPORTED,
        None => TEST_ENQUEUE_OVERRIDE_NONE,
    }
}

// Helper: atomic saturating decrement (avoid underflow)
fn atomic_saturating_decrement(a: &core::sync::atomic::AtomicUsize) {
    loop {
        let cur = a.load(core::sync::atomic::Ordering::Acquire);
        if cur == 0 {
            break;
        }
        if a.compare_exchange(
            cur,
            cur - 1,
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
        )
        .is_ok()
        {
            break;
        }
    }
}

// Runtime metrics
static GLOBAL_ZSWAP_FAILS: AtomicUsize = AtomicUsize::new(0);
static GLOBAL_ASYNC_DEALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
static GLOBAL_HUGE_2M_SKIPPED: AtomicUsize = AtomicUsize::new(0);
fn release_frame_and_untrack(frame: FrameIndex) {
    // Untrack from memcg if tracked
    crate::mm::meta::memcg::memcg_untrack_and_uncharge(frame, 1);

    // Untrack frame backing (ignore errors)
    let _ = frame_backing::untrack_frame_backing(frame);

    // Deallocate
    let physf = unsafe {
        PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(frame.to_phys_addr()))
    };
    buddy_allocator::buddy_dealloc_frame(physf);

    // Update global metric
    GLOBAL_ASYNC_DEALLOC_COUNT.fetch_add(1, AtomicOrdering::AcqRel);
}

// Accessors for metrics
pub fn stats_zswap_fail_count() -> usize {
    GLOBAL_ZSWAP_FAILS.load(AtomicOrdering::Acquire)
}

pub fn stats_async_dealloc_count() -> usize {
    GLOBAL_ASYNC_DEALLOC_COUNT.load(AtomicOrdering::Acquire)
}

// ---------------------------
// 4KiB Buffer Pool with Per-CPU Cache
// ---------------------------
// Per-CPU cache enables lock-free buffer access for the common case.
// Each CPU has a local cache slot; overflow goes to the global pool.

const BUFFER_POOL_4K_DEFAULT_CAPACITY: usize = 128;
const MAX_CPUS: usize = 64;
const PER_CPU_CACHE_SIZE: usize = 4; // Number of buffers cached per CPU

// Global pool (overflow/underflow)
static BUFFER_POOL_4K_POOL: spin::Mutex<alloc::vec::Vec<alloc::vec::Vec<u8>>> =
    spin::Mutex::new(alloc::vec::Vec::new());
static BUFFER_POOL_4K_HITS: AtomicUsize = AtomicUsize::new(0);
static BUFFER_POOL_4K_MISSES: AtomicUsize = AtomicUsize::new(0);
static BUFFER_POOL_4K_CAPACITY: AtomicUsize = AtomicUsize::new(BUFFER_POOL_4K_DEFAULT_CAPACITY);

// Per-CPU local cache statistics
static BUFFER_POOL_4K_LOCAL_HITS: AtomicUsize = AtomicUsize::new(0);

// Per-CPU cache structure
struct PerCpuBufferCache4K {
    // Each slot is an Option<Vec<u8>> wrapped in UnsafeCell
    // Access is safe because each CPU only accesses its own slots
    slots: [core::cell::UnsafeCell<Option<alloc::vec::Vec<u8>>>; PER_CPU_CACHE_SIZE],
    // Track how many slots are used
    count: AtomicUsize,
}

impl PerCpuBufferCache4K {
    const fn new() -> Self {
        const EMPTY: core::cell::UnsafeCell<Option<alloc::vec::Vec<u8>>> =
            core::cell::UnsafeCell::new(None);
        Self {
            slots: [EMPTY; PER_CPU_CACHE_SIZE],
            count: AtomicUsize::new(0),
        }
    }

    /// Try to get a buffer from local cache (lock-free)
    /// SAFETY: Caller must ensure this is only called from the owning CPU
    #[inline]
    unsafe fn try_get(&self) -> Option<alloc::vec::Vec<u8>> {
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
    unsafe fn try_put(&self, buf: alloc::vec::Vec<u8>) -> Option<alloc::vec::Vec<u8>> {
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
    // Use the SMP module to get current CPU ID
    // Falls back to 0 if SMP is not initialized
    #[cfg(not(any(test, feature = "std")))]
    {
        crate::smp::current_cpu() as usize % MAX_CPUS
    }
    #[cfg(any(test, feature = "std"))]
    {
        0 // Single CPU for tests
    }
}

pub fn buffer_pool_get_4k() -> alloc::vec::Vec<u8> {
    let cpu = current_cpu_for_cache();

    // Fast path: try local cache first (lock-free)
    // SAFETY: We are on the owning CPU
    if let Some(mut buf) = unsafe { PER_CPU_BUFFER_CACHE_4K[cpu].try_get() } {
        BUFFER_POOL_4K_LOCAL_HITS.fetch_add(1, AtomicOrdering::Relaxed);
        if buf.len() != crate::mm::types::PAGE_SIZE_4K {
            buf.resize(crate::mm::types::PAGE_SIZE_4K, 0);
        }
        return buf;
    }

    // Slow path: try global pool
    let mut pool = BUFFER_POOL_4K_POOL.lock();
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

pub fn buffer_pool_put_4k(mut buf: alloc::vec::Vec<u8>) {
    if buf.len() != crate::mm::types::PAGE_SIZE_4K {
        buf.resize(crate::mm::types::PAGE_SIZE_4K, 0);
    }

    let cpu = current_cpu_for_cache();

    // Fast path: try local cache first (lock-free)
    // SAFETY: We are on the owning CPU
    let overflow = unsafe { PER_CPU_BUFFER_CACHE_4K[cpu].try_put(buf) };

    if let Some(buf) = overflow {
        // Local cache full, put in global pool
        let cap = BUFFER_POOL_4K_CAPACITY.load(AtomicOrdering::Acquire);
        let mut pool = BUFFER_POOL_4K_POOL.lock();
        if pool.len() < cap {
            pool.push(buf);
        }
        // If global pool is also full, buffer is dropped
    }
}

pub fn buffer_pool_4k_stats() -> (usize, usize, usize) {
    (
        BUFFER_POOL_4K_HITS.load(AtomicOrdering::Acquire),
        BUFFER_POOL_4K_MISSES.load(AtomicOrdering::Acquire),
        BUFFER_POOL_4K_POOL.lock().len(),
    )
}

/// Extended stats including local cache hits
pub fn buffer_pool_4k_extended_stats() -> (usize, usize, usize, usize) {
    (
        BUFFER_POOL_4K_LOCAL_HITS.load(AtomicOrdering::Acquire),
        BUFFER_POOL_4K_HITS.load(AtomicOrdering::Acquire),
        BUFFER_POOL_4K_MISSES.load(AtomicOrdering::Acquire),
        BUFFER_POOL_4K_POOL.lock().len(),
    )
}

pub fn buffer_pool_4k_set_capacity(n: usize) {
    BUFFER_POOL_4K_CAPACITY.store(n, AtomicOrdering::Release);
    let mut pool = BUFFER_POOL_4K_POOL.lock();
    while pool.len() > n {
        pool.pop();
    }
}

pub fn buffer_pool_4k_clear() {
    BUFFER_POOL_4K_HITS.store(0, AtomicOrdering::Release);
    BUFFER_POOL_4K_MISSES.store(0, AtomicOrdering::Release);
    BUFFER_POOL_4K_LOCAL_HITS.store(0, AtomicOrdering::Release);
    BUFFER_POOL_4K_POOL.lock().clear();

    // Clear per-CPU caches too
    for cpu in 0..MAX_CPUS {
        // SAFETY: Clearing is safe during initialization/reset
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
static BUFFER_POOL_2M_POOL: spin::Mutex<alloc::vec::Vec<alloc::vec::Vec<u8>>> =
    spin::Mutex::new(alloc::vec::Vec::new());
static BUFFER_POOL_2M_HITS: AtomicUsize = AtomicUsize::new(0);
static BUFFER_POOL_2M_MISSES: AtomicUsize = AtomicUsize::new(0);
static BUFFER_POOL_2M_CAPACITY: AtomicUsize = AtomicUsize::new(BUFFER_POOL_2M_DEFAULT_CAPACITY);

pub fn buffer_pool_get_2m() -> alloc::vec::Vec<u8> {
    let mut pool = BUFFER_POOL_2M_POOL.lock();
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

pub fn buffer_pool_put_2m(mut buf: alloc::vec::Vec<u8>) {
    if buf.len() != crate::mm::types::PAGE_SIZE_2M as usize {
        buf.resize(crate::mm::types::PAGE_SIZE_2M as usize, 0);
    }
    let cap = BUFFER_POOL_2M_CAPACITY.load(AtomicOrdering::Acquire);
    let mut pool = BUFFER_POOL_2M_POOL.lock();
    if pool.len() < cap {
        pool.push(buf);
    }
}

pub fn buffer_pool_2m_stats() -> (usize, usize, usize) {
    (
        BUFFER_POOL_2M_HITS.load(AtomicOrdering::Acquire),
        BUFFER_POOL_2M_MISSES.load(AtomicOrdering::Acquire),
        BUFFER_POOL_2M_POOL.lock().len(),
    )
}

pub fn buffer_pool_2m_set_capacity(n: usize) {
    BUFFER_POOL_2M_CAPACITY.store(n, AtomicOrdering::Release);
    let mut pool = BUFFER_POOL_2M_POOL.lock();
    while pool.len() > n {
        pool.pop();
    }
}

pub fn buffer_pool_2m_clear() {
    BUFFER_POOL_2M_HITS.store(0, AtomicOrdering::Release);
    BUFFER_POOL_2M_MISSES.store(0, AtomicOrdering::Release);
    BUFFER_POOL_2M_POOL.lock().clear();
}

// ---------------------------
// 1GiB Buffer Pool
// ---------------------------
const BUFFER_POOL_1G_DEFAULT_CAPACITY: usize = 1;
static BUFFER_POOL_1G_POOL: spin::Mutex<alloc::vec::Vec<alloc::vec::Vec<u8>>> =
    spin::Mutex::new(alloc::vec::Vec::new());
static BUFFER_POOL_1G_HITS: AtomicUsize = AtomicUsize::new(0);
static BUFFER_POOL_1G_MISSES: AtomicUsize = AtomicUsize::new(0);
static BUFFER_POOL_1G_CAPACITY: AtomicUsize = AtomicUsize::new(BUFFER_POOL_1G_DEFAULT_CAPACITY);

pub fn buffer_pool_get_1g() -> alloc::vec::Vec<u8> {
    let mut pool = BUFFER_POOL_1G_POOL.lock();
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

pub fn buffer_pool_put_1g(mut buf: alloc::vec::Vec<u8>) {
    if buf.len() != crate::mm::types::PAGE_SIZE_1G as usize {
        buf.resize(crate::mm::types::PAGE_SIZE_1G as usize, 0);
    }
    let cap = BUFFER_POOL_1G_CAPACITY.load(AtomicOrdering::Acquire);
    let mut pool = BUFFER_POOL_1G_POOL.lock();
    if pool.len() < cap {
        pool.push(buf);
    }
}

pub fn buffer_pool_1g_stats() -> (usize, usize, usize) {
    (
        BUFFER_POOL_1G_HITS.load(AtomicOrdering::Acquire),
        BUFFER_POOL_1G_MISSES.load(AtomicOrdering::Acquire),
        BUFFER_POOL_1G_POOL.lock().len(),
    )
}

pub fn buffer_pool_1g_set_capacity(n: usize) {
    BUFFER_POOL_1G_CAPACITY.store(n, AtomicOrdering::Release);
    let mut pool = BUFFER_POOL_1G_POOL.lock();
    while pool.len() > n {
        pool.pop();
    }
}

pub fn buffer_pool_1g_clear() {
    BUFFER_POOL_1G_HITS.store(0, AtomicOrdering::Release);
    BUFFER_POOL_1G_MISSES.store(0, AtomicOrdering::Release);
    BUFFER_POOL_1G_POOL.lock().clear();
}

// Helper: try storing page to zswap using provided buffer and deallocate on success.
// Returns true if deallocated, false otherwise.
fn try_zswap_store_and_dealloc(frame: FrameIndex, buf: &mut [u8]) -> bool {
    if crate::mm::reclaim::zswap::zswap_is_enabled() {
        let phys = frame.to_phys_addr();
        let vaddr = crate::mm::virt::mapping::phys_to_virt(x86_64::PhysAddr::new(phys));
        let src = vaddr.as_u64() as *const u8;
        unsafe {
            core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), crate::mm::types::PAGE_SIZE_4K);
        }
        match crate::mm::reclaim::zswap::zswap_store(0, buf) {
            Ok(_) => {
                let physf = unsafe {
                    PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(
                        frame.to_phys_addr(),
                    ))
                };
                buddy_allocator::buddy_dealloc_frame(physf);
                GLOBAL_ASYNC_DEALLOC_COUNT.fetch_add(1, AtomicOrdering::AcqRel);
                true
            }
            Err(e) => {
                log::warn!("zswap_store failed for frame {:?}: {:?}", frame, e);
                GLOBAL_ZSWAP_FAILS.fetch_add(1, AtomicOrdering::AcqRel);
                false
            }
        }
    } else {
        // zswap disabled -> just dealloc
        let physf = unsafe {
            PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(frame.to_phys_addr()))
        };
        buddy_allocator::buddy_dealloc_frame(physf);
        true
    }
}

// Detect page size for a given frame. Returns PAGE_SIZE_1G / PAGE_SIZE_2M / PAGE_SIZE_4K
// Conservative check: alignment + all subframes allocated.
/// Check if ALL frames in a contiguous range starting at `base` with count `frame_count` are allocated.
fn are_contiguous_frames_allocated(base: usize, frame_count: usize) -> bool {
    for i in 0..frame_count {
        if !crate::mm::phys::buddy_allocator::is_frame_allocated(base + i) {
            return false;
        }
    }
    true
}

fn detect_frame_page_size(frame: FrameIndex) -> usize {
    // Try 1GiB first (very rare)
    let frames_per_1g = crate::mm::types::PAGE_SIZE_1G / crate::mm::types::PAGE_SIZE_4K;
    if frame.as_usize() % frames_per_1g == 0
        && are_contiguous_frames_allocated(frame.as_usize(), frames_per_1g)
    {
        return crate::mm::types::PAGE_SIZE_1G;
    }

    // Try 2MiB
    let frames_per_2m = crate::mm::types::PAGE_SIZE_2M / crate::mm::types::PAGE_SIZE_4K;
    if frame.as_usize() % frames_per_2m == 0
        && are_contiguous_frames_allocated(frame.as_usize(), frames_per_2m)
    {
        return crate::mm::types::PAGE_SIZE_2M;
    }

    // Otherwise treat as 4KiB page
    crate::mm::types::PAGE_SIZE_4K
}

/// Deallocate a physical frame using the buddy allocator (without zswap).
fn dealloc_frame_by_size(phys: u64, page_size: usize) -> bool {
    match page_size {
        s if s == crate::mm::types::PAGE_SIZE_4K => {
            let physf =
                unsafe { PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(phys)) };
            buddy_allocator::buddy_dealloc_frame(physf);
            true
        }
        s if s == crate::mm::types::PAGE_SIZE_2M => {
            let physf2m = unsafe {
                PhysFrame::<Size2MiB>::from_start_address_unchecked(x86_64::PhysAddr::new(phys))
            };
            buddy_allocator::buddy_dealloc_frame_2m(physf2m);
            true
        }
        s if s == crate::mm::types::PAGE_SIZE_1G => {
            let physf1g = unsafe {
                PhysFrame::<Size1GiB>::from_start_address_unchecked(x86_64::PhysAddr::new(phys))
            };
            buddy_allocator::buddy_dealloc_frame_1g(physf1g);
            true
        }
        _ => false,
    }
}

/// Attempt zswap store for a frame, then deallocate on success.
/// `buf` must cover the full page contents.
fn zswap_store_then_dealloc(frame: FrameIndex, phys: u64, page_size: usize, buf: &[u8]) -> bool {
    match crate::mm::reclaim::zswap::zswap_store_auto(buf) {
        Ok(_) => {
            dealloc_frame_by_size(phys, page_size);
            GLOBAL_ASYNC_DEALLOC_COUNT.fetch_add(1, AtomicOrdering::AcqRel);
            true
        }
        Err(e) => {
            log::warn!(
                "zswap_store failed for {:?} frame {:?}: {:?}",
                page_size,
                frame,
                e
            );
            GLOBAL_ZSWAP_FAILS.fetch_add(1, AtomicOrdering::AcqRel);
            false
        }
    }
}

// Generic helper: try storing page to zswap (4K/2M/1G) using available buffer(s) and
// deallocate via the appropriate buddy deallocator on success. Returns true if deallocated.
fn try_zswap_store_and_dealloc_any(frame: FrameIndex, buf4k: &mut [u8]) -> bool {
    let page_size = detect_frame_page_size(frame);
    let phys = frame.to_phys_addr();

    // If zswap is disabled, just dealloc directly according to page size
    if !crate::mm::reclaim::zswap::zswap_is_enabled() {
        return dealloc_frame_by_size(phys, page_size);
    }

    // zswap enabled: copy page contents, store, and dealloc on success
    match page_size {
        s if s == crate::mm::types::PAGE_SIZE_4K => {
            let vaddr = crate::mm::virt::mapping::phys_to_virt(x86_64::PhysAddr::new(phys));
            let src = vaddr.as_u64() as *const u8;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    src,
                    buf4k.as_mut_ptr(),
                    crate::mm::types::PAGE_SIZE_4K,
                );
            }
            zswap_store_then_dealloc(frame, phys, page_size, buf4k)
        }
        s if s == crate::mm::types::PAGE_SIZE_2M => {
            let mut buf = crate::mm::reclaim::async_swapout::buffer_pool_get_2m();
            let vaddr = crate::mm::virt::mapping::phys_to_virt(x86_64::PhysAddr::new(phys));
            unsafe {
                core::ptr::copy_nonoverlapping(
                    vaddr.as_u64() as *const u8,
                    buf.as_mut_ptr(),
                    crate::mm::types::PAGE_SIZE_2M,
                );
            }
            let ok = zswap_store_then_dealloc(frame, phys, page_size, &buf);
            crate::mm::reclaim::async_swapout::buffer_pool_put_2m(buf);
            ok
        }
        s if s == crate::mm::types::PAGE_SIZE_1G => {
            let mut buf = crate::mm::reclaim::async_swapout::buffer_pool_get_1g();
            let vaddr = crate::mm::virt::mapping::phys_to_virt(x86_64::PhysAddr::new(phys));
            unsafe {
                core::ptr::copy_nonoverlapping(
                    vaddr.as_u64() as *const u8,
                    buf.as_mut_ptr(),
                    crate::mm::types::PAGE_SIZE_1G,
                );
            }
            let ok = zswap_store_then_dealloc(frame, phys, page_size, &buf);
            crate::mm::reclaim::async_swapout::buffer_pool_put_1g(buf);
            ok
        }
        _ => false,
    }
}

// テスト専用: 永続ワーカ実装（条件変数 + バウンドキュー）
pub fn stats_huge_2m_skip_count() -> u64 {
    GLOBAL_HUGE_2M_SKIPPED.load(AtomicOrdering::Acquire) as u64
}
