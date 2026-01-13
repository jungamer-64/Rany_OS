// ============================================================================
// kernel/src/mm/async_swapout.rs
// ============================================================================
//! 非同期スワップアウト / 書き戻し合流モジュール
//!
//! - テスト時は std スレッドを使ったワーカを起動し非同期処理をシミュレートする
//! - 非テスト（カーネル実装）ではフォールバックとして同期処理を行う
//!
#![allow(dead_code)]

use x86_64::structures::paging::{PhysFrame, Size2MiB, Size1GiB};

use crate::mm::types::FrameIndex;
use crate::mm::frame_backing;
use crate::mm::buddy_allocator;

// ファイルシステム型（Inode）
use crate::fs::fs_abstraction::InodeNum;


/// スワップアウト種別
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

use core::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

// Helper: atomic saturating decrement (avoid underflow)
fn atomic_saturating_decrement(a: &core::sync::atomic::AtomicUsize) {
    loop {
        let cur = a.load(core::sync::atomic::Ordering::Acquire);
        if cur == 0 { break; }
        if a.compare_exchange(cur, cur - 1, core::sync::atomic::Ordering::AcqRel, core::sync::atomic::Ordering::Acquire).is_ok() { break; }
    }
}

// Runtime metrics
static GLOBAL_ZSWAP_FAILS: AtomicUsize = AtomicUsize::new(0);
static GLOBAL_ASYNC_DEALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
    static GLOBAL_HUGE_2M_SKIPPED: AtomicUsize = AtomicUsize::new(0);
fn release_frame_and_untrack(frame: FrameIndex) {
    // Untrack from memcg if tracked
    if let Some(info) = crate::mm::memcg::memcg_untrack_page(frame) {
        let _ = crate::mm::memcg::memcg_uncharge(info.memcg_id, 1, info.charge_type);
    }

    // Untrack frame backing (ignore errors)
    let _ = frame_backing::untrack_frame_backing(frame);

    // Deallocate
    let physf = unsafe { PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(frame.to_phys_addr())) };
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
static BUFFER_POOL_4K_POOL: spin::Mutex<alloc::vec::Vec<alloc::vec::Vec<u8>>> = spin::Mutex::new(alloc::vec::Vec::new());
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
        if buf.len() != crate::mm::PAGE_SIZE_4K { 
            buf.resize(crate::mm::PAGE_SIZE_4K, 0); 
        }
        return buf;
    }
    
    // Slow path: try global pool
    let mut pool = BUFFER_POOL_4K_POOL.lock();
    if let Some(mut buf) = pool.pop() {
        BUFFER_POOL_4K_HITS.fetch_add(1, AtomicOrdering::AcqRel);
        if buf.len() != crate::mm::PAGE_SIZE_4K { 
            buf.resize(crate::mm::PAGE_SIZE_4K, 0); 
        }
        buf
    } else {
        drop(pool);
        BUFFER_POOL_4K_MISSES.fetch_add(1, AtomicOrdering::AcqRel);
        alloc::vec![0u8; crate::mm::PAGE_SIZE_4K]
    }
}

pub fn buffer_pool_put_4k(mut buf: alloc::vec::Vec<u8>) {
    if buf.len() != crate::mm::PAGE_SIZE_4K { 
        buf.resize(crate::mm::PAGE_SIZE_4K, 0); 
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
        BUFFER_POOL_4K_POOL.lock().len()
    )
}

/// Extended stats including local cache hits
pub fn buffer_pool_4k_extended_stats() -> (usize, usize, usize, usize) {
    (
        BUFFER_POOL_4K_LOCAL_HITS.load(AtomicOrdering::Acquire),
        BUFFER_POOL_4K_HITS.load(AtomicOrdering::Acquire), 
        BUFFER_POOL_4K_MISSES.load(AtomicOrdering::Acquire), 
        BUFFER_POOL_4K_POOL.lock().len()
    )
}

pub fn buffer_pool_4k_set_capacity(n: usize) {
    BUFFER_POOL_4K_CAPACITY.store(n, AtomicOrdering::Release);
    let mut pool = BUFFER_POOL_4K_POOL.lock();
    while pool.len() > n { pool.pop(); }
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
            PER_CPU_BUFFER_CACHE_4K[cpu].count.store(0, AtomicOrdering::Release);
        }
    }
}

// ---------------------------
// 2MiB Buffer Pool
// ---------------------------
const BUFFER_POOL_2M_DEFAULT_CAPACITY: usize = 16;
static BUFFER_POOL_2M_POOL: spin::Mutex<alloc::vec::Vec<alloc::vec::Vec<u8>>> = spin::Mutex::new(alloc::vec::Vec::new());
static BUFFER_POOL_2M_HITS: AtomicUsize = AtomicUsize::new(0);
static BUFFER_POOL_2M_MISSES: AtomicUsize = AtomicUsize::new(0);
static BUFFER_POOL_2M_CAPACITY: AtomicUsize = AtomicUsize::new(BUFFER_POOL_2M_DEFAULT_CAPACITY);

pub fn buffer_pool_get_2m() -> alloc::vec::Vec<u8> {
    let mut pool = BUFFER_POOL_2M_POOL.lock();
    if let Some(mut buf) = pool.pop() {
        BUFFER_POOL_2M_HITS.fetch_add(1, AtomicOrdering::AcqRel);
        if buf.len() != crate::mm::PAGE_SIZE_2M as usize { buf.resize(crate::mm::PAGE_SIZE_2M as usize, 0); }
        buf
    } else {
        BUFFER_POOL_2M_MISSES.fetch_add(1, AtomicOrdering::AcqRel);
        alloc::vec![0u8; crate::mm::PAGE_SIZE_2M as usize]
    }
}

pub fn buffer_pool_put_2m(mut buf: alloc::vec::Vec<u8>) {
    if buf.len() != crate::mm::PAGE_SIZE_2M as usize { buf.resize(crate::mm::PAGE_SIZE_2M as usize, 0); }
    let cap = BUFFER_POOL_2M_CAPACITY.load(AtomicOrdering::Acquire);
    let mut pool = BUFFER_POOL_2M_POOL.lock();
    if pool.len() < cap {
        pool.push(buf);
    }
}

pub fn buffer_pool_2m_stats() -> (usize, usize, usize) {
    (BUFFER_POOL_2M_HITS.load(AtomicOrdering::Acquire), BUFFER_POOL_2M_MISSES.load(AtomicOrdering::Acquire), BUFFER_POOL_2M_POOL.lock().len())
}

pub fn buffer_pool_2m_set_capacity(n: usize) {
    BUFFER_POOL_2M_CAPACITY.store(n, AtomicOrdering::Release);
    let mut pool = BUFFER_POOL_2M_POOL.lock();
    while pool.len() > n { pool.pop(); }
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
static BUFFER_POOL_1G_POOL: spin::Mutex<alloc::vec::Vec<alloc::vec::Vec<u8>>> = spin::Mutex::new(alloc::vec::Vec::new());
static BUFFER_POOL_1G_HITS: AtomicUsize = AtomicUsize::new(0);
static BUFFER_POOL_1G_MISSES: AtomicUsize = AtomicUsize::new(0);
static BUFFER_POOL_1G_CAPACITY: AtomicUsize = AtomicUsize::new(BUFFER_POOL_1G_DEFAULT_CAPACITY);

pub fn buffer_pool_get_1g() -> alloc::vec::Vec<u8> {
    let mut pool = BUFFER_POOL_1G_POOL.lock();
    if let Some(mut buf) = pool.pop() {
        BUFFER_POOL_1G_HITS.fetch_add(1, AtomicOrdering::AcqRel);
        if buf.len() != crate::mm::PAGE_SIZE_1G as usize { buf.resize(crate::mm::PAGE_SIZE_1G as usize, 0); }
        buf
    } else {
        BUFFER_POOL_1G_MISSES.fetch_add(1, AtomicOrdering::AcqRel);
        alloc::vec![0u8; crate::mm::PAGE_SIZE_1G as usize]
    }
}

pub fn buffer_pool_put_1g(mut buf: alloc::vec::Vec<u8>) {
    if buf.len() != crate::mm::PAGE_SIZE_1G as usize { buf.resize(crate::mm::PAGE_SIZE_1G as usize, 0); }
    let cap = BUFFER_POOL_1G_CAPACITY.load(AtomicOrdering::Acquire);
    let mut pool = BUFFER_POOL_1G_POOL.lock();
    if pool.len() < cap {
        pool.push(buf);
    }
}

pub fn buffer_pool_1g_stats() -> (usize, usize, usize) {
    (BUFFER_POOL_1G_HITS.load(AtomicOrdering::Acquire), BUFFER_POOL_1G_MISSES.load(AtomicOrdering::Acquire), BUFFER_POOL_1G_POOL.lock().len())
}

pub fn buffer_pool_1g_set_capacity(n: usize) {
    BUFFER_POOL_1G_CAPACITY.store(n, AtomicOrdering::Release);
    let mut pool = BUFFER_POOL_1G_POOL.lock();
    while pool.len() > n { pool.pop(); }
}

pub fn buffer_pool_1g_clear() {
    BUFFER_POOL_1G_HITS.store(0, AtomicOrdering::Release);
    BUFFER_POOL_1G_MISSES.store(0, AtomicOrdering::Release);
    BUFFER_POOL_1G_POOL.lock().clear();
}

// Helper: try storing page to zswap using provided buffer and deallocate on success.
// Returns true if deallocated, false otherwise.
fn try_zswap_store_and_dealloc(frame: FrameIndex, buf: &mut [u8]) -> bool {
    if crate::mm::zswap::zswap_is_enabled() {
        let phys = frame.to_phys_addr();
        let vaddr = crate::mm::mapping::phys_to_virt(x86_64::PhysAddr::new(phys));
        let src = vaddr.as_u64() as *const u8;
        unsafe { core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), crate::mm::PAGE_SIZE_4K); }
        match crate::mm::zswap::zswap_store(0, buf) {
            Ok(_) => {
                let physf = unsafe { PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(frame.to_phys_addr())) };
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
        let physf = unsafe { PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(frame.to_phys_addr())) };
        buddy_allocator::buddy_dealloc_frame(physf);
        true
    }
}

// Detect page size for a given frame. Returns PAGE_SIZE_1G / PAGE_SIZE_2M / PAGE_SIZE_4K
// Conservative check: alignment + all subframes allocated.
fn detect_frame_page_size(frame: FrameIndex) -> usize {
    // Try 1GiB first (very rare)
    let frames_per_1g = crate::mm::PAGE_SIZE_1G / crate::mm::PAGE_SIZE_4K;
    if frame.as_usize() % frames_per_1g == 0 {
        let mut ok = true;
        for i in 0..frames_per_1g {
            if !crate::mm::buddy_allocator::is_frame_allocated(frame.as_usize() + i) {
                ok = false;
                break;
            }
        }
        if ok { return crate::mm::PAGE_SIZE_1G; }
    }

    // Try 2MiB
    let frames_per_2m = crate::mm::PAGE_SIZE_2M / crate::mm::PAGE_SIZE_4K;
    if frame.as_usize() % frames_per_2m == 0 {
        let mut ok = true;
        for i in 0..frames_per_2m {
            if !crate::mm::buddy_allocator::is_frame_allocated(frame.as_usize() + i) {
                ok = false;
                break;
            }
        }
        if ok { return crate::mm::PAGE_SIZE_2M; }
    }

    // Otherwise treat as 4KiB page
    crate::mm::PAGE_SIZE_4K
}

// Generic helper: try storing page to zswap (4K/2M/1G) using available buffer(s) and
// deallocate via the appropriate buddy deallocator on success. Returns true if deallocated.
fn try_zswap_store_and_dealloc_any(frame: FrameIndex, buf4k: &mut [u8]) -> bool {
    let page_size = detect_frame_page_size(frame);
    let phys = frame.to_phys_addr();

    // If zswap is disabled, just dealloc directly according to page size
    if !crate::mm::zswap::zswap_is_enabled() {
        match page_size {
            s if s == crate::mm::PAGE_SIZE_4K => {
                let physf = unsafe { PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(phys)) };
                buddy_allocator::buddy_dealloc_frame(physf);
                return true;
            }
            s if s == crate::mm::PAGE_SIZE_2M => {
                let physf2m = unsafe { PhysFrame::<Size2MiB>::from_start_address_unchecked(x86_64::PhysAddr::new(phys)) };
                buddy_allocator::buddy_dealloc_frame_2m(physf2m);
                return true;
            }
            s if s == crate::mm::PAGE_SIZE_1G => {
                let physf1g = unsafe { PhysFrame::<Size1GiB>::from_start_address_unchecked(x86_64::PhysAddr::new(phys)) };
                buddy_allocator::buddy_dealloc_frame_1g(physf1g);
                return true;
            }
            _ => return false,
        }
    }

    // zswap enabled: perform store and dealloc on success
    match page_size {
        s if s == crate::mm::PAGE_SIZE_4K => {
            let vaddr = crate::mm::mapping::phys_to_virt(x86_64::PhysAddr::new(phys));
            let src = vaddr.as_u64() as *const u8;
            unsafe { core::ptr::copy_nonoverlapping(src, buf4k.as_mut_ptr(), crate::mm::PAGE_SIZE_4K); }
            match crate::mm::zswap::zswap_store_auto(buf4k) {
                Ok(_) => {
                    let physf = unsafe { PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(phys)) };
                    buddy_allocator::buddy_dealloc_frame(physf);
                    GLOBAL_ASYNC_DEALLOC_COUNT.fetch_add(1, AtomicOrdering::AcqRel);
                    true
                }
                Err(e) => {
                    log::warn!("zswap_store failed for 4K frame {:?}: {:?}", frame, e);
                    GLOBAL_ZSWAP_FAILS.fetch_add(1, AtomicOrdering::AcqRel);
                    false
                }
            }
        }
        s if s == crate::mm::PAGE_SIZE_2M => {
            let mut buf = crate::mm::async_swapout::buffer_pool_get_2m();
            let vaddr = crate::mm::mapping::phys_to_virt(x86_64::PhysAddr::new(phys));
            unsafe { core::ptr::copy_nonoverlapping(vaddr.as_u64() as *const u8, buf.as_mut_ptr(), crate::mm::PAGE_SIZE_2M); }
            match crate::mm::zswap::zswap_store_auto(&buf) {
                Ok(_) => {
                    let physf2m = unsafe { PhysFrame::<Size2MiB>::from_start_address_unchecked(x86_64::PhysAddr::new(phys)) };
                    buddy_allocator::buddy_dealloc_frame_2m(physf2m);
                    GLOBAL_ASYNC_DEALLOC_COUNT.fetch_add(1, AtomicOrdering::AcqRel);
                    crate::mm::async_swapout::buffer_pool_put_2m(buf);
                    true
                }
                Err(e) => {
                    log::warn!("zswap_store failed for 2M frame {:?}: {:?}", frame, e);
                    GLOBAL_ZSWAP_FAILS.fetch_add(1, AtomicOrdering::AcqRel);
                    crate::mm::async_swapout::buffer_pool_put_2m(buf);
                    false
                }
            }
        }
        s if s == crate::mm::PAGE_SIZE_1G => {
            let mut buf = crate::mm::async_swapout::buffer_pool_get_1g();
            let vaddr = crate::mm::mapping::phys_to_virt(x86_64::PhysAddr::new(phys));
            unsafe { core::ptr::copy_nonoverlapping(vaddr.as_u64() as *const u8, buf.as_mut_ptr(), crate::mm::PAGE_SIZE_1G); }
            match crate::mm::zswap::zswap_store_auto(&buf) {
                Ok(_) => {
                    let physf1g = unsafe { PhysFrame::<Size1GiB>::from_start_address_unchecked(x86_64::PhysAddr::new(phys)) };
                    buddy_allocator::buddy_dealloc_frame_1g(physf1g);
                    GLOBAL_ASYNC_DEALLOC_COUNT.fetch_add(1, AtomicOrdering::AcqRel);
                    crate::mm::async_swapout::buffer_pool_put_1g(buf);
                    true
                }
                Err(e) => {
                    log::warn!("zswap_store failed for 1G frame {:?}: {:?}", frame, e);
                    GLOBAL_ZSWAP_FAILS.fetch_add(1, AtomicOrdering::AcqRel);
                    crate::mm::async_swapout::buffer_pool_put_1g(buf);
                    false
                }
            }
        }
        _ => false,
    }
}

// テスト専用: 永続ワーカ実装（条件変数 + バウンドキュー）
pub fn stats_huge_2m_skip_count() -> u64 {
    0 // TODO: Implement tracking
}

#[cfg(all(test, feature = "std"))]
mod test_impl {
    use super::*;
    use alloc::collections::BTreeSet;
    use alloc::sync::Arc;
    use std::collections::VecDeque;
    use std::sync::{Mutex as StdMutex, Condvar};
    use spin::Once;
    use std::thread;

    /// キュー容量／バッチサイズはテスト向けに控えめに設定可能
    const QUEUE_CAPACITY: usize = 64;
    const BATCH_SIZE: usize = 8;

    use core::sync::atomic::{AtomicBool, AtomicUsize, AtomicU64, Ordering};

    static TEST_FILE_QUEUE_COUNT: AtomicUsize = AtomicUsize::new(0);
    static TEST_PROCESSING_DELAY_MS: AtomicU64 = AtomicU64::new(0);
    static TEST_WORKER_RUNNING: AtomicBool = AtomicBool::new(false);
    static TEST_WORKER_SHUTDOWN: AtomicBool = AtomicBool::new(false);
    // Test diagnostics
    static TEST_DEALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
    static TEST_ZSWAP_FAILS: AtomicUsize = AtomicUsize::new(0);

    // Token-bucket backpressure (test)
    const TEST_TOKEN_CAPACITY: usize = QUEUE_CAPACITY / 4; // burst capacity for anon entries
    const TEST_REFILL_PER_BATCH: usize = BATCH_SIZE / 2; // tokens added per processed batch

    // Allow dynamic test-time override of token capacity and reserved slots
    static TEST_TOKEN_CAPACITY_DYNAMIC: AtomicUsize = AtomicUsize::new(TEST_TOKEN_CAPACITY);
    static TEST_TOKENS: AtomicUsize = AtomicUsize::new(TEST_TOKEN_CAPACITY);

    // Dynamic reserved file slots
    const RESERVED_FILE_SLOTS_TEST: usize = QUEUE_CAPACITY / 8;
    static TEST_RESERVED_FILE_SLOTS_DYNAMIC: AtomicUsize = AtomicUsize::new(RESERVED_FILE_SLOTS_TEST);

    struct WorkerInner {
        queue: StdMutex<VecDeque<SwapEntry>>,
        pending: StdMutex<BTreeSet<usize>>,
        condvar: Condvar,
    }

    static WORKER: Once<Arc<WorkerInner>> = Once::new();

    fn init_worker() -> Arc<WorkerInner> {
        WORKER.call_once(|| {
            Arc::new(WorkerInner {
                queue: StdMutex::new(VecDeque::new()),
                pending: StdMutex::new(BTreeSet::new()),
                condvar: Condvar::new(),
            })
        });

        let worker = WORKER.get().as_ref().unwrap().clone(); // Arc clone

        // Spawn worker thread if not already running

        // Spawn worker thread if not already running
        if TEST_WORKER_RUNNING.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            let thread_inner = worker.clone();
            std::thread::spawn(move || {
                // reuse buffer to avoid per-page allocations
                let mut reuse_buf = crate::mm::async_swapout::buffer_pool_get_4k();
                loop {
                    // Wait for work or shutdown
                    let mut q_guard = thread_inner.queue.lock().unwrap();
                    while q_guard.is_empty() && !TEST_WORKER_SHUTDOWN.load(Ordering::Acquire) {
                        q_guard = thread_inner.condvar.wait(q_guard).unwrap();
                    }

                    // if shutdown and queue empty, exit
                    if q_guard.is_empty() && TEST_WORKER_SHUTDOWN.load(Ordering::Acquire) {
                        break;
                    }

                    let mut batch = Vec::new();
                    for _ in 0..BATCH_SIZE {
                        if let Some(entry) = q_guard.pop_front() {
                            batch.push(entry);
                        } else {
                            break;
                        }
                    }
                    drop(q_guard);

                    // バッチ処理
                    for entry in batch {
                        match entry.kind {
                            SwapKind::File { ino, page_num } => {
                                let res = crate::fs::page_cache().sync_page(ino, page_num, |offset, data| {
                                    match crate::fs::write_inode_by_number(ino, offset, data) {
                                        Ok(_) => Ok(()),
                                        Err(_) => Err(()),
                                    }
                                });

                                if res.is_ok() {
                                    // Release memcg accounting and deallocate
                                    release_frame_and_untrack(entry.frame);
                                    TEST_DEALLOC_COUNT.fetch_add(1, Ordering::AcqRel);
                                }
                            }
                            SwapKind::Anon => {
                                if try_zswap_store_and_dealloc_any(entry.frame, &mut reuse_buf) {
                                    TEST_DEALLOC_COUNT.fetch_add(1, Ordering::AcqRel);
                                } else {
                                    TEST_ZSWAP_FAILS.fetch_add(1, Ordering::AcqRel);
                                }
                            }
                        }

                        // 完了通知
                        let (lock, cvar) = &*entry.completion;
                        let mut done = lock.lock().unwrap();
                        *done = true;
                        cvar.notify_all();

                        // pending を解除
                        thread_inner.pending.lock().unwrap().remove(&entry.frame.as_usize());

                        // decrement file queue count when file processed (saturating)
                        if let SwapKind::File { .. } = entry.kind {
                            atomic_saturating_decrement(&TEST_FILE_QUEUE_COUNT);
                        }

                        // optional processing delay
                        let d = TEST_PROCESSING_DELAY_MS.load(Ordering::Acquire);
                        if d > 0 {
                            std::thread::sleep(std::time::Duration::from_millis(d));
                        }
                    }

                    // Refill token bucket after processing batch
                    {
                        let add = TEST_REFILL_PER_BATCH;
                        loop {
                            let cur = TEST_TOKENS.load(Ordering::Acquire);
                            let cap = TEST_TOKEN_CAPACITY_DYNAMIC.load(Ordering::Acquire);
                            if cur >= cap { break; }
                            let new = (cur + add).min(cap);
                            match TEST_TOKENS.compare_exchange(cur, new, Ordering::AcqRel, Ordering::Acquire) {
                                Ok(_) => break,
                                Err(_) => continue,
                            }
                        }
                    }
                }

                crate::mm::async_swapout::buffer_pool_put_4k(reuse_buf);
                TEST_WORKER_RUNNING.store(false, Ordering::Release);
            });
        }

        worker.clone()
    }

    pub fn try_enqueue(frame: FrameIndex, kind: SwapKind) -> Result<super::SwapHandle, SwapError> {
        let worker = init_worker();

        // pending と容量チェック
        {
            let mut pending = worker.pending.lock().unwrap();
            if pending.contains(&frame.as_usize()) {
                return Err(SwapError::AlreadyPending);
            }

            let mut q = worker.queue.lock().unwrap();
            if q.len() >= QUEUE_CAPACITY {
                return Err(SwapError::QueueFull);
            }

            // Enforce reservation for file writes when queue nearly full
            if let SwapKind::Anon = kind {
                let total = q.len();
                let file_q = TEST_FILE_QUEUE_COUNT.load(Ordering::Acquire);
                let free_slots = QUEUE_CAPACITY.saturating_sub(total);
                let reserved = TEST_RESERVED_FILE_SLOTS_DYNAMIC.load(Ordering::Acquire);
                if free_slots <= reserved && file_q >= reserved {
                    return Err(SwapError::QueueFull);
                }
            }

            pending.insert(frame.as_usize());

            let completion = Arc::new((StdMutex::new(false), Condvar::new()));
            let entry = SwapEntry { frame, kind, completion: completion.clone() };

            // Consume a token for anon entries
            if let SwapKind::Anon = entry.kind {
                let mut cur = TEST_TOKENS.load(Ordering::Acquire);
                loop {
                    if cur == 0 {
                        // rollback pending and fail fast - use the already-held `pending` guard to avoid re-locking
                        pending.remove(&frame.as_usize());
                        return Err(SwapError::QueueFull);
                    }
                    match TEST_TOKENS.compare_exchange(cur, cur - 1, Ordering::AcqRel, Ordering::Acquire) {
                        Ok(_) => break,
                        Err(c) => cur = c,
                    }
                }
            }

            if let SwapKind::File { .. } = entry.kind {
                TEST_FILE_QUEUE_COUNT.fetch_add(1, Ordering::AcqRel);
            }

            q.push_back(entry);
            worker.condvar.notify_one();

            Ok(super::SwapHandle { done: completion })
        }
    }

    // Test inspection helpers
    #[cfg(test)]
    pub fn _queue_len() -> usize {
        let worker = init_worker();
        worker.queue.lock().unwrap().len()
    }

    #[cfg(test)]
    pub fn _pending_len() -> usize {
        let worker = init_worker();
        worker.pending.lock().unwrap().len()
    }

    #[cfg(test)]
    pub fn _is_pending(frame: FrameIndex) -> bool {
        let worker = init_worker();
        worker.pending.lock().unwrap().contains(&frame.as_usize())
    }

    // Additional test helpers
    #[cfg(test)]
    pub fn _file_queue_len() -> usize {
        TEST_FILE_QUEUE_COUNT.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub fn _queue_capacity() -> usize {
        QUEUE_CAPACITY
    }

    #[cfg(test)]
    pub fn _reserved_file_slots() -> usize {
        RESERVED_FILE_SLOTS_TEST
    }

    #[cfg(test)]
    pub fn set_processing_delay(ms: u64) {
        TEST_PROCESSING_DELAY_MS.store(ms, Ordering::Release);
    }

    #[cfg(test)]
    pub fn stop_worker() {
        TEST_WORKER_SHUTDOWN.store(true, Ordering::Release);
        if let Some(inner) = WORKER.get() {
            inner.condvar.notify_all();
        }
    }

    #[cfg(test)]
    pub fn start_worker() {
        TEST_WORKER_SHUTDOWN.store(false, Ordering::Release);
        init_worker();
    }

    #[cfg(test)]
    pub fn is_worker_running() -> bool {
        TEST_WORKER_RUNNING.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub fn _token_count() -> usize {
        TEST_TOKENS.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub fn set_tokens(n: usize) {
        let cap = TEST_TOKEN_CAPACITY_DYNAMIC.load(Ordering::Acquire);
        TEST_TOKENS.store(n.min(cap), Ordering::Release);
    }

    #[cfg(test)]
    pub fn _huge_2m_skip_count() -> usize {
        GLOBAL_HUGE_2M_SKIPPED.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub fn _reset_huge_2m_skip_count() {
        GLOBAL_HUGE_2M_SKIPPED.store(0, Ordering::Release);
    }

    #[cfg(test)]
    pub fn add_tokens(n: usize) {
        loop {
            let cur = TEST_TOKENS.load(Ordering::Acquire);
            let cap = TEST_TOKEN_CAPACITY_DYNAMIC.load(Ordering::Acquire);
            if cur >= cap { break; }
            let new = (cur + n).min(cap);
            match TEST_TOKENS.compare_exchange(cur, new, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
    }

    #[cfg(test)]
    pub fn token_capacity() -> usize {
        TEST_TOKEN_CAPACITY_DYNAMIC.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub fn set_token_capacity_for_test(n: usize) {
        let cap = n.min(QUEUE_CAPACITY);
        TEST_TOKEN_CAPACITY_DYNAMIC.store(cap, Ordering::Release);
        // Trim current tokens to new cap
        loop {
            let cur = TEST_TOKENS.load(Ordering::Acquire);
            let new = cur.min(cap);
            if cur == new { break; }
            match TEST_TOKENS.compare_exchange(cur, new, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
    }

    #[cfg(test)]
    pub fn set_reserved_file_slots_for_test(n: usize) {
        let v = n.min(QUEUE_CAPACITY);
        TEST_RESERVED_FILE_SLOTS_DYNAMIC.store(v, Ordering::Release);
    }


    #[cfg(test)]
    pub fn _dealloc_count() -> usize {
        TEST_DEALLOC_COUNT.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub fn _reset_dealloc_count() {
        TEST_DEALLOC_COUNT.store(0, Ordering::Release);
    }

    #[cfg(test)]
    pub fn _dec_file_queue_count_safe() {
        atomic_saturating_decrement(&TEST_FILE_QUEUE_COUNT);
    }

    #[cfg(test)]
    pub fn _zswap_fail_count() -> usize {
        TEST_ZSWAP_FAILS.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub fn _reset_zswap_fail_count() {
        TEST_ZSWAP_FAILS.store(0, Ordering::Release);
    }
}


// カーネル向け実装: 永続ワーカ（non-test）
#[cfg(any(not(test), feature = "full_mm_tests"))]
mod kernel_impl {
    use super::*;
    use alloc::vec::Vec;
    use spin::Once;
    use crate::sync::lockfree::{BoundedChannel, BoundedSender, BoundedReceiver};
    use crate::sync::AtomicWaker;
    use crate::task::Task;
    use crate::mm::page_flags::{self, PageFlags};

    // Channel capacity and batch size tunables
    const CHANNEL_SIZE: usize = 1024;
    const BATCH_SIZE: usize = 32;

    #[derive(Clone, Copy)]
    struct SwapEntryKernel {
        frame: FrameIndex,
        kind: SwapKind,
    }

    // Static channel (initialized once)
    static CHANNEL_ONCE: Once<Option<(BoundedSender<SwapEntryKernel, CHANNEL_SIZE>, BoundedReceiver<SwapEntryKernel, CHANNEL_SIZE>)>> = Once::new();

    // Pending set is replaced by GlobalPageFlags

    // Queue occupancy counters (for reservation of file slots)
    use core::sync::atomic::{AtomicUsize, Ordering};
    static QUEUE_COUNT: AtomicUsize = AtomicUsize::new(0);
    static FILE_QUEUE_COUNT: AtomicUsize = AtomicUsize::new(0);
    // Reserve some slots for file writes so heavy anon traffic cannot starve file writebacks
    const RESERVED_FILE_SLOTS: usize = CHANNEL_SIZE / 8; // reserve ~12.5% for file writes
    // Token-bucket backpressure (anonymous pages)
    // - TOKEN_BUCKET_CAPACITY: Burst capacity for anon enqueues. Larger value allows absorbing transient spikes
    //   but increases risk of anon traffic delaying file writebacks.
    // - TOKEN_REFILL_PER_BATCH: Amount of tokens restored per processed batch. Controls long-term sustained rate.
    const TOKEN_BUCKET_CAPACITY: usize = CHANNEL_SIZE / 4; // anonymous burst capacity
    const TOKEN_REFILL_PER_BATCH: usize = BATCH_SIZE / 2;

    // Runtime-adjustable parameters (Atomics allow tuning without recompilation)
    static RESERVED_FILE_SLOTS_ATOMIC: AtomicUsize = AtomicUsize::new(RESERVED_FILE_SLOTS);
    static TOKEN_BUCKET_CAPACITY_ATOMIC: AtomicUsize = AtomicUsize::new(TOKEN_BUCKET_CAPACITY);
    static TOKEN_REFILL_PER_BATCH_ATOMIC: AtomicUsize = AtomicUsize::new(TOKEN_REFILL_PER_BATCH);

    static TOKENS: AtomicUsize = AtomicUsize::new(TOKEN_BUCKET_CAPACITY);
    // Worker waker and running flags
    static WORKER_WAKER: AtomicWaker = AtomicWaker::new();
    static WORKER_RUNNING: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    static WORKER_SHUTDOWN: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

    fn ensure_channel_started() {
        CHANNEL_ONCE.call_once(|| {
            let (s, r) = BoundedChannel::<SwapEntryKernel, CHANNEL_SIZE>::new();
            Some((s, r))
        });

        // Try to spawn the worker if not already running
        if WORKER_RUNNING.compare_exchange(false, true, core::sync::atomic::Ordering::AcqRel, core::sync::atomic::Ordering::Acquire).is_ok() {
            WORKER_SHUTDOWN.store(false, core::sync::atomic::Ordering::Release);
            let task = Task::new(async move { worker_loop().await });
            crate::task::Executor::spawn_global(task);
        }
    }

    // Future that waits until there is work in the channel
    struct WaitForWork;
    impl core::future::Future for WaitForWork {
        type Output = ();
        fn poll(self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> core::task::Poll<()> {
            // Fast path: if receiver has elements, return ready
            if let Some(ch) = CHANNEL_ONCE.get().and_then(|opt| opt.as_ref()) {
                if !ch.1.is_empty() {
                    return core::task::Poll::Ready(());
                }
            }

            // Register waker
            WORKER_WAKER.register(cx.waker());

            // Re-check to avoid races
            if let Some(ch) = CHANNEL_ONCE.get().and_then(|opt| opt.as_ref()) {
                if !ch.1.is_empty() {
                    return core::task::Poll::Ready(());
                }
            }

            core::task::Poll::Pending
        }
    }

    async fn worker_loop() {
        // reuse buffer to avoid per-page allocations
        let mut reuse_buf = buffer_pool_get_4k();
        loop {
            WaitForWork.await;

            // If shutdown requested and channel empty, stop
            if WORKER_SHUTDOWN.load(core::sync::atomic::Ordering::Acquire) {
                if let Some(ch) = CHANNEL_ONCE.get().and_then(|opt| opt.as_ref()) {
                    if ch.1.is_empty() {
                        WORKER_RUNNING.store(false, core::sync::atomic::Ordering::Release);
                        break;
                    }
                } else {
                    WORKER_RUNNING.store(false, core::sync::atomic::Ordering::Release);
                    break;
                }
            }

            // Drain up to BATCH_SIZE entries
            let mut batch: Vec<SwapEntryKernel> = Vec::new();
            if let Some(ch) = CHANNEL_ONCE.get().and_then(|opt| opt.as_ref()) {
                let rx = &ch.1;
                for _ in 0..BATCH_SIZE {
                    if let Some(entry) = rx.recv() {
                        batch.push(entry);
                    } else {
                        break;
                    }
                }
            }

            // Process batch
            for entry in batch {
                match entry.kind {
                    SwapKind::File { ino, page_num } => {
                        let written = crate::fs::page_cache().sync_page(ino, page_num, |offset, data| {
                            match crate::fs::write_inode_by_number(ino, offset, data) {
                                Ok(_) => Ok(()),
                                Err(_) => Err(()),
                            }
                        });

                        match written {
                            Ok(true) => {
                                // Release memcg accounting and deallocate
                                release_frame_and_untrack(entry.frame);
                            }
                            _ => {
                                // Fall back to global sync; if any were written by global flush, free
                                if crate::fs::page_cache().sync_all(|ino, offset, data| {
                                    match crate::fs::write_inode_by_number(ino, offset, data) {
                                        Ok(_) => Ok(()),
                                        Err(_) => Err(()),
                                    }
                                }).unwrap_or(0) > 0 {
                                    release_frame_and_untrack(entry.frame);
                                } else {
                                    crate::mm::page_reclaim::PAGE_RECLAIM.account_writeback_skipped();
                                }
                            }
                        }

                        // Remove pending flag and update queue counters
                        page_flags::clear_flag(entry.frame, PageFlags::SwapPending);
                        atomic_saturating_decrement(&QUEUE_COUNT);
                        atomic_saturating_decrement(&FILE_QUEUE_COUNT); // safe to call; saturating at 0
                    }
                    SwapKind::Anon => {
                        if try_zswap_store_and_dealloc_any(entry.frame, &mut reuse_buf) {
                            // success: frame deallocated via helper
                        } else {
                            log::warn!("zswap store failed during anon swapout for frame {:?}", entry.frame);
                        }

                        page_flags::clear_flag(entry.frame, PageFlags::SwapPending);
                        atomic_saturating_decrement(&QUEUE_COUNT);
                    }
                }
            }


            // Refill token bucket after processing batch
            // Only refill if we actually processed something or if we just woke up to check
            // Use a simple strategy: constant refill rate per batch processing cycle
            add_tokens(TOKEN_REFILL_PER_BATCH_ATOMIC.load(Ordering::Acquire));

            // If shutdown requested and channel empty after processing, stop
            if WORKER_SHUTDOWN.load(core::sync::atomic::Ordering::Acquire) {
                if let Some(ch) = CHANNEL_ONCE.get().and_then(|opt| opt.as_ref()) {
                    if ch.1.is_empty() {
                        WORKER_RUNNING.store(false, core::sync::atomic::Ordering::Release);
                        break;
                    }
                } else {
                    WORKER_RUNNING.store(false, core::sync::atomic::Ordering::Release);
                    break;
                }
            }
        }
    }

    fn try_consume_token() -> bool {
        let mut cur = TOKENS.load(Ordering::Acquire);
        loop {
            if cur == 0 {
                return false;
            }
            match TOKENS.compare_exchange(cur, cur - 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return true,
                Err(c) => cur = c,
            }
        }
    }

    fn add_tokens(n: usize) {
        // Respect current dynamic capacity
        let cap = TOKEN_BUCKET_CAPACITY_ATOMIC.load(Ordering::Acquire);
        let mut cur = TOKENS.load(Ordering::Acquire);
        loop {
            if cur >= cap {
                return;
            }
            let new = (cur + n).min(cap);
            match TOKENS.compare_exchange(cur, new, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return,
                Err(c) => cur = c,
            }
        }
    }



    pub fn try_enqueue(frame: FrameIndex, kind: SwapKind) -> Result<super::SwapHandle, SwapError> {
        ensure_channel_started();

        // If worker has been stopped, not supported
        if !WORKER_RUNNING.load(core::sync::atomic::Ordering::Acquire) {
            return Err(SwapError::NotSupported);
        }

        // Fast-path: try to set pending flag (atomic)
        if page_flags::test_and_set_flag(frame, PageFlags::SwapPending) {
             // Already set
             return Err(SwapError::AlreadyPending);
        }

        // Check sender capacity
        if let Some(ch) = CHANNEL_ONCE.get().and_then(|opt| opt.as_ref()) {
            let sender = &ch.0;
            if sender.is_full() {
                page_flags::clear_flag(frame, PageFlags::SwapPending);
                return Err(SwapError::QueueFull);
            }

            // Enforce strict reservation for file writes: keep RESERVED_FILE_SLOTS free for file entries
            if let SwapKind::Anon = kind {
                let total = QUEUE_COUNT.load(Ordering::Acquire);
                let free_slots = CHANNEL_SIZE.saturating_sub(total);
                let reserved = RESERVED_FILE_SLOTS_ATOMIC.load(Ordering::Acquire);
                if free_slots <= reserved {
                    // reserve slots for file writes — anon enqueues fail fast
                    page_flags::clear_flag(frame, PageFlags::SwapPending);
                    return Err(SwapError::QueueFull);
                }
            }

            // Token-bucket consumption for anon entries
            let mut token_consumed = false;
            if let SwapKind::Anon = kind {
                if !try_consume_token() {
                    page_flags::clear_flag(frame, PageFlags::SwapPending);
                    return Err(SwapError::QueueFull);
                }
                token_consumed = true;
            }

            match sender.send(SwapEntryKernel { frame, kind }) {
                Ok(()) => {
                    // Update counters
                    QUEUE_COUNT.fetch_add(1, Ordering::AcqRel);
                    if let SwapKind::File { .. } = kind {
                        FILE_QUEUE_COUNT.fetch_add(1, Ordering::AcqRel);
                    }

                    // Wake the worker
                    WORKER_WAKER.wake();
                    Ok(super::SwapHandle {})
                }
                Err(_v) => {
                    if token_consumed {
                        add_tokens(1);
                    }
                    page_flags::clear_flag(frame, PageFlags::SwapPending);
                    Err(SwapError::QueueFull)
                }
            }
        } else {
            page_flags::clear_flag(frame, PageFlags::SwapPending);
            Err(SwapError::NotSupported)
        }
    }

    // Kernel control / introspection
    pub fn queued_counts() -> (usize, usize) {
        (QUEUE_COUNT.load(core::sync::atomic::Ordering::Acquire), FILE_QUEUE_COUNT.load(core::sync::atomic::Ordering::Acquire))
    }

    pub fn token_count() -> usize {
        TOKENS.load(core::sync::atomic::Ordering::Acquire)
    }

    /// Runtime tunables and inspection
    pub fn set_token_bucket_capacity(n: usize) {
        let n = n.min(CHANNEL_SIZE);
        TOKEN_BUCKET_CAPACITY_ATOMIC.store(n, Ordering::Release);
        // Trim current tokens if above new capacity
        loop {
            let cur = TOKENS.load(Ordering::Acquire);
            if cur <= n { break; }
            match TOKENS.compare_exchange(cur, n, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
    }

    pub fn token_bucket_capacity() -> usize {
        TOKEN_BUCKET_CAPACITY_ATOMIC.load(Ordering::Acquire)
    }

    pub fn set_token_refill_per_batch(n: usize) {
        TOKEN_REFILL_PER_BATCH_ATOMIC.store(n, Ordering::Release);
    }

    pub fn token_refill_per_batch() -> usize {
        TOKEN_REFILL_PER_BATCH_ATOMIC.load(Ordering::Acquire)
    }

    pub fn set_reserved_file_slots(n: usize) {
        RESERVED_FILE_SLOTS_ATOMIC.store(n.min(CHANNEL_SIZE), Ordering::Release);
    }

    pub fn reserved_file_slots() -> usize {
        RESERVED_FILE_SLOTS_ATOMIC.load(Ordering::Acquire)
    }

    pub fn set_token_count(n: usize) {
        let cap = TOKEN_BUCKET_CAPACITY_ATOMIC.load(Ordering::Acquire);
        TOKENS.store(n.min(cap), Ordering::Release);
    }

    pub fn add_tokens_public(n: usize) {
        add_tokens(n);
    }

    pub fn start_worker() {
        ensure_channel_started();
    }

    pub fn stop_worker() {
        WORKER_SHUTDOWN.store(true, core::sync::atomic::Ordering::Release);
        WORKER_WAKER.wake();
    }

    pub fn is_worker_running() -> bool {
        WORKER_RUNNING.load(core::sync::atomic::Ordering::Acquire)
    }
}



// 公開API: try_enqueue_swapout
pub fn try_enqueue_swapout(frame: FrameIndex, kind: SwapKind) -> Result<SwapHandle, SwapError> {
    #[cfg(all(test, not(feature = "full_mm_tests")))]
    {
        test_impl::try_enqueue(frame, kind)
    }

    #[cfg(any(not(test), feature = "full_mm_tests"))]
    {
        kernel_impl::try_enqueue(frame, kind)
    }
}

/// Start the async swapout worker (tests call test worker, kernel calls kernel worker)
pub fn start_worker() {
    #[cfg(all(test, not(feature = "full_mm_tests")))]
    {
        test_impl::start_worker();
    }

    #[cfg(any(not(test), feature = "full_mm_tests"))]
    {
        kernel_impl::start_worker();
    }
}

/// Stop the async swapout worker
pub fn stop_worker() {
    #[cfg(all(test, not(feature = "full_mm_tests")))]
    {
        test_impl::stop_worker();
    }

    #[cfg(any(not(test), feature = "full_mm_tests"))]
    {
        kernel_impl::stop_worker();
    }
}

/// Return whether the worker is running
pub fn is_worker_running() -> bool {
    #[cfg(all(test, not(feature = "full_mm_tests")))]
    {
        test_impl::is_worker_running()
    }

    #[cfg(any(not(test), feature = "full_mm_tests"))]
    {
        kernel_impl::is_worker_running()
    }
}

/// Return (queue_len, file_queue_len)
pub fn queued_counts() -> (usize, usize) {
    #[cfg(all(test, not(feature = "full_mm_tests")))]
    {
        (test_impl::_queue_len(), test_impl::_file_queue_len())
    }

    #[cfg(any(not(test), feature = "full_mm_tests"))]
    {
        kernel_impl::queued_counts()
    }
}

/// Return the current token count (anon token bucket)
pub fn token_count() -> usize {
    #[cfg(all(test, not(feature = "full_mm_tests")))]
    {
        test_impl::_token_count()
    }

    #[cfg(any(not(test), feature = "full_mm_tests"))]
    {
        kernel_impl::token_count()
    }
}

/// Runtime tunables (top-level wrappers)
pub fn set_token_bucket_capacity(n: usize) {
    #[cfg(any(not(test), feature = "full_mm_tests"))]
    { kernel_impl::set_token_bucket_capacity(n); }
}

pub fn token_bucket_capacity() -> usize {
    #[cfg(any(not(test), feature = "full_mm_tests"))]
    { kernel_impl::token_bucket_capacity() }
    #[cfg(all(test, not(feature = "full_mm_tests")))]
    { 0 }
}

pub fn set_token_refill_per_batch(n: usize) {
    #[cfg(any(not(test), feature = "full_mm_tests"))]
    { kernel_impl::set_token_refill_per_batch(n); }
}

pub fn token_refill_per_batch() -> usize {
    #[cfg(any(not(test), feature = "full_mm_tests"))]
    { kernel_impl::token_refill_per_batch() }
    #[cfg(all(test, not(feature = "full_mm_tests")))]
    { 0 }
}

pub fn set_reserved_file_slots(n: usize) {
    #[cfg(any(not(test), feature = "full_mm_tests"))]
    { kernel_impl::set_reserved_file_slots(n); }
}

pub fn reserved_file_slots() -> usize {
    #[cfg(any(not(test), feature = "full_mm_tests"))]
    { kernel_impl::reserved_file_slots() }
    #[cfg(all(test, not(feature = "full_mm_tests")))]
    { 0 }
}

pub fn set_token_count(n: usize) {
    #[cfg(any(not(test), feature = "full_mm_tests"))]
    { kernel_impl::set_token_count(n); }
    #[cfg(all(test, not(feature = "full_mm_tests")))]
    { test_impl::set_tokens(n); }
}

pub fn add_tokens(n: usize) {
    #[cfg(any(not(test), feature = "full_mm_tests"))]
    { kernel_impl::add_tokens_public(n); }
    #[cfg(all(test, not(feature = "full_mm_tests")))]
    { test_impl::add_tokens(n); }
}

// テスト: キューイング API とワーカの動作を検証するユニットテストを追加
#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::mm::{PAGE_SIZE_4K, frame_backing};

    #[test_case]
    fn test_async_swapout_file_backed() {
        // セットアップ: page cache にページを入れ、対応するフレームを確保して frame_backing を登録
        let cache = crate::fs::PageCache::new(64 * 1024);
        let ino = 42u64;
        let page_num = 1u64;
        let data = alloc::vec![0xAAu8; PAGE_SIZE_4K];
        cache.insert(ino, page_num, data, PAGE_SIZE_4K as u64);
        assert!(cache.mark_dirty(ino, page_num));

        // allocate a frame to represent the physical page
        let frame = crate::mm::alloc_frame().expect("alloc frame");
        let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());

        // track the frame backing
        frame_backing::track_frame_backing(frame_idx, ino, page_num);

        // enqueue
        let handle = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::File { ino, page_num })
            .expect("enqueue ok");

        // wait for completion
        handle.wait();

        // backing must be gone
        assert!(frame_backing::get_frame_backing(frame_idx).is_none());

        // page should be present and readable (cleanness asserted via PageCache API)
        let mut buf = vec![0u8; PAGE_SIZE_4K];
        let read = crate::fs::PageCache::read(&cache, ino, page_num * PAGE_SIZE_4K as u64, &mut buf, PAGE_SIZE_4K as u64);
        assert!(read.is_some(), "page should exist and be readable");
    }

    #[test_case]
    fn test_async_swapout_dedup() {
        // setup similar to file-backed test
        let cache = crate::fs::PageCache::new(64 * 1024);
        let ino = 43u64;
        let page_num = 2u64;
        let data = alloc::vec![0xBBu8; PAGE_SIZE_4K];
        cache.insert(ino, page_num, data, PAGE_SIZE_4K as u64);
        assert!(cache.mark_dirty(ino, page_num));

        let frame = crate::mm::alloc_frame().expect("alloc frame");
        let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
        frame_backing::track_frame_backing(frame_idx, ino, page_num);

        // first enqueue should succeed
        let handle1 = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::File { ino, page_num }).expect("enqueue ok");

        // second enqueue for same frame should return AlreadyPending
        let err = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::File { ino, page_num }).expect_err("should be pending");
        assert_eq!(err, SwapError::AlreadyPending);

        // wait for first completion, then enqueue again
        handle1.wait();
        let handle2 = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::File { ino, page_num }).expect("enqueue ok");
        handle2.wait();

        // after completion backing must be removed
        assert!(frame_backing::get_frame_backing(frame_idx).is_none());
    }

    #[test_case]
    #[cfg(feature = "std")]
    fn test_memcg_concurrent_swapout() {
        // Initialize memcg and global page cache
        crate::mm::memcg::init_memcg();
        let cg = crate::mm::memcg::memcg_create(String::from("concurrent"), crate::mm::memcg::memcg_root()).expect("create memcg");
        crate::fs::init_page_cache(64 * 1024);
        let cache = crate::fs::page_cache();

        let n = 64usize;
        let mut join_handles = Vec::new();

        for i in 0..n {
            let cache = cache; // copy ref
            let cg = cg;
            let handle = std::thread::spawn(move || {
                // allocate a frame
                let frame = crate::mm::alloc_frame().expect("alloc frame");
                let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());

                if i % 2 == 0 {
                    // file-backed
                    assert!(crate::mm::memcg::memcg_charge(cg, 1, crate::mm::memcg::ChargeType::Cache).is_ok());
                    crate::mm::memcg::memcg_track_page(frame_idx, cg, crate::mm::memcg::ChargeType::Cache);

                    let ino = 1000u64;
                    let page_num = i as u64;
                    let data = alloc::vec![0u8; PAGE_SIZE_4K];
                    cache.insert(ino, page_num, data, PAGE_SIZE_4K as u64);
                    assert!(cache.mark_dirty(ino, page_num));
                    crate::mm::frame_backing::track_frame_backing(frame_idx, ino, page_num);

                    let h = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::File { ino, page_num }).expect("enqueue ok");
                    h.wait();
                } else {
                    // anon
                    assert!(crate::mm::memcg::memcg_charge(cg, 1, crate::mm::memcg::ChargeType::Anon).is_ok());
                    crate::mm::memcg::memcg_track_page(frame_idx, cg, crate::mm::memcg::ChargeType::Anon);

                    let h = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon).expect("enqueue ok");
                    h.wait();
                }

                // After completion, page info should be gone
                assert!(crate::mm::memcg::memcg_get_page_info(frame_idx).is_none());
            });

            join_handles.push(handle);
        }

        for h in join_handles {
            h.join().expect("thread join");
        }

        // All charges should be cleared
        let stats = crate::mm::memcg::memcg_stats(cg).expect("stats");
        assert_eq!(stats.cache_pages, 0);
        assert_eq!(stats.anon_pages, 0);
    }

    #[test_case]
    #[cfg(feature = "std")]
    fn test_async_swapout_concurrent_dedup() {
        // Initialize global cache
        crate::fs::init_page_cache(64 * 1024);
        let cache = crate::fs::page_cache();

        // Setup a single frame and track it
        let ino = 2000u64;
        let page_num = 1u64;
        let data = alloc::vec![0xEEu8; PAGE_SIZE_4K];
        cache.insert(ino, page_num, data, PAGE_SIZE_4K as u64);
        assert!(cache.mark_dirty(ino, page_num));

        let frame = crate::mm::alloc_frame().expect("alloc frame");
        let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
        crate::mm::frame_backing::track_frame_backing(frame_idx, ino, page_num);

        // Check queue/pending metrics before enqueue
        assert_eq!(test_impl::_queue_len(), 0);
        assert_eq!(test_impl::_pending_len(), 0);
        assert!(!test_impl::_is_pending(frame_idx));

        // Barrier to synchronize enqueuers
        let threads = 8usize;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(threads + 1));
        let results = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

        let mut joiners = Vec::new();
        for _ in 0..threads {
            let barrier = barrier.clone();
            let results = results.clone();
            let frame_idx = frame_idx;
            let t = std::thread::spawn(move || {
                barrier.wait();
                let res = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::File { ino, page_num });
                results.lock().unwrap().push(res);
            });
            joiners.push(t);
        }

        // Release all enqueuers
        barrier.wait();

        // Give a tiny moment for enqueues to be processed
        std::thread::sleep(std::time::Duration::from_millis(10));

        // After enqueuing, queue and pending should reflect the entry
        assert!(test_impl::_queue_len() >= 1);
        assert_eq!(test_impl::_pending_len(), 1);
        assert!(test_impl::_is_pending(frame_idx));

        for j in joiners {
            j.join().expect("join");
        }

        let resvec = results.lock().unwrap();
        // There should be at least one Ok and at least one AlreadyPending among the others
        let mut ok_count = 0usize;
        let mut pending_count = 0usize;
        for r in resvec.iter() {
            match r {
                Ok(_) => ok_count += 1,
                Err(SwapError::AlreadyPending) => pending_count += 1,
                Err(_) => (),
            }
        }

        assert!(ok_count >= 1, "expected at least one successful enqueue");
        assert!(pending_count >= 1, "expected at least one AlreadyPending");

        // Wait for any successful handles to complete
        for r in resvec.iter() {
            if let Ok(h) = r {
                h.wait();
            }
        }

        // After completion, queue must be drained and pending cleared
        assert_eq!(test_impl::_queue_len(), 0);
        assert_eq!(test_impl::_pending_len(), 0);
        assert!(!test_impl::_is_pending(frame_idx));

        assert!(crate::mm::frame_backing::get_frame_backing(frame_idx).is_none());
    }

    #[test_case]
    #[cfg(feature = "std")]
    fn test_worker_restart() {
        // ensure worker lifecycle control works via top-level API
        start_worker();
        assert!(is_worker_running(), "worker should be running after start");

        stop_worker();
        // Wait for worker to stop
        for _ in 0..20 {
            if !is_worker_running() { break; }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(!is_worker_running(), "worker should have stopped");

        // Restart and ensure it runs
        start_worker();
        assert!(is_worker_running(), "worker should be running after restart");

        // Clean up
        stop_worker();
    }

    #[test_case]
    #[cfg(feature = "std")]
    fn test_async_swapout_qos_reservation() {
        crate::fs::init_page_cache(64 * 1024);
        let cache = crate::fs::page_cache();

        // Stop worker to allow deterministic queue fill
        test_impl::stop_worker();
        for _ in 0..20 {
            if !test_impl::is_worker_running() { break; }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let cap = test_impl::_queue_capacity();
        let reserved = test_impl::_reserved_file_slots();

        let fill_count = cap.saturating_sub(reserved) + 1;

        let mut handles = Vec::new();

        let ino = 3000u64;
        for i in 0..fill_count {
            let page_num = i as u64;
            let data = alloc::vec![0u8; PAGE_SIZE_4K];
            cache.insert(ino, page_num, data, PAGE_SIZE_4K as u64);
            assert!(cache.mark_dirty(ino, page_num));

            let frame = crate::mm::alloc_frame().expect("alloc frame");
            let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
            crate::mm::frame_backing::track_frame_backing(frame_idx, ino, page_num);

            let h = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::File { ino, page_num }).expect("enqueue ok");
            handles.push(h);
        }

        assert!(test_impl::_queue_len() >= fill_count);
        assert!(test_impl::_file_queue_len() >= reserved);

        let frame = crate::mm::alloc_frame().expect("alloc frame");
        let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
        let err = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon).expect_err("expected QueueFull due to reservation");
        assert_eq!(err, SwapError::QueueFull);

        // Start worker to process entries
        test_impl::start_worker();

        for h in handles {
            h.wait();
        }

        // After processing, queue should be empty
        assert_eq!(test_impl::_queue_len(), 0);
        assert_eq!(test_impl::_file_queue_len(), 0);

        // Now anon enqueue should succeed
        let frame = crate::mm::alloc_frame().expect("alloc frame");
        let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
        let h = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon).expect("enqueue ok");
        h.wait();

        // Ensure backing removed (if any)
        assert!(crate::mm::memcg::memcg_get_page_info(frame_idx).is_none());
    }

    #[test_case]
    #[cfg(feature = "std")]
    fn test_token_bucket_exhaustion_and_refill() {
        // Ensure worker controlled
        stop_worker();
        for _ in 0..20 { if !is_worker_running() { break; } std::thread::sleep(std::time::Duration::from_millis(10)); }

        // Set tokens to zero to simulate exhaustion
        test_impl::set_tokens(0);

        // allocate a frame
        let frame = crate::mm::alloc_frame().expect("alloc frame");
        let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());

        // Ensure anon enqueue fails
        let err = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon).expect_err("should be QueueFull due to tokens");
        assert_eq!(err, SwapError::QueueFull);

        // Add one token and try again
        test_impl::add_tokens(1);

        // Start worker to allow processing
        start_worker();

        let h = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon).expect("enqueue ok");
        h.wait();

        // cleanup: restore tokens to capacity
        test_impl::set_tokens(test_impl::token_capacity());

        // stop worker
        stop_worker();
    }

    #[test_case]
    #[cfg(feature = "std")]
    fn test_token_refill_on_processing() {
        // Stop worker to control processing
        stop_worker();
        for _ in 0..20 { if !is_worker_running() { break; } std::thread::sleep(std::time::Duration::from_millis(10)); }

        // Set tokens to zero
        test_impl::set_tokens(0);

        // Enqueue a file-backed entry to trigger processing and refill
        crate::fs::init_page_cache(64 * 1024);
        let cache = crate::fs::page_cache();
        let ino = 4000u64;
        let page_num = 1u64;
        let data = alloc::vec![0u8; PAGE_SIZE_4K];
        cache.insert(ino, page_num, data, PAGE_SIZE_4K as u64);
        assert!(cache.mark_dirty(ino, page_num));

        let frame = crate::mm::alloc_frame().expect("alloc frame");
        let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
        crate::mm::frame_backing::track_frame_backing(frame_idx, ino, page_num);

        // Enqueue file entry
        let h = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::File { ino, page_num }).expect("enqueue ok");

        // Start worker to process and refill tokens
        start_worker();

        h.wait();

        // After processing, tokens should have been refilled
        assert!(test_impl::_token_count() > 0);

        // Clean up
        stop_worker();
    }

    #[test_case]
    #[cfg(feature = "std")]
    fn test_async_swapout_stress_concurrency() {
        crate::mm::memcg::init_memcg();
        let cg = crate::mm::memcg::memcg_create(String::from("stress"), crate::mm::memcg::memcg_root()).expect("create memcg");
        crate::fs::init_page_cache(64 * 1024);
        let cache = crate::fs::page_cache();

        // Slow down processing to build pressure and exercise tokens
        test_impl::set_processing_delay(2);
        test_impl::set_tokens(test_impl::token_capacity());

        start_worker();

        let threads = 32usize;
        let iters = 80usize;
        let mut joiners = Vec::new();

        for t in 0..threads {
            let cache = cache;
            let cg = cg;
            #[cfg(feature = "std")]
            let j = std::thread::spawn(move || {
                for i in 0..iters {
                    let frame = crate::mm::alloc_frame().expect("alloc frame");
                    let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());

                    if ((i + t) % 2) == 0 {
                        // file-backed
                        assert!(crate::mm::memcg::memcg_charge(cg, 1, crate::mm::memcg::ChargeType::Cache).is_ok());
                        crate::mm::memcg::memcg_track_page(frame_idx, cg, crate::mm::memcg::ChargeType::Cache);

                        let ino = 6000u64 + (i % 256) as u64;
                        let page_num = i as u64;
                        let data = alloc::vec![0u8; PAGE_SIZE_4K];
                        cache.insert(ino, page_num, data, PAGE_SIZE_4K as u64);
                        assert!(cache.mark_dirty(ino, page_num));
                        crate::mm::frame_backing::track_frame_backing(frame_idx, ino, page_num);

                        match crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::File { ino, page_num }) {
                            Ok(h) => { h.wait(); }
                            Err(SwapError::QueueFull) => {
                                // fallback sync writeback
                                let _ = crate::fs::page_cache().sync_page(ino, page_num, |_offset, _data| Ok(()));
                                let physf = unsafe { PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(frame_idx.to_phys_addr())) };
                                buddy_allocator::buddy_dealloc_frame(physf);
                            }
                            Err(e) => panic!("unexpected enqueue error: {:?}", e),
                        }
                    } else {
                        // anon
                        assert!(crate::mm::memcg::memcg_charge(cg, 1, crate::mm::memcg::ChargeType::Anon).is_ok());
                        crate::mm::memcg::memcg_track_page(frame_idx, cg, crate::mm::memcg::ChargeType::Anon);

                        match crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon) {
                            Ok(h) => { h.wait(); }
                            Err(SwapError::QueueFull) => {
                                let physf = unsafe { PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(frame_idx.to_phys_addr())) };
                                buddy_allocator::buddy_dealloc_frame(physf);
                            }
                            Err(e) => panic!("unexpected enqueue error: {:?}", e),
                        }
                    }
                }
            });

            joiners.push(j);
        }

        for j in joiners {
            j.join().expect("join");
        }

        stop_worker();
        for _ in 0..200 {
            if !is_worker_running() { break; }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        let stats = crate::mm::memcg::memcg_stats(cg).expect("stats");
        assert_eq!(stats.cache_pages, 0);
        assert_eq!(stats.anon_pages, 0);
    }

    #[test_case]
    #[ignore]
    fn test_async_swapout_heavy_stress() {
        crate::mm::memcg::init_memcg();
        let cg = crate::mm::memcg::memcg_create(String::from("heavy"), crate::mm::memcg::memcg_root()).expect("create memcg");
        crate::fs::init_page_cache(64 * 1024);
        let cache = crate::fs::page_cache();

        test_impl::set_processing_delay(5);
        // Apply recommended validation defaults for heavy stress run
        test_impl::set_token_capacity_for_test(32);
        test_impl::set_reserved_file_slots_for_test(128);
        test_impl::set_tokens(test_impl::token_capacity());

        start_worker();

        let threads = 64usize;
        let iters = 200usize;
        let mut joiners = Vec::new();

        for t in 0..threads {
            let cache = cache;
            let cg = cg;
            let j = std::thread::spawn(move || {
                for i in 0..iters {
                    let frame = crate::mm::alloc_frame().expect("alloc frame");
                    let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
                    if ((i + t) % 2) == 0 {
                        assert!(crate::mm::memcg::memcg_charge(cg, 1, crate::mm::memcg::ChargeType::Cache).is_ok());
                        crate::mm::memcg::memcg_track_page(frame_idx, cg, crate::mm::memcg::ChargeType::Cache);
                        let ino = 7000u64 + (i % 512) as u64;
                        let page_num = i as u64;
                        let data = alloc::vec![0u8; PAGE_SIZE_4K];
                        cache.insert(ino, page_num, data, PAGE_SIZE_4K as u64);
                        assert!(cache.mark_dirty(ino, page_num));
                        crate::mm::frame_backing::track_frame_backing(frame_idx, ino, page_num);
                        match crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::File { ino, page_num }) {
                            Ok(h) => { h.wait(); }
                            Err(SwapError::QueueFull) => {
                                let _ = crate::fs::page_cache().sync_page(ino, page_num, |_o, _d| Ok(()));
                                let physf = unsafe { PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(frame_idx.to_phys_addr())) };
                                buddy_allocator::buddy_dealloc_frame(physf);
                            }
                            Err(e) => panic!("unexpected enqueue error: {:?}", e),
                        }
                    } else {
                        assert!(crate::mm::memcg::memcg_charge(cg, 1, crate::mm::memcg::ChargeType::Anon).is_ok());
                        crate::mm::memcg::memcg_track_page(frame_idx, cg, crate::mm::memcg::ChargeType::Anon);
                        match crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon) {
                            Ok(h) => { h.wait(); }
                            Err(SwapError::QueueFull) => {
                                let physf = unsafe { PhysFrame::from_start_address_unchecked(x86_64::PhysAddr::new(frame_idx.to_phys_addr())) };
                                buddy_allocator::buddy_dealloc_frame(physf);
                            }
                            Err(e) => panic!("unexpected enqueue error: {:?}", e),
                        }
                    }
                }
            });
            joiners.push(j);
        }

        for j in joiners { j.join().expect("join"); }

        stop_worker();
        for _ in 0..500 { if !is_worker_running() { break; } std::thread::sleep(std::time::Duration::from_millis(10)); }

        let stats = crate::mm::memcg::memcg_stats(cg).expect("stats");
        assert_eq!(stats.cache_pages, 0);
        assert_eq!(stats.anon_pages, 0);
    }

    #[test_case]
    #[ignore]
    fn bench_enqueue_throughput() {
        crate::fs::init_page_cache(64 * 1024);

        test_impl::set_processing_delay(1);
        test_impl::set_tokens(test_impl::token_capacity());

        start_worker();

        let count = 2000usize;
        let start = std::time::Instant::now();
        for _ in 0..count {
            let frame = crate::mm::alloc_frame().expect("alloc frame");
            let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
            let h = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon).expect("enqueue ok");
            h.wait();
        }
        let dur = start.elapsed();
        println!("Enqueued+processed {} anon entries in {:?}", count, dur);

        stop_worker();
    }

    #[test_case]
    fn test_zswap_failure_does_not_dealloc() {
        crate::fs::init_page_cache(64 * 1024);

        // Ensure deterministic worker lifecycle
        test_impl::stop_worker();
        for _ in 0..20 { if !test_impl::is_worker_running() { break; } std::thread::sleep(std::time::Duration::from_millis(10)); }

        test_impl::_reset_dealloc_count();
        test_impl::_reset_zswap_fail_count();

        // Configure zswap to be effectively full (force PoolFull)
        crate::mm::zswap::zswap_set_enabled(true);
        crate::mm::zswap::zswap_update_config(crate::mm::zswap::ZswapConfig {
            enabled: true,
            compressor: crate::mm::zswap::CompressionAlgo::Lz4,
            max_pool_size: 0,
            max_compression_ratio: 0.9,
            same_filled_pages_enabled: false,
            writeback_threshold: 0.8,
        });

        let frame = crate::mm::alloc_frame().expect("alloc frame");
        let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());

        let h = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon).expect("enqueue ok");
        test_impl::start_worker();
        h.wait();

        // On zswap failure we must NOT deallocate the frame (test-only counter)
        assert_eq!(test_impl::_dealloc_count(), 0);
        assert!(test_impl::_zswap_fail_count() > 0);

        stop_worker();
    }

    #[test_case]
    fn test_huge_page_2m_anon_store() {
        // Ensure deterministic worker lifecycle
        test_impl::stop_worker();
        for _ in 0..20 { if !test_impl::is_worker_running() { break; } std::thread::sleep(std::time::Duration::from_millis(10)); }

        // Ensure zswap is enabled and has room for 2MiB
        crate::mm::zswap::zswap_set_enabled(true);
        crate::mm::zswap::zswap_update_config(crate::mm::zswap::ZswapConfig {
            enabled: true,
            compressor: crate::mm::zswap::CompressionAlgo::Lz4,
            max_pool_size: crate::mm::PAGE_SIZE_2M * 4,
            max_compression_ratio: 1.0,
            same_filled_pages_enabled: false,
            writeback_threshold: 0.8,
        });

        // Allocate a 2MiB huge page (buddy allocator)
        let huge = crate::mm::buddy_allocator::buddy_alloc_frame_2m().expect("alloc 2m frame");
        let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(huge.start_address().as_u64());

        let before = crate::mm::zswap::zswap_stats().stored_pages_2m;

        // Enqueue as anon
        let h = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon).expect("enqueue ok");
        test_impl::start_worker();
        h.wait();

        // Should have been stored and deallocated
        assert!(crate::mm::zswap::zswap_stats().stored_pages_2m > before);
        assert!(!crate::mm::buddy_allocator::is_frame_allocated(frame_idx.as_usize()));

        stop_worker();
    }

    #[test_case]
    fn test_global_async_swapout_metrics_update() {
        // ensure metrics are zeroed in the beginning
        // Note: These are global, so we don't reset them here; just ensure they are accessible and behave monotonically
        let before_fail = crate::mm::async_swapout::stats_zswap_fail_count();
        let before_dealloc = crate::mm::async_swapout::stats_async_dealloc_count();

        // Force zswap failure and enqueue anon
        test_impl::stop_worker();
        for _ in 0..20 { if !test_impl::is_worker_running() { break; } std::thread::sleep(std::time::Duration::from_millis(10)); }

        crate::mm::zswap::zswap_set_enabled(true);
        crate::mm::zswap::zswap_update_config(crate::mm::zswap::ZswapConfig {
            enabled: true,
            compressor: crate::mm::zswap::CompressionAlgo::Lz4,
            max_pool_size: 0,
            max_compression_ratio: 0.9,
            same_filled_pages_enabled: false,
            writeback_threshold: 0.8,
        });

        let frame = crate::mm::alloc_frame().expect("alloc frame");
        let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());

        let h = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon).expect("enqueue ok");
        test_impl::start_worker();
        h.wait();

        // Metrics should be non-decreasing
        assert!(crate::mm::async_swapout::stats_zswap_fail_count() >= before_fail);
        assert!(crate::mm::async_swapout::stats_async_dealloc_count() >= before_dealloc);

        stop_worker();
    }

    #[test_case]
    fn test_token_exhaustion_does_not_leave_pending() {
        test_impl::stop_worker();
        for _ in 0..20 { if !test_impl::is_worker_running() { break; } std::thread::sleep(std::time::Duration::from_millis(10)); }

        test_impl::set_tokens(0);

        let frame = crate::mm::alloc_frame().expect("alloc frame");
        let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());

        let err = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon).expect_err("should be QueueFull due to tokens");
        assert_eq!(err, SwapError::QueueFull);

        // Ensure pending flag was rolled back
        assert_eq!(test_impl::_pending_len(), 0);
    }

    #[test_case]
    fn test_file_queue_counter_saturation() {
        test_impl::stop_worker();
        for _ in 0..20 { if !test_impl::is_worker_running() { break; } std::thread::sleep(std::time::Duration::from_millis(10)); }

        // Repeated safe decrement must not underflow
        for _ in 0..10 {
            test_impl::_dec_file_queue_count_safe();
            assert_eq!(test_impl::_file_queue_len(), 0);
        }
    }

    #[test_case]
    fn test_buffer_pool_basic() {
        // Ensure pool is cleared and capacity is small
        crate::mm::async_swapout::buffer_pool_4k_clear();
        crate::mm::async_swapout::buffer_pool_4k_set_capacity(2);

        let (h0, m0, o0) = crate::mm::async_swapout::buffer_pool_4k_stats();
        assert_eq!(h0, 0);
        assert_eq!(m0, 0);
        assert_eq!(o0, 0);

        let b1 = crate::mm::async_swapout::buffer_pool_get_4k();
        let b2 = crate::mm::async_swapout::buffer_pool_get_4k();
        let (_h1, m1, _o1) = crate::mm::async_swapout::buffer_pool_4k_stats();
        assert_eq!(m1 - m0, 2);

        crate::mm::async_swapout::buffer_pool_put_4k(b1);
        crate::mm::async_swapout::buffer_pool_put_4k(b2);

        let _b3 = crate::mm::async_swapout::buffer_pool_get_4k();
        let _b4 = crate::mm::async_swapout::buffer_pool_get_4k();
        let (h2, _m2, o2) = crate::mm::async_swapout::buffer_pool_4k_stats();
        assert!(h2 >= 1);
        assert!(o2 <= 2);

        crate::mm::async_swapout::buffer_pool_4k_clear();
    }

    #[test_case]
    fn test_buffer_pool_concurrent() {
        crate::mm::async_swapout::buffer_pool_4k_clear();
        crate::mm::async_swapout::buffer_pool_4k_set_capacity(16);

        let threads = 8usize;
        let iters = 500usize;
        let mut handles = Vec::new();
        for _ in 0..threads {
            #[cfg(feature = "std")]
            let h = std::thread::spawn(move || {
                for _ in 0..iters {
                    let mut b = crate::mm::async_swapout::buffer_pool_get_4k();
                    b[0] = 1; // touch
                    crate::mm::async_swapout::buffer_pool_put_4k(b);
                }
            });
            handles.push(h);
        }

        for h in handles { h.join().expect("join"); }

        let (hits, misses, occ) = crate::mm::async_swapout::buffer_pool_4k_stats();
        assert!(hits + misses >= threads * iters);
        assert!(occ <= 16);

        crate::mm::async_swapout::buffer_pool_4k_clear();
    }

    #[test_case]
    fn test_buffer_pool_2m_basic() {
        crate::mm::async_swapout::buffer_pool_2m_clear();
        crate::mm::async_swapout::buffer_pool_2m_set_capacity(2);

        let (h0, m0, o0) = crate::mm::async_swapout::buffer_pool_2m_stats();
        assert_eq!(h0, 0);
        assert_eq!(m0, 0);
        assert_eq!(o0, 0);

        let b1 = crate::mm::async_swapout::buffer_pool_get_2m();
        let b2 = crate::mm::async_swapout::buffer_pool_get_2m();
        let (_h1, m1, _o1) = crate::mm::async_swapout::buffer_pool_2m_stats();
        assert_eq!(m1 - m0, 2);

        crate::mm::async_swapout::buffer_pool_put_2m(b1);
        crate::mm::async_swapout::buffer_pool_put_2m(b2);

        let _b3 = crate::mm::async_swapout::buffer_pool_get_2m();
        let _b4 = crate::mm::async_swapout::buffer_pool_get_2m();
        let (h2, _m2, o2) = crate::mm::async_swapout::buffer_pool_2m_stats();
        assert!(h2 >= 1);
        assert!(o2 <= 2);

        crate::mm::async_swapout::buffer_pool_2m_clear();
    }

    #[test_case]
    fn test_buffer_pool_2m_concurrent() {
        crate::mm::async_swapout::buffer_pool_2m_clear();
        crate::mm::async_swapout::buffer_pool_2m_set_capacity(8);

        let threads = 4usize;
        let iters = 10usize;
        let mut handles = Vec::new();
        for _ in 0..threads {
            let h = std::thread::spawn(move || {
                for _ in 0..iters {
                    let mut b = crate::mm::async_swapout::buffer_pool_get_2m();
                    b[0] = 1; // touch
                    crate::mm::async_swapout::buffer_pool_put_2m(b);
                }
            });
            handles.push(h);
        }

        for h in handles { h.join().expect("join"); }

        let (hits, misses, occ) = crate::mm::async_swapout::buffer_pool_2m_stats();
        assert!(hits + misses >= threads * iters);
        assert!(occ <= 8);

        crate::mm::async_swapout::buffer_pool_2m_clear();
    }

    #[test_case]
    #[ignore]
    fn test_buffer_pool_1g_basic() {
        crate::mm::async_swapout::buffer_pool_1g_clear();
        crate::mm::async_swapout::buffer_pool_1g_set_capacity(1);

        let (h0, m0, o0) = crate::mm::async_swapout::buffer_pool_1g_stats();
        assert_eq!(h0, 0);
        assert_eq!(m0, 0);
        assert_eq!(o0, 0);

        let b1 = crate::mm::async_swapout::buffer_pool_get_1g();
        let (_h1, m1, _o1) = crate::mm::async_swapout::buffer_pool_1g_stats();
        assert_eq!(m1 - m0, 1);

        crate::mm::async_swapout::buffer_pool_put_1g(b1);

        let _b2 = crate::mm::async_swapout::buffer_pool_get_1g();
        let (h2, _m2, o2) = crate::mm::async_swapout::buffer_pool_1g_stats();
        assert!(h2 >= 1);
        assert!(o2 <= 1);

        crate::mm::async_swapout::buffer_pool_1g_clear();
    }

    #[test_case]
    #[ignore]
    #[cfg(feature = "std")]
    fn bench_enqueue_throughput_pool_vs_nopool() {
        crate::fs::init_page_cache(64 * 1024);

        // small micro-bench (ignored by default)
        let count = 200usize;

        // Phase A: no pool
        crate::mm::async_swapout::buffer_pool_4k_clear();
        crate::mm::async_swapout::buffer_pool_4k_set_capacity(0);

        test_impl::set_processing_delay(1);
        test_impl::set_tokens(test_impl::token_capacity());
        test_impl::start_worker();

        let start = std::time::Instant::now();
        for _ in 0..count {
            let frame = crate::mm::alloc_frame().expect("alloc frame");
            let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
            let h = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon).expect("enqueue ok");
            h.wait();
        }
        let dur_no_pool = start.elapsed();
        if cfg!(feature = "std") {
            test_impl::stop_worker();
        }

        // Phase B: pool enabled
        crate::mm::async_swapout::buffer_pool_4k_clear();
        crate::mm::async_swapout::buffer_pool_4k_set_capacity(128);

        if cfg!(feature = "std") {
            test_impl::set_processing_delay(1);
            test_impl::set_tokens(test_impl::token_capacity());
            test_impl::start_worker();
        }

        let start2 = std::time::Instant::now();
        for _ in 0..count {
            let frame = crate::mm::alloc_frame().expect("alloc frame");
            let frame_idx = crate::mm::types::FrameIndex::from_phys_addr(frame.start_address().as_u64());
            let h = crate::mm::async_swapout::try_enqueue_swapout(frame_idx, SwapKind::Anon).expect("enqueue ok");
            h.wait();
        }
        let dur_pool = start2.elapsed();
        if cfg!(feature = "std") {
            test_impl::stop_worker();
        }

        eprintln!("No-pool: {:?}, With-pool: {:?}", dur_no_pool, dur_pool);

        // make sure pool was exercised
        let (hits, misses, _occ) = crate::mm::async_swapout::buffer_pool_4k_stats();
        assert!(hits + misses > 0);
    }

    #[test_case]
    #[ignore]
    #[cfg(feature = "std")]
    fn bench_buffer_pool_2m_throughput() {
        // micro-bench: small counts to avoid excessive memory use
        let count = 12usize;

        // Phase A: no pool
        crate::mm::async_swapout::buffer_pool_2m_clear();
        crate::mm::async_swapout::buffer_pool_2m_set_capacity(0);

        let start = std::time::Instant::now();
        for _ in 0..count {
            let mut b = crate::mm::async_swapout::buffer_pool_get_2m();
            b[0] = 1;
            crate::mm::async_swapout::buffer_pool_put_2m(b);
        }
        let dur_no_pool = start.elapsed();

        // Phase B: pool enabled
        crate::mm::async_swapout::buffer_pool_2m_clear();
        crate::mm::async_swapout::buffer_pool_2m_set_capacity(8);

        let start2 = std::time::Instant::now();
        for _ in 0..count {
            let mut b = crate::mm::async_swapout::buffer_pool_get_2m();
            b[0] = 1;
            crate::mm::async_swapout::buffer_pool_put_2m(b);
        }
        let dur_pool = start2.elapsed();

        eprintln!("2M No-pool: {:?}, With-pool: {:?}", dur_no_pool, dur_pool);

        let (hits, misses, _occ) = crate::mm::async_swapout::buffer_pool_2m_stats();
        assert!(hits + misses > 0);
    }

    #[test_case]
    #[ignore]
    #[cfg(feature = "std")]
    fn bench_buffer_pool_1g_throughput() {
        // very small count due to size
        let count = 2usize;

        crate::mm::async_swapout::buffer_pool_1g_clear();
        crate::mm::async_swapout::buffer_pool_1g_set_capacity(0);

        let start = std::time::Instant::now();
        for _ in 0..count {
            let mut b = crate::mm::async_swapout::buffer_pool_get_1g();
            b[0] = 1;
            crate::mm::async_swapout::buffer_pool_put_1g(b);
        }
        let dur_no_pool = start.elapsed();

        crate::mm::async_swapout::buffer_pool_1g_clear();
        crate::mm::async_swapout::buffer_pool_1g_set_capacity(1);

        let start2 = std::time::Instant::now();
        for _ in 0..count {
            let mut b = crate::mm::async_swapout::buffer_pool_get_1g();
            b[0] = 1;
            crate::mm::async_swapout::buffer_pool_put_1g(b);
        }
        let dur_pool = start2.elapsed();

        eprintln!("1G No-pool: {:?}, With-pool: {:?}", dur_no_pool, dur_pool);

        let (hits, misses, _occ) = crate::mm::async_swapout::buffer_pool_1g_stats();
        assert!(hits + misses > 0);
    }
}



