// ============================================================================
// src/mm/page_flags.rs - Global Page Flags
// ============================================================================
//! Global atomic page flags for lock-free state tracking.
//!
//! Replaces global mutexes (e.g. swap pending) with per-frame atomic flags.
//!
//! # Memory Overhead
//! Uses 1 byte per 4KiB page.
//! - 16GB RAM = 4M pages = 4MB overhead.
//!
//! # Usage
//! ```
//! use crate::mm::page_flags::{self, PageFlags};
//! 
//! // Set swap pending flag
//! if page_flags::test_and_set_flag(frame_idx, PageFlags::SWAP_PENDING) {
//!     // Already set
//! } else {
//!     // Successfully set
//! }
//! ```
// ============================================================================

use core::sync::atomic::{AtomicU8, Ordering};
use alloc::vec::Vec;
use crate::mm::types::FrameIndex;

/// Global array of atomic page flags.
/// Initialized during memory management setup.
static mut PAGE_FLAGS: *mut AtomicU8 = core::ptr::null_mut();
/// Global array of page orders (store allocation order for Folios).
/// 0 for order-0 pages.
static mut PAGE_ORDERS: *mut u8 = core::ptr::null_mut();
static mut TOTAL_FRAMES: usize = 0;

/// Atomic flags for each page
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageFlags {
    /// Page is currently queued for swapout (prevent duplicate enqueue)
    SwapPending = 1 << 0,
    /// Page is currently under writeback
    Writeback = 1 << 1,
    /// Page is dirty (software dirty bit)
    Dirty = 1 << 2,
    /// Page is locked (cannot be reclaimed)
    Locked = 1 << 3,
    /// Page is referenced (software accessed bit for LRU)
    Referenced = 1 << 4,
    /// Page is a head page of a compound page (Folio)
    CompoundHead = 1 << 5,
    /// Page is a tail page of a compound page
    CompoundTail = 1 << 6,
}

impl PageFlags {
    #[inline]
    pub const fn bits(self) -> u8 {
        self as u8
    }
}

/// Initialize the global page flags array.
/// 
/// # Safety
/// Must be called once during kernel initialization with valid heap.
pub unsafe fn init_page_flags(total_frames: usize) {
    TOTAL_FRAMES = total_frames;
    
    // Allocate the flags array
    let mut flags = Vec::with_capacity(total_frames);
    flags.resize_with(total_frames, || AtomicU8::new(0));
    let leaked_flags = flags.leak();
    PAGE_FLAGS = leaked_flags.as_mut_ptr();

    // Allocate the orders array
    let mut orders = Vec::with_capacity(total_frames);
    orders.resize(total_frames, 0);
    let leaked_orders = orders.leak();
    PAGE_ORDERS = leaked_orders.as_mut_ptr();
}

/// Get reference to the atomic flags for a frame.
#[inline]
fn get_atomic(frame: FrameIndex) -> Option<&'static AtomicU8> {
    let idx = frame.as_usize();
    unsafe {
        if idx >= TOTAL_FRAMES || PAGE_FLAGS.is_null() {
            return None;
        }
        Some(&*PAGE_FLAGS.add(idx))
    }
}

/// Test if specific flag is set
#[inline]
pub fn test_flag(frame: FrameIndex, flag: PageFlags) -> bool {
    if let Some(atomic) = get_atomic(frame) {
        (atomic.load(Ordering::Relaxed) & flag.bits()) != 0
    } else {
        false
    }
}

/// Set a flag (atomically)
#[inline]
pub fn set_flag(frame: FrameIndex, flag: PageFlags) {
    if let Some(atomic) = get_atomic(frame) {
        atomic.fetch_or(flag.bits(), Ordering::Relaxed);
    }
}

/// Clear a flag (atomically)
#[inline]
pub fn clear_flag(frame: FrameIndex, flag: PageFlags) {
    if let Some(atomic) = get_atomic(frame) {
        atomic.fetch_and(!flag.bits(), Ordering::Relaxed);
    }
}

/// Test and set a flag (atomically).
/// Returns true if the flag was ALREADY set.
#[inline]
pub fn test_and_set_flag(frame: FrameIndex, flag: PageFlags) -> bool {
    if let Some(atomic) = get_atomic(frame) {
        let prev = atomic.fetch_or(flag.bits(), Ordering::Acquire);
        (prev & flag.bits()) != 0
    } else {
        false
    }
}

/// Test and clear a flag (atomically).
/// Returns true if the flag was previously set.
#[inline]
pub fn test_and_clear_flag(frame: FrameIndex, flag: PageFlags) -> bool {
    if let Some(atomic) = get_atomic(frame) {
        let prev = atomic.fetch_and(!flag.bits(), Ordering::Release);
        (prev & flag.bits()) != 0
    } else {
        false
    }
}

/// Get the allocated order of a page.
#[inline]
pub fn get_order(frame: FrameIndex) -> u8 {
    let idx = frame.as_usize();
    unsafe {
        if idx >= TOTAL_FRAMES || PAGE_ORDERS.is_null() {
            return 0;
        }
        *PAGE_ORDERS.add(idx)
    }
}

/// Set the allocated order of a page.
/// 
/// # Safety
/// Caller must ensure synchronization. Typically set during allocation/deallocation.
#[inline]
pub unsafe fn set_order(frame: FrameIndex, order: u8) {
     let idx = frame.as_usize();
     if idx < TOTAL_FRAMES && !PAGE_ORDERS.is_null() {
         *PAGE_ORDERS.add(idx) = order;
     }
}
