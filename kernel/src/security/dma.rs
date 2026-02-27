// ============================================================================
// kernel/src/security/dma.rs - DMA Security & Physical Page Protection
// ============================================================================

//! DMA Security Monitor
//!
//! Provides a global registry of physical pages that are protected from DMA.
//! This is used by the IOMMU subsystem to prevent malicious or faulty devices
//! from accessing sensitive memory like page tables, kernel stacks, etc.

use alloc::vec::Vec;
use core::sync::atomic::{Ordering};
use spin::Once;
use crate::sync::IrqMutex;

/// Bitmap for protecting individual physical pages (4KB granularity).
/// Covers up to 64GB of RAM by default (2MB bitmap).
const PROTECTED_BITMAP_PAGES: usize = 16384 * 1024; // 16M pages = 64GB
const PROTECTED_BITMAP_SIZE: usize = PROTECTED_BITMAP_PAGES / 8; // 2MB

static PROTECTED_PAGE_BITMAP: Once<IrqMutex<Vec<u8>>> = Once::new();

fn get_protected_bitmap() -> &'static IrqMutex<Vec<u8>> {
    PROTECTED_PAGE_BITMAP.call_once(|| {
        let mut v = Vec::with_capacity(PROTECTED_BITMAP_SIZE);
        v.resize(PROTECTED_BITMAP_SIZE, 0);
        IrqMutex::new(v)
    })
}

/// Register a physical page as protected from DMA.
pub fn register_protected_page(phys: u64) {
    let page_idx = (phys / 4096) as usize;
    if page_idx < PROTECTED_BITMAP_PAGES {
        let mut bitmap = get_protected_bitmap().lock();
        bitmap[page_idx / 8] |= 1 << (page_idx % 8);
    }
}

/// Unregister a physical page from protection.
pub fn unregister_protected_page(phys: u64) {
    let page_idx = (phys / 4096) as usize;
    if page_idx < PROTECTED_BITMAP_PAGES {
        let mut bitmap = get_protected_bitmap().lock();
        bitmap[page_idx / 8] &= !(1 << (page_idx % 8));
    }
}

/// Check if a physical page is registered as protected.
pub fn is_page_protected(phys: u64) -> bool {
    let page_idx = (phys / 4096) as usize;
    if page_idx < PROTECTED_BITMAP_PAGES {
        let bitmap = get_protected_bitmap().lock();
        (bitmap[page_idx / 8] & (1 << (page_idx % 8))) != 0
    } else {
        false
    }
}

/// Register a physical memory range as protected.
pub fn register_protected_range(start: u64, size: u64) {
    let end = start.saturating_add(size);
    let mut current = (start / 4096) * 4096;
    while current < end {
        register_protected_page(current);
        if let Some(next) = current.checked_add(4096) {
            current = next;
        } else {
            break;
        }
    }
}
