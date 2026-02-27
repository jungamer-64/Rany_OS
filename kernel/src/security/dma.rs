// ============================================================================
// kernel/src/security/dma.rs - DMA Security & Physical Page Protection
// ============================================================================

//! DMA Security Monitor
//!
//! Provides a global registry of physical pages that are protected from DMA.
//! This is used by the IOMMU subsystem to prevent malicious or faulty devices
//! from accessing sensitive memory like page tables, kernel stacks, etc.

use alloc::vec::Vec;
use spin::{Once, RwLock};
use crate::sync::IrqMutex;

/// Bitmap for protecting individual physical pages (4KB granularity).
/// Covers up to 1TB of RAM by default (32MB bitmap).
/// Increased from 64GB to support high-memory systems.
const PROTECTED_BITMAP_PAGES: usize = 256 * 1024 * 1024; // 256M pages = 1TB
const PROTECTED_BITMAP_SIZE: usize = PROTECTED_BITMAP_PAGES / 8; // 32MB

static PROTECTED_PAGE_BITMAP: Once<IrqMutex<Vec<u8>>> = Once::new();

/// Physical memory region that should be protected from DMA access.
#[derive(Debug, Clone, Copy)]
pub struct ProtectedRegion {
    pub start: u64,
    pub end: u64,
    pub name: &'static str,
}

/// Global registry of protected physical memory regions.
/// Used for regions above 1TB or large contiguous regions.
/// Sorted by start address for O(log n) lookup.
static PROTECTED_REGIONS: RwLock<Vec<ProtectedRegion>> = RwLock::new(Vec::new());

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
    } else {
        // Fallback for pages above 1TB: add to protected regions list
        register_protected_region_internal(phys, 4096, "Dynamic Page Table / Stack (High Mem)");
    }
}

/// Unregister a physical page from protection.
pub fn unregister_protected_page(phys: u64) {
    let page_idx = (phys / 4096) as usize;
    if page_idx < PROTECTED_BITMAP_PAGES {
        let mut bitmap = get_protected_bitmap().lock();
        bitmap[page_idx / 8] &= !(1 << (page_idx % 8));
    } else {
        // Remove from protected regions list
        let end = phys.saturating_add(4096);
        let mut regions = PROTECTED_REGIONS.write();
        if let Ok(idx) = regions.binary_search_by(|r| r.start.cmp(&phys)) {
            if regions[idx].end == end {
                regions.remove(idx);
            }
        }
    }
}

/// Check if a physical page is registered as protected.
pub fn is_page_protected(phys: u64) -> bool {
    let page_idx = (phys / 4096) as usize;
    if page_idx < PROTECTED_BITMAP_PAGES {
        let bitmap = get_protected_bitmap().lock();
        (bitmap[page_idx / 8] & (1 << (page_idx % 8))) != 0
    } else {
        // Fallback for pages above 1TB: check protected regions list via binary search
        let regions = PROTECTED_REGIONS.read();
        match regions.binary_search_by(|r| {
            if phys < r.start {
                core::cmp::Ordering::Greater
            } else if phys >= r.end {
                core::cmp::Ordering::Less
            } else {
                core::cmp::Ordering::Equal
            }
        }) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

/// Register a physical memory range as protected.
pub fn register_protected_range(start: u64, size: u64) {
    if size == 0 { return; }
    let end = start.saturating_add(size);
    
    // For large regions (> 1MB) or high-memory regions, use the regions list directly
    if size > 1024 * 1024 || start >= (PROTECTED_BITMAP_PAGES as u64 * 4096) {
        register_protected_region_internal(start, size, "Large/High Protected Range");
        if start >= (PROTECTED_BITMAP_PAGES as u64 * 4096) {
            return; // No need to try bitmap for high memory
        }
    }

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

/// Unregister a physical memory range from protection.
pub fn unregister_protected_range(start: u64, size: u64) {
    if size == 0 { return; }
    let end = start.saturating_add(size);

    // If it was potentially in the regions list
    if size > 1024 * 1024 || start >= (PROTECTED_BITMAP_PAGES as u64 * 4096) {
        let mut regions = PROTECTED_REGIONS.write();
        if let Ok(idx) = regions.binary_search_by(|r| r.start.cmp(&start)) {
            if regions[idx].end == end {
                regions.remove(idx);
            }
        }
    }

    let mut current = (start / 4096) * 4096;
    while current < end && current < (PROTECTED_BITMAP_PAGES as u64 * 4096) {
        unregister_protected_page(current);
        if let Some(next) = current.checked_add(4096) {
            current = next;
        } else {
            break;
        }
    }
}

/// Internal helper to register a protected region.
fn register_protected_region_internal(start: u64, size: u64, name: &'static str) {
    let end = start.saturating_add(size);
    let mut regions = PROTECTED_REGIONS.write();
    
    match regions.binary_search_by(|r| r.start.cmp(&start)) {
        Ok(idx) => {
            // Already exists or overlaps at start
            if regions[idx].end < end {
                regions[idx].end = end; // Extend existing
            }
        }
        Err(idx) => {
            // Insert at idx to keep sorted
            regions.insert(idx, ProtectedRegion { start, end, name });
            
            // Scalability Warning: If we have too many regions, it impacts performance
            if regions.len() > 2048 && regions.len() % 1024 == 0 {
                log::warn!(
                    "[DMA][SECURITY] Large number of protected regions: {}. Performance may degrade.",
                    regions.len()
                );
            }
        }
    }
}

/// Check if a range overlaps with any protected region.
pub fn range_overlaps_protected(start: u64, size: u64) -> bool {
    if size == 0 { return false; }
    let end = start.saturating_add(size);

    // 1. Check bitmap for pages in range
    let mut current = (start / 4096) * 4096;
    while current < end && current < (PROTECTED_BITMAP_PAGES as u64 * 4096) {
        if is_page_protected(current) {
            return true;
        }
        if let Some(next) = current.checked_add(4096) {
            current = next;
        } else {
            break;
        }
    }

    // 2. Check regions list via binary search for overlap
    let regions = PROTECTED_REGIONS.read();
    // Find the first region that could possibly overlap (start < r.end)
    match regions.binary_search_by(|r| {
        if end <= r.start {
            core::cmp::Ordering::Greater
        } else if start >= r.end {
            core::cmp::Ordering::Less
        } else {
            core::cmp::Ordering::Equal
        }
    }) {
        Ok(_) => true,
        Err(_) => false,
    }
}
