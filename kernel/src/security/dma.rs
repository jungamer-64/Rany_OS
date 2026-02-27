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
static PROTECTED_REGIONS: RwLock<Vec<ProtectedRegion>> = RwLock::new(Vec::new());

/// Maximum number of protected physical memory regions.
const MAX_PROTECTED_REGIONS: usize = 1024;

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
        // Remove from protected regions list (best effort)
        let mut regions = PROTECTED_REGIONS.write();
        let end = phys.saturating_add(4096);
        regions.retain(|r| r.start != phys || r.end != end);
    }
}

/// Check if a physical page is registered as protected.
pub fn is_page_protected(phys: u64) -> bool {
    let page_idx = (phys / 4096) as usize;
    if page_idx < PROTECTED_BITMAP_PAGES {
        let bitmap = get_protected_bitmap().lock();
        (bitmap[page_idx / 8] & (1 << (page_idx % 8))) != 0
    } else {
        // Fallback for pages above 1TB: check protected regions list
        let regions = PROTECTED_REGIONS.read();
        for region in regions.iter() {
            if phys >= region.start && phys < region.end {
                return true;
            }
        }
        false
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
        regions.retain(|r| r.start != start || r.end != end);
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
    if regions.len() < MAX_PROTECTED_REGIONS {
        // Check for duplicates
        if !regions.iter().any(|r| r.start == start && r.end == end) {
            regions.push(ProtectedRegion { start, end, name });
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

    // 2. Check regions list
    let regions = PROTECTED_REGIONS.read();
    for region in regions.iter() {
        if start < region.end && region.start < end {
            return true;
        }
    }
    
    false
}
