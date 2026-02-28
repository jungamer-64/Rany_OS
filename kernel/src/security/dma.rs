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
    let boundary = PROTECTED_BITMAP_PAGES as u64 * 4096;
    
    // For large regions (> 1MB) or if ANY part is above the bitmap range,
    // use the regions list to ensure coverage of the high-memory part.
    if size > 1024 * 1024 || end > boundary {
        register_protected_region_internal(start, size, "Large/High Protected Range");
        if start >= boundary {
            return; // No need to try bitmap for purely high memory
        }
    }

    let start_page = (start / 4096) as usize;
    let end_page = ((end.saturating_add(4095)) / 4096) as usize;
    let check_end_page = end_page.min(PROTECTED_BITMAP_PAGES);

    if start_page < check_end_page {
        let mut bitmap = get_protected_bitmap().lock();
        for page_idx in start_page..check_end_page {
            bitmap[page_idx / 8] |= 1 << (page_idx % 8);
        }
    }
}

/// Unregister a physical memory range from protection.
pub fn unregister_protected_range(start: u64, size: u64) {
    if size == 0 { return; }
    let end = start.saturating_add(size);
    let boundary = PROTECTED_BITMAP_PAGES as u64 * 4096;

    // If it was potentially in the regions list
    if size > 1024 * 1024 || end > boundary {
        let mut regions = PROTECTED_REGIONS.write();
        let mut i = 0;
        while i < regions.len() {
            let r_start = regions[i].start;
            let r_end = regions[i].end;
            let r_name = regions[i].name;

            // No overlap
            if end <= r_start || start >= r_end {
                i += 1;
                continue;
            }

            // Case 1: Unregistered range covers the entire protected region
            if start <= r_start && end >= r_end {
                regions.remove(i);
                // Don't increment i; the next region shifts into this index.
                continue;
            }

            // Case 2: Unregistered range overlaps with the start of the region
            if start <= r_start && end < r_end {
                regions[i].start = end;
                i += 1;
                continue;
            }

            // Case 3: Unregistered range overlaps with the end of the region
            if start > r_start && end >= r_end {
                regions[i].end = start;
                i += 1;
                continue;
            }

            // Case 4: Unregistered range is in the middle of the region - split it
            if start > r_start && end < r_end {
                regions[i].end = start;
                regions.insert(i + 1, ProtectedRegion {
                    start: end,
                    end: r_end,
                    name: r_name,
                });
                i += 2;
                continue;
            }
            i += 1;
        }
    }

    let start_page = (start / 4096) as usize;
    let end_page = ((end.saturating_add(4095)) / 4096) as usize;
    let check_end_page = end_page.min(PROTECTED_BITMAP_PAGES);

    if start_page < check_end_page {
        let mut bitmap = get_protected_bitmap().lock();
        for page_idx in start_page..check_end_page {
            bitmap[page_idx / 8] &= !(1 << (page_idx % 8));
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
                
                // After extending, it might now overlap with the next one(s)
                let mut new_end = end;
                let next_idx = idx + 1;
                while next_idx < regions.len() && regions[next_idx].start <= new_end {
                    new_end = new_end.max(regions[next_idx].end);
                    regions.remove(next_idx);
                }
                regions[idx].end = new_end;
            }
        }
        Err(idx) => {
            // 1. Check if it overlaps with previous region and can be merged
            if idx > 0 && regions[idx-1].end >= start {
                if regions[idx-1].end < end {
                    regions[idx-1].end = end;
                    // After merging with previous, it might now overlap with the next one
                    let mut new_end = end;
                    while idx < regions.len() && regions[idx].start <= new_end {
                        new_end = new_end.max(regions[idx].end);
                        regions.remove(idx);
                    }
                    regions[idx-1].end = new_end;
                }
                return;
            }
            
            // 2. Check if it overlaps with next region(s) and can be merged
            let mut current_end = end;
            let insert_idx = idx;
            while insert_idx < regions.len() && regions[insert_idx].start <= current_end {
                current_end = current_end.max(regions[insert_idx].end);
                regions.remove(insert_idx);
            }

            // Insert at idx to keep sorted
            regions.insert(idx, ProtectedRegion { start, end: current_end, name });
            
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
    let start_page = (start / 4096) as usize;
    let end_page = ((end.saturating_add(4095)) / 4096) as usize;
    
    // Limit check to what the bitmap covers
    let check_end_page = end_page.min(PROTECTED_BITMAP_PAGES);
    
    if start_page < check_end_page {
        let bitmap = get_protected_bitmap().lock();
        
        // Fast path: check bytes instead of bits for most of the range
        let mut curr_page = start_page;
        
        // Align to byte boundary
        while curr_page < check_end_page && (curr_page % 8) != 0 {
            if (bitmap[curr_page / 8] & (1 << (curr_page % 8))) != 0 {
                return true;
            }
            curr_page += 1;
        }
        
        // Check whole bytes
        while curr_page + 8 <= check_end_page {
            if bitmap[curr_page / 8] != 0 {
                // There is at least one protected page in this byte
                for bit in 0..8 {
                    if (bitmap[curr_page / 8] & (1 << bit)) != 0 {
                        return true;
                    }
                }
            }
            curr_page += 8;
        }
        
        // Check remaining pages
        while curr_page < check_end_page {
            if (bitmap[curr_page / 8] & (1 << (curr_page % 8))) != 0 {
                return true;
            }
            curr_page += 1;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_dma_protection_boundary_hole() {
        let boundary = PROTECTED_BITMAP_PAGES as u64 * 4096;
        let start = boundary - 4096;
        let size = 8192;
        
        register_protected_range(start, size);
        
        let p1 = is_page_protected(start);
        let p2 = is_page_protected(boundary);
        
        unregister_protected_range(start, size);

        assert!(p1, "Page below boundary should be protected");
        assert!(p2, "Page at boundary should be protected (VULNERABILITY REPRODUCTION)");
    }
}
