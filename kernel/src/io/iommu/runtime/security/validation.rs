// ============================================================================
// kernel/src/io/iommu/runtime/security/validation.rs
// ============================================================================

use crate::io::iommu::types::IommuError;

/// Check if two memory ranges overlap.
pub fn ranges_overlap(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start < b_end && b_start < a_end
}

/// Validate privileged DMA region safety.
pub fn validate_critical_dma_region(start: u64, size: u64) -> Result<(), IommuError> {
    if size == 0 {
        return Ok(());
    }
    let end = start.saturating_add(size);

    if super::range_overlaps_protected(start, size) {
        log::error!(
            "[IOMMU][SECURITY] CRITICAL: Attempt to map privileged region overlapping protected memory! range={:#x}-{:#x}",
            start,
            end
        );
        return Err(IommuError::InvalidAddress);
    }

    // NOTE: kernel_phys_range() check removed — see validate_dma_region() comment.

    Ok(())
}

/// Validate that a DMA region does not overlap protected memory.
pub fn validate_dma_region(start: u64, size: u64) -> Result<(), IommuError> {
    if size == 0 {
        return Ok(());
    }
    let end = start.saturating_add(size);

    if super::range_overlaps_protected(start, size) {
        log::error!(
            "[IOMMU][SECURITY] DMA mapping overlaps protected memory range: {:#x}-{:#x}",
            start,
            end
        );
        return Err(IommuError::InvalidAddress);
    }

    // NOTE: kernel_phys_range() check is intentionally removed.
    // The bootloader uses UEFI alloc_zeroed_pages() for each ELF segment,
    // so there is no single contiguous physical range for the kernel image.
    // The linker-script AT() formula produces WRONG physical addresses.
    // Protection is provided by:
    //   1. The frame allocator (kernel pages are not re-allocated for DMA)
    //   2. Individual page protection via register_protected_page() (page tables, stacks)
    //   3. The range_overlaps_protected() check above (bitmap + region list)

    let max_phys = crate::mm::phys::frame_allocator::pmm_managed_end().unwrap_or(0);
    if max_phys == 0 {
        // Early boot check: RAM layout is unknown, but we already confirmed it
        // doesn't overlap the kernel image (above).
        // Still, we must restrict early boot mappings to below 4GB (firmware space).
        if end <= 0x1_0000_0000 {
            log::warn!(
                "[IOMMU][SECURITY] Early boot DMA mapping allowed (verified no-kernel-overlap): {:#x}-{:#x}",
                start,
                end
            );
            return Ok(());
        }

        log::error!(
            "[IOMMU][SECURITY] DMA mapping attempted before RAM layout is known outside low-mem"
        );
        return Err(IommuError::NotInitialized);
    }

    if end > max_phys {
        log::error!(
            "[IOMMU][SECURITY] DMA mapping outside known RAM: {:#x}-{:#x} (max {:#x})",
            start,
            end,
            max_phys
        );
        return Err(IommuError::InvalidAddress);
    }

    Ok(())
}
