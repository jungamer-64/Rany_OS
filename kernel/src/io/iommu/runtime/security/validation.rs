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

    if let Some((k_start, k_end)) = super::protection::kernel_phys_range() {
        if start < k_end && k_start < end {
            log::error!(
                "[IOMMU][SECURITY] CRITICAL: Attempt to map privileged region overlapping kernel image! range={:#x}-{:#x}, kernel={:#x}-{:#x}",
                start,
                end,
                k_start,
                k_end
            );
            return Err(IommuError::InvalidAddress);
        }
    }

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

    if let Some((kstart, kend)) = super::protection::kernel_phys_range() {
        if ranges_overlap(start, end, kstart, kend) {
            log::error!(
                "[IOMMU][SECURITY] DMA mapping overlaps kernel image (fallback): {:#x}-{:#x} vs {:#x}-{:#x}",
                start,
                end,
                kstart,
                kend
            );
            return Err(IommuError::InvalidAddress);
        }
    }

    let max_phys = crate::mm::phys::frame_allocator::pmm_managed_end().unwrap_or(0);
    if max_phys == 0 {
        // Early boot exception for common firmware low-memory reservations.
        if end <= 0x1_0000_0000 {
            log::warn!(
                "[IOMMU][SECURITY] Early boot DMA mapping allowed in low-mem: {:#x}-{:#x}",
                start,
                end
            );
            return Ok(());
        }

        log::error!("[IOMMU][SECURITY] DMA mapping attempted before RAM layout is known");
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
