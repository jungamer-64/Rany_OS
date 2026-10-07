// ============================================================================
// kernel/src/io/iommu/runtime/security/protection.rs
// ============================================================================

/// Register a physical memory region that should be protected from DMA access.
///
/// This is used to protect MMIO regions like IOMMU registers, APIC, etc.
pub fn register_protected_region(start: u64, size: u64, name: &'static str) {
    // Delegates to security::dma which now manages the consolidated registry.
    crate::security::dma::register_protected_range(start, size);
    log::info!(
        "[IOMMU][SECURITY] Registered protected region '{}': {:#x}-{:#x}",
        name,
        start,
        start.saturating_add(size)
    );
}

/// Initialize IOMMU security subsystem with default protected regions.
pub fn init() {
    #[cfg(not(test))]
    {
        // This is required by setup_iommu_for_pci_device regardless of backend.
        crate::io::iommu::runtime::groups::IOMMU_GROUP_MANAGER
            .call_once(|| crate::io::iommu::runtime::groups::IommuGroupManager::new());
    }

    register_protected_region(0xFEE0_0000, 0x1000, "Local APIC");
    register_protected_region(0xFEC0_0000, 0x1000, "I/O APIC 0");
    // NOTE: protect_kernel_image() is intentionally NOT called here.
    // The bootloader uses UEFI alloc_zeroed_pages() to allocate kernel segment
    // pages at arbitrary physical addresses (ignoring linker AT() directives).
    // This means there is no single contiguous physical range for the kernel,
    // and the linker-script formula would produce WRONG physical addresses.
    // Kernel pages are already protected by:
    //   1. The frame allocator (kernel pages are marked as used/reserved)
    //   2. Individual page protection via register_protected_page()

    log::info!("[IOMMU][SECURITY] Security subsystem initialized");
}

/// Protect firmware-retained memory after RAM ownership has been admitted.
/// Reclaimed PMM RAM and the retained bootstrap slab are excluded by their
/// admitted ownership, independently of the firmware descriptor's type.
///
/// # Errors
/// Malformed firmware geometry or unavailable RAM admission leaves the policy
/// unpublished. The boot root must terminate before enabling device DMA.
pub(crate) fn protect_bios_reserved_regions(
    boot_info: &boot_proto::ExoBootInfoView<'_>,
    admission: crate::heap::BootRamAdmission,
) -> Result<(), crate::mm::phys::frame_allocator::FrameAllocError> {
    use crate::mm::phys::frame_allocator::{self as pmm, FrameAllocError};
    use x86_64::PhysAddr;

    let descriptors = boot_info.memory_map();
    // Validate every descriptor before publishing any firmware protection.
    let mut ranges = alloc::vec::Vec::new();
    ranges
        .try_reserve_exact(descriptors.len())
        .map_err(|_| FrameAllocError::MetadataAllocation)?;
    for desc in descriptors {
        let size = desc
            .page_count
            .checked_mul(4096)
            .ok_or(FrameAllocError::InvalidRange)?;
        if size == 0 {
            continue;
        }
        if desc.phys_start % 4096 != 0 {
            return Err(FrameAllocError::Alignment);
        }
        let start =
            PhysAddr::try_new(desc.phys_start).map_err(|_| FrameAllocError::InvalidRange)?;
        let gaps = pmm::unmanaged_physical_ranges(start, size)?;
        ranges.push(gaps);
    }

    let reclaimed = admission.bootstrap_range();
    let mut protected_count = 0usize;
    let mut protected_bytes = 0u64;
    for gaps in ranges {
        for (start, size) in gaps {
            let range = start.as_u64()..start.as_u64() + size;
            for retained in subtract_range(range, reclaimed.clone())
                .into_iter()
                .flatten()
            {
                let bytes = retained.end - retained.start;
                crate::security::dma::register_protected_range(retained.start, bytes);
                protected_count += 1;
                protected_bytes = protected_bytes.saturating_add(bytes);
            }
        }
    }
    log::info!(
        "[IOMMU][SECURITY] Protected {} firmware-retained regions ({} KB total)",
        protected_count,
        protected_bytes / 1024
    );
    Ok(())
}

fn subtract_range(
    source: core::ops::Range<u64>,
    admitted: core::ops::Range<u64>,
) -> [Option<core::ops::Range<u64>>; 2] {
    if source.end <= admitted.start || admitted.end <= source.start {
        return [Some(source), None];
    }
    [
        (source.start < admitted.start).then_some(source.start..admitted.start),
        (admitted.end < source.end).then_some(admitted.end..source.end),
    ]
}

#[cfg(test)]
mod tests {
    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn retained_firmware_preserves_both_sides_of_admitted_bootstrap_slab() {
        assert_eq!(
            super::subtract_range(0x1000..0x8000, 0x3000..0x6000),
            [Some(0x1000..0x3000), Some(0x6000..0x8000)]
        );
        assert_eq!(
            super::subtract_range(0x3000..0x6000, 0x3000..0x6000),
            [None, None]
        );
        assert_eq!(
            super::subtract_range(0x1000..0x3000, 0x3000..0x6000),
            [Some(0x1000..0x3000), None]
        );
        assert_eq!(
            super::subtract_range(0x4000..0x5000, 0x3000..0x6000),
            [None, None]
        );
    }
}
