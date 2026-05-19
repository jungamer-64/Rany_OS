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

/// Protect BIOS/UEFI reserved memory regions from DMA access.
pub fn protect_bios_reserved_regions(boot_info: &boot_proto::ExoBootInfoView<'_>) {
    let descriptors = boot_info.memory_map();
    if descriptors.is_empty() {
        return;
    }

    let mut protected_count = 0;
    let mut protected_bytes = 0u64;

    for desc in descriptors.iter().take(2048) {
        let ty = desc.r#type;
        // SECURITY: Skip only ranges that are genuinely usable RAM for general purposes.
        // Conventional Memory (7) is free RAM.
        // Boot Services Code/Data (3, 4) are often used for early allocations and reclaimed.
        // EVERYTHING ELSE (including ACPI tables, NVS, and Reserved) MUST be protected.
        if ty == 7 || ty == 3 || ty == 4 {
            continue;
        }

        let start = desc.phys_start;
        let size = desc.page_count.saturating_mul(4096);
        if size > 0 {
            crate::security::dma::register_protected_range(start, size);
            protected_count += 1;
            protected_bytes = protected_bytes.saturating_add(size);
        }
    }

    if protected_count > 0 {
        log::info!(
            "[IOMMU][SECURITY] Protected {} BIOS/UEFI reserved regions ({} KB total)",
            protected_count,
            protected_bytes / 1024
        );
    }
}
