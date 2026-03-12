// ============================================================================
// kernel/src/io/iommu/runtime/security/protection.rs
// ============================================================================

use core::sync::atomic::{AtomicBool, Ordering};

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
pub fn protect_bios_reserved_regions(boot_info: &boot_proto::ExoBootInfo) {
    let mmap = &boot_info.memory_map;
    if mmap.entries.is_null() || mmap.count == 0 {
        return;
    }

    let count = mmap.count.min(2048) as usize;
    let descriptors = unsafe { core::slice::from_raw_parts(mmap.entries, count) };

    let mut protected_count = 0;
    let mut protected_bytes = 0u64;

    for desc in descriptors {
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

/// Register the kernel image physical range as protected from DMA.
pub fn protect_kernel_image() {
    if let Some((start, end)) = kernel_phys_range() {
        crate::security::dma::register_protected_range(start, end.saturating_sub(start));
        log::info!(
            "[IOMMU][SECURITY] Protected kernel image: {:#x}-{:#x}",
            start,
            end
        );
    }
}

/// Get the physical address range of the kernel image.
#[cfg(test)]
pub(crate) fn kernel_phys_range() -> Option<(u64, u64)> {
    // Return a dummy range for unit tests to allow mapping validation to proceed
    Some((0, 0))
}

/// Get the physical address range of the kernel image.
#[cfg(not(test))]
pub(crate) fn kernel_phys_range() -> Option<(u64, u64)> {
    // The kernel is linked at virtual 0xFFFFFFFF80000000 with AT(0x1000),
    // meaning physical load address = 0x1000.  The HHDM (Higher Half Direct
    // Map) covers physical RAM at 0xFFFF800000000000+phys but the kernel
    // image is *not* part of the HHDM – it has its own separate higher-half
    // mapping.  Therefore the only lock-free and always-correct translation
    // is the linker-script formula, which we try first.
    //
    // Fallback priority:
    //   1. Linker-script AT(0x1000) formula (no locks, always correct)
    //   2. Page-table walk via global_translate (needs PAGE_TABLE_MANAGER)

    unsafe extern "C" {
        static __kernel_start: u8;
        static __kernel_end: u8;
    }

    let (kstart_virt, kend_virt) = unsafe {
        (
            crate::mm::virt::higher_half::VirtAddr::new(&__kernel_start as *const u8 as u64),
            crate::mm::virt::higher_half::VirtAddr::new(&__kernel_end as *const u8 as u64),
        )
    };
    if kend_virt.as_u64() <= kstart_virt.as_u64() {
        return None;
    }

    // --- phys_start ---
    let phys_start = linker_virt_to_phys(kstart_virt.as_u64()).or_else(|| {
        crate::mm::virt::higher_half::global_translate(kstart_virt).map(|p| p.as_u64())
    })?;

    // --- phys_end ---
    let last_virt_val = kend_virt.as_u64().saturating_sub(1);
    let last_virt = crate::mm::virt::higher_half::VirtAddr::new(last_virt_val);
    let phys_last = linker_virt_to_phys(last_virt_val).or_else(|| {
        crate::mm::virt::higher_half::global_translate(last_virt).map(|p| p.as_u64())
    })?;
    let phys_end = phys_last.saturating_add(1);

    if phys_end <= phys_start {
        return None;
    }
    Some((phys_start, phys_end))
}

/// Convert a kernel higher-half virtual address to its physical address
/// using the linker-script AT(0x1000) base.
///
/// The kernel is linked at virtual 0xFFFFFFFF80000000 with physical load
/// address 0x1000 (`.text : AT(0x1000)`).  Any virtual address in the
/// range `[0xFFFFFFFF80000000, ...)` can be converted to physical by:
///     phys = virt - 0xFFFFFFFF80000000 + 0x1000
///
/// Returns `None` if the address is outside the kernel image range.
#[inline]
fn linker_virt_to_phys(virt: u64) -> Option<u64> {
    const KERNEL_VIRT_BASE: u64 = 0xffffffff80000000;
    const KERNEL_PHYS_BASE: u64 = 0x1000;
    if virt >= KERNEL_VIRT_BASE {
        let offset = virt.wrapping_sub(KERNEL_VIRT_BASE);
        Some(KERNEL_PHYS_BASE.saturating_add(offset))
    } else {
        None
    }
}

/// Identity mapping fallback gate (default: false).
#[cfg(debug_assertions)]
static UNSAFE_ALLOW_IDENTITY_MAPPING: AtomicBool = AtomicBool::new(false);

/// Enable/disable identity mapping fallback.
#[cfg(debug_assertions)]
pub unsafe fn set_unsafe_identity_mapping_allowed(allowed: bool) {
    if allowed {
        log::error!(
            "[IOMMU][SECURITY][CRITICAL] Identity mapping ENABLED - \
             system is VULNERABLE to DMA attacks! \
             This should NEVER be enabled in production!"
        );
        log::error!("[IOMMU][SECURITY][TAINTED] TAINTED: IOMMU BYPASS ENABLED");
    } else {
        log::info!("[IOMMU][SECURITY] Identity mapping DISABLED - DMA protection restored");
    }
    UNSAFE_ALLOW_IDENTITY_MAPPING.store(allowed, Ordering::Release);
}

/// Check whether identity mapping fallback is allowed.
#[cfg(debug_assertions)]
pub fn is_unsafe_identity_mapping_allowed() -> bool {
    UNSAFE_ALLOW_IDENTITY_MAPPING.load(Ordering::Acquire)
}

/// Check whether identity mapping fallback is allowed.
#[cfg(not(debug_assertions))]
#[inline(always)]
pub fn is_unsafe_identity_mapping_allowed() -> bool {
    false
}
