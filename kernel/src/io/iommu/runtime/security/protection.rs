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
        crate::io::iommu::runtime::groups::IOMMU_GROUP_MANAGER.call_once(|| {
            crate::io::iommu::runtime::groups::IommuGroupManager::new()
        });
    }

    register_protected_region(0xFEE0_0000, 0x1000, "Local APIC");
    register_protected_region(0xFEC0_0000, 0x1000, "I/O APIC 0");
    protect_kernel_image();

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

    let phys_start = crate::mm::virt::higher_half::global_translate(kstart_virt)
        .map(|p| p.as_u64())
        .or_else(|| {
            // Fallback 1: direct-map offset based conversion when table is not ready.
            let offset = crate::mm::virt::higher_half::physical_memory_offset();
            if offset != 0 && kstart_virt.as_u64() >= offset {
                Some(kstart_virt.as_u64().saturating_sub(offset))
            } else {
                None
            }
        })
        .or_else(|| {
            // Fallback 2: Linker-script provided physical start (0x1000)
            // This is safer than allowing all DMA in early boot.
            if kstart_virt.as_u64() >= 0xffffffff80000000 {
                 Some(0x1000)
            } else {
                 None
            }
        })?;

    let last_virt =
        crate::mm::virt::higher_half::VirtAddr::new(kend_virt.as_u64().saturating_sub(1));
    let phys_last = crate::mm::virt::higher_half::global_translate(last_virt)
        .map(|p| p.as_u64())
        .or_else(|| {
            let offset = crate::mm::virt::higher_half::physical_memory_offset();
            if offset != 0 && last_virt.as_u64() >= offset {
                Some(last_virt.as_u64().saturating_sub(offset))
            } else {
                None
            }
        })
        .or_else(|| {
            // Fallback 2: Linker-script provided physical base + offset
            if last_virt.as_u64() >= 0xffffffff80000000 {
                 let k_offset = last_virt.as_u64().saturating_sub(0xffffffff80000000);
                 Some(0x1000u64.saturating_add(k_offset))
            } else {
                 None
            }
        })?;
    let phys_end = phys_last.saturating_add(1);

    if phys_end <= phys_start {
        return None;
    }
    Some((phys_start, phys_end))
}

/// Identity mapping fallback gate (default: false).
#[cfg(any(feature = "unsafe_iommu_bypass", debug_assertions))]
static UNSAFE_ALLOW_IDENTITY_MAPPING: AtomicBool = AtomicBool::new(false);

/// Global DMA mapping gate (device-scoped mappings remain allowed).
static ALLOW_GLOBAL_MAPPINGS: AtomicBool = AtomicBool::new(cfg!(debug_assertions));

/// Enable/disable identity mapping fallback.
#[cfg(any(feature = "unsafe_iommu_bypass", debug_assertions))]
pub unsafe fn set_unsafe_identity_mapping_allowed(allowed: bool) {
    if allowed {
        log::error!(
            "[IOMMU][SECURITY][CRITICAL] Identity mapping ENABLED - \
             system is VULNERABLE to DMA attacks! \
             This should NEVER be enabled in production!"
        );
        log::error!("[IOMMU][SECURITY][TAINTED] TAINTED: IOMMU BYPASS ENABLED");
        #[cfg(all(not(debug_assertions), feature = "unsafe_iommu_bypass"))]
        log::error!(
            "[IOMMU][SECURITY] You are using unsafe_iommu_bypass in a release build. \
             This feature should only be used for hardware bring-up and debugging."
        );
    } else {
        log::info!("[IOMMU][SECURITY] Identity mapping DISABLED - DMA protection restored");
    }
    UNSAFE_ALLOW_IDENTITY_MAPPING.store(allowed, Ordering::Release);
}

/// Check whether identity mapping fallback is allowed.
#[cfg(any(feature = "unsafe_iommu_bypass", debug_assertions))]
pub fn is_unsafe_identity_mapping_allowed() -> bool {
    UNSAFE_ALLOW_IDENTITY_MAPPING.load(Ordering::Acquire)
}

/// Check whether identity mapping fallback is allowed.
#[cfg(not(any(feature = "unsafe_iommu_bypass", debug_assertions)))]
#[inline(always)]
pub fn is_unsafe_identity_mapping_allowed() -> bool {
    false
}

/// Enable/disable global DMA mappings (non device-scoped).
pub fn set_global_dma_mapping_allowed(allowed: bool) {
    if allowed {
        log::warn!(
            "[IOMMU][SECURITY] Global DMA mappings ENABLED. \
             This relaxes device isolation and should not be used in production!"
        );
    } else {
        log::info!("[IOMMU][SECURITY] Global DMA mappings DISABLED.");
    }
    ALLOW_GLOBAL_MAPPINGS.store(allowed, Ordering::Release);
}

/// Check whether global DMA mappings are allowed.
pub fn is_global_dma_mapping_allowed() -> bool {
    ALLOW_GLOBAL_MAPPINGS.load(Ordering::Acquire)
}
