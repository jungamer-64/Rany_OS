//! UEFI Runtime Services preservation
//!
//! This module collects information about UEFI Runtime Services and runtime
//! memory regions so the kernel can continue using UEFI services after
//! ExitBootServices().

use boot_proto::{
    runtime_caps, RuntimeMemoryRegion, UefiRuntimeInfo, MAX_RUNTIME_MMAP_ENTRIES,
};
use log::info;
use uefi::table::boot::{BootServices, MemoryType};
use uefi::table::{Runtime, SystemTable};

/// UEFI memory types that must remain accessible at runtime
const RUNTIME_MEMORY_TYPES: &[MemoryType] = &[
    MemoryType::RUNTIME_SERVICES_CODE,
    MemoryType::RUNTIME_SERVICES_DATA,
    MemoryType::ACPI_RECLAIM,
    MemoryType::ACPI_NON_VOLATILE,
    MemoryType::MMIO,
    MemoryType::MMIO_PORT_SPACE,
];

/// Collect UEFI Runtime Services information before ExitBootServices
///
/// # Arguments
/// * `system_table` - UEFI System Table
/// * `boot_services` - UEFI Boot Services (must be called before exit)
/// * `hhdm_offset` - Higher Half Direct Map offset for virtual address calculation
///
/// # Returns
/// UefiRuntimeInfo structure with runtime services address and memory map
pub fn collect_runtime_info(
    system_table: &SystemTable<uefi::table::Boot>,
    boot_services: &BootServices,
    hhdm_offset: u64,
) -> UefiRuntimeInfo {
    let mut runtime_info = UefiRuntimeInfo::default();

    // Get Runtime Services Table address
    // Note: We store the physical address; kernel will need to map it
    let runtime_services = system_table.runtime_services();
    runtime_info.runtime_services_addr = runtime_services as *const _ as u64;
    runtime_info.runtime_services_virt = hhdm_offset + runtime_info.runtime_services_addr;

    info!(
        "UEFI Runtime: Services table at phys 0x{:x}, virt 0x{:x}",
        runtime_info.runtime_services_addr, runtime_info.runtime_services_virt
    );

    // Determine available runtime services capabilities
    runtime_info.capabilities = detect_runtime_capabilities();

    // Collect runtime memory regions from memory map
    collect_runtime_memory_map(boot_services, &mut runtime_info, hhdm_offset);

    runtime_info
}

/// Detect which runtime services are available
fn detect_runtime_capabilities() -> u32 {
    // All standard UEFI 2.x implementations support these
    // We could probe more carefully, but these are required by spec
    runtime_caps::TIME_SERVICES
        | runtime_caps::VARIABLE_SERVICES
        | runtime_caps::RESET_SYSTEM
}

/// Collect runtime memory regions from UEFI memory map
fn collect_runtime_memory_map(
    boot_services: &BootServices,
    runtime_info: &mut UefiRuntimeInfo,
    hhdm_offset: u64,
) {
    // Get memory map
    let mmap_size = boot_services.memory_map_size().map_size + 4096;
    let mut mmap_buf = alloc::vec![0u8; mmap_size];

    let mmap = match boot_services.memory_map(&mut mmap_buf) {
        Ok(map) => map,
        Err(e) => {
            info!("UEFI Runtime: Failed to get memory map: {:?}", e);
            return;
        }
    };

    let mut count = 0usize;

    for desc in mmap.entries() {
        // Check if this is a runtime memory type
        if !is_runtime_memory_type(desc.ty) {
            continue;
        }

        if count >= MAX_RUNTIME_MMAP_ENTRIES {
            info!(
                "UEFI Runtime: WARNING - Too many runtime regions, truncated at {}",
                MAX_RUNTIME_MMAP_ENTRIES
            );
            break;
        }

        runtime_info.runtime_mmap[count] = RuntimeMemoryRegion {
            phys_addr: desc.phys_start,
            virt_addr: hhdm_offset + desc.phys_start, // Use HHDM for virtual address
            page_count: desc.page_count,
            memory_type: desc.ty.0,
            attributes: (desc.att.bits() & 0xFFFF_FFFF) as u32,
        };

        count += 1;
    }

    runtime_info.runtime_mmap_count = count as u32;

    info!(
        "UEFI Runtime: Collected {} runtime memory region(s)",
        count
    );

    // Log first few regions for debugging
    for i in 0..count.min(4) {
        let region = &runtime_info.runtime_mmap[i];
        info!(
            "  Region {}: phys 0x{:x}, {} pages, type {}",
            i, region.phys_addr, region.page_count, region.memory_type
        );
    }
}

/// Check if a memory type requires runtime preservation
fn is_runtime_memory_type(mem_type: MemoryType) -> bool {
    RUNTIME_MEMORY_TYPES.contains(&mem_type)
}

/// After ExitBootServices, update the runtime info with actual runtime table
///
/// # Safety
/// Must be called after ExitBootServices with the returned Runtime table
#[allow(dead_code)]
pub fn finalize_runtime_info(
    runtime_info: &mut UefiRuntimeInfo,
    runtime_table: &SystemTable<Runtime>,
) {
    // Update with the actual runtime services pointer
    // After ExitBootServices, the Runtime table pointer may have changed
    // Safety: We have exclusive access to the runtime table after ExitBootServices
    let rs = unsafe { runtime_table.runtime_services() };
    runtime_info.runtime_services_addr = rs as *const _ as u64;
}
