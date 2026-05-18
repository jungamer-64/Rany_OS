//! Application Processor (AP) boot preparation
//!
//! This module allocates and prepares resources needed for AP startup:
//! - Real-mode trampoline code (must be below 1MB)
//! - Per-AP stacks
//! - AP boot information structure

use ap_trampoline::{TRAMPOLINE_SIZE, TrampolinePageMut, TrampolinePhysAddr};
use boot_proto::{ApBootInfo, ApBootLayout};
use log::info;
use uefi::Identify;
use uefi::boot::{self, AllocateType, SearchType};
use uefi::mem::memory_map::MemoryType;
use uefi::proto::pi::mp::MpServices;

/// Size of AP trampoline code region (4KB aligned)
pub const AP_TRAMPOLINE_SIZE: usize = TRAMPOLINE_SIZE;

/// Size of each AP's stack (64KB)
pub const AP_STACK_SIZE: usize = 64 * 1024;

/// Maximum number of APs to support
pub const MAX_AP_COUNT: usize = 255;

/// Preferred address for trampoline (below 1MB, 4KB aligned)
/// Using 0x8000 which is typically safe in real mode
pub const TRAMPOLINE_PREFERRED_ADDR: u64 = 0x8000;

/// Prepare AP boot resources
///
/// This function:
/// 1. Counts available CPUs via UEFI MP Services Protocol
/// 2. Allocates real-mode trampoline region below 1MB
/// 3. Pre-allocates stacks for all APs
///
/// # Arguments
/// * `cpu_count` - Total number of CPUs (BSP + APs), or 0 to detect via MP protocol
///
/// # Returns
/// ApBootInfo structure with allocated resources
pub fn prepare_ap_boot(cpu_count: u32) -> ApBootInfo {
    let ap_count = if cpu_count > 1 {
        cpu_count - 1 // Subtract BSP
    } else {
        // If cpu_count is 0 or 1, try to detect via MP Services Protocol
        detect_cpu_count().saturating_sub(1)
    };

    if ap_count == 0 {
        info!("AP Boot: No APs detected (single-core system)");
        return ApBootInfo::default();
    }

    info!("AP Boot: Preparing resources for {} AP(s)", ap_count);

    // Allocate trampoline region below 1MB
    let Some(trampoline_addr) = allocate_trampoline() else {
        info!("AP Boot: WARNING - Failed to allocate trampoline region");
        return ApBootInfo::default();
    };
    if !install_trampoline(trampoline_addr) {
        info!("AP Boot: WARNING - Failed to populate trampoline region");
        return ApBootInfo::default();
    }

    // Allocate stacks for APs
    let (stack_base, stack_count) = allocate_ap_stacks(ap_count as usize);

    let ap_boot_info = build_ap_boot_info(
        ap_count,
        Some(trampoline_addr),
        stack_base,
        stack_count,
        true,
    );

    info!(
        "AP Boot: Trampoline at 0x{:x}, {} stacks at 0x{:x}",
        trampoline_addr.as_u64(),
        stack_count,
        stack_base
    );

    ap_boot_info
}

/// Detect CPU count using UEFI MP Services Protocol
fn detect_cpu_count() -> u32 {
    // Try to find MP Services Protocol
    // Note: This protocol may not be available on all systems

    // First try to find handles that support the protocol
    match boot::locate_handle_buffer(SearchType::ByProtocol(&MpServices::GUID)) {
        Ok(handles) => {
            if let Some(&handle) = handles.first() {
                match boot::open_protocol_exclusive::<MpServices>(handle) {
                    Ok(mp_protocol) => match mp_protocol.get_number_of_processors() {
                        Ok(processor_count) => {
                            let total = processor_count.total;
                            info!("AP Boot: MP Protocol reports {} processor(s)", total);
                            return total as u32;
                        }
                        Err(e) => {
                            info!("AP Boot: MP Protocol query failed: {:?}", e);
                        }
                    },
                    Err(e) => {
                        info!("AP Boot: Failed to open MP Services: {:?}", e);
                    }
                }
            }
        }
        Err(_) => {
            info!("AP Boot: MP Services Protocol not available");
        }
    }

    1 // Assume single processor
}

fn build_ap_boot_info(
    ap_count: u32,
    trampoline_addr: Option<TrampolinePhysAddr>,
    stack_base: u64,
    stack_count: usize,
    trampoline_ready: bool,
) -> ApBootInfo {
    let Some(trampoline_addr) = trampoline_addr else {
        return ApBootInfo::default();
    };

    if ap_count == 0
        || stack_base == 0
        || stack_count == 0
        || stack_count < ap_count as usize
        || !trampoline_ready
    {
        return ApBootInfo::default();
    }

    ApBootLayout::new(
        ap_count.min(u16::MAX as u32) as u16,
        stack_count.min(u16::MAX as usize) as u16,
        trampoline_addr,
        AP_TRAMPOLINE_SIZE as u64,
        stack_base,
        AP_STACK_SIZE as u64,
    )
    .map(ApBootLayout::into_boot_info)
    .unwrap_or_default()
}

fn install_trampoline(trampoline_addr: TrampolinePhysAddr) -> bool {
    let install_result =
        unsafe { TrampolinePageMut::from_raw_ptr(trampoline_addr.as_u64() as *mut u8) }
            .and_then(|mut page| page.install(trampoline_addr));

    if let Err(error) = install_result {
        info!("AP Boot: Failed to patch trampoline image: {}", error);
        return false;
    }

    true
}

/// Allocate real-mode trampoline region below 1MB
fn allocate_trampoline() -> Option<TrampolinePhysAddr> {
    // Try to allocate at preferred address first
    match boot::allocate_pages(
        AllocateType::Address(TRAMPOLINE_PREFERRED_ADDR),
        MemoryType::LOADER_DATA,
        (AP_TRAMPOLINE_SIZE + 4095) / 4096,
    ) {
        Ok(ptr) => {
            let addr = ptr.as_ptr() as u64;
            match TrampolinePhysAddr::new(addr) {
                Ok(addr) => {
                    info!(
                        "AP Boot: Trampoline allocated at preferred address 0x{:x}",
                        addr.as_u64()
                    );
                    return Some(addr);
                }
                Err(error) => {
                    info!(
                        "AP Boot: Preferred trampoline allocation at 0x{:x} is invalid: {}",
                        addr, error
                    );
                }
            }
        }
        Err(_) => {
            // Preferred address not available, try MaxAddress allocation
        }
    }

    // Fallback: allocate anywhere below 1MB
    match boot::allocate_pages(
        AllocateType::MaxAddress(0x100000), // Below 1MB
        MemoryType::LOADER_DATA,
        (AP_TRAMPOLINE_SIZE + 4095) / 4096,
    ) {
        Ok(ptr) => {
            let addr = ptr.as_ptr() as u64;
            match TrampolinePhysAddr::new(addr) {
                Ok(addr) => {
                    info!(
                        "AP Boot: Trampoline allocated at fallback address 0x{:x}",
                        addr.as_u64()
                    );
                    Some(addr)
                }
                Err(error) => {
                    info!(
                        "AP Boot: Fallback trampoline allocation at 0x{:x} is invalid: {}",
                        addr, error
                    );
                    None
                }
            }
        }
        Err(e) => {
            info!("AP Boot: Failed to allocate trampoline: {:?}", e);
            None
        }
    }
}

/// Allocate stacks for Application Processors
fn allocate_ap_stacks(ap_count: usize) -> (u64, usize) {
    let stack_count = ap_count.min(MAX_AP_COUNT);
    let total_size = stack_count * AP_STACK_SIZE;
    let page_count = (total_size + 4095) / 4096;

    match boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, page_count) {
        Ok(ptr) => {
            let addr = ptr.as_ptr() as u64;
            info!(
                "AP Boot: Allocated {} stacks ({} pages) at 0x{:x}",
                stack_count, page_count, addr
            );

            // Zero-initialize stacks
            unsafe {
                core::ptr::write_bytes(addr as *mut u8, 0, total_size);
            }

            (addr, stack_count)
        }
        Err(e) => {
            info!("AP Boot: Failed to allocate stacks: {:?}", e);
            (0, 0)
        }
    }
}

/// Get the stack pointer for a specific AP
///
/// # Arguments
/// * `ap_boot_info` - AP boot information structure
/// * `ap_index` - Zero-based AP index (0 = first AP, not BSP)
///
/// # Returns
/// Stack pointer (top of stack) for the AP, or 0 if invalid
pub fn get_ap_stack_pointer(ap_boot_info: &ApBootInfo, ap_index: usize) -> u64 {
    ap_boot_info.stack_top_for(ap_index).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ap_trampoline::{ApBootFlags, LAYOUT_VERSION, MAILBOX_OFFSET};

    #[test]
    fn build_ap_boot_info_sets_shared_trampoline_metadata() {
        let info = build_ap_boot_info(
            4,
            Some(TrampolinePhysAddr::new(0x8000).unwrap()),
            0x20_0000,
            4,
            true,
        );

        assert_eq!(info.ap_count, 4);
        assert_eq!(info.stack_count, 4);
        assert_eq!(info.flags, ApBootFlags::TRAMPOLINE_READY);
        assert_eq!(info.trampoline_layout_version, LAYOUT_VERSION);
        assert_eq!(info.trampoline_mailbox_offset, MAILBOX_OFFSET as u32);
        assert_eq!(info.trampoline_addr, 0x8000);
        assert_eq!(info.trampoline_size, AP_TRAMPOLINE_SIZE as u64);
        assert_eq!(info.stack_base, 0x20_0000);
        assert_eq!(info.stack_size, AP_STACK_SIZE as u64);
        assert_eq!(info.layout().unwrap().stack_top_for(3), Some(0x24_0000));
    }

    #[test]
    fn build_ap_boot_info_falls_back_to_default_when_trampoline_is_not_ready() {
        let info = build_ap_boot_info(
            2,
            Some(TrampolinePhysAddr::new(0x8000).unwrap()),
            0x20_0000,
            2,
            false,
        );

        assert_eq!(info, ApBootInfo::default());
    }

    #[test]
    fn build_ap_boot_info_falls_back_to_default_when_stack_count_is_short() {
        let info = build_ap_boot_info(
            4,
            Some(TrampolinePhysAddr::new(0x8000).unwrap()),
            0x20_0000,
            3,
            true,
        );

        assert_eq!(info, ApBootInfo::default());
    }
}
