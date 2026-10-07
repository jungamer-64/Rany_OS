// ============================================================================
// kernel/src/boot/entry.rs
// ============================================================================
use crate::{drivers, io};
use boot_proto::ExoBootInfo;
use log::{info, warn};

// Ensure a device BAR physical range is mapped into kernel virtual space and return
// the virtual base address on success, or None on failure.
pub(super) fn ensure_phys_bar_mapped(base_phys: u64, bar_size: u64) -> Option<u64> {
    // Compute the HHDM-based virtual address for the BAR
    let base_virt =
        crate::mm::virt::mapping::phys_to_virt(x86_64::PhysAddr::new_truncate(base_phys)).as_u64();
    let virt_start = crate::mm::virt::higher_half::VirtAddr::new(base_virt);
    let phys_expected = crate::mm::virt::higher_half::PhysAddr::new(base_phys);

    // Complete translation synchronization before reporting BAR visibility.
    fn try_map_bar(base_phys: u64, base_virt: u64, bar_size: u64) -> bool {
        if bar_size == 0 {
            crate::io::log::early_print("[AHCI] BAR size 0 - skipping\n");
            return false;
        }
        let page_size: u64 = 0x1000;
        let Some(map_size) = bar_size
            .checked_add(page_size - 1)
            .map(|size| size & !(page_size - 1))
        else {
            return false;
        };

        let flags = crate::mm::virt::higher_half::PageFlags::write_combining();

        match unsafe {
            crate::mm::virt::higher_half::global_map_range(
                crate::mm::virt::higher_half::VirtAddr::new(base_virt),
                crate::mm::virt::higher_half::PhysAddr::new(base_phys),
                map_size,
                flags,
            )
        } {
            Ok(()) => {
                crate::io::log::early_print("[AHCI] mapped BAR region ");
                crate::io::log::early_print_hex(base_phys);
                crate::io::log::early_print(" -> ");
                crate::io::log::early_print_hex(base_virt);
                crate::io::log::early_print(" size=");
                crate::io::log::early_print_hex(map_size);
                crate::io::log::early_print("\n");
                true
            }
            Err(e) => {
                crate::io::log::early_print("[BAR] Failed to map BAR region ");
                crate::io::log::early_print_hex(base_phys);
                crate::io::log::early_print(" err=");
                let err_str = match e.cause {
                    crate::mm::virt::higher_half::MapError::FrameAllocation(_) => "FrameAllocation",
                    crate::mm::virt::higher_half::MapError::AlreadyMapped => "AlreadyMapped",
                    crate::mm::virt::higher_half::MapError::NotMapped => "NotMapped",
                    crate::mm::virt::higher_half::MapError::MappingChanged => "MappingChanged",
                    crate::mm::virt::higher_half::MapError::InvalidAddress => "InvalidAddress",
                    crate::mm::virt::higher_half::MapError::AlignmentError => "AlignmentError",
                    crate::mm::virt::higher_half::MapError::ParentEntryHugePage => {
                        "ParentEntryHugePage"
                    }
                    crate::mm::virt::higher_half::MapError::ParentPermissionDenied => {
                        "ParentPermissionDenied"
                    }
                    crate::mm::virt::higher_half::MapError::HardwareError => "HardwareError",
                    crate::mm::virt::higher_half::MapError::MetadataAllocation => {
                        "MetadataAllocation"
                    }
                    crate::mm::virt::higher_half::MapError::UnsupportedPageSize => {
                        "UnsupportedPageSize"
                    }
                };
                crate::io::log::early_print(err_str);
                crate::io::log::early_print("\n");
                if e.cause != crate::mm::virt::higher_half::MapError::AlreadyMapped {
                    return false;
                }
                (0..map_size).step_by(page_size as usize).all(|offset| {
                    crate::mm::virt::higher_half::global_translate(
                        crate::mm::virt::higher_half::VirtAddr::new(base_virt + offset),
                    )
                    .is_some_and(|mapped| mapped.as_u64() == base_phys + offset)
                })
            }
        }
    }

    // Check the existing page table entry
    match crate::mm::virt::higher_half::get_current_pte(virt_start) {
        Some(pte) => {
            crate::io::log::early_print("[AHCI] existing PTE present? ");
            crate::io::log::early_print_hex(if pte.is_present() { 1 } else { 0 });
            crate::io::log::early_print(" phys=");
            crate::io::log::early_print_hex(pte.phys_addr().as_u64());
            crate::io::log::early_print(" flags=");
            crate::io::log::early_print_hex(pte.flags().as_u64());
            crate::io::log::early_print("\n");

            if pte.is_present() {
                if pte.phys_addr() != phys_expected {
                    crate::io::log::early_print(
                        "[AHCI] PTE mapped to different phys - skipping init\n",
                    );
                    return None;
                }
                // Already mapped as expected
                return Some(base_virt);
            } else {
                crate::io::log::early_print("[AHCI] PTE not present - attempting to map pages\n");
                if try_map_bar(base_phys, base_virt, bar_size) {
                    return Some(base_virt);
                }
                return None;
            }
        }
        None => {
            crate::io::log::early_print("[AHCI] no PTE found - mapping pages\n");
            if try_map_bar(base_phys, base_virt, bar_size) {
                return Some(base_virt);
            }
            return None;
        }
    }
}

// Number of 4KB pages allocated for the BSP boot stack.  Historically the
// stack began at just 20 pages (~80 KiB), which proved to be far too small once
// the kernel added ACPI parsing, IOMMU setup, PCI enumeration, and other
// complex subsystems during early boot.  A 512‑KiB stack (128 pages) fixed the
// initial overflows, but as the kernel has grown additional headroom is
// required.  We now allocate 1 MiB (256 pages) to give plenty of breathing
// room for initialization and avoid hitting the guard page unexpectedly.
pub(super) const KERNEL_STACK_PAGES: usize = 256;

#[repr(C, align(4096))]
pub(super) struct KernelStack {
    _bytes: core::cell::UnsafeCell<[u8; 4096 * KERNEL_STACK_PAGES]>,
}

// SAFETY: the naked entry point claims this storage exactly once for the BSP
// before Rust code runs. It is never exposed as a Rust reference or reused by
// another CPU; all later access occurs through the active stack pointer.
unsafe impl Sync for KernelStack {}

/// Boot stack for the BSP (Bootstrap Processor).
///
/// 1 MiB (256 pages) by default.  A guard page (Present=0) is installed at the
/// bottom of this stack immediately after `heap::init()` completes (see
/// `kmain_inner`), so future overflows trigger a Page Fault instead of silent
/// corruption.  The previous 512 KiB allocation was still occasionally exhausted
/// during early boot; the larger size restores a generous margin without
/// significant memory cost.
#[unsafe(link_section = ".bss")]
pub(super) static KERNEL_STACK: KernelStack = KernelStack {
    _bytes: core::cell::UnsafeCell::new([0; 4096 * KERNEL_STACK_PAGES]),
};

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn kmain(boot_info: &'static ExoBootInfo) -> ! {
    core::arch::naked_asm!(
        "lea rsp, [rip + {stack} + {size}]",
        "jmp {enter}",
        stack = sym KERNEL_STACK,
        // `size` must match the actual byte size of `KERNEL_STACK`.
        size = const 4096 * KERNEL_STACK_PAGES,
        enter = sym enter,
    );
}

pub fn enter(boot_info: &'static ExoBootInfo) -> ! {
    super::phases::kmain_inner(boot_info)
}

/// Early serial port (COM1) initialization and boot message output.
pub(super) fn init_early_serial() {
    unsafe {
        let port = 0x3F8u16;
        core::arch::asm!("out dx, al", in("dx") port + 1, in("al") 0u8);
        core::arch::asm!("out dx, al", in("dx") port + 3, in("al") 0x80u8);
        core::arch::asm!("out dx, al", in("dx") port + 0, in("al") 0x03u8);
        core::arch::asm!("out dx, al", in("dx") port + 1, in("al") 0x00u8);
        core::arch::asm!("out dx, al", in("dx") port + 3, in("al") 0x03u8);
        core::arch::asm!("out dx, al", in("dx") port + 2, in("al") 0xC7u8);
        core::arch::asm!("out dx, al", in("dx") port + 4, in("al") 0x0Bu8);
        core::arch::asm!("out dx, al", in("dx") port, in("al") b'M');
        for byte in b"RanyOS UEFI Boot OK!\r\n" {
            core::arch::asm!("out dx, al", in("dx") port, in("al") *byte);
        }
    }
}

/// ACPI and IOMMU initialization.
fn iommu_config_from_boot_policy(
    policy: &boot_proto::BootPolicy,
) -> io::iommu::runtime::config::IommuConfig {
    io::iommu::runtime::config::IommuConfig {
        force: policy.iommu_force_enabled(),
        scalable_mode: policy.iommu_scalable_enabled(),
    }
}

pub(super) fn init_acpi_and_iommu(boot_info: &boot_proto::ExoBootInfoView<'_>) {
    let raw = boot_info.boot_info();
    if raw.rsdp_addr == 0 {
        panic!(
            "[SECURITY] IOMMU is mandatory but the bootloader did not provide an RSDP. \
             ACPI DMAR/IVRS discovery cannot continue."
        );
    }

    let catalog = crate::platform::firmware::tables().unwrap_or_else(|| {
        panic!("[SECURITY] IOMMU is mandatory but the ACPI table catalog is unavailable")
    });
    let runtime = crate::platform::firmware::initialize_runtime()
        .unwrap_or_else(|error| panic!("ACPI runtime initialization order failed: {error}"));
    info!(target: "init", "ACPI runtime state: {:?}", runtime.state());

    let iommu_config = iommu_config_from_boot_policy(&raw.boot_policy);
    init_iommu_driver(catalog, &iommu_config);
    io::iommu::api::enforce_iommu_requirement();

    debug_assert!(
        io::iommu::api::is_iommu_enabled(),
        "translated IOMMU must remain enabled after enforcement"
    );

    // Security: Protect BIOS/UEFI reserved regions from DMA.
    // This is called after IOMMU security init in init_iommu_from_acpi.
    io::iommu::runtime::security::protect_bios_reserved_regions(boot_info);

    if let Err(e) = io::iommu::runtime::panic::init_panic_dma_pool_default() {
        warn!(target: "init", "IOMMU panic DMA pool init failed: {:?}", e);
    } else {
        info!(target: "init", "IOMMU panic DMA pool initialized");
    }

    match catalog.first(drivers::acpi::TableSignature::MCFG) {
        Some(table) => info!(target: "init", "MCFG table found at {:#x}", table.physical_address()),
        None => warn!(target: "init", "No MCFG table found."),
    }

    drivers::pci::init();
    info!(target: "init", "PCI driver initialized");
    let mut devices = drivers::pci::scan_all_devices();
    if let Err(e) = io::iommu::runtime::pci::setup_iommu_for_all_pci_devices(&mut devices) {
        warn!(target: "init", "PCI IOMMU setup failed for some devices: {:?}", e);
    }
    info!(target: "init", "Early IOMMU PCI domain assignment completed");
    #[cfg(feature = "qemu-test-export")]
    {
        // full-boot test profiles prioritize deterministic runtime execution.
        // ACPI reclaim can be deferred without affecting the DriverDomain suite.
        info!(target: "init", "Skipping ACPI reclaim in qemu-test-export profile");
    }
}

#[cfg(test)]
mod iommu_policy_tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn iommu_policy_maps_force_and_scalable_flags() {
        let policy = boot_proto::BootPolicy {
            iommu_force: 1,
            iommu_scalable: 1,
            ..boot_proto::BootPolicy::default()
        };
        let config = iommu_config_from_boot_policy(&policy);
        assert!(config.force);
        assert!(config.scalable_mode);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn iommu_policy_defaults_to_translated_mode() {
        let config = iommu_config_from_boot_policy(&boot_proto::BootPolicy::default());
        assert!(!config.force);
        assert!(!config.scalable_mode);
    }
}

/// Try to register and start an IOMMU driver (Intel VT-d or AMD-Vi).
fn init_iommu_driver(
    catalog: &drivers::acpi::TableCatalog,
    iommu_config: &io::iommu::runtime::config::IommuConfig,
) {
    use crate::driver_registry::{driver_registry, register_driver};

    match catalog.first(drivers::acpi::TableSignature::DMAR) {
        Some(dmar) => {
            let drv =
                io::iommu::api::create_intel_vtd_driver(dmar.owned_bytes(), iommu_config.clone());
            match register_driver(drv) {
                Ok(handle) => {
                    info!(target: "init", "Registered Intel VT-d driver");
                    if let Err(e) = driver_registry().probe_and_start(handle) {
                        panic!(
                            "[SECURITY] Intel VT-d driver failed to start while IOMMU is mandatory: {:?}",
                            e
                        );
                    } else {
                        info!(target: "init", "Intel VT-d initialized via DriverRegistry");
                        if let Err(e) = io::iommu::api::enable_iommu() {
                            panic!(
                                "[SECURITY] Failed to enable Intel VT-d while IOMMU is mandatory: {:?}",
                                e
                            );
                        } else {
                            info!(target: "init", "IOMMU translation enabled");
                        }
                    }
                }
                Err(e) => {
                    panic!(
                        "[SECURITY] Intel VT-d driver registration failed while IOMMU is mandatory: {:?}",
                        e
                    );
                }
            }
        }
        None => match catalog.first(drivers::acpi::TableSignature::IVRS) {
            Some(ivrs) => {
                let drv =
                    io::iommu::api::create_amd_vi_driver(ivrs.owned_bytes(), iommu_config.clone());
                match register_driver(drv) {
                    Ok(handle) => {
                        info!(target: "init", "Registered AMD-Vi driver");
                        if let Err(e) = driver_registry().probe_and_start(handle) {
                            panic!(
                                "[SECURITY] AMD-Vi driver failed to start while IOMMU is mandatory: {:?}",
                                e
                            );
                        } else {
                            info!(target: "init", "AMD-Vi initialized via DriverRegistry");
                            if let Err(e) = io::iommu::api::enable_iommu() {
                                panic!(
                                    "[SECURITY] Failed to enable AMD-Vi while IOMMU is mandatory: {:?}",
                                    e
                                );
                            } else {
                                info!(target: "init", "IOMMU translation enabled");
                            }
                        }
                    }
                    Err(e) => {
                        panic!(
                            "[SECURITY] AMD-Vi driver registration failed while IOMMU is mandatory: {:?}",
                            e
                        );
                    }
                }
            }
            None => {
                panic!("[SECURITY] IOMMU is mandatory but no ACPI DMAR or IVRS table was found.");
            }
        },
    }
}
