// ============================================================================
// kernel/src/kernel_content.rs
// ============================================================================
extern crate alloc;

// use alloc::string::String;
// use core::panic::PanicInfo;
use boot_proto::{EXO_BOOT_INFO_VERSION, ExoBootInfo};

use log::{info, warn};

mod crypto;
mod debug;
mod domain;
mod domain_system;
mod durability;
mod error;
#[path = "../../filesystems/kernel_fs/mod.rs"]
mod fs;
mod async_boot_runtime_snapshot;
mod kernel_main;
pub use kernel_main::*;
#[macro_use]
mod interrupt_macros;
// ============================================================================
// Macro Re-exports (from drivers)
// ============================================================================

mod driver_domain;
pub mod drivers;
mod graphics;
pub mod interrupts;
pub mod io;
mod ipc;
mod loader;
mod memory;
mod mm;
mod net;
mod panic_handler;
mod platform;
mod power;
mod provider_registry;
#[cfg(feature = "qemu-test-export")]
mod qemu_tests;
mod sas;
mod security;
mod shell;
mod smp;
// spectre は security/spectre.rs に移動済み。security::spectre として参照する。
mod per_cpu;
mod sync;
mod task;
mod time;
mod unwind;
mod util;
// vga は graphics/vga.rs に移動済み。graphics::vga として参照する。

// Phase 4: High-Performance & Advanced Features
mod console;
mod cpu;
mod diag;
mod system_info;

// Phase 5: Extended Features & System Integration
// gpu は io/ 配下に移動済み (io::gpu)
mod profiler;
mod runtime_bridge;
mod thermal;
mod watchdog;

// Phase 6: Testing, Demos & System Monitor
mod monitor;
mod test;

// Phase 7: System Integration & Application Support
mod application;
mod benchmark;
mod driver_registry;
// boot artifact loader は loader/boot_artifacts.rs に配置される。
mod integration; // 旧称: userspace → SPL単一特権レベルを反映
mod service_impl; // KernelServices implementation // Driver lifecycle management

#[allow(dead_code)]
fn debug_heap_check(tag: &str) {
    io::log::early_print("[HEAP] Check: ");
    io::log::early_print(tag);
    io::log::early_print("\n");

    // Simple allocation test
    let mut v = alloc::vec::Vec::new();
    for i in 0..100 {
        v.push(i as u64);
    }
    drop(v);

    // Large allocation test
    let b = alloc::boxed::Box::new([0u8; 1024]);
    core::hint::black_box(&b);
    drop(b);

    io::log::early_print("[HEAP] Check OK\n");
}

// Ensure a device BAR physical range is mapped into kernel virtual space and return
// the virtual base address on success, or None on failure.
fn ensure_phys_bar_mapped(base_phys: u64, bar_size: u64) -> Option<u64> {
    // Compute the HHDM-based virtual address for the BAR
    let base_virt = memory::phys_to_virt(x86_64::PhysAddr::new_truncate(base_phys)).as_u64();
    let virt_start = crate::mm::virt::higher_half::VirtAddr::new(base_virt);
    let phys_expected = crate::mm::virt::higher_half::PhysAddr::new(base_phys);

    // Helper to map the BAR region using a local PageTableManager
    fn try_map_bar(base_phys: u64, base_virt: u64, bar_size: u64) -> bool {
        if bar_size == 0 {
            crate::io::log::early_print("[AHCI] BAR size 0 - skipping\n");
            return false;
        }
        let page_size: u64 = 0x1000;
        let map_size = ((bar_size + page_size - 1) / page_size) * page_size;

        let pm_offset = crate::mm::virt::higher_half::physical_memory_offset();
        let mut manager =
            unsafe { crate::mm::virt::higher_half::PageTableManager::from_current_cr3(pm_offset) };
        let flags = crate::mm::virt::higher_half::PageFlags::write_combining();

        match unsafe {
            manager.map_range(
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
                let err_str = match e {
                    crate::mm::virt::higher_half::MapError::FrameAllocationFailed => {
                        "FrameAllocationFailed"
                    }
                    crate::mm::virt::higher_half::MapError::AlreadyMapped => "AlreadyMapped",
                    crate::mm::virt::higher_half::MapError::NotMapped => "NotMapped",
                    crate::mm::virt::higher_half::MapError::InvalidAddress => "InvalidAddress",
                    crate::mm::virt::higher_half::MapError::AlignmentError => "AlignmentError",
                    crate::mm::virt::higher_half::MapError::ParentEntryHugePage => {
                        "ParentEntryHugePage"
                    }
                    crate::mm::virt::higher_half::MapError::HardwareError => "HardwareError",
                };
                crate::io::log::early_print(err_str);
                crate::io::log::early_print("\n");
                matches!(e, crate::mm::virt::higher_half::MapError::AlreadyMapped)
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
const KERNEL_STACK_PAGES: usize = 256;

#[cfg(not(test))]
#[repr(align(4096))]
#[allow(dead_code)]
struct KernelStack([u8; 4096 * KERNEL_STACK_PAGES]);

/// Boot stack for the BSP (Bootstrap Processor).
///
/// 1 MiB (256 pages) by default.  A guard page (Present=0) is installed at the
/// bottom of this stack immediately after `memory::init()` completes (see
/// `kmain_inner`), so future overflows trigger a Page Fault instead of silent
/// corruption.  The previous 512 KiB allocation was still occasionally exhausted
/// during early boot; the larger size restores a generous margin without
/// significant memory cost.
#[unsafe(link_section = ".bss")]
static mut KERNEL_STACK: KernelStack = KernelStack([0; 4096 * KERNEL_STACK_PAGES]);

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn kmain(boot_info: &'static ExoBootInfo) -> ! {
    core::arch::naked_asm!(
        "lea rsp, [rip + {stack} + {size}]",
        "jmp {kmain_inner}",
        stack = sym KERNEL_STACK,
        // `size` must match the actual byte size of `KERNEL_STACK`.
        size = const 4096 * KERNEL_STACK_PAGES,
        kmain_inner = sym kmain_inner,
    );
}

/// Early serial port (COM1) initialization and boot message output.
fn init_early_serial() {
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

/// Enable SSE/SSE2 (required by x86_64 ABI).
fn init_sse() {
    io::log::early_print("[BOOT] Enabling SSE...\n");
    unsafe {
        use core::arch::asm;
        let mut cr0: u64;
        asm!("mov {}, cr0", out(reg) cr0);
        cr0 &= !(1 << 2); // EM=0
        cr0 &= !(1 << 3); // TS=0
        asm!("mov cr0, {}", in(reg) cr0);

        let mut cr4: u64;
        asm!("mov {}, cr4", out(reg) cr4);
        cr4 |= 1 << 9; // OSFXSR
        cr4 |= 1 << 10; // OSXMMEXCPT
        asm!("mov cr4, {}", in(reg) cr4);
    }
    io::log::early_print("[BOOT] SSE enabled\n");
}

/// Detect and enable AVX/AVX2 if the CPU supports them.
fn init_avx() {
    unsafe {
        use core::arch::x86_64::{__cpuid, __cpuid_count};

        let res = __cpuid(1);
        let has_avx = (res.ecx & (1 << 28)) != 0;
        let has_osxsave = (res.ecx & (1 << 27)) != 0;

        if has_avx && has_osxsave {
            io::log::early_print("[BOOT] Enabling AVX...\n");

            let mut cr4: u64;
            core::arch::asm!("mov {}, cr4", out(reg) cr4);
            cr4 |= 1 << 18;
            core::arch::asm!("mov cr4, {}", in(reg) cr4);

            let xcr0_low: u32;
            let xcr0_high: u32;
            core::arch::asm!(
                "xgetbv",
                in("ecx") 0,
                out("eax") xcr0_low,
                out("edx") xcr0_high,
            );

            let new_xcr0_low = xcr0_low | 6;
            core::arch::asm!(
                "xsetbv",
                in("ecx") 0,
                in("eax") new_xcr0_low,
                in("edx") xcr0_high,
            );

            io::log::early_print("[BOOT] AVX enabled (XCR0 set)\n");
            hal::mmio::set_simd_level(hal::mmio::simd_level::AVX);

            let res7 = __cpuid_count(7, 0);
            if (res7.ebx & (1 << 5)) != 0 {
                io::log::early_print("[BOOT] AVX2 detected\n");
                hal::mmio::set_simd_level(hal::mmio::simd_level::AVX2);
            }
        } else {
            io::log::early_print("[BOOT] AVX not supported\n");
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

fn init_acpi_and_iommu(boot_info: &boot_proto::ExoBootInfoView<'_>) {
    let raw = boot_info.boot_info();
    if raw.rsdp_addr == 0 {
        panic!(
            "[SECURITY] IOMMU is mandatory but the bootloader did not provide an RSDP. \
             ACPI DMAR/IVRS discovery cannot continue."
        );
    }

    let rsdp_addr = raw.rsdp_addr as usize;
    let parser = match unsafe { drivers::acpi::init(rsdp_addr as u64) } {
        Ok(p) => p,
        Err(e) => {
            panic!(
                "[SECURITY] IOMMU is mandatory but ACPI initialization failed: {:?}",
                e
            );
        }
    };
    info!(target: "init", "ACPI initialized via RSDP at {:#x}", rsdp_addr);

    let iommu_config = iommu_config_from_boot_policy(&raw.boot_policy);
    init_iommu_driver(&parser, &iommu_config);
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

    match parser.find_table(b"MCFG") {
        Ok(addr) => info!(target: "init", "MCFG table found at {:#x}", addr),
        Err(_) => warn!(target: "init", "No MCFG table found."),
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
    #[cfg(not(feature = "qemu-test-export"))]
    {
        memory::reclaim_acpi_reclaimable(boot_info);
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
    parser: &io::acpi::AcpiParser,
    iommu_config: &io::iommu::runtime::config::IommuConfig,
) {
    use crate::driver_registry::{driver_registry, register_driver};

    match parser.find_table(b"DMAR") {
        Ok(dmar_addr) => {
            let drv = io::iommu::api::create_intel_vtd_driver(dmar_addr, iommu_config.clone());
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
        Err(_) => match parser.find_table(b"IVRS") {
            Ok(ivrs_addr) => {
                let drv = io::iommu::api::create_amd_vi_driver(ivrs_addr, iommu_config.clone());
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
            Err(_) => {
                panic!("[SECURITY] IOMMU is mandatory but no ACPI DMAR or IVRS table was found.");
            }
        },
    }
}

/// Scan PCI bus for NVMe controllers and initialize them.
fn init_nvme_controllers() {
    io::log::early_print("[DEBUG] NVMe scan STARTING\n");
    info!(target: "init", "Scanning for NVMe controllers...");

    let mut nvme_controller_id: u8 = 0;
    let nvme_devices = crate::platform::pci::find_by_class(0x01, 0x08);
    for dev in nvme_devices {
        info!(target: "init", "NVMe controller found at {}", dev.bdf);
        dev.enable_bus_master();
        dev.enable_memory_space();

        let iommu_device = crate::io::iommu::types::DeviceId::new(
            dev.segment,
            dev.bdf.bus(),
            dev.bdf.device(),
            dev.bdf.function(),
        );
        crate::drivers::nvme::set_iommu_device(iommu_device);

        if crate::drivers::nvme::with_driver(|_| ()).is_some() {
            info!(target: "init", "NVMe driver already initialized, skipping");
            continue;
        }

        init_single_nvme_controller(&dev, nvme_controller_id);
        nvme_controller_id = nvme_controller_id.wrapping_add(1);
    }
}

/// Initialize a single NVMe controller from a PCI device.
fn init_single_nvme_controller(
    dev: &kernel_api::service::platform::PciDeviceInfo,
    nvme_controller_id: u8,
) {
    let bar0 = match dev.bars[0] {
        Some(b) => b,
        None => {
            warn!(target: "init", "NVMe controller found but BAR0 is missing");
            return;
        }
    };

    let bar0_virt = match ensure_phys_bar_mapped(bar0.base(), bar0.size()) {
        Some(v) => v,
        None => {
            warn!(target: "init", "NVMe controller BAR0 mapping failed - skipping init");
            return;
        }
    };

    let mut standalone_ctx = kernel_api::abi::driver::DriverContext::for_pci(
        bar0_virt,
        dev.interrupt_line as u32,
        dev.vendor_id.0,
        dev.device_id.0,
        ((dev.class_code.class as u32) << 16)
            | ((dev.class_code.subclass as u32) << 8)
            | dev.class_code.prog_if as u32,
        dev.packed_locator(),
    );
    standalone_ctx.device_address_secondary = 0;
    match crate::loader::staged_pci::try_start_for_device(dev, standalone_ctx) {
        crate::loader::staged_pci::StagedPciBindOutcome::Started { .. }
        | crate::loader::staged_pci::StagedPciBindOutcome::AlreadyBound => {
            info!(target: "init", "NVMe controller initialized via staged standalone driver");
            return;
        }
        crate::loader::staged_pci::StagedPciBindOutcome::Failed(reason) => {
            warn!(target: "init", "{}; falling back to built-in NVMe path", reason);
        }
        crate::loader::staged_pci::StagedPciBindOutcome::NoMatch => {}
    }

    let num_cores = crate::cpu::count() as u32;
    let packed_device_id = dev.packed_locator();
    match crate::drivers::nvme::init_nvme_polling(bar0_virt, num_cores, packed_device_id) {
        Ok(()) => {
            info!(target: "init", "NVMe driver initialized (polling)");
            if let Err(e) =
                crate::drivers::nvme::register_with_io_scheduler(nvme_controller_id, 1, num_cores)
            {
                warn!(target: "init", "NVMe IoScheduler registration failed: {}", e);
            }
            crate::io::log::early_print("[HEAP_CHECK] after NVMe controller init\n");
            crate::memory::verify_buddy_integrity();
        }
        Err(e) => warn!(target: "init", "NVMe driver init failed: {}", e),
    }
}

/// Scan PCI bus for AHCI controllers and initialize them.
fn init_ahci_controllers() {
    info!(target: "init", "Scanning for AHCI controllers...");

    let ahci_devices = crate::platform::pci::find_by_class(0x01, 0x06);
    for dev in ahci_devices {
        info!(target: "init", "AHCI controller found at {}", dev.bdf);
        dev.enable_bus_master();
        dev.enable_memory_space();
        init_single_ahci_controller(&dev);
    }
}

/// Initialize a single AHCI controller from its BAR5 address.
fn init_single_ahci_controller(dev: &kernel_api::service::platform::PciDeviceInfo) {
    let bar5 = match dev.bars[5] {
        Some(b) => b,
        None => {
            warn!(target: "init", "AHCI controller found but BAR5 is missing");
            return;
        }
    };

    let base_phys = bar5.base();
    let bar_size = bar5.size();
    let base_virt = memory::phys_to_virt(x86_64::PhysAddr::new_truncate(base_phys)).as_u64();

    crate::io::log::early_print("[AHCI] BAR5 phys=");
    crate::io::log::early_print_hex(base_phys);
    crate::io::log::early_print(" size=");
    crate::io::log::early_print_hex(bar_size);
    crate::io::log::early_print(" base_virt=");
    crate::io::log::early_print_hex(base_virt);
    crate::io::log::early_print("\n");

    let virt_start = crate::mm::virt::higher_half::VirtAddr::new(base_virt);
    let phys_expected = crate::mm::virt::higher_half::PhysAddr::new(base_phys);

    let mapping_ok = ahci_ensure_mapping(virt_start, phys_expected, base_phys, base_virt, bar_size);

    if !mapping_ok {
        warn!(target: "init", "AHCI controller mapping failed or mismatched - skipping init");
        return;
    }

    // Diagnostic PTE log
    if let Some(pte) = crate::mm::virt::higher_half::get_current_pte(
        crate::mm::virt::higher_half::VirtAddr::new(base_virt),
    ) {
        crate::io::log::early_print("[AHCI] PTE: present=");
        crate::io::log::early_print_hex(if pte.is_present() { 1 } else { 0 });
        crate::io::log::early_print(" phys=");
        crate::io::log::early_print_hex(pte.phys_addr().as_u64());
        crate::io::log::early_print(" flags=");
        crate::io::log::early_print_hex(pte.flags().as_u64());
        crate::io::log::early_print("\n");
    } else {
        crate::io::log::early_print("[AHCI] PTE: not present in page tables\n");
    }

    let iommu_device = crate::io::iommu::types::DeviceId::new(
        dev.segment,
        dev.bdf.bus(),
        dev.bdf.device(),
        dev.bdf.function(),
    );

    let mut standalone_ctx = kernel_api::abi::driver::DriverContext::for_pci(
        base_virt,
        dev.interrupt_line as u32,
        dev.vendor_id.0,
        dev.device_id.0,
        ((dev.class_code.class as u32) << 16)
            | ((dev.class_code.subclass as u32) << 8)
            | dev.class_code.prog_if as u32,
        dev.packed_locator(),
    );
    standalone_ctx.device_address_secondary = 0;
    match crate::loader::staged_pci::try_start_for_device(dev, standalone_ctx) {
        crate::loader::staged_pci::StagedPciBindOutcome::Started { .. }
        | crate::loader::staged_pci::StagedPciBindOutcome::AlreadyBound => {
            info!(target: "init", "AHCI controller initialized via staged standalone driver");
            return;
        }
        crate::loader::staged_pci::StagedPciBindOutcome::Failed(reason) => {
            warn!(target: "init", "{}; falling back to built-in AHCI path", reason);
        }
        crate::loader::staged_pci::StagedPciBindOutcome::NoMatch => {}
    }

    match crate::drivers::ahci::init_from_pci(base_virt, iommu_device) {
        Ok(controller) => {
            info!(target: "init", "AHCI controller initialized");
            let first_port = controller
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get_port_start_index()
                .unwrap_or(0) as u8;
            crate::drivers::ahci::register_ahci_with_io_scheduler(controller.clone(), first_port);
            crate::memory::verify_buddy_integrity();
        }
        Err(e) => warn!(target: "init", "AHCI init failed: {:?}", e),
    }
}
