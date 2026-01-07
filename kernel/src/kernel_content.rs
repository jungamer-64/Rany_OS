// ============================================================================
// kernel/src/kernel_content.rs
// ============================================================================
extern crate alloc;

// use alloc::string::String;
// use core::panic::PanicInfo;
use boot_proto::ExoBootInfo;

use log::{debug, error, info, warn};

mod allocator;

mod domain;
mod domain_system;
mod epoch;
mod error;
mod fs;
#[macro_use]
mod interrupt_macros;
// ============================================================================
// Macro Re-exports (from drivers)
// ============================================================================
#[deprecated(
    note = "serial_print is deprecated; prefer `crate::io::log::early_print` or the kernel logging APIs (e.g., `log::info!`)."
)]
#[allow(deprecated)]
pub use serial_driver::serial_print;
#[deprecated(
    note = "serial_println is deprecated; prefer `crate::io::log::early_print` or the kernel logging APIs (e.g., `log::info!`)."
)]
#[allow(deprecated)]
pub use serial_driver::serial_println;

mod graphics;
pub mod interrupts;
pub mod io;
mod ipc;
mod loader;
mod memory;
mod mm;
mod net;
mod panic_handler;
mod power;
mod sas;
mod security;
mod shell;
mod smp;
mod spectre;
mod sync;
mod task;
mod time;
mod unwind;
mod util;
mod vga;

// Phase 4: High-Performance & Advanced Features
mod console;
mod diag;
mod smp_advanced;

// Phase 5: Extended Features & System Integration
mod gpu;
mod profiler;
mod thermal;
mod watchdog;

// Phase 6: Testing, Demos & System Monitor
mod demo;
mod monitor;
mod test;

// Phase 7: System Integration & Application Support
mod application;
mod benchmark;
mod driver_registry;
mod initramfs; // Dynamic Cell loading from TAR archive
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

#[cfg(not(test))]
#[unsafe(no_mangle)]
extern "C" fn kmain(boot_info: &'static ExoBootInfo) -> ! {
    // Early serial output to confirm kernel loaded
    unsafe {
        // Initialize COM1 (0x3F8)
        let port = 0x3F8u16;
        core::arch::asm!(
            "out dx, al",
            in("dx") port + 1,
            in("al") 0u8,  // Disable interrupts
        );
        core::arch::asm!(
            "out dx, al",
            in("dx") port + 3,
            in("al") 0x80u8,  // DLAB on
        );
        core::arch::asm!(
            "out dx, al",
            in("dx") port + 0,
            in("al") 0x03u8,  // Divisor low
        );
        core::arch::asm!(
            "out dx, al",
            in("dx") port + 1,
            in("al") 0x00u8,  // Divisor high
        );
        core::arch::asm!(
            "out dx, al",
            in("dx") port + 3,
            in("al") 0x03u8,  // 8N1
        );
        core::arch::asm!(
            "out dx, al",
            in("dx") port + 2,
            in("al") 0xC7u8,  // FIFO
        );
        core::arch::asm!(
            "out dx, al",
            in("dx") port + 4,
            in("al") 0x0Bu8,  // RTS/DSR
        );

        // Output 'M' to serial to confirm we reached this point in kmain
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") b'M',
        );

        // Send boot message
        for byte in b"RanyOS UEFI Boot OK!\r\n" {
            core::arch::asm!(
                "out dx, al",
                in("dx") port,
                in("al") *byte,
            );
        }
    }

    // Removed local `serial_print` helper in favor of `io::log::early_print` for early boot messages.
    // Use `log` macros (e.g., `info!`, `debug!`) after the logger has been initialized.

    // Limine protocol check removed.
    // Verify ExoBootInfo version if necessary.
    io::log::early_print("[BOOT] Booted via ExoLoader!\n");
    if boot_info.version != 1 {
        io::log::early_print("[BOOT] WARNING: Protocol version mismatch\n");
    }

    // SSE/SSE2を有効化（x86_64ではABIで必須）
    io::log::early_print("[BOOT] Enabling SSE...\n");
    unsafe {
        use core::arch::asm;
        // CR0: EM=0, TS=0
        let mut cr0: u64;
        asm!("mov {}, cr0", out(reg) cr0);
        cr0 &= !(1 << 2); // EM=0
        cr0 &= !(1 << 3); // TS=0
        asm!("mov cr0, {}", in(reg) cr0);

        // CR4: OSFXSR=1, OSXMMEXCPT=1
        let mut cr4: u64;
        asm!("mov {}, cr4", out(reg) cr4);
        cr4 |= 1 << 9; // OSFXSR
        cr4 |= 1 << 10; // OSXMMEXCPT  
        asm!("mov cr4, {}", in(reg) cr4);
    }
    io::log::early_print("[BOOT] SSE enabled\n");

    // Enable AVX/AVX2 if available
    unsafe {
        use core::arch::x86_64::{__cpuid, __cpuid_count};

        // 1. Check AVX support (CPUID.1:ECX.AVX[bit 28])
        let res = __cpuid(1);
        let has_avx = (res.ecx & (1 << 28)) != 0;
        let has_osxsave = (res.ecx & (1 << 27)) != 0; // OSXSAVE support

        if has_avx && has_osxsave {
            io::log::early_print("[BOOT] Enabling AVX...\n");

            // 2. Enable OSXSAVE in CR4 (bit 18)
            let mut cr4: u64;
            core::arch::asm!("mov {}, cr4", out(reg) cr4);
            cr4 |= 1 << 18;
            core::arch::asm!("mov cr4, {}", in(reg) cr4);

            // 3. Enable YMM state in XCR0 (bits 2)
            // XCR0 bits: 0=x87, 1=SSE, 2=AVX
            // We need to set bit 2. Bit 0 and 1 must be set.
            let xcr0_low: u32;
            let xcr0_high: u32;

            // XGETBV (ecx=0)
            core::arch::asm!(
                "xgetbv",
                in("ecx") 0,
                out("eax") xcr0_low,
                out("edx") xcr0_high,
            );

            let new_xcr0_low = xcr0_low | 6; // Set bit 1 (SSE) and 2 (AVX)

            // XSETBV (ecx=0)
            core::arch::asm!(
                "xsetbv",
                in("ecx") 0,
                in("eax") new_xcr0_low,
                in("edx") xcr0_high,
            );

            io::log::early_print("[BOOT] AVX enabled (XCR0 set)\n");

            // 4. Notify HAL
            hal::mmio::set_simd_level(hal::mmio::simd_level::AVX);

            // 5. Check AVX2 (CPUID.7:EBX.AVX2[bit 5])
            let res7 = __cpuid_count(7, 0);
            if (res7.ebx & (1 << 5)) != 0 {
                io::log::early_print("[BOOT] AVX2 detected\n");
                hal::mmio::set_simd_level(hal::mmio::simd_level::AVX2);
            }
        } else {
            io::log::early_print("[BOOT] AVX not supported\n");
        }
    }

    // Get physical memory offset from ExoBootInfo
    io::log::early_print("[BOOT] Getting HHDM offset...\n");
    let phys_mem_offset = boot_info.phys_mem_offset;
    io::log::early_print("[BOOT] HHDM offset obtained\n");

    // VGAバッファの初期化（ログ出力用）
    io::log::early_print("[BOOT] Initializing VGA...\n");
    vga::init();
    io::log::early_print("[BOOT] VGA initialized\n");

    // ロギングシステムの初期化（最優先、ヒープ不要）
    io::log::early_print("[BOOT] Initializing logger...\n");
    if io::log::init().is_err() {
        io::log::early_print("[FATAL] Logger init failed\n");
        io::log::early_print("[BOOT] Logger init FAILED!\n");
    } else {
        info!(target: "init", "Logger initialized");
    }

    // 早期ブートログ（log crateを使用）
    info!(target: "boot", "kernel_main started");

    // 物理メモリオフセットを設定
    info!(target: "init", "Setting physical memory offset...");
    memory::set_physical_memory_offset(phys_mem_offset);
    info!(target: "init", "Physical memory offset set");
    debug!(target: "boot", "physical memory offset set: {:#x}", phys_mem_offset);

    print_logo();

    // 0. 割り込みシステムの早期初期化（例外ハンドラの設定）
    // これにより、メモリ初期化中の例外でデバッグ情報が得られる
    info!(target: "init", "Initializing interrupt system");
    interrupts::init();

    // Serial Driver Initialization (Enables UART interrupts)
    // interrupts::init() already unmasked IRQ4 (COM1) in PIC
    #[allow(deprecated)]
    if let Err(e) = io::serial::init() {
        error!(target: "init", "Serial driver init failed: {:?}", e);
    } else {
        info!(target: "init", "Serial driver initialized");
    }

    info!(target: "init", "Interrupt system initialized");

    // 1. メモリ管理の初期化
    info!(target: "init", "Initializing memory management");
    let numa_info = if boot_info.numa_info.node_count > 0 {
        Some(&boot_info.numa_info)
    } else {
        None
    };
    memory::init(
        if boot_info.rsdp_addr > 0 {
            Some(boot_info.rsdp_addr)
        } else {
            None
        },
        numa_info,
        Some(boot_info),
    );
    info!(target: "init", "Memory management initialized");

    // 1.5. ACPI & IOMMU Initialization
    // Requires memory management for allocation
    info!(target: "init", "Initializing ACPI...");

    // Configure ACPI driver with HHDM offset for physical-to-virtual translation
    io::acpi::set_hhdm_offset(phys_mem_offset);

    // static KERNEL_FILE_REQUEST removed (was shadowing global one without link section)
    // static KERNEL_FILE_REQUEST removed (was shadowing global one without link section)
    if boot_info.rsdp_addr != 0 {
        let rsdp_addr = boot_info.rsdp_addr as usize;
        // Function init expects u64 physical address usually
        match unsafe { io::acpi::init(rsdp_addr as u64) } {
            Ok(parser) => {
                info!(target: "init", "ACPI initialized via RSDP at {:#x}", rsdp_addr);

                let mut iommu_config = io::iommu::config::IommuConfig::default();
                if boot_info.cmdline_len > 0 {
                    let ptr = (phys_mem_offset + boot_info.cmdline_ptr) as *const u8;
                    let slice =
                        unsafe { core::slice::from_raw_parts(ptr, boot_info.cmdline_len as usize) };
                    if let Ok(cmdline) = core::str::from_utf8(slice) {
                        info!(target: "init", "Kernel cmdline: {}", cmdline);

                        // Parse 'iommu' option
                        if let Some(val) = util::get_cmdline_option(cmdline, "iommu") {
                            match val {
                                "off" => iommu_config.enabled = false,
                                "pt" | "passthrough" => iommu_config.passthrough = true,
                                "force" => iommu_config.force = true,
                                _ => {}
                            }
                        }
                        if let Some(val) = util::get_cmdline_option(cmdline, "iommu_global") {
                            match val {
                                "on" | "1" | "true" => iommu_config.allow_global_mappings = true,
                                "off" | "0" | "false" => {
                                    iommu_config.allow_global_mappings = false;
                                }
                                _ => {}
                            }
                        }
                        if let Some(val) = util::get_cmdline_option(cmdline, "iommu_scalable") {
                            match val {
                                "on" | "1" | "true" => iommu_config.scalable_mode = true,
                                "off" | "0" | "false" => {
                                    iommu_config.scalable_mode = false;
                                }
                                _ => {}
                            }
                        }
                    }
                }

                // Initialize IOMMU using ACPI tables and config
                unsafe {
                    match parser.find_table(b"DMAR") {
                        Ok(dmar_addr) => {
                            use crate::io::iommu::intel::IntelVtDDriver;
                            use crate::driver_registry::{register_driver, driver_registry};
                            use alloc::boxed::Box;

                            let drv = Box::new(IntelVtDDriver::new(dmar_addr, iommu_config.clone()));
                            match register_driver(drv) {
                                Ok(handle) => {
                                    info!(target: "init", "Registered Intel VT-d driver");
                                    if let Err(e) = driver_registry().probe_and_start(handle) {
                                        warn!(target: "init", "Intel VT-d start failed: {:?}", e);
                                    } else {
                                        info!(target: "init", "Intel VT-d initialized via DriverRegistry");
                                        // Enable IOMMU API
                                        if let Err(e) = io::iommu::api::enable_iommu() {
                                            error!(target: "init", "Failed to enable IOMMU: {:?}", e);
                                        } else {
                                            info!(target: "init", "IOMMU translation enabled");
                                        }
                                    }
                                }
                                Err(e) => warn!(target: "init", "Intel VT-d registration failed: {:?}", e),
                            }
                        }
                        Err(_) => match parser.find_table(b"IVRS") {
                            Ok(ivrs_addr) => {
                                use crate::io::iommu::amd::AmdViDriver;
                                use crate::driver_registry::{register_driver, driver_registry};
                                use alloc::boxed::Box;
                                
                                let drv = Box::new(AmdViDriver::new(ivrs_addr, iommu_config.clone()));
                                match register_driver(drv) {
                                    Ok(handle) => {
                                        info!(target: "init", "Registered AMD-Vi driver");
                                        if let Err(e) = driver_registry().probe_and_start(handle) {
                                            warn!(target: "init", "AMD-Vi start failed: {:?}", e);
                                        } else {
                                            info!(target: "init", "AMD-Vi initialized via DriverRegistry");
                                             if let Err(e) = io::iommu::api::enable_iommu() {
                                                error!(target: "init", "Failed to enable IOMMU: {:?}", e);
                                            } else {
                                                info!(target: "init", "IOMMU translation enabled");
                                            }
                                        }
                                    }
                                    Err(e) => warn!(target: "init", "AMD-Vi registration failed: {:?}", e),
                                }
                            }
                            Err(_) => {
                                info!(target: "init", "IOMMU not initialized (No DMAR/IVRS table)");
                            }
                        },
                    }

                    if io::iommu::api::is_iommu_enabled() {
                        if let Err(e) = io::iommu::panic::init_panic_dma_pool_default() {
                            warn!(target: "init", "IOMMU panic DMA pool init failed: {:?}", e);
                        } else {
                            info!(target: "init", "IOMMU panic DMA pool initialized");
                        }
                    }

                    let mut _mcfg_base_addr: Option<u64> = None;
                    match parser.find_table(b"MCFG") {
                        Ok(addr) => {
                            _mcfg_base_addr = Some(addr as u64);
                            info!(target: "init", "MCFG table found at {:#x}", addr);
                        }
                        Err(_) => {
                            warn!(target: "init", "No MCFG table found.");
                        }
                    }

                    // Initialize PCI subsystem
                    // Initialize PCI subsystem
                    // pci_driver::init(); // DISABLED FOR HEAP DEBUG
                    // info!(target: "init", "PCI driver initialized");

                    // ACPI tables have been parsed; reclaim ACPI-reclaimable memory.
                    memory::reclaim_acpi_reclaimable(boot_info);
                }
            }
            Err(e) => {
                warn!(target: "init", "ACPI initialization failed: {:?}", e);
            }
        }
    } else {
        warn!(target: "init", "No RSDP found provided by bootloader");
    }

    // 1.1. 1GB Huge Page サポートの初期化 (設計書 11.1.1)
    info!(target: "init", "Initializing 1GB Huge Page support...");
    mm::huge_pages::init();
    info!(target: "init", "1GB Huge Page support initialized");

    // Debug: pinpoint crash location
    io::log::early_print("[DEBUG] After huge_pages::init\n");

    // ヒープが使用可能になったことを通知
    io::log::notify_heap_available();

    io::log::early_print("[DEBUG] After notify_heap_available\n");

    // Register kernel services (SPL契約の有効化)
    info!(target: "init", "Registering kernel services...");

    io::log::early_print("[DEBUG] Before register_kernel_services\n");

    unsafe {
        service_impl::register_kernel_services();
    }

    io::log::early_print("[DEBUG] After register_kernel_services\n");

    io::log::early_print("[DEBUG] About to call info! macro\n");

    info!(target: "init", "Kernel services registered");

    io::log::early_print("[DEBUG] After first info! macro\n");

    io::log::early_print("[DEBUG] Before second info! macro\n");
    info!(target: "init", "KernelServices registered");
    io::log::early_print("[DEBUG] After second info! macro\n");

    // グラフィックスフレームバッファの初期化（ExoLoader経由）
    io::log::early_print("[DEBUG] Before graphics init info!\n");
    info!(target: "init", "Initializing graphics framebuffer...");
    io::log::early_print("[DEBUG] After graphics init info!\n");

    #[cfg(not(any(test, feature = "bench")))]
    {
        if graphics::init_from_boot_info(&boot_info.framebuffer, phys_mem_offset) {
            info!(target: "init", "Graphics framebuffer initialized");

            // ブートスプラッシュを表示
            graphics::show_boot_splash();
            info!(target: "init", "Boot splash displayed");
        } else {
            warn!(target: "init", "Graphics framebuffer init failed");
        }
    }
    #[cfg(any(test, feature = "bench"))]
    {
        info!(target: "init", "Skipping graphics framebuffer init in test/bench build");
    }

    // 進捗: 10% - メモリ初期化完了
    #[cfg(not(any(test, feature = "bench")))]
    {
        graphics::update_boot_progress_with_message(10, "Memory initialized");
    }

    // アロケーションテスト（シンプル化）
    io::log::early_print("[DEBUG] Before Allocation Tests\n");
    /*
    debug!(target: "test", "Running allocation tests");
    {
        let v: alloc::vec::Vec<u8> = alloc::vec![1, 2, 3, 4];
        debug!(target: "test", "Vec allocation OK");
        let _sum: u8 = v.iter().sum();
        debug!(target: "test", "Vec iteration OK");

        // BTreeMapテスト
        io::log::early_print("[DEBUG] Creating BTreeMap\n");
        {
            let mut map: alloc::collections::BTreeMap<u64, u64> =
                alloc::collections::BTreeMap::new();
            map.insert(1, 100);
            map.insert(2, 200);
            for i in 3..100 {
                map.insert(i, i * 10);
            }
        }
        io::log::early_print("[DEBUG] BTreeMap Dropped & Allocating Vec\n");
        let mut v: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
        v.push(1);
        drop(v);
        io::log::early_print("[DEBUG] Vec Dropped\n");
    }
    info!(target: "test", "Allocation tests passed");
    io::log::early_print("[DEBUG] After Allocation Tests\n");
    */

    // 2. ドメイン管理システムの初期化
    io::log::early_print("[DEBUG] Before domain_system::init\n");
    info!(target: "init", "Initializing domain system");
    // domain_system::init();
    info!(target: "init", "Domain system initialized");
    io::log::early_print("[DEBUG] After domain_system::init\n");
    #[cfg(not(any(test, feature = "bench")))]
    {
        graphics::update_boot_progress_with_message(20, "Domain system ready");
    }

    // 2.5. SAS（単一アドレス空間）の初期化
    info!(target: "init", "Initializing SAS");
    sas::init();
    info!(target: "init", "SAS initialized");

    // 2.6. Spectre/Meltdown緩和策の初期化
    info!(target: "init", "Initializing Spectre mitigations");
    spectre::init();
    info!(target: "init", "Spectre mitigations initialized");
    #[cfg(not(any(test, feature = "bench")))]
    {
        graphics::update_boot_progress_with_message(30, "Security initialized");
    }

    // 2.7. セキュリティフレームワークの初期化
    info!(target: "init", "Initializing security framework");
    security::init();
    info!(target: "init", "Security framework initialized");

    // 2.8. MPK/PKU セキュリティの初期化 (設計書 9.2.2)
    info!(target: "init", "Initializing MPK/PKU security");
    security::mpk::init();
    info!(target: "init", "MPK/PKU security initialized");
    #[cfg(not(any(test, feature = "bench")))]
    {
        graphics::update_boot_progress_with_message(40, "Kernel API ready");
    }

    // 2.9. Initramfs からドライバ Cells をロード
    info!(target: "init", "Loading driver Cells from initramfs...");
    let loaded_cells = initramfs::load_cells_from_initramfs(&boot_info.initramfs);
    if loaded_cells > 0 {
        info!(target: "init", "Loaded {} driver Cell(s) from initramfs", loaded_cells);
    } else {
        debug!(target: "init", "No initramfs or no Cells found");
    }

    // 3. HID ドライバの初期化 (DriverRegistry 経由)
    info!(target: "init", "Initializing HID drivers via DriverRegistry");
    {
        use alloc::boxed::Box;
        use driver_registry::register_driver;
        use io::hid::{Ps2KeyboardDriver, Ps2MouseDriver};

        // PS/2 キーボードドライバを登録
        let kb_handle = register_driver(Box::new(Ps2KeyboardDriver::new()));
        if let Err(e) = driver_registry::driver_registry()
            .probe_and_start(kb_handle.expect("Failed to register PS/2 Keyboard driver"))
        {
            warn!(target: "init", "PS/2 Keyboard driver init failed: {:?}", e);
        } else {
            info!(target: "init", "PS/2 Keyboard driver initialized via DriverRegistry");
        }

        // PS/2 マウスドライバを登録
        let mouse_handle = register_driver(Box::new(Ps2MouseDriver::new()));
        if let Err(e) = driver_registry::driver_registry()
            .probe_and_start(mouse_handle.expect("Failed to register PS/2 Mouse driver"))
        {
            warn!(target: "init", "PS/2 Mouse driver init failed: {:?}", e);
        } else {
            info!(target: "init", "PS/2 Mouse driver initialized via DriverRegistry");
        }
    }
    info!(target: "init", "HID drivers initialized");

    // 完了
    info!(target: "boot", "BOOT COMPLETE!");

    // 3.5. シリアルポートの初期化（デバッグ用）via DriverRegistry
    io::log::early_print("[DEBUG] Before Serial Driver\n");
    info!(target: "init", "Initializing serial port via DriverRegistry");
    {
        use alloc::boxed::Box;
        use driver_registry::register_driver;
        use io::serial::SerialDriver;

        // Serialドライバを登録
        let serial_handle = register_driver(Box::new(SerialDriver::new()));

        // プローブと開始
        if let Err(e) = driver_registry::driver_registry()
            .probe_and_start(serial_handle.expect("Failed to register Serial driver"))
        {
            warn!(target: "init", "Serial driver init failed: {:?}", e);
        } else {
            info!(target: "init", "Serial driver initialized via DriverRegistry");
        }
    }
    io::log::early_print("[DEBUG] After Serial Driver\n");
    io::log::early_print("[DEBUG] calling info! for NVMe\n");
    // 3.5.5. NVMeドライバの初期化（PCIスキャン）- DISABLED FOR DEBUGGING
    io::log::early_print("[DEBUG] NVMe scan SKIPPED\n");
    /*
    info!(target: "init", "Scanning for NVMe controllers...");
    io::log::early_print("[DEBUG] Calling find_by_class\n");
    {
        use alloc::boxed::Box;
        use driver_registry::register_driver;
        use nvme_driver::driver_impl::NvmeDriverWrapper;
        use pci_driver::find_by_class;

        // PCIバススキャン（初期化）- すでにカーネルのio::init等で呼ばれている可能性もあるが、
        // ここで再スキャンしても問題ないか、あるいはfind_by_classが内部でスキャンするか確認が必要。
        // pci_driver::init(); // 必要なら呼ぶ

        // NVMeコントローラを検索 (Class 01h, Subclass 08h, ProgIF 02h)
        let devices = find_by_class(0x01, 0x08);
        io::log::early_print("[DEBUG] Returned from find_by_class\n");
        let _dev_count = devices.len();
        io::log::early_print("[DEBUG] devices.len() obtained (no format)\n");
        io::log::early_print("[DEBUG] About to call devices.iter().find()\n");
        if let Some(device_info) = devices.iter().find(|d| d.class_code.prog_if == 0x02) {
            io::log::early_print("[DEBUG] Found NVMe device, calling info!\n");
            info!(target: "init", "NVMe controller found at {}", device_info.bdf);

            // BAR0を取得 (NVMeは64bit BAR0/1を使うことが多い)
            // bus.rsのPciDeviceInfo定義を見ると bars: [Option<Bar>; 6]
            if let Some(bar0) = device_info.bars[0] {
                let bar0_phys = bar0.base();
                // BARは物理アドレスなのでHHDMオフセットを加えて仮想アドレスに変換
                // new_truncate()で無効な高位ビットをマスク
                let bar0_virt =
                    memory::phys_to_virt(x86_64::PhysAddr::new_truncate(bar0_phys)).as_u64();
                info!(target: "init", "NVMe BAR0: phys={:#x} virt={:#x}", bar0_phys, bar0_virt);

                // バス制御を有効化
                device_info.enable_bus_master();
                device_info.enable_memory_space();

                // ドライバを登録
                let nvme_handle = register_driver(Box::new(NvmeDriverWrapper::new(bar0_virt, 1))); // Core=1 for now

                // Register NVMe ISR Handler (Vector 48) - Reactor Pattern
                io::interrupt_manager::register_handler(
                    io::interrupt_manager::NVME_VECTOR,
                    Box::new(io::nvme::per_core::irq_handler),
                );

                // プローブと開始
                if let Err(e) = driver_registry::driver_registry()
                    .probe_and_start(nvme_handle.expect("Failed to register NVMe driver"))
                {
                    error!(target: "init", "NVMe driver init failed: {:?}", e);
                } else {
                    info!(target: "init", "NVMe driver initialized via DriverRegistry");
                }
            } else {
                warn!(target: "init", "NVMe controller found but BAR0 is invalid");
            }
        } else {
            info!(target: "init", "No NVMe controller found");
        }
    }
    */

    // 3.5.6. AHCIドライバの初期化（PCIスキャン）- DISABLED FOR HEAP DEBUG
    io::log::early_print("[DEBUG] AHCI scan SKIPPED\n");
    /*
    info!(target: "init", "Scanning for AHCI controllers...");
    {
        use ahci_driver::driver_impl::AhciDriverWrapper;
        use alloc::boxed::Box;
        use driver_registry::register_driver;
        use pci_driver::find_by_class;

        // AHCIコントローラを検索 (Class 01h, Subclass 06h)
        let devices = find_by_class(0x01, 0x06);
        if let Some(device_info) = devices.first() {
            info!(target: "init", "AHCI controller found at {}", device_info.bdf);

            // BAR5 (ABAR) を取得
            if let Some(bar5) = device_info.bars[5] {
                let abar_phys = bar5.base();
                // BARは物理アドレスなのでHHDMオフセットを加えて仮想アドレスに変換
                // new_truncate()で無効な高位ビットをマスク
                let abar_virt =
                    memory::phys_to_virt(x86_64::PhysAddr::new_truncate(abar_phys)).as_u64();
                info!(target: "init", "AHCI ABAR: phys={:#x} virt={:#x}", abar_phys, abar_virt);

                // バス制御を有効化
                device_info.enable_bus_master();
                device_info.enable_memory_space();

                // ドライバを登録
                let ahci_handle = register_driver(Box::new(AhciDriverWrapper::new(abar_virt, 11))); // IRQ hardcoded for now

                // プローブと開始
                if let Err(e) = driver_registry::driver_registry()
                    .probe_and_start(ahci_handle.expect("Failed to register AHCI driver"))
                {
                    error!(target: "init", "AHCI driver init failed: {:?}", e);
                } else {
                    info!(target: "init", "AHCI driver initialized via DriverRegistry");
                }
            } else {
                warn!(target: "init", "AHCI controller found but BAR5 is invalid");
            }
        } else {
            info!(target: "init", "No AHCI controller found");
        }
    }
    */

    // 3.5.7. USBドライバの初期化（PCIスキャン）- DISABLED FOR HEAP DEBUG
    io::log::early_print("[DEBUG] USB scan SKIPPED\n");
    /*
    info!(target: "init", "Scanning for USB xHCI controllers...");
    {
        use alloc::boxed::Box;
        use driver_registry::register_driver;
        use pci_driver::find_by_class;
        use usb_driver::driver_impl::UsbDriverWrapper;

        // xHCIコントローラを検索 (Class 0Ch, Subclass 03h, ProgIF 30h)
        let devices = find_by_class(0x0C, 0x03);
        for device_info in devices.iter().filter(|d| d.class_code.is_xhci()) {
            info!(target: "init", "USB xHCI controller found at {}", device_info.bdf);

            // BAR0 を取得
            if let Some(bar0) = device_info.bars[0] {
                let bar0_phys = bar0.base();
                // BARは物理アドレスなのでHHDMオフセットを加えて仮想アドレスに変換
                // new_truncate()で無効な高位ビットをマスク
                let base_virt =
                    memory::phys_to_virt(x86_64::PhysAddr::new_truncate(bar0_phys)).as_u64();
                info!(target: "init", "xHCI BAR0: phys={:#x} virt={:#x}", bar0_phys, base_virt);

                // バス制御を有効化
                device_info.enable_bus_master();
                device_info.enable_memory_space();

                // ドライバを登録
                let usb_handle = register_driver(Box::new(UsbDriverWrapper::new(base_virt)));

                // プローブと開始
                if let Err(e) = driver_registry::driver_registry()
                    .probe_and_start(usb_handle.expect("Failed to register USB driver"))
                {
                    error!(target: "init", "USB xHCI driver init failed: {:?}", e);
                } else {
                    info!(target: "init", "USB xHCI driver initialized via DriverRegistry");
                }
            } else {
                warn!(target: "init", "xHCI controller found but BAR0 is invalid");
            }
        }
    }
    */
    // 3.5.8. ドライバ初期化サマリ - DISABLED FOR HEAP DEBUG
    io::log::early_print("[DEBUG] Driver Summary SKIPPED\n");
    /*
    {
        let registry = driver_registry::driver_registry();
        let drivers = registry.list();
        info!(target: "init", "=== Driver Registry Summary ===");
        info!(target: "init", "Registered: {} drivers, Running: {}", registry.count(), registry.running_count());
        for (handle, name, dtype, state) in drivers {
            info!(target: "init", "  [{:?}] {} ({:?}): {:?}", handle, name, dtype, state);
        }
        info!(target: "init", "==============================");
    }
    */

    // 3.6. ネットワークサブシステムの初期化 - DISABLED FOR HEAP DEBUG
    io::log::early_print("[DEBUG] Network init SKIPPED\n");
    /*
    info!(target: "init", "Initializing network subsystem");
    net::init_stack_default();
    net::init_socket_manager();

    // 3.6.1. ネットワークシェルAPIの初期化
    info!(target: "init", "Initializing network shell API");
    net::init_network_shell();
    info!(target: "init", "Network stack initialized");
    */
    #[cfg(not(any(test, feature = "bench")))]
    {
        // graphics::update_boot_progress_with_message(50, "Network stack ready"); // DISABLED FOR HEAP DEBUG
        io::log::early_print("[DEBUG] Boot progress 50 SKIPPED\n");
    }

    // 3.6.2. VirtIO-Net driver via DriverRegistry
    /*
    info!(target: "init", "Registering VirtIO-Net driver via DriverRegistry");
    {
        // debug_heap_check("Before VirtIO-Net init");

        use alloc::boxed::Box;
        use driver_registry::register_driver;
        use net::driver::VirtioNetDriver;

        let net_handle = register_driver(Box::new(VirtioNetDriver::new()));

        if let Err(e) = driver_registry::driver_registry()
            .probe_and_start(net_handle.expect("Failed to register VirtIO-Net driver"))
        {
            warn!(target: "init", "VirtIO-Net driver init failed: {:?}", e);
        } else {
            info!(target: "init", "VirtIO-Net driver initialized via DriverRegistry");
        }

        // debug_heap_check("After VirtIO-Net init");
    }
    */

    // 3.7. ファイルシステム（memfs）の初期化
    io::log::early_print("[DEBUG] Before memfs init\n");
    info!(target: "init", "Initializing memory filesystem");
    fs::init_shell_fs();
    info!(target: "init", "Memory filesystem initialized");
    io::log::early_print("[DEBUG] After memfs init\n");
    #[cfg(not(any(test, feature = "bench")))]
    {
        io::log::early_print("[DEBUG] Before boot progress 60\n");
        graphics::update_boot_progress_with_message(60, "Filesystem mounted");
        io::log::early_print("[DEBUG] After boot progress 60\n");
    }

    // 4. タスクスケジューラの初期化
    io::log::early_print("[DEBUG] Before scheduler init\n");
    info!(target: "init", "Initializing task scheduler");
    #[cfg(feature = "legacy-scheduler")]
    task::init_scheduler(0); // CPU 0
    info!(target: "init", "Task scheduler initialized");
    io::log::early_print("[DEBUG] After scheduler init\n");
    #[cfg(not(any(test, feature = "bench")))]
    {
        graphics::update_boot_progress_with_message(70, "Scheduler started");
    }

    // 4.5. Per-Core Executorの初期化（設計書 4.3）
    io::log::early_print("[DEBUG] Before executor init\n");
    info!(target: "init", "Initializing per-core executors");
    task::init_executors(1); // シングルコアで開始
    info!(target: "init", "Per-core executors initialized");
    io::log::early_print("[DEBUG] After executor init\n");

    // Aggregation is performed in the executor idle loop; explicit aggregator
    // spawn is not required in the normal runtime path.
    debug!(target: "init", "Log aggregation will run on executor idle");

    // 5. ローダーシステムの初期化
    io::log::early_print("[DEBUG] Before loader init\n");
    info!(target: "init", "Initializing cell loader");
    loader::init_kernel_cell();
    register_kernel_symbols();
    info!(target: "init", "Cell loader initialized");
    io::log::early_print("[DEBUG] After loader init\n");

    // 5.1. ライブアップデート / Epoch-based Reclamation の初期化 (設計書 3.5.3)
    info!(target: "init", "Initializing live update (Epoch-based Reclamation)");
    loader::live_update::init();
    info!(target: "init", "Live update initialized");
    #[cfg(not(any(test, feature = "bench")))]
    {
        graphics::update_boot_progress_with_message(80, "Loader ready");
    }

    // 5.5. シンボルテーブルの初期化（バックトレース用）
    io::log::early_print("[DEBUG] Before symbol table init\n");
    info!(target: "init", "Initializing symbol table");
    unwind::init_symbol_table();
    info!(target: "init", "Symbol table initialized");
    io::log::early_print("[DEBUG] After symbol table init\n");

    // 5.6. テストフレームワークの初期化
    info!(target: "init", "Initializing test framework");
    test::init();
    info!(target: "init", "Test framework initialized");

    // 5.7. システム統合の初期化
    info!(target: "init", "Initializing system integration");
    if let Err(e) = integration::init() {
        warn!(target: "init", "System integration failed: {:?}", e);
    } else {
        info!(target: "init", "System integration initialized");
    }

    // If built with feature `run-integration-tests`, run the integration tests at boot and exit QEMU
    #[cfg(feature = "run-integration-tests")]
    {
        info!(target: "init", "Feature run-integration-tests enabled: running integration tests (storage)");
        let (_passed, failed) = integration::run_all_integration_tests();
        use hal::port_io::PortU32;

        let mut port = PortU32::new(0xf4);
        if failed == 0 {
            port.write(0x10u32); // QEMU success
        } else {
            port.write(0x11u32); // QEMU failure
        }
        loop {
            x86_64::instructions::hlt();
        }
    }

    // If requested on the kernel cmdline, run integration tests and exit QEMU.
    if boot_info.cmdline_len > 0 {
        let ptr = (phys_mem_offset + boot_info.cmdline_ptr) as *const u8;
        let slice = unsafe { core::slice::from_raw_parts(ptr, boot_info.cmdline_len as usize) };
        if let Ok(cmdline) = core::str::from_utf8(slice) {
            if let Some(val) = util::get_cmdline_option(cmdline, "run_integration") {
                if val == "storage" || val == "1" {
                    info!(target: "init", "Running integration tests (storage) as requested by cmdline");
                    let (_passed, failed) = crate::test::integration::run_all_integration_tests();
                    use hal::port_io::PortU32;

                    let mut port = PortU32::new(0xf4);
                    if failed == 0 {
                        port.write(0x10u32); // QEMU success
                    } else {
                        port.write(0x11u32); // QEMU failure
                    }

                    // Stop here; QEMU will exit on the port write
                    loop {
                        x86_64::instructions::hlt();
                    }
                }
            }
        }
    }
    #[cfg(not(any(test, feature = "bench")))]
    {
        graphics::update_boot_progress_with_message(90, "Integration complete");
    }

    // 6. 割り込みを有効化
    io::log::early_print("[DEBUG] Before enable interrupts\n");
    interrupts::enable_interrupts();
    info!(target: "init", "Interrupts enabled");
    io::log::early_print("[DEBUG] After enable interrupts\n");
    #[cfg(not(any(test, feature = "bench")))]
    {
        io::log::early_print("[DEBUG] Before boot progress 100\n");
        graphics::update_boot_progress_with_message(100, "Ready!");
        io::log::early_print("[DEBUG] After boot progress 100\n");
    }

    // 7. システム統計を表示
    io::log::early_print("[DEBUG] Before print_system_stats\n");
    print_system_stats();
    io::log::early_print("[DEBUG] After print_system_stats\n");

    // 8. Executorの作成とタスクスポーン
    io::log::early_print("[DEBUG] Before Executor::new\n");
    info!(target: "init", "Creating async executor");
    let mut executor = task::Executor::new();
    io::log::early_print("[DEBUG] After Executor::new\n");

    io::log::early_print("[DEBUG] Before spawn_kernel_tasks\n");
    spawn_kernel_tasks(&mut executor);
    info!(target: "init", "Kernel tasks spawned");
    io::log::early_print("[DEBUG] After spawn_kernel_tasks\n");

    // =========================================================================
    // 🚨 STACK OVERFLOW TEST (Double Fault Verification)
    // このブロックを有効化して、GDT/TSS/IST修正が機能しているか確認してください。
    // 成功すれば、再起動せず "!!! DOUBLE FAULT !!!" ログが出力されて停止します。
    // =========================================================================
    // warn!("!!! INITIATING STACK OVERFLOW TEST !!!");
    // fn stack_overflow() { stack_overflow(); } // 無限再帰
    // stack_overflow();
    // =========================================================================

    io::log::early_print("[DEBUG] Before executor info macro\n");
    // info!(target: "run", "Starting executor main loop");  // DISABLED FOR DEBUGGING
    // info!("================================================================================");  // DISABLED FOR DEBUGGING
    io::log::early_print("[DEBUG] Before executor.run()\n");

    // メインループ開始（戻ってこない）
    executor.run();
}

/// カーネルタスクをスポーン
fn spawn_kernel_tasks(executor: &mut task::Executor) {
    use ipc::RRef;
    use task::Task;

    // ドメイン1を作成：ユーザーアプリケーション
    let domain1 = domain_system::create_domain(alloc::string::String::from("user_app_1"))
        .expect("create_domain failed");

    // SAS統計をログ
    let sas_stats = sas::stats();
    info!(target: "init", "SAS Stats: {} regions, {} objects, {} domains",
        sas_stats.total_regions,
        sas_stats.total_objects,
        sas_stats.domains
    );
    domain_system::start_domain(domain1).ok();

    // タスク1: ドメイン1のメインタスク
    executor.spawn(Task::new(async move {
        info!(target: "task1", "User application domain started (ID: {})", domain1.as_u64());

        // シミュレーション: データ処理
        for i in 0..5 {
            debug!(target: "task1", "Processing iteration {}", i);
            task::sleep_ms(100).await;

            // Yield point（プリエンプション対策）
            task::yield_point();
        }

        info!(target: "task1", "User application completed");
    }));

    // タスク2: ゼロコピー通信デモ
    let domain2 = domain_system::create_domain(alloc::string::String::from("ipc_demo"))
        .expect("create_domain failed");
    domain_system::start_domain(domain2).ok();

    executor.spawn(Task::new(async move {
        info!(target: "task2", "IPC demonstration started");

        // RRefを使用したゼロコピーデータ転送
        let data = RRef::new(
            ipc::DomainId::new(domain1.as_u64()),
            alloc::vec![0xDE, 0xAD, 0xBE, 0xEF],
        );
        debug!(target: "task2", "Created RRef in domain {}", domain1.as_u64());

        // 所有権を domain2 に移動
        let data = data.move_to(ipc::DomainId::new(domain2.as_u64()));
        debug!(target: "task2", "Transferred ownership to domain {} (zero-copy)", data.owner().as_u64());

        debug!(target: "task2", "Data: {:?}", &data[..]);
        info!(target: "task2", "IPC demo completed");
    }));

    // タスク3: プリエンプション統計デモ
    executor.spawn(Task::new(async {
        info!(target: "task3", "Preemption stats demo started");

        for i in 0..3 {
            debug!(target: "task3", "Iteration {}", i);
            task::sleep_ms(200).await;

            let stats = task::preemption_controller().stats();
            debug!(target: "task3", "Preemption Stats - Forced: {}, Voluntary: {}",
                stats.forced_preemptions,
                stats.voluntary_yields
            );
        }

        info!(target: "task3", "Preemption demo completed");
    }));

    // タスク4: メモリ統計モニタリング
    executor.spawn(Task::new(async {
        info!(target: "task4", "Memory monitor started");

        for _ in 0..3 {
            task::sleep_ms(500).await;

            let (used, free) = memory::heap_stats();
            debug!(target: "task4", "Heap: Used={} bytes, Free={} bytes", used, free);

            // ドメイン統計
            let domain_stats = domain_system::get_domain_stats();
            debug!(target: "task4", "Domains: {} total, {} running",
                domain_stats.total,
                domain_stats.running
            );
        }

        info!(target: "task4", "Memory monitor completed");
    }));

    // タスク5: Wakerのテスト
    executor.spawn(Task::new(async {
        info!(target: "task5", "Waker test started");

        use core::future::poll_fn;
        use core::task::Poll;

        let mut counter = 0;
        poll_fn(|_cx| {
            counter += 1;
            if counter >= 3 {
                debug!(target: "task5", "Polled {} times, completing", counter);
                Poll::Ready(())
            } else {
                debug!(target: "task5", "Polled {} times, pending", counter);
                Poll::Pending
            }
        })
        .await;

        info!(target: "task5", "Completed");
    }));

    // タスク6: ベンチマーク実行（オプション）
    // 注意: 大量メモリ割り当てでパニックするため一時的に無効化
    // シェルから sys.benchmark() で手動実行可能
    // executor.spawn(Task::new(async {
    //     info!(target: "task6", "Benchmark task started");
    //     task::sleep_ms(1000).await;
    //
    //     // ベンチマーク結果を取得
    //     let results = benchmark::run_all_benchmarks();
    //     info!(target: "task6", "Ran {} benchmarks", results.len());
    //     info!(target: "task6", "Benchmark task completed");
    // }));

    // タスク7: 統合テスト実行
    // 注意: 大量メモリ割り当てでパニックする可能性があるため一時的に無効化
    // シェルから sys.test() で手動実行可能
    // executor.spawn(Task::new(async {
    //     info!(target: "task7", "Integration test task started");
    //     task::sleep_ms(2000).await;
    //
    //     let (passed, failed) = test::integration::run_all_integration_tests();
    //     info!(target: "task7", "Integration tests: {} passed, {} failed", passed, failed);
    //     info!(target: "task7", "Integration test task completed");
    // }));

    // タスク8: 非同期シリアルシェル（IRQ4駆動）
    // シリアルシェルはバックグラウンドで維持（シリアル接続用）
    executor.spawn(Task::new(async {
        info!(target: "task8", "Async serial shell task starting...");
        // シェルをすぐに開始（デバッグ用）
        shell::async_shell::run_async_shell().await;
    }));

    // タスク9: グラフィカルシェル（フレームバッファ描画）
    executor.spawn(Task::new(async {
        info!(target: "task9", "Graphical shell task starting...");

        // グラフィカルシェルを初期化
        shell::graphical::init();
        shell::graphical::start();

        info!(target: "task9", "Graphical shell started - running async...");

        // 非同期メインループ（完全async版）
        shell::graphical::run_async_shell().await;
    }));
}

/// システム統計を表示
fn print_system_stats() {
    info!(target: "stats", "=== System Statistics ===");

    // メモリ統計
    let (used, free) = memory::heap_stats();
    info!(target: "stats", "Heap: {} bytes used / {} bytes free", used, free);

    // ドメイン統計
    let domain_stats = domain_system::get_domain_stats();
    info!(target: "stats", "Domains: {} total, {} running, {} stopped",
        domain_stats.total,
        domain_stats.running,
        domain_stats.stopped
    );

    // SAS統計
    let sas_stats = sas::stats();
    info!(target: "stats", "SAS: {} regions, {} objects",
        sas_stats.total_regions,
        sas_stats.total_objects
    );

    // セキュリティ統計
    let security_violations = security::access_control().violation_count();
    let zero_copy_stats = security::zero_copy_barrier().stats();
    info!(target: "stats", "Security: {} violations, {} bytes transferred",
        security_violations,
        zero_copy_stats.bytes_transferred
    );

    // 割り込みWaker統計
    let waker_stats = task::interrupt_waker::interrupt_waker_registry().stats();
    info!(target: "stats", "Interrupt-Waker: {} interrupts, {} wakes, {} registered",
        waker_stats.interrupt_count,
        waker_stats.wake_count,
        waker_stats.registered_sources
    );

    // 割り込み統計
    let timer_ticks = interrupts::get_timer_ticks();
    info!(target: "stats", "Timer ticks: {}", timer_ticks);

    info!(target: "stats", "================================");
}

/// カーネルシンボルを登録（セルローダー用）
fn register_kernel_symbols() {
    loader::with_registry_mut(|registry| {
        // システムコールシンボルを登録
        registry.symbol_table.insert(
            alloc::string::String::from("sys_log"),
            sys_log as *const () as usize,
        );

        registry.symbol_table.insert(
            alloc::string::String::from("sys_alloc"),
            sys_alloc as *const () as usize,
        );

        registry.symbol_table.insert(
            alloc::string::String::from("sys_dealloc"),
            sys_dealloc as *const () as usize,
        );

        registry.symbol_table.insert(
            alloc::string::String::from("sys_sleep"),
            sys_sleep as *const () as usize,
        );

        registry.symbol_table.insert(
            alloc::string::String::from("sys_panic"),
            sys_panic as *const () as usize,
        );
    });

    debug!(target: "loader", "Kernel symbols registered (5 syscalls)");
}

/// システムコール: ログ出力
#[unsafe(no_mangle)]
pub extern "C" fn sys_log(msg: *const u8, len: usize) {
    if msg.is_null() || len == 0 {
        return;
    }

    let slice = unsafe { core::slice::from_raw_parts(msg, len) };
    if let Ok(s) = core::str::from_utf8(slice) {
        info!(target: "cell", "{}", s);
    }
}

/// システムコール: メモリ割り当て
#[unsafe(no_mangle)]
pub extern "C" fn sys_alloc(size: usize) -> *mut u8 {
    use core::alloc::Layout;

    if size == 0 {
        return core::ptr::null_mut();
    }

    let layout = match Layout::from_size_align(size, 8) {
        Ok(l) => l,
        Err(_) => return core::ptr::null_mut(),
    };

    unsafe { alloc::alloc::alloc(layout) }
}

/// システムコール: スリープ
#[unsafe(no_mangle)]
pub extern "C" fn sys_sleep(ms: u64) {
    // 注意: extern "C" から async 関数を呼べないため、
    // ここではブロッキングスリープをシミュレート
    let target = task::current_tick() + ms;
    while task::current_tick() < target {
        core::hint::spin_loop();
    }
}

/// システムコール: メモリ解放
#[unsafe(no_mangle)]
pub extern "C" fn sys_dealloc(ptr: *mut u8, size: usize) {
    use core::alloc::Layout;

    if ptr.is_null() || size == 0 {
        return;
    }

    let layout = match Layout::from_size_align(size, 8) {
        Ok(l) => l,
        Err(_) => return,
    };

    unsafe { alloc::alloc::dealloc(ptr, layout) }
}

/// システムコール: パニック（Cellからの呼び出し用）
#[unsafe(no_mangle)]
pub extern "C" fn sys_panic(msg: *const u8, len: usize) -> ! {
    if !msg.is_null() && len > 0 {
        let slice = unsafe { core::slice::from_raw_parts(msg, len) };
        if let Ok(s) = core::str::from_utf8(slice) {
            log::error!(target: "cell", "Cell panic: {}", s);
        }
    }
    panic!("Cell panic - aborting");
}

/// ExoRustロゴを表示
fn print_logo() {
    let logo = r#"
  _____           ____            _   
 | ____|_  _____ |  _ \ _   _ ___| |_ 
 |  _| \ \/ / _ \| |_) | | | / __| __|
 | |___ >  < (_) |  _ <| |_| \__ \ |_ 
 |_____/_/\_\___/|_| \_\\__,_|___/\__|
"#;

    info!("{}", logo);
    info!(" :: ExoRust Kernel v0.3.0-alpha ::");
    info!(" ------------------------------------------------------------");
    info!(" Build Time : 2025-12-04 03:25:00 JST");
    info!(" Arch       : x86_64 (Long Mode)");
    info!(" Mem Layout : Higher Half Kernel / Single Address Space");
    info!(" System     : Initializing Ring 0...");
    info!(" ------------------------------------------------------------");
}

/// Panicハンドラ
#[cfg(all(not(test), not(feature = "std")))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    panic_handler::handle_panic(info)
}
