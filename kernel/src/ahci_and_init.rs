use super::*;

mod kernel_runtime;
use self::kernel_runtime::*;

pub(crate) fn ahci_ensure_mapping(
    virt_start: crate::mm::virt::higher_half::VirtAddr,
    phys_expected: crate::mm::virt::higher_half::PhysAddr,
    base_phys: u64,
    base_virt: u64,
    bar_size: u64,
) -> bool {
    fn try_map_bar(base_phys: u64, base_virt: u64, bar_size: u64) -> bool {
        if bar_size == 0 {
            crate::io::log::early_print("[AHCI] BAR5 has size 0 - skipping\n");
            return false;
        }
        let page_size: u64 = 0x1000;
        let map_size = ((bar_size + page_size - 1) / page_size) * page_size;
        let pm_offset = crate::mm::virt::higher_half::physical_memory_offset();
        let mut manager = unsafe { crate::mm::virt::higher_half::PageTableManager::from_current_cr3(pm_offset) };
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
                crate::io::log::early_print("[AHCI] Failed to map BAR region ");
                crate::io::log::early_print_hex(base_phys);
                crate::io::log::early_print(" err=");
                let err_str = match e {
                    crate::mm::virt::higher_half::MapError::FrameAllocationFailed => "FrameAllocationFailed",
                    crate::mm::virt::higher_half::MapError::AlreadyMapped => "AlreadyMapped",
                    crate::mm::virt::higher_half::MapError::NotMapped => "NotMapped",
                    crate::mm::virt::higher_half::MapError::InvalidAddress => "InvalidAddress",
                    crate::mm::virt::higher_half::MapError::AlignmentError => "AlignmentError",
                    crate::mm::virt::higher_half::MapError::ParentEntryHugePage => "ParentEntryHugePage",
                    crate::mm::virt::higher_half::MapError::HardwareError => "HardwareError",
                };
                crate::io::log::early_print(err_str);
                crate::io::log::early_print("\n");
                false
            }
        }
    }

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
                pte.phys_addr() == phys_expected
            } else {
                crate::io::log::early_print("[AHCI] PTE not present - attempting to map pages\n");
                try_map_bar(base_phys, base_virt, bar_size)
            }
        }
        None => {
            crate::io::log::early_print("[AHCI] no PTE found - mapping pages\n");
            try_map_bar(base_phys, base_virt, bar_size)
        }
    }
}

/// Initialize HID (keyboard) and serial port drivers via DriverRegistry.
pub(crate) fn init_hid_and_serial_drivers() {
    use alloc::boxed::Box;
    use driver_registry::register_driver;

    // PS/2 Keyboard
    info!(target: "init", "Initializing HID drivers via DriverRegistry");
    {
        use io::hid::Ps2KeyboardDriver;
        let kb_handle = register_driver(Box::new(Ps2KeyboardDriver::new()));
        if let Err(e) = driver_registry::driver_registry()
            .probe_and_start(kb_handle.expect("Failed to register PS/2 Keyboard driver"))
        {
            warn!(target: "init", "PS/2 Keyboard driver init failed: {:?}", e);
        } else {
            info!(target: "init", "PS/2 Keyboard driver initialized via DriverRegistry");
        }
    }
    info!(target: "init", "HID drivers initialized");
    info!(target: "boot", "BOOT COMPLETE!");

    // Serial port
    io::log::early_print("[DEBUG] Before Serial Driver\n");
    info!(target: "init", "Initializing serial port via DriverRegistry");
    {
        use io::serial::SerialDriver;
        let serial_handle = register_driver(Box::new(SerialDriver::new()));
        if let Err(e) = driver_registry::driver_registry()
            .probe_and_start(serial_handle.expect("Failed to register Serial driver"))
        {
            warn!(target: "init", "Serial driver init failed: {:?}", e);
        } else {
            info!(target: "init", "Serial driver initialized via DriverRegistry");
        }
    }
    io::log::early_print("[DEBUG] After Serial Driver\n");
}

/// Initialize the network subsystem, shell API, and VirtIO-Net driver.
pub(crate) fn init_network_subsystem() {
    io::log::early_print("[DEBUG] Network init\n");
    info!(target: "init", "Initializing network subsystem");
    net::init_stack_default();
    net::init_socket_manager();

    info!(target: "init", "Initializing network shell API");
    net::init_network_shell();
    info!(target: "init", "Network stack initialized");

    info!(target: "init", "Net Bridge initialized: {}", crate::net::driver_bridge::is_initialized());
    info!(target: "init", "Global VirtIO-Net device present: {}", crate::io::virtio::with_virtio_net(|_| ()).is_some());

    // VirtIO-Net driver via DriverRegistry
    info!(target: "init", "Registering VirtIO-Net driver via DriverRegistry");
    {
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
    }

    // Diagnostic: attempt a manual ping to exercise the transmit path
    info!(target: "init", "Manual network ping attempt to 10.0.2.2 (will trigger ARP)");
    match crate::net::send_icmp_echo([10, 0, 2, 2], 1) {
        Ok(rtt) => info!(target: "init", "Manual ping success rtt={}", rtt),
        Err(e) => warn!(target: "init", "Manual ping failed: {}", e),
    }
}

/// Run integration tests if requested by build feature or kernel cmdline, then exit QEMU.
pub(crate) fn run_integration_tests_if_requested(boot_info: &ExoBootInfo, phys_mem_offset: u64) {
    #[cfg(feature = "run-integration-tests")]
    {
        info!(target: "init", "Feature run-integration-tests enabled: running integration tests (storage)");
        let (_passed, failed) = integration::run_all_integration_tests();
        use hal::port_io::PortU32;

        let mut port = PortU32::new(0xf4);
        if failed == 0 {
            port.write(0x10u32);
        } else {
            port.write(0x11u32);
        }
        loop {
            x86_64::instructions::hlt();
        }
    }

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
                        port.write(0x10u32);
                    } else {
                        port.write(0x11u32);
                    }
                    loop {
                        x86_64::instructions::hlt();
                    }
                } else if val == "driver_cell" {
                    info!(target: "init", "Running integration tests (driver_cell) as requested by cmdline");
                    #[cfg(feature = "qemu-test-export")]
                    {
                        let summary = crate::driver_cell::qemu_tests::run_driver_cell_runtime_suite();
                        info!(
                            target: "init",
                            "driver_cell runtime summary: pass={} fail={} blocked={}",
                            summary.passed,
                            summary.failed,
                            summary.blocked
                        );
                        use hal::port_io::PortU32;

                        let mut port = PortU32::new(0xf4);
                        if summary.is_success() {
                            port.write(0x10u32);
                        } else {
                            port.write(0x11u32);
                        }
                        loop {
                            x86_64::instructions::hlt();
                        }
                    }
                    #[cfg(not(feature = "qemu-test-export"))]
                    {
                        warn!(
                            target: "init",
                            "run_integration=driver_cell requires qemu-test-export feature"
                        );
                        use hal::port_io::PortU32;

                        let mut port = PortU32::new(0xf4);
                        port.write(0x11u32);
                        loop {
                            x86_64::instructions::hlt();
                        }
                    }
                }
            }
        }
    }
}

/// Scan PCI bus for USB xHCI controllers and initialize them.
pub(crate) fn init_usb_controllers() {
    io::log::early_print("[DEBUG] USB scan STARTING\n");
    info!(target: "init", "Scanning for USB xHCI controllers...");

    use alloc::boxed::Box;
    use driver_registry::register_driver;
    use pci_driver::find_by_class;
    use usb_driver::driver_impl::UsbDriverWrapper;

    let devices = find_by_class(0x0C, 0x03);
    for device_info in devices.iter().filter(|d| d.class_code.is_xhci()) {
        info!(target: "init", "USB xHCI controller found at {}", device_info.bdf);

        let bar0 = match device_info.bars[0] {
            Some(b) => b,
            None => {
                warn!(target: "init", "xHCI controller found but BAR0 is invalid");
                continue;
            }
        };

        let base_virt = match ensure_phys_bar_mapped(bar0.base(), bar0.size()) {
            Some(v) => v,
            None => {
                warn!(target: "init", "xHCI BAR0 mapping failed - skipping init");
                continue;
            }
        };

        info!(target: "init", "xHCI BAR0: phys={:#x} virt={:#x}", bar0.base(), base_virt);
        device_info.enable_bus_master();
        device_info.enable_memory_space();

        let usb_handle = register_driver(Box::new(UsbDriverWrapper::new(base_virt)));
        if let Err(e) = driver_registry::driver_registry()
            .probe_and_start(usb_handle.expect("Failed to register USB driver"))
        {
            error!(target: "init", "USB xHCI driver init failed: {:?}", e);
        } else {
            info!(target: "init", "USB xHCI driver initialized via DriverRegistry");
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn kmain_inner(boot_info: &'static ExoBootInfo) -> ! {
    // Early serial output to confirm kernel loaded
    init_early_serial();

    // Verify ExoBootInfo version if necessary.
    io::log::early_print("[BOOT] Booted via ExoLoader!\n");
    if boot_info.version != EXO_BOOT_INFO_VERSION {
        io::log::early_print("[BOOT] WARNING: Protocol version mismatch\n");
    }

    // SSE/SSE2を有効化（x86_64ではABIで必須）
    init_sse();

    // Enable AVX/AVX2 if available
    init_avx();

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

    // Serial driver initialization is handled later via the DriverRegistry.
    // Avoid calling the deprecated `io::serial::init()` here to keep
    // initialization centralized and ensure drivers are started via
    // `driver_registry::register_driver` (see serial registration below).

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

    // 1.1. Interrupt Waker Registryの早期初期化 (Lazy Allocation)
    // ISRが有効になる前にリソースを確保し、ISR内での初期化（デッドロックリスク）を防ぐ
    info!(target: "init", "Initializing Interrupt Waker Registry (Pre-allocation)");
    let _ = task::interrupt_waker::interrupt_waker_registry().stats();


    // 1.5. ACPI & IOMMU Initialization
    // Requires memory management for allocation
    info!(target: "init", "Initializing ACPI...");

    // Configure ACPI driver with HHDM offset for physical-to-virtual translation
    io::acpi::set_hhdm_offset(phys_mem_offset);

    init_acpi_and_iommu(boot_info, phys_mem_offset);



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

    // Initialize Graphical Shell (removed - integrated into console)
    // use crate::shell::graphical::async_runtime as graphical_shell;
    // Moved below graphics initialization

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
            // graphics::show_boot_splash(); // Disabled by user request
            // info!(target: "init", "Boot splash displayed");

            // Initialize Text Console driver
            graphics::init_console();
            info!(target: "init", "Text Console driver initialized");

            // Initialize Graphical Shell (now that framebuffer is ready)
            // graphical_shell::init();
        } else {
            warn!(target: "init", "Graphics framebuffer init failed");
        }
    }
    #[cfg(any(test, feature = "bench"))]
    {
        info!(target: "init", "Skipping graphics framebuffer init in test/bench build");
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
    domain_system::init();
    info!(target: "init", "Domain system initialized");
    io::log::early_print("[DEBUG] After domain_system::init\n");
    // Check buddy heap integrity for early detection of corruption
    crate::memory::verify_buddy_integrity();

    // 2.5. SAS（単一アドレス空間）の初期化
    info!(target: "init", "Initializing SAS");
    sas::init();
    info!(target: "init", "SAS initialized");

    // 2.6. Spectre/Meltdown緩和策の初期化
    info!(target: "init", "Initializing Spectre mitigations");
    spectre::init();
    info!(target: "init", "Spectre mitigations initialized");

    // 2.7. セキュリティフレームワークの初期化
    info!(target: "init", "Initializing security framework");
    security::init();
    info!(target: "init", "Security framework initialized");

    // 2.8. MPK/PKU セキュリティの初期化 (設計書 9.2.2)
    info!(target: "init", "Initializing MPK/PKU security");
    security::mpk::init();
    info!(target: "init", "MPK/PKU security initialized");

    // 2.8.5. セルローダー / ライブアップデート / DriverCell の基盤初期化
    io::log::early_print("[DEBUG] Before early loader init\n");
    info!(target: "init", "Initializing cell loader (early)");
    loader::init_kernel_cell();
    register_kernel_symbols();
    loader::live_update::init();
    loader::live_update::set_active_cores(1);
    crate::driver_cell::init();
    info!(target: "init", "Cell loader/live update/DriverCell initialized");
    io::log::early_print("[DEBUG] After early loader init\n");

    // 2.9. Initramfs からドライバ Cells をロード
    info!(target: "init", "Loading driver Cells from initramfs...");
    let loaded_cells = initramfs::load_cells_from_initramfs(&boot_info.initramfs);
    if loaded_cells > 0 {
        info!(target: "init", "Loaded {} driver Cell(s) from initramfs", loaded_cells);
    } else {
        debug!(target: "init", "No initramfs or no Cells found");
    }

    init_hid_and_serial_drivers();
    io::log::early_print("[DEBUG] calling info! for NVMe\n");
    // 3.5.5 – 3.5.7. Storage and USB controller scanning
    init_nvme_controllers();
    init_ahci_controllers();
    init_usb_controllers();
    // 3.5.8. ドライバ初期化サマリ
    io::log::early_print("[DEBUG] Driver Summary STARTING\n");
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

    init_network_subsystem();

    // 3.7. ファイルシステム（memfs）の初期化
    io::log::early_print("[DEBUG] Before memfs init\n");
    info!(target: "init", "Initializing memory filesystem");
    fs::init_shell_fs();
    info!(target: "init", "Memory filesystem initialized");
    io::log::early_print("[DEBUG] After memfs init\n");

    // 4. タスクスケジューラの初期化
    io::log::early_print("[DEBUG] Before scheduler init\n");
    info!(target: "init", "Initializing task scheduler");
    #[cfg(feature = "legacy-scheduler")]
    task::init_scheduler(0); // CPU 0
    info!(target: "init", "Task scheduler initialized");
    io::log::early_print("[DEBUG] After scheduler init\n");

    // 4.5. Per-Core Executorの初期化（設計書 4.3）
    io::log::early_print("[DEBUG] Before executor init\n");
    info!(target: "init", "Initializing per-core executors");
    task::init_executors(1); // シングルコアで開始
    info!(target: "init", "Per-core executors initialized");
    io::log::early_print("[DEBUG] After executor init\n");

    // 4.6. I/Oスケジューラの初期化
    io::io_scheduler::init_io_scheduler();

    // Aggregation is performed in the executor idle loop; explicit aggregator
    // spawn is not required in the normal runtime path.
    debug!(target: "init", "Log aggregation will run on executor idle");

    // 5. ローダー/ライブアップデートは initramfs より前に初期化済み
    debug!(target: "init", "Cell loader/live update already initialized (early path)");

    // 5.5. シンボルテーブルの初期化（バックトレース用）
    io::log::early_print("[DEBUG] Before symbol table init\n");
    info!(target: "init", "Initializing symbol table");
    unwind::init_symbol_table();
    info!(target: "init", "Symbol table initialized");
    io::log::early_print("[DEBUG] After symbol table init\n");

    // 5.6. テストフレームワークの初期化
    io::log::early_print("[DEBUG] Before test::init\n");
    info!(target: "init", "Initializing test framework");
    test::init();
    info!(target: "init", "Test framework initialized");
    io::log::early_print("[DEBUG] After test::init\n");

    // 5.7. システム統合の初期化
    io::log::early_print("[DEBUG] Before integration::init\n");
    info!(target: "init", "Initializing system integration");
    if let Err(e) = integration::init() {
        warn!(target: "init", "System integration failed: {:?}", e);
    } else {
        info!(target: "init", "System integration initialized");
    }
    io::log::early_print("[DEBUG] After integration::init\n");

    // Diagnostic: immediate manual ping attempt to exercise network transmit path
    io::log::early_print("[DEBUG] Manual ping insertion point\n");
    io::log::early_print("[DEBUG] Manual network ping attempt to 10.0.2.2 (will trigger ARP)\n");
    let ping_res = crate::net::send_real_icmp_echo([10, 0, 2, 2], 1);
    match ping_res {
        Ok(rtt) => {
            info!(target: "init", "Manual ping success rtt={}", rtt);
            io::log::early_print(&alloc::format!("[DEBUG] Manual ping success rtt={}\n", rtt));
        }
        Err(e) => {
            warn!(target: "init", "Manual ping failed: {}", e);
            io::log::early_print(&alloc::format!("[DEBUG] Manual ping failed: {}\n", e));
        }
    }

    // 6. 割り込みを有効化
    io::log::early_print("[DEBUG] Before enable interrupts\n");
    #[cfg(not(feature = "qemu-test-export"))]
    {
        interrupts::enable_interrupts();
        info!(target: "init", "Interrupts enabled");
    }
    #[cfg(feature = "qemu-test-export")]
    {
        let mut skip_interrupt_enable = false;
        if boot_info.cmdline_len > 0 {
            let ptr = (phys_mem_offset + boot_info.cmdline_ptr) as *const u8;
            let slice =
                unsafe { core::slice::from_raw_parts(ptr, boot_info.cmdline_len as usize) };
            if let Ok(cmdline) = core::str::from_utf8(slice) {
                if let Some(v) = util::get_cmdline_option(cmdline, "qemu_no_if") {
                    if v == "1" || v == "true" || v == "yes" {
                        skip_interrupt_enable = true;
                    }
                }
            }
        }

        if skip_interrupt_enable {
            info!(
                target: "init",
                "Interrupt enable skipped by cmdline option qemu_no_if=1"
            );
        } else {
            interrupts::enable_interrupts();
            info!(target: "init", "Interrupts enabled (qemu-test-export mode)");
        }
    }
    io::log::early_print("[DEBUG] After enable interrupts\n");

    // 6.5. cmdline 指定の統合テスト実行（必要ならここで QEMU へ終了コードを返す）
    run_integration_tests_if_requested(boot_info, phys_mem_offset);

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
    info!(target: "run", "Starting executor main loop");
    crate::io::log::early_print("[DEBUG] Executor run starting...\n");

    // グラフィカルシェルを開始
    // graphical_shell::start();

    // メインループ開始（戻ってこない）
    executor.run();
}
