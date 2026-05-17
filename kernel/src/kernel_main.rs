// ============================================================================
// kernel_main.rs - カーネルメインエントリポイント (kmain) とシステム初期化
// ============================================================================
// 責務: kmain_inner()、デバイス検出、ドライバ初期化、Executorループ
// ============================================================================
use super::*;
use crate::{
    debug, domain, driver_registry, durability, fs, graphics, heap, integration, interrupts, io,
    kapi, loader, sas, security, task, test, util,
};
use log::{debug, error, info, warn};

#[path = "kernel_main/kernel_runtime.rs"]
mod kernel_runtime;
use self::kernel_runtime::{print_logo, register_kernel_symbols, start_async_boot_runtime};

#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) fn async_boot_stage_runtime_snapshot()
-> crate::async_boot_runtime_snapshot::AsyncBootStageRuntimeSnapshot {
    self::kernel_runtime::async_boot_stage_runtime_snapshot()
}

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
                crate::io::log::early_print("[AHCI] Failed to map BAR region ");
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
    use crate::driver_registry::register_driver;
    use alloc::boxed::Box;

    crate::drivers::usb::class::hid::set_keyboard_event_sink(Some(
        crate::drivers::hid::keyboard::handle_key_event,
    ));

    // PS/2 Keyboard
    info!(target: "init", "Initializing HID drivers via DriverRegistry");
    {
        use crate::drivers::hid::Ps2KeyboardDriver;
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

    // Serial port
    info!(target: "init", "Initializing serial port via DriverRegistry");
    {
        use crate::drivers::serial::SerialDriver;
        let serial_handle = register_driver(Box::new(SerialDriver::new()));
        if let Err(e) = driver_registry::driver_registry()
            .probe_and_start(serial_handle.expect("Failed to register Serial driver"))
        {
            warn!(target: "init", "Serial driver init failed: {:?}", e);
        } else {
            info!(target: "init", "Serial driver initialized via DriverRegistry");
        }
    }
}

/// ネットワークインフラストラクチャの早期初期化（Executor不要）
///
/// NetworkStack、EndpointManager、OOOキュー、再送タイマーの初期化のみを行う。
/// ドライバ登録・DHCP・pingは `network_bootstrap_task()` で
/// Executor起動後に完全非同期で確認される。
pub(crate) fn init_network_infra() {
    info!(target: "init", "Initializing network infrastructure (pre-executor)");

    // Initialize hash secrets for sharded structures (e.g. OOO queue)
    crate::net::l4::types::init_hash_secrets();

    // Initialize firewall with secure default rules
    crate::net::security::firewall::setup_default_firewall();

    // Initialize TCP SYN cookies
    crate::net::runtime::transport::tcp_table_in(crate::net::runtime::default_runtime())
        .init_syncookies();

    let stack_initialized = crate::net::runtime::device::is_initialized();
    let port_runtime_initialized =
        !crate::net::runtime::device::list_port_ids_in(crate::net::runtime::default_runtime())
            .is_empty();
    let endpoint_manager_initialized = true;
    debug!(
        target: "init",
        "Network bootstrap precheck: port_runtime_active={} stack_initialized={} socket_manager_initialized={}",
        port_runtime_initialized,
        stack_initialized,
        endpoint_manager_initialized
    );

    if stack_initialized {
        info!(
            target: "init",
            "Network stack already initialized by port runtime; skipping default init"
        );
    } else {
        match crate::net::runtime::device::ensure_stack_initialized(
            crate::net::runtime::stack::NetworkConfig::default(),
        ) {
            Ok(()) => info!(target: "init", "Network stack initialized via port runtime"),
            Err(err) => warn!(
                target: "init",
                "Network stack init via port runtime failed: {}",
                err
            ),
        }
    }

    info!(target: "init", "Socket registry is owned by each network runtime");

    let stack_initialized = crate::net::runtime::device::is_initialized();
    let port_runtime_initialized =
        !crate::net::runtime::device::list_port_ids_in(crate::net::runtime::default_runtime())
            .is_empty();
    let endpoint_manager_initialized = true;
    info!(
        target: "init",
        "Network core ready: stack_initialized={} socket_manager_initialized={} port_runtime_active={} async_port_bootstrap_pending={}",
        stack_initialized,
        endpoint_manager_initialized,
        port_runtime_initialized,
        !port_runtime_initialized
    );

    // OOOキューとタイミングホイールを初期化
    crate::net::l4::tcp::ooo_queue::init_ooo_queues();
    crate::net::l4::tcp::retransmit::init_timer_wheel();
    info!(target: "init", "OOO queues and retransmit timer wheel initialized");

    info!(target: "init", "Network driver class init deferred to async bootstrap");
}

// ============================================================================
// 同期DHCP / 同期ping / io_delay_vmexit は廃止。
// ネットワーク初期化は network_bootstrap_task() (kernel_runtime.rs) で
// Executor起動後に完全非同期で実行される。
// ============================================================================

fn kernel_cmdline(boot_info: &boot_proto::ExoBootInfoView<'static>) -> Option<&'static str> {
    boot_info.cmdline()
}

#[inline]
fn parse_cmdline_bool(v: &str) -> bool {
    matches!(v, "1" | "true" | "yes" | "on")
}

fn parse_cmdline_u64(v: &str) -> Option<u64> {
    if let Some(rest) = v.strip_prefix("0x") {
        u64::from_str_radix(rest, 16).ok()
    } else {
        v.parse::<u64>().ok()
    }
}

#[derive(Clone, Copy)]
struct KernelBootContext {
    boot_info_addr: usize,
    boot_info_view: boot_proto::ExoBootInfoView<'static>,
    phys_mem_offset: u64,
    cmdline: Option<&'static str>,
}

impl KernelBootContext {
    fn new(boot_info: &'static ExoBootInfo) -> Self {
        let phys_mem_offset = boot_info.phys_mem_offset;
        let boot_info_view = unsafe { boot_info.view() }
            .expect("bootloader handoff must validate before kernel initialization");
        let cmdline = kernel_cmdline(&boot_info_view);
        crate::util::set_boot_cmdline(cmdline);
        Self {
            boot_info_addr: boot_info as *const ExoBootInfo as usize,
            boot_info_view,
            phys_mem_offset,
            cmdline,
        }
    }

    fn boot_info(&self) -> &'static ExoBootInfo {
        // SAFETY: the bootloader handoff is immutable and lives for the full
        // kernel lifetime; the context only stores its stable address.
        unsafe { &*(self.boot_info_addr as *const ExoBootInfo) }
    }

    fn boot_info_view(&self) -> &boot_proto::ExoBootInfoView<'static> {
        &self.boot_info_view
    }

    fn numa_info(&self) -> Option<&boot_proto::NumaInfo> {
        let boot_info = self.boot_info();
        (boot_info.numa_info.node_count > 0).then_some(&boot_info.numa_info)
    }

    fn should_skip_text_console_init(&self) -> bool {
        #[cfg(feature = "qemu-test-export")]
        {
            self.cmdline
                .and_then(|cmdline| util::get_cmdline_option(cmdline, "run_integration"))
                .map(|profile| profile == "driver_domain")
                .unwrap_or(false)
        }
        #[cfg(not(feature = "qemu-test-export"))]
        {
            false
        }
    }
}

fn phase_bootloader_handoff(_context: &KernelBootContext) {
    io::log::early_print("[BOOT] Booted via ExoLoader!\n");
}

fn verify_boot_protocol_version(boot_info: &ExoBootInfo) {
    if !boot_info.is_version_compatible() {
        io::log::early_print("[FATAL] Boot protocol version mismatch!\n");
        io::log::early_print("[FATAL] Expected version: ");
        io::log::early_print_hex(EXO_BOOT_INFO_VERSION);
        io::log::early_print(", got: ");
        io::log::early_print_hex(boot_info.version);
        io::log::early_print("\n[FATAL] Rebuild bootloader and kernel from the same tree.\n");
        panic!(
            "ExoBootInfo version mismatch: expected {}, got {}",
            EXO_BOOT_INFO_VERSION, boot_info.version
        );
    }
}

fn phase_entry_and_early_cpu(context: &KernelBootContext) {
    let boot_info = context.boot_info();
    init_early_serial();
    phase_bootloader_handoff(context);
    verify_boot_protocol_version(boot_info);
    crate::platform::acpi::install_boot_snapshot(&boot_info.acpi_snapshot);

    // SSE/SSE2を有効化（x86_64ではABIで必須）
    init_sse();

    // Enable AVX/AVX2 if available
    init_avx();

    // Seed the monotonic clock before the logger comes up so structured logs
    // can carry timestamps even while IRQ delivery is still deferred.
    crate::time::init_early_clock();

    // Get physical memory offset from ExoBootInfo
    io::log::early_print("[BOOT] Getting HHDM offset...\n");
    io::log::early_print("[BOOT] HHDM offset obtained\n");

    // VGAバッファの初期化（ログ出力用）
    io::log::early_print("[BOOT] Initializing VGA...\n");
    graphics::vga::init();
    io::log::early_print("[BOOT] VGA initialized\n");

    unsafe {
        crate::per_cpu::bootstrap_bsp_per_cpu_early();
    }

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
    heap::set_physical_memory_offset(context.phys_mem_offset);
    info!(target: "init", "Physical memory offset set");
    debug!(
        target: "boot",
        "physical memory offset set: {:#x}",
        context.phys_mem_offset
    );

    print_logo();
}

fn install_bsp_stack_guard() {
    let stack_base = &raw const KERNEL_STACK as usize;
    const STACK_SIZE: usize = 4096 * KERNEL_STACK_PAGES; // 1 MiB
    crate::panic_handler::setup_stack_guard(stack_base, STACK_SIZE);
    let guard_end = stack_base + 4096;
    let stack_top = stack_base + STACK_SIZE;
    info!(
        target: "init",
        "BSP stack guard page: [{:#x}..{:#x}) unmapped, usable stack: [{:#x}..{:#x}) ({} KiB)",
        stack_base,
        guard_end,
        guard_end,
        stack_top,
        (stack_top - guard_end) / 1024
    );
}

fn phase_early_kernel_substrate(context: &KernelBootContext) {
    // 0. 割り込みシステムの早期初期化（例外ハンドラの設定）
    // これにより、メモリ初期化中の例外でデバッグ情報が得られる
    info!(target: "init", "Initializing interrupt system");
    interrupts::init();

    // Serial driver initialization is handled later via the DriverRegistry.
    // Keep initialization centralized and ensure drivers are started via
    // `driver_registry::register_driver` (see serial registration below).
    info!(target: "init", "Interrupt system initialized");

    // 0.1. PIT (Programmable Interval Timer) を 1000 Hz に設定
    // 早期 clock 基盤 (RTC/TSC) は Phase 2 で初期化済み。ここでは IRQ 駆動の
    // 周期 tick だけを有効化して 1 tick = 1ms の前提を整える。
    crate::time::init(1000);
    info!(target: "init", "PIT initialized at 1000 Hz");

    // 1. メモリ管理の初期化
    info!(target: "init", "Initializing memory management");
    heap::init(context.numa_info(), Some(context.boot_info_view()));
    heap::ensure_global_heap_ready();
    info!(target: "init", "Memory management initialized");

    // Heap-backed task runtime primitives are available at this point, so
    // provision the BSP executor before later boot stages enqueue async work.
    task::provision_executors(1);
    info!(
        target: "init",
        "Bootstrap per-core executor provisioned for early async services"
    );

    // 0.5. BSPブートスタック下端にガードページ（Present=0）を設置
    // メモリ管理が初期化されたので、ページテーブル操作が可能になった。
    install_bsp_stack_guard();

    // 1.1. Interrupt Waker Registryの早期初期化 (Lazy Allocation)
    // ISRが有効になる前にリソースを確保し、ISR内での初期化（デッドロックリスク）を防ぐ
    info!(
        target: "init",
        "Initializing Interrupt Waker Registry (Pre-allocation)"
    );
    let _ = task::interrupt_waker::interrupt_waker_registry().stats();

    bootstrap_smp_early(context);
}

fn bootstrap_smp_early(context: &KernelBootContext) {
    info!(
        target: "init",
        "Bootstrapping SMP before ACPI/IOMMU platform bring-up"
    );

    match crate::cpu::initialize(context.boot_info()) {
        Ok(report) => {
            info!(
                target: "init",
                "SMP bootstrap report: detected={} started={}",
                report.detected,
                report.started
            );
        }
        Err(err) => {
            warn!(target: "init", "SMP bootstrap failed: {}", err);
        }
    }
}

// Helper used during early boot to report how much of the BSP
// boot stack remains above the guard page.  This is purely diagnostic and
// helps catch unchecked growth of the initialization call stack.
#[allow(dead_code)]
fn log_stack_free_space(label: &str) {
    let rsp: usize;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp) };
    // these constants must match those used in kernel_content.rs
    let stack_base = &raw const KERNEL_STACK as usize;
    let guard_end = stack_base + 4096;
    let free = rsp.saturating_sub(guard_end);
    info!(
        target: "init",
        "[stack] {}: rsp={:#x}, free above guard = {} bytes",
        label,
        rsp,
        free
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeRegistrationStep {
    PlatformProviders,
    TimeProvider,
    KernelServices,
}

fn for_each_runtime_registration_step(mut visit: impl FnMut(RuntimeRegistrationStep)) {
    visit(RuntimeRegistrationStep::PlatformProviders);
    visit(RuntimeRegistrationStep::TimeProvider);
    visit(RuntimeRegistrationStep::KernelServices);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutorOnlineMilestone {
    ConfigureBootRunMode,
    ReleaseWorkers,
    StartExecutorRun,
}

fn for_each_executor_online_milestone(mut visit: impl FnMut(ExecutorOnlineMilestone)) {
    visit(ExecutorOnlineMilestone::ConfigureBootRunMode);
    visit(ExecutorOnlineMilestone::ReleaseWorkers);
    visit(ExecutorOnlineMilestone::StartExecutorRun);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AsyncBootCompletionMilestone {
    ResolveShellMode,
    SpawnKernelTasks,
    BootComplete,
}

fn for_each_async_boot_completion_milestone(mut visit: impl FnMut(AsyncBootCompletionMilestone)) {
    visit(AsyncBootCompletionMilestone::ResolveShellMode);
    visit(AsyncBootCompletionMilestone::SpawnKernelTasks);
    visit(AsyncBootCompletionMilestone::BootComplete);
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BootLifecycleMilestone {
    ConfigureBootRunMode,
    ReleaseWorkers,
    StartExecutorRun,
    ResolveShellMode,
    SpawnKernelTasks,
    BootComplete,
}

#[cfg(test)]
fn for_each_boot_lifecycle_milestone(mut visit: impl FnMut(BootLifecycleMilestone)) {
    visit(BootLifecycleMilestone::ConfigureBootRunMode);
    visit(BootLifecycleMilestone::ReleaseWorkers);
    visit(BootLifecycleMilestone::StartExecutorRun);
    visit(BootLifecycleMilestone::ResolveShellMode);
    visit(BootLifecycleMilestone::SpawnKernelTasks);
    visit(BootLifecycleMilestone::BootComplete);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn runtime_registration_step_order_is_canonical() {
        let mut seen = [RuntimeRegistrationStep::PlatformProviders; 3];
        let mut idx = 0usize;

        for_each_runtime_registration_step(|step| {
            seen[idx] = step;
            idx += 1;
        });

        assert_eq!(idx, seen.len());
        assert_eq!(
            seen,
            [
                RuntimeRegistrationStep::PlatformProviders,
                RuntimeRegistrationStep::TimeProvider,
                RuntimeRegistrationStep::KernelServices,
            ]
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn executor_online_milestone_order_is_canonical() {
        let mut seen = [ExecutorOnlineMilestone::ConfigureBootRunMode; 3];
        let mut idx = 0usize;

        for_each_executor_online_milestone(|step| {
            seen[idx] = step;
            idx += 1;
        });

        assert_eq!(idx, seen.len());
        assert_eq!(
            seen,
            [
                ExecutorOnlineMilestone::ConfigureBootRunMode,
                ExecutorOnlineMilestone::ReleaseWorkers,
                ExecutorOnlineMilestone::StartExecutorRun,
            ]
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn async_boot_completion_milestone_order_places_boot_complete_last() {
        let mut seen = [AsyncBootCompletionMilestone::ResolveShellMode; 3];
        let mut idx = 0usize;

        for_each_async_boot_completion_milestone(|step| {
            seen[idx] = step;
            idx += 1;
        });

        assert_eq!(idx, seen.len());
        assert_eq!(
            seen,
            [
                AsyncBootCompletionMilestone::ResolveShellMode,
                AsyncBootCompletionMilestone::SpawnKernelTasks,
                AsyncBootCompletionMilestone::BootComplete,
            ]
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn boot_lifecycle_starts_executor_before_boot_complete() {
        let mut seen = [BootLifecycleMilestone::ConfigureBootRunMode; 6];
        let mut idx = 0usize;

        for_each_boot_lifecycle_milestone(|step| {
            seen[idx] = step;
            idx += 1;
        });

        assert_eq!(idx, seen.len());
        assert_eq!(
            seen,
            [
                BootLifecycleMilestone::ConfigureBootRunMode,
                BootLifecycleMilestone::ReleaseWorkers,
                BootLifecycleMilestone::StartExecutorRun,
                BootLifecycleMilestone::ResolveShellMode,
                BootLifecycleMilestone::SpawnKernelTasks,
                BootLifecycleMilestone::BootComplete,
            ]
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn boot_cmdline_interrupt_policy_defaults_to_enabled_without_override() {
        assert!(boot_cmdline_allows_interrupts(None));
        assert!(boot_cmdline_allows_interrupts(Some("run_integration=boot")));
    }

    #[cfg(feature = "qemu-test-export")]
    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn boot_cmdline_interrupt_policy_honors_qemu_no_if_override() {
        assert!(!boot_cmdline_allows_interrupts(Some("qemu_no_if=1")));
        assert!(!boot_cmdline_allows_interrupts(Some("qemu_no_if=true")));
        assert!(!boot_cmdline_allows_interrupts(Some("qemu_no_if=yes")));
        assert!(boot_cmdline_allows_interrupts(Some("qemu_no_if=0")));
    }
}

fn register_spl_kernel_services() {
    // We are hitting mysterious stack corruption after this function returns,
    // so emit fine-grained diagnostics around every step.
    log_stack_free_space("before register_kernel_services");
    info!(target: "init", "Registering kernel services...");
    log_stack_free_space("after log before call");

    // The act of registering kernel services should not require interrupts, and
    // a buggy ISR might be corrupting the stack pointer.  Disable them to
    // diagnose and (temporarily) avoid the issue.
    interrupts::without_interrupts(|| unsafe {
        kapi::register_kernel_services();
    });
    log_stack_free_space("after register_kernel_services call");

    info!(target: "init", "Kernel services registered");
    log_stack_free_space("after log after call");
}

fn register_runtime_service_boundary() {
    for_each_runtime_registration_step(|step| match step {
        RuntimeRegistrationStep::PlatformProviders => {
            log_stack_free_space("runtime registration: platform providers");
            info!(target: "init", "Registering builtin platform providers...");
            crate::platform::register_builtin_services();
            info!(target: "init", "Builtin platform providers registered");
        }
        RuntimeRegistrationStep::TimeProvider => {
            info!(target: "init", "Registering builtin time provider...");
            crate::drivers::time::register_builtin_service();
            info!(target: "init", "Builtin time provider registered");
        }
        RuntimeRegistrationStep::KernelServices => {
            log_stack_free_space("runtime registration: kernel services");
            info!(target: "init", "Registering builtin kernel service providers...");
            crate::kapi::register_builtin_service_providers();
            info!(target: "init", "Builtin kernel service providers registered");
            info!(target: "init", "Publishing kernel services...");
            register_spl_kernel_services();
            info!(target: "init", "Kernel services published");
        }
    });
}

fn enable_async_logging_for_boot() {
    // qemu-test-export/full-boot profiles can run with interrupts disabled
    // (`qemu_no_if=1`), so keep synchronous logging there to avoid async
    // logger backpressure stalls before runtime profile dispatch.
    #[cfg(not(feature = "qemu-test-export"))]
    {
        io::log::enable_async_logging();
    }
    #[cfg(feature = "qemu-test-export")]
    {}
}

fn boot_cmdline_allows_interrupts(cmdline: Option<&str>) -> bool {
    #[cfg(not(feature = "qemu-test-export"))]
    {
        let _ = cmdline;
        true
    }
    #[cfg(feature = "qemu-test-export")]
    {
        !cmdline
            .and_then(|cmdline| util::get_cmdline_option(cmdline, "qemu_no_if"))
            .map(|v| v == "1" || v == "true" || v == "yes")
            .unwrap_or(false)
    }
}

fn init_graphics_console(context: &KernelBootContext) -> bool {
    info!(target: "init", "Initializing graphics framebuffer...");

    #[cfg(not(any(test, feature = "bench")))]
    {
        if graphics::init_from_boot_info(&context.boot_info().framebuffer, context.phys_mem_offset)
        {
            info!(target: "init", "Graphics framebuffer initialized");

            if context.should_skip_text_console_init() {
                info!(
                    target: "init",
                    "Skipping text console init for qemu-test-export driver_domain profile"
                );
                false
            } else {
                graphics::init_console();
                info!(target: "init", "Text Console driver initialized");
                true
            }
        } else {
            warn!(target: "init", "Graphics framebuffer init failed");
            false
        }
    }
    #[cfg(any(test, feature = "bench"))]
    {
        info!(
            target: "init",
            "Skipping graphics framebuffer init in test/bench build"
        );
        false
    }
}

fn phase_platform_and_security_base(context: &KernelBootContext) {
    // 1.5. ACPI & IOMMU Initialization
    // SMP bring-up is already complete at this point so APs can park while the
    // BSP handles the heavier platform discovery and security setup.
    info!(target: "init", "Initializing ACPI...");

    // Configure ACPI driver with HHDM offset for physical-to-virtual translation
    io::acpi::set_hhdm_offset(context.phys_mem_offset);
    init_acpi_and_iommu(context.boot_info_view());

    crate::mm::numa::topology::configure_from_boot_info(&context.boot_info().numa_info);
    crate::mm::numa::topology::apply_current_cpu_locality();

    // ヒープが使用可能になったことを通知
    io::log::notify_heap_available();

    register_runtime_service_boundary();
    enable_async_logging_for_boot();
}

fn phase_graphics_console(context: &KernelBootContext) -> bool {
    if context.boot_info().boot_policy.shell_mode != boot_proto::BootShellMode::Console {
        info!(
            target: "init",
            "Skipping graphics console init; enable with shell=console"
        );
        return false;
    }

    init_graphics_console(context)
}

fn log_driver_registry_summary() {
    let registry = driver_registry::driver_registry();
    let drivers = registry.list();
    info!(target: "init", "=== Driver Registry Summary ===");
    info!(
        target: "init",
        "Registered: {} drivers, Running: {}",
        registry.count(),
        registry.running_count()
    );
    for (handle, name, dtype, state) in drivers {
        info!(
            target: "init",
            "  [{:?}] {} ({:?}): {:?}",
            handle,
            name,
            dtype,
            state
        );
    }
    info!(target: "init", "==============================");
}

fn initialize_system_integration() -> bool {
    info!(target: "init", "Initializing system integration");
    if let Err(e) = integration::init() {
        warn!(target: "init", "System integration failed: {:?}", e);
        false
    } else {
        info!(target: "init", "System integration initialized");
        true
    }
}

fn retry_system_integration_if_needed(integration_ready: bool) -> bool {
    if integration_ready {
        debug!(
            target: "init",
            "(late) Skipping system integration: already initialized"
        );
        return true;
    }

    info!(target: "init", "(late) Initializing system integration");
    if let Err(e) = integration::init() {
        warn!(target: "init", "(late) System integration failed: {:?}", e);
        false
    } else {
        info!(target: "init", "(late) System integration initialized");
        true
    }
}

fn init_durability_and_kgdb(context: &KernelBootContext) {
    info!(target: "init", "Initializing durability + kgdb subsystems");
    durability::init();

    if let Some(cmdline) = context.cmdline
        && let Some(wal_mode) = util::get_cmdline_option(cmdline, "wal")
        && wal_mode == "nvme_raw"
    {
        let nsid = util::get_cmdline_option(cmdline, "wal_nsid")
            .and_then(parse_cmdline_u64)
            .unwrap_or(0) as u32;
        let lba_start = util::get_cmdline_option(cmdline, "wal_lba_start")
            .and_then(parse_cmdline_u64)
            .unwrap_or(0);
        let lba_len = util::get_cmdline_option(cmdline, "wal_lba_len")
            .and_then(parse_cmdline_u64)
            .unwrap_or(0);
        if nsid != 0 && lba_len != 0 {
            if let Err(e) = durability::wal::set_backend_nvme_raw(nsid, lba_start, lba_len) {
                warn!(target: "init", "WAL NVMe backend disabled: {:?}", e);
            } else {
                info!(
                    target: "init",
                    "WAL backend enabled: nvme_raw nsid={} lba_start={} lba_len={}",
                    nsid,
                    lba_start,
                    lba_len
                );
            }
        } else {
            warn!(
                target: "init",
                "wal=nvme_raw requested but wal_nsid/wal_lba_len missing; WAL kept disabled"
            );
        }
    }

    if let Err(e) = durability::wal::recover_from_backend(|_tx_id, _op| {
        // Recovery apply-hook is intentionally a no-op at kernel boot stage.
    }) {
        warn!(target: "init", "WAL recovery skipped: {:?}", e);
    }
    if let Err(e) = durability::wal::checkpoint() {
        warn!(target: "init", "WAL checkpoint skipped: {:?}", e);
    }

    let kgdb_on = context
        .cmdline
        .and_then(|c| util::get_cmdline_option(c, "kgdb"))
        .map(parse_cmdline_bool)
        .unwrap_or(false);
    if kgdb_on {
        let transport_mode = context
            .cmdline
            .and_then(|c| util::get_cmdline_option(c, "kgdb_transport"))
            .unwrap_or("both");
        let use_serial = transport_mode == "serial" || transport_mode == "both";
        let serial_exclusive = context
            .cmdline
            .and_then(|c| util::get_cmdline_option(c, "kgdb_serial_exclusive"))
            .map(parse_cmdline_bool)
            .unwrap_or(use_serial);

        let _ = debug::gdb_stub::init_gdb_stub();
        debug::gdb_stub::set_enabled(true);
        if use_serial {
            let _ = debug::gdb_stub::register_transport(alloc::sync::Arc::new(
                debug::gdb_stub::SerialCom1Transport::new(),
            ));
        }
        if serial_exclusive && use_serial {
            io::log::set_serial_output_enabled(false);
        }
        info!(
            target: "init",
            "kgdb enabled (transport={}, serial_exclusive={})",
            transport_mode,
            serial_exclusive
        );
    } else {
        debug::gdb_stub::set_enabled(false);
    }
    info!(target: "init", "Durability + kgdb subsystems initialized");
}

fn phase_core_services_base(context: &KernelBootContext) {
    // 2. ドメイン管理システムの初期化
    info!(target: "init", "Initializing domain system");
    domain::init();
    info!(target: "init", "Domain system initialized");
    crate::heap::verify_buddy_integrity();

    // 2.5. SAS（単一アドレス空間）の初期化
    info!(target: "init", "Initializing SAS");
    sas::init();
    info!(target: "init", "SAS initialized");

    // 2.6. Spectre/Meltdown緩和策の初期化
    info!(target: "init", "Initializing Spectre mitigations");
    security::spectre::init();
    info!(target: "init", "Spectre mitigations initialized");

    // 2.7. セキュリティフレームワークの初期化
    info!(target: "init", "Initializing security framework");
    security::init();
    info!(target: "init", "Security framework initialized");

    // 2.8. MPK/PKU セキュリティの初期化 (設計書 9.2.2)
    info!(target: "init", "Initializing MPK/PKU security");
    security::mpk::init();
    info!(target: "init", "MPK/PKU security initialized");

    // 2.8.5. セルローダー / ライブアップデート / DriverDomain の基盤初期化
    info!(target: "init", "Initializing cell loader (early)");
    loader::init_kernel_cell();
    register_kernel_symbols();
    loader::live_update::init();
    loader::live_update::set_active_cores(crate::cpu::count() as u64);
    crate::driver_domain::init();
    info!(target: "init", "Cell loader/live update/DriverDomain initialized");

    // 2.9. Boot artifact handoff からドライバ Cells をロード
    info!(target: "init", "Loading driver Cells from boot artifacts...");
    let boot_artifacts = context.boot_info_view().boot_artifacts();
    let loaded_cells = loader::boot_artifacts::load_cells_from_boot_artifacts(&boot_artifacts);
    if loaded_cells > 0 {
        info!(
            target: "init",
            "Loaded {} driver Cell(s) from boot artifacts",
            loaded_cells
        );
    } else {
        debug!(target: "init", "No boot artifacts or no Cells found");
    }
}

fn phase_driver_bringup() -> bool {
    init_hid_and_serial_drivers();

    // 3.5.5 - 3.5.7. Storage and USB controller scanning
    init_nvme_controllers();
    init_ahci_controllers();
    init_usb_controllers();
    log_driver_registry_summary();

    // 3.6. システム統合 (PCI掃描/デバイス初期化) をネットワークより先に行う
    initialize_system_integration()
}

fn phase_post_driver_services(context: &KernelBootContext) {
    init_network_infra();

    // 3.7. ファイルシステム（memfs）の初期化
    info!(target: "init", "Initializing memory filesystem");
    fs::init_shell_fs();
    info!(target: "init", "Memory filesystem initialized");

    // 3.8. WAL / PMEM / KGDB initialization
    init_durability_and_kgdb(context);
}

fn runtime_interrupts_enabled(_context: &KernelBootContext) -> bool {
    boot_cmdline_allows_interrupts(_context.cmdline)
}

#[derive(Clone, Copy)]
struct RuntimeTestRequest {
    profile: &'static str,
    case_filter: Option<&'static str>,
}

fn exit_with_runtime_summary(summary: crate::test::runtime_dispatch::RuntimeRunSummary) -> ! {
    use hal::port_io::PortU32;

    let mut port = PortU32::new(0xf4);
    if summary.is_success() {
        port.write(0x10u32);
    } else {
        port.write(0x11u32);
    }
    // LOOP_PROOF: mode=halt; reason=Runtime summary path intentionally halts forever after publishing the terminal QEMU exit code.;
    loop {
        x86_64::instructions::hlt();
    }
}

fn requested_runtime_test(context: &KernelBootContext) -> Option<RuntimeTestRequest> {
    #[cfg(feature = "run-integration-tests")]
    {
        return Some(RuntimeTestRequest {
            profile: "pr-required",
            case_filter: None,
        });
    }

    context.cmdline.and_then(|cmdline| {
        util::get_cmdline_option(cmdline, "run_integration").map(|profile| RuntimeTestRequest {
            profile,
            case_filter: util::get_cmdline_option(cmdline, "run_case"),
        })
    })
}

fn schedule_runtime_tests_if_requested(context: &KernelBootContext) {
    let Some(request) = requested_runtime_test(context) else {
        return;
    };

    match request.case_filter {
        Some(case_id) => info!(
            target: "init",
            "Scheduling runtime test profile '{}' case '{}' after executor handoff",
            request.profile,
            case_id
        ),
        None => info!(
            target: "init",
            "Scheduling runtime test profile '{}' after executor handoff",
            request.profile
        ),
    }

    let cpu_count = crate::cpu::count() as usize;
    let _target_cpu = if cpu_count > 2 {
        cpu_count - 1
    } else {
        cpu_count.saturating_sub(1)
    };

    #[cfg(feature = "qemu-test-export")]
    crate::task::spawn_on_cpu_with_priority(target_cpu, crate::task::Priority::High, async move {
        info!(
            target: "init",
            "Runtime test task starting on cpu={} profile='{}'",
            target_cpu,
            request.profile
        );
        crate::task::yield_now().await;
        let summary = crate::test::runtime_dispatch::run(request.profile, request.case_filter);
        exit_with_runtime_summary(summary);
    });

    #[cfg(not(feature = "qemu-test-export"))]
    crate::task::spawn_with_priority(
        async move {
            info!(
                target: "init",
                "Runtime test task starting profile='{}'",
                request.profile
            );
            crate::task::yield_now().await;
            let summary = crate::test::runtime_dispatch::run(request.profile, request.case_filter);
            exit_with_runtime_summary(summary);
        },
        crate::task::Priority::High,
        None,
    );
}

fn resolve_shell_mode(
    context: &KernelBootContext,
    graphics_console_ready: bool,
) -> crate::shell::session::ShellLaunchMode {
    let mode =
        crate::shell::session::shell_launch_mode_from_boot_policy(&context.boot_info().boot_policy);
    let adjusted_mode = crate::shell::session::adjust_shell_launch_mode_for_console_availability(
        mode,
        graphics_console_ready,
    );
    if adjusted_mode != mode {
        warn!(
            target: "init",
            "Framebuffer console unavailable; falling back shell mode {:?} -> {:?}",
            mode,
            adjusted_mode
        );
    }

    info!(target: "init", "Shell launch mode: {:?}", adjusted_mode);
    adjusted_mode
}

/// Scan PCI bus for USB xHCI controllers and initialize them.
pub(crate) fn init_usb_controllers() {
    info!(target: "init", "Scanning for USB xHCI controllers...");

    use crate::driver_registry::register_driver;
    use crate::drivers::usb::UsbDriverWrapper;
    use alloc::boxed::Box;

    let devices = crate::platform::pci::find_by_class(0x0C, 0x03);
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

        let mut standalone_ctx = kernel_api::abi::driver::DriverContext::for_pci(
            base_virt,
            device_info.interrupt_line as u32,
            device_info.vendor_id.0,
            device_info.device_id.0,
            ((device_info.class_code.class as u32) << 16)
                | ((device_info.class_code.subclass as u32) << 8)
                | device_info.class_code.prog_if as u32,
            device_info.packed_locator(),
        );
        standalone_ctx.device_address_secondary = 0;
        match crate::loader::staged_pci::try_start_for_device(device_info, standalone_ctx) {
            crate::loader::staged_pci::StagedPciBindOutcome::Started { .. }
            | crate::loader::staged_pci::StagedPciBindOutcome::AlreadyBound => {
                info!(target: "init", "USB xHCI controller initialized via staged standalone driver");
                continue;
            }
            crate::loader::staged_pci::StagedPciBindOutcome::Failed(reason) => {
                warn!(target: "init", "{}; falling back to built-in xHCI path", reason);
            }
            crate::loader::staged_pci::StagedPciBindOutcome::NoMatch => {}
        }

        let usb_handle = register_driver(Box::new(UsbDriverWrapper::new(
            base_virt,
            device_info.packed_locator(),
        )));
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
    let context = KernelBootContext::new(boot_info);

    phase_entry_and_early_cpu(&context);
    phase_early_kernel_substrate(&context);
    start_async_boot_runtime(context);
}
