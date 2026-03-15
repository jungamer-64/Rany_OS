// ============================================================================
// kernel/src/kernel_main/kernel_runtime.rs
// ============================================================================
//! カーネルのランタイム機能（タスクスポーン、統計表示、シンボル登録など）
//!! カーネルの初期化後、Executor上で動作するタスクをスポーンする関数や、システム統計を表示する関数などを定義する。
use super::*;
use alloc::sync::Arc;
use core::future::poll_fn;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use core::task::Poll;
use log::debug;

const ASYNC_BOOT_STAGE_COUNT: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum AsyncBootStage {
    Platform = 0,
    Graphics = 1,
    CoreServices = 2,
    Driver = 3,
    PostDriver = 4,
    Finalizer = 5,
}

impl AsyncBootStage {
    const fn index(self) -> usize {
        self as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum AsyncBootStageStatus {
    Pending = 0,
    Running = 1,
    Complete = 2,
}

struct BootStageLatch {
    complete: AtomicBool,
    waker: crate::sync::AtomicWaker,
}

impl BootStageLatch {
    const fn new() -> Self {
        Self {
            complete: AtomicBool::new(false),
            waker: crate::sync::AtomicWaker::new(),
        }
    }

    fn complete(&self) {
        self.complete.store(true, Ordering::Release);
        self.waker.wake();
    }

    fn is_complete(&self) -> bool {
        self.complete.load(Ordering::Acquire)
    }

    async fn wait(&self) {
        poll_fn(|cx| {
            if self.is_complete() {
                return Poll::Ready(());
            }

            self.waker.register(cx.waker());
            if self.is_complete() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await
    }
}

struct AsyncBootStageState {
    status: AtomicU8,
    latch: BootStageLatch,
}

impl AsyncBootStageState {
    const fn new() -> Self {
        Self {
            status: AtomicU8::new(AsyncBootStageStatus::Pending as u8),
            latch: BootStageLatch::new(),
        }
    }

    fn mark_running(&self) {
        self.status
            .store(AsyncBootStageStatus::Running as u8, Ordering::Release);
    }

    fn mark_complete(&self) {
        self.status
            .store(AsyncBootStageStatus::Complete as u8, Ordering::Release);
        self.latch.complete();
    }

    fn status(&self) -> AsyncBootStageStatus {
        match self.status.load(Ordering::Acquire) {
            x if x == AsyncBootStageStatus::Pending as u8 => AsyncBootStageStatus::Pending,
            x if x == AsyncBootStageStatus::Running as u8 => AsyncBootStageStatus::Running,
            _ => AsyncBootStageStatus::Complete,
        }
    }
}

struct AsyncBootCoordinator {
    graphics_console_ready: AtomicBool,
    integration_ready: AtomicBool,
    stages: [AsyncBootStageState; ASYNC_BOOT_STAGE_COUNT],
}

impl AsyncBootCoordinator {
    fn new() -> Self {
        Self {
            graphics_console_ready: AtomicBool::new(false),
            integration_ready: AtomicBool::new(false),
            stages: [const { AsyncBootStageState::new() }; ASYNC_BOOT_STAGE_COUNT],
        }
    }

    fn stage(&self, stage: AsyncBootStage) -> &AsyncBootStageState {
        &self.stages[stage.index()]
    }

    fn mark_stage_running(&self, stage: AsyncBootStage) {
        self.stage(stage).mark_running();
    }

    fn mark_stage_complete(&self, stage: AsyncBootStage) {
        self.stage(stage).mark_complete();
    }

    async fn wait_for_stage(&self, stage: AsyncBootStage) {
        self.stage(stage).latch.wait().await;
    }

    fn set_graphics_console_ready(&self, ready: bool) {
        self.graphics_console_ready.store(ready, Ordering::Release);
    }

    fn graphics_console_ready(&self) -> bool {
        self.graphics_console_ready.load(Ordering::Acquire)
    }

    fn set_integration_ready(&self, ready: bool) {
        self.integration_ready.store(ready, Ordering::Release);
    }

    fn integration_ready(&self) -> bool {
        self.integration_ready.load(Ordering::Acquire)
    }
}

fn async_boot_stage_target_cpu(stage: AsyncBootStage, active_cpus: usize) -> usize {
    let max_cpu = active_cpus.saturating_sub(1);
    let preferred = match stage {
        AsyncBootStage::Platform => 0,
        AsyncBootStage::Graphics => 1,
        AsyncBootStage::CoreServices => 2,
        AsyncBootStage::Driver => 3,
        AsyncBootStage::PostDriver => 3,
        AsyncBootStage::Finalizer => 0,
    };
    preferred.min(max_cpu)
}

fn log_executor_interrupt_policy(allow_interrupts: bool) {
    if allow_interrupts {
        #[cfg(feature = "qemu-test-export")]
        info!(
            target: "init",
            "Executor interrupt policy: enabled (qemu-test-export mode)"
        );
        #[cfg(not(feature = "qemu-test-export"))]
        info!(
            target: "init",
            "Executor interrupt policy: enabled"
        );
    } else {
        info!(
            target: "init",
            "Executor interrupt policy: disabled by cmdline option qemu_no_if=1"
        );
    }
}

async fn run_platform_stage(context: KernelBootContext, coordinator: Arc<AsyncBootCoordinator>) {
    coordinator.mark_stage_running(AsyncBootStage::Platform);
    phase_platform_and_security_base(&context);
    coordinator.mark_stage_complete(AsyncBootStage::Platform);
}

async fn run_graphics_stage(context: KernelBootContext, coordinator: Arc<AsyncBootCoordinator>) {
    coordinator.mark_stage_running(AsyncBootStage::Graphics);
    coordinator.set_graphics_console_ready(phase_graphics_console(&context));
    coordinator.mark_stage_complete(AsyncBootStage::Graphics);
}

async fn run_core_services_stage(
    context: KernelBootContext,
    coordinator: Arc<AsyncBootCoordinator>,
) {
    coordinator.mark_stage_running(AsyncBootStage::CoreServices);
    coordinator.wait_for_stage(AsyncBootStage::Platform).await;
    phase_core_services_base(&context);
    coordinator.mark_stage_complete(AsyncBootStage::CoreServices);
}

async fn run_driver_stage(context: KernelBootContext, coordinator: Arc<AsyncBootCoordinator>) {
    coordinator.mark_stage_running(AsyncBootStage::Driver);
    coordinator
        .wait_for_stage(AsyncBootStage::CoreServices)
        .await;
    coordinator.set_integration_ready(phase_driver_bringup());
    coordinator.mark_stage_complete(AsyncBootStage::Driver);
    let _ = context;
}

async fn run_post_driver_stage(context: KernelBootContext, coordinator: Arc<AsyncBootCoordinator>) {
    coordinator.mark_stage_running(AsyncBootStage::PostDriver);
    coordinator.wait_for_stage(AsyncBootStage::Driver).await;
    phase_post_driver_services(&context);
    coordinator.mark_stage_complete(AsyncBootStage::PostDriver);
}

fn finalize_runtime_boot(context: KernelBootContext, coordinator: &AsyncBootCoordinator) {
    debug!(
        target: "init",
        "Finalizing async boot after early executor handoff"
    );

    io::io_scheduler::init_io_scheduler();

    // Aggregation is performed in the executor idle loop; explicit aggregator
    // spawn is not required in the normal runtime path.
    debug!(target: "init", "Log aggregation will run on executor idle");
    debug!(
        target: "init",
        "Cell loader/live update already initialized (early path)"
    );

    info!(target: "init", "Initializing symbol table");
    unwind::init_symbol_table();
    info!(target: "init", "Symbol table initialized");

    info!(target: "init", "Initializing test framework");
    test::init();
    info!(target: "init", "Test framework initialized");

    coordinator.set_integration_ready(retry_system_integration_if_needed(
        coordinator.integration_ready(),
    ));

    match crate::io::iommu::vendors::intel::controller::init_global::start_runtime_services() {
        Ok(0) => {}
        Ok(count) => info!(
            target: "init",
            "Intel VT-d runtime services activated for {} controller(s)",
            count
        ),
        Err(err) => warn!(
            target: "init",
            "Intel VT-d runtime services activation failed: {:?}",
            err
        ),
    }

    let allow_interrupts = runtime_interrupts_enabled(&context);
    crate::task::configure_runtime_interrupts(allow_interrupts);
    if allow_interrupts {
        if !crate::interrupts::are_interrupts_enabled() {
            crate::interrupts::enable_interrupts();
        }
    } else if crate::interrupts::are_interrupts_enabled() {
        crate::interrupts::disable_interrupts();
    }

    let apic_timer_runtime = crate::interrupts::transition_to_runtime_local_timers();
    crate::task::transition_to_runtime_run_mode();
    if allow_interrupts && crate::cpu::count() > 1 {
        crate::cpu::broadcast_ipi(crate::cpu::IpiKind::ExecutorWake);
    }
    if apic_timer_runtime {
        info!(target: "run", "Runtime handoff switched to per-core APIC timers");
    }

    print_system_stats();
    info!(target: "init", "Scheduling runtime tasks onto per-core executors");

    let mut shell_mode = None;
    for_each_async_boot_completion_milestone(|step| match step {
        AsyncBootCompletionMilestone::ResolveShellMode => {
            shell_mode = Some(resolve_shell_mode(
                &context,
                coordinator.graphics_console_ready(),
            ));
        }
        AsyncBootCompletionMilestone::SpawnKernelTasks => {
            let shell_mode = shell_mode.expect("shell mode must be resolved before spawn");
            spawn_kernel_tasks(shell_mode);
            info!(target: "init", "Kernel tasks spawned");
        }
        AsyncBootCompletionMilestone::BootComplete => {
            info!(target: "boot", "BOOT COMPLETE!");
        }
    });

    schedule_runtime_tests_if_requested(&context);
}

async fn run_finalizer_stage(context: KernelBootContext, coordinator: Arc<AsyncBootCoordinator>) {
    coordinator.mark_stage_running(AsyncBootStage::Finalizer);
    coordinator.wait_for_stage(AsyncBootStage::Graphics).await;
    coordinator.wait_for_stage(AsyncBootStage::PostDriver).await;
    finalize_runtime_boot(context, &coordinator);
    coordinator.mark_stage_complete(AsyncBootStage::Finalizer);
}

fn spawn_async_boot_orchestrator(
    context: KernelBootContext,
    coordinator: Arc<AsyncBootCoordinator>,
) {
    let active_cpus = crate::task::executor_slot_count().max(1);

    let platform = coordinator.clone();
    crate::task::spawn_on_cpu_with_priority(
        async_boot_stage_target_cpu(AsyncBootStage::Platform, active_cpus),
        crate::task::Priority::High,
        async move {
            run_platform_stage(context, platform).await;
        },
    );

    let graphics = coordinator.clone();
    crate::task::spawn_on_cpu_with_priority(
        async_boot_stage_target_cpu(AsyncBootStage::Graphics, active_cpus),
        crate::task::Priority::High,
        async move {
            run_graphics_stage(context, graphics).await;
        },
    );

    let core = coordinator.clone();
    crate::task::spawn_on_cpu_with_priority(
        async_boot_stage_target_cpu(AsyncBootStage::CoreServices, active_cpus),
        crate::task::Priority::High,
        async move {
            run_core_services_stage(context, core).await;
        },
    );

    let driver = coordinator.clone();
    crate::task::spawn_on_cpu_with_priority(
        async_boot_stage_target_cpu(AsyncBootStage::Driver, active_cpus),
        crate::task::Priority::High,
        async move {
            run_driver_stage(context, driver).await;
        },
    );

    let post_driver = coordinator.clone();
    crate::task::spawn_on_cpu_with_priority(
        async_boot_stage_target_cpu(AsyncBootStage::PostDriver, active_cpus),
        crate::task::Priority::High,
        async move {
            run_post_driver_stage(context, post_driver).await;
        },
    );

    crate::task::spawn_on_cpu_with_priority(
        async_boot_stage_target_cpu(AsyncBootStage::Finalizer, active_cpus),
        crate::task::Priority::High,
        async move {
            run_finalizer_stage(context, coordinator).await;
        },
    );
}

pub(crate) fn start_async_boot_runtime(context: KernelBootContext) -> ! {
    info!(
        target: "init",
        "Phase-4 early executor handoff entering the per-core executor path"
    );

    let allow_interrupts = runtime_interrupts_enabled(&context);
    for_each_executor_online_milestone(|step| match step {
        ExecutorOnlineMilestone::ConfigureBootRunMode => {
            crate::task::configure_boot_run_mode(allow_interrupts);
            log_executor_interrupt_policy(allow_interrupts);
        }
        ExecutorOnlineMilestone::ReleaseWorkers => {
            crate::cpu::release_workers();
        }
        ExecutorOnlineMilestone::StartExecutorRun => {
            info!(target: "run", "Starting per-core executor main loop");
        }
    });

    let coordinator = Arc::new(AsyncBootCoordinator::new());
    spawn_async_boot_orchestrator(context, coordinator);

    crate::cpu::set_stage(0, crate::cpu::CpuStage::ExecutorRunning);
    task::run_forever(0);
}

/// ネットワークブートストラップ（完全非同期）
///
/// Executor起動後にスポーンされ、VirtIO-Net/mlx5 ドライバの port registration・
/// DHCP完了待機・接続性確認をすべてasyncコンテキストで実行する。
/// 設計書 §3「Async-First」原則に準拠し、同期ブロッキングI/Oを排除する。
/// `net::runtime::device` が `init_dhcp_runtime()` 経由で DHCPv4/v6 クライアント
/// タスクを `spawn_global` するため、port registration 後は DHCP が自動的に
/// 非同期で走る。このタスクは状態が Bound になるのを待ってから ping で
/// 接続性を確認する。
fn aggregate_port_runtime_stats() -> (usize, u64, u64, u64, u64) {
    let keys = crate::net::runtime::device::list_port_keys(None);
    let mut rx_packets = 0u64;
    let mut tx_packets = 0u64;
    let mut tx_errors = 0u64;
    let mut rx_errors = 0u64;

    for key in &keys {
        if let Some(stats) = crate::net::runtime::device::port_stats(*key) {
            rx_packets = rx_packets.saturating_add(stats.rx_packets);
            tx_packets = tx_packets.saturating_add(stats.tx_packets);
            tx_errors = tx_errors.saturating_add(stats.tx_errors);
            rx_errors = rx_errors.saturating_add(stats.rx_errors);
        }
    }

    (keys.len(), rx_packets, tx_packets, tx_errors, rx_errors)
}

async fn network_bootstrap_task() {
    info!(target: "net_boot", "Network bootstrap task started (async)");

    let virtio_net_present = crate::drivers::virtio::virtio_net_driver_adapter(0)
        .info()
        .flags
        != 0;
    if virtio_net_present {
        let virtio_port_registered = crate::net::runtime::device::port_info(
            crate::net::runtime::device::NetDeviceKey::Virtio(0),
        )
        .is_some();
        if virtio_port_registered {
            info!(
                target: "net_boot",
                "VirtIO-Net port already registered; skipping startup"
            );
        } else {
            // VirtIO-Net ドライバ登録と port runtime への接続。
            info!(target: "net_boot", "Registering VirtIO-Net driver via DriverRegistry");
            {
                use crate::net::drivers::virtio_registry::VirtioNetDriver;
                use alloc::boxed::Box;
                use driver_registry::register_driver;

                let net_handle = register_driver(Box::new(VirtioNetDriver::new()));
                if let Err(e) = driver_registry::driver_registry()
                    .probe_and_start(net_handle.expect("Failed to register VirtIO-Net driver"))
                {
                    warn!(target: "net_boot", "VirtIO-Net driver init failed: {:?}", e);
                } else {
                    info!(target: "net_boot", "VirtIO-Net driver initialized via DriverRegistry");
                }
            }
        }
    } else {
        info!(
            target: "net_boot",
            "VirtIO-Net device not present; continuing with non-VirtIO probes (mlx5)"
        );
    }

    // ConnectX ファミリ (mlx5) ドライバのPCI検出・登録
    let staged_mlx5_started = {
        let mut started = false;
        for &(_vendor_id, device_id) in crate::net::drivers::mlx5_registry::SUPPORTED_DEVICE_IDS {
            let pci_devices = crate::io::pci::find_by_id(
                crate::net::drivers::mlx5_registry::MELLANOX_VENDOR_ID,
                device_id,
            );
            let Some(native_dev) = pci_devices.first().cloned() else {
                continue;
            };
            let dev = crate::platform::pci::from_native_device(native_dev);
            let Some(bar0) = dev.bars[0] else {
                continue;
            };

            let mut ctx = kernel_api::abi::driver::DriverContext::for_pci(
                bar0.base(),
                dev.interrupt_line as u32,
                dev.vendor_id.0,
                dev.device_id.0,
                ((dev.class_code.class as u32) << 16)
                    | ((dev.class_code.subclass as u32) << 8)
                    | dev.class_code.prog_if as u32,
                dev.packed_locator(),
            );
            ctx.device_address_secondary = 0;

            match crate::loader::staged_pci::try_start_for_device(&dev, ctx) {
                crate::loader::staged_pci::StagedPciBindOutcome::Started { .. }
                | crate::loader::staged_pci::StagedPciBindOutcome::AlreadyBound => {
                    info!(
                        target: "net_boot",
                        "ConnectX (mlx5) initialized via staged standalone driver"
                    );
                    started = true;
                    break;
                }
                crate::loader::staged_pci::StagedPciBindOutcome::Failed(reason) => {
                    warn!(target: "net_boot", "{}; falling back to built-in mlx5 path", reason);
                    break;
                }
                crate::loader::staged_pci::StagedPciBindOutcome::NoMatch => {}
            }
        }
        started
    };
    if !staged_mlx5_started {
        use crate::net::drivers::mlx5_registry::Mlx5ConnectXDriver;
        use alloc::boxed::Box;
        use driver_registry::register_driver;

        info!(target: "net_boot", "Probing ConnectX (mlx5) via DriverRegistry");
        let mlx5_handle = register_driver(Box::new(Mlx5ConnectXDriver::new()));
        match mlx5_handle {
            Ok(handle) => {
                match driver_registry::driver_registry().probe_and_start(handle) {
                    Ok(()) => {
                        info!(target: "net_boot", "ConnectX (mlx5) driver initialized via DriverRegistry");
                    }
                    Err(e) => {
                        // ConnectX NIC が実機に接続されていない場合はNotFoundが返るので
                        // 警告レベルで報告のみ（起動失敗にはしない）
                        info!(target: "net_boot", "ConnectX (mlx5) not found or init failed: {:?}", e);
                    }
                }
            }
            Err(e) => {
                warn!(target: "net_boot", "Failed to register mlx5 driver: {:?}", e);
            }
        }
    }

    // Yield して tx_worker / DHCPクライアント等のバックグラウンドタスクに実行機会を与える
    task::yield_now().await;

    // VirtIO / mlx5 probe 後に有効なポートがなければ DHCP 待機は行わない。
    let virtio_port_ready = crate::net::runtime::device::port_info(
        crate::net::runtime::device::NetDeviceKey::Virtio(0),
    )
    .is_some();
    let mlx5_port_ready =
        crate::net::runtime::device::port_info(crate::net::runtime::device::NetDeviceKey::Mlx5(0))
            .is_some();
    let (port_count, rx_packets, tx_packets, tx_errors, rx_errors) = aggregate_port_runtime_stats();
    if port_count == 0 {
        info!(
            target: "net_boot",
            "No active network ports after driver probes; skipping DHCP/connectivity checks (stack_init={} virtio_port={} mlx5_port={} ports={} rx={} tx={} tx_err={} rx_err={})",
            crate::net::runtime::device::is_initialized(),
            virtio_port_ready,
            mlx5_port_ready,
            port_count,
            rx_packets,
            tx_packets,
            tx_errors,
            rx_errors
        );
        return;
    }

    // DHCPクライアントが Bound 状態になるのを待機（最大10秒）
    info!(target: "net_boot", "Waiting for DHCP lease acquisition (async)...");
    let mut dhcp_bound = false;
    for _ in 0..100 {
        // 100ms × 100 = 最大10秒
        task::sleep_ms(100).await;

        let states =
            crate::net::api::dhcp::list_dhcp_states_in(crate::net::runtime::default_runtime())
                .await;
        if states.iter().any(|state| state.state.v4_state == "Bound") {
            for state in states
                .into_iter()
                .filter(|state| state.state.v4_state == "Bound")
            {
                info!(
                    target: "net_boot",
                    "DHCP lease acquired: if{} ip={:?}",
                    state.if_id,
                    state.state.v4_assigned_ip
                );
            }
            dhcp_bound = true;
            break;
        }
    }

    if !dhcp_bound {
        warn!(target: "net_boot", "DHCP did not reach Bound state within timeout; using default config");
    }

    // 非同期ping: ゲートウェイへの接続性確認
    let ping_targets: alloc::vec::Vec<_> = if dhcp_bound {
        crate::net::api::config::list_interface_configs_in(crate::net::runtime::default_runtime())
            .await
            .into_iter()
            .filter_map(|cfg| {
                if cfg.gateway != [0, 0, 0, 0] {
                    Some((cfg.if_id, cfg.gateway))
                } else {
                    None
                }
            })
            .collect()
    } else {
        alloc::vec::Vec::new()
    };

    if ping_targets.is_empty() {
        warn!(target: "net_boot", "No gateway available (DHCP not bound); skipping connectivity check");
        let (port_count, rx_packets, tx_packets, tx_errors, rx_errors) =
            aggregate_port_runtime_stats();
        info!(
            target: "net_boot",
            "Network bootstrap complete (no DHCP): ports={} rx={} tx={} tx_err={} rx_err={}",
            port_count,
            rx_packets,
            tx_packets,
            tx_errors,
            rx_errors
        );
        return;
    };

    for (if_id, ping_target) in ping_targets {
        info!(target: "net_boot", "Async connectivity check if{} -> {:?}", if_id, ping_target);
        match crate::net::api::icmp::ping_in(crate::net::runtime::default_runtime(), ping_target, 1)
            .await
        {
            Ok(echo) => info!(
                target: "net_boot",
                "Async ping success if{} rtt={} us",
                if_id,
                echo.rtt_us
            ),
            Err(e) => warn!(target: "net_boot", "Async ping failed if{}: {:?}", if_id, e),
        }
    }

    let (port_count, rx_packets, tx_packets, tx_errors, rx_errors) = aggregate_port_runtime_stats();
    info!(
        target: "net_boot",
        "Network bootstrap complete: ports={} rx={} tx={} tx_err={} rx_err={}",
        port_count,
        rx_packets,
        tx_packets,
        tx_errors,
        rx_errors
    );
}

fn spawn_shell_tasks(shell_mode: crate::shell::session::ShellLaunchMode) {
    use crate::shell::session::{ShellLaunchMode, spawn_console_shell, spawn_serial_shell};

    match shell_mode {
        ShellLaunchMode::Console => spawn_console_shell(),
        ShellLaunchMode::Serial => spawn_serial_shell(),
        ShellLaunchMode::Both => {
            spawn_serial_shell();
            spawn_console_shell();
        }
        ShellLaunchMode::Off => {
            info!(target: "init", "Shell launch disabled by boot policy (shell=off)");
        }
    }
}

pub(crate) fn spawn_core_runtime_tasks() {
    use task::Task;

    // === ネットワークブートストラップ（完全非同期） ===
    // VirtIO-Netドライバ登録 → DHCP → ping をExecutor上で非同期実行
    task::spawn_task(Task::new(network_bootstrap_task()));
    info!(target: "init", "Network bootstrap task spawned (async)");

    // Host-to-guest communication endpoint for QEMU hostfwd (tcp:5555 -> guest:80).
    crate::net::services::http::server::start_once();

    // [PR-COMPLIANCE] ICMP Responder activation log
    info!(target: "init", "ICMP responder server active");

    // Initialize network event handler and spawn the background task for async networking
    crate::net::l4::endpoint::handler::init_network_event_handler();
    task::spawn_task(crate::task::Task::new(
        crate::net::l4::endpoint::tcp_rx::network_event_task(),
    ));

    // Spawn async timeout processing task (TCP retransmit, keep-alive, ARP expiry, etc.)
    task::spawn_task(crate::task::Task::new(
        crate::net::runtime::stack::timeout_task(),
    ));
}

pub(crate) fn spawn_demo_runtime_tasks() {
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
    task::spawn_task(Task::new(async move {
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

    task::spawn_task(Task::new(async move {
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
    task::spawn_task(Task::new(async {
        info!(target: "task3", "Preemption stats demo started");

        for i in 0..3 {
            debug!(target: "task3", "Iteration {}", i);
            task::sleep_ms(200).await;

            let stats = task::aggregate_preemption_stats();
            debug!(target: "task3", "Preemption Stats - Forced: {}, Voluntary: {}",
                stats.forced_preemptions,
                stats.voluntary_yields
            );
        }

        info!(target: "task3", "Preemption demo completed");
    }));

    // タスク4: メモリ統計モニタリング
    task::spawn_task(Task::new(async {
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
    task::spawn_task(Task::new(async {
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

    // タスク (ネットワーク ping テスト): ゲートウェイへの ICMP を試して結果をログ出力
    task::spawn_task(Task::new(async {
        info!(target: "net_test", "Network ping test: waiting for stack to be ready...");

        // DHCP/スタックからゲートウェイを取得
        let gw_opt =
            crate::net::api::config::list_interface_configs_in(crate::net::runtime::default_runtime())
            .await
            .into_iter()
            .map(|cfg| cfg.gateway)
            .find(|gw| *gw != [0, 0, 0, 0]);
        let Some(gw) = gw_opt else {
            warn!(target: "net_test", "No gateway configured yet; skipping ping test");
            return;
        };
        info!(target: "net_test", "Sending ICMP echo to {}.{}.{}.{} seq=1", gw[0], gw[1], gw[2], gw[3]);
        // 完全非同期: IcmpEchoFuture 経由で送信 + 応答待機
        match crate::net::api::icmp::ping_in(crate::net::runtime::default_runtime(), gw, 1).await {
            Ok(echo) => info!(target: "net_test", "Ping success rtt={} us", echo.rtt_us),
            Err(e) => warn!(target: "net_test", "Ping failed: {:?}", e),
        }

        let (port_count, rx_packets, tx_packets, tx_errors, rx_errors) =
            aggregate_port_runtime_stats();
        info!(
            target: "net_test",
            "Port runtime stats after ping: ports={} rx={} tx={} tx_err={} rx_err={}",
            port_count,
            rx_packets,
            tx_packets,
            tx_errors,
            rx_errors
        );
    }));

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
    // タスク8: 非同期シリアルシェル（IRQ4駆動）
    // Serial Shell spawned above
    /*
    task::spawn_task(Task::new(async {
        info!(target: "task8", "Async serial shell task starting...");
        // シェルをすぐに開始（デバッグ用）
        shell::async_shell::run_async_shell().await;
    }));
    */

    // タスク9: グラフィカルシェル（フレームバッファ描画）
    // タスク9: グラフィカルシェル（フレームバッファ描画）
    // Console Shell spawned above
    /*
    executor.spawn(Task::new(async {
        info!(target: "task9", "Graphical shell task starting...");

        // グラフィカルシェルを開始 (initはkmainで完了と想定)
        shell::graphical::start();

        info!(target: "task9", "Graphical shell started - running async...");

        // 非同期メインループ（完全async版）
        shell::graphical::run_async_shell().await;
    }));
    */
}

/// カーネルタスクをスポーン
pub(crate) fn spawn_kernel_tasks(shell_mode: crate::shell::session::ShellLaunchMode) {
    spawn_shell_tasks(shell_mode);
    spawn_core_runtime_tasks();
    spawn_demo_runtime_tasks();
}

/// システム統計を表示
pub(crate) fn print_system_stats() {
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
pub(crate) fn register_kernel_symbols() {
    debug!(
        target: "loader",
        "Kernel API symbol is resolved via dedicated loader path"
    );
}

/// ExoRustロゴを表示
pub(crate) fn print_logo() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, Ordering};

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn async_boot_stage_target_cpu_falls_back_to_bsp_on_low_core_counts() {
        assert_eq!(async_boot_stage_target_cpu(AsyncBootStage::Platform, 1), 0);
        assert_eq!(async_boot_stage_target_cpu(AsyncBootStage::Graphics, 1), 0);
        assert_eq!(
            async_boot_stage_target_cpu(AsyncBootStage::CoreServices, 2),
            1
        );
        assert_eq!(async_boot_stage_target_cpu(AsyncBootStage::Driver, 3), 2);
        assert_eq!(
            async_boot_stage_target_cpu(AsyncBootStage::PostDriver, 2),
            1
        );
        assert_eq!(async_boot_stage_target_cpu(AsyncBootStage::Finalizer, 4), 0);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn async_boot_stage_status_transitions_to_complete() {
        let coordinator = AsyncBootCoordinator::new();
        assert_eq!(
            coordinator.stage(AsyncBootStage::Platform).status(),
            AsyncBootStageStatus::Pending
        );
        coordinator.mark_stage_running(AsyncBootStage::Platform);
        assert_eq!(
            coordinator.stage(AsyncBootStage::Platform).status(),
            AsyncBootStageStatus::Running
        );
        coordinator.mark_stage_complete(AsyncBootStage::Platform);
        assert_eq!(
            coordinator.stage(AsyncBootStage::Platform).status(),
            AsyncBootStageStatus::Complete
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn async_boot_waiter_releases_after_stage_completion() {
        let coordinator = Arc::new(AsyncBootCoordinator::new());
        let completed = Arc::new(AtomicBool::new(false));
        let mut executor = crate::task::TestExecutor::new();

        let wait_coordinator = coordinator.clone();
        let wait_completed = completed.clone();
        executor.spawn(crate::task::Task::new(async move {
            wait_coordinator
                .wait_for_stage(AsyncBootStage::Graphics)
                .await;
            wait_completed.store(true, Ordering::Release);
        }));

        executor.drive_once_for_test();
        assert!(!completed.load(Ordering::Acquire));

        coordinator.mark_stage_complete(AsyncBootStage::Graphics);
        executor.drive_once_for_test();
        assert!(completed.load(Ordering::Acquire));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn finalizer_waits_for_graphics_and_post_driver_completion() {
        let coordinator = Arc::new(AsyncBootCoordinator::new());
        let completed = Arc::new(AtomicBool::new(false));
        let mut executor = crate::task::TestExecutor::new();

        let wait_coordinator = coordinator.clone();
        let wait_completed = completed.clone();
        executor.spawn(crate::task::Task::new(async move {
            wait_coordinator
                .wait_for_stage(AsyncBootStage::Graphics)
                .await;
            wait_coordinator
                .wait_for_stage(AsyncBootStage::PostDriver)
                .await;
            wait_completed.store(true, Ordering::Release);
        }));

        executor.drive_once_for_test();
        coordinator.mark_stage_complete(AsyncBootStage::Graphics);
        executor.drive_once_for_test();
        assert!(!completed.load(Ordering::Acquire));

        coordinator.mark_stage_complete(AsyncBootStage::PostDriver);
        executor.drive_once_for_test();
        assert!(completed.load(Ordering::Acquire));
    }
}

/// Panicハンドラ
#[cfg(all(not(test), target_os = "none"))]
#[panic_handler]
pub(crate) fn panic(info: &core::panic::PanicInfo) -> ! {
    panic_handler::handle_panic(info)
}

// ============================================================================
// Global Allocator (Binary Only)
// ============================================================================
// Defined here to avoid conflict with the library crate `rany_os` which
// may also define an allocator for tests.
// Wrapper to delegate to memory::ALLOCATOR
pub(crate) struct GlobalAllocatorWrapper;

#[cfg(not(test))]
unsafe impl core::alloc::GlobalAlloc for GlobalAllocatorWrapper {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        crate::memory::ALLOCATOR.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        crate::memory::ALLOCATOR.dealloc(ptr, layout)
    }
}

#[cfg(not(test))]
#[global_allocator]
pub(crate) static GLOBAL_ALLOCATOR: GlobalAllocatorWrapper = GlobalAllocatorWrapper;

#[cfg(all(not(test), target_os = "none"))]
#[alloc_error_handler]
pub(crate) fn alloc_error_handler(layout: alloc::alloc::Layout) -> ! {
    crate::io::log::early_print("\n!!! ALLOCATION FAILED !!!\n");
    crate::io::log::early_print("Layout Size: ");
    crate::io::log::early_print_dec(layout.size() as u64);
    crate::io::log::early_print("\nLayout Align: ");
    crate::io::log::early_print_dec(layout.align() as u64);
    crate::io::log::early_print("\n");
    let recovered = crate::memory::oom_killer::try_free_memory();
    crate::io::log::early_print("OOM recovery attempt: ");
    crate::io::log::early_print(if recovered { "success\n" } else { "failed\n" });
    panic!(
        "allocation error: size={} align={} oom_recovered={}",
        layout.size(),
        layout.align(),
        recovered
    )
}
