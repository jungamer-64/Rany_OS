// ============================================================================
// kernel/src/kernel_main/kernel_runtime.rs
// ============================================================================
//! カーネルのランタイム機能（タスクスポーン、統計表示、シンボル登録など）
//!! カーネルの初期化後、Executor上で動作するタスクをスポーンする関数や、システム統計を表示する関数などを定義する。
use super::*;
use crate::{domain, heap, interrupts, io, task, unwind};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::{Future, poll_fn};
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use core::task::Poll;
use log::debug;

const ASYNC_BOOT_STAGE_COUNT: usize = 6;
const NET_BOOT_PING_TIMEOUT_MS: u64 = 1_500;

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

    const fn label(self) -> &'static str {
        match self {
            Self::Platform => "platform",
            Self::Graphics => "graphics",
            Self::CoreServices => "core_services",
            Self::Driver => "driver",
            Self::PostDriver => "post_driver",
            Self::Finalizer => "finalizer",
        }
    }

    const fn ap_round_robin_slot(self) -> Option<usize> {
        match self {
            Self::Platform => None,
            Self::Graphics => Some(0),
            Self::CoreServices => Some(1),
            Self::Driver => Some(2),
            Self::PostDriver => Some(3),
            Self::Finalizer => Some(4),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum AsyncBootStageStatus {
    Pending = 0,
    Running = 1,
    Complete = 2,
}

fn normalized_async_boot_ap_candidates(
    active_cpus: usize,
    topology_candidates: &[usize],
) -> Vec<usize> {
    let active_cpus = active_cpus.max(1).min(crate::per_cpu::MAX_CPUS);
    let mut normalized = Vec::new();

    if active_cpus <= 1 {
        return normalized;
    }

    for &candidate in topology_candidates {
        if candidate == 0 || candidate >= active_cpus || normalized.contains(&candidate) {
            continue;
        }
        normalized.push(candidate);
    }

    for candidate in 1..active_cpus {
        if !normalized.contains(&candidate) {
            normalized.push(candidate);
        }
    }

    normalized
}

fn async_boot_stage_target_cpu_with_candidates(
    stage: AsyncBootStage,
    active_cpus: usize,
    topology_candidates: &[usize],
) -> usize {
    let active_cpus = active_cpus.max(1).min(crate::per_cpu::MAX_CPUS);
    if active_cpus <= 1 || matches!(stage, AsyncBootStage::Platform) {
        return 0;
    }

    let ap_candidates = normalized_async_boot_ap_candidates(active_cpus, topology_candidates);
    let Some(slot) = stage.ap_round_robin_slot() else {
        return 0;
    };

    ap_candidates
        .get(slot % ap_candidates.len().max(1))
        .copied()
        .unwrap_or(0)
}

#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) fn async_boot_stage_runtime_snapshot()
-> crate::async_boot_runtime_snapshot::AsyncBootStageRuntimeSnapshot {
    crate::async_boot_runtime_snapshot::async_boot_stage_runtime_snapshot()
}

fn reset_async_boot_stage_runtime_snapshot() {
    crate::async_boot_runtime_snapshot::reset_async_boot_stage_runtime_snapshot();
}

fn record_async_boot_stage_assigned_cpu(stage: AsyncBootStage, cpu_id: usize) {
    crate::async_boot_runtime_snapshot::record_async_boot_stage_assigned_cpu(stage.index(), cpu_id);
}

fn record_async_boot_stage_started_cpu(stage: AsyncBootStage, cpu_id: usize) {
    crate::async_boot_runtime_snapshot::record_async_boot_stage_started_cpu(stage.index(), cpu_id);
}

fn record_async_boot_stage_completed_cpu(stage: AsyncBootStage, cpu_id: usize) {
    crate::async_boot_runtime_snapshot::record_async_boot_stage_completed_cpu(
        stage.index(),
        cpu_id,
    );
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
    let topology_candidates = crate::mm::numa::topology::steal_candidates_for_cpu(0);
    async_boot_stage_target_cpu_with_candidates(stage, active_cpus, &topology_candidates)
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

async fn run_platform_stage(
    context: KernelBootContext,
    coordinator: Arc<AsyncBootCoordinator>,
    assigned_cpu: usize,
) {
    coordinator.mark_stage_running(AsyncBootStage::Platform);
    let current_cpu = crate::cpu::current_id();
    record_async_boot_stage_started_cpu(AsyncBootStage::Platform, current_cpu);
    info!(
        target: "init",
        "[async-boot] Platform stage starting on cpu={} assigned_cpu={}",
        current_cpu,
        assigned_cpu
    );
    phase_platform_and_security_base(&context);
    let current_cpu = crate::cpu::current_id();
    record_async_boot_stage_completed_cpu(AsyncBootStage::Platform, current_cpu);
    info!(
        target: "init",
        "[async-boot] Platform stage completed on cpu={} assigned_cpu={}",
        current_cpu,
        assigned_cpu
    );
    coordinator.mark_stage_complete(AsyncBootStage::Platform);
}

async fn run_graphics_stage(
    context: KernelBootContext,
    coordinator: Arc<AsyncBootCoordinator>,
    assigned_cpu: usize,
) {
    coordinator.mark_stage_running(AsyncBootStage::Graphics);
    let current_cpu = crate::cpu::current_id();
    record_async_boot_stage_started_cpu(AsyncBootStage::Graphics, current_cpu);
    info!(
        target: "init",
        "[async-boot] Graphics stage starting on cpu={} assigned_cpu={}",
        current_cpu,
        assigned_cpu
    );
    coordinator.set_graphics_console_ready(phase_graphics_console(&context));
    let current_cpu = crate::cpu::current_id();
    record_async_boot_stage_completed_cpu(AsyncBootStage::Graphics, current_cpu);
    info!(
        target: "init",
        "[async-boot] Graphics stage completed on cpu={} assigned_cpu={}",
        current_cpu,
        assigned_cpu
    );
    coordinator.mark_stage_complete(AsyncBootStage::Graphics);
}

async fn run_core_services_stage(
    context: KernelBootContext,
    coordinator: Arc<AsyncBootCoordinator>,
    assigned_cpu: usize,
) {
    coordinator.mark_stage_running(AsyncBootStage::CoreServices);
    let current_cpu = crate::cpu::current_id();
    record_async_boot_stage_started_cpu(AsyncBootStage::CoreServices, current_cpu);
    info!(
        target: "init",
        "[async-boot] CoreServices stage waiting for Platform on cpu={} assigned_cpu={}",
        current_cpu,
        assigned_cpu
    );
    coordinator.wait_for_stage(AsyncBootStage::Platform).await;
    let current_cpu = crate::cpu::current_id();
    info!(
        target: "init",
        "[async-boot] CoreServices stage starting on cpu={} assigned_cpu={}",
        current_cpu,
        assigned_cpu
    );
    phase_core_services_base(&context);
    let current_cpu = crate::cpu::current_id();
    record_async_boot_stage_completed_cpu(AsyncBootStage::CoreServices, current_cpu);
    info!(
        target: "init",
        "[async-boot] CoreServices stage completed on cpu={} assigned_cpu={}",
        current_cpu,
        assigned_cpu
    );
    coordinator.mark_stage_complete(AsyncBootStage::CoreServices);
}

async fn run_driver_stage(
    context: KernelBootContext,
    coordinator: Arc<AsyncBootCoordinator>,
    assigned_cpu: usize,
) {
    coordinator.mark_stage_running(AsyncBootStage::Driver);
    let current_cpu = crate::cpu::current_id();
    record_async_boot_stage_started_cpu(AsyncBootStage::Driver, current_cpu);
    info!(
        target: "init",
        "[async-boot] Driver stage waiting for CoreServices on cpu={} assigned_cpu={}",
        current_cpu,
        assigned_cpu
    );
    coordinator
        .wait_for_stage(AsyncBootStage::CoreServices)
        .await;
    let current_cpu = crate::cpu::current_id();
    info!(
        target: "init",
        "[async-boot] Driver stage starting on cpu={} assigned_cpu={}",
        current_cpu,
        assigned_cpu
    );
    coordinator.set_integration_ready(phase_driver_bringup());
    let current_cpu = crate::cpu::current_id();
    record_async_boot_stage_completed_cpu(AsyncBootStage::Driver, current_cpu);
    info!(
        target: "init",
        "[async-boot] Driver stage completed on cpu={} assigned_cpu={}",
        current_cpu,
        assigned_cpu
    );
    coordinator.mark_stage_complete(AsyncBootStage::Driver);
    let _ = context;
}

async fn run_post_driver_stage(
    context: KernelBootContext,
    coordinator: Arc<AsyncBootCoordinator>,
    assigned_cpu: usize,
) {
    coordinator.mark_stage_running(AsyncBootStage::PostDriver);
    let current_cpu = crate::cpu::current_id();
    record_async_boot_stage_started_cpu(AsyncBootStage::PostDriver, current_cpu);
    info!(
        target: "init",
        "[async-boot] PostDriver stage waiting for Driver on cpu={} assigned_cpu={}",
        current_cpu,
        assigned_cpu
    );
    coordinator.wait_for_stage(AsyncBootStage::Driver).await;
    let current_cpu = crate::cpu::current_id();
    info!(
        target: "init",
        "[async-boot] PostDriver stage starting on cpu={} assigned_cpu={}",
        current_cpu,
        assigned_cpu
    );
    phase_post_driver_services(&context);
    let current_cpu = crate::cpu::current_id();
    record_async_boot_stage_completed_cpu(AsyncBootStage::PostDriver, current_cpu);
    info!(
        target: "init",
        "[async-boot] PostDriver stage completed; publishing completion on cpu={} assigned_cpu={}",
        current_cpu,
        assigned_cpu
    );
    coordinator.mark_stage_complete(AsyncBootStage::PostDriver);
}

fn finalize_runtime_boot(context: KernelBootContext, coordinator: &AsyncBootCoordinator) {
    info!(
        target: "init",
        "Finalizing async boot after early executor handoff"
    );
    info!(
        target: "init",
        "Deferring I/O scheduler initialization until runtime tasks are active"
    );

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

async fn run_finalizer_stage(
    context: KernelBootContext,
    coordinator: Arc<AsyncBootCoordinator>,
    assigned_cpu: usize,
) {
    coordinator.mark_stage_running(AsyncBootStage::Finalizer);
    let current_cpu = crate::cpu::current_id();
    record_async_boot_stage_started_cpu(AsyncBootStage::Finalizer, current_cpu);
    info!(
        target: "init",
        "[async-boot] Finalizer stage waiting for Graphics on cpu={} assigned_cpu={}",
        current_cpu,
        assigned_cpu
    );
    coordinator.wait_for_stage(AsyncBootStage::Graphics).await;
    let current_cpu = crate::cpu::current_id();
    info!(
        target: "init",
        "[async-boot] Finalizer stage waiting for PostDriver on cpu={} assigned_cpu={}",
        current_cpu,
        assigned_cpu
    );
    coordinator.wait_for_stage(AsyncBootStage::PostDriver).await;
    let current_cpu = crate::cpu::current_id();
    info!(
        target: "init",
        "[async-boot] Finalizer stage starting on cpu={} assigned_cpu={}",
        current_cpu,
        assigned_cpu
    );
    finalize_runtime_boot(context, &coordinator);
    let current_cpu = crate::cpu::current_id();
    record_async_boot_stage_completed_cpu(AsyncBootStage::Finalizer, current_cpu);
    info!(
        target: "init",
        "[async-boot] Finalizer stage completed on cpu={} assigned_cpu={}",
        current_cpu,
        assigned_cpu
    );
    coordinator.mark_stage_complete(AsyncBootStage::Finalizer);
}

fn spawn_async_boot_stage<F>(stage: AsyncBootStage, target_cpu: usize, future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    record_async_boot_stage_assigned_cpu(stage, target_cpu);
    info!(
        target: "init",
        "[async-boot] scheduling stage={} target_cpu={}",
        stage.label(),
        target_cpu
    );
    crate::task::spawn_on_cpu_with_priority(target_cpu, crate::task::Priority::High, future);
}

fn spawn_async_boot_orchestrator(
    context: KernelBootContext,
    coordinator: Arc<AsyncBootCoordinator>,
) {
    let active_cpus = crate::task::executor_slot_count().max(1);

    let platform = coordinator.clone();
    let platform_cpu = async_boot_stage_target_cpu(AsyncBootStage::Platform, active_cpus);
    spawn_async_boot_stage(AsyncBootStage::Platform, platform_cpu, async move {
        run_platform_stage(context, platform, platform_cpu).await;
    });

    let graphics = coordinator.clone();
    let graphics_cpu = async_boot_stage_target_cpu(AsyncBootStage::Graphics, active_cpus);
    spawn_async_boot_stage(AsyncBootStage::Graphics, graphics_cpu, async move {
        run_graphics_stage(context, graphics, graphics_cpu).await;
    });

    let core = coordinator.clone();
    let core_cpu = async_boot_stage_target_cpu(AsyncBootStage::CoreServices, active_cpus);
    spawn_async_boot_stage(AsyncBootStage::CoreServices, core_cpu, async move {
        run_core_services_stage(context, core, core_cpu).await;
    });

    let driver = coordinator.clone();
    let driver_cpu = async_boot_stage_target_cpu(AsyncBootStage::Driver, active_cpus);
    spawn_async_boot_stage(AsyncBootStage::Driver, driver_cpu, async move {
        run_driver_stage(context, driver, driver_cpu).await;
    });

    let post_driver = coordinator.clone();
    let post_driver_cpu = async_boot_stage_target_cpu(AsyncBootStage::PostDriver, active_cpus);
    spawn_async_boot_stage(AsyncBootStage::PostDriver, post_driver_cpu, async move {
        run_post_driver_stage(context, post_driver, post_driver_cpu).await;
    });

    let finalizer_cpu = async_boot_stage_target_cpu(AsyncBootStage::Finalizer, active_cpus);
    spawn_async_boot_stage(AsyncBootStage::Finalizer, finalizer_cpu, async move {
        run_finalizer_stage(context, coordinator, finalizer_cpu).await;
    });
}

pub(crate) fn start_async_boot_runtime(context: KernelBootContext) -> ! {
    info!(
        target: "init",
        "Phase-4 early executor handoff entering the per-core executor path"
    );
    reset_async_boot_stage_runtime_snapshot();

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
    let keys = crate::net::runtime::device::list_port_keys_in(
        crate::net::runtime::default_runtime(),
        None,
    );
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

fn log_mlx5_boot_snapshot(stage: &str) {
    let key = crate::net::runtime::device::NetDeviceKey::Mlx5(0);
    let Some(info) = crate::net::runtime::device::port_info(key) else {
        return;
    };

    let runtime_stats = crate::net::runtime::device::port_stats(key).unwrap_or_default();
    let stack_stats = crate::net::runtime::bridge::get_stack_glue_stats();
    let link_up = info.flags & kernel_api::service::netdev::NETDEV_FLAG_LINK_UP != 0;
    let healthy = info.flags & kernel_api::service::netdev::NETDEV_FLAG_HEALTHY != 0;
    let mac = info.mac.as_bytes();
    info!(
        target: "net_boot",
        "mlx5 boot snapshot [{}]: runtime_init={} link_up={} healthy={} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} stack_init={} stack_rx={} stack_tx={} runtime_rx={} runtime_tx={} runtime_tx_err={} runtime_rx_err={}",
        stage,
        runtime_stats.initialized,
        link_up,
        healthy,
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5],
        stack_stats.initialized,
        stack_stats.rx_packets,
        stack_stats.tx_packets,
        runtime_stats.rx_packets,
        runtime_stats.tx_packets,
        runtime_stats.tx_errors,
        runtime_stats.rx_errors,
    );

    if let Some(stats) = crate::net::runtime::bridge::mlx5_bridge::get_mlx5_port_stats(0, 0) {
        info!(
            target: "net_boot",
            "mlx5 hw stats [{}]: rx_pkts={} rx_bytes={} rx_err={} rx_drop={} tx_pkts={} tx_bytes={} tx_err={} tx_drop={}",
            stage,
            stats.rx_packets,
            stats.rx_bytes,
            stats.rx_errors,
            stats.rx_dropped,
            stats.tx_packets,
            stats.tx_bytes,
            stats.tx_errors,
            stats.tx_dropped
        );
    }
}

async fn network_bootstrap_task() {
    info!(target: "net_boot", "Network bootstrap task started (async)");

    let virtio_net_present = virtio_driver::net::virtio_net_driver_adapter(0)
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
                use alloc::boxed::Box;
                use driver_registry::register_driver;
                use virtio_driver::net::driver::VirtioNetDriver;

                let hooks = crate::net::drivers::virtio_runtime::kernel_virtio_net_driver_hooks();
                let net_handle = register_driver(Box::new(VirtioNetDriver::new(0, hooks)));
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
            let pci_devices = crate::drivers::pci::find_by_id(
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
            log_mlx5_boot_snapshot("dhcp-bound");
            dhcp_bound = true;
            break;
        }
    }

    if !dhcp_bound {
        warn!(target: "net_boot", "DHCP did not reach Bound state within timeout; using default config");
        log_mlx5_boot_snapshot("dhcp-timeout");
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
        log_mlx5_boot_snapshot("no-gateway");
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
        match crate::task::with_timeout(
            crate::net::api::icmp::ping_in(crate::net::runtime::default_runtime(), ping_target, 1),
            NET_BOOT_PING_TIMEOUT_MS,
        )
        .await
        {
            crate::task::TimeoutResult::Completed(Ok(echo)) => info!(
                target: "net_boot",
                "Async ping success if{} rtt={} us",
                if_id,
                echo.rtt_us
            ),
            crate::task::TimeoutResult::Completed(Err(e)) => {
                warn!(target: "net_boot", "Async ping failed if{}: {:?}", if_id, e)
            }
            crate::task::TimeoutResult::TimedOut => warn!(
                target: "net_boot",
                "Async ping timed out if{} after {} ms",
                if_id,
                NET_BOOT_PING_TIMEOUT_MS
            ),
        }
    }

    if dhcp_bound {
        task::sleep_ms(250).await;
        log_mlx5_boot_snapshot("post-http-watch");
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
        ShellLaunchMode::Off => {
            info!(target: "init", "Shell launch disabled by boot policy (shell=off)");
        }
    }
}

fn spawn_early_network_task<F>(label: &'static str, priority: crate::task::Priority, future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    info!(
        target: "net_boot",
        "Scheduling {} on bootstrap CPU0 with priority {:?}",
        label,
        priority
    );
    crate::task::spawn_on_cpu_with_priority(0, priority, async move {
        info!(
            target: "net_boot",
            "{} running on CPU {}",
            label,
            crate::cpu::try_current_id().unwrap_or(0)
        );
        future.await;
    });
}

pub(crate) fn spawn_core_runtime_tasks() {
    spawn_early_network_task(
        "io scheduler initialization task",
        crate::task::Priority::Normal,
        async {
            info!(
                target: "init",
                "Initializing I/O scheduler on CPU {}",
                crate::cpu::try_current_id().unwrap_or(0)
            );
            io::io_scheduler::init_io_scheduler();
            info!(target: "init", "I/O scheduler initialized");
        },
    );

    // === ネットワークブートストラップ（完全非同期） ===
    spawn_early_network_task(
        "network bootstrap task",
        crate::task::Priority::High,
        network_bootstrap_task(),
    );
    info!(target: "init", "Network bootstrap task queued on CPU0");

    // [PR-COMPLIANCE] ICMP Responder activation log
    info!(target: "init", "ICMP responder server active");

    // Initialize network event handler and spawn the background task for async networking
    crate::net::l4::endpoint::handler::init_network_event_handler();
    spawn_early_network_task(
        "network event task",
        crate::task::Priority::High,
        crate::net::l4::endpoint::event_loop::network_event_task(),
    );

    // Spawn async timeout processing task (TCP retransmit, keep-alive, ARP expiry, etc.)
    spawn_early_network_task(
        "network timeout task",
        crate::task::Priority::High,
        crate::net::runtime::stack::timeout_task(),
    );

    info!(
        target: "net_boot",
        "Starting deferred DHCP/DNS/mDNS background service tasks on bootstrap CPU0"
    );
    crate::net::api::dhcp::start_background_service_tasks();
}

/// カーネルタスクをスポーン
pub(crate) fn spawn_kernel_tasks(shell_mode: crate::shell::session::ShellLaunchMode) {
    spawn_shell_tasks(shell_mode);
    spawn_core_runtime_tasks();
}

/// システム統計を表示
pub(crate) fn print_system_stats() {
    info!(target: "stats", "=== System Statistics ===");

    // メモリ統計
    let (used, free) = heap::heap_stats();
    info!(target: "stats", "Heap: {} bytes used / {} bytes free", used, free);

    // ドメイン統計
    let domain_stats = domain::get_domain_stats();
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
    fn async_boot_stage_target_cpu_keeps_all_stages_on_cpu0_for_uniprocessor() {
        assert_eq!(async_boot_stage_target_cpu(AsyncBootStage::Platform, 1), 0);
        assert_eq!(async_boot_stage_target_cpu(AsyncBootStage::Graphics, 1), 0);
        assert_eq!(
            async_boot_stage_target_cpu(AsyncBootStage::CoreServices, 1),
            0
        );
        assert_eq!(async_boot_stage_target_cpu(AsyncBootStage::Driver, 1), 0);
        assert_eq!(
            async_boot_stage_target_cpu(AsyncBootStage::PostDriver, 1),
            0
        );
        assert_eq!(async_boot_stage_target_cpu(AsyncBootStage::Finalizer, 1), 0);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn async_boot_stage_target_cpu_uses_topology_candidates_round_robin() {
        let topology_candidates = [2usize, 1, 3];

        assert_eq!(
            async_boot_stage_target_cpu_with_candidates(
                AsyncBootStage::Platform,
                4,
                &topology_candidates,
            ),
            0
        );
        assert_eq!(
            async_boot_stage_target_cpu_with_candidates(
                AsyncBootStage::Graphics,
                4,
                &topology_candidates,
            ),
            2
        );
        assert_eq!(
            async_boot_stage_target_cpu_with_candidates(
                AsyncBootStage::CoreServices,
                4,
                &topology_candidates,
            ),
            1
        );
        assert_eq!(
            async_boot_stage_target_cpu_with_candidates(
                AsyncBootStage::Driver,
                4,
                &topology_candidates,
            ),
            3
        );
        assert_eq!(
            async_boot_stage_target_cpu_with_candidates(
                AsyncBootStage::PostDriver,
                4,
                &topology_candidates,
            ),
            2
        );
        assert_eq!(
            async_boot_stage_target_cpu_with_candidates(
                AsyncBootStage::Finalizer,
                4,
                &topology_candidates,
            ),
            1
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn async_boot_stage_target_cpu_backfills_missing_ap_candidates() {
        let topology_candidates = [3usize];

        assert_eq!(
            normalized_async_boot_ap_candidates(4, &topology_candidates),
            alloc::vec![3, 1, 2]
        );
        assert_eq!(
            async_boot_stage_target_cpu_with_candidates(
                AsyncBootStage::Graphics,
                4,
                &topology_candidates,
            ),
            3
        );
        assert_eq!(
            async_boot_stage_target_cpu_with_candidates(
                AsyncBootStage::CoreServices,
                4,
                &topology_candidates,
            ),
            1
        );
        assert_eq!(
            async_boot_stage_target_cpu_with_candidates(
                AsyncBootStage::Driver,
                4,
                &topology_candidates,
            ),
            2
        );
        assert_eq!(
            async_boot_stage_target_cpu_with_candidates(
                AsyncBootStage::Finalizer,
                4,
                &topology_candidates,
            ),
            1
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn async_boot_stage_target_cpu_keeps_finalizer_off_bsp_when_aps_exist() {
        assert_ne!(
            async_boot_stage_target_cpu_with_candidates(AsyncBootStage::Finalizer, 2, &[]),
            0
        );
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
    fn async_boot_stage_runtime_snapshot_resets_and_records_cpu_transitions() {
        reset_async_boot_stage_runtime_snapshot();
        let snapshot = async_boot_stage_runtime_snapshot();
        assert_eq!(snapshot.platform.assigned_cpu, None);
        assert_eq!(snapshot.graphics.started_cpu, None);
        assert_eq!(snapshot.finalizer.completed_cpu, None);

        record_async_boot_stage_assigned_cpu(AsyncBootStage::Platform, 0);
        record_async_boot_stage_started_cpu(AsyncBootStage::Graphics, 2);
        record_async_boot_stage_completed_cpu(AsyncBootStage::Finalizer, 3);

        let snapshot = async_boot_stage_runtime_snapshot();
        assert_eq!(snapshot.platform.assigned_cpu, Some(0));
        assert_eq!(snapshot.graphics.started_cpu, Some(2));
        assert_eq!(snapshot.finalizer.completed_cpu, Some(3));

        reset_async_boot_stage_runtime_snapshot();
        let snapshot = async_boot_stage_runtime_snapshot();
        assert_eq!(snapshot.platform.assigned_cpu, None);
        assert_eq!(snapshot.graphics.started_cpu, None);
        assert_eq!(snapshot.finalizer.completed_cpu, None);
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
    crate::panic_handler::handle_panic(info)
}

// ============================================================================
// Global Allocator (Binary Only)
// ============================================================================
// Defined here to avoid conflict with the library crate `rany_os` which
// may also define an allocator for tests.
// Wrapper to delegate to heap::ALLOCATOR
pub(crate) struct GlobalAllocatorWrapper;

#[cfg(not(test))]
unsafe impl core::alloc::GlobalAlloc for GlobalAllocatorWrapper {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        crate::heap::ALLOCATOR.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        crate::heap::ALLOCATOR.dealloc(ptr, layout)
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
    let recovered = crate::heap::oom::try_free_memory();
    crate::io::log::early_print("OOM recovery attempt: ");
    crate::io::log::early_print(if recovered { "success\n" } else { "failed\n" });
    panic!(
        "allocation error: size={} align={} oom_recovered={}",
        layout.size(),
        layout.align(),
        recovered
    )
}
