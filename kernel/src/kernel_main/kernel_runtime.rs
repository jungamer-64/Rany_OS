// ============================================================================
// kernel/src/kernel_main/kernel_runtime.rs
// ============================================================================
//! カーネルのランタイム機能（タスクスポーン、統計表示、シンボル登録など）
//!! カーネルの初期化後、Executor上で動作するタスクをスポーンする関数や、システム統計を表示する関数などを定義する。
use super::*;

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
    crate::io::log::early_print("[NET_BOOT] task enter\n");
    info!(target: "net_boot", "Network bootstrap task started (async)");

    crate::io::log::early_print("[NET_BOOT] checking virtio presence\n");
    let virtio_net_present = crate::drivers::virtio::virtio_net_driver_adapter(0)
        .info()
        .flags
        != 0;
    crate::io::log::early_print("[NET_BOOT] virtio presence checked\n");
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

                crate::io::log::early_print("[NET_BOOT] registering virtio driver\n");
                let net_handle = register_driver(Box::new(VirtioNetDriver::new()));
                crate::io::log::early_print("[NET_BOOT] registered virtio driver\n");
                crate::io::log::early_print("[NET_BOOT] probing/starting virtio driver\n");
                if let Err(e) = driver_registry::driver_registry()
                    .probe_and_start(net_handle.expect("Failed to register VirtIO-Net driver"))
                {
                    warn!(target: "net_boot", "VirtIO-Net driver init failed: {:?}", e);
                } else {
                    info!(target: "net_boot", "VirtIO-Net driver initialized via DriverRegistry");
                }
                crate::io::log::early_print("[NET_BOOT] probe/start virtio driver returned\n");
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

        crate::io::log::early_print("[NET_BOOT] registering mlx5 driver\n");
        info!(target: "net_boot", "Probing ConnectX (mlx5) via DriverRegistry");
        let mlx5_handle = register_driver(Box::new(Mlx5ConnectXDriver::new()));
        crate::io::log::early_print("[NET_BOOT] registered mlx5 driver\n");
        match mlx5_handle {
            Ok(handle) => {
                crate::io::log::early_print("[NET_BOOT] probing/starting mlx5 driver\n");
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
                crate::io::log::early_print("[NET_BOOT] probe/start mlx5 driver returned\n");
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

        let states = crate::net::api::dhcp::list_dhcp_states().await;
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
        crate::net::api::config::list_interface_configs()
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
        match crate::net::api::icmp::ping(ping_target, 1).await {
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

fn spawn_shell_tasks(
    executor: &mut task::Executor,
    shell_mode: crate::shell::session::ShellLaunchMode,
) {
    use crate::shell::session::{ShellLaunchMode, spawn_console_shell, spawn_serial_shell};

    match shell_mode {
        ShellLaunchMode::Console => spawn_console_shell(executor),
        ShellLaunchMode::Serial => spawn_serial_shell(executor),
        ShellLaunchMode::Both => {
            spawn_serial_shell(executor);
            spawn_console_shell(executor);
        }
        ShellLaunchMode::Off => {
            info!(target: "init", "Shell launch disabled by cmdline (shell=off)");
        }
    }
}

pub(crate) fn spawn_core_runtime_tasks(executor: &mut task::Executor) {
    use task::Task;

    // === ネットワークブートストラップ（完全非同期） ===
    // VirtIO-Netドライバ登録 → DHCP → ping をExecutor上で非同期実行
    executor.spawn(Task::new(network_bootstrap_task()));
    info!(target: "init", "Network bootstrap task spawned (async)");

    // IOMMU フォルトハンドラタスク: ISRがキューに積んだフォルトイベントを定期的にdrainする
    executor.spawn(Task::new(
        crate::io::iommu::vendors::intel::controller::fault::fault_handler_task(),
    ));
    info!(target: "init", "IOMMU fault handler task spawned");

    // Host-to-guest communication endpoint for QEMU hostfwd (tcp:5555 -> guest:80).
    crate::net::services::http::server::start_once(executor);

    // [PR-COMPLIANCE] ICMP Responder activation log
    info!(target: "init", "ICMP responder server active");

    // Initialize network event handler and spawn the background task for async networking
    crate::net::l4::endpoint::handler::init_network_event_handler();
    executor.spawn(crate::task::Task::new(
        crate::net::l4::endpoint::tcp_rx::network_event_task(),
    ));

    // Spawn async timeout processing task (TCP retransmit, keep-alive, ARP expiry, etc.)
    executor.spawn(crate::task::Task::new(
        crate::net::runtime::stack::timeout_task(),
    ));
}

pub(crate) fn spawn_demo_runtime_tasks(executor: &mut task::Executor) {
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
    crate::io::log::early_print("[INIT] Task 1 (User App) spawned\n");

    // タスク2: ゼロコピー通信デモ
    let domain2 = domain_system::create_domain(alloc::string::String::from("ipc_demo"))
        .expect("create_domain failed");
    domain_system::start_domain(domain2).ok();

    executor.spawn(Task::new(async move {
        info!(target: "task2", "IPC demonstration started");
        crate::io::log::early_print("[TASK2] IPC demo started\n");

        // RRefを使用したゼロコピーデータ転送
        crate::io::log::early_print("[TASK2] Creating RRef...\n");
        let data = RRef::new(
            ipc::DomainId::new(domain1.as_u64()),
            alloc::vec![0xDE, 0xAD, 0xBE, 0xEF],
        );
        crate::io::log::early_print("[TASK2] RRef created\n");
        debug!(target: "task2", "Created RRef in domain {}", domain1.as_u64());

        // 所有権を domain2 に移動
        crate::io::log::early_print("[TASK2] Moving RRef...\n");
        let data = data.move_to(ipc::DomainId::new(domain2.as_u64()));
        crate::io::log::early_print("[TASK2] RRef moved\n");
        debug!(target: "task2", "Transferred ownership to domain {} (zero-copy)", data.owner().as_u64());

        debug!(target: "task2", "Data: {:?}", &data[..]);
        info!(target: "task2", "IPC demo completed");
        crate::io::log::early_print("[TASK2] IPC demo completed\n");
    }));
    crate::io::log::early_print("[INIT] Task 2 (IPC Demo) spawned\n");

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
    crate::io::log::early_print("[INITDBG] task5 spawned\n");

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
    executor.spawn(Task::new(async {
        info!(target: "net_test", "Network ping test: waiting for stack to be ready...");

        // DHCP/スタックからゲートウェイを取得
        let gw_opt = crate::net::api::config::list_interface_configs()
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
        match crate::net::api::icmp::ping(gw, 1).await {
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
    crate::io::log::early_print("[INITDBG] net_test spawned\n");

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
    executor.spawn(Task::new(async {
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
    crate::io::log::early_print("[INITDBG] spawn_kernel_tasks complete\n");
}

/// カーネルタスクをスポーン
pub(crate) fn spawn_kernel_tasks(executor: &mut task::Executor, context: &KernelBootContext) {
    spawn_shell_tasks(executor, context.shell_mode);
    spawn_core_runtime_tasks(executor);
    spawn_demo_runtime_tasks(executor);
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

/// Panicハンドラ
#[cfg(all(not(test), not(feature = "std")))]
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

#[cfg(not(test))]
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
