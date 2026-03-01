use super::*;


/// カーネルタスクをスポーン
pub(crate) fn spawn_kernel_tasks(executor: &mut task::Executor, console_available: bool) {
    use ipc::RRef;
    use task::Task;
    use crate::shell::session::{spawn_console_shell, spawn_serial_shell};

    // Spawn Serial Shell
    spawn_serial_shell(executor);

    // Spawn Console Shell Task
    if console_available {
        spawn_console_shell(executor);
    } else {
        warn!(
            target: "init",
            "Framebuffer console unavailable; skipping console shell in kernel_content runtime"
        );
    }

    // Host-to-guest communication endpoint for QEMU hostfwd (tcp:5555 -> guest:80).
    crate::net::runtime::host_http_service::start_once(executor);

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

        crate::io::log::early_print("[NET-PING-MANUAL] sending manual ping now\n");
        info!(target: "net_test", "Sending ICMP echo to 10.0.2.2 seq=1");
        match crate::net::runtime::bridge::send_real_icmp_echo([10, 0, 2, 2], 1) {
            Ok(rtt) => info!(target: "net_test", "Ping success rtt={} (units depending on implementation)", rtt),
            Err(e) => warn!(target: "net_test", "Ping failed: {}", e),
        }

        let bridge_stats = crate::net::runtime::bridge::get_bridge_stats();
        info!(target: "net_test", "Bridge stats after ping: init={} rx={} tx={} ", bridge_stats.initialized, bridge_stats.rx_packets, bridge_stats.tx_packets);
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
    loader::with_registry_mut(|registry| {
        registry.register_symbol(
            alloc::string::String::from(kernel_api::driver_abi::KERNEL_API_SYMBOL),
            crate::driver_registry::kernel_api_v1() as *const kernel_api::driver_abi::KernelApiV1
                as usize,
        );
    });

    debug!(target: "loader", "Kernel API symbol registered for cell loader");
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
