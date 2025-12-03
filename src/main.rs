#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

extern crate alloc;

use core::panic::PanicInfo;

mod allocator;
mod domain;
mod domain_system;
mod error;
mod fs;
mod graphics;
mod input;
mod interrupts;
mod io;
mod ipc;
mod kapi; // 旧称: syscall → SPL直接呼び出しを反映
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
mod vga;

// Phase 4: High-Performance & Advanced Features
mod console;
mod diag;
mod smp_advanced;

// Phase 5: Extended Features & System Integration
mod gpu;
mod pcie;
mod profiler;
mod thermal;
mod usb;
mod watchdog;

// Phase 6: Testing, Demos & System Monitor
mod demo;
mod monitor;
mod test;

// Phase 7: System Integration & Application Support
mod application;
mod benchmark;
mod integration; // 旧称: userspace → SPL単一特権レベルを反映

// Note: smp module with bootstrap is included in the main smp module

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // VGAバッファの初期化（ログ出力用）
    vga::init();

    print_logo();
    log!("ExoRust Kernel v0.2.0 - Booting...\n");

    // 0. 割り込みシステムの早期初期化（例外ハンドラの設定）
    // これにより、メモリ初期化中の例外でデバッグ情報が得られる
    log!("[INIT] Early interrupt system initialization\n");
    interrupts::init();
    log!("[OK] Interrupt system initialized (exceptions enabled)\n");

    // 1. メモリ管理の初期化
    log!("[INIT] Initializing memory subsystem\n");
    memory::init();
    log!("[OK] Memory subsystem initialized\n");

    // 2. ドメイン管理システムの初期化
    log!("[INIT] Initializing domain system\n");
    domain_system::init();
    log!("[OK] Domain system initialized\n");

    // 2.5. SAS（単一アドレス空間）の初期化
    log!("[INIT] Initializing Single Address Space manager\n");
    sas::init();
    log!("[OK] SAS manager initialized\n");

    // 2.6. Spectre/Meltdown緩和策の初期化
    log!("[INIT] Initializing Spectre mitigations\n");
    spectre::init();
    let status = spectre::status_summary();
    log!(
        "[OK] Spectre mitigations: IBRS={}, STIBP={}, SSBD={}, Retpoline={}\n",
        status.ibrs_enabled,
        status.stibp_enabled,
        status.ssbd_enabled,
        status.using_retpoline
    );

    // 2.7. セキュリティフレームワークの初期化
    log!("[INIT] Initializing security framework\n");
    security::init();
    log!("[OK] Security framework initialized\n");

    // 2.8. カーネルAPIインターフェースの初期化（旧: syscall）
    log!("[INIT] Initializing kernel API interface\n");
    kapi::init();
    log!("[OK] Kernel API interface initialized\n");

    // 3. キーボードドライバの初期化
    log!("[INIT] Initializing keyboard driver\n");
    io::keyboard::init();
    log!("[OK] Keyboard driver initialized\n");

    // 3.5. シリアルポートの初期化（デバッグ用）
    log!("[INIT] Initializing serial port\n");
    if io::serial::init().is_ok() {
        log!("[OK] Serial port initialized\n");
    } else {
        log!("[WARN] Serial port initialization failed\n");
    }

    // 4. タスクスケジューラの初期化
    log!("[INIT] Initializing task scheduler\n");
    task::init_scheduler(0); // CPU 0
    log!("[OK] Task scheduler initialized\n");

    // 4.5. Per-Core Executorの初期化（設計書 4.3）
    log!("[INIT] Initializing per-core executors\n");
    task::init_executors(1); // シングルコアで開始
    log!("[OK] Per-core executors initialized\n");

    // 5. ローダーシステムの初期化
    log!("[INIT] Initializing cell loader\n");
    loader::init_kernel_cell();
    register_kernel_symbols();
    log!("[OK] Cell loader initialized\n");

    // 5.5. シンボルテーブルの初期化（バックトレース用）
    log!("[INIT] Initializing symbol table\n");
    unwind::init_symbol_table();
    log!("[OK] Symbol table initialized\n");

    // 5.6. テストフレームワークの初期化
    log!("[INIT] Initializing test framework\n");
    test::init();
    log!("[OK] Test framework initialized\n");

    // 5.7. システム統合の初期化
    log!("[INIT] Initializing system integration\n");
    if let Err(e) = integration::init() {
        log!("[WARN] System integration failed: {:?}\n", e);
    } else {
        log!("[OK] System integration initialized\n");
    }

    // 6. 割り込みを有効化
    interrupts::enable_interrupts();
    log!("[OK] Interrupts enabled\n");

    // 7. システム統計を表示
    print_system_stats();

    // 8. Executorの作成とタスクスポーン
    log!("[INIT] Creating async executor\n");
    let mut executor = task::Executor::new();

    spawn_kernel_tasks(&mut executor);
    log!("[OK] Kernel tasks spawned\n");

    log!("[RUN] Starting executor main loop\n");
    log!("================================================================================\n\n");

    // メインループ開始（戻ってこない）
    executor.run();
}

/// カーネルタスクをスポーン
fn spawn_kernel_tasks(executor: &mut task::Executor) {
    use ipc::RRef;
    use task::Task;

    // ドメイン1を作成：ユーザーアプリケーション
    let domain1 = domain_system::create_domain(alloc::string::String::from("user_app_1"));

    // SAS統計をログ
    let sas_stats = sas::stats();
    log!(
        "[INIT] SAS Stats: {} regions, {} objects, {} domains\n",
        sas_stats.total_regions,
        sas_stats.total_objects,
        sas_stats.domains
    );
    domain_system::start_domain(domain1).ok();

    // タスク1: ドメイン1のメインタスク
    executor.spawn(Task::new(async move {
        log!(
            "[Task 1] User application domain started (ID: {})\n",
            domain1.as_u64()
        );

        // シミュレーション: データ処理
        for i in 0..5 {
            log!("[Task 1] Processing iteration {}\n", i);
            task::sleep_ms(100).await;

            // Yield point（プリエンプション対策）
            task::yield_point();
        }

        log!("[Task 1] User application completed\n");
    }));

    // タスク2: ゼロコピー通信デモ
    let domain2 = domain_system::create_domain(alloc::string::String::from("ipc_demo"));
    domain_system::start_domain(domain2).ok();

    executor.spawn(Task::new(async move {
        log!("[Task 2] IPC demonstration started\n");

        // RRefを使用したゼロコピーデータ転送
        let data = RRef::new(
            ipc::DomainId::new(domain1.as_u64()),
            alloc::vec![0xDE, 0xAD, 0xBE, 0xEF],
        );
        log!("[Task 2] Created RRef in domain {}\n", domain1.as_u64());

        // 所有権を domain2 に移動
        let data = data.move_to(ipc::DomainId::new(domain2.as_u64()));
        log!(
            "[Task 2] Transferred ownership to domain {} (zero-copy)\n",
            data.owner().as_u64()
        );

        log!("[Task 2] Data: {:?}\n", &data[..]);
        log!("[Task 2] IPC demo completed\n");
    }));

    // タスク3: プリエンプション統計デモ
    executor.spawn(Task::new(async {
        log!("[Task 3] Preemption stats demo started\n");

        for i in 0..3 {
            log!("[Task 3] Iteration {}\n", i);
            task::sleep_ms(200).await;

            let stats = task::preemption_controller().stats();
            log!(
                "[Task 3] Preemption Stats - Forced: {}, Voluntary: {}\n",
                stats.forced_preemptions,
                stats.voluntary_yields
            );
        }

        log!("[Task 3] Preemption demo completed\n");
    }));

    // タスク4: メモリ統計モニタリング
    executor.spawn(Task::new(async {
        log!("[Task 4] Memory monitor started\n");

        for _ in 0..3 {
            task::sleep_ms(500).await;

            let (used, free) = memory::heap_stats();
            log!("[Task 4] Heap: Used={} bytes, Free={} bytes\n", used, free);

            // ドメイン統計
            let domain_stats = domain_system::get_domain_stats();
            log!(
                "[Task 4] Domains: {} total, {} running\n",
                domain_stats.total,
                domain_stats.running
            );
        }

        log!("[Task 4] Memory monitor completed\n");
    }));

    // タスク5: Wakerのテスト
    executor.spawn(Task::new(async {
        log!("[Task 5] Waker test started\n");

        use core::future::poll_fn;
        use core::task::Poll;

        let mut counter = 0;
        poll_fn(|_cx| {
            counter += 1;
            if counter >= 3 {
                log!("[Task 5] Polled {} times, completing\n", counter);
                Poll::Ready(())
            } else {
                log!("[Task 5] Polled {} times, pending\n", counter);
                Poll::Pending
            }
        })
        .await;

        log!("[Task 5] Completed\n");
    }));

    // タスク6: ベンチマーク実行（オプション）
    executor.spawn(Task::new(async {
        log!("[Task 6] Benchmark task started\n");
        task::sleep_ms(1000).await;

        // ベンチマーク結果を取得
        let results = benchmark::run_all_benchmarks();
        log!("[Task 6] Ran {} benchmarks\n", results.len());
        log!("[Task 6] Benchmark task completed\n");
    }));

    // タスク7: 統合テスト実行
    executor.spawn(Task::new(async {
        log!("[Task 7] Integration test task started\n");
        task::sleep_ms(2000).await;

        let (passed, failed) = test::integration::run_all_integration_tests();
        log!(
            "[Task 7] Integration tests: {} passed, {} failed\n",
            passed,
            failed
        );
        log!("[Task 7] Integration test task completed\n");
    }));
}

/// システム統計を表示
fn print_system_stats() {
    log!("\n[STATS] === System Statistics ===\n");

    // メモリ統計
    let (used, free) = memory::heap_stats();
    log!("[STATS] Heap: {} bytes used / {} bytes free\n", used, free);

    // ドメイン統計
    let domain_stats = domain_system::get_domain_stats();
    log!(
        "[STATS] Domains: {} total, {} running, {} stopped\n",
        domain_stats.total,
        domain_stats.running,
        domain_stats.stopped
    );

    // SAS統計
    let sas_stats = sas::stats();
    log!(
        "[STATS] SAS: {} regions, {} objects\n",
        sas_stats.total_regions,
        sas_stats.total_objects
    );

    // セキュリティ統計
    let security_violations = security::access_control().violation_count();
    let zero_copy_stats = security::zero_copy_barrier().stats();
    log!(
        "[STATS] Security: {} violations, {} bytes transferred\n",
        security_violations,
        zero_copy_stats.bytes_transferred
    );

    // 割り込みWaker統計
    let waker_stats = task::interrupt_waker::interrupt_waker_registry().stats();
    log!(
        "[STATS] Interrupt-Waker: {} interrupts, {} wakes, {} registered\n",
        waker_stats.interrupt_count,
        waker_stats.wake_count,
        waker_stats.registered_sources
    );

    // 割り込み統計
    let timer_ticks = interrupts::get_timer_ticks();
    log!("[STATS] Timer ticks: {}\n", timer_ticks);

    log!("[STATS] ================================\n\n");
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
            alloc::string::String::from("sys_sleep"),
            sys_sleep as *const () as usize,
        );
    });

    log!("[LOADER] Kernel symbols registered\n");
}

/// システムコール: ログ出力
#[unsafe(no_mangle)]
pub extern "C" fn sys_log(msg: *const u8, len: usize) {
    if msg.is_null() || len == 0 {
        return;
    }

    let slice = unsafe { core::slice::from_raw_parts(msg, len) };
    if let Ok(s) = core::str::from_utf8(slice) {
        log!("[CELL] {}", s);
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

/// ExoRustロゴを表示
fn print_logo() {
    log!("================================================================================\n");
    log!("  ___           ____            _   \n");
    log!(" | __|_ _____ _|  _ \\ _  _ ___ | |_ \n");
    log!(" | _|\\ \\ / _ \\ | |_) | || (_-< |  _|\n");
    log!(" |___/_\\_\\___|_|____/ \\_,_/__/  \\__|\n");
    log!("\n");
    log!("  Single Address Space | Async-First | Zero-Copy\n");
    log!("  Rust-Based OS Kernel with Memory Safety Guarantee\n");
    log!("================================================================================\n");
}

/// Panicハンドラ
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    panic_handler::handle_panic(info)
}
