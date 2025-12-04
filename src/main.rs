#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

extern crate alloc;

use limine::request::{MemoryMapRequest, HhdmRequest, FramebufferRequest, StackSizeRequest, RequestsStartMarker, RequestsEndMarker};
use limine::BaseRevision;
use core::panic::PanicInfo;
use log::{info, warn, debug, error};

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

// Limine bootloader protocol requests (UEFI/BIOS compatible)
// Define the start and end markers for Limine requests
#[used]
#[unsafe(link_section = ".requests_start_marker")]
static _START_MARKER: RequestsStartMarker = RequestsStartMarker::new();

#[used]
#[unsafe(link_section = ".requests_end_marker")]
static _END_MARKER: RequestsEndMarker = RequestsEndMarker::new();

// Be sure to mark all limine requests with #[used], otherwise they may be removed by the compiler.
#[used]
#[unsafe(link_section = ".requests")]
static BASE_REVISION: BaseRevision = BaseRevision::new();

#[used]
#[unsafe(link_section = ".requests")]
static HHDM_REQUEST: HhdmRequest = HhdmRequest::new();

#[used]
#[unsafe(link_section = ".requests")]
static MEMORY_MAP_REQUEST: MemoryMapRequest = MemoryMapRequest::new();

#[used]
#[unsafe(link_section = ".requests")]
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();

#[used]
#[unsafe(link_section = ".requests")]
static STACK_SIZE_REQUEST: StackSizeRequest = StackSizeRequest::new()
    .with_size(512 * 1024); // 512 KiB stack

#[unsafe(no_mangle)]
extern "C" fn kmain() -> ! {
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

        // Send boot message
        for byte in b"RanyOS UEFI Boot OK!\r\n" {
            core::arch::asm!(
                "out dx, al",
                in("dx") port,
                in("al") *byte,
            );
        }
    }

    // Simple serial print helper for debugging
    fn serial_print(s: &str) {
        unsafe {
            let port = 0x3F8u16;
            for byte in s.bytes() {
                core::arch::asm!(
                    "out dx, al",
                    in("dx") port,
                    in("al") byte,
                );
            }
        }
    }

    serial_print("[BOOT] Checking Limine revision...\r\n");

    // Verify Limine protocol support
    if !BASE_REVISION.is_supported() {
        serial_print("[BOOT] Limine revision NOT supported!\r\n");
        // Limine not available, halt
        loop { core::hint::spin_loop(); }
    }
    serial_print("[BOOT] Limine revision OK\r\n");

    // SSE/SSE2を有効化（x86_64ではABIで必須）
    serial_print("[BOOT] Enabling SSE...\r\n");
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
        cr4 |= 1 << 9;  // OSFXSR
        cr4 |= 1 << 10; // OSXMMEXCPT  
        asm!("mov cr4, {}", in(reg) cr4);
    }
    serial_print("[BOOT] SSE enabled\r\n");
    
    // Get physical memory offset from HHDM (Higher Half Direct Map)
    serial_print("[BOOT] Getting HHDM offset...\r\n");
    let phys_mem_offset = HHDM_REQUEST.get_response()
        .map(|r| r.offset())
        .unwrap_or(0);
    serial_print("[BOOT] HHDM offset obtained\r\n");
    
    // VGAバッファの初期化（ログ出力用）
    serial_print("[BOOT] Initializing VGA...\r\n");
    vga::init();
    serial_print("[BOOT] VGA initialized\r\n");
    
    // ロギングシステムの初期化（最優先、ヒープ不要）
    serial_print("[BOOT] Initializing logger...\r\n");
    if io::log::init().is_err() {
        io::log::early_print("[FATAL] Logger init failed\n");
        serial_print("[BOOT] Logger init FAILED!\r\n");
    } else {
        serial_print("[BOOT] Logger initialized\r\n");
    }
    
    // 早期ブートログ（log crateを使用）
    info!(target: "boot", "kernel_main started");
    
    // 物理メモリオフセットを設定
    serial_print("[BOOT] Setting physical memory offset...\r\n");
    memory::set_physical_memory_offset(phys_mem_offset);
    serial_print("[BOOT] Physical memory offset set\r\n");
    debug!(target: "boot", "physical memory offset set: {:#x}", phys_mem_offset);

    print_logo();

    // 0. 割り込みシステムの早期初期化（例外ハンドラの設定）
    // これにより、メモリ初期化中の例外でデバッグ情報が得られる
    serial_print("[BOOT] Initializing interrupt system...\r\n");
    info!(target: "init", "Initializing interrupt system");
    interrupts::init();
    serial_print("[BOOT] Interrupt system initialized\r\n");
    info!(target: "init", "Interrupt system initialized");

    // 1. メモリ管理の初期化
    serial_print("[BOOT] Initializing memory management...\r\n");
    info!(target: "init", "Initializing memory management");
    memory::init();
    serial_print("[BOOT] Memory management initialized\r\n");
    info!(target: "init", "Memory management initialized");
    
    // ヒープが使用可能になったことを通知
    io::log::notify_heap_available();
    
    // グラフィックスフレームバッファの初期化（Limine経由）
    serial_print("[BOOT] Initializing graphics framebuffer...\r\n");
    if let Some(fb_response) = FRAMEBUFFER_REQUEST.get_response() {
        if graphics::init_from_limine(fb_response) {
            serial_print("[BOOT] Graphics framebuffer initialized\r\n");
            
            // ブートスプラッシュを表示
            graphics::show_boot_splash();
            serial_print("[BOOT] Boot splash displayed\r\n");
        } else {
            serial_print("[BOOT] Graphics framebuffer init failed\r\n");
        }
    } else {
        serial_print("[BOOT] No framebuffer response from bootloader\r\n");
    }
    
    // 進捗: 10% - メモリ初期化完了
    graphics::update_boot_progress_with_message(10, "Memory initialized");
    
    // アロケーションテスト（シンプル化）
    debug!(target: "test", "Running allocation tests");
    {
        let v: alloc::vec::Vec<u8> = alloc::vec![1, 2, 3, 4];
        debug!(target: "test", "Vec allocation OK");
        let _sum: u8 = v.iter().sum();
        debug!(target: "test", "Vec iteration OK");
        
        // BTreeMapテスト
        debug!(target: "test", "Testing BTreeMap");
        let mut map: alloc::collections::BTreeMap<u64, u64> = alloc::collections::BTreeMap::new();
        map.insert(1, 100);
        map.insert(2, 200);
        debug!(target: "test", "BTreeMap OK");
    }
    info!(target: "test", "Allocation tests passed");

    // 2. ドメイン管理システムの初期化
    info!(target: "init", "Initializing domain system");
    domain_system::init();
    info!(target: "init", "Domain system initialized");
    graphics::update_boot_progress_with_message(20, "Domain system ready");

    // 2.5. SAS（単一アドレス空間）の初期化
    info!(target: "init", "Initializing SAS");
    sas::init();
    info!(target: "init", "SAS initialized");

    // 2.6. Spectre/Meltdown緩和策の初期化
    info!(target: "init", "Initializing Spectre mitigations");
    spectre::init();
    info!(target: "init", "Spectre mitigations initialized");
    graphics::update_boot_progress_with_message(30, "Security initialized");

    // 2.7. セキュリティフレームワークの初期化
    info!(target: "init", "Initializing security framework");
    security::init();
    info!(target: "init", "Security framework initialized");

    // 2.8. カーネルAPIインターフェースの初期化（旧: syscall）
    info!(target: "init", "Initializing kernel API");
    kapi::init();
    info!(target: "init", "Kernel API initialized");
    graphics::update_boot_progress_with_message(40, "Kernel API ready");

    // 3. キーボードドライバの初期化
    info!(target: "init", "Initializing keyboard driver");
    io::keyboard::init();
    info!(target: "init", "Keyboard driver initialized");
    
    // 完了
    info!(target: "boot", "BOOT COMPLETE!");

    // 3.5. シリアルポートの初期化（デバッグ用）
    info!(target: "init", "Initializing serial port");
    if io::serial::init().is_ok() {
        info!(target: "init", "Serial port initialized");
    } else {
        warn!(target: "init", "Serial port initialization failed");
    }

    // 3.6. ネットワークシェルAPIの初期化
    info!(target: "init", "Initializing network shell API");
    net::init_network_shell();
    info!(target: "init", "Network shell API initialized");
    graphics::update_boot_progress_with_message(50, "Network stack ready");

    // 3.6.1. ネットワークドライバブリッジの初期化
    info!(target: "init", "Initializing network driver bridge");
    if let Err(e) = net::init_driver_bridge() {
        warn!(target: "init", "Network driver bridge failed: {}", e);
    } else {
        info!(target: "init", "Network driver bridge initialized");
    };

    // 3.7. ファイルシステム（memfs）の初期化
    info!(target: "init", "Initializing memory filesystem");
    fs::init_shell_fs();
    info!(target: "init", "Memory filesystem initialized");
    graphics::update_boot_progress_with_message(60, "Filesystem mounted");

    // 4. タスクスケジューラの初期化
    info!(target: "init", "Initializing task scheduler");
    task::init_scheduler(0); // CPU 0
    info!(target: "init", "Task scheduler initialized");
    graphics::update_boot_progress_with_message(70, "Scheduler started");

    // 4.5. Per-Core Executorの初期化（設計書 4.3）
    info!(target: "init", "Initializing per-core executors");
    task::init_executors(1); // シングルコアで開始
    info!(target: "init", "Per-core executors initialized");

    // 5. ローダーシステムの初期化
    info!(target: "init", "Initializing cell loader");
    loader::init_kernel_cell();
    register_kernel_symbols();
    info!(target: "init", "Cell loader initialized");
    graphics::update_boot_progress_with_message(80, "Loader ready");

    // 5.5. シンボルテーブルの初期化（バックトレース用）
    info!(target: "init", "Initializing symbol table");
    unwind::init_symbol_table();
    info!(target: "init", "Symbol table initialized");

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
    graphics::update_boot_progress_with_message(90, "Integration complete");

    // 6. 割り込みを有効化
    interrupts::enable_interrupts();
    info!(target: "init", "Interrupts enabled");
    graphics::update_boot_progress_with_message(100, "Ready!");

    // 7. システム統計を表示
    print_system_stats();

    // 8. Executorの作成とタスクスポーン
    info!(target: "init", "Creating async executor");
    let mut executor = task::Executor::new();

    spawn_kernel_tasks(&mut executor);
    info!(target: "init", "Kernel tasks spawned");

    info!(target: "run", "Starting executor main loop");
    info!("================================================================================");

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
    let domain2 = domain_system::create_domain(alloc::string::String::from("ipc_demo"));
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
        
        info!(target: "task9", "Graphical shell started - polling...");
        
        // メインループ（ポーリング方式）
        loop {
            // キー入力と描画を処理
            shell::graphical::poll();
            
            // CPUを少し休ませる（約16ms = 60fps程度）
            task::sleep_ms(16).await;
        }
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
            alloc::string::String::from("sys_sleep"),
            sys_sleep as *const () as usize,
        );
    });

    debug!(target: "loader", "Kernel symbols registered");
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
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    panic_handler::handle_panic(info)
}
