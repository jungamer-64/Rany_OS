#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

extern crate alloc;

use core::panic::PanicInfo;

mod allocator;
mod memory;
mod mm;
mod task;
mod vga;
mod interrupts;
mod io;
mod loader;
mod net;
mod fs;
mod smp;
mod spectre;
mod unwind;
mod panic_handler;
mod sync;
mod domain_system;
mod domain;
mod sas;
mod error;

// ipc モジュールは ipc/ ディレクトリを使用
mod ipc {
    pub mod rref;
    pub mod proxy;
    pub use rref::{DomainId, RRef, reclaim_domain_resources};
    #[allow(unused_imports)]
    pub use proxy::{DomainProxy, ProxyError, ProxyResult};
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // VGAバッファの初期化（ログ出力用）
    vga::init();
    
    print_logo();
    log!("ExoRust Kernel v0.2.0 - Booting...\n");
    
    // 1. メモリ管理の初期化
    log!("[INIT] Initializing memory subsystem\n");
    memory::init();
    log!("[OK] Memory subsystem initialized\n");
    
    // 2. ドメイン管理システムの初期化
    log!("[INIT] Initializing domain system\n");
    domain_system::init();
    log!("[OK] Domain system initialized\n");
    
    // 3. 割り込みシステムの初期化（GDT/TSS + IDT + PIC）
    log!("[INIT] Initializing interrupt system\n");
    interrupts::init();
    log!("[OK] Interrupt system initialized\n");
    
    // 4. タスクスケジューラの初期化
    log!("[INIT] Initializing task scheduler\n");
    task::init_scheduler(0); // CPU 0
    log!("[OK] Task scheduler initialized\n");
    
    // 5. ローダーシステムの初期化
    log!("[INIT] Initializing cell loader\n");
    loader::init_kernel_cell();
    register_kernel_symbols();
    log!("[OK] Cell loader initialized\n");
    
    // 5.5. シンボルテーブルの初期化（バックトレース用）
    log!("[INIT] Initializing symbol table\n");
    unwind::init_symbol_table();
    log!("[OK] Symbol table initialized\n");
    
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
    use task::Task;
    use ipc::RRef;
    
    // ドメイン1を作成：ユーザーアプリケーション
    let domain1 = domain_system::create_domain(alloc::string::String::from("user_app_1"));
    domain_system::start_domain(domain1).ok();
    
    // タスク1: ドメイン1のメインタスク
    executor.spawn(Task::new(async move {
        log!("[Task 1] User application domain started (ID: {})\n", domain1.as_u64());
        
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
        let data = RRef::new(ipc::DomainId::new(domain1.as_u64()), alloc::vec![0xDE, 0xAD, 0xBE, 0xEF]);
        log!("[Task 2] Created RRef in domain {}\n", domain1.as_u64());
        
        // 所有権を domain2 に移動
        let data = data.move_to(ipc::DomainId::new(domain2.as_u64()));
        log!("[Task 2] Transferred ownership to domain {} (zero-copy)\n", 
            data.owner().as_u64());
        
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
            log!("[Task 3] Preemption Stats - Forced: {}, Voluntary: {}\n",
                stats.forced_preemptions, stats.voluntary_yields);
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
            log!("[Task 4] Domains: {} total, {} running\n",
                domain_stats.total, domain_stats.running);
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
        }).await;
        
        log!("[Task 5] Completed\n");
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
    log!("[STATS] Domains: {} total, {} running, {} stopped\n",
        domain_stats.total,
        domain_stats.running,
        domain_stats.stopped);
    
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
