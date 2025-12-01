#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

extern crate alloc;

use core::panic::PanicInfo;

mod memory;
mod mm;
mod task;
mod ipc;
mod vga;
mod interrupts;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // VGAバッファの初期化（ログ出力用）
    vga::init();
    
    print_logo();
    log!("ExoRust Kernel v0.1.0 - Booting...\n");
    
    // メモリ管理の初期化
    log!("[INIT] Initializing memory subsystem\n");
    memory::init();
    log!("[OK] Memory subsystem initialized\n");
    
    // 割り込みシステムの初期化
    log!("[INIT] Initializing interrupt system\n");
    interrupts::init_idt();
    interrupts::init_pics();
    interrupts::enable_interrupts();
    log!("[OK] Interrupt system initialized\n");
    
    // Executorの作成
    log!("[INIT] Creating async executor\n");
    let mut executor = task::Executor::new();
    
    // サンプルタスクのスポーン
    spawn_example_tasks(&mut executor);
    log!("[OK] Example tasks spawned\n");
    
    log!("[RUN] Starting executor main loop\n");
    // メインループ開始（戻ってこない）
    executor.run();
}

/// サンプルタスクをスポーン
fn spawn_example_tasks(executor: &mut task::Executor) {
    use task::Task;
    use ipc::{DomainId, RRef};
    
    // タスク1: 非同期カウンター
    executor.spawn(Task::new(async {
        log!("[Task 1] Async counter started\n");
        for i in 0..3 {
            log!("[Task 1] Count: {}\n", i);
        }
        log!("[Task 1] Completed\n");
    }));
    
    // タスク2: ゼロコピー通信のデモ
    executor.spawn(Task::new(async {
        log!("[Task 2] Zero-copy demo started\n");
        
        let domain1 = DomainId::new(1);
        let domain2 = DomainId::new(2);
        
        // RRefを作成（データはExchange Heap上に配置）
        let data = RRef::new(domain1, alloc::vec![0xDE, 0xAD, 0xBE, 0xEF]);
        log!("[Task 2] Created RRef ({} bytes) in domain {}\n", data.len(), domain1.as_u64());
        
        // 所有権をdomain2に移動（ゼロコピー）
        let data = data.move_to(domain2);
        log!("[Task 2] Moved RRef to domain {} (zero-copy!)\n", data.owner().as_u64());
        
        log!("[Task 2] Completed\n");
    }));
    
    // タスク3: Wakerのテスト
    executor.spawn(Task::new(async {
        log!("[Task 3] Waker test started\n");
        
        // poll_fn を使ってカスタムFutureを作成
        use core::future::poll_fn;
        use core::task::Poll;
        
        let mut counter = 0;
        poll_fn(|_cx| {
            counter += 1;
            if counter >= 3 {
                log!("[Task 3] Polled {} times, completing\n", counter);
                Poll::Ready(())
            } else {
                log!("[Task 3] Polled {} times, pending\n", counter);
                Poll::Pending
            }
        }).await;
        
        log!("[Task 3] Completed\n");
    }));
    
    // タスク4: 非同期スリープのデモ
    executor.spawn(Task::new(async {
        use task::sleep_ms;
        
        log!("[Task 4] Sleep demo started\n");
        log!("[Task 4] Sleeping for 1000ms...\n");
        sleep_ms(1000).await;
        log!("[Task 4] Woke up! Tick={}\n", task::current_tick());
        log!("[Task 4] Completed\n");
    }));
}

/// ExoRustロゴを表示
fn print_logo() {
    log!("================================================\n");
    log!("  ___           ____            _   \n");
    log!(" | __|_ _____ _|  _ \\ _  _ ___ | |_ \n");
    log!(" | _|\\ \\ / _ \\ | |_) | || (_-< |  _|\n");
    log!(" |___/_\\_\\___|_|____/ \\_,_/__/  \\__|\n");
    log!("\n");
    log!("  SAS | Async-First | Zero-Copy\n");
    log!("================================================\n");
}

/// Panicハンドラ
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    log!("\n!!! KERNEL PANIC !!!\n{}\n", info);
    loop {
        x86_64::instructions::hlt();
    }
}
