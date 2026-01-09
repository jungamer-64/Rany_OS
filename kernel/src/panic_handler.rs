// ============================================================================
// src/panic_handler.rs - Enhanced Panic Handler with Domain Isolation
// 設計書 8.1: スタックアンワインドとリソース回収
// ============================================================================
#![allow(dead_code)]

use alloc::string::String;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

/// 【設計書 8.5.1】Double Panic検出用フラグ
/// 各CPUコアにパニック中フラグを設置（現在は単一コア想定）
static PANIC_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

/// パニック情報の記録
#[derive(Debug)]
pub struct PanicRecord {
    /// パニックメッセージ
    pub message: String,
    /// パニックが発生したドメインID
    pub domain_id: Option<u64>,
    /// パニックが発生した場所
    pub location: Option<PanicLocation>,
    /// パニック発生時刻（ティック）
    pub tick: u64,
}

/// パニック発生場所
#[derive(Debug, Clone)]
pub struct PanicLocation {
    pub file: String,
    pub line: u32,
    pub column: u32,
}

/// パニック統計
static PANIC_COUNT: AtomicU64 = AtomicU64::new(0);
static LAST_PANIC: Mutex<Option<PanicRecord>> = Mutex::new(None);

/// 現在実行中のドメインID（Thread Local相当）
/// 実際のマルチコア環境ではCPUごとに保持する必要がある
static CURRENT_DOMAIN_ID: AtomicU64 = AtomicU64::new(0);

/// 現在のドメインIDを設定
pub fn set_current_domain(domain_id: u64) {
    CURRENT_DOMAIN_ID.store(domain_id, Ordering::Release);
}

/// 現在のドメインIDを取得
pub fn get_current_domain() -> u64 {
    CURRENT_DOMAIN_ID.load(Ordering::Acquire)
}

/// パニックハンドラの本体
/// 設計書 8.1: パニック捕捉とドメイン境界での処理
pub fn handle_panic(info: &PanicInfo) -> ! {
    // 割り込みを無効化
    x86_64::instructions::interrupts::disable();

    // 【設計書 8.2】パニック捕捉が有効かチェック（catch_panic機構）
    // プロキシ呼び出し中であれば、パニックを記録して特別な処理を行う
    if crate::unwind::is_panic_catch_active() {
        // パニックメッセージを抽出
        let message = {
            use core::fmt::Write;
            let mut s = String::new();
            let _ = write!(s, "{}", info.message());
            if s.is_empty() {
                String::from("Unknown panic")
            } else {
                s
            }
        };
        
        // パニック場所情報を抽出
        let (file, line, column) = info.location()
            .map(|loc| (Some(loc.file()), Some(loc.line()), Some(loc.column())))
            .unwrap_or((None, None, None));
        
        // パニック情報を記録
        crate::unwind::record_caught_panic(&message, file, line, column);
        
        // プロキシ呼び出し中のパニックも記録
        crate::ipc::proxy::record_proxy_panic(message);
        
        // 注意: 現在の実装では真のsetjmp/longjmpがないため、
        // ここでHALTする。将来的にはランディングパッドに
        // ジャンプして復帰できるようにする。
        log::info!("[PanicHandler] Panic caught in catch_panic context, halting...");
        loop {
            x86_64::instructions::hlt();
        }
    }

    // 【設計書 8.5.1】Double Panic検出
    // パニックハンドラの入口でこのフラグをチェックし、
    // 既にtrueであればDouble Panicと判定して即座にabort
    if PANIC_IN_PROGRESS.swap(true, Ordering::SeqCst) {
        // 既にパニック処理中 → Double Panic検出
        // 最小限のエラー情報をシリアルポートに出力
        crate::io::log::early_print("\n!!! DOUBLE PANIC DETECTED !!!\n");
        crate::io::log::early_print("Aborting without further processing.\n");

        // 即座にHALT（スタックアンワインドを試みない）
        loop {
            x86_64::instructions::hlt();
        }
    }

    // 【設計書 8.4】パニック状態をマーク（PoisonLockのため）
    crate::sync::set_panicking(true);

    // パニックモードに入る（ログ出力時のデッドロック回避）
    crate::io::log::enter_panic_mode();

    // パニック回数をインクリメント
    let count = PANIC_COUNT.fetch_add(1, Ordering::Relaxed);

    // 現在のドメインIDを取得
    let domain_id = get_current_domain();

    // 3. ログ出力（ヒープ割り当ての前に行う！）
    //
    // 注意: ここで String::new() などを呼ぶと、パニックの原因がメモリアロケータの破損だった場合に
    // ダブルパニック（再帰的パニック）が発生し、元のパニック理由が表示されないままシステム停止する。
    // したがって、まず最小限の情報を出力し、その後にリッチなログ記録を試みる。

    // Raw output to ensure we see SOMETHING
    crate::io::log::early_print("\n!!! KERNEL PANIC DETECTED !!!\n");

    // Print location if available
    if let Some(location) = info.location() {
        log::error!(
            "Panic at {}:{}:{}",
            location.file(),
            location.line(),
            location.column()
        );
    } else {
        log::error!("Panic at unknown location");
    }

    // Print message directly (no heap alloc yet)
    log::error!("Message: {}", info.message());

    // ここから下はヒープ割り当てを含む可能性があるため、失敗するリスクがある
    // パニックメッセージを構築（DMAログ用）
    let message = {
        use core::fmt::Write;
        // String::new() はヒープを使用する
        let mut s = String::new();
        // PanicMessage から文字列を取得
        if write!(s, "{}", info.message()).is_err() {
            // アロケーション失敗時は静的文字列を使用（ダブルパニック回避の最終手段）
            String::from("Panic (OOM while formatting message)")
        } else if s.is_empty() {
             String::from("Unknown panic")
        } else {
             s
        }
    };

    // パニック場所を記録
    let location = info.location().map(|loc| PanicLocation {
        file: String::from(loc.file()),
        line: loc.line(),
        column: loc.column(),
    });

    // パニック情報を保存
    let record = PanicRecord {
        message: message.clone(),
        domain_id: if domain_id > 0 { Some(domain_id) } else { None },
        location: location.clone(),
        tick: crate::task::timer::current_tick(),
    };

    *LAST_PANIC.lock() = Some(record);

    if let Some(info) = crate::io::iommu::panic::write_panic_record(&message) {
        log::info!(
            "[PANIC] DMA record: iova=0x{:x} phys=0x{:x} len={}",
            info.iova,
            info.phys.as_u64(),
            info.len
        );
    }

    // エラー出力（シリアルコンソール用）
    log::info!("\n");
    log::info!(
        "================================================================================\n"
    );
    log::info!("                            !!! KERNEL PANIC !!!\n");
    log::info!(
        "================================================================================\n"
    );
    log::info!("Panic #{}\n", count + 1);

    if let Some(loc) = &location {
        log::info!("Location: {}:{}:{}\n", loc.file, loc.line, loc.column);
    }

    log::info!("Message: {}\n", message);

    if domain_id > 0 {
        log::info!("Domain ID: {}\n", domain_id);

        // ドメイン固有のパニック処理を試みる
        if try_handle_domain_panic(domain_id, &message) {
            // ドメインのリソースを回収して続行を試みる
            log::info!(
                "Domain {} terminated, attempting to continue...\n",
                domain_id
            );

            // ドメインをリセット
            set_current_domain(0);

            // 注意: no_std環境では実際のアンワインドは困難
            // ここでは概念的な処理を示す
        }
    }

    log::info!(
        "================================================================================\n"
    );

    // BSOD表示を試みる（グラフィックモードが利用可能な場合）
    display_bsod_on_panic(
        &message,
        location.as_ref().map(|l| l.file.as_str()),
        location.as_ref().and_then(|l| Some(l.line)),
        location.as_ref().and_then(|l| Some(l.column)),
    );

    // システム停止
    loop {
        x86_64::instructions::hlt();
    }
}

/// ドメイン固有のパニック処理を試みる
/// 設計書 8.1: 障害を起こしたドメインに関連するすべてのタスクとリソースを解放
/// 設計書 8.4: ドメインが所有するオブジェクトをポイズニング
fn try_handle_domain_panic(domain_id: u64, _message: &str) -> bool {
    use crate::ipc::rref::DomainId;

    let id = DomainId::new(domain_id);
    let sas_domain_id = crate::sas::DomainId::new(domain_id);

    // 【設計書 8.4】ドメインが所有する全オブジェクトをポイズニング
    // これにより、他のドメインがこのドメインのRRefにアクセスしようとすると
    // Poisonedエラーが返される
    let poisoned_count = crate::sas::poison_domain_objects(sas_domain_id);
    if poisoned_count > 0 {
        log::info!(
            "[PanicHandler] Poisoned {} objects owned by domain {}\n",
            poisoned_count,
            domain_id
        );
    }

    // ドメインのリソースを回収
    crate::ipc::reclaim_domain_resources(id);

    // 注意: 完全な実装ではdomainモジュールとの統合が必要
    // crate::domain::lifecycle::handle_domain_panic(id, String::from(message));

    true
}

/// パニック統計を取得
pub fn panic_stats() -> PanicStats {
    PanicStats {
        total_panics: PANIC_COUNT.load(Ordering::Relaxed),
        last_panic: LAST_PANIC.lock().as_ref().map(|r| r.message.clone()),
    }
}

/// パニック統計
#[derive(Debug, Clone)]
pub struct PanicStats {
    pub total_panics: u64,
    pub last_panic: Option<String>,
}

// ============================================================================
// Double Fault Handler
// ============================================================================

/// Double Fault発生時のハンドラ
pub fn handle_double_fault(
    stack_frame: &x86_64::structures::idt::InterruptStackFrame,
    error_code: u64,
) -> ! {
    x86_64::instructions::interrupts::disable();

    log::info!("\n");
    log::info!(
        "================================================================================\n"
    );
    log::info!("                         !!! DOUBLE FAULT !!!\n");
    log::info!(
        "================================================================================\n"
    );
    log::info!("Error Code: {}\n", error_code);
    log::info!("Stack Frame:\n{:#?}\n", stack_frame);
    log::info!(
        "================================================================================\n"
    );

    // BSOD表示を試みる (テスト/ベンチビルドではグラフィックスは無効化されているためスキップ)
    #[cfg(not(any(test, feature = "bench")))]
    {
        crate::graphics::bsod::show_double_fault_bsod(stack_frame, error_code);
    }

    loop {
        x86_64::instructions::hlt();
    }
}

// ============================================================================
// Stack Overflow Detection
// ============================================================================

/// スタックオーバーフロー検出用のガードページ設定
///
/// 【設計書 8.3】ガードページによるスタックオーバーフロー検出
///
/// スタックの下端（低アドレス側）にガードページ（Present=0）を配置する。
/// スタックオーバーフローが発生すると、ガードページへのアクセスにより
/// Page Fault (#PF) が発生し、カスタムPage Faultハンドラがこれを捕捉する。
///
/// # 引数
/// - `stack_bottom`: スタックの下端アドレス（ガードページを配置する位置）
/// - `stack_size`: スタックのサイズ（バイト単位）
///
/// # 安全性
/// この関数を呼び出す前に、`stack_bottom`がページ境界にアラインされている必要がある。
pub fn setup_stack_guard(stack_bottom: usize, _stack_size: usize) {
    use crate::mm::higher_half::VirtAddr;

    // ガードページのアドレス（スタックの直下）
    let guard_page_addr = VirtAddr::new(stack_bottom as u64).align_down();

    // ページテーブルからガードページをアンマップ
    // これにより、このアドレスへのアクセスはPage Faultを発生させる
    unsafe {
        if let Err(e) = crate::mm::higher_half::global_unmap_page(guard_page_addr) {
            // アンマップに失敗した場合（既にマップされていない等）は警告のみ
            log::warn!(
                "[StackGuard] Warning: Could not setup guard page at {:?}: {:?}",
                guard_page_addr,
                e
            );
        } else {
            log::info!(
                "[StackGuard] Guard page set at {:?} (stack bottom)",
                guard_page_addr
            );
        }
    }
}

/// タスクスタック用のガードページを設定
///
/// 各タスクのスタックにガードページを設定する。
/// Per-Core ExecutorやTaskManagerから呼び出される。
pub fn setup_task_stack_guard(stack_start: usize, stack_size: usize) {
    // スタックは高アドレスから低アドレスに向かって成長する
    // ガードページはスタックの最下端（stack_start）の直下に配置
    setup_stack_guard(stack_start, stack_size);
}

/// IST（Interrupt Stack Table）スタック用のガードページを設定
///
/// Double FaultやPage Fault用のISTスタックにもガードページを設定する。
pub fn setup_ist_stack_guards() {
    

    // ISTスタックの情報を取得してガードページを設定
    // 現在のGDT実装では静的に確保されているため、
    // ここでは警告のみを出力
    log::warn!("[StackGuard] IST stack guard pages should be configured manually");
}

// ============================================================================
// Abort Handler
// ============================================================================

/// 回復不能なエラー時の処理
pub fn abort(message: &str) -> ! {
    x86_64::instructions::interrupts::disable();

    log::info!("\n!!! ABORT: {} !!!\n", message);

    loop {
        x86_64::instructions::hlt();
    }
}

// ============================================================================
// BSOD Display Functions
// ============================================================================

/// パニック時にBSODを表示
///
/// グラフィックモードが利用可能な場合、青い画面にエラー情報を表示する。
/// フレームバッファが未初期化の場合は何もしない。
#[cfg(not(any(test, feature = "bench")))]
fn display_bsod_on_panic(
    message: &str,
    file: Option<&str>,
    line: Option<u32>,
    column: Option<u32>,
) {
    // グラフィックスが初期化されているか確認
    // パニック時はデッドロックを回避するために強制的にロックを解除
    unsafe {
        crate::graphics::force_unlock_framebuffer();
    }

    if crate::graphics::framebuffer().is_none() {
        log::info!("[BSOD] Framebuffer not available, skipping BSOD display\n");
        return;
    }

    log::info!("[BSOD] Displaying Blue Screen of Death...\n");

    // BSOD表示
    crate::graphics::bsod::show_panic_bsod(message, file, line, column);
}

#[cfg(any(test, feature = "bench"))]
fn display_bsod_on_panic(
    _message: &str,
    _file: Option<&str>,
    _line: Option<u32>,
    _column: Option<u32>,
) {
    // No-op in tests
}

/// 手動でBSODをテスト表示する
///
/// デバッグ用途でBSOD表示をテストするための関数
#[cfg(not(any(test, feature = "bench")))]
pub fn test_bsod(message: &str) {
    crate::graphics::bsod::show_panic_bsod(message, Some("test_file.rs"), Some(42), Some(1));
}

#[cfg(any(test, feature = "bench"))]
pub fn test_bsod(_message: &str) {
    // No-op in tests
}
