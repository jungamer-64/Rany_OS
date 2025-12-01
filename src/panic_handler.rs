// ============================================================================
// src/panic_handler.rs - Enhanced Panic Handler with Domain Isolation
// 設計書 8.1: スタックアンワインドとリソース回収
// ============================================================================

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};
use alloc::string::String;
use spin::Mutex;

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
    
    // パニック回数をインクリメント
    let count = PANIC_COUNT.fetch_add(1, Ordering::Relaxed);
    
    // 現在のドメインIDを取得
    let domain_id = get_current_domain();
    
    // パニックメッセージを構築
    let message = if let Some(msg) = info.payload().downcast_ref::<&str>() {
        String::from(*msg)
    } else if let Some(msg) = info.payload().downcast_ref::<String>() {
        msg.clone()
    } else {
        String::from("Unknown panic")
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
    
    // エラー出力
    crate::log!("\n");
    crate::log!("================================================================================\n");
    crate::log!("                            !!! KERNEL PANIC !!!\n");
    crate::log!("================================================================================\n");
    crate::log!("Panic #{}\n", count + 1);
    
    if let Some(loc) = &location {
        crate::log!("Location: {}:{}:{}\n", loc.file, loc.line, loc.column);
    }
    
    crate::log!("Message: {}\n", message);
    
    if domain_id > 0 {
        crate::log!("Domain ID: {}\n", domain_id);
        
        // ドメイン固有のパニック処理を試みる
        if try_handle_domain_panic(domain_id, &message) {
            // ドメインのリソースを回収して続行を試みる
            crate::log!("Domain {} terminated, attempting to continue...\n", domain_id);
            
            // ドメインをリセット
            set_current_domain(0);
            
            // 注意: no_std環境では実際のアンワインドは困難
            // ここでは概念的な処理を示す
        }
    }
    
    crate::log!("================================================================================\n");
    
    // システム停止
    loop {
        x86_64::instructions::hlt();
    }
}

/// ドメイン固有のパニック処理を試みる
/// 設計書 8.1: 障害を起こしたドメインに関連するすべてのタスクとリソースを解放
fn try_handle_domain_panic(domain_id: u64, message: &str) -> bool {
    use crate::ipc::rref::DomainId;
    
    let id = DomainId::new(domain_id);
    
    // ドメインのリソースを回収
    crate::ipc::reclaim_domain_resources(id);
    
    // ドメインの状態を更新
    crate::domain::lifecycle::handle_domain_panic(id, String::from(message));
    
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
pub fn handle_double_fault(stack_frame: &x86_64::structures::idt::InterruptStackFrame, error_code: u64) -> ! {
    x86_64::instructions::interrupts::disable();
    
    crate::log!("\n");
    crate::log!("================================================================================\n");
    crate::log!("                         !!! DOUBLE FAULT !!!\n");
    crate::log!("================================================================================\n");
    crate::log!("Error Code: {}\n", error_code);
    crate::log!("Stack Frame:\n{:#?}\n", stack_frame);
    crate::log!("================================================================================\n");
    
    loop {
        x86_64::instructions::hlt();
    }
}

// ============================================================================
// Stack Overflow Detection
// ============================================================================

/// スタックオーバーフロー検出用のガードページ設定
/// 将来的な実装のためのプレースホルダー
pub fn setup_stack_guard(_stack_bottom: usize, _stack_size: usize) {
    // TODO: ガードページの設定
    // ページテーブルでスタック下端をマップ解除してアクセス時にPage Faultを発生させる
}

// ============================================================================
// Abort Handler
// ============================================================================

/// 回復不能なエラー時の処理
pub fn abort(message: &str) -> ! {
    x86_64::instructions::interrupts::disable();
    
    crate::log!("\n!!! ABORT: {} !!!\n", message);
    
    loop {
        x86_64::instructions::hlt();
    }
}
