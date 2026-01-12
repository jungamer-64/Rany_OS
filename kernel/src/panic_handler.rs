// ============================================================================
// src/panic_handler.rs - Enhanced Panic Handler with Domain Isolation
// 設計書 8.1: スタックアンワインドとリソース回収
// ============================================================================
#![allow(dead_code)]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use core::mem::MaybeUninit;
use core::fmt::{self, Write};

/// 【設計書 8.5.1】Double Panic検出用フラグ
/// 各CPUコアにパニック中フラグを設置（現在は単一コア想定）
static PANIC_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

/// パニック状態
/// 0: 初期状態
/// 1: 書き込み中 (Locked)
/// 2: 書き込み完了 (Valid)
static PANIC_RECORD_STATE: AtomicU8 = AtomicU8::new(0);

const MAX_PANIC_MSG: usize = 1024;
const MAX_FILE_LEN: usize = 128;

/// パニック情報の記録 (ヒープ割り当てなし)
pub struct PanicRecord {
    /// パニックメッセージ (UTF-8 bytes)
    pub message: [u8; MAX_PANIC_MSG],
    pub message_len: usize,
    /// パニックが発生したドメインID
    pub domain_id: Option<u64>,
    /// パニックが発生した場所
    pub location: Option<PanicLocation>,
    /// パニック発生時刻（ティック）
    pub tick: u64,
}

/// パニック発生場所 (ヒープ割り当てなし)
#[derive(Clone, Copy)]
pub struct PanicLocation {
    pub file: [u8; MAX_FILE_LEN],
    pub file_len: usize,
    pub line: u32,
    pub column: u32,
}

/// 静的パニックレコードバッファ
static mut PANIC_RECORD: MaybeUninit<PanicRecord> = MaybeUninit::uninit();

/// パニック統計
static PANIC_COUNT: AtomicU64 = AtomicU64::new(0);

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

/// 固定長バッファへの書き込み用ヘルパー
struct PanicBufferWriter<'a> {
    buffer: &'a mut [u8],
    offset: usize,
}

impl<'a> PanicBufferWriter<'a> {
    fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, offset: 0 }
    }
}

impl<'a> Write for PanicBufferWriter<'a> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let remaining = self.buffer.len() - self.offset;
        let bytes = s.as_bytes();
        let len = bytes.len().min(remaining);
        
        if len > 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    self.buffer.as_mut_ptr().add(self.offset),
                    len,
                );
            }
            self.offset += len;
        }
        
        if len < bytes.len() {
            // Buffer full, but we don't error, just truncate
            Ok(()) 
        } else {
            Ok(())
        }
    }
}

/// パニックハンドラの本体
/// 設計書 8.1: パニック捕捉とドメイン境界での処理
pub fn handle_panic(info: &PanicInfo) -> ! {
    // 割り込みを無効化
    x86_64::instructions::interrupts::disable();

    // 【設計書 8.5.1】Double Panic検出
    // パニックハンドラの入口でこのフラグをチェックし、
    // 既にtrueであればDouble Panicと判定して即座にabort
    if PANIC_IN_PROGRESS.swap(true, Ordering::SeqCst) {
        // 既にパニック処理中 → Double Panic検出
        // 最小限のエラー情報をシリアルポートに出力
        crate::io::log::early_print("\n!!! DOUBLE PANIC DETECTED !!!\n");
        crate::io::log::early_print("Aborting without further processing.\n");

        // 即座にHALT
        loop {
            x86_64::instructions::hlt();
        }
    }

    // パニックモードに入る（ログ出力時のデッドロック回避）
    // これにより、以降の log::info! 等はロックなしでシリアルに出力しようとする
    crate::io::log::enter_panic_mode();
    
    // 【設計書 8.4】パニック状態をマーク（PoisonLockのため）
    crate::sync::set_panicking(true);

    // パニック回数をインクリメント
    let _count = PANIC_COUNT.fetch_add(1, Ordering::Relaxed);

    // 現在のドメインIDを取得
    let domain_id = get_current_domain();

    // Raw output to ensure we see SOMETHING
    crate::io::log::early_print("\n!!! KERNEL PANIC DETECTED !!!\n");
    
    // ロックフリーなパニックレコードの構築
    // 最初のパニックのみがレコードを書き込む権利を持つ
    let mut message_slice: &[u8] = b"Unknown panic";
    
    // 静的バッファへの書き込み（競合に勝った場合のみ）
    if PANIC_RECORD_STATE.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire).is_ok() {
        unsafe {
            // Use core::ptr::addr_of_mut! to avoid creating a reference to static mut
            let record_ptr = core::ptr::addr_of_mut!(PANIC_RECORD) as *mut PanicRecord;
            let record_ref = &mut *record_ptr;
            
            // 1. メッセージのフォーマット
            let mut writer = PanicBufferWriter::new(&mut record_ref.message);
            let _ = write!(writer, "{}", info.message());
            record_ref.message_len = writer.offset;
            message_slice = &record_ref.message[..record_ref.message_len];

            // 2. ロケーションの保存
            if let Some(loc) = info.location() {
                let mut file_buf = [0u8; MAX_FILE_LEN];
                let file_bytes = loc.file().as_bytes();
                let copy_len = file_bytes.len().min(MAX_FILE_LEN);
                core::ptr::copy_nonoverlapping(file_bytes.as_ptr(), file_buf.as_mut_ptr(), copy_len);
                
                record_ref.location = Some(PanicLocation {
                    file: file_buf,
                    file_len: copy_len,
                    line: loc.line(),
                    column: loc.column(),
                });
            } else {
                record_ref.location = None;
            }

            // 3. その他情報の保存
            record_ref.domain_id = if domain_id > 0 { Some(domain_id) } else { None };
            record_ref.tick = crate::task::timer::current_tick();

            // 書き込み完了マーク
            PANIC_RECORD_STATE.store(2, Ordering::Release);
        }
    } else {
        // 他のコアが書き込み中または完了済み。
        // ここではメッセージの取得は諦め、デフォルトメッセージを使うか、直接出力する
        crate::io::log::early_print("Concurrent panic detected, skipping record capture.\n");
    }

    // ログ出力 (Lock-Free)
    if let Some(location) = info.location() {
        crate::io::log::early_print("Panic at ");
        crate::io::log::early_print(location.file());
        crate::io::log::early_print(":");
        crate::io::log::early_print_dec(location.line() as u64);
        crate::io::log::early_print(":");
        crate::io::log::early_print_dec(location.column() as u64);
        crate::io::log::early_print("\n");
    } else {
        crate::io::log::early_print("Panic at unknown location\n");
    }

    crate::io::log::early_print("Message: ");
    if let Ok(s) = core::str::from_utf8(message_slice) {
        crate::io::log::early_print(s);
    } else {
        crate::io::log::early_print("(invalid utf8 message)");
    }
    crate::io::log::early_print("\n");
    
    // IOMMU Panic Record (Lock-Free)
    if let Ok(s) = core::str::from_utf8(message_slice) {
        if let Some(info) = crate::io::iommu::panic::write_panic_record(s) {
            crate::io::log::early_print("[PANIC] DMA record saved\n");
            // 詳細なIOMMU情報はデバッグに有用だが、ここでallocを使わずにprintするのは面倒なので省略、
            // またはearly_print_hexを使って頑張る
            crate::io::log::early_print("DMA iova=0x");
            crate::io::log::early_print_hex(info.iova);
            crate::io::log::early_print(" phys=0x");
            crate::io::log::early_print_hex(info.phys.as_u64());
            crate::io::log::early_print("\n");
        }
    }

    // ドメイン処理
    if domain_id > 0 {
        crate::io::log::early_print("Domain ID: ");
        crate::io::log::early_print_dec(domain_id);
        crate::io::log::early_print("\n");

        if let Ok(s) = core::str::from_utf8(message_slice) {
            if try_handle_domain_panic(domain_id, s) {
                 crate::io::log::early_print("Domain terminated, attempting to continue...\n");
                 set_current_domain(0);
                 // Note: Actual continuation requires longjmp which is not implemented here.
            }
        }
    }

    // BSOD and Serial Dump (Lock-Free)
    // display_bsod_on_panic handles force unlocking framebuffer internally
    // We pass slice references constructed from the raw buffer if valid, to avoid String allocation
    
    // 1. Capture additional debugging info (Registers, Backtrace)
    use crate::graphics::bsod::{BsodInfo, RegisterDump};
    use crate::unwind::Backtrace;
    
    // Note: Capture backtrace first as it might be relevant for registers? 
    // Actually registers are from *now*. Backtrace walks *now*.
    let registers = RegisterDump::capture();
    let backtrace = Backtrace::capture();
    
    let (file_str, line, col) = unsafe {
        if PANIC_RECORD_STATE.load(Ordering::Acquire) == 2 {
            let record_ptr = core::ptr::addr_of!(PANIC_RECORD) as *const PanicRecord;
            let record = &*record_ptr;
            if let Some(loc) = &record.location {
                let f = core::str::from_utf8(&loc.file[..loc.file_len]).unwrap_or("unknown");
                (Some(f), Some(loc.line), Some(loc.column))
            } else {
                (None, None, None)
            }
        } else {
            (None, None, None)
        }
    };
    
    let msg_str = core::str::from_utf8(message_slice).unwrap_or("Panic error");
    let first_word = msg_str.split_whitespace().next().unwrap_or("KERNEL_PANIC");

    // 2. Construct BsodInfo
    let mut bsod_info = BsodInfo::new(msg_str);
    if let (Some(f), Some(l), Some(c)) = (file_str, line, col) {
        bsod_info = bsod_info.with_location(f, l, c);
    }
    bsod_info = bsod_info
        .with_registers(registers)
        .with_backtrace(backtrace)
        .with_error_code(first_word);

    // 3. Dump to Serial (First priority)
    crate::graphics::bsod::dump_bsod_info_to_serial(&bsod_info);

    // 4. Display on Screen
    display_bsod_on_panic(&bsod_info);

    // システム停止
    loop {
        x86_64::instructions::hlt();
    }
}

/// ドメイン固有のパニック処理を試みる
fn try_handle_domain_panic(domain_id: u64, _message: &str) -> bool {
    use crate::ipc::rref::DomainId;

    let id = DomainId::new(domain_id);
    let sas_domain_id = crate::sas::DomainId::new(domain_id);

    // 【設計書 8.4】ドメインが所有する全オブジェクトをポイズニング
    let poisoned_count = crate::sas::poison_domain_objects(sas_domain_id);
    if poisoned_count > 0 {
        crate::io::log::early_print("[PanicHandler] Poisoned objects owned by domain\n");
    }

    // ドメインのリソースを回収
    crate::ipc::reclaim_domain_resources(id);

    true
}

/// パニック統計を取得 (Lock-Free read attempt)
/// 注意: Stringを返すため、アロケーションが発生します。パニックハンドラ内では使用しないでください。
pub fn panic_stats() -> PanicStats {
    let msg = unsafe {
        if PANIC_RECORD_STATE.load(Ordering::Acquire) == 2 {
            let record_ptr = core::ptr::addr_of!(PANIC_RECORD) as *const PanicRecord;
            let record = &*record_ptr;
            let s = core::str::from_utf8(&record.message[..record.message_len]).unwrap_or("Invalid UTF-8");
            Some(alloc::string::String::from(s))
        } else {
            None
        }
    };

    PanicStats {
        total_panics: PANIC_COUNT.load(Ordering::Relaxed),
        last_panic: msg,
    }
}

/// パニック統計
#[derive(Debug, Clone)]
pub struct PanicStats {
    pub total_panics: u64,
    pub last_panic: Option<alloc::string::String>,
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
    
    // Ensure we can print even if locks are held
    crate::io::log::enter_panic_mode();

    crate::io::log::early_print("\n!!! DOUBLE FAULT !!!\n");
    crate::io::log::early_print("Error Code: ");
    crate::io::log::early_print_dec(error_code);
    crate::io::log::early_print("\n");
    
    // Stack frame dump would require formatting wrapper for early_print, 
    // or we can just rely on the fact that enter_panic_mode allows log::info! to work without locks?
    // Let's stick to early_print where possible for absolute safety, but accessing the logger might work now.
    // However, log::info! macro expands to allocating code sometimes (formatting arguments).
    // Safest is to just print what we can simply.
    
    // BSOD表示を試みる
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

pub fn setup_stack_guard(stack_bottom: usize, _stack_size: usize) {
    use crate::mm::higher_half::VirtAddr;

    // ガードページのアドレス（スタックの直下）
    let guard_page_addr = VirtAddr::new(stack_bottom as u64).align_down();

    // ページテーブルからガードページをアンマップ
    unsafe {
        if let Err(e) = crate::mm::higher_half::global_unmap_page(guard_page_addr) {
            // alloc::formatは使わない
             crate::io::log::early_print("[StackGuard] Warning: Could not setup guard page\n");
             let _ = e;
        } else {
             // Success
        }
    }
}

pub fn setup_task_stack_guard(stack_start: usize, stack_size: usize) {
    setup_stack_guard(stack_start, stack_size);
}

pub fn setup_ist_stack_guards() {
    // nothing
}

// ============================================================================
// Abort Handler
// ============================================================================

pub fn abort(message: &str) -> ! {
    x86_64::instructions::interrupts::disable();
    crate::io::log::enter_panic_mode();
    crate::io::log::early_print("\n!!! ABORT: ");
    crate::io::log::early_print(message);
    crate::io::log::early_print(" !!!\n");
    loop {
        x86_64::instructions::hlt();
    }
}

// ============================================================================
// BSOD Display Functions
// ============================================================================

#[cfg(not(any(test, feature = "bench")))]
fn display_bsod_on_panic(info: &crate::graphics::bsod::BsodInfo) {
    // グラフィックスが初期化されているか確認
    unsafe {
        crate::graphics::force_unlock_framebuffer();
    }

    if crate::graphics::framebuffer().is_none() {
        return;
    }

    // BSOD表示
    crate::graphics::bsod::show_panic_bsod(info);
}

#[cfg(any(test, feature = "bench"))]
fn display_bsod_on_panic(_info: &crate::graphics::bsod::BsodInfo) {
    // No-op in tests
}

#[cfg(not(any(test, feature = "bench")))]
pub fn test_bsod(message: &str) {
    use crate::graphics::bsod::BsodInfo;
    let mut info = BsodInfo::new(message);
    info = info.with_location("test_file.rs", 42, 1);
    crate::graphics::bsod::show_panic_bsod(&info);
}

#[cfg(any(test, feature = "bench"))]
pub fn test_bsod(_message: &str) {
}
