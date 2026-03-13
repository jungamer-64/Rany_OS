// ============================================================================
// src/panic_handler.rs - Enhanced Panic Handler with Domain Isolation
// 設計書 8.1: スタックアンワインドとリソース回収
// ============================================================================
#![allow(dead_code)]

use crate::graphics::bsod::BsodInfo;
use core::fmt::{self, Write};
use core::mem::MaybeUninit;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

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

/// Capture the panic record into the static buffer (lock-free, first-writer-wins).
/// Returns a slice to the recorded message or a default fallback.
fn panic_capture_record(info: &PanicInfo, domain_id: u64) -> &'static [u8] {
    let mut message_slice: &[u8] = b"Unknown panic";

    if PANIC_RECORD_STATE
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        unsafe {
            let record_ptr = core::ptr::addr_of_mut!(PANIC_RECORD) as *mut PanicRecord;
            let record_ref = &mut *record_ptr;

            let mut writer = PanicBufferWriter::new(&mut record_ref.message);
            let _ = write!(writer, "{}", info.message());
            record_ref.message_len = writer.offset;
            message_slice = &record_ref.message[..record_ref.message_len];

            if let Some(loc) = info.location() {
                let mut file_buf = [0u8; MAX_FILE_LEN];
                let file_bytes = loc.file().as_bytes();
                let copy_len = file_bytes.len().min(MAX_FILE_LEN);
                core::ptr::copy_nonoverlapping(
                    file_bytes.as_ptr(),
                    file_buf.as_mut_ptr(),
                    copy_len,
                );

                record_ref.location = Some(PanicLocation {
                    file: file_buf,
                    file_len: copy_len,
                    line: loc.line(),
                    column: loc.column(),
                });
            } else {
                record_ref.location = None;
            }

            record_ref.domain_id = if domain_id > 0 { Some(domain_id) } else { None };
            record_ref.tick = crate::task::current_tick();

            PANIC_RECORD_STATE.store(2, Ordering::Release);
        }
    } else {
        crate::io::log::early_print("Concurrent panic detected, skipping record capture.\n");
    }
    message_slice
}

/// Output the panic location and message to serial (lock-free).
fn panic_output_location(info: &PanicInfo, message_slice: &[u8]) {
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
}

/// Save IOMMU DMA panic record if message is valid UTF-8 (lock-free).
fn panic_save_iommu_record(message_slice: &[u8]) {
    if let Ok(s) = core::str::from_utf8(message_slice) {
        if let Some(info) = crate::io::iommu::api::write_panic_record(s) {
            crate::io::log::early_print("[PANIC] record saved\n");
            crate::io::log::early_print("record phys=0x");
            crate::io::log::early_print_hex(info.phys.as_u64());
            crate::io::log::early_print("\n");
        }
    }
}

/// Attempt domain-specific panic handling if running in a non-zero domain.
fn panic_notify_domain(domain_id: u64, message_slice: &[u8]) {
    if domain_id == 0 {
        return;
    }
    crate::io::log::early_print("Domain ID: ");
    crate::io::log::early_print_dec(domain_id);
    crate::io::log::early_print("\n");

    if let Ok(s) = core::str::from_utf8(message_slice) {
        if try_handle_domain_panic(domain_id, s) {
            crate::io::log::early_print("Domain terminated, attempting to continue...\n");
            set_current_domain(0);
        }
    }
}

/// Build a BsodInfo struct with panic-safe metadata for BSOD rendering.
fn panic_build_bsod(message_slice: &[u8]) -> BsodInfo<'_> {
    // Keep the panic path minimal and allocation-free. Register capture has
    // triggered secondary faults during SMP bring-up, which hides the original
    // panic we actually need to diagnose.
    let backtrace = crate::unwind::Backtrace::capture();

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

    let mut bsod_info = BsodInfo::new(msg_str);
    if let (Some(f), Some(l), Some(c)) = (file_str, line, col) {
        bsod_info = bsod_info.with_location(f, l, c);
    }
    if !backtrace.is_empty() {
        bsod_info = bsod_info.with_backtrace(backtrace);
    }
    bsod_info = bsod_info.with_error_code(first_word);

    if let Some(first) = bsod_info.backtrace.as_ref().and_then(|bt| bt.iter().next()) {
        if let Some(sym) = &first.symbol {
            crate::io::log::early_print("[PANIC] Likely at symbol: ");
            if let Some(name) = sym.name {
                crate::io::log::early_print(name);
                crate::io::log::early_print("\n");
            }
        }
    }

    bsod_info
}

/// パニックハンドラの本体
/// 設計書 8.1: パニック捕捉とドメイン境界での処理
pub fn handle_panic(info: &PanicInfo) -> ! {
    // 割り込みを無効化
    x86_64::instructions::interrupts::disable();

    // 【設計書 8.5.1】Double Panic検出
    if PANIC_IN_PROGRESS.swap(true, Ordering::SeqCst) {
        crate::io::log::early_print("\n!!! DOUBLE PANIC DETECTED !!!\n");
        crate::io::log::early_print("Aborting without further processing.\n");
        // LOOP_PROOF: mode=event; reason=Double panic path intentionally halts forever to prevent reentrant panic recovery attempts.;
        loop {
            x86_64::instructions::hlt();
        }
    }

    // パニックモードに入る（ログ出力時のデッドロック回避）
    crate::io::log::enter_panic_mode();

    // 【設計書 8.4】パニック状態をマーク（PoisonLockのため）
    crate::sync::set_panicking(true);

    let _count = PANIC_COUNT.fetch_add(1, Ordering::Relaxed);
    let domain_id = get_current_domain();

    crate::io::log::early_print("\n!!! KERNEL PANIC DETECTED !!!\n");

    let message_slice = panic_capture_record(info, domain_id);
    panic_output_location(info, message_slice);
    panic_save_iommu_record(message_slice);
    panic_notify_domain(domain_id, message_slice);

    let bsod_info = panic_build_bsod(message_slice);
    crate::graphics::bsod::dump_bsod_info_to_serial(&bsod_info);
    display_bsod_on_panic(&bsod_info);

    // システム停止
    // LOOP_PROOF: mode=event; reason=Primary panic path intentionally halts forever after logging to preserve crash state.;
    loop {
        x86_64::instructions::hlt();
    }
}

/// ドメイン固有のパニック処理を試みる
fn try_handle_domain_panic(domain_id: u64, message: &str) -> bool {
    use crate::ipc::rref::DomainId;

    let id = DomainId::new(domain_id);
    let sas_domain_id = crate::sas::DomainId::new(domain_id);
    let target_domain_id = crate::domain_system::DomainId::new(domain_id);

    // 【設計書 8.4】ドメインが所有する全オブジェクトをポイズニング
    let poisoned_count = crate::sas::poison_domain_objects(sas_domain_id);
    if poisoned_count > 0 {
        crate::io::log::early_print("[PanicHandler] Poisoned objects owned by domain\n");
    }

    if crate::driver_domain::driver_domain_manager()
        .find_by_domain(target_domain_id)
        .is_some()
    {
        crate::driver_domain::fault::notify_domain_panic(
            target_domain_id,
            alloc::string::String::from(message),
        );
        return true;
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
            let s = core::str::from_utf8(&record.message[..record.message_len])
                .unwrap_or("Invalid UTF-8");
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

    // LOOP_PROOF: mode=event; reason=Double fault handler intentionally halts forever because continuing execution is unsafe.;
    loop {
        x86_64::instructions::hlt();
    }
}

// ============================================================================
// Stack Overflow Detection
// ============================================================================

/// BSPブートスタックにガードページ（Present=0）を設置する。
///
/// # 前提
/// - `stack_bottom` はスタック領域の最下位アドレス（ページ4KiBアライン済み）
/// - `stack_size` はガードページ含む全体サイズ（最低 8KiB = ガード1頁＋実用1頁）
///
/// # 動作
/// `stack_bottom` のページをアンマップし、TLBをフラッシュする（`global_unmap_page` 内部）。
/// これにより使用可能スタックは `[stack_bottom + 4096 .. stack_bottom + stack_size)` になる。
///
/// # 失敗時
/// - debug ビルド: panic して停止
/// - release ビルド: 警告を出して続行（ガード無し）
pub fn setup_stack_guard(stack_bottom: usize, stack_size: usize) {
    use crate::mm::virt::higher_half::VirtAddr;

    // ── 1) ページアライメントを強制チェック（release でも有効） ──
    if stack_bottom & 0xFFF != 0 {
        crate::io::log::early_print("[StackGuard] FATAL: stack_bottom is not page-aligned!\n");
        #[cfg(debug_assertions)]
        panic!(
            "setup_stack_guard: stack_bottom {:#x} is not 4KiB-aligned",
            stack_bottom
        );
        #[cfg(not(debug_assertions))]
        return;
    }

    // ── 2) stack_size の整合チェック ──
    //    ガード1ページ + 実用1ページ = 最低 8KiB 必要
    if stack_size < 4096 * 2 {
        crate::io::log::early_print("[StackGuard] FATAL: stack_size too small for guard page!\n");
        #[cfg(debug_assertions)]
        panic!(
            "setup_stack_guard: stack_size {:#x} < 8KiB (need guard + 1 usable page)",
            stack_size
        );
        #[cfg(not(debug_assertions))]
        return;
    }

    // ── 3) Inner guard: stack_bottom そのものをアンマップ ──
    //    align_down() は使わず、事前チェック済みのアドレスを直接指定。
    //    「静かに別ページを狙う」リスクを排除。
    let guard_page_addr = VirtAddr::new(stack_bottom as u64);

    // ── 4) アンマップ + TLB flush（global_unmap_page 内部で実施） ──
    unsafe {
        match crate::mm::virt::higher_half::global_unmap_page(guard_page_addr) {
            Ok(_phys) => {
                // 成功: global_unmap_page は invalidate_page → flush_tlb_immediate で
                // マルチコア TLB シュートダウン済み。追加の invlpg は不要。
            }
            Err(e) => {
                // エラー種別を固定文字列で表示（alloc::format! 不使用）
                use crate::mm::virt::higher_half::MapError;
                let reason = match e {
                    MapError::NotMapped => "page already not mapped",
                    MapError::InvalidAddress => "invalid address",
                    MapError::HardwareError => "page table manager poisoned/uninitialized",
                    MapError::FrameAllocationFailed => "frame allocation failed",
                    MapError::AlreadyMapped => "unexpected: already mapped",
                    MapError::AlignmentError => "alignment error in page table",
                    MapError::ParentEntryHugePage => "parent entry is huge page",
                };
                crate::io::log::early_print("[StackGuard] ERROR: guard page setup failed: ");
                crate::io::log::early_print(reason);
                crate::io::log::early_print("\n");

                // NotMapped はガード効果があるので続行可、それ以外は致命的
                if !matches!(e, MapError::NotMapped) {
                    crate::io::log::early_print(
                        "[StackGuard] WARNING: continuing WITHOUT stack overflow protection!\n",
                    );
                    #[cfg(debug_assertions)]
                    panic!("setup_stack_guard failed: {}", reason);
                }
            }
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
    // LOOP_PROOF: mode=event; reason=Abort path intentionally halts forever after reporting because no safe rollback exists.;
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
pub fn test_bsod(_message: &str) {}
// Basic panic handler implementation
pub fn panic(_info: &PanicInfo) -> ! {
    // Attempt to acquire lock and print panic info
    // In a real implementation we would write to the panic record
    // For now, just loop
    PANIC_IN_PROGRESS.store(true, Ordering::SeqCst);

    // Simplistic printing if possible (depends on logger state)
    // We avoid complex formatting to prevent double panic

    // LOOP_PROOF: mode=event; reason=Fallback panic stub intentionally spins forever when panic infrastructure is unavailable.;
    loop {
        core::hint::spin_loop();
    }
}
