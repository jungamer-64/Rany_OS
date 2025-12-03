// ============================================================================
// src/interrupts/mod.rs - 割り込みシステム統合モジュール
//
// GDT, IDT, 例外ハンドラ、ハードウェア割り込みを統合管理
// ============================================================================
#![allow(dead_code)]

pub mod exceptions;
pub mod gdt;

use core::sync::atomic::{AtomicBool, Ordering};
use spin::Lazy;
use x86_64::structures::idt::InterruptDescriptorTable;

/// IDT初期化完了フラグ
static IDT_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// ハードウェア割り込みのベースオフセット
pub const PIC1_OFFSET: u8 = 32;
pub const PIC2_OFFSET: u8 = 40;

/// 割り込みベクタ番号
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum InterruptVector {
    Timer = PIC1_OFFSET,
    Keyboard = PIC1_OFFSET + 1,
    Cascade = PIC1_OFFSET + 2, // PIC2 への接続
    Com2 = PIC1_OFFSET + 3,
    Com1 = PIC1_OFFSET + 4,
    Lpt2 = PIC1_OFFSET + 5,
    Floppy = PIC1_OFFSET + 6,
    Lpt1 = PIC1_OFFSET + 7,
    Rtc = PIC2_OFFSET, // Real Time Clock
    Free1 = PIC2_OFFSET + 1,
    Free2 = PIC2_OFFSET + 2,
    Free3 = PIC2_OFFSET + 3,
    Mouse = PIC2_OFFSET + 4,
    Fpu = PIC2_OFFSET + 5,
    PrimaryAta = PIC2_OFFSET + 6,
    SecondaryAta = PIC2_OFFSET + 7,
}

/// IDT (Interrupt Descriptor Table)
static IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
    let mut idt = InterruptDescriptorTable::new();

    // ============================================================
    // CPU例外ハンドラの設定
    // ============================================================

    // Division Error (#DE) - Vector 0
    idt.divide_error
        .set_handler_fn(exceptions::divide_error_handler);

    // Debug (#DB) - Vector 1
    idt.debug.set_handler_fn(exceptions::debug_handler);

    // Breakpoint (#BP) - Vector 3
    idt.breakpoint
        .set_handler_fn(exceptions::breakpoint_handler);

    // Invalid Opcode (#UD) - Vector 6
    idt.invalid_opcode
        .set_handler_fn(exceptions::invalid_opcode_handler);

    // Device Not Available (#NM) - Vector 7
    idt.device_not_available
        .set_handler_fn(exceptions::device_not_available_handler);

    // Double Fault (#DF) - Vector 8
    // 重要: IST (Interrupt Stack Table) を使用
    unsafe {
        idt.double_fault
            .set_handler_fn(exceptions::double_fault_handler)
            .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
    }

    // General Protection Fault (#GP) - Vector 13
    idt.general_protection_fault
        .set_handler_fn(exceptions::general_protection_fault_handler);

    // Page Fault (#PF) - Vector 14
    // オプション: IST を使用することもできる
    unsafe {
        idt.page_fault
            .set_handler_fn(exceptions::page_fault_handler)
            .set_stack_index(gdt::PAGE_FAULT_IST_INDEX);
    }

    // Alignment Check (#AC) - Vector 17
    idt.alignment_check
        .set_handler_fn(exceptions::alignment_check_handler);

    // Machine Check (#MC) - Vector 18
    idt.machine_check
        .set_handler_fn(exceptions::machine_check_handler);

    // SIMD Floating Point (#XM) - Vector 19
    idt.simd_floating_point
        .set_handler_fn(exceptions::simd_floating_point_handler);

    // ============================================================
    // ハードウェア割り込みハンドラの設定
    // ============================================================

    idt[InterruptVector::Timer as usize].set_handler_fn(timer_interrupt_handler);

    idt[InterruptVector::Keyboard as usize].set_handler_fn(keyboard_interrupt_handler);

    idt
});

// ============================================================================
// 割り込みシステムの初期化
// ============================================================================

/// 割り込みシステム全体の初期化
///
/// 呼び出し順序:
/// 1. GDT/TSSの初期化（ISTスタックの設定）
/// 2. PICの初期化
/// 3. IDTのロード
pub fn init() {
    crate::log!("[INT] Initializing interrupt system...\n");

    // 1. GDT と TSS の初期化（IST スタックを含む）
    gdt::init_gdt();
    crate::log!("[INT] GDT/TSS initialized with IST\n");

    // 2. PIC の初期化（ハードウェア割り込みのリマップ）
    init_pic();
    crate::log!(
        "[INT] PIC remapped (IRQ 0-15 -> Vector {}-{})\n",
        PIC1_OFFSET,
        PIC2_OFFSET + 7
    );

    // 3. IDT のロード
    IDT.load();
    IDT_INITIALIZED.store(true, Ordering::SeqCst);
    crate::log!("[INT] IDT loaded\n");

    crate::log!("[INT] Interrupt system ready\n");
}

/// 割り込みを有効化
///
/// # Safety
/// IDT が初期化されていないと未定義動作
pub fn enable_interrupts() {
    if !IDT_INITIALIZED.load(Ordering::SeqCst) {
        panic!("Cannot enable interrupts: IDT not initialized");
    }
    x86_64::instructions::interrupts::enable();
}

/// 割り込みを無効化
pub fn disable_interrupts() {
    x86_64::instructions::interrupts::disable();
}

/// 割り込みが有効かどうか
pub fn are_interrupts_enabled() -> bool {
    x86_64::instructions::interrupts::are_enabled()
}

/// 割り込みを無効にしてクロージャを実行
pub fn without_interrupts<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    x86_64::instructions::interrupts::without_interrupts(f)
}

// ============================================================================
// PIC (8259A) 無効化 - APIC専用設計
// ============================================================================
// 設計理念: レガシーPICはモダンx86_64では不要
// - pic8259クレートを削除し、直接I/Oポート操作で無効化
// - 全ての割り込みはAPIC/IO APICで処理
// ============================================================================

use x86_64::instructions::port::Port;

/// PICのI/Oポートアドレス
const PIC1_COMMAND: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_COMMAND: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

/// ICW1: 初期化コマンド
const ICW1_INIT: u8 = 0x10;
const ICW1_ICW4: u8 = 0x01;
/// ICW4: 8086モード
const ICW4_8086: u8 = 0x01;

/// PICを完全に無効化（APICモードへ移行）
///
/// これは設計理念に基づく重要な処理：
/// - レガシーPICはシングルコア時代の遺物
/// - 現代のx86_64ではAPIC/MSI-Xを使用すべき
/// - PICは初期化後に全マスクして無効化
fn init_pic() {
    unsafe {
        let mut pic1_cmd: Port<u8> = Port::new(PIC1_COMMAND);
        let mut pic1_data: Port<u8> = Port::new(PIC1_DATA);
        let mut pic2_cmd: Port<u8> = Port::new(PIC2_COMMAND);
        let mut pic2_data: Port<u8> = Port::new(PIC2_DATA);

        // PICの初期化シーケンス（リマップ）
        // これは必要: BIOSがPIC割り込みをCPU例外と衝突する位置に設定するため

        // ICW1: 初期化開始
        pic1_cmd.write(ICW1_INIT | ICW1_ICW4);
        io_wait();
        pic2_cmd.write(ICW1_INIT | ICW1_ICW4);
        io_wait();

        // ICW2: ベクタオフセット設定（例外との衝突を回避）
        pic1_data.write(PIC1_OFFSET);
        io_wait();
        pic2_data.write(PIC2_OFFSET);
        io_wait();

        // ICW3: カスケード設定
        pic1_data.write(4); // IRQ2にスレーブ接続
        io_wait();
        pic2_data.write(2); // カスケードID
        io_wait();

        // ICW4: 8086モード
        pic1_data.write(ICW4_8086);
        io_wait();
        pic2_data.write(ICW4_8086);
        io_wait();

        // 全割り込みをマスク（APIC使用のため）
        // 0xFF = 全ビットマスク
        pic1_data.write(0xFF);
        pic2_data.write(0xFF);
    }
}

/// I/O待機（PICは遅いデバイス）
#[inline]
fn io_wait() {
    unsafe {
        // 未使用ポートへのI/Oで遅延を発生
        let mut port: Port<u8> = Port::new(0x80);
        port.write(0);
    }
}

/// EOI送信（タイマー/キーボード用 - APICへの移行までの暫定）
///
/// # Safety
/// 割り込みハンドラ内でのみ呼び出すこと
pub unsafe fn send_eoi(irq: u8) {
    let mut pic1_cmd: Port<u8> = Port::new(PIC1_COMMAND);
    let mut pic2_cmd: Port<u8> = Port::new(PIC2_COMMAND);

    if irq >= 8 {
        pic2_cmd.write(0x20); // スレーブPICにEOI
    }
    pic1_cmd.write(0x20); // マスターPICにEOI
}

/// 特定の割り込みをアンマスク（APIC移行までの暫定）
pub fn unmask_irq(irq: u8) {
    unsafe {
        if irq < 8 {
            let mut port: Port<u8> = Port::new(PIC1_DATA);
            let mask = port.read();
            port.write(mask & !(1 << irq));
        } else {
            let mut port: Port<u8> = Port::new(PIC2_DATA);
            let mask = port.read();
            port.write(mask & !(1 << (irq - 8)));
        }
    }
}

/// 特定の割り込みをマスク
pub fn mask_irq(irq: u8) {
    unsafe {
        if irq < 8 {
            let mut port: Port<u8> = Port::new(PIC1_DATA);
            let mask = port.read();
            port.write(mask | (1 << irq));
        } else {
            let mut port: Port<u8> = Port::new(PIC2_DATA);
            let mask = port.read();
            port.write(mask | (1 << (irq - 8)));
        }
    }
}

// ============================================================================
// Hardware Interrupt Handlers
// ============================================================================

use core::sync::atomic::AtomicU64;
use x86_64::structures::idt::InterruptStackFrame;

/// タイマー割り込みカウンタ
pub static TIMER_TICKS: AtomicU64 = AtomicU64::new(0);

/// タイマー割り込みハンドラ
///
/// 仕様書 4.2: プリエンプション制御との統合
/// - タイマーティックの管理
/// - タスクの時間スライス減少
/// - 必要に応じてプリエンプション要求
/// - Interrupt-Wakerブリッジとの連携
extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
    // タイマーティックを増加
    let tick = TIMER_TICKS.fetch_add(1, Ordering::SeqCst);

    // プリエンプションシステムにタイマーティックを通知
    // これにより時間スライスが減少し、必要に応じてプリエンプションが要求される
    crate::task::preemption::handle_timer_tick(tick);

    // Interrupt-Wakerブリッジにタイマー割り込みを通知（設計書 4.2）
    // これによりsleep_ms等で待機中のタスクが起床される
    crate::task::interrupt_waker::handle_timer_interrupt_waker();

    // EOI (End Of Interrupt) を送信
    unsafe {
        send_eoi(InterruptVector::Timer as u8 - PIC1_OFFSET);
    }

    // プリエンプションが要求されていて、割り込み可能な状態なら
    // タスク切り替えを試みる
    if crate::task::preemption::should_preempt() {
        // 協調的yield（割り込みハンドラ終了後に実行）
        crate::task::preemption::request_yield();
    }
}

/// キーボード割り込みハンドラ
/// Interrupt-Wakerブリッジとの連携
extern "x86-interrupt" fn keyboard_interrupt_handler(_stack_frame: InterruptStackFrame) {
    use x86_64::instructions::port::Port;

    // キーボードデータポートから読み取り（これをしないと次の割り込みが来ない）
    let mut port = Port::new(0x60);
    let scancode: u8 = unsafe { port.read() };

    // スキャンコードを処理キューに追加
    // TODO: キーボードドライバの実装
    crate::log!("Key: {:#x}\n", scancode);

    // Interrupt-Wakerブリッジにキーボード割り込みを通知（設計書 4.2）
    crate::task::interrupt_waker::wake_from_interrupt(
        crate::task::interrupt_waker::InterruptSource::Keyboard,
    );

    // EOI を送信
    unsafe {
        send_eoi(InterruptVector::Keyboard as u8 - PIC1_OFFSET);
    }
}

/// 現在のタイマーティック数を取得
pub fn get_timer_ticks() -> u64 {
    TIMER_TICKS.load(Ordering::SeqCst)
}

// ============================================================================
// テスト用ヘルパー
// ============================================================================

/// ブレークポイントをトリガー（デバッグ用）
pub fn trigger_breakpoint() {
    x86_64::instructions::interrupts::int3();
}

/// 割り込みシステムの状態をダンプ
pub fn dump_interrupt_state() {
    crate::log!("[INT] === Interrupt System State ===\n");
    crate::log!(
        "  IDT Initialized: {}\n",
        IDT_INITIALIZED.load(Ordering::SeqCst)
    );
    crate::log!("  Interrupts Enabled: {}\n", are_interrupts_enabled());
    crate::log!("  Timer Ticks: {}\n", get_timer_ticks());

    let (pf, gpf, df, bp, ud, de) = exceptions::get_exception_stats();
    crate::log!("  Exception Stats:\n");
    crate::log!("    Page Faults: {}\n", pf);
    crate::log!("    GP Faults: {}\n", gpf);
    crate::log!("    Double Faults: {}\n", df);
    crate::log!("    Breakpoints: {}\n", bp);
    crate::log!("    Invalid Opcodes: {}\n", ud);
    crate::log!("    Divide Errors: {}\n", de);
}
