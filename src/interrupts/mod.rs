// ============================================================================
// src/interrupts/mod.rs - 割り込みシステム統合モジュール
// 
// GDT, IDT, 例外ハンドラ、ハードウェア割り込みを統合管理
// ============================================================================
#![allow(dead_code)]

pub mod gdt;
pub mod exceptions;

use x86_64::structures::idt::InterruptDescriptorTable;
use spin::Lazy;
use core::sync::atomic::{AtomicBool, Ordering};

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
    Cascade = PIC1_OFFSET + 2,    // PIC2 への接続
    Com2 = PIC1_OFFSET + 3,
    Com1 = PIC1_OFFSET + 4,
    Lpt2 = PIC1_OFFSET + 5,
    Floppy = PIC1_OFFSET + 6,
    Lpt1 = PIC1_OFFSET + 7,
    Rtc = PIC2_OFFSET,            // Real Time Clock
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
    idt.divide_error.set_handler_fn(exceptions::divide_error_handler);
    
    // Debug (#DB) - Vector 1
    idt.debug.set_handler_fn(exceptions::debug_handler);
    
    // Breakpoint (#BP) - Vector 3
    idt.breakpoint.set_handler_fn(exceptions::breakpoint_handler);
    
    // Invalid Opcode (#UD) - Vector 6
    idt.invalid_opcode.set_handler_fn(exceptions::invalid_opcode_handler);
    
    // Device Not Available (#NM) - Vector 7
    idt.device_not_available.set_handler_fn(exceptions::device_not_available_handler);
    
    // Double Fault (#DF) - Vector 8
    // 重要: IST (Interrupt Stack Table) を使用
    unsafe {
        idt.double_fault
            .set_handler_fn(exceptions::double_fault_handler)
            .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
    }
    
    // General Protection Fault (#GP) - Vector 13
    idt.general_protection_fault.set_handler_fn(exceptions::general_protection_fault_handler);
    
    // Page Fault (#PF) - Vector 14
    // オプション: IST を使用することもできる
    unsafe {
        idt.page_fault
            .set_handler_fn(exceptions::page_fault_handler)
            .set_stack_index(gdt::PAGE_FAULT_IST_INDEX);
    }
    
    // Alignment Check (#AC) - Vector 17
    idt.alignment_check.set_handler_fn(exceptions::alignment_check_handler);
    
    // Machine Check (#MC) - Vector 18
    idt.machine_check.set_handler_fn(exceptions::machine_check_handler);
    
    // SIMD Floating Point (#XM) - Vector 19
    idt.simd_floating_point.set_handler_fn(exceptions::simd_floating_point_handler);
    
    // ============================================================
    // ハードウェア割り込みハンドラの設定
    // ============================================================
    
    idt[InterruptVector::Timer as usize]
        .set_handler_fn(timer_interrupt_handler);
    
    idt[InterruptVector::Keyboard as usize]
        .set_handler_fn(keyboard_interrupt_handler);
    
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
    crate::log!("[INT] PIC remapped (IRQ 0-15 -> Vector {}-{})\n", PIC1_OFFSET, PIC2_OFFSET + 7);
    
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
// PIC (8259A Programmable Interrupt Controller)
// ============================================================================

use pic8259::ChainedPics;
use spin::Mutex;

/// カスケード接続されたPIC
pub static PICS: Mutex<ChainedPics> = Mutex::new(
    unsafe { ChainedPics::new(PIC1_OFFSET, PIC2_OFFSET) }
);

/// PICの初期化
fn init_pic() {
    unsafe {
        PICS.lock().initialize();
    }
}

/// 特定の割り込みをマスク（無効化）
pub fn mask_irq(irq: u8) {
    unsafe {
        let mut pics = PICS.lock();
        let mut masks = pics.read_masks();
        if irq < 8 {
            masks[0] |= 1 << irq;
        } else {
            masks[1] |= 1 << (irq - 8);
        }
        pics.write_masks(masks[0], masks[1]);
    }
}

/// 特定の割り込みをアンマスク（有効化）
pub fn unmask_irq(irq: u8) {
    unsafe {
        let mut pics = PICS.lock();
        let mut masks = pics.read_masks();
        if irq < 8 {
            masks[0] &= !(1 << irq);
        } else {
            masks[1] &= !(1 << (irq - 8));
        }
        pics.write_masks(masks[0], masks[1]);
    }
}

// ============================================================================
// Hardware Interrupt Handlers
// ============================================================================

use x86_64::structures::idt::InterruptStackFrame;
use core::sync::atomic::AtomicU64;

/// タイマー割り込みカウンタ
pub static TIMER_TICKS: AtomicU64 = AtomicU64::new(0);

/// タイマー割り込みハンドラ
/// 
/// 仕様書 4.2: プリエンプション制御との統合
/// - タイマーティックの管理
/// - タスクの時間スライス減少
/// - 必要に応じてプリエンプション要求
extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
    // タイマーティックを増加
    let tick = TIMER_TICKS.fetch_add(1, Ordering::SeqCst);
    
    // プリエンプションシステムにタイマーティックを通知
    // これにより時間スライスが減少し、必要に応じてプリエンプションが要求される
    crate::task::preemption::handle_timer_tick(tick);
    
    // タスクタイマーシステムにも通知（将来のタイマー処理用）
    // TODO: crate::task::timer::process_timers(tick);
    
    // EOI (End Of Interrupt) を送信
    unsafe {
        PICS.lock().notify_end_of_interrupt(InterruptVector::Timer as u8);
    }
    
    // プリエンプションが要求されていて、割り込み可能な状態なら
    // タスク切り替えを試みる
    if crate::task::preemption::should_preempt() {
        // 協調的yield（割り込みハンドラ終了後に実行）
        crate::task::preemption::request_yield();
    }
}

/// キーボード割り込みハンドラ
extern "x86-interrupt" fn keyboard_interrupt_handler(_stack_frame: InterruptStackFrame) {
    use x86_64::instructions::port::Port;
    
    // キーボードデータポートから読み取り（これをしないと次の割り込みが来ない）
    let mut port = Port::new(0x60);
    let scancode: u8 = unsafe { port.read() };
    
    // スキャンコードを処理キューに追加
    // TODO: キーボードドライバの実装
    crate::log!("Key: {:#x}\n", scancode);
    
    // EOI を送信
    unsafe {
        PICS.lock().notify_end_of_interrupt(InterruptVector::Keyboard as u8);
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
    crate::log!("  IDT Initialized: {}\n", IDT_INITIALIZED.load(Ordering::SeqCst));
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
