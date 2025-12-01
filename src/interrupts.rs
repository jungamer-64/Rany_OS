// ============================================================================
// src/interrupts.rs - Interrupt Descriptor Table and Handlers
// 設計書 4.2: Interrupt-Waker Bridge
// ============================================================================
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};
use spin::Mutex;
use lazy_static::lazy_static;

lazy_static! {
    /// グローバルIDT
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        
        // Exceptions
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        idt.page_fault.set_handler_fn(page_fault_handler);
        idt.general_protection_fault.set_handler_fn(general_protection_fault_handler);
        
        // Hardware interrupts
        // IRQ 0: Timer (APIC timer)
        idt[InterruptIndex::Timer.as_usize()]
            .set_handler_fn(timer_interrupt_handler);
        
        // IRQ 1: Keyboard
        idt[InterruptIndex::Keyboard.as_usize()]
            .set_handler_fn(keyboard_interrupt_handler);
        
        idt
    };
}

/// IDTの初期化
pub fn init_idt() {
    IDT.load();
}

// ============================================================================
// Exception Handlers
// ============================================================================

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    crate::log!("[INT] BREAKPOINT EXCEPTION\n{:#?}\n", stack_frame);
}

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: x86_64::structures::idt::PageFaultErrorCode,
) {
    use x86_64::registers::control::Cr2;
    
    crate::log!("[INT] PAGE FAULT\n");
    crate::log!("  Accessed Address: {:?}\n", Cr2::read());
    crate::log!("  Error Code: {:?}\n", error_code);
    crate::log!("{:#?}\n", stack_frame);
    panic!("Page fault");
}

extern "x86-interrupt" fn general_protection_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    crate::log!("[INT] GENERAL PROTECTION FAULT\n");
    crate::log!("  Error Code: {}\n", error_code);
    crate::log!("{:#?}\n", stack_frame);
    panic!("General protection fault");
}

// ============================================================================
// Hardware Interrupt Handlers
// ============================================================================

/// 割り込み番号の定義
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum InterruptIndex {
    Timer = 32,     // PIC IRQ 0
    Keyboard = 33,  // PIC IRQ 1
}

impl InterruptIndex {
    fn as_u8(self) -> u8 {
        self as u8
    }
    
    fn as_usize(self) -> usize {
        usize::from(self.as_u8())
    }
}

/// タイマー割り込みハンドラ
/// 設計書 4.2: ISRはWaker.wake()を呼び出すだけ
extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
    // Wakerの起動
    crate::task::timer::handle_timer_interrupt();
    
    // EOI送信
    unsafe {
        PICS.lock().notify_end_of_interrupt(InterruptIndex::Timer.as_u8());
    }
}

/// キーボード割り込みハンドラ
extern "x86-interrupt" fn keyboard_interrupt_handler(_stack_frame: InterruptStackFrame) {
    use x86_64::instructions::port::Port;
    
    // PS/2キーボードからスキャンコードを読み取る
    let mut port = Port::new(0x60);
    let scancode: u8 = unsafe { port.read() };
    
    // TODO: スキャンコードをキューに追加し、対応するWakerを起動
    crate::log!("[INT] Keyboard: scancode={}\n", scancode);
    
    // EOI送信
    unsafe {
        PICS.lock().notify_end_of_interrupt(InterruptIndex::Keyboard.as_u8());
    }
}

// ============================================================================
// PIC (Programmable Interrupt Controller) Setup
// ============================================================================

use pic8259::ChainedPics;

pub const PIC_1_OFFSET: u8 = 32;
pub const PIC_2_OFFSET: u8 = 40;

static PICS: Mutex<ChainedPics> = Mutex::new(unsafe {
    ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET)
});

/// PICの初期化
pub fn init_pics() {
    unsafe {
        PICS.lock().initialize();
    }
}

/// 割り込みの有効化
pub fn enable_interrupts() {
    x86_64::instructions::interrupts::enable();
}
