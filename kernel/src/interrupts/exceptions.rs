// ============================================================================
// src/interrupts/exceptions.rs - CPU Exception Handlers
// 堅牢な例外処理：詳細なダンプ、リカバリ可能な場合の対応
// ============================================================================
#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::registers::control::Cr2;
use x86_64::structures::idt::{InterruptStackFrame, PageFaultErrorCode};
use crate::io::log::{early_print, early_print_hex, early_print_dec};

/// 例外統計
pub struct ExceptionStats {
    pub page_faults: AtomicU64,
    pub general_protection_faults: AtomicU64,
    pub double_faults: AtomicU64,
    pub breakpoints: AtomicU64,
    pub invalid_opcodes: AtomicU64,
    pub divide_errors: AtomicU64,
}

pub static EXCEPTION_STATS: ExceptionStats = ExceptionStats {
    page_faults: AtomicU64::new(0),
    general_protection_faults: AtomicU64::new(0),
    double_faults: AtomicU64::new(0),
    breakpoints: AtomicU64::new(0),
    invalid_opcodes: AtomicU64::new(0),
    divide_errors: AtomicU64::new(0),
};

/// スタックフレームの詳細ダンプ
fn dump_stack_frame(stack_frame: &InterruptStackFrame) {
    early_print("  RIP: ");
    early_print_hex(stack_frame.instruction_pointer.as_u64());
    early_print("\n  RSP: ");
    early_print_hex(stack_frame.stack_pointer.as_u64());
    early_print("\n  CS:  ");
    early_print_hex(stack_frame.code_segment.0 as u64);
    early_print("\n  SS:  ");
    early_print_hex(stack_frame.stack_segment.0 as u64);
    early_print("\n  RFLAGS: ");
    early_print_hex(stack_frame.cpu_flags.bits());
    early_print("\n");
}

/// レジスタダンプ（インラインアセンブリで取得）
fn dump_registers() {
    let rax: u64;
    let rbx: u64;
    let rcx: u64;
    let rdx: u64;
    let rsi: u64;
    let rdi: u64;
    let rbp: u64;
    let r8: u64;
    let r9: u64;
    let r10: u64;
    let r11: u64;
    let r12: u64;
    let r13: u64;
    let r14: u64;
    let r15: u64;

    unsafe {
        core::arch::asm!("mov {}, rax", out(reg) rax, options(nomem, nostack));
        core::arch::asm!("mov {}, rbx", out(reg) rbx, options(nomem, nostack));
        core::arch::asm!("mov {}, rcx", out(reg) rcx, options(nomem, nostack));
        core::arch::asm!("mov {}, rdx", out(reg) rdx, options(nomem, nostack));
        core::arch::asm!("mov {}, rsi", out(reg) rsi, options(nomem, nostack));
        core::arch::asm!("mov {}, rdi", out(reg) rdi, options(nomem, nostack));
        core::arch::asm!("mov {}, rbp", out(reg) rbp, options(nomem, nostack));
        core::arch::asm!("mov {}, r8", out(reg) r8, options(nomem, nostack));
        core::arch::asm!("mov {}, r9", out(reg) r9, options(nomem, nostack));
        core::arch::asm!("mov {}, r10", out(reg) r10, options(nomem, nostack));
        core::arch::asm!("mov {}, r11", out(reg) r11, options(nomem, nostack));
        core::arch::asm!("mov {}, r12", out(reg) r12, options(nomem, nostack));
        core::arch::asm!("mov {}, r13", out(reg) r13, options(nomem, nostack));
        core::arch::asm!("mov {}, r14", out(reg) r14, options(nomem, nostack));
        core::arch::asm!("mov {}, r15", out(reg) r15, options(nomem, nostack));
    }

    early_print("  RAX: "); early_print_hex(rax);
    early_print("  RBX: "); early_print_hex(rbx); early_print("\n");
    early_print("  RCX: "); early_print_hex(rcx);
    early_print("  RDX: "); early_print_hex(rdx); early_print("\n");
    early_print("  RSI: "); early_print_hex(rsi);
    early_print("  RDI: "); early_print_hex(rdi); early_print("\n");
    early_print("  RBP: "); early_print_hex(rbp); early_print("\n");
    early_print("  R8:  "); early_print_hex(r8);
    early_print("  R9:  "); early_print_hex(r9); early_print("\n");
    early_print("  R10: "); early_print_hex(r10);
    early_print("  R11: "); early_print_hex(r11); early_print("\n");
    early_print("  R12: "); early_print_hex(r12);
    early_print("  R13: "); early_print_hex(r13); early_print("\n");
    early_print("  R14: "); early_print_hex(r14);
    early_print("  R15: "); early_print_hex(r15); early_print("\n");
}

/// コントロールレジスタのダンプ
fn dump_control_registers() {
    use x86_64::registers::control::{Cr0, Cr3, Cr4};

    let cr0 = Cr0::read();
    let (cr3_frame, _cr3_flags) = Cr3::read();
    let cr4 = Cr4::read();

    early_print("  CR0: ");
    early_print_hex(cr0.bits());
    early_print("\n  CR2: ");
    // Cr2::read() returns Result in newer x86_64 crate
    if let Ok(addr) = Cr2::read() {
        early_print_hex(addr.as_u64());
    } else {
        early_print("(invalid)");
    }
    early_print(" (Faulting Address)\n  CR3: ");
    early_print_hex(cr3_frame.start_address().as_u64());
    early_print(" (PML4)\n  CR4: ");
    early_print_hex(cr4.bits());
    early_print("\n");
}

// ============================================================================
// Exception Handlers
// ============================================================================

/// Divide Error (#DE)
pub extern "x86-interrupt" fn divide_error_handler(stack_frame: InterruptStackFrame) {
    EXCEPTION_STATS.divide_errors.fetch_add(1, Ordering::Relaxed);

    early_print("\n[EXCEPTION] DIVIDE ERROR (#DE)\n");
    dump_stack_frame(&stack_frame);

    panic!("Divide by zero");
}

/// Debug Exception (#DB)
pub extern "x86-interrupt" fn debug_handler(stack_frame: InterruptStackFrame) {
    early_print("\n[EXCEPTION] DEBUG (#DB)\n");
    dump_stack_frame(&stack_frame);
    // デバッグ例外は継続可能
}

/// Breakpoint (#BP)
pub extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    EXCEPTION_STATS.breakpoints.fetch_add(1, Ordering::Relaxed);

    early_print("\n[EXCEPTION] BREAKPOINT (#BP)\n");
    dump_stack_frame(&stack_frame);
    // ブレークポイントは継続可能
}

/// Invalid Opcode (#UD)
pub extern "x86-interrupt" fn invalid_opcode_handler(stack_frame: InterruptStackFrame) {
    EXCEPTION_STATS.invalid_opcodes.fetch_add(1, Ordering::Relaxed);

    early_print("\n[EXCEPTION] INVALID OPCODE (#UD)\n");
    dump_stack_frame(&stack_frame);
    dump_registers();

    // 問題の命令を表示
    let rip = stack_frame.instruction_pointer.as_u64() as *const u8;
    early_print("  Instruction bytes: ");
    for i in 0..8 {
        let byte = unsafe { *rip.add(i) };
        // 16進数でバイトを表示
        let high = (byte >> 4) & 0xF;
        let low = byte & 0xF;
        let high_char = if high < 10 { b'0' + high } else { b'a' + high - 10 };
        let low_char = if low < 10 { b'0' + low } else { b'a' + low - 10 };
        crate::io::log::early_print_char(high_char);
        crate::io::log::early_print_char(low_char);
        early_print(" ");
    }
    early_print("\n");

    panic!("Invalid opcode");
}

/// Device Not Available (#NM)
pub extern "x86-interrupt" fn device_not_available_handler(stack_frame: InterruptStackFrame) {
    early_print("\n[EXCEPTION] DEVICE NOT AVAILABLE (#NM)\n");
    dump_stack_frame(&stack_frame);

    // FPU/SSE の遅延切り替え用
    panic!("FPU not available");
}

/// Double Fault (#DF)
///
/// これは専用のISTスタックで動作する（スタック破損時でも動く）
pub extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) -> ! {
    EXCEPTION_STATS.double_faults.fetch_add(1, Ordering::Relaxed);

    early_print("\n");
    early_print("========================================================\n");
    early_print("              DOUBLE FAULT - UNRECOVERABLE\n");
    early_print("========================================================\n");
    early_print("Error Code: ");
    early_print_hex(error_code);
    early_print("\n\n");

    early_print("Stack Frame:\n");
    dump_stack_frame(&stack_frame);

    early_print("\nControl Registers:\n");
    dump_control_registers();

    early_print("\nGeneral Registers:\n");
    dump_registers();

    early_print("\n[FATAL] System halted.\n");

    // 回復不能 - ハルト
    loop {
        x86_64::instructions::hlt();
    }
}

/// General Protection Fault (#GP)
pub extern "x86-interrupt" fn general_protection_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    EXCEPTION_STATS.general_protection_faults.fetch_add(1, Ordering::Relaxed);

    early_print("\n[EXCEPTION] GENERAL PROTECTION FAULT (#GP)\n");
    early_print("Error Code: ");
    early_print_hex(error_code);
    early_print("\n");

    // エラーコードの解析
    if error_code != 0 {
        let external = (error_code & 0x1) != 0;
        let table = (error_code >> 1) & 0x3;
        let index = (error_code >> 3) & 0x1FFF;

        early_print("  External: ");
        early_print(if external { "true" } else { "false" });
        early_print("\n  Table: ");
        early_print_dec(table);
        early_print(" (0=GDT, 1=IDT, 2=LDT, 3=IDT)\n  Selector Index: ");
        early_print_dec(index);
        early_print("\n");
    }

    early_print("\nStack Frame:\n");
    dump_stack_frame(&stack_frame);

    early_print("\nGeneral Registers:\n");
    dump_registers();

    panic!("General protection fault");
}

/// Page Fault (#PF)
pub extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    EXCEPTION_STATS.page_faults.fetch_add(1, Ordering::Relaxed);

    let fault_addr = Cr2::read().unwrap_or(x86_64::VirtAddr::zero());

    early_print("\n[EXCEPTION] PAGE FAULT (#PF)\n");
    early_print("Faulting Address: ");
    early_print_hex(fault_addr.as_u64());
    early_print("\nError Code: ");
    early_print_hex(error_code.bits() as u64);
    early_print("\n");

    // エラーコードの詳細解析
    let error_bits = error_code.bits();
    early_print("  Present: ");
    early_print(if (error_bits & 0x1) != 0 { "true" } else { "false" });
    early_print("\n  Write: ");
    early_print(if (error_bits & 0x2) != 0 { "true" } else { "false" });
    early_print("\n  User Mode: ");
    early_print(if (error_bits & 0x4) != 0 { "true" } else { "false" });
    early_print("\n  Reserved Write: ");
    early_print(if (error_bits & 0x8) != 0 { "true" } else { "false" });
    early_print("\n  Instruction Fetch: ");
    early_print(if (error_bits & 0x10) != 0 { "true" } else { "false" });
    early_print("\n");

    early_print("\nStack Frame:\n");
    dump_stack_frame(&stack_frame);

    panic!("Page fault at {:#x}", fault_addr.as_u64());
}

/// Alignment Check (#AC)
pub extern "x86-interrupt" fn alignment_check_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    early_print("\n[EXCEPTION] ALIGNMENT CHECK (#AC)\n");
    early_print("Error Code: ");
    early_print_hex(error_code);
    early_print("\n");
    dump_stack_frame(&stack_frame);

    panic!("Alignment check");
}

/// Machine Check (#MC)
pub extern "x86-interrupt" fn machine_check_handler(stack_frame: InterruptStackFrame) -> ! {
    early_print("\n[EXCEPTION] MACHINE CHECK (#MC) - HARDWARE ERROR\n");
    dump_stack_frame(&stack_frame);

    // ハードウェアエラーは回復不能
    loop {
        x86_64::instructions::hlt();
    }
}

/// SIMD Floating Point Exception (#XM/#XF)
pub extern "x86-interrupt" fn simd_floating_point_handler(stack_frame: InterruptStackFrame) {
    early_print("\n[EXCEPTION] SIMD FLOATING POINT (#XM)\n");
    dump_stack_frame(&stack_frame);

    // MXCSR レジスタの読み取り
    let mut mxcsr: u32 = 0;
    unsafe {
        core::arch::asm!(
            "stmxcsr [{}]",
            in(reg) &mut mxcsr as *mut u32,
            options(nostack)
        );
    }
    early_print("  MXCSR: ");
    early_print_hex(mxcsr as u64);
    early_print("\n");

    panic!("SIMD floating point exception");
}

/// 例外統計を取得
pub fn get_exception_stats() -> (u64, u64, u64, u64, u64, u64) {
    (
        EXCEPTION_STATS.page_faults.load(Ordering::Relaxed),
        EXCEPTION_STATS.general_protection_faults.load(Ordering::Relaxed),
        EXCEPTION_STATS.double_faults.load(Ordering::Relaxed),
        EXCEPTION_STATS.breakpoints.load(Ordering::Relaxed),
        EXCEPTION_STATS.invalid_opcodes.load(Ordering::Relaxed),
        EXCEPTION_STATS.divide_errors.load(Ordering::Relaxed),
    )
}
