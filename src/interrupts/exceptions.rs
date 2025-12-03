// ============================================================================
// src/interrupts/exceptions.rs - CPU Exception Handlers
// 堅牢な例外処理：詳細なダンプ、リカバリ可能な場合の対応
// ============================================================================
#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::registers::control::Cr2;
use x86_64::structures::idt::{InterruptStackFrame, PageFaultErrorCode};

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
    crate::log!(
        "  RIP: {:#018x}\n",
        stack_frame.instruction_pointer.as_u64()
    );
    crate::log!("  RSP: {:#018x}\n", stack_frame.stack_pointer.as_u64());
    crate::log!("  CS:  {:#06x}\n", stack_frame.code_segment);
    crate::log!("  SS:  {:#06x}\n", stack_frame.stack_segment);
    crate::log!("  RFLAGS: {:#018x}\n", stack_frame.cpu_flags);
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
        core::arch::asm!(
            "mov {}, rax",
            out(reg) rax,
            options(nomem, nostack)
        );
        core::arch::asm!(
            "mov {}, rbx",
            out(reg) rbx,
            options(nomem, nostack)
        );
        core::arch::asm!(
            "mov {}, rcx",
            out(reg) rcx,
            options(nomem, nostack)
        );
        core::arch::asm!(
            "mov {}, rdx",
            out(reg) rdx,
            options(nomem, nostack)
        );
        core::arch::asm!(
            "mov {}, rsi",
            out(reg) rsi,
            options(nomem, nostack)
        );
        core::arch::asm!(
            "mov {}, rdi",
            out(reg) rdi,
            options(nomem, nostack)
        );
        core::arch::asm!(
            "mov {}, rbp",
            out(reg) rbp,
            options(nomem, nostack)
        );
        core::arch::asm!(
            "mov {}, r8",
            out(reg) r8,
            options(nomem, nostack)
        );
        core::arch::asm!(
            "mov {}, r9",
            out(reg) r9,
            options(nomem, nostack)
        );
        core::arch::asm!(
            "mov {}, r10",
            out(reg) r10,
            options(nomem, nostack)
        );
        core::arch::asm!(
            "mov {}, r11",
            out(reg) r11,
            options(nomem, nostack)
        );
        core::arch::asm!(
            "mov {}, r12",
            out(reg) r12,
            options(nomem, nostack)
        );
        core::arch::asm!(
            "mov {}, r13",
            out(reg) r13,
            options(nomem, nostack)
        );
        core::arch::asm!(
            "mov {}, r14",
            out(reg) r14,
            options(nomem, nostack)
        );
        core::arch::asm!(
            "mov {}, r15",
            out(reg) r15,
            options(nomem, nostack)
        );
    }

    crate::log!("  RAX: {:#018x}  RBX: {:#018x}\n", rax, rbx);
    crate::log!("  RCX: {:#018x}  RDX: {:#018x}\n", rcx, rdx);
    crate::log!("  RSI: {:#018x}  RDI: {:#018x}\n", rsi, rdi);
    crate::log!("  RBP: {:#018x}\n", rbp);
    crate::log!("  R8:  {:#018x}  R9:  {:#018x}\n", r8, r9);
    crate::log!("  R10: {:#018x}  R11: {:#018x}\n", r10, r11);
    crate::log!("  R12: {:#018x}  R13: {:#018x}\n", r12, r13);
    crate::log!("  R14: {:#018x}  R15: {:#018x}\n", r14, r15);
}

/// コントロールレジスタのダンプ
fn dump_control_registers() {
    use x86_64::registers::control::{Cr0, Cr3, Cr4};

    let cr0 = Cr0::read();
    let (cr3_frame, _cr3_flags) = Cr3::read();
    let cr4 = Cr4::read();

    crate::log!("  CR0: {:?}\n", cr0);
    crate::log!("  CR2: {:#018x} (Faulting Address)\n", Cr2::read().as_u64());
    crate::log!(
        "  CR3: {:#018x} (PML4)\n",
        cr3_frame.start_address().as_u64()
    );
    crate::log!("  CR4: {:?}\n", cr4);
}

// ============================================================================
// Exception Handlers
// ============================================================================

/// Divide Error (#DE)
pub extern "x86-interrupt" fn divide_error_handler(stack_frame: InterruptStackFrame) {
    EXCEPTION_STATS
        .divide_errors
        .fetch_add(1, Ordering::Relaxed);

    crate::log!("\n[EXCEPTION] DIVIDE ERROR (#DE)\n");
    dump_stack_frame(&stack_frame);

    panic!("Divide by zero");
}

/// Debug Exception (#DB)
pub extern "x86-interrupt" fn debug_handler(stack_frame: InterruptStackFrame) {
    crate::log!("\n[EXCEPTION] DEBUG (#DB)\n");
    dump_stack_frame(&stack_frame);
    // デバッグ例外は継続可能
}

/// Breakpoint (#BP)
pub extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    EXCEPTION_STATS.breakpoints.fetch_add(1, Ordering::Relaxed);

    crate::log!("\n[EXCEPTION] BREAKPOINT (#BP)\n");
    dump_stack_frame(&stack_frame);
    // ブレークポイントは継続可能
}

/// Invalid Opcode (#UD)
pub extern "x86-interrupt" fn invalid_opcode_handler(stack_frame: InterruptStackFrame) {
    EXCEPTION_STATS
        .invalid_opcodes
        .fetch_add(1, Ordering::Relaxed);

    crate::log!("\n[EXCEPTION] INVALID OPCODE (#UD)\n");
    dump_stack_frame(&stack_frame);
    dump_registers();

    // 問題の命令を表示
    let rip = stack_frame.instruction_pointer.as_u64() as *const u8;
    crate::log!("  Instruction bytes: ");
    for i in 0..8 {
        let byte = unsafe { *rip.add(i) };
        crate::log!("{:02x} ", byte);
    }
    crate::log!("\n");

    panic!("Invalid opcode");
}

/// Device Not Available (#NM)
pub extern "x86-interrupt" fn device_not_available_handler(stack_frame: InterruptStackFrame) {
    crate::log!("\n[EXCEPTION] DEVICE NOT AVAILABLE (#NM)\n");
    dump_stack_frame(&stack_frame);

    // FPU/SSE の遅延切り替え用
    // TODO: FPU state の保存・復元を実装
    panic!("FPU not available");
}

/// Double Fault (#DF)
///
/// これは専用のISTスタックで動作する（スタック破損時でも動く）
pub extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) -> ! {
    EXCEPTION_STATS
        .double_faults
        .fetch_add(1, Ordering::Relaxed);

    crate::log!("\n");
    crate::log!("╔══════════════════════════════════════════════════════════╗\n");
    crate::log!("║              DOUBLE FAULT - UNRECOVERABLE                ║\n");
    crate::log!("╚══════════════════════════════════════════════════════════╝\n");
    crate::log!("Error Code: {:#x}\n\n", error_code);

    crate::log!("Stack Frame:\n");
    dump_stack_frame(&stack_frame);

    crate::log!("\nControl Registers:\n");
    dump_control_registers();

    crate::log!("\nGeneral Registers:\n");
    dump_registers();

    crate::log!("\n[FATAL] System halted.\n");

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
    EXCEPTION_STATS
        .general_protection_faults
        .fetch_add(1, Ordering::Relaxed);

    crate::log!("\n[EXCEPTION] GENERAL PROTECTION FAULT (#GP)\n");
    crate::log!("Error Code: {:#x}\n", error_code);

    // エラーコードの解析
    if error_code != 0 {
        let external = (error_code & 0x1) != 0;
        let table = (error_code >> 1) & 0x3;
        let index = (error_code >> 3) & 0x1FFF;

        crate::log!("  External: {}\n", external);
        crate::log!("  Table: {} (0=GDT, 1=IDT, 2=LDT, 3=IDT)\n", table);
        crate::log!("  Selector Index: {}\n", index);
    }

    crate::log!("\nStack Frame:\n");
    dump_stack_frame(&stack_frame);

    crate::log!("\nGeneral Registers:\n");
    dump_registers();

    panic!("General protection fault");
}

/// Page Fault (#PF)
pub extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    EXCEPTION_STATS.page_faults.fetch_add(1, Ordering::Relaxed);

    let fault_addr = Cr2::read();

    crate::log!("\n[EXCEPTION] PAGE FAULT (#PF)\n");
    crate::log!("Faulting Address: {:#018x}\n", fault_addr.as_u64());
    crate::log!("Error Code: {:?}\n", error_code);

    // エラーコードの詳細解析 (ビットフィールドを直接チェック)
    let error_bits = error_code.bits();
    crate::log!("  Present: {}\n", (error_bits & 0x1) != 0);
    crate::log!("  Write: {}\n", (error_bits & 0x2) != 0);
    crate::log!("  User Mode: {}\n", (error_bits & 0x4) != 0);
    crate::log!("  Reserved Write: {}\n", (error_bits & 0x8) != 0);
    crate::log!("  Instruction Fetch: {}\n", (error_bits & 0x10) != 0);

    crate::log!("\nStack Frame:\n");
    dump_stack_frame(&stack_frame);

    // TODO: Demand Paging の実装
    // 現時点では全てのページフォルトは致命的

    panic!("Page fault at {:#x}", fault_addr.as_u64());
}

/// Alignment Check (#AC)
pub extern "x86-interrupt" fn alignment_check_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    crate::log!("\n[EXCEPTION] ALIGNMENT CHECK (#AC)\n");
    crate::log!("Error Code: {:#x}\n", error_code);
    dump_stack_frame(&stack_frame);

    panic!("Alignment check");
}

/// Machine Check (#MC)
pub extern "x86-interrupt" fn machine_check_handler(stack_frame: InterruptStackFrame) -> ! {
    crate::log!("\n[EXCEPTION] MACHINE CHECK (#MC) - HARDWARE ERROR\n");
    dump_stack_frame(&stack_frame);

    // ハードウェアエラーは回復不能
    loop {
        x86_64::instructions::hlt();
    }
}

/// SIMD Floating Point Exception (#XM/#XF)
pub extern "x86-interrupt" fn simd_floating_point_handler(stack_frame: InterruptStackFrame) {
    crate::log!("\n[EXCEPTION] SIMD FLOATING POINT (#XM)\n");
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
    crate::log!("  MXCSR: {:#010x}\n", mxcsr);

    panic!("SIMD floating point exception");
}

/// 例外統計を取得
pub fn get_exception_stats() -> (u64, u64, u64, u64, u64, u64) {
    (
        EXCEPTION_STATS.page_faults.load(Ordering::Relaxed),
        EXCEPTION_STATS
            .general_protection_faults
            .load(Ordering::Relaxed),
        EXCEPTION_STATS.double_faults.load(Ordering::Relaxed),
        EXCEPTION_STATS.breakpoints.load(Ordering::Relaxed),
        EXCEPTION_STATS.invalid_opcodes.load(Ordering::Relaxed),
        EXCEPTION_STATS.divide_errors.load(Ordering::Relaxed),
    )
}
