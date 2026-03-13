#![allow(unused_doc_comments)]
// ============================================================================
// src/interrupts/exceptions.rs - CPU Exception Handlers
// 堅牢な例外処理：詳細なダンプ、リカバリ可能な場合の対応
// ============================================================================
#![allow(dead_code)]

use crate::io::log::{early_print, early_print_dec, early_print_hex};
use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::registers::control::Cr2;
use x86_64::structures::idt::{InterruptStackFrame, PageFaultErrorCode};

// `handle_page_fault` works with our own higher_half `VirtAddr` type
use crate::mm::virt::higher_half::VirtAddr as HHVirtAddr;

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

    early_print("  RAX: ");
    early_print_hex(rax);
    early_print("  RBX: ");
    early_print_hex(rbx);
    early_print("\n");
    early_print("  RCX: ");
    early_print_hex(rcx);
    early_print("  RDX: ");
    early_print_hex(rdx);
    early_print("\n");
    early_print("  RSI: ");
    early_print_hex(rsi);
    early_print("  RDI: ");
    early_print_hex(rdi);
    early_print("\n");
    early_print("  RBP: ");
    early_print_hex(rbp);
    early_print("\n");
    early_print("  R8:  ");
    early_print_hex(r8);
    early_print("  R9:  ");
    early_print_hex(r9);
    early_print("\n");
    early_print("  R10: ");
    early_print_hex(r10);
    early_print("  R11: ");
    early_print_hex(r11);
    early_print("\n");
    early_print("  R12: ");
    early_print_hex(r12);
    early_print("  R13: ");
    early_print_hex(r13);
    early_print("\n");
    early_print("  R14: ");
    early_print_hex(r14);
    early_print("  R15: ");
    early_print_hex(r15);
    early_print("\n");
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

#[repr(C, packed)]
struct Idtr {
    limit: u16,
    base: u64,
}

fn dump_idt_gate(label: &str, vector: u8) {
    let mut idtr = Idtr { limit: 0, base: 0 };
    unsafe {
        core::arch::asm!("sidt [{}]", in(reg) &mut idtr, options(nostack, preserves_flags));
    }

    early_print("  ");
    early_print(label);
    early_print(" IDTR base=");
    early_print_hex(idtr.base);
    early_print(" limit=");
    early_print_hex(idtr.limit as u64);
    early_print("\n");

    let gate_offset = (vector as usize) * 16;
    if gate_offset + 16 > idtr.limit as usize + 1 {
        early_print("    gate out of range\n");
        return;
    }

    let gate_ptr = (idtr.base as usize + gate_offset) as *const u8;
    let mut raw = [0u8; 16];
    for (idx, byte) in raw.iter_mut().enumerate() {
        *byte = unsafe { *gate_ptr.add(idx) };
    }

    early_print("    raw=");
    for byte in raw {
        let high = (byte >> 4) & 0xF;
        let low = byte & 0xF;
        let high_char = if high < 10 {
            b'0' + high
        } else {
            b'a' + high - 10
        };
        let low_char = if low < 10 {
            b'0' + low
        } else {
            b'a' + low - 10
        };
        crate::io::log::early_print_char(high_char);
        crate::io::log::early_print_char(low_char);
        early_print(" ");
    }
    early_print("\n");

    let offset_low = u16::from_le_bytes([raw[0], raw[1]]) as u64;
    let selector = u16::from_le_bytes([raw[2], raw[3]]) as u64;
    let ist = (raw[4] & 0x7) as u64;
    let type_attr = raw[5] as u64;
    let offset_mid = u16::from_le_bytes([raw[6], raw[7]]) as u64;
    let offset_high = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]) as u64;
    let target = offset_low | (offset_mid << 16) | (offset_high << 32);

    early_print("    target=");
    early_print_hex(target);
    early_print(" selector=");
    early_print_hex(selector);
    early_print(" ist=");
    early_print_hex(ist);
    early_print(" attr=");
    early_print_hex(type_attr);
    early_print("\n");
}

fn dump_local_apic_in_service() {
    let lapic_base = crate::platform::acpi::local_apic_address().unwrap_or(0xFEE0_0000) as usize;
    early_print("  LAPIC ISR:");
    let mut found = false;

    for block in 0..8usize {
        let reg = lapic_base + 0x100 + (block * 0x10);
        let bits = crate::io::mmio::mmio_read_u32(reg);
        if bits == 0 {
            continue;
        }

        found = true;
        early_print(" [");
        early_print_dec((block * 32) as u64);
        early_print("]=");
        early_print_hex(bits as u64);
    }

    if !found {
        early_print(" none");
    }
    early_print("\n");
}

fn dump_saved_rsp_words(stack_frame: &InterruptStackFrame) {
    let rsp = stack_frame.stack_pointer.as_u64() as *const u64;
    early_print("  Saved RSP words:");
    for idx in 0..4usize {
        let word = unsafe { *rsp.add(idx) };
        early_print(" [");
        early_print_dec(idx as u64);
        early_print("]=");
        early_print_hex(word);
    }
    early_print("\n");
}

// ============================================================================
// Exception Handlers
// ============================================================================

/// Divide Error (#DE)
define_interrupt!(
    pub fn divide_error_handler(stack_frame: InterruptStackFrame) {
        EXCEPTION_STATS
            .divide_errors
            .fetch_add(1, Ordering::Relaxed);

        early_print("\n[EXCEPTION] DIVIDE ERROR (#DE)\n");
        dump_stack_frame(&stack_frame);

        panic!("Divide by zero");
    }
);

/// Debug Exception (#DB)
define_interrupt!(
    pub fn debug_handler(stack_frame: InterruptStackFrame) {
        crate::debug::gdb_stub::on_trap(5, &stack_frame);
        early_print("\n[EXCEPTION] DEBUG (#DB)\n");
        dump_stack_frame(&stack_frame);
        // デバッグ例外は継続可能
    }
);

/// Breakpoint (#BP)
define_interrupt!(
    pub fn breakpoint_handler(stack_frame: InterruptStackFrame) {
        EXCEPTION_STATS.breakpoints.fetch_add(1, Ordering::Relaxed);
        crate::debug::gdb_stub::on_trap(5, &stack_frame);

        early_print("\n[EXCEPTION] BREAKPOINT (#BP)\n");
        dump_stack_frame(&stack_frame);
        // ブレークポイントは継続可能
    }
);

/// Invalid Opcode (#UD)
define_interrupt!(
    pub fn invalid_opcode_handler(stack_frame: InterruptStackFrame) {
        EXCEPTION_STATS
            .invalid_opcodes
            .fetch_add(1, Ordering::Relaxed);
        crate::io::log::enter_panic_mode();

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
            let high_char = if high < 10 {
                b'0' + high
            } else {
                b'a' + high - 10
            };
            let low_char = if low < 10 {
                b'0' + low
            } else {
                b'a' + low - 10
            };
            crate::io::log::early_print_char(high_char);
            crate::io::log::early_print_char(low_char);
            early_print(" ");
        }
        early_print("\n");
        let rip_u64 = stack_frame.instruction_pointer.as_u64();
        let symbol = crate::unwind::resolve_symbol_name(rip_u64 as usize).unwrap_or("unknown");
        early_print("  Symbol: ");
        early_print(symbol);
        early_print("\n");
        let current_cpu = crate::cpu::try_current_id().unwrap_or_else(|| crate::cpu::current_id());
        let executor_phase = crate::task::current_executor_phase(current_cpu).unwrap_or("unknown");
        let worker_stage = crate::cpu::stage_name(current_cpu).unwrap_or("unknown");
        early_print("  CPU: ");
        early_print_dec(current_cpu as u64);
        early_print("\n  Executor phase: ");
        early_print(executor_phase);
        early_print("\n  Worker stage: ");
        early_print(worker_stage);
        if let Some((last_vector, last_rip, last_rsp)) =
            crate::interrupts::last_interrupt_context(current_cpu)
        {
            early_print("\n  Last vector: ");
            early_print_hex(last_vector as u64);
            early_print("\n  Last interrupted RIP: ");
            early_print_hex(last_rip);
            early_print("\n  Last interrupted RSP: ");
            early_print_hex(last_rsp);
        }
        early_print("\n");
        dump_idt_gate("com1", crate::interrupts::InterruptVector::Com1 as u8);
        dump_idt_gate("wake", crate::interrupts::EXECUTOR_WAKE_VECTOR);
        dump_idt_gate("tlb", crate::mm::sync::tlb_batch::TLB_FLUSH_VECTOR);
        dump_idt_gate("timer", crate::interrupts::InterruptVector::Timer as u8);
        dump_local_apic_in_service();
        dump_saved_rsp_words(&stack_frame);

        if let Some(ctx) = crate::task::current_polled_task_context() {
            early_print("  Task context: task=");
            early_print_dec(ctx.task_id);
            early_print(" domain=");
            early_print_dec(ctx.domain_id);
            early_print("\n");
            panic!(
                "Invalid opcode rip={:#x} symbol={} cpu={} phase={} task={} domain={}",
                rip_u64, symbol, ctx.cpu_id, executor_phase, ctx.task_id, ctx.domain_id
            );
        }

        panic!(
            "Invalid opcode rip={:#x} symbol={} cpu={} phase={}",
            rip_u64, symbol, current_cpu, executor_phase
        );
    }
);

/// Device Not Available (#NM)
define_interrupt!(
    pub fn device_not_available_handler(stack_frame: InterruptStackFrame) {
        early_print("\n[EXCEPTION] DEVICE NOT AVAILABLE (#NM)\n");
        dump_stack_frame(&stack_frame);

        // FPU/SSE の遅延切り替え用
        panic!("FPU not available");
    }
);

/// Double Fault (#DF)
///
/// これは専用のISTスタックで動作する（スタック破損時でも動く）
define_interrupt!(
    pub fn double_fault_handler(stack_frame: InterruptStackFrame, error_code: u64) -> ! {
        EXCEPTION_STATS
            .double_faults
            .fetch_add(1, Ordering::Relaxed);

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
        // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
        loop {
            x86_64::instructions::hlt();
        }
    }
);

/// General Protection Fault (#GP)
define_interrupt!(
    pub fn general_protection_fault_handler(stack_frame: InterruptStackFrame, error_code: u64) {
        EXCEPTION_STATS
            .general_protection_faults
            .fetch_add(1, Ordering::Relaxed);

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
);

/// Page Fault (#PF)
define_interrupt!(
    pub fn page_fault_handler(stack_frame: InterruptStackFrame, error_code: PageFaultErrorCode) {
        EXCEPTION_STATS.page_faults.fetch_add(1, Ordering::Relaxed);

        // Convert the raw stack pointer into our kernel's higher-half VirtAddr type
        let rsp: HHVirtAddr = HHVirtAddr::new(stack_frame.stack_pointer.as_u64());

        // 高度なページフォルトハンドラを呼び出し
        let res = crate::mm::virt::fault_handler::handle_page_fault(error_code.bits(), rsp);

        if matches!(
            res,
            crate::mm::virt::fault_handler::FaultResult::Resolved
                | crate::mm::virt::fault_handler::FaultResult::CowHandled
                | crate::mm::virt::fault_handler::FaultResult::DemandPaged
                | crate::mm::virt::fault_handler::FaultResult::StackGrown
                | crate::mm::virt::fault_handler::FaultResult::FilePageLoaded
        ) {
            // 解決されたので例外から復帰
            return;
        }

        // 解決できなかった場合は詳細を表示してパニック
        let fault_addr = Cr2::read().unwrap_or(x86_64::VirtAddr::zero());

        early_print("\n[EXCEPTION] UNRESOLVED PAGE FAULT (#PF)\n");
        early_print("Faulting Address: ");
        early_print_hex(fault_addr.as_u64());
        early_print("\nError Code: ");
        early_print_hex(error_code.bits() as u64);
        early_print("\nResult: ");
        early_print(match res {
            crate::mm::virt::fault_handler::FaultResult::NoVma => "No VMA found",
            crate::mm::virt::fault_handler::FaultResult::PermissionDenied => "Permission Denied",
            crate::mm::virt::fault_handler::FaultResult::OutOfMemory => "Out of Memory",
            crate::mm::virt::fault_handler::FaultResult::StackOverflow => "Stack Overflow",
            crate::mm::virt::fault_handler::FaultResult::KernelBug => "Kernel Bug",
            crate::mm::virt::fault_handler::FaultResult::IoError => "I/O Error",
            _ => "Unknown Error",
        });
        early_print("\n");

        // エラーコードの詳細解析
        let error_bits = error_code.bits();
        early_print("  Present: ");
        early_print(if (error_bits & 0x1) != 0 {
            "true"
        } else {
            "false"
        });
        early_print("\n  Write: ");
        early_print(if (error_bits & 0x2) != 0 {
            "true"
        } else {
            "false"
        });
        early_print("\n  User Mode: ");
        early_print(if (error_bits & 0x4) != 0 {
            "true"
        } else {
            "false"
        });
        early_print("\n");

        early_print("\nStack Frame:\n");
        dump_stack_frame(&stack_frame);

        panic!(
            "Page fault at {:#x} (Result: {:?})",
            fault_addr.as_u64(),
            res
        );
    }
);

/// Alignment Check (#AC)
define_interrupt!(
    pub fn alignment_check_handler(stack_frame: InterruptStackFrame, error_code: u64) {
        early_print("\n[EXCEPTION] ALIGNMENT CHECK (#AC)\n");
        early_print("Error Code: ");
        early_print_hex(error_code);
        early_print("\n");
        dump_stack_frame(&stack_frame);

        panic!("Alignment check");
    }
);

/// Machine Check (#MC)
define_interrupt!(
    pub fn machine_check_handler(stack_frame: InterruptStackFrame) -> ! {
        early_print("\n[EXCEPTION] MACHINE CHECK (#MC) - HARDWARE ERROR\n");
        dump_stack_frame(&stack_frame);

        // ハードウェアエラーは回復不能
        // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
        loop {
            x86_64::instructions::hlt();
        }
    }
);

/// SIMD Floating Point Exception (#XM/#XF)
define_interrupt!(
    pub fn simd_floating_point_handler(stack_frame: InterruptStackFrame) {
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
);

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
