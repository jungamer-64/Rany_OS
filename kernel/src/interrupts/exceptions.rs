// src/interrupts/exceptions.rs - CPU Exception Handlers
// 堅牢な例外処理：詳細なダンプ、リカバリ可能な場合の対応
// ============================================================================
use crate::io::log::{early_print, early_print_hex};
use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::structures::idt::InterruptStackFrame;

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

// Debug Exception (#DB)
define_interrupt!(
    pub fn debug_handler(stack_frame: InterruptStackFrame) {
        crate::debug::gdb_stub::on_trap(5, &stack_frame);
        early_print("\n[EXCEPTION] DEBUG (#DB)\n");
        dump_stack_frame(&stack_frame);
        // デバッグ例外は継続可能
    }
);

// Breakpoint (#BP)
define_interrupt!(
    pub fn breakpoint_handler(stack_frame: InterruptStackFrame) {
        EXCEPTION_STATS.breakpoints.fetch_add(1, Ordering::Relaxed);
        crate::debug::gdb_stub::on_trap(5, &stack_frame);

        early_print("\n[EXCEPTION] BREAKPOINT (#BP)\n");
        dump_stack_frame(&stack_frame);
        // ブレークポイントは継続可能
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
