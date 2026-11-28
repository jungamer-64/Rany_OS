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

#[cfg(target_os = "none")]
pub(super) use native::install_fatal_handlers;

#[cfg(target_os = "none")]
mod native {
    use super::{EXCEPTION_STATS, Ordering};
    use crate::cpu::CurrentCpu;
    use crate::mm::virt::fault_handler;
    use crate::panic_handler::{FatalFault, handle_fault};
    use crate::unwind::StackFrame;
    use core::arch::naked_asm;
    use x86_64::structures::idt::InterruptDescriptorTable;
    use x86_64::{VirtAddr, registers::control::Cr2};

    const DIVIDE_ERROR: u64 = 0;
    const INVALID_OPCODE: u64 = 6;
    const DEVICE_NOT_AVAILABLE: u64 = 7;
    const DOUBLE_FAULT: u64 = 8;
    const GENERAL_PROTECTION: u64 = 13;
    const PAGE_FAULT: u64 = 14;
    const ALIGNMENT_CHECK: u64 = 17;
    const MACHINE_CHECK: u64 = 18;
    const SIMD_FLOATING_POINT: u64 = 19;

    #[repr(C)]
    struct ExceptionFrame {
        vector: u64,
        code: u64,
        rip: usize,
        _cs: u64,
        _rflags: u64,
        rsp: usize,
        _ss: u64,
    }

    #[unsafe(naked)]
    unsafe extern "C" fn exception_entry() -> ! {
        // The CPU aligns the stack before pushing its frame. With the vector
        // and a hardware or synthesized error code, nine pushes align the
        // SysV call. The soft-float kernel cannot clobber the interrupted SIMD
        // state, and the SysV callee preserves all nonvolatile GPRs.
        naked_asm!(
            "push rax",
            "push rcx",
            "push rdx",
            "push rsi",
            "push rdi",
            "push r8",
            "push r9",
            "push r10",
            "push r11",
            "lea rdi, [rsp + {saved_registers}]",
            "mov rsi, rbp",
            "cld",
            "call {dispatch}",
            "pop r11",
            "pop r10",
            "pop r9",
            "pop r8",
            "pop rdi",
            "pop rsi",
            "pop rdx",
            "pop rcx",
            "pop rax",
            "add rsp, {hardware_frame_offset}",
            "iretq",
            saved_registers = const 9 * size_of::<u64>(),
            hardware_frame_offset = const core::mem::offset_of!(ExceptionFrame, rip),
            dispatch = sym dispatch_exception,
        );
    }

    pub(in crate::interrupts) fn install_fatal_handlers(idt: &mut InterruptDescriptorTable) {
        macro_rules! gate {
            ($field:ident, $vector:ident $(, $normalize:literal)?) => {{
                #[unsafe(naked)]
                unsafe extern "C" fn entry() -> ! {
                    naked_asm!(
                        $($normalize,)?
                        "push {vector}",
                        "jmp {common}",
                        vector = const $vector,
                        common = sym exception_entry,
                    );
                }

                // SAFETY: each gate uses its x86 vector's hardware error-code
                // convention. entry normalizes the frame and returns via IRETQ.
                unsafe { idt.$field.set_handler_addr(VirtAddr::new(entry as *const () as u64)) }
            }};
        }

        gate!(divide_error, DIVIDE_ERROR, "push 0");
        gate!(invalid_opcode, INVALID_OPCODE, "push 0");
        gate!(device_not_available, DEVICE_NOT_AVAILABLE, "push 0");
        gate!(general_protection_fault, GENERAL_PROTECTION);
        gate!(alignment_check, ALIGNMENT_CHECK);
        gate!(machine_check, MACHINE_CHECK, "push 0");
        gate!(simd_floating_point, SIMD_FLOATING_POINT, "push 0");

        let double_fault = gate!(double_fault, DOUBLE_FAULT);
        let page_fault = gate!(page_fault, PAGE_FAULT);
        // SAFETY: both IST pointers refer to distinct CPU-local stacks.
        unsafe {
            double_fault.set_stack_index(super::super::gdt::DOUBLE_FAULT_IST_INDEX);
            page_fault.set_stack_index(super::super::gdt::PAGE_FAULT_IST_INDEX);
        }
    }

    unsafe extern "sysv64" fn dispatch_exception(frame: *const ExceptionFrame, rbp: usize) {
        // SAFETY: exception_entry passes a pointer to the normalized hardware
        // frame. Take a snapshot before any operation that could fault again.
        let frame = unsafe { frame.read() };
        let interrupted = StackFrame {
            instruction_pointer: frame.rip,
            stack_pointer: frame.rsp,
            frame_pointer: rbp,
        };
        let kind = match frame.vector {
            DIVIDE_ERROR => {
                EXCEPTION_STATS
                    .divide_errors
                    .fetch_add(1, Ordering::Relaxed);
                FatalFault::DivideError
            }
            INVALID_OPCODE => {
                EXCEPTION_STATS
                    .invalid_opcodes
                    .fetch_add(1, Ordering::Relaxed);
                FatalFault::InvalidOpcode
            }
            DEVICE_NOT_AVAILABLE => FatalFault::DeviceNotAvailable,
            DOUBLE_FAULT => {
                EXCEPTION_STATS
                    .double_faults
                    .fetch_add(1, Ordering::Relaxed);
                FatalFault::DoubleFault { code: frame.code }
            }
            GENERAL_PROTECTION => {
                EXCEPTION_STATS
                    .general_protection_faults
                    .fetch_add(1, Ordering::Relaxed);
                FatalFault::GeneralProtection { code: frame.code }
            }
            PAGE_FAULT => {
                let address = Cr2::read_raw();
                EXCEPTION_STATS.page_faults.fetch_add(1, Ordering::Relaxed);
                let _interrupt = CurrentCpu::acquire().map(CurrentCpu::enter_interrupt);
                let reason = match fault_handler::handle_page_fault(address, frame.code) {
                    Ok(()) => return,
                    Err(reason) => reason,
                };
                FatalFault::PageFault {
                    address,
                    code: frame.code,
                    reason,
                }
            }
            ALIGNMENT_CHECK => FatalFault::AlignmentCheck { code: frame.code },
            MACHINE_CHECK => FatalFault::MachineCheck,
            SIMD_FLOATING_POINT => FatalFault::SimdFloatingPoint,
            _ => unreachable!("only the installed exception gates reach this dispatcher"),
        };
        handle_fault(kind, interrupted)
    }
}
