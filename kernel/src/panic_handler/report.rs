use core::alloc::Layout;
use core::cell::UnsafeCell;
use core::fmt::Write;
use core::panic::{Location, PanicInfo};
use x86_64::structures::idt::InterruptStackFrame;

use super::{FatalFault, bounded_message, fail_stop, record};
use crate::graphics::bsod::BsodInfo;
use crate::io::serial::{self, FatalSerial};
use crate::unwind::Backtrace;

const REPORT_STACK_SIZE: usize = 64 * 1024;
#[repr(align(4096))]
struct ReportStack(UnsafeCell<[u8; REPORT_STACK_SIZE]>);

// SAFETY: the terminal owner is elected before changing RSP. Its stack is
// never borrowed by any peer or reused by a recursive fatal call.
unsafe impl Sync for ReportStack {}

static REPORT_STACK: ReportStack = ReportStack(UnsafeCell::new([0; REPORT_STACK_SIZE]));

enum Cause<'a> {
    Rust(&'a PanicInfo<'a>),
    OutOfMemory(Layout),
    Fault {
        kind: FatalFault,
        rip: u64,
        rsp: u64,
    },
}

impl Cause<'_> {
    fn message(&self) -> &'static str {
        match self {
            Self::Rust(info) => {
                // Formatting the arguments could call application code again.
                bounded_message(
                    info.message()
                        .as_str()
                        .unwrap_or("Panic message requires runtime formatting"),
                )
            }
            Self::OutOfMemory(_) => "Kernel allocation failed",
            Self::Fault { kind, .. } => match kind {
                FatalFault::DoubleFault { .. } => "Double fault (#DF)",
                FatalFault::InvalidOpcode => "Invalid opcode (#UD)",
                FatalFault::PageFault { .. } => "Unresolved page fault (#PF)",
                FatalFault::MachineCheck => "Machine check (#MC)",
            },
        }
    }

    fn location(&self) -> Option<&'static Location<'static>> {
        match self {
            Self::Rust(info) => info.location(),
            _ => None,
        }
    }

    fn minimal(&self) -> bool {
        matches!(
            self,
            Self::Fault {
                kind: FatalFault::DoubleFault { .. } | FatalFault::MachineCheck,
                ..
            }
        )
    }

    fn write_detail(&self, serial: &mut FatalSerial) -> core::fmt::Result {
        match self {
            Self::Rust(_) => Ok(()),
            Self::OutOfMemory(layout) => {
                writeln!(
                    serial,
                    "[PANIC] Allocation size={} align={}",
                    layout.size(),
                    layout.align()
                )
            }
            Self::Fault { kind, rip, rsp } => {
                writeln!(serial, "[PANIC] Fault RIP={rip:#018x} RSP={rsp:#018x}")?;
                match kind {
                    FatalFault::InvalidOpcode | FatalFault::MachineCheck => Ok(()),
                    FatalFault::DoubleFault { code } => {
                        writeln!(serial, "[PANIC] Error code={code:#x}")
                    }
                    FatalFault::PageFault {
                        address,
                        code,
                        reason,
                    } => {
                        writeln!(
                            serial,
                            "[PANIC] CR2={address:#018x} error={code:#x} result={reason:?}"
                        )
                    }
                }
            }
        }
    }
}

struct Request<'a> {
    owner: fail_stop::FatalOwner,
    cause: Cause<'a>,
}

#[cfg(not(test))]
pub(crate) fn handle_panic(info: &PanicInfo<'_>) -> ! {
    enter(Cause::Rust(info))
}

#[cfg(not(test))]
pub(crate) fn handle_oom(layout: Layout) -> ! {
    enter(Cause::OutOfMemory(layout))
}

pub(super) fn handle_fault(kind: FatalFault, frame: &InterruptStackFrame) -> ! {
    enter(Cause::Fault {
        kind,
        rip: frame.instruction_pointer.as_u64(),
        rsp: frame.stack_pointer.as_u64(),
    })
}

#[inline(never)]
fn enter(cause: Cause<'_>) -> ! {
    x86_64::instructions::interrupts::disable();
    let request = Request {
        owner: fail_stop::FatalOwner::claim(),
        cause,
    };
    let base = REPORT_STACK.0.get() as usize;
    // SAFETY: the elected owner has exclusive use of this static stack. Its
    // top is 16-byte aligned before the SysV call. The abandoned caller stack
    // retains the request and captured frame chain. Execution never returns.
    unsafe {
        core::arch::asm!(
            "mov rsi, rsp",
            "mov rdx, rbp",
            "mov rsp, rax",
            "xor ebp, ebp",
            "call {report}",
            report = sym report_on_stack,
            in("rax") base + REPORT_STACK_SIZE,
            in("rdi") &raw const request,
            options(noreturn),
        )
    }
}

unsafe extern "sysv64" fn report_on_stack(
    request: *const Request<'_>,
    rsp: usize,
    rbp: usize,
) -> ! {
    // SAFETY: the assembly entry retains an initialized request in its
    // suspended frame for all remaining execution of the reporter.
    let Request { owner, cause } = unsafe { request.read() };
    serial::suppress_runtime_serial();
    let stopped = owner.stop_peers();
    let (targets, unconfirmed, delivery_errors) = (
        stopped.targets,
        stopped.unconfirmed,
        stopped.delivery_errors,
    );
    let mut output = match stopped.into_quiesced() {
        Some(peers) => Some(FatalSerial::take_quiesced(peers)),
        None => FatalSerial::try_open(),
    };

    let record = record::publish(cause.message());
    let mut info = BsodInfo::new(record.message);
    if let Some(location) = cause.location() {
        info = info.with_location(location.file(), location.line(), location.column());
    }
    if let Some(serial) = &mut output {
        // Hardware failure consumes this best-effort reporter. The in-memory
        // record remains published even when the UART cannot deliver it.
        let _ = writeln!(serial, "\n!!! KERNEL PANIC DETECTED !!!\n{info}");
        let _ = writeln!(
            serial,
            "[PANIC] CPU stop acknowledged={}/{} delivery_errors={}",
            targets - unconfirmed,
            targets,
            delivery_errors
        );
        if let Some(page) = &record.page {
            let _ = writeln!(serial, "[PANIC] record saved at {:#x}", page.phys);
        }
        let _ = cause.write_detail(serial);
        serial.finish();
    }
    if !cause.minimal() {
        show_backtrace(info, output.as_mut(), rsp, rbp);
    }
    if let Some(serial) = &mut output {
        let _ = writeln!(serial, "[PANIC] Halting reporting CPU");
        serial.finish();
    }
    fail_stop::stop_current_cpu()
}

#[inline(never)]
fn show_backtrace(info: BsodInfo<'_>, serial: Option<&mut FatalSerial>, rsp: usize, rbp: usize) {
    let trace = Backtrace::from_stack_registers(rsp, rbp);
    let info = if trace.is_empty() {
        info
    } else {
        if let Some(serial) = serial {
            let _ = crate::graphics::bsod::write_backtrace(serial, &trace);
            serial.finish();
        }
        info.with_backtrace(&trace)
    };
    #[cfg(not(any(test, feature = "bench")))]
    crate::graphics::try_with_framebuffer(|framebuffer| {
        crate::graphics::bsod::display_bsod_direct(framebuffer, &info);
    });
    #[cfg(any(test, feature = "bench"))]
    let _ = info;
}
