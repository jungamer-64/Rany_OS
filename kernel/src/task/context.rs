//! x86 task-stack transfers. The scheduler stack remains CPU-owned; an
//! interrupted poll retains its interrupt frame on its own guarded stack.

use core::cell::UnsafeCell;

use crate::cpu::xstate::XStateImage;

#[repr(C, align(64))]
pub(super) struct TaskContext {
    scheduler_rsp: UnsafeCell<u64>,
    interrupted_rsp: UnsafeCell<u64>,
    xstate: UnsafeCell<XStateImage>,
    // Immutable projection of the stack retained by the same TaskRecord.
    stack_bottom: u64,
    stack_top: u64,
}

// SAFETY: a published context has exactly one running CPU. Interrupts on
// that CPU may write its saved frame only while Rust task execution is
// suspended; the scheduler observes it after switching to its own stack.
unsafe impl Sync for TaskContext {}

impl TaskContext {
    pub(super) fn new(stack: &super::stack::TaskStack) -> Self {
        let bounds = stack.bounds();
        Self {
            scheduler_rsp: UnsafeCell::new(0),
            interrupted_rsp: UnsafeCell::new(0),
            xstate: UnsafeCell::new(XStateImage::initial()),
            stack_bottom: bounds.start,
            stack_top: bounds.end,
        }
    }

    pub(super) fn address(&self) -> usize {
        self as *const Self as usize
    }
}

pub(crate) fn task_stack_bounds(current: &crate::cpu::CurrentCpu) -> Option<core::ops::Range<u64>> {
    let address = current.preemption_state().active_context();
    if address == 0 {
        return None;
    }
    // SAFETY: this CPU's switch owner installed exactly one TaskContext and
    // retains its TaskRecord until leaving the task. This CPU-local caller
    // reads only the immutable bounds; a suspended poll resumes on this CPU.
    let context = unsafe { &*(address as *const TaskContext) };
    Some(context.stack_bottom..context.stack_top)
}

pub(crate) const SCHEDULER_RSP_OFFSET: usize = core::mem::offset_of!(TaskContext, scheduler_rsp);
pub(crate) const INTERRUPTED_RSP_OFFSET: usize =
    core::mem::offset_of!(TaskContext, interrupted_rsp);
pub(crate) const XSTATE_OFFSET: usize = core::mem::offset_of!(TaskContext, xstate);

const _: () = assert!(XSTATE_OFFSET % 64 == 0);

// The return value is 0 for completed poll, 1 for timer suspension, and 2
// for Pending. Both entry functions return with local interrupts disabled.
unsafe extern "sysv64" {
    fn rany_task_start(
        context: *const TaskContext,
        top: u64,
        task: *const (),
        interrupts_enabled: u64,
    ) -> u64;
    fn rany_task_resume(context: *const TaskContext) -> u64;
    fn rany_task_exit(context: *const TaskContext, poll: u64) -> !;
}

pub(super) unsafe fn start(
    context: &TaskContext,
    top: u64,
    task: *const (),
    interrupts_enabled: bool,
) -> u64 {
    unsafe { rany_task_start(context, top, task, u64::from(interrupts_enabled)) }
}

pub(super) unsafe fn resume(context: &TaskContext) -> u64 {
    unsafe { rany_task_resume(context) }
}

pub(super) unsafe fn exit(context: &TaskContext, poll: u64) -> ! {
    unsafe { rany_task_exit(context, poll) }
}

core::arch::global_asm!(
    r#"
    .global rany_task_start
    rany_task_start:
        push rbx
        push rbp
        push r12
        push r13
        push r14
        push r15
        mov [rdi + {scheduler_rsp}], rsp
        mov r12, rdi
        mov r13, rdx
        mov r11, gs:[{scheduler_xstate}]
        mov r10, gs:[{xstate_mask}]
        test r10, r10
        jz 10f
        mov eax, r10d
        shr r10, 32
        mov edx, r10d
        xsave64 [r11]
        jmp 11f
    10:
        fxsave64 [r11]
    11:
        lea r11, [r12 + {task_xstate}]
        mov r10, gs:[{xstate_mask}]
        test r10, r10
        jz 12f
        mov eax, r10d
        shr r10, 32
        mov edx, r10d
        xrstor64 [r11]
        jmp 13f
    12:
        fxrstor64 [r11]
    13:
        mov rsp, rsi
        and rsp, -16
        sub rsp, 8
        mov qword ptr [rsp], 0
        mov rdi, r13
        test rcx, rcx
        jz 14f
        sti
    14:
        jmp {entry}

    .global rany_task_resume
    rany_task_resume:
        push rbx
        push rbp
        push r12
        push r13
        push r14
        push r15
        mov [rdi + {scheduler_rsp}], rsp
        mov r12, rdi
        mov r11, gs:[{scheduler_xstate}]
        mov r10, gs:[{xstate_mask}]
        test r10, r10
        jz 20f
        mov eax, r10d
        shr r10, 32
        mov edx, r10d
        xsave64 [r11]
        jmp 21f
    20:
        fxsave64 [r11]
    21:
        lea r11, [r12 + {task_xstate}]
        mov r10, gs:[{xstate_mask}]
        test r10, r10
        jz 22f
        mov eax, r10d
        shr r10, 32
        mov edx, r10d
        xrstor64 [r11]
        jmp 23f
    22:
        fxrstor64 [r11]
    23:
        mov rsp, [r12 + {interrupted_rsp}]
        pop r15
        pop r14
        pop r13
        pop r12
        pop r11
        pop r10
        pop r9
        pop r8
        pop rbp
        pop rdi
        pop rsi
        pop rdx
        pop rcx
        pop rbx
        pop rax
        iretq

    .global rany_task_exit
    rany_task_exit:
        cli
        mov r12, rdi
        mov r13, rsi
        lea r11, [r12 + {task_xstate}]
        mov r10, gs:[{xstate_mask}]
        test r10, r10
        jz 30f
        mov eax, r10d
        shr r10, 32
        mov edx, r10d
        xsave64 [r11]
        jmp 31f
    30:
        fxsave64 [r11]
    31:
        mov r11, gs:[{scheduler_xstate}]
        mov r10, gs:[{xstate_mask}]
        test r10, r10
        jz 32f
        mov eax, r10d
        shr r10, 32
        mov edx, r10d
        xrstor64 [r11]
        jmp 33f
    32:
        fxrstor64 [r11]
    33:
        mov rsp, [r12 + {scheduler_rsp}]
        mov rax, r13
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbp
        pop rbx
        ret
    "#,
    scheduler_rsp = const SCHEDULER_RSP_OFFSET,
    interrupted_rsp = const INTERRUPTED_RSP_OFFSET,
    task_xstate = const XSTATE_OFFSET,
    scheduler_xstate = const hal::preemption::SCHEDULER_XSTATE_OFFSET,
    xstate_mask = const hal::preemption::XSTATE_MASK_OFFSET,
    entry = sym super::scheduler::task_entry,
);
