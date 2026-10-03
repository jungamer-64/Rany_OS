//! CPU-local exclusion of task context switches.
//!
//! The kernel installs [`CpuPreemptionHeader`] as the prefix of its GS-backed
//! CPU-local allocation. An interrupt may request a switch while a guard is
//! held; the request stays pending until a later timer interrupt observes an
//! unguarded task. Dropping a guard never switches stacks.

use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

#[repr(C)]
pub struct CpuPreemptionHeader {
    pub self_address: usize,
    state: PreemptionState,
}

pub const ACTIVE_CONTEXT_OFFSET: usize = core::mem::offset_of!(CpuPreemptionHeader, state)
    + core::mem::offset_of!(PreemptionState, active_context);
pub const SCHEDULER_XSTATE_OFFSET: usize = core::mem::offset_of!(CpuPreemptionHeader, state)
    + core::mem::offset_of!(PreemptionState, scheduler_xstate);
pub const XSTATE_MASK_OFFSET: usize = core::mem::offset_of!(CpuPreemptionHeader, state)
    + core::mem::offset_of!(PreemptionState, xstate_mask);

impl CpuPreemptionHeader {
    pub const fn unbound() -> Self {
        Self {
            self_address: 0,
            state: PreemptionState::new(),
        }
    }

    pub fn state(&self) -> &PreemptionState {
        &self.state
    }
}

#[repr(C)]
pub struct PreemptionState {
    depth: AtomicU32,
    pending: AtomicBool,
    active_context: AtomicUsize,
    scheduler_xstate: AtomicUsize,
    xstate_mask: AtomicU64,
    task_timer_ticks: AtomicU32,
}

impl PreemptionState {
    const fn new() -> Self {
        Self {
            depth: AtomicU32::new(0),
            pending: AtomicBool::new(false),
            active_context: AtomicUsize::new(0),
            scheduler_xstate: AtomicUsize::new(0),
            xstate_mask: AtomicU64::new(0),
            task_timer_ticks: AtomicU32::new(0),
        }
    }

    pub fn request(&self) {
        self.pending.store(true, Ordering::Release);
    }

    pub fn may_switch(&self) -> bool {
        self.depth.load(Ordering::Acquire) == 0 && self.pending.load(Ordering::Acquire)
    }

    pub fn clear_request(&self) {
        self.pending.store(false, Ordering::Release);
    }

    pub fn guarded(&self) -> bool {
        self.depth.load(Ordering::Acquire) != 0
    }

    /// The switch owner sets this with interrupts disabled. The pointer is
    /// valid until that same CPU returns to its scheduler stack.
    /// # Safety
    /// `context` must point at the kernel's saved-register context on this
    /// CPU, and remain live until `leave_task` after the stack transfer.
    /// # Panics
    /// Panics if the context is null or this CPU already owns an active task.
    #[expect(
        unsafe_code,
        reason = "the CPU switch owner supplies a live context address"
    )]
    pub unsafe fn enter_task(&self, context: usize) {
        assert_ne!(context, 0);
        assert_eq!(self.active_context.swap(context, Ordering::AcqRel), 0);
        self.task_timer_ticks.store(0, Ordering::Release);
        self.clear_request();
    }

    /// # Panics
    /// Panics if the caller does not own this CPU's active context.
    pub fn leave_task(&self, context: usize) {
        assert_eq!(self.active_context.swap(0, Ordering::AcqRel), context);
        self.task_timer_ticks.store(0, Ordering::Release);
        self.clear_request();
    }

    pub fn active_context(&self) -> usize {
        self.active_context.load(Ordering::Acquire)
    }

    pub fn timer_tick(&self, quantum_ticks: u32) -> bool {
        if self.active_context() == 0 {
            return false;
        }
        let ticks = self
            .task_timer_ticks
            .try_update(Ordering::AcqRel, Ordering::Acquire, |ticks| {
                Some(ticks.saturating_add(1))
            })
            .unwrap_or_else(|_| unreachable!())
            .saturating_add(1);
        if ticks >= quantum_ticks {
            self.request();
        }
        self.may_switch()
    }

    /// # Safety
    /// The image must be a live, CPU-owned area aligned to 64 bytes and large
    /// enough for the configured XSAVE mask (or FXSAVE when mask is zero).
    /// # Panics
    /// Panics if the image is null or not aligned to 64 bytes.
    #[expect(
        unsafe_code,
        reason = "the kernel establishes the CPU xstate storage lifetime"
    )]
    pub unsafe fn configure_xstate(&self, scheduler_image: usize, mask: u64) {
        assert_ne!(scheduler_image, 0);
        assert_eq!(scheduler_image & 63, 0);
        self.scheduler_xstate
            .store(scheduler_image, Ordering::Release);
        self.xstate_mask.store(mask, Ordering::Release);
    }

    /// Resets a CPU slot after its prior physical generation has stopped.
    ///
    /// # Safety
    /// No guard or interrupt may still refer to this state.
    #[expect(
        unsafe_code,
        reason = "rearming requires the prior CPU generation to have stopped"
    )]
    pub unsafe fn reset_for_new_cpu_generation(&self) {
        self.depth.store(0, Ordering::Release);
        self.pending.store(false, Ordering::Release);
        self.active_context.store(0, Ordering::Release);
        self.task_timer_ticks.store(0, Ordering::Release);
    }

    fn enter(&self) {
        self.depth
            .try_update(Ordering::AcqRel, Ordering::Acquire, |depth| {
                depth.checked_add(1)
            })
            .unwrap_or_else(|_| panic!("preemption guard depth exhausted"));
    }

    fn leave(&self) {
        let previous = self.depth.fetch_sub(1, Ordering::AcqRel);
        assert!(previous != 0, "unbalanced preemption guard");
    }
}

/// A guard belongs to the executing CPU and cannot cross a CPU boundary.
pub struct PreemptionGuard {
    state: Option<&'static PreemptionState>,
    _not_send: PhantomData<*const ()>,
}

impl PreemptionGuard {
    pub fn enter() -> Self {
        let state = current_state();
        if let Some(state) = state {
            state.enter();
        }
        Self {
            state,
            _not_send: PhantomData,
        }
    }
}

impl Drop for PreemptionGuard {
    fn drop(&mut self) {
        if let Some(state) = self.state {
            state.leave();
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn current_state() -> Option<&'static PreemptionState> {
    let lower: u32;
    let upper: u32;
    #[expect(
        unsafe_code,
        reason = "reading the kernel-owned GS base requires RDMSR"
    )]
    // SAFETY: RDMSR is available in kernel privilege level. CPU binding owns
    // IA32_GS_BASE and installs only a pinned CpuPreemptionHeader prefix.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") 0xc000_0101u32,
            out("eax") lower,
            out("edx") upper,
            options(nomem, nostack, preserves_flags),
        );
    }
    let address = (u64::from(upper) << 32) | u64::from(lower);
    if address == 0 {
        return None;
    }
    let header = address as *const CpuPreemptionHeader;
    // SAFETY: the kernel clears GS before retiring a CPU-local allocation;
    // while installed the header remains pinned for that CPU generation.
    #[expect(unsafe_code, reason = "GS points at the pinned CPU-local prefix")]
    let header = unsafe { &*header };
    assert_eq!(header.self_address as u64, address);
    Some(header.state())
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
fn current_state() -> Option<&'static PreemptionState> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_timer_interrupts_do_not_request_a_task_switch() {
        let state = PreemptionState::new();
        for _ in 0..32 {
            assert!(!state.timer_tick(10));
        }
        assert!(!state.may_switch());
        assert_eq!(state.task_timer_ticks.load(Ordering::Acquire), 0);
    }

    #[test]
    fn nested_guards_retain_the_request_until_a_later_timer() {
        let state = PreemptionState::new();
        // This local state model has an active owner but performs no stack
        // transfer or dereference of the identity recorded in the field.
        state.active_context.store(1, Ordering::Release);
        state.enter();
        state.enter();
        assert!(!state.timer_tick(1));
        assert!(state.pending.load(Ordering::Acquire));
        state.leave();
        assert!(!state.may_switch());
        state.leave();
        assert!(state.pending.load(Ordering::Acquire));
        assert_eq!(state.active_context(), 1);
        // Guard release changes only exclusion depth. The timer still owns
        // the decision to transfer the active execution to its scheduler.
        assert!(state.timer_tick(1));
        state.leave_task(1);
        assert!(!state.may_switch());
        assert!(!state.timer_tick(1));
    }

    #[test]
    fn quantum_is_counted_only_for_the_active_execution_fragment() {
        let state = PreemptionState::new();
        state.active_context.store(1, Ordering::Release);
        for _ in 0..9 {
            assert!(!state.timer_tick(10));
        }
        assert!(state.timer_tick(10));
        state.leave_task(1);
        assert_eq!(state.task_timer_ticks.load(Ordering::Acquire), 0);
        state.active_context.store(2, Ordering::Release);
        assert!(!state.timer_tick(10));
    }
}
