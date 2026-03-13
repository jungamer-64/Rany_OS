use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

const MAX_ROUTED_CPUS: usize = crate::per_cpu::MAX_CPUS;

static RUNTIME_WORKERS_RELEASED: AtomicBool = AtomicBool::new(false);
static RUNTIME_WORKER_STAGE: [AtomicU8; MAX_ROUTED_CPUS] = {
    const INIT: AtomicU8 = AtomicU8::new(RuntimeWorkerStage::Unknown as u8);
    [INIT; MAX_ROUTED_CPUS]
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum RuntimeWorkerStage {
    Unknown = 0,
    BootstrapReady = 1,
    Parked = 2,
    ReleaseObserved = 3,
    HandoffIrqsMasked = 4,
    Registered = 5,
    LazyTlbExited = 6,
    ColdStartHelper = 7,
    ExecutorConstructed = 8,
    ExecutorRun = 9,
}

pub fn runtime_workers_released() -> bool {
    RUNTIME_WORKERS_RELEASED.load(Ordering::Acquire)
}

pub(crate) fn set_runtime_worker_stage(cpu_id: usize, stage: RuntimeWorkerStage) {
    if cpu_id < MAX_ROUTED_CPUS {
        RUNTIME_WORKER_STAGE[cpu_id].store(stage as u8, Ordering::Release);
    }
}

pub fn runtime_worker_stage(cpu_id: usize) -> Option<&'static str> {
    if cpu_id >= MAX_ROUTED_CPUS {
        return None;
    }

    match RUNTIME_WORKER_STAGE[cpu_id].load(Ordering::Acquire) {
        x if x == RuntimeWorkerStage::Unknown as u8 => Some("unknown"),
        x if x == RuntimeWorkerStage::BootstrapReady as u8 => Some("bootstrap_ready"),
        x if x == RuntimeWorkerStage::Parked as u8 => Some("parked"),
        x if x == RuntimeWorkerStage::ReleaseObserved as u8 => Some("release_observed"),
        x if x == RuntimeWorkerStage::HandoffIrqsMasked as u8 => Some("handoff_irqs_masked"),
        x if x == RuntimeWorkerStage::Registered as u8 => Some("registered"),
        x if x == RuntimeWorkerStage::LazyTlbExited as u8 => Some("lazy_tlb_exited"),
        x if x == RuntimeWorkerStage::ColdStartHelper as u8 => Some("cold_start_helper"),
        x if x == RuntimeWorkerStage::ExecutorConstructed as u8 => Some("executor_constructed"),
        x if x == RuntimeWorkerStage::ExecutorRun as u8 => Some("executor_run"),
        _ => None,
    }
}

pub fn release_runtime_workers() {
    RUNTIME_WORKERS_RELEASED.store(true, Ordering::Release);
}

pub fn wait_for_runtime_workers() {
    loop {
        if runtime_workers_released() {
            #[cfg(not(test))]
            x86_64::instructions::interrupts::disable();
            return;
        }

        #[cfg(test)]
        core::hint::spin_loop();

        #[cfg(not(test))]
        unsafe {
            core::arch::asm!("sti", "hlt", "cli", options(nomem, nostack));
        }
    }
}

pub(crate) fn reset_runtime_state() {
    RUNTIME_WORKERS_RELEASED.store(false, Ordering::Relaxed);
    for entry in &RUNTIME_WORKER_STAGE {
        entry.store(RuntimeWorkerStage::Unknown as u8, Ordering::Relaxed);
    }
}

#[cfg(test)]
pub(crate) fn reset_runtime_workers_for_tests() {
    reset_runtime_state();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn runtime_worker_release_flag_is_observable() {
        reset_runtime_state();

        assert!(!runtime_workers_released());
        release_runtime_workers();
        assert!(runtime_workers_released());
    }
}
