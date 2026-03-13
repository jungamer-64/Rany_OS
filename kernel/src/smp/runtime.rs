use core::sync::atomic::{AtomicU8, Ordering};

const MAX_ROUTED_CPUS: usize = crate::per_cpu::MAX_CPUS;
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
    ExecutorRunning = 9,
}

pub fn runtime_workers_released() -> bool {
    crate::smp::lifecycle::runtime_workers_released()
}

pub(crate) fn set_runtime_worker_stage(cpu_id: usize, stage: RuntimeWorkerStage) {
    if cpu_id < MAX_ROUTED_CPUS {
        RUNTIME_WORKER_STAGE[cpu_id].store(stage as u8, Ordering::Release);
        let lifecycle_stage = match stage {
            RuntimeWorkerStage::Unknown => crate::smp::lifecycle::CpuLifecycleStage::Detected,
            RuntimeWorkerStage::BootstrapReady
            | RuntimeWorkerStage::Registered
            | RuntimeWorkerStage::ColdStartHelper
            | RuntimeWorkerStage::ExecutorConstructed => {
                crate::smp::lifecycle::CpuLifecycleStage::PerCpuReady
            }
            RuntimeWorkerStage::Parked => crate::smp::lifecycle::CpuLifecycleStage::Parked,
            RuntimeWorkerStage::ReleaseObserved | RuntimeWorkerStage::HandoffIrqsMasked => {
                crate::smp::lifecycle::CpuLifecycleStage::Released
            }
            RuntimeWorkerStage::LazyTlbExited => {
                crate::smp::lifecycle::CpuLifecycleStage::LazyTlbExited
            }
            RuntimeWorkerStage::ExecutorRunning => {
                crate::smp::lifecycle::CpuLifecycleStage::ExecutorRunning
            }
        };
        crate::smp::set_cpu_lifecycle_stage(cpu_id, lifecycle_stage);
    }
}

pub fn runtime_worker_stage(cpu_id: usize) -> Option<&'static str> {
    crate::smp::lifecycle::stage_name(cpu_id)
}

pub fn release_runtime_workers() {
    crate::smp::runtime_handoff::runtime_handoff_coordinator().release_runtime_workers();
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
    crate::smp::lifecycle::reset_state();
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

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn runtime_worker_release_flag_is_observable() {
        reset_runtime_state();

        assert!(!runtime_workers_released());
        release_runtime_workers();
        assert!(runtime_workers_released());
    }
}
