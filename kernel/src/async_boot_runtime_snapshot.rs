
const ASYNC_BOOT_STAGE_COUNT: usize = 6;
const ASYNC_BOOT_CPU_UNSET: usize = usize::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct AsyncBootStageCpuRuntimeSnapshot {
    pub assigned_cpu: Option<usize>,
    pub started_cpu: Option<usize>,
    pub completed_cpu: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct AsyncBootStageRuntimeSnapshot {
    pub platform: AsyncBootStageCpuRuntimeSnapshot,
    pub graphics: AsyncBootStageCpuRuntimeSnapshot,
    pub core_services: AsyncBootStageCpuRuntimeSnapshot,
    pub driver: AsyncBootStageCpuRuntimeSnapshot,
    pub post_driver: AsyncBootStageCpuRuntimeSnapshot,
    pub finalizer: AsyncBootStageCpuRuntimeSnapshot,
}

#[cfg(any(test, feature = "qemu-test-export"))]
static ASYNC_BOOT_ASSIGNED_CPUS: [AtomicUsize; ASYNC_BOOT_STAGE_COUNT] = {
    const INIT: AtomicUsize = AtomicUsize::new(ASYNC_BOOT_CPU_UNSET);
    [INIT; ASYNC_BOOT_STAGE_COUNT]
};
#[cfg(any(test, feature = "qemu-test-export"))]
static ASYNC_BOOT_STARTED_CPUS: [AtomicUsize; ASYNC_BOOT_STAGE_COUNT] = {
    const INIT: AtomicUsize = AtomicUsize::new(ASYNC_BOOT_CPU_UNSET);
    [INIT; ASYNC_BOOT_STAGE_COUNT]
};
#[cfg(any(test, feature = "qemu-test-export"))]
static ASYNC_BOOT_COMPLETED_CPUS: [AtomicUsize; ASYNC_BOOT_STAGE_COUNT] = {
    const INIT: AtomicUsize = AtomicUsize::new(ASYNC_BOOT_CPU_UNSET);
    [INIT; ASYNC_BOOT_STAGE_COUNT]
};

#[cfg(any(test, feature = "qemu-test-export"))]
fn decode_async_boot_cpu(value: usize) -> Option<usize> {
    (value != ASYNC_BOOT_CPU_UNSET).then_some(value)
}

#[cfg(any(test, feature = "qemu-test-export"))]
fn read_async_boot_stage_runtime(stage_index: usize) -> AsyncBootStageCpuRuntimeSnapshot {
    AsyncBootStageCpuRuntimeSnapshot {
        assigned_cpu: decode_async_boot_cpu(
            ASYNC_BOOT_ASSIGNED_CPUS[stage_index].load(Ordering::Acquire),
        ),
        started_cpu: decode_async_boot_cpu(
            ASYNC_BOOT_STARTED_CPUS[stage_index].load(Ordering::Acquire),
        ),
        completed_cpu: decode_async_boot_cpu(
            ASYNC_BOOT_COMPLETED_CPUS[stage_index].load(Ordering::Acquire),
        ),
    }
}

#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) fn async_boot_stage_runtime_snapshot() -> AsyncBootStageRuntimeSnapshot {
    AsyncBootStageRuntimeSnapshot {
        platform: read_async_boot_stage_runtime(0),
        graphics: read_async_boot_stage_runtime(1),
        core_services: read_async_boot_stage_runtime(2),
        driver: read_async_boot_stage_runtime(3),
        post_driver: read_async_boot_stage_runtime(4),
        finalizer: read_async_boot_stage_runtime(5),
    }
}

#[cfg(not(any(test, feature = "qemu-test-export")))]
pub(crate) fn async_boot_stage_runtime_snapshot() -> AsyncBootStageRuntimeSnapshot {
    AsyncBootStageRuntimeSnapshot::default()
}

#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) fn reset_async_boot_stage_runtime_snapshot() {
    for stage_index in 0..ASYNC_BOOT_STAGE_COUNT {
        ASYNC_BOOT_ASSIGNED_CPUS[stage_index].store(ASYNC_BOOT_CPU_UNSET, Ordering::Release);
        ASYNC_BOOT_STARTED_CPUS[stage_index].store(ASYNC_BOOT_CPU_UNSET, Ordering::Release);
        ASYNC_BOOT_COMPLETED_CPUS[stage_index].store(ASYNC_BOOT_CPU_UNSET, Ordering::Release);
    }
}

#[cfg(not(any(test, feature = "qemu-test-export")))]
pub(crate) fn reset_async_boot_stage_runtime_snapshot() {}

#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) fn record_async_boot_stage_assigned_cpu(stage_index: usize, cpu_id: usize) {
    if stage_index < ASYNC_BOOT_STAGE_COUNT {
        ASYNC_BOOT_ASSIGNED_CPUS[stage_index].store(cpu_id, Ordering::Release);
    }
}

#[cfg(not(any(test, feature = "qemu-test-export")))]
pub(crate) fn record_async_boot_stage_assigned_cpu(_stage_index: usize, _cpu_id: usize) {}

#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) fn record_async_boot_stage_started_cpu(stage_index: usize, cpu_id: usize) {
    if stage_index < ASYNC_BOOT_STAGE_COUNT {
        ASYNC_BOOT_STARTED_CPUS[stage_index].store(cpu_id, Ordering::Release);
    }
}

#[cfg(not(any(test, feature = "qemu-test-export")))]
pub(crate) fn record_async_boot_stage_started_cpu(_stage_index: usize, _cpu_id: usize) {}

#[cfg(any(test, feature = "qemu-test-export"))]
pub(crate) fn record_async_boot_stage_completed_cpu(stage_index: usize, cpu_id: usize) {
    if stage_index < ASYNC_BOOT_STAGE_COUNT {
        ASYNC_BOOT_COMPLETED_CPUS[stage_index].store(cpu_id, Ordering::Release);
    }
}

#[cfg(not(any(test, feature = "qemu-test-export")))]
pub(crate) fn record_async_boot_stage_completed_cpu(_stage_index: usize, _cpu_id: usize) {}
