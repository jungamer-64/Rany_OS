use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};

use super::topology::CpuTopology;

const MAX_CPUS: usize = crate::per_cpu::MAX_CPUS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CpuLifecycleStage {
    Detected = 0,
    BootPrepared = 1,
    Launching = 2,
    PerCpuReady = 3,
    Parked = 4,
    Released = 5,
    LazyTlbExited = 6,
    ExecutorRunning = 7,
    Failed = 8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuLifecycleSnapshot {
    pub detected_cpu_count: usize,
    pub bootable_cpu_count: usize,
    pub online_cpu_count: usize,
    pub online_cpu_mask: u64,
    pub runtime_workers_released: bool,
}

static DETECTED_CPU_COUNT: AtomicUsize = AtomicUsize::new(1);
static BOOTABLE_CPU_COUNT: AtomicUsize = AtomicUsize::new(1);
static ONLINE_CPU_MASK: AtomicU64 = AtomicU64::new(0);
static RUNTIME_WORKERS_RELEASED: AtomicBool = AtomicBool::new(false);
static CPU_STAGES: [AtomicU8; MAX_CPUS] = {
    const INIT: AtomicU8 = AtomicU8::new(CpuLifecycleStage::Detected as u8);
    [INIT; MAX_CPUS]
};

pub(crate) fn reset_state() {
    DETECTED_CPU_COUNT.store(1, Ordering::Relaxed);
    BOOTABLE_CPU_COUNT.store(1, Ordering::Relaxed);
    ONLINE_CPU_MASK.store(0, Ordering::Relaxed);
    RUNTIME_WORKERS_RELEASED.store(false, Ordering::Relaxed);
    for stage in &CPU_STAGES {
        stage.store(CpuLifecycleStage::Detected as u8, Ordering::Relaxed);
    }
}

pub(crate) fn initialize_from_topology(topology: &CpuTopology) {
    reset_state();
    DETECTED_CPU_COUNT.store(topology.detected_cpu_count(), Ordering::Release);
    BOOTABLE_CPU_COUNT.store(topology.bootable_cpu_count(), Ordering::Release);
    for record in topology.records() {
        set_cpu_stage(record.logical_cpu_id, CpuLifecycleStage::Detected);
    }
}

pub fn snapshot() -> CpuLifecycleSnapshot {
    CpuLifecycleSnapshot {
        detected_cpu_count: detected_cpu_count(),
        bootable_cpu_count: bootable_cpu_count(),
        online_cpu_count: online_cpu_count(),
        online_cpu_mask: ONLINE_CPU_MASK.load(Ordering::Acquire),
        runtime_workers_released: runtime_workers_released(),
    }
}

pub fn detected_cpu_count() -> usize {
    DETECTED_CPU_COUNT.load(Ordering::Acquire).max(1)
}

pub fn bootable_cpu_count() -> usize {
    BOOTABLE_CPU_COUNT.load(Ordering::Acquire).max(1)
}

pub fn online_cpu_count() -> usize {
    let mask = ONLINE_CPU_MASK.load(Ordering::Acquire);
    let count = mask.count_ones() as usize;
    if count == 0 { 1 } else { count }
}

pub fn runtime_workers_released() -> bool {
    RUNTIME_WORKERS_RELEASED.load(Ordering::Acquire)
}

pub fn stage(cpu_id: usize) -> Option<CpuLifecycleStage> {
    if cpu_id >= MAX_CPUS {
        return None;
    }

    let known_cpus = detected_cpu_count()
        .min(MAX_CPUS)
        .max(bootable_cpu_count().min(MAX_CPUS))
        .max(online_cpu_count().min(MAX_CPUS));
    if cpu_id >= known_cpus {
        return None;
    }

    Some(stage_from_u8(CPU_STAGES[cpu_id].load(Ordering::Acquire)))
}

pub fn stage_name(cpu_id: usize) -> Option<&'static str> {
    Some(match stage(cpu_id)? {
        CpuLifecycleStage::Detected => "detected",
        CpuLifecycleStage::BootPrepared => "boot_prepared",
        CpuLifecycleStage::Launching => "launching",
        CpuLifecycleStage::PerCpuReady => "per_cpu_ready",
        CpuLifecycleStage::Parked => "parked",
        CpuLifecycleStage::Released => "released",
        CpuLifecycleStage::LazyTlbExited => "lazy_tlb_exited",
        CpuLifecycleStage::ExecutorRunning => "executor_running",
        CpuLifecycleStage::Failed => "failed",
    })
}

pub(crate) fn set_cpu_stage(cpu_id: usize, stage: CpuLifecycleStage) {
    if cpu_id >= MAX_CPUS {
        return;
    }

    CPU_STAGES[cpu_id].store(stage as u8, Ordering::Release);
    let bit = 1u64 << cpu_id;
    if matches!(
        stage,
        CpuLifecycleStage::PerCpuReady
            | CpuLifecycleStage::Parked
            | CpuLifecycleStage::Released
            | CpuLifecycleStage::LazyTlbExited
            | CpuLifecycleStage::ExecutorRunning
    ) {
        ONLINE_CPU_MASK.fetch_or(bit, Ordering::Release);
    } else if cpu_id != 0 {
        ONLINE_CPU_MASK.fetch_and(!bit, Ordering::Release);
    }
}

pub(crate) fn mark_boot_prepared(cpu_id: usize) {
    set_cpu_stage(cpu_id, CpuLifecycleStage::BootPrepared);
}

pub(crate) fn mark_launching(cpu_id: usize) {
    set_cpu_stage(cpu_id, CpuLifecycleStage::Launching);
}

pub(crate) fn mark_runtime_workers_released() {
    RUNTIME_WORKERS_RELEASED.store(true, Ordering::Release);
}

fn stage_from_u8(value: u8) -> CpuLifecycleStage {
    match value {
        x if x == CpuLifecycleStage::Detected as u8 => CpuLifecycleStage::Detected,
        x if x == CpuLifecycleStage::BootPrepared as u8 => CpuLifecycleStage::BootPrepared,
        x if x == CpuLifecycleStage::Launching as u8 => CpuLifecycleStage::Launching,
        x if x == CpuLifecycleStage::PerCpuReady as u8 => CpuLifecycleStage::PerCpuReady,
        x if x == CpuLifecycleStage::Parked as u8 => CpuLifecycleStage::Parked,
        x if x == CpuLifecycleStage::Released as u8 => CpuLifecycleStage::Released,
        x if x == CpuLifecycleStage::LazyTlbExited as u8 => CpuLifecycleStage::LazyTlbExited,
        x if x == CpuLifecycleStage::ExecutorRunning as u8 => CpuLifecycleStage::ExecutorRunning,
        _ => CpuLifecycleStage::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn stage_transitions_update_online_counts() {
        reset_state();

        set_cpu_stage(0, CpuLifecycleStage::PerCpuReady);
        set_cpu_stage(1, CpuLifecycleStage::BootPrepared);
        assert_eq!(online_cpu_count(), 1);

        set_cpu_stage(1, CpuLifecycleStage::Parked);
        assert_eq!(online_cpu_count(), 2);
        assert_eq!(stage_name(1), Some("parked"));

        set_cpu_stage(1, CpuLifecycleStage::ExecutorRunning);
        assert_eq!(stage_name(1), Some("executor_running"));
        assert_eq!(online_cpu_count(), 2);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn initialize_from_topology_tracks_detected_and_bootable_counts() {
        let topology = CpuTopology::from_sources(
            &boot_proto::AcpiBootSnapshot::default(),
            &boot_proto::NumaInfo::default(),
            &boot_proto::ApBootInfo::default(),
            1,
        );

        initialize_from_topology(&topology);

        assert_eq!(detected_cpu_count(), 1);
        assert_eq!(bootable_cpu_count(), 1);
        assert_eq!(stage_name(0), Some("detected"));
    }
}
