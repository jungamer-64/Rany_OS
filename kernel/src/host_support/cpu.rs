pub use crate::smp::{apic_id_for_cpu as apic_id, cpu_for_apic_id as cpu_for_apic};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CpuBootReport {
    pub detected: u32,
    pub started: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuStage {
    Detected,
    BootPrepared,
    Launching,
    PerCpuReady,
    Parked,
    Released,
    LazyTlbExited,
    ExecutorRunning,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuSnapshot {
    pub detected_cpu_count: usize,
    pub bootable_cpu_count: usize,
    pub online_cpu_count: usize,
    pub online_cpu_mask: u64,
    pub runtime_workers_released: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpiKind {
    ExecutorWake,
    TlbFlush,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuRecord {
    pub logical_cpu_id: usize,
    pub apic_id: u32,
    pub is_bsp: bool,
    pub numa_node: Option<usize>,
    pub boot_slot: Option<usize>,
    pub bootable: bool,
}

pub fn initialize(_boot_info: &boot_proto::ExoBootInfo) -> Result<CpuBootReport, &'static str> {
    Ok(CpuBootReport::default())
}

pub fn count() -> usize {
    1
}

pub fn detected_count() -> usize {
    1
}

pub fn bootable_count() -> usize {
    1
}

pub fn current_id() -> usize {
    0
}

pub fn try_current_id() -> Option<usize> {
    Some(0)
}

pub fn active_ids() -> alloc::vec::Vec<usize> {
    alloc::vec![0]
}

pub fn snapshot() -> CpuSnapshot {
    CpuSnapshot {
        detected_cpu_count: 1,
        bootable_cpu_count: 1,
        online_cpu_count: 1,
        online_cpu_mask: 1,
        runtime_workers_released: false,
    }
}

pub fn stage(_cpu_id: usize) -> Option<CpuStage> {
    Some(CpuStage::PerCpuReady)
}

pub fn stage_name(_cpu_id: usize) -> Option<&'static str> {
    Some("per_cpu_ready")
}

pub fn numa_node(_cpu_id: usize) -> Option<usize> {
    Some(0)
}

pub fn workers_released() -> bool {
    false
}

pub fn release_workers() {}

pub fn send_ipi(_cpu_id: usize, _kind: IpiKind) {}

pub fn broadcast_ipi(_kind: IpiKind) {}

pub fn send_eoi_current_cpu() {}

pub fn current_apic_id() -> u32 {
    0
}
