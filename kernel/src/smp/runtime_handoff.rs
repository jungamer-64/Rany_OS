use super::lifecycle::{self, CpuLifecycleStage};

pub struct RuntimeHandoffCoordinator;

impl RuntimeHandoffCoordinator {
    pub const fn new() -> Self {
        Self
    }

    pub fn apply_online_cpu_count(&self, count: usize) {
        let count = count.max(1).min(crate::per_cpu::MAX_CPUS);
        crate::mm::cache::slab_cache::init_per_core_caches(count);
        crate::mm::sync::page_table_cache::set_active_cpu_count(count);
        crate::loader::live_update::set_active_cores(count as u64);
        crate::task::provision_executors(count);
    }

    pub fn apply_current_online_cpu_count(&self) {
        self.apply_online_cpu_count(lifecycle::online_cpu_count());
    }

    pub fn release_runtime_workers(&self) {
        lifecycle::mark_runtime_workers_released();
        lifecycle::set_cpu_stage(0, CpuLifecycleStage::Released);
        let snapshot = lifecycle::snapshot();
        log::info!(
            "[SMP][HANDOFF] runtime_workers_released=1 detected={} bootable={} online={} mask={:#018x}",
            snapshot.detected_cpu_count,
            snapshot.bootable_cpu_count,
            snapshot.online_cpu_count,
            snapshot.online_cpu_mask
        );
        if snapshot.online_cpu_count > 1 {
            crate::io::interrupt_manager::broadcast_ipi(crate::interrupts::EXECUTOR_WAKE_VECTOR);
        }
    }
}

static RUNTIME_HANDOFF_COORDINATOR: RuntimeHandoffCoordinator = RuntimeHandoffCoordinator::new();

pub fn runtime_handoff_coordinator() -> &'static RuntimeHandoffCoordinator {
    &RUNTIME_HANDOFF_COORDINATOR
}
