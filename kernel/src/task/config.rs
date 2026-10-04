/// Resource and scheduling policy for the task runtime. These values are kept
/// together so admission, timer accounting, and stack allocation agree.
pub(crate) struct SchedulerConfig {
    pub quantum_ns: u64,
    pub fuel_per_poll: u64,
    pub stack_bytes: usize,
    pub max_tasks: usize,
}

pub(crate) const SCHEDULER_CONFIG: SchedulerConfig = SchedulerConfig {
    quantum_ns: 10_000_000,
    fuel_per_poll: 10_000,
    stack_bytes: 1024 * 1024,
    max_tasks: 256,
};

const _: () = {
    assert!(SCHEDULER_CONFIG.quantum_ns != 0);
    assert!(SCHEDULER_CONFIG.stack_bytes != 0);
    assert!(SCHEDULER_CONFIG.stack_bytes.is_multiple_of(4096));
    assert!(SCHEDULER_CONFIG.max_tasks != 0);
};
