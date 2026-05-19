//! SMP Module
//!
//! Symmetric Multi-Processing support including:
//! - AP bootstrap (INIT-SIPI-SIPI)
//! - Per-CPU data structures
//! - Inter-processor interrupts
pub mod bootstrap;
pub(crate) mod lifecycle;
pub(crate) mod runtime;
pub mod topology;
pub(crate) use lifecycle::mark_launching;
pub(crate) use runtime::reset_runtime_state;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SmpBootReport {
    pub detected: u32,
    pub started: u32,
}

#[cfg(test)]
pub(crate) fn reset_runtime_workers_for_tests() {
    reset_runtime_state();
}

#[cfg(test)]
pub(crate) fn reset_cpu_routing_for_tests() {
    topology::reset();
}
