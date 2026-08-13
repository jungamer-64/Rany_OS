mod boot;
mod ipi;

pub use ipi::{IpiKind, broadcast_ipi, current_apic_id, send_eoi_current_cpu, send_ipi};
