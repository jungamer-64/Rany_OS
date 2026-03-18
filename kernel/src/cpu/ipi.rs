#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpiKind {
    ExecutorWake,
    TlbFlush,
}

pub fn send_ipi(cpu_id: usize, kind: IpiKind) {
    let Some(apic_id) = crate::cpu::apic_id(cpu_id) else {
        broadcast_ipi(kind);
        return;
    };

    let vector = vector_for(kind);
    crate::smp::bootstrap::send_ipi(apic_id, vector);
}

pub fn broadcast_ipi(kind: IpiKind) {
    crate::smp::bootstrap::broadcast_ipi(vector_for(kind));
}

pub fn send_eoi_current_cpu() {
    crate::smp::bootstrap::send_eoi_current_cpu();
}

pub fn current_apic_id() -> u32 {
    crate::drivers::apic::local_apic().id() as u32
}

fn vector_for(kind: IpiKind) -> u8 {
    match kind {
        IpiKind::ExecutorWake => crate::interrupts::EXECUTOR_WAKE_VECTOR,
        IpiKind::TlbFlush => crate::mm::sync::tlb_batch::TLB_FLUSH_VECTOR,
    }
}
