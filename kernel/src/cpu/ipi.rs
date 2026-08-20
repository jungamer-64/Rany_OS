use super::{ApicId, CpuId, CpuSlotState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpiKind {
    ExecutorWake,
    TlbFlush,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CpuIpiError {
    CpuNotPresent(CpuId),
    CpuStateIneligible {
        cpu_id: CpuId,
        state: CpuSlotState,
        kind: IpiKind,
    },
    LocalApic(crate::drivers::apic::LocalApicError),
}

pub(crate) fn send_ipi(cpu_id: CpuId, kind: IpiKind) -> Result<(), CpuIpiError> {
    let snapshot = super::snapshot();
    let slot = snapshot
        .slot(cpu_id)
        .ok_or(CpuIpiError::CpuNotPresent(cpu_id))?;
    let eligible = match kind {
        IpiKind::ExecutorWake => slot.state.accepts_executor_wake(),
        IpiKind::TlbFlush => slot.state.participates_in_tlb(),
    };
    if !eligible {
        return Err(CpuIpiError::CpuStateIneligible {
            cpu_id,
            state: slot.state,
            kind,
        });
    }
    send_ipi_to_apic(slot.firmware.apic_id, kind)
}

pub(crate) fn send_ipi_to_apic(apic_id: ApicId, kind: IpiKind) -> Result<(), CpuIpiError> {
    crate::drivers::apic::local_apic()
        .map_err(CpuIpiError::LocalApic)?
        .send_ipi(
            crate::drivers::apic::ApicDestination::new(apic_id.as_u32()),
            vector_for(kind),
        )
        .map_err(CpuIpiError::LocalApic)
}

pub(crate) fn send_eoi_current_cpu() -> Result<(), CpuIpiError> {
    crate::drivers::apic::end_of_interrupt().map_err(CpuIpiError::LocalApic)
}

pub(crate) fn current_apic_id() -> Result<ApicId, CpuIpiError> {
    crate::drivers::apic::local_apic()
        .map(|apic| ApicId::new(apic.id()))
        .map_err(CpuIpiError::LocalApic)
}

const fn vector_for(kind: IpiKind) -> u8 {
    match kind {
        IpiKind::ExecutorWake => crate::interrupts::EXECUTOR_WAKE_VECTOR,
        IpiKind::TlbFlush => crate::mm::sync::tlb::TLB_FLUSH_VECTOR,
    }
}
