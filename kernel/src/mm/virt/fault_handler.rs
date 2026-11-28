use core::sync::atomic::{AtomicU64, Ordering};
#[cfg(target_os = "none")]
use x86_64::structures::idt::PageFaultErrorCode;

#[cfg(target_os = "none")]
use super::higher_half::{FaultPageError, VirtAddr, try_restore_fault_page};

#[cfg(target_os = "none")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PageFaultFailure {
    NoVma,
    Protection,
    PageTablesBusy,
    PageTablesUnavailable,
    InvalidContext,
}

pub struct FaultStatSnapshot {
    pub total: u64,
    pub resolved: u64,
    pub rejected: u64,
}

struct FaultStats {
    total: AtomicU64,
    resolved: AtomicU64,
    rejected: AtomicU64,
}

static FAULT_STATS: FaultStats = FaultStats {
    total: AtomicU64::new(0),
    resolved: AtomicU64::new(0),
    rejected: AtomicU64::new(0),
};

pub fn fault_stats() -> FaultStatSnapshot {
    FaultStatSnapshot {
        total: FAULT_STATS.total.load(Ordering::Relaxed),
        resolved: FAULT_STATS.resolved.load(Ordering::Relaxed),
        rejected: FAULT_STATS.rejected.load(Ordering::Relaxed),
    }
}

#[cfg(target_os = "none")]
pub(crate) fn handle_page_fault(address: u64, code: u64) -> Result<(), PageFaultFailure> {
    FAULT_STATS.total.fetch_add(1, Ordering::Relaxed);
    let result = repair_page_fault(address, PageFaultErrorCode::from_bits_retain(code));
    if result.is_ok() {
        FAULT_STATS.resolved.fetch_add(1, Ordering::Relaxed);
    } else {
        FAULT_STATS.rejected.fetch_add(1, Ordering::Relaxed);
    }
    result
}

#[cfg(target_os = "none")]
fn repair_page_fault(address: u64, code: PageFaultErrorCode) -> Result<(), PageFaultFailure> {
    let current = crate::cpu::CurrentCpu::acquire().ok_or(PageFaultFailure::InvalidContext)?;
    let _fault_guard = current
        .try_enter_page_fault()
        .map_err(|_| PageFaultFailure::InvalidContext)?;
    // A hint fault has the non-present encoding of an ordinary data or
    // instruction access. Protection and malformed-entry faults are terminal.
    let ordinary_access = PageFaultErrorCode::CAUSED_BY_WRITE
        | PageFaultErrorCode::USER_MODE
        | PageFaultErrorCode::INSTRUCTION_FETCH;
    if !(code - ordinary_access).is_empty() {
        return Err(PageFaultFailure::Protection);
    }
    let canonical =
        x86_64::VirtAddr::try_new(address).map_err(|_| PageFaultFailure::InvalidContext)?;
    let virt = VirtAddr::new(address);
    let restored = try_restore_fault_page(virt).map_err(|cause| match cause {
        FaultPageError::Busy => PageFaultFailure::PageTablesBusy,
        FaultPageError::Unavailable => PageFaultFailure::PageTablesUnavailable,
        FaultPageError::Unmapped => PageFaultFailure::NoVma,
    })?;

    // Only presence changed. Each faulting CPU discards its own cached walk
    // before retrying. No peer must acknowledge a revocation or mapping change.
    x86_64::instructions::tlb::flush(canonical);
    if let Some(frame) = restored {
        crate::mm::numa::autonuma::record_hint_fault(virt, frame);
    }
    Ok(())
}
