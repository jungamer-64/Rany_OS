#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::registers::control::Cr2;

use super::higher_half::{PageFlags, VirtAddr, with_current_pte_mut};
use crate::mm::numa::autonuma::{
    MIGRATION_ENGINE, MigrationRequest, NumaFaultAction, get_page_numa_stats, handle_numa_fault,
};
use crate::mm::types::FrameIndex;
use crate::per_cpu::PerCpuHot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultResult {
    Resolved,
    NoVma,
    PermissionDenied,
    OutOfMemory,
    StackOverflow,
    KernelBug,
    IoError,
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

pub fn handle_page_fault(_error_code: u64, _current_rsp: VirtAddr) -> FaultResult {
    FAULT_STATS.total.fetch_add(1, Ordering::Relaxed);

    let recursive = crate::per_cpu::with_current_hot(PerCpuHot::enter_page_fault).unwrap_or(false);
    if recursive {
        return FaultResult::KernelBug;
    }

    let result = match Cr2::read() {
        Ok(addr) => handle_fault_addr(VirtAddr::new(addr.as_u64())),
        Err(_) => FaultResult::KernelBug,
    };

    let _ = crate::per_cpu::with_current_hot(PerCpuHot::exit_page_fault);
    match result {
        FaultResult::Resolved => {
            FAULT_STATS.resolved.fetch_add(1, Ordering::Relaxed);
        }
        _ => {
            FAULT_STATS.rejected.fetch_add(1, Ordering::Relaxed);
        }
    }
    result
}

fn handle_fault_addr(fault_addr: VirtAddr) -> FaultResult {
    if let Some(result) = handle_numa_hint_fault(fault_addr) {
        return result;
    }

    FaultResult::NoVma
}

fn handle_numa_hint_fault(fault_addr: VirtAddr) -> Option<FaultResult> {
    with_current_pte_mut(fault_addr, |pte| {
        let flags = pte.flags();
        if !flags.contains(PageFlags::NUMA_HINT) {
            return None;
        }

        let new_flags = flags.clear(PageFlags::NUMA_HINT).set(PageFlags::PRESENT);
        pte.set_flags(new_flags);
        super::higher_half::invalidate_page(fault_addr);

        let frame = FrameIndex::from_phys_addr(pte.phys_addr().as_u64());
        let stats = get_page_numa_stats(frame);
        let node_id = crate::per_cpu::with_current_cold(|cold| cold.get_local_numa_node().as_u8())
            .unwrap_or(0);
        let action = handle_numa_fault(&stats, node_id, crate::time::current_time_ns());
        if let NumaFaultAction::Migrate {
            from_node: _,
            to_node,
        } = action
        {
            MIGRATION_ENGINE.queue_migration(MigrationRequest {
                src_frame: frame,
                dest_node: to_node,
                priority: 5,
                timestamp: crate::time::current_time_ns(),
            });
        }

        Some(FaultResult::Resolved)
    })
    .flatten()
}
