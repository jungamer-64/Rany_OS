//! Sparse-topology TLB shootdown.
//!
//! Remote CPUs receive a monotonically increasing generation through their
//! CPU-local atomic mailbox. Remote invalidation intentionally flushes the
//! complete local TLB: this makes concurrent requests naturally coalesce and
//! avoids a global payload lock in interrupt context.

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

use x86_64::VirtAddr;

use crate::cpu::{CpuId, CpuSet, CurrentCpu};

/// Local APIC vector used for TLB shootdowns.
pub(crate) const TLB_FLUSH_VECTOR: u8 = 241;

const SHOOTDOWN_SPIN_LIMIT: usize = 100_000_000;

static NEXT_SHOOTDOWN_GENERATION: AtomicU64 = AtomicU64::new(0);
static LOCAL_PAGE_FLUSHES: AtomicU64 = AtomicU64::new(0);
static LOCAL_FULL_FLUSHES: AtomicU64 = AtomicU64::new(0);
static REMOTE_SHOOTDOWNS: AtomicU64 = AtomicU64::new(0);

fn remote_targets<'a>(online: &'a CpuSet, current: CpuId) -> impl Iterator<Item = CpuId> + 'a {
    online.iter().filter(move |candidate| *candidate != current)
}

fn next_generation() -> u64 {
    NEXT_SHOOTDOWN_GENERATION
        .try_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
            current.checked_add(1)
        })
        .unwrap_or_else(|_| panic!("TLB shootdown generation exhausted"))
        + 1
}

fn current_cpu() -> CurrentCpu {
    CurrentCpu::acquire()
        .unwrap_or_else(|| panic!("TLB operation executed without CPU-local state"))
}

fn service_pending_on_current(current: &CurrentCpu) -> bool {
    let Some(generation) = current.pending_tlb_generation() else {
        return false;
    };

    unsafe { flush_all_local() };
    current.complete_tlb_generation(generation);
    true
}

fn request_remote_shootdown(current: &CurrentCpu) {
    let topology = crate::cpu::snapshot();
    if remote_targets(topology.online(), current.id())
        .next()
        .is_none()
    {
        return;
    }

    let generation = next_generation();
    let runtime = crate::cpu::runtime();

    for target in remote_targets(topology.online(), current.id()) {
        let local = runtime
            .cpu_local(target)
            .unwrap_or_else(|| panic!("online CPU {} has no CPU-local TLB mailbox", target));
        local.remote().request_tlb_generation(generation);
    }

    for target in remote_targets(topology.online(), current.id()) {
        let local = runtime
            .cpu_local(target)
            .unwrap_or_else(|| panic!("online CPU {} lost its CPU-local TLB mailbox", target));
        if local.remote().tlb_is_lazy() {
            continue;
        }
        crate::cpu::send_ipi(target, crate::cpu::IpiKind::TlbFlush).unwrap_or_else(|error| {
            panic!(
                "failed to send TLB shootdown generation {} to CPU {}: {:?}",
                generation, target, error
            )
        });
        REMOTE_SHOOTDOWNS.fetch_add(1, Ordering::Relaxed);
    }

    for target in remote_targets(topology.online(), current.id()) {
        let local = runtime
            .cpu_local(target)
            .unwrap_or_else(|| panic!("online CPU {} lost its CPU-local TLB mailbox", target));
        let mut spins = 0usize;
        while local.remote().observed_tlb_generation() < generation {
            // Two CPUs may initiate a shootdown while local interrupts are
            // disabled. Servicing our own mailbox here prevents a cyclic wait.
            service_pending_on_current(current);
            core::hint::spin_loop();
            spins = spins.saturating_add(1);
            assert!(
                spins <= SHOOTDOWN_SPIN_LIMIT,
                "TLB shootdown generation {} timed out waiting for CPU {} (observed={})",
                generation,
                target,
                local.remote().observed_tlb_generation()
            );
        }
    }
}

/// Invalidates one page locally and synchronously invalidates every other
/// online CPU.
///
/// # Panics
/// Panics on a CPU-local/topology invariant violation, generation exhaustion,
/// IPI delivery failure, or shootdown timeout. Continuing after any of these
/// failures could expose freed mappings through a stale TLB entry.
#[track_caller]
pub(crate) fn flush_immediate(address: VirtAddr) {
    let current = current_cpu();
    unsafe { flush_page_local(address) };
    request_remote_shootdown(&current);
}

/// Invalidates all non-global TLB entries locally and synchronously invalidates
/// every other online CPU.
///
/// # Panics
/// Panics on a CPU-local/topology invariant violation, generation exhaustion,
/// IPI delivery failure, or shootdown timeout. Continuing after any of these
/// failures could expose freed mappings through a stale TLB entry.
#[track_caller]
pub(crate) fn flush_all() {
    let current = current_cpu();
    unsafe { flush_all_local() };
    request_remote_shootdown(&current);
}

/// Processes the current CPU's TLB generation mailbox from the TLB IPI.
///
/// # Safety
/// Must run on a CPU with installed CPU-local state from the dedicated TLB IPI
/// handler or an equivalent interrupts-excluded control path.
pub(crate) unsafe fn handle_shootdown_ipi() {
    let current = current_cpu();
    service_pending_on_current(&current);
}

pub(crate) fn enter_lazy_mode() {
    current_cpu().enter_lazy_tlb();
}

pub(crate) fn exit_lazy_mode() -> bool {
    let current = current_cpu();
    let Some(generation) = current.activate_tlb() else {
        return false;
    };
    unsafe { flush_all_local() };
    current.complete_tlb_generation(generation);
    true
}

#[inline]
unsafe fn flush_page_local(address: VirtAddr) {
    unsafe {
        asm!(
            "invlpg [{}]",
            in(reg) address.as_u64(),
            options(nostack, preserves_flags)
        );
    }
    LOCAL_PAGE_FLUSHES.fetch_add(1, Ordering::Relaxed);
}

#[inline]
unsafe fn flush_all_local() {
    let cr3: u64;
    unsafe {
        asm!(
            "mov {}, cr3",
            out(reg) cr3,
            options(nomem, nostack, preserves_flags)
        );
        asm!(
            "mov cr3, {}",
            in(reg) cr3,
            options(nostack, preserves_flags)
        );
    }
    LOCAL_FULL_FLUSHES.fetch_add(1, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpu(value: usize) -> CpuId {
        CpuId::try_from(value).unwrap()
    }

    #[test]
    fn sparse_shootdown_targets_only_actual_remote_members() {
        let online = CpuSet::from_ids(8, [cpu(0), cpu(2), cpu(7)]).unwrap();
        assert_eq!(
            remote_targets(&online, cpu(2)).collect::<alloc::vec::Vec<_>>(),
            [cpu(0), cpu(7)]
        );
    }
}
