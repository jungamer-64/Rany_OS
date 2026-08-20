//! Sparse-topology TLB shootdown.
//!
//! Remote CPUs receive a monotonically increasing generation through their
//! CPU-local atomic mailbox. Remote invalidation intentionally flushes the
//! complete local TLB: this makes concurrent requests naturally coalesce and
//! avoids a global payload lock in interrupt context.

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

use x86_64::VirtAddr;

use crate::cpu::{CpuId, CpuSnapshot, CurrentCpu};

/// Local APIC vector used for TLB shootdowns.
pub(crate) const TLB_FLUSH_VECTOR: u8 = 241;

const SHOOTDOWN_SPIN_LIMIT: usize = 100_000_000;

static NEXT_SHOOTDOWN_GENERATION: AtomicU64 = AtomicU64::new(0);
static LOCAL_PAGE_FLUSHES: AtomicU64 = AtomicU64::new(0);
static LOCAL_FULL_FLUSHES: AtomicU64 = AtomicU64::new(0);
static REMOTE_SHOOTDOWNS: AtomicU64 = AtomicU64::new(0);

fn remote_targets(topology: &CpuSnapshot, current: CpuId) -> impl Iterator<Item = CpuId> + '_ {
    topology
        .slots()
        .iter()
        .filter(move |slot| slot.id != current && slot.state.participates_in_tlb())
        .map(|slot| slot.id)
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
    if remote_targets(&topology, current.id()).next().is_none() {
        return;
    }

    let generation = next_generation();
    let runtime = crate::cpu::runtime();

    for target in remote_targets(&topology, current.id()) {
        let local = runtime
            .cpu_local(target)
            .unwrap_or_else(|| panic!("coherent CPU {} has no CPU-local TLB mailbox", target));
        local.remote().request_tlb_generation(generation);
    }

    for target in remote_targets(&topology, current.id()) {
        let local = runtime
            .cpu_local(target)
            .unwrap_or_else(|| panic!("coherent CPU {} lost its CPU-local TLB mailbox", target));
        if local.remote().tlb_is_lazy() {
            continue;
        }
        match crate::cpu::send_ipi(target, crate::cpu::IpiKind::TlbFlush) {
            Ok(()) => {}
            Err(crate::cpu::CpuIpiError::CpuStateIneligible { .. })
                if local.remote().tlb_is_lazy() =>
            {
                continue;
            }
            Err(error) => {
                panic!(
                    "failed to send TLB shootdown generation {} to CPU {}: {:?}",
                    generation, target, error
                );
            }
        }
        REMOTE_SHOOTDOWNS.fetch_add(1, Ordering::Relaxed);
    }

    for target in remote_targets(&topology, current.id()) {
        let local = runtime
            .cpu_local(target)
            .unwrap_or_else(|| panic!("coherent CPU {} lost its CPU-local TLB mailbox", target));
        let mut spins = 0usize;
        while local.remote().observed_tlb_generation() < generation {
            if local.remote().tlb_is_lazy() {
                break;
            }
            let current_state = crate::cpu::snapshot().slot(target).map(|slot| slot.state);
            assert!(
                current_state.is_some_and(crate::cpu::CpuSlotState::participates_in_tlb),
                "CPU {} left TLB participation without entering lazy mode",
                target
            );
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
    fn sparse_shootdown_includes_starting_and_draining_cpus() {
        let runtime = crate::cpu::CpuRuntime::bootstrap(crate::cpu::ApicId::new(0), None).unwrap();
        let firmware = |uid, apic| crate::cpu::FirmwareCpuIdentity {
            uid: Some(crate::cpu::FirmwareCpuUid::Integer(uid)),
            apic_id: crate::cpu::ApicId::new(apic),
            proximity_domain: Some(0),
            eject: crate::cpu::CpuEjectCapability::FirmwareEject,
        };
        let cpu1 = runtime.discover_present(firmware(1, 1)).unwrap();
        let cpu2 = runtime.discover_present(firmware(2, 2)).unwrap();
        let cpu3 = runtime.discover_present(firmware(3, 3)).unwrap();
        runtime.begin_start(cpu1).unwrap();
        runtime.begin_start(cpu2).unwrap();
        runtime.startup_ready(cpu2).unwrap();
        runtime.begin_start(cpu3).unwrap();
        runtime.startup_ready(cpu3).unwrap();
        runtime.begin_drain(cpu3).unwrap();

        let topology = runtime.snapshot();
        assert_eq!(
            remote_targets(&topology, cpu(2)).collect::<alloc::vec::Vec<_>>(),
            [cpu(0), cpu(1), cpu(3)]
        );
    }
}
