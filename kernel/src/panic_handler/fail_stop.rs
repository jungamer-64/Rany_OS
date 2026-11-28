use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::cpu::{CpuId, CurrentCpu, MAX_POSSIBLE_CPUS};
use crate::drivers::apic::{self, ApicDestination, LocalApic};

const UNBOUND_OWNER: usize = MAX_POSSIBLE_CPUS;
const NO_OWNER: usize = UNBOUND_OWNER + 1;
static OWNER: AtomicUsize = AtomicUsize::new(NO_OWNER);

// An admitted CPU has loaded the kernel NMI gate and enabled its local APIC.
// A CPU may acknowledge only after surrendering all normal execution.
const ABSENT: u64 = 0;
const STOPPED: u64 = 1;
const APIC_ID_OFFSET: u64 = 2;
static ENDPOINTS: [AtomicU64; MAX_POSSIBLE_CPUS] =
    [const { AtomicU64::new(ABSENT) }; MAX_POSSIBLE_CPUS];

fn index(id: CpuId) -> usize {
    usize::from(id.as_u16())
}

fn current_index() -> usize {
    CurrentCpu::acquire().map_or(UNBOUND_OWNER, |cpu| index(cpu.id()))
}

pub(super) struct FatalOwner {
    index: usize,
}

impl FatalOwner {
    pub(super) fn claim() -> Self {
        let index = current_index();
        match OWNER.compare_exchange(NO_OWNER, index, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => Self { index },
            Err(_) => acknowledge_and_halt(index),
        }
    }

    pub(super) fn stop_peers(self) -> StopOutcome {
        let mut targeted = [false; MAX_POSSIBLE_CPUS];
        let mut delivery_errors = 0;
        // A fault can occur in an AP before its local APIC mode is initialized.
        // Only a published endpoint proves that this CPU can access that backend.
        let sender = if ENDPOINTS
            .get(self.index)
            .is_some_and(|endpoint| endpoint.load(Ordering::Relaxed) >= APIC_ID_OFFSET)
        {
            apic::local_apic().ok()
        } else {
            None
        };
        for (index, endpoint) in ENDPOINTS.iter().enumerate() {
            if index == self.index {
                continue;
            }
            let address = endpoint.load(Ordering::SeqCst);
            if address < APIC_ID_OFFSET {
                continue;
            }
            targeted[index] = true;
            let destination = ApicDestination::new((address - APIC_ID_OFFSET) as u32);
            if !sender.is_some_and(|apic| apic.send_nmi(destination).is_ok()) {
                delivery_errors += 1;
            }
        }

        let targets = targeted.iter().filter(|&&target| target).count();
        let pending = || {
            targeted
                .iter()
                .zip(&ENDPOINTS)
                .filter(|(target, endpoint)| {
                    **target && endpoint.load(Ordering::Acquire) >= APIC_ID_OFFSET
                })
                .count()
        };
        // Acknowledgements cannot depend on kernel timers, the scheduler or
        // any lock a stopped CPU may retain.
        for _ in 0..65_536 {
            if pending() == 0 {
                break;
            }
            core::hint::spin_loop();
        }
        StopOutcome {
            targets,
            unconfirmed: pending(),
            delivery_errors,
        }
    }
}

pub(crate) struct QuiescedPeers(());

pub(super) struct StopOutcome {
    pub(super) targets: usize,
    pub(super) unconfirmed: usize,
    pub(super) delivery_errors: usize,
}

/// Publishes the endpoint after the CPU has loaded its NMI gate and enabled its
/// local APIC. This precedes admission to ordinary execution, even with IF clear.
pub(crate) fn admit_current_cpu(apic: &LocalApic) {
    let current = CurrentCpu::acquire().expect("NMI admission requires a bound CPU");
    let index = index(current.id());
    let endpoint = &ENDPOINTS[index];
    if endpoint.load(Ordering::Relaxed) == ABSENT {
        endpoint.store(u64::from(apic.id()) + APIC_ID_OFFSET, Ordering::SeqCst);
    }

    // The SeqCst order closes the race with the owner's first scan. An
    // endpoint missed by that scan cannot leave admission to run normal work.
    if OWNER.load(Ordering::SeqCst) != NO_OWNER {
        acknowledge_and_halt(index);
    }
}

pub(crate) fn stop_if_fatal_requested() {
    if OWNER.load(Ordering::Acquire) != NO_OWNER {
        stop_current_cpu();
    }
}

pub(crate) fn remove_ejected_cpu(id: CpuId) {
    ENDPOINTS[index(id)].store(ABSENT, Ordering::Release);
}

pub(crate) fn on_nmi() {
    let owner = OWNER.load(Ordering::Acquire);
    if owner != NO_OWNER {
        let index = current_index();
        if index != owner {
            acknowledge_and_halt(index);
        }
    }
}

pub(crate) fn stop_current_cpu() -> ! {
    acknowledge_and_halt(current_index())
}

fn acknowledge_and_halt(index: usize) -> ! {
    x86_64::instructions::interrupts::disable();
    if let Some(endpoint) = ENDPOINTS.get(index) {
        endpoint.store(STOPPED, Ordering::Release);
    }
    // LOOP_PROOF: mode=halt; reason=The acknowledging CPU has permanently surrendered normal execution.;
    loop {
        x86_64::instructions::hlt();
    }
}

impl StopOutcome {
    pub(super) fn into_quiesced(self) -> Option<QuiescedPeers> {
        (self.unconfirmed == 0).then_some(QuiescedPeers(()))
    }
}
