//! Per-task wake coalescing with generation-bound, allocation-free wakers.

use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{RawWaker, RawWakerVTable, Waker};

use super::config::SCHEDULER_CONFIG;

const PENDING: u64 = 1;
const ACTIVE: u64 = 2;
const GENERATION_SHIFT: u32 = 2;
const SLOT_BITS: u32 = SCHEDULER_CONFIG.max_tasks.next_power_of_two().ilog2();
const SLOT_MASK: usize = (1 << SLOT_BITS) - 1;
const MAX_GENERATION: u64 = {
    let pointer_limit = (usize::MAX >> SLOT_BITS) as u64;
    let state_limit = u64::MAX >> GENERATION_SHIFT;
    if pointer_limit < state_limit {
        pointer_limit
    } else {
        state_limit
    }
};

struct WakeSlot(AtomicU64);

impl WakeSlot {
    const fn new() -> Self {
        Self(AtomicU64::new(0))
    }
}

static WAKE_SLOTS: [WakeSlot; SCHEDULER_CONFIG.max_tasks] =
    [const { WakeSlot::new() }; SCHEDULER_CONFIG.max_tasks];
static WAKE_REVISION: AtomicU64 = AtomicU64::new(0);

/// Owned by exactly one published task record. Dropping it invalidates every
/// previously cloned waker before the stack arena slot can be reused.
pub(super) struct WakeLease {
    slot: usize,
    generation: u64,
}

impl WakeLease {
    pub(super) fn waker(&self) -> Waker {
        let token = ((self.generation as usize) << SLOT_BITS) | self.slot;
        let raw = RawWaker::new(token as *const (), &VTABLE);
        // SAFETY: clone and drop never dereference the token; wake validates
        // generation and active ownership against the static slot array.
        unsafe { Waker::from_raw(raw) }
    }

    pub(super) fn take_pending(&self) -> bool {
        let state = &WAKE_SLOTS[self.slot].0;
        // LOOP_PROOF: mode=event; reason=CAS retries until ownership changes or the atomic wake transition commits.;
        loop {
            let previous = state.load(Ordering::Acquire);
            if previous >> GENERATION_SHIFT != self.generation
                || previous & ACTIVE == 0
                || previous & PENDING == 0
            {
                return false;
            }
            if state
                .compare_exchange(
                    previous,
                    previous & !PENDING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return true;
            }
        }
    }

    pub(super) fn is_pending(&self) -> bool {
        let state = WAKE_SLOTS[self.slot].0.load(Ordering::Acquire);
        state >> GENERATION_SHIFT == self.generation
            && state & (ACTIVE | PENDING) == (ACTIVE | PENDING)
    }
}

impl Drop for WakeLease {
    fn drop(&mut self) {
        let state = &WAKE_SLOTS[self.slot].0;
        let previous = state.swap(self.generation << GENERATION_SHIFT, Ordering::AcqRel);
        assert_eq!(previous >> GENERATION_SHIFT, self.generation);
        assert!(previous & ACTIVE != 0, "wake lease retired twice");
    }
}

pub(super) fn wake_revision() -> u64 {
    WAKE_REVISION.load(Ordering::Acquire)
}

fn wake_token(token: usize) {
    let slot = token & SLOT_MASK;
    let generation = (token >> SLOT_BITS) as u64;
    let Some(state) = WAKE_SLOTS.get(slot).map(|slot| &slot.0) else {
        return;
    };
    // LOOP_PROOF: mode=event; reason=CAS retries until ownership changes or the atomic wake transition commits.;
    loop {
        let previous = state.load(Ordering::Acquire);
        if previous >> GENERATION_SHIFT != generation
            || previous & ACTIVE == 0
            || previous & PENDING != 0
        {
            return;
        }
        if state
            .compare_exchange(
                previous,
                previous | PENDING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            WAKE_REVISION.fetch_add(1, Ordering::Release);
            return;
        }
    }
}

unsafe fn clone_waker(data: *const ()) -> RawWaker {
    RawWaker::new(data, &VTABLE)
}

unsafe fn wake(data: *const ()) {
    wake_token(data as usize);
}

unsafe fn wake_by_ref(data: *const ()) {
    wake_token(data as usize);
}

unsafe fn drop_waker(_data: *const ()) {}

static VTABLE: RawWakerVTable = RawWakerVTable::new(clone_waker, wake, wake_by_ref, drop_waker);

#[cfg(test)]
mod tests {
    use super::WakeLease;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn repeated_wakes_merge_until_consumed() {
        let lease = WakeLease::activate(254);
        let waker = lease.waker();
        waker.wake_by_ref();
        waker.wake_by_ref();
        assert!(lease.take_pending());
        assert!(!lease.take_pending());
        waker.wake_by_ref();
        assert!(lease.take_pending());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn retired_waker_cannot_wake_reused_slot() {
        let old = WakeLease::activate(255);
        let stale = old.waker();
        drop(old);
        let replacement = WakeLease::activate(255);
        stale.wake_by_ref();
        assert!(!replacement.take_pending());
        replacement.waker().wake_by_ref();
        assert!(replacement.take_pending());
    }
}
