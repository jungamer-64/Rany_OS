//! Per-task wake coalescing with identity-bound, allocation-free wakers.

use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{RawWaker, RawWakerVTable, Waker};
use kernel_api::resource::task::{SpawnError, TaskId};

use super::config::SCHEDULER_CONFIG;

const PENDING: u64 = 1;
const ACTIVE: u64 = 2;
const STATE_ID_SHIFT: u32 = 2;
const SLOT_BITS: u32 = SCHEDULER_CONFIG.max_tasks.next_power_of_two().ilog2();
const SLOT_MASK: usize = (1 << SLOT_BITS) - 1;
const MAX_TASK_ID: u64 = {
    let pointer_limit = (usize::MAX >> SLOT_BITS) as u64;
    let state_limit = u64::MAX >> STATE_ID_SHIFT;
    if pointer_limit < state_limit {
        pointer_limit
    } else {
        state_limit
    }
};

/// Reservation consumes one identity from the runtime's last-issued counter.
/// The private representation fits both the notification state and its opaque
/// pointer token. Dropping a reservation never permits identity reuse.
pub(super) struct AssignedTaskId(NonZeroU64);

impl AssignedTaskId {
    pub(super) fn reserve(last_issued: &AtomicU64) -> Result<Self, SpawnError> {
        // LOOP_PROOF: mode=event; reason=Each CAS retry observes the competing identity reservation, and exhaustion rejects without changing the counter.;
        loop {
            let previous = last_issued.load(Ordering::Relaxed);
            let identity = NonZeroU64::MIN
                .checked_add(previous)
                .filter(|identity| identity.get() <= MAX_TASK_ID)
                .ok_or(SpawnError::TaskIdentityExhausted)?;
            if last_issued
                .compare_exchange(
                    previous,
                    identity.get(),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return Ok(Self(identity));
            }
        }
    }

    pub(super) fn observed(&self) -> TaskId {
        TaskId::from_raw(self.0.get())
    }
}

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
    identity: AssignedTaskId,
}

impl WakeLease {
    pub(super) fn activate(slot: usize, identity: AssignedTaskId) -> Self {
        assert!(slot < SCHEDULER_CONFIG.max_tasks);
        let state = &WAKE_SLOTS[slot].0;
        assert!(
            state.load(Ordering::Acquire) & ACTIVE == 0,
            "wake slot activated twice"
        );
        // Stack arena ownership serializes activation. Inactive notifications
        // cannot mutate this slot, and stale task identities cannot match it.
        state.store(
            (identity.0.get() << STATE_ID_SHIFT) | ACTIVE,
            Ordering::Release,
        );
        Self { slot, identity }
    }

    pub(super) fn waker(&self) -> Waker {
        let token = ((self.identity.0.get() as usize) << SLOT_BITS) | self.slot;
        let raw = RawWaker::new(token as *const (), &VTABLE);
        // SAFETY: clone and drop never dereference the token; wake validates
        // task identity and active ownership against the static slot array.
        unsafe { Waker::from_raw(raw) }
    }

    pub(super) fn take_pending(&self) -> bool {
        let state = &WAKE_SLOTS[self.slot].0;
        // LOOP_PROOF: mode=event; reason=CAS retries until ownership changes or the atomic wake transition commits.;
        loop {
            let previous = state.load(Ordering::Acquire);
            if previous >> STATE_ID_SHIFT != self.identity.0.get()
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
        state >> STATE_ID_SHIFT == self.identity.0.get()
            && state & (ACTIVE | PENDING) == (ACTIVE | PENDING)
    }
}

impl Drop for WakeLease {
    fn drop(&mut self) {
        let state = &WAKE_SLOTS[self.slot].0;
        let previous = state.swap(self.identity.0.get() << STATE_ID_SHIFT, Ordering::AcqRel);
        assert_eq!(previous >> STATE_ID_SHIFT, self.identity.0.get());
        assert!(previous & ACTIVE != 0, "wake lease retired twice");
    }
}

pub(super) fn wake_revision() -> u64 {
    WAKE_REVISION.load(Ordering::Acquire)
}

fn wake_token(token: usize) {
    let slot = token & SLOT_MASK;
    let identity = (token >> SLOT_BITS) as u64;
    let Some(state) = WAKE_SLOTS.get(slot).map(|slot| &slot.0) else {
        return;
    };
    // LOOP_PROOF: mode=event; reason=CAS retries until ownership changes or the atomic wake transition commits.;
    loop {
        let previous = state.load(Ordering::Acquire);
        if previous >> STATE_ID_SHIFT != identity
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
    use super::{AssignedTaskId, MAX_TASK_ID, WakeLease};
    use core::sync::atomic::{AtomicU64, Ordering};
    use kernel_api::resource::task::SpawnError;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn repeated_wakes_merge_until_consumed() {
        let identities = AtomicU64::new(0);
        let lease = WakeLease::activate(254, AssignedTaskId::reserve(&identities).unwrap());
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
        let identities = AtomicU64::new(0);
        let old = WakeLease::activate(255, AssignedTaskId::reserve(&identities).unwrap());
        let stale = old.waker();
        drop(old);
        let replacement = WakeLease::activate(255, AssignedTaskId::reserve(&identities).unwrap());
        stale.wake_by_ref();
        assert!(!replacement.take_pending());
        replacement.waker().wake_by_ref();
        assert!(replacement.take_pending());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn final_identity_round_trips_and_exhaustion_preserves_the_counter() {
        let identities = AtomicU64::new(MAX_TASK_ID - 1);
        let identity = AssignedTaskId::reserve(&identities).unwrap();
        assert_eq!(identity.observed().as_u64(), MAX_TASK_ID);
        let lease = WakeLease::activate(253, identity);
        let waker = lease.waker();
        waker.wake_by_ref();
        assert!(lease.take_pending());
        assert!(matches!(
            AssignedTaskId::reserve(&identities),
            Err(SpawnError::TaskIdentityExhausted)
        ));
        assert_eq!(identities.load(Ordering::Relaxed), MAX_TASK_ID);
        assert!(!lease.take_pending());
    }
}
