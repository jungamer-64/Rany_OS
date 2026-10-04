//! A code generation closes admission before testing its retained references.
//! Future leases include event waiting and suspended stack frames. CPU dispatch
//! boundaries do not release them; destruction of the Future does.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

const CLOSED: usize = 1 << (usize::BITS - 1);
const COUNT: usize = CLOSED - 1;

#[derive(Debug)]
pub(crate) struct CodeGeneration {
    ownership: AtomicUsize,
    retired_at: AtomicU64,
}

impl CodeGeneration {
    pub(crate) const fn new() -> Self {
        Self {
            ownership: AtomicUsize::new(0),
            retired_at: AtomicU64::new(0),
        }
    }

    pub(crate) fn acquire(self: &Arc<Self>, cell: super::CellId) -> Option<CodeLease> {
        self.ownership
            .try_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                if state & CLOSED == 0 && state & COUNT != COUNT {
                    Some(state + 1)
                } else {
                    None
                }
            })
            .ok()?;
        Some(CodeLease {
            generation: Arc::clone(self),
            cell,
        })
    }

    pub(crate) fn leases(&self) -> usize {
        self.ownership.load(Ordering::Acquire) & COUNT
    }

    /// Failure retains a closed generation and every resource. Existing leases
    /// may finish; no fresh Future or synchronous invocation can acquire it.
    pub(crate) fn close(&self) -> Result<(), usize> {
        let leases = self.ownership.fetch_or(CLOSED, Ordering::AcqRel) & COUNT;
        if leases == 0 { Ok(()) } else { Err(leases) }
    }

    /// The mapped cell owner may begin finalization only with fresh admission
    /// closed and no outstanding reference. This creates the finalizer's source
    /// lease; only that lease can delegate callback work while closure holds.
    pub(super) fn claim_finalization(self: &Arc<Self>, cell: super::CellId) -> Option<CodeLease> {
        self.ownership
            .compare_exchange(CLOSED, CLOSED | 1, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        Some(CodeLease {
            generation: Arc::clone(self),
            cell,
        })
    }

    /// Retirement follows dispatch publication; rollback may restore this
    /// generation while it still owns its mappings and has not been closed.
    pub(crate) fn retire(&self, epoch: u64) {
        self.retired_at.store(epoch, Ordering::Release);
    }

    pub(crate) fn restore(&self) {
        self.retired_at.store(0, Ordering::Release);
    }

    pub(crate) fn quiescent_before(&self, epoch: u64) -> bool {
        let retired = self.retired_at.load(Ordering::Acquire);
        retired == 0 || retired > epoch || self.leases() == 0
    }
}

#[derive(Debug)]
pub(crate) struct CodeLease {
    generation: Arc<CodeGeneration>,
    cell: super::CellId,
}

impl CodeLease {
    /// A registered owner may finish a callback after fresh admission closes.
    /// The source lease keeps the generation mapped during this acquisition.
    pub(crate) fn retain(&self) -> Option<Self> {
        self.generation
            .ownership
            .try_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                let count = state & COUNT;
                if count == 0 || count == COUNT {
                    None
                } else {
                    Some(state + 1)
                }
            })
            .ok()?;
        Some(Self {
            generation: Arc::clone(&self.generation),
            cell: self.cell,
        })
    }

    pub(crate) fn cell(&self) -> super::CellId {
        self.cell
    }
}

impl Drop for CodeLease {
    fn drop(&mut self) {
        let previous = self.generation.ownership.fetch_sub(1, Ordering::AcqRel);
        assert_ne!(previous & COUNT, 0, "code lease released twice");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn module_finalization_waits_for_ordinary_and_deferred_code() {
        let generation = Arc::new(CodeGeneration::new());
        let cell = super::super::CellId::from_u64(4);
        assert!(generation.claim_finalization(cell).is_none());
        let waiting_future = generation.acquire(cell).unwrap();
        generation.retire(8);
        assert_eq!(generation.close(), Err(1));
        assert!(generation.claim_finalization(cell).is_none());
        drop(waiting_future);

        let finalizer = generation.claim_finalization(cell).unwrap();
        assert!(generation.acquire(cell).is_none());
        assert!(generation.claim_finalization(cell).is_none());
        let deferred = finalizer.retain().unwrap();
        drop(finalizer);
        assert_eq!(generation.close(), Err(1));
        assert!(!generation.quiescent_before(8));
        drop(deferred);
        assert_eq!(generation.close(), Ok(()));
        assert!(generation.quiescent_before(8));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn retained_callback_can_finish_after_fresh_admission_closes() {
        let generation = Arc::new(CodeGeneration::new());
        let registered = generation
            .acquire(super::super::CellId::from_u64(3))
            .unwrap();
        generation.retire(7);
        assert_eq!(generation.close(), Err(1));
        let finalizer = registered.retain().expect("registered code remains mapped");
        assert!(
            generation
                .acquire(super::super::CellId::from_u64(3))
                .is_none()
        );
        drop(registered);
        assert_eq!(generation.close(), Err(1));
        assert!(!generation.quiescent_before(7));
        drop(finalizer);
        assert_eq!(generation.close(), Ok(()));
        assert!(generation.quiescent_before(7));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn closed_generation_retains_existing_leases_and_denies_new_entries() {
        let generation = Arc::new(CodeGeneration::new());
        let retained = generation
            .acquire(super::super::CellId::from_u64(1))
            .unwrap();
        assert_eq!(generation.close(), Err(1));
        assert!(
            generation
                .acquire(super::super::CellId::from_u64(1))
                .is_none()
        );
        drop(retained);
        assert_eq!(generation.close(), Ok(()));
        assert!(
            generation
                .acquire(super::super::CellId::from_u64(1))
                .is_none()
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn retirement_waits_for_the_old_generation_without_blocking_the_new_one() {
        let old = Arc::new(CodeGeneration::new());
        let current = Arc::new(CodeGeneration::new());
        let suspended = old.acquire(super::super::CellId::from_u64(1)).unwrap();
        let _new_future = current.acquire(super::super::CellId::from_u64(2)).unwrap();
        old.retire(3);
        assert!(!old.quiescent_before(3));
        assert!(current.quiescent_before(3));
        old.restore();
        assert!(old.quiescent_before(3));
        old.retire(4);
        drop(suspended);
        assert!(old.quiescent_before(4));
    }
}
