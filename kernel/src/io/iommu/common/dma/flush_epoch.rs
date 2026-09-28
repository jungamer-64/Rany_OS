//! Retirement ordering for allocator-wide translation invalidation.
//! Hardware authority belongs to the allocator's pending flush, not this clock.
#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicU32, Ordering};

/// The signed comparisons used by quarantine rings are unambiguous in this range.
const LAST_RETIREMENT_EPOCH: u32 = i32::MAX as u32;

#[derive(Debug)]
pub(super) struct FlushBoundary(u32);

#[derive(Debug)]
pub(super) struct RetirementClock {
    current: AtomicU32,
    completed: AtomicU32,
}

impl RetirementClock {
    pub(super) const fn new() -> Self {
        Self {
            current: AtomicU32::new(0),
            completed: AtomicU32::new(0),
        }
    }

    pub(super) fn retirement_epoch(&self) -> u32 {
        self.current.load(Ordering::Acquire)
    }

    /// Begin before submitting the global invalidation. Exhaustion leaves state intact.
    pub(super) fn begin(&self) -> Option<FlushBoundary> {
        self.current
            .try_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                epoch
                    .checked_add(1)
                    .filter(|next| *next <= LAST_RETIREMENT_EPOCH)
            })
            .ok()
            .map(FlushBoundary)
    }

    /// Publish observed coverage. The enclosing allocator supplies hardware proof.
    pub(super) fn confirm(&self, boundary: FlushBoundary) -> u32 {
        self.completed.fetch_max(boundary.0, Ordering::AcqRel);
        self.completed.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retirement_after_submission_is_outside_the_captured_boundary() {
        let clock = RetirementClock::new();
        let Some(flush) = clock.begin() else {
            panic!("initial epoch must be available")
        };
        let retired_after_begin = clock.retirement_epoch();
        assert!(clock.confirm(flush) < retired_after_begin);
    }

    #[test]
    fn cancellation_does_not_publish_completion() {
        let clock = RetirementClock::new();
        {
            let Some(_first) = clock.begin() else {
                panic!("first epoch must be available")
            };
            let Some(_second) = clock.begin() else {
                panic!("second epoch must be available")
            };
        }
        assert_eq!(clock.completed.load(Ordering::Acquire), 0);
        assert_eq!(clock.retirement_epoch(), 2);
    }

    #[test]
    fn out_of_order_global_completions_do_not_regress_coverage() {
        let clock = RetirementClock::new();
        let Some(first) = clock.begin() else {
            panic!("first epoch must be available")
        };
        let Some(second) = clock.begin() else {
            panic!("second epoch must be available")
        };
        assert_eq!(clock.confirm(second), 1);
        assert_eq!(clock.confirm(first), 1);
    }

    #[test]
    fn exhaustion_cannot_wrap_or_cross_the_signed_comparison_range() {
        let clock = RetirementClock {
            current: AtomicU32::new(LAST_RETIREMENT_EPOCH - 1),
            completed: AtomicU32::new(0),
        };
        assert!(clock.begin().is_some());
        assert!(clock.begin().is_none());
        assert_eq!(clock.retirement_epoch(), LAST_RETIREMENT_EPOCH);
    }
}
