//! Stable quota return targets. Registry ownership plus binding/charged-byte
//! pins protects each account's address. Heap credits add no reference-count
//! operation: their nonzero byte reservation itself pins the account.
use super::{DomainId, QuotaError};
use core::num::NonZeroU64;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Debug)]
pub(super) struct MemoryAccount {
    domain: DomainId,
    open: AtomicBool,
    limit: AtomicU64,
    used: AtomicU64,
    bindings: AtomicU64,
}

impl MemoryAccount {
    pub(super) fn new(domain: DomainId, limit: u64) -> Self {
        Self {
            domain,
            open: AtomicBool::new(true),
            limit: AtomicU64::new(limit),
            used: AtomicU64::new(0),
            bindings: AtomicU64::new(0),
        }
    }

    pub(super) fn is_open(&self) -> bool {
        self.open.load(Ordering::Acquire)
    }

    pub(super) fn close(&self) {
        self.open.store(false, Ordering::Release);
    }

    pub(super) fn limit(&self) -> u64 {
        self.limit.load(Ordering::Relaxed)
    }

    pub(super) fn set_limit(&self, limit: u64) {
        self.limit.store(limit, Ordering::Relaxed);
    }

    pub(super) fn used(&self) -> u64 {
        self.used.load(Ordering::Acquire)
    }

    pub(super) fn can_reclaim(&self) -> bool {
        // Reclamation runs under the registry lock after admission closes.
        // Acquiring the final binding release observes every prior reservation;
        // acquiring the final credit release observes the last return.
        self.bindings.load(Ordering::Acquire) == 0 && self.used() == 0
    }

    pub(super) fn bind(&self) -> Result<MemoryBinding, QuotaError> {
        // Registry serialization prevents close/removal while establishing the
        // first pin. There is no public constructor from an observed address.
        self.bindings
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                count.checked_add(1)
            })
            .map_err(|_| QuotaError::AccountingOverflow)?;
        Ok(MemoryBinding {
            account: Some(NonNull::from(self)),
        })
    }
}

/// An execution binding keeps its account stable across CPU-local entry/exit.
/// Kernel execution is explicitly uncharged. Bindings cannot be duplicated.
#[derive(Debug)]
pub(crate) struct MemoryBinding {
    account: Option<NonNull<MemoryAccount>>,
}

// SAFETY: bindings pin an immutable-address account. All mutable account fields
// are atomic; transfer moves one pin and its sole release obligation.
unsafe impl Send for MemoryBinding {}
// SAFETY: shared access can only atomically reserve bytes; binding release needs
// exclusive ownership, and the registry cannot reclaim its pinned account.
unsafe impl Sync for MemoryBinding {}

impl MemoryBinding {
    pub(crate) const fn kernel() -> Self {
        Self { account: None }
    }

    /// Reserve nonzero payload bytes. Contention is bounded and classified;
    /// overflow is never treated as successful unlimited-quota admission.
    pub(crate) fn reserve(&self, bytes: u64) -> Result<Option<MemoryCredit>, QuotaError> {
        let Some(pointer) = self.account else {
            return Ok(None);
        };
        let bytes = NonZeroU64::new(bytes).ok_or(QuotaError::InvalidSize)?;
        // SAFETY: this binding pins backing independently of its charged bytes.
        let account = unsafe { pointer.as_ref() };
        if !account.is_open() {
            return Err(QuotaError::Retired {
                domain_id: account.domain,
            });
        }
        let current = account.used.load(Ordering::Relaxed);
        let total = current
            .checked_add(bytes.get())
            .ok_or(QuotaError::AccountingOverflow)?;
        let limit = account.limit();
        if total > limit {
            return Err(QuotaError::MemoryExceeded {
                requested: bytes.get(),
                available: limit.saturating_sub(current),
                limit,
            });
        }
        // Usage is an admission counter, not a publication of payload memory.
        account
            .used
            .compare_exchange(current, total, Ordering::Relaxed, Ordering::Relaxed)
            .map_err(|_| QuotaError::AllocationRace)?;
        let credit = MemoryCredit {
            account: pointer,
            bytes,
        };
        // A policy decrease or retirement racing this reservation rolls back
        // before any allocation becomes visible. An in-flight admission that
        // observes the old policy may complete before a later policy update.
        if !account.is_open() {
            return Err(QuotaError::Retired {
                domain_id: account.domain,
            });
        }
        let limit = account.limit();
        if account.used() > limit {
            return Err(QuotaError::MemoryExceeded {
                requested: bytes.get(),
                available: limit.saturating_sub(current),
                limit,
            });
        }
        Ok(Some(credit))
    }
}

impl Drop for MemoryBinding {
    fn drop(&mut self) {
        if let Some(pointer) = self.account {
            // SAFETY: our pin protects this access. Release is the final account
            // access; the registry may reclaim immediately after observing zero.
            let previous = unsafe { pointer.as_ref() }
                .bindings
                .fetch_sub(1, Ordering::Release);
            debug_assert!(previous != 0);
        }
    }
}

/// Unique charge/return authority retained inside a heap allocation header.
/// Observation and domain deletion cannot reconstruct a credit. Forgetting a
/// credit retains usage/backing, rather than enabling a return into freed RAM.
#[derive(Debug)]
pub(crate) struct MemoryCredit {
    account: NonNull<MemoryAccount>,
    bytes: NonZeroU64,
}

// SAFETY: this credit's nonzero reservation pins its account; moving the credit
// transfers exactly one atomic return, without touching the payload allocation.
unsafe impl Send for MemoryCredit {}
// SAFETY: shared observers cannot consume the return right. Release needs
// ownership; the account remains pinned by this credit until that release.
unsafe impl Sync for MemoryCredit {}

impl Drop for MemoryCredit {
    fn drop(&mut self) {
        // SAFETY: the credit's nonzero bytes pin backing through this final
        // atomic operation. No account access occurs after publishing the return.
        let previous = unsafe { self.account.as_ref() }
            .used
            .fetch_sub(self.bytes.get(), Ordering::Release);
        debug_assert!(previous >= self.bytes.get());
    }
}
