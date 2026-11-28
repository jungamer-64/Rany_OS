//! The slot retains the mapping or records its current exclusive borrower.
//! Retirement keeps the slot occupied until translation removal completes.

use super::QuarantineReason;
use kernel_api::dma::{DmaLeaseError, DmaQueueIdentity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TransferState {
    CpuOwned,
    Prepared {
        queue: DmaQueueIdentity,
    },
    SharedPrepared {
        queue: DmaQueueIdentity,
    },
    SharedActive {
        queue: DmaQueueIdentity,
    },
    InFlight {
        queue: DmaQueueIdentity,
    },
    Completed {
        queue: DmaQueueIdentity,
    },
    Quarantined {
        reason: QuarantineReason,
        queue: Option<DmaQueueIdentity>,
    },
    RevokedAfterReset {
        queue: DmaQueueIdentity,
        reset_generation: u64,
    },
}

pub(super) struct MappedDma<T> {
    pub(super) mapping: T,
    pub(super) state: TransferState,
}

pub(super) enum DmaStorage<T> {
    Mapped(MappedDma<T>),
    CpuBorrowed(CpuBorrowReturn),
    Retiring(T),
    Closing(CloseMode),
}

#[derive(Clone, Copy)]
pub(super) enum CpuBorrowReturn {
    Restore,
    Retire,
}

#[derive(Clone, Copy)]
pub(super) enum CloseMode {
    Explicit,
    Detached,
}

impl<T> DmaStorage<T> {
    pub(super) fn mapped(&self) -> Result<&MappedDma<T>, DmaLeaseError> {
        match self {
            Self::Mapped(mapped) => Ok(mapped),
            Self::CpuBorrowed(_) | Self::Closing(_) | Self::Retiring(_) => {
                Err(DmaLeaseError::InvalidState)
            }
        }
    }

    pub(super) fn mapped_mut(&mut self) -> Result<&mut MappedDma<T>, DmaLeaseError> {
        match self {
            Self::Mapped(mapped) => Ok(mapped),
            Self::CpuBorrowed(_) | Self::Closing(_) | Self::Retiring(_) => {
                Err(DmaLeaseError::InvalidState)
            }
        }
    }

    pub(super) fn borrow_cpu(&mut self) -> Result<T, DmaLeaseError> {
        if self.mapped()?.state != TransferState::CpuOwned {
            return Err(DmaLeaseError::InvalidState);
        }
        let Self::Mapped(mapped) =
            core::mem::replace(self, Self::CpuBorrowed(CpuBorrowReturn::Restore))
        else {
            unreachable!("CPU admission checked a retained mapping under one exclusive borrow");
        };
        Ok(mapped.mapping)
    }

    /// A loan can return the CPU owner or hand it off for deferred retirement,
    /// after the last CPU reference has ended.
    pub(super) fn return_cpu(&mut self, mapping: T) -> CpuBorrowReturn {
        let Self::CpuBorrowed(return_to) = *self else {
            unreachable!("the loan retains its slot until return");
        };
        *self = match return_to {
            CpuBorrowReturn::Restore => Self::Mapped(MappedDma {
                mapping,
                state: TransferState::CpuOwned,
            }),
            CpuBorrowReturn::Retire => Self::Retiring(mapping),
        };
        return_to
    }

    /// Take a mapping only after its transfer state permits retirement.
    pub(super) fn take_for_close(&mut self, mode: CloseMode) -> Result<T, DmaLeaseError> {
        match self {
            Self::Mapped(mapped) if mapped.state.can_retire() => {}
            Self::Retiring(_) => {}
            _ => return Err(DmaLeaseError::InvalidState),
        }
        match core::mem::replace(self, Self::Closing(mode)) {
            Self::Mapped(mapped) => Ok(mapped.mapping),
            Self::Retiring(mapping) => Ok(mapping),
            _ => unreachable!("close admission validated the owner under one exclusive borrow"),
        }
    }

    /// Revoke an abandoned capability using the registry's transfer state.
    /// Returns true when a mapping becomes ready for the retirement worker.
    pub(super) fn abandon(&mut self, observed: kernel_api::dma::DmaLeaseState) -> bool {
        match self {
            Self::Mapped(mapped) if mapped.state.can_retire() => {
                let mapping = self
                    .take_for_close(CloseMode::Detached)
                    .expect("abandon admitted the mapping under one exclusive borrow");
                *self = Self::Retiring(mapping);
                true
            }
            Self::Mapped(mapped) => {
                if !matches!(mapped.state, TransferState::Quarantined { .. }) {
                    mapped.state = TransferState::Quarantined {
                        reason: QuarantineReason::CapabilityAbandoned(observed),
                        queue: mapped.state.queue(),
                    };
                }
                false
            }
            Self::CpuBorrowed(return_to) => {
                *return_to = CpuBorrowReturn::Retire;
                false
            }
            Self::Closing(mode) => {
                *mode = CloseMode::Detached;
                false
            }
            Self::Retiring(_) => false,
        }
    }
}

impl TransferState {
    pub(super) fn can_retire(self) -> bool {
        matches!(
            self,
            Self::CpuOwned
                | Self::Prepared { .. }
                | Self::SharedPrepared { .. }
                | Self::Completed { .. }
                | Self::RevokedAfterReset { .. }
                | Self::Quarantined {
                    reason: QuarantineReason::UnmapFailed,
                    queue: None
                }
        )
    }

    pub(super) fn queue(self) -> Option<DmaQueueIdentity> {
        match self {
            Self::Prepared { queue }
            | Self::SharedPrepared { queue }
            | Self::SharedActive { queue }
            | Self::InFlight { queue }
            | Self::Completed { queue }
            | Self::RevokedAfterReset { queue, .. } => Some(queue),
            Self::Quarantined { queue, .. } => queue,
            Self::CpuOwned => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};

    struct Owner {
        id: usize,
        dropped: Arc<AtomicUsize>,
    }
    impl Drop for Owner {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn abandoned_unpublished_leases_retain_the_mapping_for_close() {
        use kernel_api::abi::driver::PackedPciLocation;
        use kernel_api::dma::DmaLeaseState;

        let queue = DmaQueueIdentity::new(PackedPciLocation::new(0, 0, 1, 0), 0, 1).unwrap();
        for (state, observed) in [
            (TransferState::CpuOwned, DmaLeaseState::CpuOwned),
            (TransferState::Prepared { queue }, DmaLeaseState::Prepared),
            (
                TransferState::SharedPrepared { queue },
                DmaLeaseState::SharedPrepared,
            ),
        ] {
            let mut storage = DmaStorage::Mapped(MappedDma { mapping: 43, state });
            assert!(storage.abandon(observed));
            assert!(storage.mapped().is_err());
            assert_eq!(storage.take_for_close(CloseMode::Detached), Ok(43));
            assert!(storage.take_for_close(CloseMode::Detached).is_err());
        }
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn abandoned_inflight_lease_cannot_be_retired() {
        use kernel_api::abi::driver::PackedPciLocation;
        use kernel_api::dma::DmaLeaseState;

        let queue = DmaQueueIdentity::new(PackedPciLocation::new(0, 0, 1, 0), 0, 1).unwrap();
        let mut storage = DmaStorage::Mapped(MappedDma {
            mapping: 43,
            state: TransferState::InFlight { queue },
        });
        assert!(!storage.abandon(DmaLeaseState::InFlight));
        assert!(storage.take_for_close(CloseMode::Detached).is_err());
        assert_eq!(storage.mapped().unwrap().state.queue(), Some(queue));
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn cpu_loan_excludes_competing_access_and_returns_the_same_live_owner() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut storage = DmaStorage::Mapped(MappedDma {
            mapping: Owner {
                id: 37,
                dropped: Arc::clone(&dropped),
            },
            state: TransferState::CpuOwned,
        });
        let loan = storage
            .borrow_cpu()
            .unwrap_or_else(|error| panic!("CPU admission failed: {error:?}"));
        assert_eq!(loan.id, 37);
        assert!(matches!(
            storage.borrow_cpu(),
            Err(DmaLeaseError::InvalidState)
        ));
        assert!(matches!(
            storage.take_for_close(CloseMode::Explicit),
            Err(DmaLeaseError::InvalidState)
        ));
        assert!(matches!(storage.return_cpu(loan), CpuBorrowReturn::Restore));
        assert_eq!(storage.mapped().unwrap().mapping.id, 37);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        drop(storage);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn shutdown_during_a_cpu_loan_retains_backing_until_the_close_owner_finishes() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut storage = DmaStorage::Mapped(MappedDma {
            mapping: Owner {
                id: 73,
                dropped: Arc::clone(&dropped),
            },
            state: TransferState::CpuOwned,
        });
        let loan = storage
            .borrow_cpu()
            .unwrap_or_else(|error| panic!("CPU admission failed: {error:?}"));
        let DmaStorage::CpuBorrowed(return_to) = &mut storage else {
            panic!("missing CPU loan");
        };
        *return_to = CpuBorrowReturn::Retire;
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        assert!(matches!(storage.return_cpu(loan), CpuBorrowReturn::Retire));
        assert!(matches!(storage, DmaStorage::Retiring(_)));
        let owner = storage.take_for_close(CloseMode::Detached).unwrap();
        assert_eq!(owner.id, 73);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        drop(owner);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn device_owned_mapping_rejects_cpu_admission_without_changing_owner_or_queue() {
        let device = kernel_api::abi::driver::PackedPciLocation::new(0, 1, 2, 0);
        let queue = DmaQueueIdentity::new(device, 2, 3).unwrap();
        let mut storage = DmaStorage::Mapped(MappedDma {
            mapping: 73,
            state: TransferState::InFlight { queue },
        });
        assert!(matches!(
            storage.borrow_cpu(),
            Err(DmaLeaseError::InvalidState)
        ));
        let mapped = storage.mapped().unwrap();
        assert_eq!(mapped.mapping, 73);
        assert_eq!(mapped.state, TransferState::InFlight { queue });
    }
}
