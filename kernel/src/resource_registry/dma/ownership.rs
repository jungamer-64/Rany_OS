//! The slot retains either a mapped owner or a synchronous loan/close witness.
//! Device transitions can only borrow a retained mapping. Loans move the owner
//! out and keep the slot unavailable until every CPU reference has ended.

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
    Closing,
}

#[derive(Clone, Copy)]
pub(super) enum CpuBorrowReturn {
    Restore,
    Close,
}

pub(super) enum CpuBorrowEnd<T> {
    Restored,
    Close(T),
}

impl<T> DmaStorage<T> {
    pub(super) fn mapped(&self) -> Result<&MappedDma<T>, DmaLeaseError> {
        match self {
            Self::Mapped(mapped) => Ok(mapped),
            Self::CpuBorrowed(_) | Self::Closing => Err(DmaLeaseError::InvalidState),
        }
    }

    pub(super) fn mapped_mut(&mut self) -> Result<&mut MappedDma<T>, DmaLeaseError> {
        match self {
            Self::Mapped(mapped) => Ok(mapped),
            Self::CpuBorrowed(_) | Self::Closing => Err(DmaLeaseError::InvalidState),
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

    /// Consume the synchronous loan only after its last CPU reference ends.
    /// Shutdown converts it to a closing owner; the registry retains identity
    /// until that owner completes IOTLB/ATS retirement or restores quarantine.
    pub(super) fn return_cpu(&mut self, mapping: T) -> CpuBorrowEnd<T> {
        let Self::CpuBorrowed(return_to) = self else {
            unreachable!("the loan retains its slot until return");
        };
        match *return_to {
            CpuBorrowReturn::Restore => {
                *self = Self::Mapped(MappedDma {
                    mapping,
                    state: TransferState::CpuOwned,
                });
                CpuBorrowEnd::Restored
            }
            CpuBorrowReturn::Close => {
                *self = Self::Closing;
                CpuBorrowEnd::Close(mapping)
            }
        }
    }

    /// The caller validates the transfer state and any required completion
    /// witness before taking a retained owner for synchronous unmap.
    pub(super) fn take_for_close(&mut self) -> Result<T, DmaLeaseError> {
        self.mapped()?;
        let Self::Mapped(mapped) = core::mem::replace(self, Self::Closing) else {
            unreachable!("close admission checked a retained owner under one exclusive borrow");
        };
        Ok(mapped.mapping)
    }
}

impl TransferState {
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
            storage.take_for_close(),
            Err(DmaLeaseError::InvalidState)
        ));
        assert!(matches!(storage.return_cpu(loan), CpuBorrowEnd::Restored));
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
        *return_to = CpuBorrowReturn::Close;
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        let CpuBorrowEnd::Close(owner) = storage.return_cpu(loan) else {
            panic!("shutdown did not request close");
        };
        assert_eq!(owner.id, 73);
        assert!(matches!(storage, DmaStorage::Closing));
        drop(storage);
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
