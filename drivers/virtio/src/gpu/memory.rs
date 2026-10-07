//! One allocation retains its preparation, activation and unmap progress.
//! An address is stored only together with the admitted immutable lease owner.
#![deny(unsafe_code)]

use kernel_api::dma::*;
use kernel_api::{KapiError, KapiResult};

enum Stage {
    Planned,
    Cpu(CpuDmaLease),
    Prepared(PreparedSharedDmaLease),
    Active {
        address: DmaDeviceAddress,
        memory: SharedDmaLease,
    },
    Retired(CpuDmaLease),
    CloseFailed(DmaCloseError),
    Closed,
    Transitioning,
}

pub(super) struct SharedAllocation {
    identity: DmaQueueIdentity,
    request: DmaAllocationRequest,
    stage: Stage,
}

impl SharedAllocation {
    pub(super) fn new(identity: DmaQueueIdentity, bytes: usize) -> KapiResult<Self> {
        let request = DmaAllocationRequest::new(bytes, DmaDirection::Bidirectional)
            .ok_or(KapiError::InvalidSize)?;
        Ok(Self {
            identity,
            request,
            stage: Stage::Planned,
        })
    }

    pub(super) fn advance_boot(&mut self) -> KapiResult<bool> {
        let stage = core::mem::replace(&mut self.stage, Stage::Transitioning);
        let (next, result) = match stage {
            Stage::Planned => match kernel_api::service::kernel::instance()
                .alloc_dma_for_device(self.request, self.identity.device())
            {
                Ok(memory) => (Stage::Cpu(memory), Ok(false)),
                Err(cause) => (Stage::Planned, Err(cause)),
            },
            Stage::Cpu(mut memory) => match memory.write(|bytes| bytes.fill(0)) {
                Err(cause) => (Stage::Cpu(memory), Err(dma_error(cause))),
                Ok(()) => match memory.prepare_shared(self.identity) {
                    Ok(memory) => (Stage::Prepared(memory), Ok(false)),
                    Err(failure) => {
                        let (cause, memory) = failure.into_parts();
                        (Stage::Cpu(memory), Err(dma_error(cause)))
                    }
                },
            },
            Stage::Prepared(memory) => {
                let address = memory.descriptor().and_then(|descriptor| {
                    let address = descriptor.device_address();
                    if descriptor.queue() != self.identity
                        || descriptor.byte_count().get() < self.request.byte_count().get()
                        || address.get() == 0
                        || !address.get().is_multiple_of(8)
                        || address
                            .checked_add(self.request.byte_count().get())
                            .is_none()
                    {
                        Err(DmaLeaseError::InvalidRange)
                    } else {
                        Ok(address)
                    }
                });
                match address {
                    Err(cause) => (Stage::Prepared(memory), Err(dma_error(cause))),
                    Ok(address) => match memory.activate() {
                        Ok(memory) => (Stage::Active { address, memory }, Ok(true)),
                        Err(failure) => {
                            let (cause, memory) = failure.into_parts();
                            (Stage::Prepared(memory), Err(dma_error(cause)))
                        }
                    },
                }
            }
            Stage::Active { address, memory } => (Stage::Active { address, memory }, Ok(true)),
            other => (other, Err(KapiError::Busy)),
        };
        self.stage = next;
        result
    }

    pub(super) fn address(&self) -> KapiResult<DmaDeviceAddress> {
        match self.stage {
            Stage::Active { address, .. } => Ok(address),
            _ => Err(KapiError::Busy),
        }
    }
    pub(super) fn memory(&mut self) -> Result<&mut SharedDmaLease, DmaLeaseError> {
        match &mut self.stage {
            Stage::Active { memory, .. } => Ok(memory),
            _ => Err(DmaLeaseError::InvalidState),
        }
    }

    /// # Safety
    /// The owner has observed device reset or a matching fenced command that
    /// detached this allocation. No outstanding operation can access its RAM;
    /// that condition must remain established throughout finalization retries.
    #[expect(
        unsafe_code,
        reason = "the device owner alone proves that its exact allocation has no remaining hardware access"
    )]
    pub(super) unsafe fn advance_retirement(&mut self) -> KapiResult<bool> {
        let stage = core::mem::replace(&mut self.stage, Stage::Transitioning);
        let (next, result) = match stage {
            Stage::Planned => (Stage::Closed, Ok(true)),
            Stage::Cpu(memory) => (Stage::Retired(memory), Ok(false)),
            Stage::Prepared(memory) => match memory.abort() {
                Ok(memory) => (Stage::Retired(memory), Ok(false)),
                Err(failure) => {
                    let (cause, memory) = failure.into_parts();
                    (Stage::Prepared(memory), Err(dma_error(cause)))
                }
            },
            Stage::Active { address, memory } => {
                // SAFETY: the caller proves hardware quiescence for this retained
                // queue generation and the immutable allocation identity.
                let witness = unsafe {
                    DmaQuiesceWitness::after_queue_quiesced(self.identity, memory.lease_id())
                };
                match memory.quiesce(witness) {
                    Ok(memory) => (Stage::Retired(memory), Ok(false)),
                    Err(failure) => {
                        let (cause, memory) = failure.into_parts();
                        (Stage::Active { address, memory }, Err(dma_error(cause)))
                    }
                }
            }
            Stage::Retired(memory) => match memory.close() {
                Ok(()) => (Stage::Closed, Ok(true)),
                Err(failure) => {
                    let cause = failure.cause();
                    (Stage::CloseFailed(failure), Err(dma_error(cause)))
                }
            },
            Stage::CloseFailed(failure) => {
                let (_, memory) = failure.into_parts();
                match memory.retry_close() {
                    Ok(()) => (Stage::Closed, Ok(true)),
                    Err(failure) => {
                        let cause = failure.cause();
                        (Stage::CloseFailed(failure), Err(dma_error(cause)))
                    }
                }
            }
            Stage::Closed => (Stage::Closed, Ok(true)),
            Stage::Transitioning => (Stage::Transitioning, Err(KapiError::Busy)),
        };
        self.stage = next;
        result
    }
}

pub(super) fn dma_error(cause: DmaLeaseError) -> KapiError {
    match cause {
        DmaLeaseError::InvalidRange => KapiError::InvalidSize,
        DmaLeaseError::InvalidAlignment => KapiError::InvalidAlignment,
        DmaLeaseError::ForeignOwner => KapiError::PermissionDenied,
        DmaLeaseError::NotSupported => KapiError::NotSupported,
        _ => KapiError::IoError,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use exorust_sync::Mutex;
    use kernel_api::abi::driver::PackedPciLocation;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State {
        Cpu,
        Prepared,
        Active,
        Retired,
        FailedClose,
        Closed,
    }
    struct Allocation {
        state: Mutex<(State, [u8; 64])>,
        queue: DmaQueueIdentity,
        quiesce_calls: AtomicUsize,
        close_calls: AtomicUsize,
        retry_calls: AtomicUsize,
        abandoned: AtomicUsize,
    }
    // SAFETY: this private fixture serializes all visits/transitions over retained
    // initialized backing. It admits no hardware DMA; shared scalar operations
    // are rejected, and retirement keeps storage alive through failed unmap.
    #[expect(
        unsafe_code,
        reason = "the fixture implements the production allocation authority with serialized initialized storage and no hardware publication"
    )]
    unsafe impl DmaLeaseAuthority for Allocation {
        fn lease_id(&self) -> DmaLeaseId {
            DmaLeaseId::from_parts(1, 1).unwrap()
        }
        fn device_address(&self) -> DmaDeviceAddress {
            DmaDeviceAddress::from_abi(4096)
        }
        fn byte_count(&self) -> DmaByteCount {
            DmaByteCount::new(64).unwrap()
        }
        fn direction(&self) -> DmaDirection {
            DmaDirection::Bidirectional
        }
        fn with_cpu_bytes(&self, visitor: &mut dyn FnMut(&[u8])) -> Result<(), DmaLeaseError> {
            let state = self.state.lock();
            if !matches!(state.0, State::Cpu | State::Retired) {
                return Err(DmaLeaseError::InvalidState);
            }
            visitor(&state.1);
            Ok(())
        }
        fn with_cpu_bytes_mut(
            &self,
            visitor: &mut dyn FnMut(&mut [u8]),
        ) -> Result<(), DmaLeaseError> {
            let mut state = self.state.lock();
            if !matches!(state.0, State::Cpu | State::Retired) {
                return Err(DmaLeaseError::InvalidState);
            }
            visitor(&mut state.1);
            Ok(())
        }
        fn prepare(&self, _: DmaQueueIdentity) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::NotSupported)
        }
        fn prepared_queue(&self) -> Result<DmaQueueIdentity, DmaLeaseError> {
            if self.state.lock().0 == State::Prepared {
                Ok(self.queue)
            } else {
                Err(DmaLeaseError::InvalidState)
            }
        }
        fn abort_prepared(&self) -> Result<(), DmaLeaseError> {
            let mut state = self.state.lock();
            if state.0 != State::Prepared {
                return Err(DmaLeaseError::InvalidState);
            }
            state.0 = State::Cpu;
            Ok(())
        }
        fn arm(&self) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::NotSupported)
        }
        fn complete(&self, _: DmaCompletionWitness) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::NotSupported)
        }
        fn return_to_cpu(&self) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::NotSupported)
        }
        fn mark_outcome_unknown(&self) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::NotSupported)
        }
        fn revoke_after_reset(&self, _: DmaResetWitness) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::NotSupported)
        }
        fn reconcile(&self, _: DmaReconcileWitness) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::NotSupported)
        }
        fn prepare_shared(&self, queue: DmaQueueIdentity) -> Result<(), DmaLeaseError> {
            let mut state = self.state.lock();
            if state.0 != State::Cpu || queue != self.queue {
                return Err(DmaLeaseError::InvalidState);
            }
            state.0 = State::Prepared;
            Ok(())
        }
        fn activate_shared(&self) -> Result<(), DmaLeaseError> {
            let mut state = self.state.lock();
            if state.0 != State::Prepared {
                return Err(DmaLeaseError::InvalidState);
            }
            state.0 = State::Active;
            Ok(())
        }
        fn read_shared_word(&self, _: usize, _: DmaAccessWidth) -> Result<u64, DmaLeaseError> {
            Err(DmaLeaseError::NotSupported)
        }
        fn write_shared_word(
            &self,
            _: usize,
            _: DmaAccessWidth,
            _: u64,
        ) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::NotSupported)
        }
        fn quiesce_shared(&self, witness: DmaQuiesceWitness) -> Result<(), DmaLeaseError> {
            let mut state = self.state.lock();
            if state.0 != State::Active
                || witness.queue() != self.queue
                || witness.lease_id() != self.lease_id()
            {
                return Err(DmaLeaseError::InvalidState);
            }
            if self.quiesce_calls.fetch_add(1, Ordering::Relaxed) == 0 {
                return Err(DmaLeaseError::IommuFailure);
            }
            state.0 = State::Retired;
            Ok(())
        }
        fn close(&self) -> Result<(), DmaLeaseError> {
            let mut state = self.state.lock();
            if state.0 != State::Retired {
                return Err(DmaLeaseError::InvalidState);
            }
            self.close_calls.fetch_add(1, Ordering::Relaxed);
            state.0 = State::FailedClose;
            Err(DmaLeaseError::IommuFailure)
        }
        fn retry_close(&self) -> Result<(), DmaLeaseError> {
            let mut state = self.state.lock();
            if state.0 != State::FailedClose {
                return Err(DmaLeaseError::InvalidState);
            }
            if self.retry_calls.fetch_add(1, Ordering::Relaxed) == 0 {
                return Err(DmaLeaseError::IommuFailure);
            }
            state.0 = State::Closed;
            Ok(())
        }
        fn abandon(&self, _: DmaLeaseState) {
            self.abandoned.fetch_add(1, Ordering::Relaxed);
        }
    }
    #[test]
    #[expect(
        unsafe_code,
        reason = "the private fixture cannot publish hardware DMA and the test holds all storage through retirement"
    )]
    fn retirement_retries_only_unfinished_quiescence_and_unmap() {
        let identity = DmaQueueIdentity::new(PackedPciLocation::new(0, 0, 1, 0), 0, 1).unwrap();
        let authority = Arc::new(Allocation {
            state: Mutex::new((State::Cpu, [7; 64])),
            queue: identity,
            quiesce_calls: AtomicUsize::new(0),
            close_calls: AtomicUsize::new(0),
            retry_calls: AtomicUsize::new(0),
            abandoned: AtomicUsize::new(0),
        });
        let mut allocation = SharedAllocation::new(identity, 64).unwrap();
        allocation.stage = Stage::Cpu(CpuDmaLease::from_authority(authority.clone()));
        assert_eq!(allocation.advance_boot(), Ok(false));
        assert_eq!(allocation.advance_boot(), Ok(true));
        // SAFETY: fixture storage is retained and cannot be exposed to hardware.
        assert_eq!(
            unsafe { allocation.advance_retirement() },
            Err(KapiError::IoError)
        );
        assert!(allocation.address().is_ok());
        // SAFETY: the same no-hardware condition holds across every retry.
        assert_eq!(unsafe { allocation.advance_retirement() }, Ok(false));
        assert!(allocation.address().is_err());
        // SAFETY: quiescence completed; retained storage has no device access.
        assert_eq!(
            unsafe { allocation.advance_retirement() },
            Err(KapiError::IoError)
        );
        // SAFETY: only failed unmap remains and storage stays owned by the fixture.
        assert_eq!(
            unsafe { allocation.advance_retirement() },
            Err(KapiError::IoError)
        );
        // SAFETY: this resumes the same failed close without any device access.
        assert_eq!(unsafe { allocation.advance_retirement() }, Ok(true));
        assert_eq!(authority.quiesce_calls.load(Ordering::Relaxed), 2);
        assert_eq!(authority.close_calls.load(Ordering::Relaxed), 1);
        assert_eq!(authority.retry_calls.load(Ordering::Relaxed), 2);
        drop(allocation);
        assert_eq!(authority.abandoned.load(Ordering::Relaxed), 0);
    }
}
