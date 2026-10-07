//! Hardware halt and resource retirement are separate, resumable transitions.

use super::*;
use kernel_api::dma::{DmaLeaseError, DmaQuiesceWitness, SharedDmaLease};

enum RetirementItem {
    Producer(ProducerRing),
    Events(EventRing),
    Shared(SharedDmaLease, DmaQueueIdentity),
    CloseFailed(DmaCloseError),
}

/// Holds all register pins until every DMA unmap has completed. A failed close
/// cannot silently become a released owner or be retried without reconciliation.
pub(crate) struct ControllerRetirement {
    _registers: super::super::registers::XhciRegisters,
    _dequeue: hal::mmio::OwnedMmioRegister<u64, hal::WriteOnly>,
    pending: Vec<RetirementItem>,
}

impl XhciController {
    #[expect(
        clippy::result_large_err,
        reason = "failure returns the actual controller owner without allocation after hardware effects"
    )]
    pub(crate) fn into_retirement(self) -> Result<ControllerRetirement, (UsbError, Self)> {
        // Outstanding transfers keep their actual in-flight capability. Halt
        // alone does not claim a transfer completion or permit forced discard.
        let blocker = self
            .transfer_rings
            .lock()
            .iter()
            .flatten()
            .flatten()
            .find_map(|queue| match &queue.state {
                EndpointState::Idle => None,
                EndpointState::Active(request) | EndpointState::Halted(request) => {
                    Some(UsbError::TransferInFlight {
                        queue: queue.ring.identity(),
                        lease: request.memory.as_ref().map(InFlightDmaLease::lease_id),
                    })
                }
            });
        if let Some(blocker) = blocker {
            return Err((blocker, self));
        }
        let count = 4
            + self.device_contexts.lock().iter().flatten().count()
            + self.scratchpads.lock().len()
            + self
                .command_requests
                .lock()
                .iter()
                .filter(|request| request.input.is_some())
                .count()
            + self.failed_inputs.lock().len()
            + self
                .transfer_rings
                .lock()
                .iter()
                .flatten()
                .flatten()
                .count()
            + self.retirement_failures.lock().len();
        let mut pending = Vec::new();
        if pending.try_reserve_exact(count).is_err() {
            return Err((UsbError::NoResources, self));
        }
        if let Err(error) = self.stop() {
            return Err((error, self));
        }
        let command_ring = self.command_ring.into_inner();
        let command_identity = command_ring.identity();
        pending.push(RetirementItem::Producer(command_ring));
        pending.push(RetirementItem::Events(self.event_ring.into_inner()));
        for region in [self.erst.into_inner(), self.dcbaa.into_inner()]
            .into_iter()
            .chain(self.device_contexts.into_inner().into_iter().flatten())
            .chain(self.failed_inputs.into_inner())
            .chain(self.scratchpads.into_inner())
        {
            pending.push(RetirementItem::Shared(region.memory, region.identity));
        }
        for request in self.command_requests.into_inner() {
            if let Some(region) = request.input {
                pending.push(RetirementItem::Shared(region.memory, command_identity));
            }
            request.receipt.complete(Err(UsbError::Busy));
            request.receipt.notify();
        }
        for queue in self
            .transfer_rings
            .into_inner()
            .into_iter()
            .flatten()
            .flatten()
        {
            pending.push(RetirementItem::Producer(queue.ring));
        }
        for failure in self.retirement_failures.into_inner() {
            pending.push(RetirementItem::CloseFailed(failure));
        }
        Ok(ControllerRetirement {
            _registers: self.registers,
            _dequeue: self.event_dequeue.into_inner(),
            pending,
        })
    }
}

impl ControllerRetirement {
    /// HCH was observed before this owner was constructed, and no controller
    /// handle remains capable of restarting any of its queues.
    pub(crate) fn finish(&mut self) -> UsbResult<()> {
        // LOOP_PROOF: mode=condition; reason=Each iteration removes one resource or returns its retained failure, so the finite retirement inventory drains without discarding a failed owner.;
        while let Some(item) = self.pending.pop() {
            match retire(item) {
                Ok(()) => {}
                Err((cause, item)) => {
                    self.pending.push(item);
                    return Err(UsbError::Dma(cause));
                }
            }
        }
        Ok(())
    }
}

#[expect(
    unsafe_code,
    reason = "the private retirement owner follows observed controller halt and consumes each queue/lease association once"
)]
fn retire(item: RetirementItem) -> Result<(), (DmaLeaseError, RetirementItem)> {
    let memory = match item {
        RetirementItem::Producer(ring) => {
            // SAFETY: all controller DMA has halted, no external controller
            // handle exists, and this owned ring identifies the exact allocation.
            let witness = unsafe {
                DmaQuiesceWitness::after_queue_quiesced(ring.identity(), ring.lease_id())
            };
            ring.quiesce(witness)
                .map_err(|failure| (failure.cause, RetirementItem::Producer(failure.ring)))
        }
        RetirementItem::Events(ring) => {
            // SAFETY: HCH stopped the event producer along with every endpoint.
            let witness = unsafe {
                DmaQuiesceWitness::after_queue_quiesced(ring.identity(), ring.lease_id())
            };
            ring.quiesce(witness)
                .map_err(|failure| (failure.cause, RetirementItem::Events(failure.ring)))
        }
        RetirementItem::Shared(memory, identity) => {
            // SAFETY: no queue can access this context/table after global halt.
            let witness =
                unsafe { DmaQuiesceWitness::after_queue_quiesced(identity, memory.lease_id()) };
            memory.quiesce(witness).map_err(|failure| {
                let (cause, memory) = failure.into_parts();
                (cause, RetirementItem::Shared(memory, identity))
            })
        }
        RetirementItem::CloseFailed(failure) => {
            let (_, memory) = failure.into_parts();
            return memory
                .retry_close()
                .map_err(|failure| (failure.cause(), RetirementItem::CloseFailed(failure)));
        }
    }?;
    memory
        .close()
        .map_err(|failure| (failure.cause(), RetirementItem::CloseFailed(failure)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use kernel_api::dma::*;

    struct Allocation {
        storage: [u8; 64],
        closes: AtomicUsize,
        retries: AtomicUsize,
        abandoned: AtomicUsize,
    }

    // SAFETY: the fixture owns initialized storage, rejects every CPU visit and
    // device transition, and retains its backing through both failed closes.
    #[expect(
        unsafe_code,
        reason = "the private allocation cannot publish hardware DMA or expose CPU references; its only supported operations retain and finish unmap"
    )]
    unsafe impl DmaLeaseAuthority for Allocation {
        fn lease_id(&self) -> DmaLeaseId {
            DmaLeaseId::from_parts(1, 1).unwrap()
        }
        fn device_address(&self) -> DmaDeviceAddress {
            DmaDeviceAddress::from_abi(4096)
        }
        fn byte_count(&self) -> DmaByteCount {
            DmaByteCount::new(self.storage.len()).unwrap()
        }
        fn direction(&self) -> DmaDirection {
            DmaDirection::Bidirectional
        }
        fn with_cpu_bytes(&self, _: &mut dyn FnMut(&[u8])) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::NotSupported)
        }
        fn with_cpu_bytes_mut(&self, _: &mut dyn FnMut(&mut [u8])) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::NotSupported)
        }
        fn prepare(&self, _: DmaQueueIdentity) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::NotSupported)
        }
        fn prepared_queue(&self) -> Result<DmaQueueIdentity, DmaLeaseError> {
            Err(DmaLeaseError::NotSupported)
        }
        fn abort_prepared(&self) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::NotSupported)
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
        fn close(&self) -> Result<(), DmaLeaseError> {
            assert_eq!(self.closes.fetch_add(1, Ordering::Relaxed), 0);
            Err(DmaLeaseError::IommuFailure)
        }
        fn prepare_shared(&self, _: DmaQueueIdentity) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::NotSupported)
        }
        fn activate_shared(&self) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::NotSupported)
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
        fn quiesce_shared(&self, _: DmaQuiesceWitness) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::NotSupported)
        }
        fn retry_close(&self) -> Result<(), DmaLeaseError> {
            assert_eq!(self.closes.load(Ordering::Relaxed), 1);
            match self.retries.fetch_add(1, Ordering::Relaxed) {
                0 => Err(DmaLeaseError::IommuFailure),
                1 => Ok(()),
                _ => panic!("completed unmap is consumed"),
            }
        }
        fn abandon(&self, _: DmaLeaseState) {
            self.abandoned.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn failed_unmap_remains_owned_and_resumes_without_repeating_quiescence() {
        let authority = Arc::new(Allocation {
            storage: [0; 64],
            closes: AtomicUsize::new(0),
            retries: AtomicUsize::new(0),
            abandoned: AtomicUsize::new(0),
        });
        let failure = CpuDmaLease::from_authority(authority.clone())
            .close()
            .unwrap_err();
        let (cause, retained) = retire(RetirementItem::CloseFailed(failure)).unwrap_err();
        assert_eq!(cause, DmaLeaseError::IommuFailure);
        assert!(retire(retained).is_ok());
        assert_eq!(authority.closes.load(Ordering::Relaxed), 1);
        assert_eq!(authority.retries.load(Ordering::Relaxed), 2);
        assert_eq!(authority.abandoned.load(Ordering::Relaxed), 0);
    }
}
