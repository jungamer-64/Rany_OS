//! The queue owns PFN-list RAM separately from the physical page owner. One
//! accepted command retains its list until used-ring acknowledgement or reset.
#![deny(unsafe_code)]

use crate::core::{
    PreparedSplitVirtQueue, QueueBuildError, QueueCommandActivationError, QueueSegment,
    QueueSubmitCause, QueueSubmitOutcome, RetiredVirtQueue, SplitVirtQueue,
};
use crate::queue_memory::{
    QueueInterrupt, QueuePrepareError, SharedAllocation, SplitQueueLayout, dma_error,
};
use crate::transport::VirtioTransport;
use kernel_api::balloon::{BalloonPageError, BalloonPageNumber};
use kernel_api::dma::*;
use kernel_api::{KapiError, KapiResult};

enum Ring {
    Planned,
    Cpu(CpuDmaLease),
    Prepared(PreparedSplitVirtQueue<usize>),
    PrepareFailed(PreparedSharedDmaLease),
    Active(SplitVirtQueue<usize>),
    Retired(RetiredVirtQueue<usize>),
    Releasing(CpuDmaLease),
    CloseFailed(DmaCloseError),
    Closed,
    Transitioning,
}
pub(super) enum SubmitError {
    Queue(KapiError),
    Page(BalloonPageError),
}
pub(super) struct PfnQueue {
    identity: DmaQueueIdentity,
    layout: SplitQueueLayout,
    request: DmaAllocationRequest,
    interrupt: QueueInterrupt,
    list: SharedAllocation,
    ring: Ring,
}
impl PfnQueue {
    pub(super) fn new(
        identity: DmaQueueIdentity,
        maximum: u16,
        interrupt: QueueInterrupt,
    ) -> KapiResult<Self> {
        let maximum = maximum.min(16);
        if maximum == 0 {
            return Err(KapiError::NotSupported);
        }
        let layout = SplitQueueLayout::new(1u16 << (15 - maximum.leading_zeros()))
            .map_err(|_| KapiError::InvalidSize)?;
        Ok(Self {
            identity,
            layout,
            request: DmaAllocationRequest::new(layout.byte_count(), DmaDirection::Bidirectional)
                .ok_or(KapiError::InvalidSize)?,
            interrupt,
            list: SharedAllocation::new(identity, 8)?,
            ring: Ring::Planned,
        })
    }
    pub(super) fn advance_boot(&mut self, transport: &dyn VirtioTransport) -> KapiResult<bool> {
        if !self.list.advance_boot()? {
            return Ok(false);
        }
        let previous = core::mem::replace(&mut self.ring, Ring::Transitioning);
        let (next, result) = match previous {
            Ring::Planned => match kernel_api::service::kernel::instance()
                .alloc_dma_for_device(self.request, self.identity.device())
            {
                Ok(memory) => (Ring::Cpu(memory), Ok(false)),
                Err(cause) => (Ring::Planned, Err(cause)),
            },
            Ring::Cpu(memory) => match PreparedSplitVirtQueue::prepare(
                self.identity,
                self.layout,
                self.interrupt,
                memory,
            ) {
                Ok(ring) => (Ring::Prepared(ring), Ok(false)),
                Err(failure) => (build_failure(failure), Err(KapiError::IoError)),
            },
            Ring::Prepared(ring) => match ring.activate(transport) {
                Ok(ring) => (Ring::Active(ring), Ok(true)),
                Err(failure) => (Ring::Prepared(failure.queue), Err(KapiError::IoError)),
            },
            Ring::Active(ring) => (Ring::Active(ring), Ok(true)),
            other => (other, Err(KapiError::Busy)),
        };
        self.ring = next;
        result
    }
    /// `activate` changes page reservation before the ring can expose its PFN.
    /// The owner establishes DRIVER_OK before requesting this publication.
    #[expect(
        unsafe_code,
        reason = "the exact-generation retained list and activated physical page owner outlive every accepted PFN publication"
    )]
    pub(super) fn submit(
        &mut self,
        pfn: BalloonPageNumber,
        slot: usize,
        activate: impl FnOnce() -> Result<(), BalloonPageError>,
    ) -> Result<QueueSubmitOutcome, SubmitError> {
        let Ring::Active(ring) = &mut self.ring else {
            return Err(SubmitError::Queue(KapiError::Busy));
        };
        if ring.pending_count() != 0 {
            return Err(SubmitError::Queue(KapiError::Busy));
        }
        let address = self.list.address().map_err(SubmitError::Queue)?;
        self.list
            .memory()
            .and_then(|memory| memory.window(0, 4))
            .and_then(|mut list| list.write_u32(0, pfn.wire_pfn()))
            .map_err(|cause| SubmitError::Queue(dma_error(cause)))?;
        let bytes = DmaByteCount::new(4).ok_or(SubmitError::Queue(KapiError::InvalidSize))?;
        let segment = QueueSegment::new(address, bytes, false)
            .map_err(|_| SubmitError::Queue(KapiError::InvalidSize))?;
        // SAFETY: the PFN list belongs to this admitted device/generation and
        // remains retained until acknowledgement/reset. Before publication the
        // page owner excludes CPU/allocator reuse; failed activation changes no
        // page authority and publishes nothing. DRIVER_OK is held by the owner.
        unsafe {
            ring.publish(&[segment], slot, |slot| {
                activate()
                    .map(|()| slot)
                    .map_err(|cause| QueueCommandActivationError { owner: slot, cause })
            })
        }
        .map_err(|failure| match failure.cause {
            QueueSubmitCause::Activation(cause) => SubmitError::Page(cause),
            QueueSubmitCause::Admission(crate::core::QueueAdmissionError::QueueFull) => {
                SubmitError::Queue(KapiError::Busy)
            }
            QueueSubmitCause::Admission(_) => SubmitError::Queue(KapiError::IoError),
        })
    }
    pub(super) fn poll(&mut self) -> KapiResult<Option<usize>> {
        let Ring::Active(ring) = &mut self.ring else {
            return Err(KapiError::Busy);
        };
        ring.poll_completion()
            .map(|completion| completion.map(|completion| completion.owner))
            .map_err(|_| KapiError::IoError)
    }
    /// # Safety
    /// Acknowledged reset is held across every retry for this exact generation.
    #[expect(
        unsafe_code,
        reason = "only the device owner may authorize PFN-list and ring retirement after observed reset"
    )]
    pub(super) unsafe fn advance_stop(&mut self) -> KapiResult<bool> {
        // SAFETY: the caller's acknowledged reset covers this retained list.
        if !unsafe { self.list.advance_retirement()? } {
            return Ok(false);
        }
        let previous = core::mem::replace(&mut self.ring, Ring::Transitioning);
        let (next, result) = match previous {
            Ring::Planned => (Ring::Closed, Ok(true)),
            Ring::Cpu(memory) => (Ring::Releasing(memory), Ok(false)),
            Ring::Prepared(ring) => match ring.abort() {
                Ok(memory) => (Ring::Releasing(memory), Ok(false)),
                Err(failure) => {
                    let (cause, memory) = failure.into_parts();
                    (Ring::PrepareFailed(memory), Err(dma_error(cause)))
                }
            },
            Ring::PrepareFailed(memory) => match memory.abort() {
                Ok(memory) => (Ring::Releasing(memory), Ok(false)),
                Err(failure) => {
                    let (cause, memory) = failure.into_parts();
                    (Ring::PrepareFailed(memory), Err(dma_error(cause)))
                }
            },
            Ring::Active(ring) => {
                // SAFETY: list retirement completed under the same held reset;
                // this step retires only the retained shared ring allocation.
                let witness = unsafe {
                    DmaQuiesceWitness::after_queue_quiesced(self.identity, ring.lease_id())
                };
                match ring.quiesce(witness) {
                    Ok(ring) => (Ring::Retired(ring), Ok(false)),
                    Err(failure) => (Ring::Active(failure.queue), Err(dma_error(failure.cause))),
                }
            }
            Ring::Retired(mut ring) => {
                for _ in 0..self.layout.size() {
                    if ring.next_aborted().is_none() {
                        break;
                    }
                }
                (Ring::Releasing(ring.memory), Ok(false))
            }
            Ring::Releasing(memory) => match memory.close() {
                Ok(()) => (Ring::Closed, Ok(true)),
                Err(failure) => {
                    let cause = failure.cause();
                    (Ring::CloseFailed(failure), Err(dma_error(cause)))
                }
            },
            Ring::CloseFailed(failure) => {
                let (_, memory) = failure.into_parts();
                match memory.retry_close() {
                    Ok(()) => (Ring::Closed, Ok(true)),
                    Err(failure) => {
                        let cause = failure.cause();
                        (Ring::CloseFailed(failure), Err(dma_error(cause)))
                    }
                }
            }
            Ring::Closed => (Ring::Closed, Ok(true)),
            Ring::Transitioning => (Ring::Transitioning, Err(KapiError::Busy)),
        };
        self.ring = next;
        result
    }
}
fn build_failure(failure: QueueBuildError) -> Ring {
    match failure {
        QueueBuildError::DescriptorLimit { memory }
        | QueueBuildError::MetadataAllocation { memory }
        | QueueBuildError::Memory(
            QueuePrepareError::InvalidMemory { memory } | QueuePrepareError::Cpu { memory, .. },
        ) => Ring::Cpu(memory),
        QueueBuildError::Memory(QueuePrepareError::Prepared { memory, .. }) => {
            Ring::PrepareFailed(memory)
        }
    }
}
