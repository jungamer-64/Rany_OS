//! Each queue admits one protocol operation at a time. The ring owns accepted
//! command metadata; a consumed completion keeps its protocol slot through any
//! response-read failure. Stop retires protocol RAM before ring RAM.
#![deny(unsafe_code)]

use super::memory::{SharedAllocation, dma_error};
use super::protocol::{
    self, DISPLAY_BYTES, REQUEST_BYTES, Reply, ReplyError, Response, WireCommand,
};
use crate::core::{
    PreparedSplitVirtQueue, QueueBuildError, QueueCommandActivationError, QueueCompletion,
    QueueSegment, QueueSubmitCause, QueueSubmitOutcome, RetiredVirtQueue, SplitVirtQueue,
};
use crate::queue_memory::{QueueInterrupt, QueuePrepareError, SplitQueueLayout};
use crate::transport::VirtioTransport;
use kernel_api::dma::*;
use kernel_api::{KapiError, KapiResult};

const RESPONSE_OFFSET: usize = REQUEST_BYTES;
enum Ring {
    Planned,
    Cpu(CpuDmaLease),
    Prepared(PreparedSplitVirtQueue<Command>),
    FailedPreparation(PreparedSharedDmaLease),
    Active(SplitVirtQueue<Command>),
    Retired(RetiredVirtQueue<Command>),
    Releasing(CpuDmaLease),
    CloseFailed(DmaCloseError),
    Closed,
    Transitioning,
}
struct Command {
    fence: u64,
    response: Response,
}

pub(super) enum PollError {
    Ring,
    Access(DmaLeaseError),
    Response(ReplyError),
}

pub(super) struct CommandQueue {
    identity: DmaQueueIdentity,
    layout: SplitQueueLayout,
    ring_request: DmaAllocationRequest,
    interrupt: QueueInterrupt,
    protocol: SharedAllocation,
    ring: Ring,
    completion: Option<QueueCompletion<Command>>,
}

impl CommandQueue {
    pub(super) fn new(
        identity: DmaQueueIdentity,
        maximum: u16,
        interrupt: QueueInterrupt,
    ) -> KapiResult<Self> {
        let limit = maximum.min(32);
        if limit < 2 {
            return Err(KapiError::NotSupported);
        }
        let layout = SplitQueueLayout::new(1u16 << (15 - limit.leading_zeros()))
            .map_err(|_| KapiError::InvalidSize)?;
        Ok(Self {
            identity,
            layout,
            ring_request: DmaAllocationRequest::new(
                layout.byte_count(),
                DmaDirection::Bidirectional,
            )
            .ok_or(KapiError::InvalidSize)?,
            interrupt,
            protocol: SharedAllocation::new(identity, REQUEST_BYTES + DISPLAY_BYTES)?,
            ring: Ring::Planned,
            completion: None,
        })
    }
    pub(super) fn advance_boot(&mut self, transport: &dyn VirtioTransport) -> KapiResult<bool> {
        if !self.protocol.advance_boot()? {
            return Ok(false);
        }
        let ring = core::mem::replace(&mut self.ring, Ring::Transitioning);
        let (next, result) = match ring {
            Ring::Planned => match kernel_api::service::kernel::instance()
                .alloc_dma_for_device(self.ring_request, self.identity.device())
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
                Err(failure) => (failed_preparation(failure), Err(KapiError::IoError)),
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

    /// The device owner establishes DRIVER_OK before this operation.
    #[expect(
        unsafe_code,
        reason = "the accepted command retains its queue-generation protocol allocation and excludes conflicting CPU writes"
    )]
    pub(super) fn submit(&mut self, wire: WireCommand) -> KapiResult<QueueSubmitOutcome> {
        let Ring::Active(ring) = &mut self.ring else {
            return Err(KapiError::Busy);
        };
        if ring.pending_count() != 0 || self.completion.is_some() {
            return Err(KapiError::Busy);
        }
        let address = self.protocol.address()?;
        let bytes = wire.bytes();
        let mut window = self
            .protocol
            .memory()
            .and_then(|memory| memory.window(0, bytes.len()))
            .map_err(dma_error)?;
        for (index, byte) in bytes.iter().copied().enumerate() {
            window.write_u8(index, byte).map_err(dma_error)?;
        }
        let request = segment(address, 0, bytes.len(), false)?;
        let response_length = wire.response.byte_count();
        let command = Command {
            fence: wire.fence,
            response: wire.response,
        };
        let response = segment(address, RESPONSE_OFFSET, response_length, true)?;
        let segments = [request, response];
        // SAFETY: admitted protocol RAM belongs to this exact device/generation
        // and remains owned through terminal completion/reset. Only an idle
        // queue permits writing the request slot; response RAM is read only after
        // the matching used entry and fence response have been validated.
        unsafe {
            ring.publish(&segments, command, |command| {
                Ok::<_, QueueCommandActivationError<Command, core::convert::Infallible>>(command)
            })
        }
        .map_err(|failure| match failure.cause {
            QueueSubmitCause::Admission(crate::core::QueueAdmissionError::QueueFull) => {
                KapiError::Busy
            }
            QueueSubmitCause::Admission(_) => KapiError::IoError,
            QueueSubmitCause::Activation(never) => match never {},
        })
    }

    pub(super) fn poll(&mut self) -> Result<Option<Reply>, PollError> {
        let Ring::Active(ring) = &mut self.ring else {
            return Err(PollError::Ring);
        };
        if self.completion.is_none() {
            self.completion = ring.poll_completion().map_err(|_| PollError::Ring)?;
        }
        deliver_reply(&mut self.completion, |bytes| {
            let window = self
                .protocol
                .memory()
                .and_then(|memory| memory.window(RESPONSE_OFFSET, bytes.len()))?;
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = window.read_u8(index)?;
            }
            Ok(())
        })
    }

    /// # Safety
    /// Device reset has been observed and fenced. The owner holds reset across
    /// retries, including partially configured queue and protocol allocations.
    #[expect(
        unsafe_code,
        reason = "only the unique device owner may authorize exact-generation queue retirement after observed reset"
    )]
    pub(super) unsafe fn advance_stop(&mut self) -> KapiResult<bool> {
        // SAFETY: the caller's observed reset covers this allocation and ring.
        if !unsafe { self.protocol.advance_retirement()? } {
            return Ok(false);
        }
        let ring = core::mem::replace(&mut self.ring, Ring::Transitioning);
        let (next, result) = match ring {
            Ring::Planned => (Ring::Closed, Ok(true)),
            Ring::Cpu(memory) => (Ring::Releasing(memory), Ok(false)),
            Ring::Prepared(ring) => match ring.abort() {
                Ok(memory) => (Ring::Releasing(memory), Ok(false)),
                Err(failure) => {
                    let (cause, memory) = failure.into_parts();
                    (Ring::FailedPreparation(memory), Err(dma_error(cause)))
                }
            },
            Ring::FailedPreparation(memory) => match memory.abort() {
                Ok(memory) => (Ring::Releasing(memory), Ok(false)),
                Err(failure) => {
                    let (cause, memory) = failure.into_parts();
                    (Ring::FailedPreparation(memory), Err(dma_error(cause)))
                }
            },
            Ring::Active(ring) => {
                // SAFETY: acknowledged reset covers this retained ring identity;
                // protocol RAM already completed its separate retirement.
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
                self.completion = None;
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
fn deliver_reply(
    completion: &mut Option<QueueCompletion<Command>>,
    read: impl FnOnce(&mut [u8]) -> Result<(), DmaLeaseError>,
) -> Result<Option<Reply>, PollError> {
    let Some(record) = completion.as_ref() else {
        return Ok(None);
    };
    let count = record.written_bytes as usize;
    if count > record.owner.response.byte_count() {
        return Err(PollError::Response(ReplyError::Protocol));
    }
    let mut bytes = [0; DISPLAY_BYTES];
    if count != 0 {
        read(&mut bytes[..count]).map_err(PollError::Access)?;
    }
    let reply = protocol::decode(&bytes[..count], record.owner.fence, record.owner.response)
        .map_err(PollError::Response)?;
    // No fallible operation follows consumption. A failed read or mismatched
    // response retains the consumed completion and denies slot reuse.
    *completion = None;
    Ok(Some(reply))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_read_retry_keeps_the_same_command_and_terminal_slot() {
        let mut completion = Some(QueueCompletion {
            head: 0,
            written_bytes: 24,
            owner: Command {
                fence: 7,
                response: Response::Header,
            },
        });
        assert!(matches!(
            deliver_reply(&mut completion, |_| Err(DmaLeaseError::IommuFailure)),
            Err(PollError::Access(DmaLeaseError::IommuFailure))
        ));
        assert_eq!(completion.as_ref().unwrap().owner.fence, 7);
        assert!(matches!(
            deliver_reply(&mut completion, |bytes| {
                bytes.fill(0);
                bytes[1] = 0x11;
                bytes[4] = 1;
                bytes[8] = 7;
                Ok(())
            }),
            Ok(Some(Reply::Done))
        ));
        assert!(completion.is_none());
        assert!(matches!(
            deliver_reply(&mut completion, |_| panic!(
                "acknowledged response cannot replay"
            )),
            Ok(None)
        ));
    }

    #[test]
    fn foreign_fence_retains_the_command_for_reset_without_reusing_protocol_ram() {
        let mut completion = Some(QueueCompletion {
            head: 0,
            written_bytes: 24,
            owner: Command {
                fence: 7,
                response: Response::Header,
            },
        });
        assert!(matches!(
            deliver_reply(&mut completion, |bytes| {
                bytes.fill(0);
                bytes[1] = 0x11;
                bytes[4] = 1;
                bytes[8] = 8;
                Ok(())
            }),
            Err(PollError::Response(ReplyError::Protocol))
        ));
        assert_eq!(completion.as_ref().unwrap().owner.fence, 7);
    }
}
fn segment(
    address: DmaDeviceAddress,
    offset: usize,
    bytes: usize,
    writable: bool,
) -> KapiResult<QueueSegment> {
    QueueSegment::new(
        address
            .checked_add(offset)
            .ok_or(KapiError::InvalidAddress)?,
        DmaByteCount::new(bytes).ok_or(KapiError::InvalidSize)?,
        writable,
    )
    .map_err(|_| KapiError::InvalidSize)
}
fn failed_preparation(failure: QueueBuildError) -> Ring {
    match failure {
        QueueBuildError::DescriptorLimit { memory }
        | QueueBuildError::MetadataAllocation { memory }
        | QueueBuildError::Memory(
            QueuePrepareError::InvalidMemory { memory } | QueuePrepareError::Cpu { memory, .. },
        ) => Ring::Cpu(memory),
        QueueBuildError::Memory(QueuePrepareError::Prepared { memory, .. }) => {
            Ring::FailedPreparation(memory)
        }
    }
}
