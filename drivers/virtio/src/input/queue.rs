//! Event/status RAM is shared only through scalar access. An accepted head owns
//! one event slot until validated completion or observed device reset.
#![deny(unsafe_code)]

use super::VirtioInputEvent;
use crate::core::{
    PreparedSplitVirtQueue, QueueBuildError, QueueCommandActivationError, QueueCompletion,
    QueueSegment, QueueSubmitCause, QueueSubmitOutcome, RetiredVirtQueue, SplitVirtQueue,
};
use crate::queue_memory::{QueueInterrupt, QueuePrepareError, SplitQueueLayout};
use crate::transport::VirtioTransport;
use kernel_api::dma::*;
use kernel_api::{KapiError, KapiResult};

const EVENT_BYTES: usize = 8;
const SLOT_LIMIT: usize = 128;

pub(super) enum InputPollError {
    Ring(crate::core::QueueFault),
    Event(DmaLeaseError),
    InvalidSlot,
    EventLength,
}

impl InputPollError {
    pub(super) fn retryable(&self) -> bool {
        matches!(self, Self::Event(_))
    }
    pub(super) fn cause(self) -> KapiError {
        match self {
            Self::Event(cause) | Self::Ring(crate::core::QueueFault::Dma(cause)) => {
                dma_error(cause)
            }
            _ => KapiError::IoError,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum QueueRole {
    Receive,
    Status,
}

enum Memory {
    Cpu(CpuDmaLease),
    Prepared(PreparedSharedDmaLease),
    CloseFailed(DmaCloseError),
}
struct Releasing {
    ring: Option<Memory>,
    events: Option<Memory>,
}

// The validated address travels with the immutable allocation owner. Shared
// state deliberately cannot reacquire a general descriptor capability.
struct EventRam {
    address: DmaDeviceAddress,
    memory: SharedDmaLease,
}

enum Stage {
    Planned,
    RingAllocated(CpuDmaLease),
    DataPrepared {
        ring: CpuDmaLease,
        data: PreparedSharedDmaLease,
    },
    PrepareFailed {
        ring: Memory,
        data: Memory,
    },
    Prepared {
        ring: PreparedSplitVirtQueue<usize>,
        data: PreparedSharedDmaLease,
    },
    Partial {
        ring: PreparedSplitVirtQueue<usize>,
        data: EventRam,
    },
    Active {
        ring: SplitVirtQueue<usize>,
        data: EventRam,
    },
    DataRetired {
        ring: SplitVirtQueue<usize>,
        data: CpuDmaLease,
    },
    Retired {
        ring: RetiredVirtQueue<usize>,
        data: CpuDmaLease,
    },
    Releasing(Releasing),
    Closed,
    Transitioning,
}

pub(super) struct InputQueue {
    identity: DmaQueueIdentity,
    layout: SplitQueueLayout,
    role: QueueRole,
    interrupt: QueueInterrupt,
    stage: Stage,
    // Derived slot index. Accepted heads in Stage::Active remain authoritative;
    // publication and acknowledged completion update this index exactly once.
    occupied: [bool; SLOT_LIMIT],
    // A used entry can be consumed before its scalar event read succeeds.
    completion: Option<QueueCompletion<usize>>,
}

impl InputQueue {
    pub(super) fn new(
        identity: DmaQueueIdentity,
        maximum: u16,
        role: QueueRole,
        interrupt: QueueInterrupt,
    ) -> KapiResult<Self> {
        let limit = maximum.min(SLOT_LIMIT as u16);
        if limit == 0 {
            return Err(KapiError::NotSupported);
        }
        let descriptors = 1u16 << (15 - limit.leading_zeros());
        let layout = SplitQueueLayout::new(descriptors).map_err(|_| KapiError::InvalidSize)?;
        Ok(Self {
            identity,
            layout,
            role,
            interrupt,
            stage: Stage::Planned,
            occupied: [false; SLOT_LIMIT],
            completion: None,
        })
    }

    pub(super) fn advance_boot(&mut self, transport: &dyn VirtioTransport) -> KapiResult<bool> {
        let stage = core::mem::replace(&mut self.stage, Stage::Transitioning);
        let (next, result) = match stage {
            Stage::Planned => match allocate(self.identity, self.layout.byte_count()) {
                Ok(ring) => (Stage::RingAllocated(ring), Ok(false)),
                Err(cause) => (Stage::Planned, Err(cause)),
            },
            Stage::RingAllocated(ring) => {
                match allocate(self.identity, usize::from(self.layout.size()) * EVENT_BYTES) {
                    Err(cause) => (Stage::RingAllocated(ring), Err(cause)),
                    Ok(mut data) => match data.write(|bytes| bytes.fill(0)) {
                        Err(cause) => {
                            log::warn!("VirtIO input event initialization retained: {cause:?}");
                            (
                                Stage::PrepareFailed {
                                    ring: Memory::Cpu(ring),
                                    data: Memory::Cpu(data),
                                },
                                Err(KapiError::IoError),
                            )
                        }
                        Ok(()) => match data.prepare_shared(self.identity) {
                            Ok(data) => (Stage::DataPrepared { ring, data }, Ok(false)),
                            Err(failure) => {
                                let (cause, data) = failure.into_parts();
                                log::warn!("VirtIO input RAM preparation retained: {cause:?}");
                                (
                                    Stage::PrepareFailed {
                                        ring: Memory::Cpu(ring),
                                        data: Memory::Cpu(data),
                                    },
                                    Err(KapiError::IoError),
                                )
                            }
                        },
                    },
                }
            }
            Stage::DataPrepared { ring, data } => match PreparedSplitVirtQueue::prepare(
                self.identity,
                self.layout,
                self.interrupt,
                ring,
            ) {
                Ok(ring) => (Stage::Prepared { ring, data }, Ok(false)),
                Err(cause) => (
                    Stage::PrepareFailed {
                        ring: build_error(cause),
                        data: Memory::Prepared(data),
                    },
                    Err(KapiError::IoError),
                ),
            },
            Stage::Prepared { ring, data } => {
                let address = data.descriptor().and_then(|descriptor| {
                    let address = descriptor.device_address();
                    let bytes = usize::from(self.layout.size()) * EVENT_BYTES;
                    if descriptor.queue() != self.identity
                        || descriptor.byte_count().get() < bytes
                        || address.get() == 0
                        || !address.get().is_multiple_of(EVENT_BYTES as u64)
                        || address.checked_add(bytes).is_none()
                    {
                        Err(DmaLeaseError::InvalidRange)
                    } else {
                        Ok(address)
                    }
                });
                match address {
                    Err(cause) => (Stage::Prepared { ring, data }, Err(dma_error(cause))),
                    Ok(address) => match data.activate() {
                        Ok(memory) => (
                            Stage::Partial {
                                ring,
                                data: EventRam { address, memory },
                            },
                            Ok(false),
                        ),
                        Err(failure) => {
                            let (cause, data) = failure.into_parts();
                            log::warn!("VirtIO input RAM activation retained: {cause:?}");
                            (Stage::Prepared { ring, data }, Err(KapiError::IoError))
                        }
                    },
                }
            }
            Stage::Partial { ring, data } => match ring.activate(transport) {
                Ok(ring) => (Stage::Active { ring, data }, Ok(true)),
                Err(failure) => (
                    Stage::Partial {
                        ring: failure.queue,
                        data,
                    },
                    Err(KapiError::IoError),
                ),
            },
            Stage::Active { ring, data } => (Stage::Active { ring, data }, Ok(true)),
            other => (other, Err(KapiError::Busy)),
        };
        self.stage = next;
        result
    }

    /// Called only after DRIVER_OK. Every accepted descriptor owns its exact
    /// RAM slot, including uncertain publication, until completion/reset.
    #[expect(
        unsafe_code,
        reason = "this private device operation publishes scalar event slots backed by the queue's retained shared DMA lease"
    )]
    fn publish(&mut self, event: Option<VirtioInputEvent>) -> KapiResult<QueueSubmitOutcome> {
        let Stage::Active { ring, data } = &mut self.stage else {
            return Err(KapiError::Busy);
        };
        let slot = self.occupied[..usize::from(self.layout.size())]
            .iter()
            .position(|busy| !busy)
            .ok_or(KapiError::Busy)?;
        let offset = slot * EVENT_BYTES;
        let writable = matches!(self.role, QueueRole::Receive);
        let address = data
            .address
            .checked_add(offset)
            .ok_or(KapiError::InvalidAddress)?;
        if data.memory.byte_count().get() < offset + EVENT_BYTES {
            return Err(KapiError::InvalidSize);
        }
        if let Some(event) = event {
            data.memory
                .window(offset, EVENT_BYTES)
                .and_then(|mut window| window.write_u64(0, encode_event(event)))
                .map_err(dma_error)?;
        }
        let segment = QueueSegment::new(
            address,
            DmaByteCount::new(EVENT_BYTES).ok_or(KapiError::InvalidSize)?,
            writable,
        )
        .map_err(|_| KapiError::InvalidSize)?;
        // SAFETY: the shared RAM is admitted for this exact queue generation;
        // slot index excludes conflicting CPU writes until this head completes.
        // The device owner establishes DRIVER_OK before calling publication.
        let outcome = unsafe {
            ring.publish(&[segment], slot, |slot| {
                Ok::<_, QueueCommandActivationError<usize, core::convert::Infallible>>(slot)
            })
        }
        .map_err(|failure| match failure.cause {
            QueueSubmitCause::Admission(crate::core::QueueAdmissionError::QueueFull) => {
                KapiError::Busy
            }
            QueueSubmitCause::Admission(_) => KapiError::IoError,
            QueueSubmitCause::Activation(never) => match never {},
        })?;
        self.occupied[slot] = true;
        Ok(outcome)
    }

    pub(super) fn refill(&mut self) -> KapiResult<()> {
        for _ in 0..self.layout.size() {
            if self.occupied[..usize::from(self.layout.size())]
                .iter()
                .all(|busy| *busy)
            {
                return Ok(());
            }
            if matches!(
                self.publish(None)?,
                QueueSubmitOutcome::PublicationUncertain { .. }
            ) {
                return Err(KapiError::IoError);
            }
        }
        Ok(())
    }

    pub(super) fn submit_status(
        &mut self,
        event: VirtioInputEvent,
    ) -> KapiResult<QueueSubmitOutcome> {
        self.publish(Some(event))
    }

    pub(super) fn poll(&mut self) -> Result<Option<VirtioInputEvent>, InputPollError> {
        let Stage::Active { ring, data } = &mut self.stage else {
            return Err(InputPollError::InvalidSlot);
        };
        if self.completion.is_none() {
            self.completion = ring.poll_completion().map_err(InputPollError::Ring)?;
        }
        deliver_event(
            &mut self.completion,
            &mut self.occupied,
            self.role,
            |slot| {
                data.memory
                    .window(slot * EVENT_BYTES, EVENT_BYTES)
                    .and_then(|window| window.read_u64(0))
            },
        )
    }

    pub(super) fn set_interrupts_enabled(&mut self, enabled: bool) -> KapiResult<()> {
        let Stage::Active { ring, .. } = &mut self.stage else {
            return Err(KapiError::Busy);
        };
        ring.set_interrupts_enabled(enabled).map_err(dma_error)
    }

    /// # Safety
    /// The owning device must remain in an observed, acknowledged reset. All
    /// event/status and ring DMA for this exact generation must have stopped.
    #[expect(
        unsafe_code,
        reason = "only the device owner can establish reset acknowledgement before retiring these exact queue and event allocations"
    )]
    pub(super) unsafe fn advance_stop(&mut self) -> KapiResult<bool> {
        let stage = core::mem::replace(&mut self.stage, Stage::Transitioning);
        let (next, result) = match stage {
            Stage::Planned => (Stage::Closed, Ok(true)),
            Stage::RingAllocated(ring) => (
                Stage::Releasing(Releasing {
                    ring: Some(Memory::Cpu(ring)),
                    events: None,
                }),
                Ok(false),
            ),
            Stage::DataPrepared { ring, data } => (
                Stage::Releasing(Releasing {
                    ring: Some(Memory::Cpu(ring)),
                    events: Some(Memory::Prepared(data)),
                }),
                Ok(false),
            ),
            Stage::PrepareFailed { ring, data } => (
                Stage::Releasing(Releasing {
                    ring: Some(ring),
                    events: Some(data),
                }),
                Ok(false),
            ),
            Stage::Prepared { ring, data } => (
                Stage::Releasing(Releasing {
                    ring: Some(abort_ring(ring)),
                    events: Some(Memory::Prepared(data)),
                }),
                Ok(false),
            ),
            Stage::Partial { ring, data } => {
                // SAFETY: acknowledged reset and this retained allocation identity
                // cover event RAM; the ring was never exposed to hardware.
                let witness = unsafe {
                    DmaQuiesceWitness::after_queue_quiesced(self.identity, data.memory.lease_id())
                };
                let EventRam { address, memory } = data;
                match memory.quiesce(witness) {
                    Ok(data) => (
                        Stage::Releasing(Releasing {
                            ring: Some(abort_ring(ring)),
                            events: Some(Memory::Cpu(data)),
                        }),
                        Ok(false),
                    ),
                    Err(failure) => {
                        let (_, memory) = failure.into_parts();
                        (
                            Stage::Partial {
                                ring,
                                data: EventRam { address, memory },
                            },
                            Err(KapiError::IoError),
                        )
                    }
                }
            }
            Stage::Active { ring, data } => {
                // SAFETY: the owning device has acknowledged reset and fenced
                // this queue generation's event and status memory accesses.
                let witness = unsafe {
                    DmaQuiesceWitness::after_queue_quiesced(self.identity, data.memory.lease_id())
                };
                let EventRam { address, memory } = data;
                match memory.quiesce(witness) {
                    Ok(data) => (Stage::DataRetired { ring, data }, Ok(false)),
                    Err(failure) => {
                        let (_, memory) = failure.into_parts();
                        (
                            Stage::Active {
                                ring,
                                data: EventRam { address, memory },
                            },
                            Err(KapiError::IoError),
                        )
                    }
                }
            }
            Stage::DataRetired { ring, data } => {
                // SAFETY: reset is still held; event RAM is CPU-owned already.
                // This retry retires only the remaining shared ring allocation.
                let witness = unsafe {
                    DmaQuiesceWitness::after_queue_quiesced(self.identity, ring.lease_id())
                };
                match ring.quiesce(witness) {
                    Ok(ring) => (Stage::Retired { ring, data }, Ok(false)),
                    Err(failure) => (
                        Stage::DataRetired {
                            ring: failure.queue,
                            data,
                        },
                        Err(KapiError::IoError),
                    ),
                }
            }
            Stage::Retired { mut ring, data } => {
                // Tokens own scalar coordinates only; reset, not completion,
                // ended their device access. No input event is manufactured.
                for _ in 0..self.layout.size() {
                    if ring.next_aborted().is_none() {
                        break;
                    }
                }
                self.completion = None;
                (
                    Stage::Releasing(Releasing {
                        ring: Some(Memory::Cpu(ring.memory)),
                        events: Some(Memory::Cpu(data)),
                    }),
                    Ok(false),
                )
            }
            Stage::Releasing(mut release) => match release.advance() {
                Ok(true) => (Stage::Closed, Ok(true)),
                Ok(false) => (Stage::Releasing(release), Ok(false)),
                Err(cause) => (Stage::Releasing(release), Err(dma_error(cause))),
            },
            Stage::Closed => (Stage::Closed, Ok(true)),
            Stage::Transitioning => (Stage::Transitioning, Err(KapiError::Busy)),
        };
        self.stage = next;
        result
    }
}

fn deliver_event(
    completion: &mut Option<QueueCompletion<usize>>,
    occupied: &mut [bool],
    role: QueueRole,
    read: impl FnOnce(usize) -> Result<u64, DmaLeaseError>,
) -> Result<Option<VirtioInputEvent>, InputPollError> {
    let Some(record) = completion.as_ref() else {
        return Ok(None);
    };
    let Some(occupied) = occupied.get_mut(record.owner).filter(|busy| **busy) else {
        return Err(InputPollError::InvalidSlot);
    };
    let event = if matches!(role, QueueRole::Receive) {
        if record.written_bytes != EVENT_BYTES as u32 {
            return Err(InputPollError::EventLength);
        }
        Some(decode_event(
            read(record.owner).map_err(InputPollError::Event)?,
        ))
    } else {
        None
    };
    // No fallible operation follows consumption. Read failure keeps both the
    // terminal completion and slot for an exactly-once retry.
    *occupied = false;
    *completion = None;
    Ok(event)
}

impl Releasing {
    fn advance(&mut self) -> Result<bool, DmaLeaseError> {
        let slot = if self.ring.is_some() {
            &mut self.ring
        } else {
            &mut self.events
        };
        let Some(memory) = slot.take() else {
            return Ok(true);
        };
        match memory {
            Memory::Cpu(memory) => {
                if let Err(failure) = memory.close() {
                    let cause = failure.cause();
                    *slot = Some(Memory::CloseFailed(failure));
                    return Err(cause);
                }
            }
            Memory::Prepared(memory) => match memory.abort() {
                Ok(memory) => *slot = Some(Memory::Cpu(memory)),
                Err(failure) => {
                    let (cause, memory) = failure.into_parts();
                    *slot = Some(Memory::Prepared(memory));
                    return Err(cause);
                }
            },
            Memory::CloseFailed(failure) => {
                let (_, memory) = failure.into_parts();
                if let Err(failure) = memory.retry_close() {
                    let cause = failure.cause();
                    *slot = Some(Memory::CloseFailed(failure));
                    return Err(cause);
                }
            }
        }
        Ok(self.ring.is_none() && self.events.is_none())
    }
}
fn build_error(cause: QueueBuildError) -> Memory {
    match cause {
        QueueBuildError::DescriptorLimit { memory }
        | QueueBuildError::MetadataAllocation { memory } => Memory::Cpu(memory),
        QueueBuildError::Memory(
            QueuePrepareError::InvalidMemory { memory } | QueuePrepareError::Cpu { memory, .. },
        ) => Memory::Cpu(memory),
        QueueBuildError::Memory(QueuePrepareError::Prepared { memory, .. }) => {
            Memory::Prepared(memory)
        }
    }
}
fn abort_ring(ring: PreparedSplitVirtQueue<usize>) -> Memory {
    match ring.abort() {
        Ok(memory) => Memory::Cpu(memory),
        Err(failure) => {
            let (_, memory) = failure.into_parts();
            Memory::Prepared(memory)
        }
    }
}
fn allocate(identity: DmaQueueIdentity, bytes: usize) -> KapiResult<CpuDmaLease> {
    kernel_api::service::kernel::instance().alloc_dma_for_device(
        DmaAllocationRequest::new(bytes, DmaDirection::Bidirectional)
            .ok_or(KapiError::InvalidSize)?,
        identity.device(),
    )
}
fn dma_error(cause: DmaLeaseError) -> KapiError {
    match cause {
        DmaLeaseError::InvalidRange => KapiError::InvalidSize,
        DmaLeaseError::InvalidAlignment => KapiError::InvalidAlignment,
        DmaLeaseError::ForeignOwner => KapiError::PermissionDenied,
        DmaLeaseError::NotSupported => KapiError::NotSupported,
        _ => KapiError::IoError,
    }
}

pub(super) fn encode_event(event: VirtioInputEvent) -> u64 {
    u64::from(event.type_) | (u64::from(event.code) << 16) | (u64::from(event.value) << 32)
}
pub(super) fn decode_event(word: u64) -> VirtioInputEvent {
    VirtioInputEvent {
        type_: word as u16,
        code: (word >> 16) as u16,
        value: (word >> 32) as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_read_failure_keeps_the_completion_and_slot_until_delivery() {
        let mut completion = Some(QueueCompletion {
            head: 0,
            written_bytes: 8,
            owner: 1,
        });
        let mut occupied = [false, true];
        assert!(matches!(
            deliver_event(&mut completion, &mut occupied, QueueRole::Receive, |slot| {
                assert_eq!(slot, 1);
                Err(DmaLeaseError::IommuFailure)
            }),
            Err(InputPollError::Event(DmaLeaseError::IommuFailure))
        ));
        assert!(occupied[1]);
        assert_eq!(completion.as_ref().unwrap().owner, 1);
        let delivered = deliver_event(&mut completion, &mut occupied, QueueRole::Receive, |_| {
            Ok(u64::from_le_bytes([1, 0, 30, 0, 1, 0, 0, 0]))
        })
        .unwrap_or_else(|_| panic!("the same completed event must remain readable"));
        assert_eq!(
            delivered,
            Some(VirtioInputEvent {
                type_: 1,
                code: 30,
                value: 1
            })
        );
        assert!(!occupied[1]);
        assert!(completion.is_none());
        assert_eq!(
            deliver_event(
                &mut completion,
                &mut occupied,
                QueueRole::Receive,
                |_| panic!("event was delivered")
            )
            .unwrap_or_else(|_| panic!("empty queue must be successful")),
            None
        );
    }

    #[test]
    fn truncated_event_does_not_read_ram_or_release_its_slot() {
        let mut completion = Some(QueueCompletion {
            head: 0,
            written_bytes: 7,
            owner: 0,
        });
        let mut occupied = [true];
        assert!(matches!(
            deliver_event(
                &mut completion,
                &mut occupied,
                QueueRole::Receive,
                |_| panic!("invalid extent")
            ),
            Err(InputPollError::EventLength)
        ));
        assert!(completion.is_some());
        assert!(occupied[0]);
    }

    #[test]
    fn status_completion_releases_the_slot_without_manufacturing_an_event() {
        let mut completion = Some(QueueCompletion {
            head: 0,
            written_bytes: 0,
            owner: 0,
        });
        let mut occupied = [true];
        assert_eq!(
            deliver_event(
                &mut completion,
                &mut occupied,
                QueueRole::Status,
                |_| panic!("status is device-readable")
            )
            .unwrap_or_else(|_| panic!("valid status completion")),
            None
        );
        assert!(completion.is_none());
        assert!(!occupied[0]);
    }
}
