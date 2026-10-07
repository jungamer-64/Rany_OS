//! Fixed byte slots are admitted before DRIVER_OK. Each accepted head excludes
//! CPU writes until completion; stop retains each RAM transition for retry.
#![deny(unsafe_code)]

use crate::core::{
    PreparedSplitVirtQueue, QueueBuildError, QueueCommandActivationError, QueueCompletion,
    QueueSegment, QueueSubmitCause, QueueSubmitOutcome, RetiredVirtQueue, SplitVirtQueue,
};
use crate::queue_memory::{QueueInterrupt, QueuePrepareError, SplitQueueLayout};
use crate::transport::VirtioTransport;
use kernel_api::dma::*;
use kernel_api::{KapiError, KapiResult};

const SLOT_LIMIT: usize = 16;
pub(super) const SLOT_BYTES: usize = 4096;

#[derive(Clone, Copy)]
pub(super) enum Direction {
    Receive,
    Transmit,
}

enum Allocation {
    Cpu(CpuDmaLease),
    Prepared(PreparedSharedDmaLease),
    Failed(DmaCloseError),
}
struct Ram {
    address: DmaDeviceAddress,
    memory: SharedDmaLease,
}
enum Stage {
    Planned,
    Ring(CpuDmaLease),
    Preparing {
        ring: CpuDmaLease,
        data: CpuDmaLease,
    },
    DataPrepared {
        ring: CpuDmaLease,
        data: PreparedSharedDmaLease,
    },
    FailedPreparation {
        ring: Allocation,
        data: Allocation,
    },
    Prepared {
        ring: PreparedSplitVirtQueue<usize>,
        data: PreparedSharedDmaLease,
    },
    Partial {
        ring: PreparedSplitVirtQueue<usize>,
        data: Ram,
    },
    Active {
        ring: SplitVirtQueue<usize>,
        data: Ram,
    },
    DataRetired {
        ring: SplitVirtQueue<usize>,
        data: CpuDmaLease,
    },
    Retired {
        ring: RetiredVirtQueue<usize>,
        data: CpuDmaLease,
    },
    Releasing {
        ring: Option<Allocation>,
        data: Option<Allocation>,
    },
    Closed,
    Transitioning,
}

struct ReadCursor {
    completion: QueueCompletion<usize>,
    offset: usize,
}

pub(super) struct StreamQueue {
    identity: DmaQueueIdentity,
    layout: SplitQueueLayout,
    direction: Direction,
    interrupt: QueueInterrupt,
    stage: Stage,
    // Projection of accepted heads plus the retained read cursor, maintained
    // by the same exclusive publication/completion transitions.
    occupied: [bool; SLOT_LIMIT],
    read: Option<ReadCursor>,
}

pub(super) enum ReadFailure {
    Queue(KapiError),
    Data { copied: usize, cause: KapiError },
}

impl StreamQueue {
    pub(super) fn new(
        identity: DmaQueueIdentity,
        maximum: u16,
        direction: Direction,
        interrupt: QueueInterrupt,
    ) -> KapiResult<Self> {
        let limit = maximum.min(SLOT_LIMIT as u16);
        if limit == 0 {
            return Err(KapiError::NotSupported);
        }
        let layout = SplitQueueLayout::new(1u16 << (15 - limit.leading_zeros()))
            .map_err(|_| KapiError::InvalidSize)?;
        Ok(Self {
            identity,
            layout,
            direction,
            interrupt,
            stage: Stage::Planned,
            occupied: [false; SLOT_LIMIT],
            read: None,
        })
    }

    pub(super) fn advance_boot(&mut self, transport: &dyn VirtioTransport) -> KapiResult<bool> {
        let stage = core::mem::replace(&mut self.stage, Stage::Transitioning);
        let (next, result) = match stage {
            Stage::Planned => match allocate(self.identity, self.layout.byte_count()) {
                Ok(ring) => (Stage::Ring(ring), Ok(false)),
                Err(cause) => (Stage::Planned, Err(cause)),
            },
            Stage::Ring(ring) => {
                match allocate(self.identity, usize::from(self.layout.size()) * SLOT_BYTES) {
                    Ok(data) => (Stage::Preparing { ring, data }, Ok(false)),
                    Err(cause) => (Stage::Ring(ring), Err(cause)),
                }
            }
            Stage::Preparing { ring, mut data } => match data.write(|bytes| bytes.fill(0)) {
                Err(cause) => (Stage::Preparing { ring, data }, Err(dma_error(cause))),
                Ok(()) => match data.prepare_shared(self.identity) {
                    Ok(data) => (Stage::DataPrepared { ring, data }, Ok(false)),
                    Err(failure) => {
                        let (cause, data) = failure.into_parts();
                        (Stage::Preparing { ring, data }, Err(dma_error(cause)))
                    }
                },
            },
            Stage::DataPrepared { ring, data } => match PreparedSplitVirtQueue::prepare(
                self.identity,
                self.layout,
                self.interrupt,
                ring,
            ) {
                Ok(ring) => (Stage::Prepared { ring, data }, Ok(false)),
                Err(failure) => (
                    Stage::FailedPreparation {
                        ring: failed_ring(failure),
                        data: Allocation::Prepared(data),
                    },
                    Err(KapiError::IoError),
                ),
            },
            Stage::Prepared { ring, data } => {
                let address = data.descriptor().and_then(|descriptor| {
                    let address = descriptor.device_address();
                    let bytes = usize::from(self.layout.size()) * SLOT_BYTES;
                    if descriptor.queue() != self.identity
                        || descriptor.byte_count().get() < bytes
                        || address.get() == 0
                        || !address.get().is_multiple_of(8)
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
                                data: Ram { address, memory },
                            },
                            Ok(false),
                        ),
                        Err(failure) => {
                            let (cause, data) = failure.into_parts();
                            (Stage::Prepared { ring, data }, Err(dma_error(cause)))
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

    /// The owner establishes DRIVER_OK before exposing any byte slot.
    #[expect(
        unsafe_code,
        reason = "the queue retains exact-generation shared RAM and excludes writes to each accepted byte slot"
    )]
    fn publish(&mut self, bytes: Option<&[u8]>) -> KapiResult<QueueSubmitOutcome> {
        let length = match (self.direction, bytes) {
            (Direction::Receive, None) => SLOT_BYTES,
            (Direction::Transmit, Some(bytes))
                if !bytes.is_empty() && bytes.len() <= SLOT_BYTES =>
            {
                bytes.len()
            }
            _ => return Err(KapiError::InvalidSize),
        };
        let Stage::Active { ring, data } = &mut self.stage else {
            return Err(KapiError::Busy);
        };
        let slot = self.occupied[..usize::from(self.layout.size())]
            .iter()
            .position(|busy| !busy)
            .ok_or(KapiError::Busy)?;
        let offset = slot * SLOT_BYTES;
        if let Some(bytes) = bytes {
            let mut window = data.memory.window(offset, length).map_err(dma_error)?;
            for (index, byte) in bytes.iter().copied().enumerate() {
                window.write_u8(index, byte).map_err(dma_error)?;
            }
        }
        let segment = QueueSegment::new(
            data.address
                .checked_add(offset)
                .ok_or(KapiError::InvalidAddress)?,
            DmaByteCount::new(length).ok_or(KapiError::InvalidSize)?,
            matches!(self.direction, Direction::Receive),
        )
        .map_err(|_| KapiError::InvalidSize)?;
        // SAFETY: the allocation and descriptor extent were admitted for this
        // generation before activation. Only this exclusive owner writes a free
        // slot; an accepted slot remains unavailable through completion/reset.
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

    pub(super) fn submit(&mut self, bytes: &[u8]) -> KapiResult<QueueSubmitOutcome> {
        self.publish(Some(bytes))
    }

    pub(super) fn drain_transmit(&mut self) -> KapiResult<()> {
        let Stage::Active { ring, .. } = &mut self.stage else {
            return Err(KapiError::Busy);
        };
        for _ in 0..self.layout.size() {
            let Some(completion) = ring.poll_completion().map_err(|_| KapiError::IoError)? else {
                break;
            };
            let slot = self
                .occupied
                .get_mut(completion.owner)
                .filter(|busy| **busy)
                .ok_or(KapiError::IoError)?;
            *slot = false;
        }
        Ok(())
    }

    pub(super) fn read(&mut self, output: &mut [u8]) -> Result<Option<usize>, ReadFailure> {
        if output.is_empty() {
            return Ok(None);
        }
        let Stage::Active { ring, data } = &mut self.stage else {
            return Err(ReadFailure::Queue(KapiError::Busy));
        };
        if self.read.is_none() {
            self.read = ring
                .poll_completion()
                .map_err(|_| ReadFailure::Queue(KapiError::IoError))?
                .map(|completion| ReadCursor {
                    completion,
                    offset: 0,
                });
        }
        read_bytes(
            &mut self.read,
            &mut self.occupied,
            output,
            |slot, offset| {
                data.memory
                    .window(slot * SLOT_BYTES + offset, 1)
                    .and_then(|window| window.read_u8(0))
            },
        )
    }

    pub(super) fn has_input(&mut self) -> KapiResult<bool> {
        let Stage::Active { ring, .. } = &mut self.stage else {
            return Err(KapiError::Busy);
        };
        if self.read.is_none() {
            self.read = ring
                .poll_completion()
                .map_err(|_| KapiError::IoError)?
                .map(|completion| ReadCursor {
                    completion,
                    offset: 0,
                });
        }
        Ok(self.read.is_some())
    }

    pub(super) fn set_interrupts_enabled(&mut self, enabled: bool) -> KapiResult<()> {
        let Stage::Active { ring, .. } = &mut self.stage else {
            return Err(KapiError::Busy);
        };
        ring.set_interrupts_enabled(enabled).map_err(dma_error)
    }

    /// # Safety
    /// The unique device owner has observed status zero and holds reset across
    /// retries; this generation's byte and ring RAM is unreachable by hardware.
    #[expect(
        unsafe_code,
        reason = "acknowledged function reset authorizes retirement of these retained RAM allocations"
    )]
    pub(super) unsafe fn advance_stop(&mut self) -> KapiResult<bool> {
        let stage = core::mem::replace(&mut self.stage, Stage::Transitioning);
        let (next, result) = match stage {
            Stage::Planned => (Stage::Closed, Ok(true)),
            Stage::Ring(ring) => (
                Stage::Releasing {
                    ring: Some(Allocation::Cpu(ring)),
                    data: None,
                },
                Ok(false),
            ),
            Stage::Preparing { ring, data } => (
                Stage::Releasing {
                    ring: Some(Allocation::Cpu(ring)),
                    data: Some(Allocation::Cpu(data)),
                },
                Ok(false),
            ),
            Stage::DataPrepared { ring, data } => (
                Stage::Releasing {
                    ring: Some(Allocation::Cpu(ring)),
                    data: Some(Allocation::Prepared(data)),
                },
                Ok(false),
            ),
            Stage::FailedPreparation { ring, data } => (
                Stage::Releasing {
                    ring: Some(ring),
                    data: Some(data),
                },
                Ok(false),
            ),
            Stage::Prepared { ring, data } => (
                Stage::Releasing {
                    ring: Some(abort_ring(ring)),
                    data: Some(Allocation::Prepared(data)),
                },
                Ok(false),
            ),
            Stage::Partial { ring, data } => {
                // SAFETY: reset is acknowledged for this retained identity;
                // prepared ring RAM has not been exposed to the device.
                let witness = unsafe {
                    DmaQuiesceWitness::after_queue_quiesced(self.identity, data.memory.lease_id())
                };
                let Ram { address, memory } = data;
                match memory.quiesce(witness) {
                    Ok(data) => (
                        Stage::Releasing {
                            ring: Some(abort_ring(ring)),
                            data: Some(Allocation::Cpu(data)),
                        },
                        Ok(false),
                    ),
                    Err(failure) => {
                        let (cause, memory) = failure.into_parts();
                        (
                            Stage::Partial {
                                ring,
                                data: Ram { address, memory },
                            },
                            Err(dma_error(cause)),
                        )
                    }
                }
            }
            Stage::Active { ring, data } => {
                // SAFETY: observed reset ended every device access to this exact
                // queue generation; CPU admission remains closed throughout.
                let witness = unsafe {
                    DmaQuiesceWitness::after_queue_quiesced(self.identity, data.memory.lease_id())
                };
                let Ram { address, memory } = data;
                match memory.quiesce(witness) {
                    Ok(data) => (Stage::DataRetired { ring, data }, Ok(false)),
                    Err(failure) => {
                        let (cause, memory) = failure.into_parts();
                        (
                            Stage::Active {
                                ring,
                                data: Ram { address, memory },
                            },
                            Err(dma_error(cause)),
                        )
                    }
                }
            }
            Stage::DataRetired { ring, data } => {
                // SAFETY: reset is still held. Byte RAM is already CPU-owned;
                // only the remaining ring allocation is retired on this retry.
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
                for _ in 0..self.layout.size() {
                    if ring.next_aborted().is_none() {
                        break;
                    }
                }
                self.read = None;
                (
                    Stage::Releasing {
                        ring: Some(Allocation::Cpu(ring.memory)),
                        data: Some(Allocation::Cpu(data)),
                    },
                    Ok(false),
                )
            }
            Stage::Releasing { mut ring, mut data } => {
                let result = if ring.is_some() {
                    close(&mut ring)
                } else {
                    close(&mut data)
                };
                match result {
                    Err(cause) => (Stage::Releasing { ring, data }, Err(dma_error(cause))),
                    Ok(()) if ring.is_none() && data.is_none() => (Stage::Closed, Ok(true)),
                    Ok(()) => (Stage::Releasing { ring, data }, Ok(false)),
                }
            }
            Stage::Closed => (Stage::Closed, Ok(true)),
            Stage::Transitioning => (Stage::Transitioning, Err(KapiError::Busy)),
        };
        self.stage = next;
        result
    }
}

fn read_bytes(
    cursor: &mut Option<ReadCursor>,
    occupied: &mut [bool],
    output: &mut [u8],
    mut read: impl FnMut(usize, usize) -> Result<u8, DmaLeaseError>,
) -> Result<Option<usize>, ReadFailure> {
    let Some(record) = cursor.as_mut() else {
        return Ok(None);
    };
    let length = record.completion.written_bytes as usize;
    let slot = record.completion.owner;
    if slot >= occupied.len() || !occupied[slot] || length > SLOT_BYTES || record.offset > length {
        return Err(ReadFailure::Queue(KapiError::IoError));
    }
    let count = output.len().min(length - record.offset);
    for (copied, destination) in output[..count].iter_mut().enumerate() {
        *destination = read(slot, record.offset).map_err(|cause| ReadFailure::Data {
            copied,
            cause: dma_error(cause),
        })?;
        record.offset += 1;
    }
    if record.offset == length {
        occupied[slot] = false;
        *cursor = None;
    }
    Ok(Some(count))
}

fn allocate(identity: DmaQueueIdentity, bytes: usize) -> KapiResult<CpuDmaLease> {
    kernel_api::service::kernel::instance().alloc_dma_for_device(
        DmaAllocationRequest::new(bytes, DmaDirection::Bidirectional)
            .ok_or(KapiError::InvalidSize)?,
        identity.device(),
    )
}
fn abort_ring(ring: PreparedSplitVirtQueue<usize>) -> Allocation {
    match ring.abort() {
        Ok(memory) => Allocation::Cpu(memory),
        Err(failure) => {
            let (_, memory) = failure.into_parts();
            Allocation::Prepared(memory)
        }
    }
}
fn failed_ring(failure: QueueBuildError) -> Allocation {
    match failure {
        QueueBuildError::DescriptorLimit { memory }
        | QueueBuildError::MetadataAllocation { memory }
        | QueueBuildError::Memory(
            QueuePrepareError::InvalidMemory { memory } | QueuePrepareError::Cpu { memory, .. },
        ) => Allocation::Cpu(memory),
        QueueBuildError::Memory(QueuePrepareError::Prepared { memory, .. }) => {
            Allocation::Prepared(memory)
        }
    }
}
fn close(slot: &mut Option<Allocation>) -> Result<(), DmaLeaseError> {
    let Some(memory) = slot.take() else {
        return Ok(());
    };
    match memory {
        Allocation::Cpu(memory) => {
            if let Err(failure) = memory.close() {
                let cause = failure.cause();
                *slot = Some(Allocation::Failed(failure));
                return Err(cause);
            }
        }
        Allocation::Prepared(memory) => match memory.abort() {
            Ok(memory) => *slot = Some(Allocation::Cpu(memory)),
            Err(failure) => {
                let (cause, memory) = failure.into_parts();
                *slot = Some(Allocation::Prepared(memory));
                return Err(cause);
            }
        },
        Allocation::Failed(failure) => {
            let (_, memory) = failure.into_parts();
            if let Err(failure) = memory.retry_close() {
                let cause = failure.cause();
                *slot = Some(Allocation::Failed(failure));
                return Err(cause);
            }
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    fn pending(length: u32) -> Option<ReadCursor> {
        Some(ReadCursor {
            completion: QueueCompletion {
                head: 0,
                owner: 0,
                written_bytes: length,
            },
            offset: 0,
        })
    }

    #[test]
    fn short_reads_keep_the_undelivered_suffix_and_slot() {
        let mut cursor = pending(3);
        let mut occupied = [true];
        let mut first = [0; 2];
        assert_eq!(
            read_bytes(&mut cursor, &mut occupied, &mut first, |_, offset| Ok(
                b"abc"[offset]
            ))
            .ok(),
            Some(Some(2))
        );
        assert_eq!(&first, b"ab");
        assert!(occupied[0]);
        assert_eq!(cursor.as_ref().unwrap().offset, 2);
        let mut second = [0; 2];
        assert_eq!(
            read_bytes(&mut cursor, &mut occupied, &mut second, |_, offset| Ok(
                b"abc"[offset]
            ))
            .ok(),
            Some(Some(1))
        );
        assert_eq!(second[0], b'c');
        assert!(!occupied[0]);
        assert!(cursor.is_none());
    }

    #[test]
    fn read_failure_reports_only_the_committed_prefix_and_resumes_after_it() {
        let mut cursor = pending(3);
        let mut occupied = [true];
        let mut bytes = [0; 3];
        let failure = read_bytes(&mut cursor, &mut occupied, &mut bytes, |_, offset| {
            if offset == 1 {
                Err(DmaLeaseError::IommuFailure)
            } else {
                Ok(b"abc"[offset])
            }
        })
        .err()
        .unwrap();
        assert!(matches!(
            failure,
            ReadFailure::Data {
                copied: 1,
                cause: KapiError::IoError
            }
        ));
        assert_eq!(bytes[0], b'a');
        assert_eq!(cursor.as_ref().unwrap().offset, 1);
        assert_eq!(
            read_bytes(&mut cursor, &mut occupied, &mut bytes, |_, offset| Ok(
                b"abc"[offset]
            ))
            .ok(),
            Some(Some(2))
        );
        assert_eq!(&bytes[..2], b"bc");
        assert!(!occupied[0]);
    }
}
