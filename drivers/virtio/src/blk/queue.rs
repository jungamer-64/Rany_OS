//! Protocol RAM and the split ring have one lifecycle owner. Slots are reserved
//! before payload activation; accepted notification ownership lives in ring
//! heads or in the one consumed completion awaiting its status-byte read.
#![deny(unsafe_code)]

use kernel_api::abi::driver::{
    AbiBlockCompletion, AbiBlockSubmission, AbiBlockSubmitOutcome, AbiError,
};
use kernel_api::dma::{
    CpuDmaLease, DmaByteCount, DmaDeviceAddress, DmaDirection, DmaLeaseError, DmaLeaseId,
    DmaQueueIdentity, DmaQuiesceWitness, PreparedSharedDmaLease, SharedDmaLease,
};

use crate::core::{
    MAX_SPLIT_QUEUE_DESCRIPTORS, PreparedSplitVirtQueue, QueueActivationError, QueueAdmissionError,
    QueueBuildError, QueueCommandActivationError, QueueCompletion, QueueFault, QueueSegment,
    QueueSubmitCause, QueueSubmitOutcome, RetiredVirtQueue, SplitVirtQueue,
};
use crate::queue_memory::{QueueConfigureCause, QueueInterrupt, SplitQueueLayout};
use crate::transport::VirtioTransport;

use super::{BlockGeometry, BlockNotification};

const HEADER_BYTES: usize = 16;
const STATUS_OFFSET: usize = HEADER_BYTES;
// Each next header and its 64-bit sector remain naturally aligned.
const REQUEST_STRIDE: usize = 24;
const MAX_REQUESTS: usize = MAX_SPLIT_QUEUE_DESCRIPTORS / 3;

/// Request slot coordinates derived before either allocation is activated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockQueueLayout {
    ring: SplitQueueLayout,
    requests: usize,
}

impl BlockQueueLayout {
    /// Reserve a header, payload descriptor and status for each admitted request.
    /// Flush also uses this bound, although its chain has no payload descriptor.
    ///
    /// # Errors
    /// Rejects non-power-of-two queues and descriptor counts outside 4..=256.
    pub fn new(descriptors: u16) -> Result<Self, AbiError> {
        let ring = SplitQueueLayout::new(descriptors).map_err(|_| AbiError::InvalidParam)?;
        if descriptors < 4 || usize::from(descriptors) > MAX_SPLIT_QUEUE_DESCRIPTORS {
            return Err(AbiError::InvalidParam);
        }
        Ok(Self {
            ring,
            requests: usize::from(descriptors) / 3,
        })
    }

    pub const fn ring(self) -> SplitQueueLayout {
        self.ring
    }
    pub const fn request_capacity(self) -> usize {
        self.requests
    }
    pub const fn protocol_byte_count(self) -> usize {
        self.requests * REQUEST_STRIDE
    }

    fn slot_offset(self, slot: usize) -> Result<usize, DmaLeaseError> {
        if slot >= self.requests {
            return Err(DmaLeaseError::InvalidRange);
        }
        Ok(slot * REQUEST_STRIDE)
    }
}

#[derive(Debug)]
pub enum BlockMetadataPrepareError {
    Cpu {
        cause: DmaLeaseError,
        memory: CpuDmaLease,
    },
    Prepared {
        cause: DmaLeaseError,
        memory: PreparedSharedDmaLease,
    },
}

/// Initialized protocol RAM not yet activated or reachable by a request.
#[derive(Debug)]
pub struct PreparedBlockMetadata {
    layout: BlockQueueLayout,
    address: DmaDeviceAddress,
    memory: PreparedSharedDmaLease,
}

impl PreparedBlockMetadata {
    fn prepare(
        identity: DmaQueueIdentity,
        layout: BlockQueueLayout,
        mut memory: CpuDmaLease,
    ) -> Result<Self, BlockMetadataPrepareError> {
        if memory.byte_count().get() < layout.protocol_byte_count()
            || memory.direction() != DmaDirection::Bidirectional
        {
            return Err(BlockMetadataPrepareError::Cpu {
                cause: DmaLeaseError::InvalidRange,
                memory,
            });
        }
        if let Err(cause) = memory.write(|bytes| bytes[..layout.protocol_byte_count()].fill(0)) {
            return Err(BlockMetadataPrepareError::Cpu { cause, memory });
        }
        let memory = memory.prepare_shared(identity).map_err(|failure| {
            let (cause, memory) = failure.into_parts();
            BlockMetadataPrepareError::Cpu { cause, memory }
        })?;
        let address = match memory.descriptor() {
            Ok(descriptor) => descriptor.device_address(),
            Err(cause) => return Err(BlockMetadataPrepareError::Prepared { cause, memory }),
        };
        if !address.get().is_multiple_of(8) {
            return Err(BlockMetadataPrepareError::Prepared {
                cause: DmaLeaseError::InvalidAlignment,
                memory,
            });
        }
        if address.get() == 0 || address.checked_add(layout.protocol_byte_count()).is_none() {
            return Err(BlockMetadataPrepareError::Prepared {
                cause: DmaLeaseError::InvalidRange,
                memory,
            });
        }
        Ok(Self {
            layout,
            address,
            memory,
        })
    }

    /// Cancel unpublished preparation, retaining the owner on failure.
    ///
    /// # Errors
    /// Returns the complete prepared metadata when the registry cannot abort it.
    pub fn abort(self) -> Result<CpuDmaLease, BlockMetadataAbortError> {
        let Self {
            layout,
            address,
            memory,
        } = self;
        match memory.abort() {
            Ok(memory) => Ok(memory),
            Err(failure) => {
                let (cause, memory) = failure.into_parts();
                Err(BlockMetadataAbortError {
                    cause,
                    metadata: Self {
                        layout,
                        address,
                        memory,
                    },
                })
            }
        }
    }
}

#[derive(Debug)]
pub struct BlockMetadataAbortError {
    pub cause: DmaLeaseError,
    pub metadata: PreparedBlockMetadata,
}

#[derive(Debug)]
pub enum BlockQueueBuildError {
    Metadata {
        cause: BlockMetadataPrepareError,
        ring: CpuDmaLease,
    },
    Ring {
        cause: QueueBuildError,
        metadata: PreparedBlockMetadata,
    },
}

/// All protocol RAM, queue RAM and command metadata admitted before publication.
#[derive(Debug)]
pub struct PreparedBlockQueue {
    identity: DmaQueueIdentity,
    geometry: BlockGeometry,
    metadata: PreparedBlockMetadata,
    ring: PreparedSplitVirtQueue<BlockNotification>,
}

impl PreparedBlockQueue {
    /// Prepare two independent DMA owners; every failure keeps both owners in
    /// their exact CPU or prepared state for the driver's shutdown owner.
    ///
    /// # Errors
    /// Returns metadata or ring preparation failure with all allocations.
    pub fn prepare(
        identity: DmaQueueIdentity,
        geometry: BlockGeometry,
        layout: BlockQueueLayout,
        interrupt: QueueInterrupt,
        ring: CpuDmaLease,
        metadata: CpuDmaLease,
    ) -> Result<Self, BlockQueueBuildError> {
        let metadata = match PreparedBlockMetadata::prepare(identity, layout, metadata) {
            Ok(metadata) => metadata,
            Err(cause) => return Err(BlockQueueBuildError::Metadata { cause, ring }),
        };
        let ring = match PreparedSplitVirtQueue::prepare(identity, layout.ring(), interrupt, ring) {
            Ok(ring) => ring,
            Err(cause) => return Err(BlockQueueBuildError::Ring { cause, metadata }),
        };
        Ok(Self {
            identity,
            geometry,
            metadata,
            ring,
        })
    }

    /// Disassemble unpublished preparation for individually observed aborts.
    pub fn into_unpublished(
        self,
    ) -> (
        PreparedSplitVirtQueue<BlockNotification>,
        PreparedBlockMetadata,
    ) {
        (self.ring, self.metadata)
    }

    /// Activate protocol RAM before programming the split ring. Ring failure
    /// keeps already-active metadata distinct from unpublished ring ownership.
    ///
    /// # Errors
    /// Returns the full owner at the last completed activation stage.
    #[expect(
        clippy::result_large_err,
        reason = "failed activation retains two admitted RAM owners without allocating a cleanup container"
    )]
    pub fn activate(
        self,
        transport: &dyn VirtioTransport,
    ) -> Result<BlockQueue, BlockQueueActivationError> {
        let Self {
            identity,
            geometry,
            metadata,
            ring,
        } = self;
        let PreparedBlockMetadata {
            layout,
            address,
            memory,
        } = metadata;
        let memory = match memory.activate() {
            Ok(memory) => memory,
            Err(failure) => {
                let (cause, memory) = failure.into_parts();
                return Err(BlockQueueActivationError::Metadata {
                    cause,
                    queue: Self {
                        identity,
                        geometry,
                        metadata: PreparedBlockMetadata {
                            layout,
                            address,
                            memory,
                        },
                        ring,
                    },
                });
            }
        };
        PartiallyActivatedBlockQueue {
            identity,
            geometry,
            layout,
            address,
            metadata: memory,
            ring,
        }
        .activate(transport)
    }
}

#[derive(Debug)]
pub enum BlockQueueActivationError {
    Metadata {
        cause: DmaLeaseError,
        queue: PreparedBlockQueue,
    },
    Ring {
        cause: QueueConfigureCause,
        queue: PartiallyActivatedBlockQueue,
    },
}

/// Metadata is active but no split queue was published. Its allocation cannot
/// be treated as CPU-owned on a ring activation failure.
#[derive(Debug)]
pub struct PartiallyActivatedBlockQueue {
    identity: DmaQueueIdentity,
    geometry: BlockGeometry,
    layout: BlockQueueLayout,
    address: DmaDeviceAddress,
    metadata: SharedDmaLease,
    ring: PreparedSplitVirtQueue<BlockNotification>,
}

impl PartiallyActivatedBlockQueue {
    /// Retry only the uncommitted ring stage, keeping metadata activation once.
    ///
    /// # Errors
    /// Returns the same owners if queue admission or programming fails again.
    #[expect(
        clippy::result_large_err,
        reason = "a retry returns the existing active metadata and prepared ring owner"
    )]
    pub fn activate(
        self,
        transport: &dyn VirtioTransport,
    ) -> Result<BlockQueue, BlockQueueActivationError> {
        let Self {
            identity,
            geometry,
            layout,
            address,
            metadata,
            ring,
        } = self;
        match ring.activate(transport) {
            Ok(ring) => Ok(BlockQueue {
                geometry,
                layout,
                address,
                metadata,
                ring,
                occupied: [false; MAX_REQUESTS],
                unreported: None,
            }),
            Err(QueueActivationError { cause, queue: ring }) => {
                Err(BlockQueueActivationError::Ring {
                    cause,
                    queue: Self {
                        identity,
                        geometry,
                        layout,
                        address,
                        metadata,
                        ring,
                    },
                })
            }
        }
    }

    pub const fn identity(&self) -> DmaQueueIdentity {
        self.identity
    }
    pub fn metadata_lease_id(&self) -> DmaLeaseId {
        self.metadata.lease_id()
    }

    /// Recover activated metadata after an observed hardware stop. The prepared
    /// ring remains a separate abort operation; no partial close is hidden.
    ///
    /// # Errors
    /// Returns the full partial owner if metadata quiescence fails.
    #[expect(
        clippy::result_large_err,
        reason = "partial initialization failure keeps both allocation owners for observed cleanup"
    )]
    pub fn quiesce(
        self,
        witness: DmaQuiesceWitness,
    ) -> Result<
        (PreparedSplitVirtQueue<BlockNotification>, CpuDmaLease),
        PartialBlockQueueRetireError,
    > {
        let Self {
            identity,
            geometry,
            layout,
            address,
            metadata,
            ring,
        } = self;
        match metadata.quiesce(witness) {
            Ok(memory) => Ok((ring, memory)),
            Err(failure) => {
                let (cause, metadata) = failure.into_parts();
                Err(PartialBlockQueueRetireError {
                    cause,
                    queue: Self {
                        identity,
                        geometry,
                        layout,
                        address,
                        metadata,
                        ring,
                    },
                })
            }
        }
    }
}

#[derive(Debug)]
pub struct PartialBlockQueueRetireError {
    pub cause: DmaLeaseError,
    pub queue: PartiallyActivatedBlockQueue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockPollError {
    Ring(QueueFault),
    Status(DmaLeaseError),
}

/// Queue ownership is serialized by the host's callback gate. `occupied` is a
/// derived index of accepted ring notifications plus `unreported`; no other
/// registry or command table can independently consume a request.
#[derive(Debug)]
pub struct BlockQueue {
    geometry: BlockGeometry,
    layout: BlockQueueLayout,
    address: DmaDeviceAddress,
    metadata: SharedDmaLease,
    ring: SplitVirtQueue<BlockNotification>,
    occupied: [bool; MAX_REQUESTS],
    unreported: Option<QueueCompletion<BlockNotification>>,
}

impl BlockQueue {
    pub const fn identity(&self) -> DmaQueueIdentity {
        self.ring.identity()
    }
    pub const fn geometry(&self) -> BlockGeometry {
        self.geometry
    }
    pub const fn capacity(&self) -> usize {
        self.layout.request_capacity()
    }
    pub fn ring_lease_id(&self) -> DmaLeaseId {
        self.ring.lease_id()
    }
    pub fn metadata_lease_id(&self) -> DmaLeaseId {
        self.metadata.lease_id()
    }
    pub fn pending_count(&self) -> usize {
        usize::from(self.ring.pending_count()) + usize::from(self.unreported.is_some())
    }

    /// Reserve protocol storage and descriptors before invoking payload
    /// activation. No input pointer or activation cookie survives this call.
    ///
    /// # Safety
    /// The host must retain each payload mapping for this exact queue generation
    /// through completion or reset reconciliation. The activation cookie is
    /// valid for one synchronous call, and success disables conflicting CPU
    /// access. `transport` must be the device owner that configured this queue.
    #[expect(
        unsafe_code,
        reason = "the synchronous host callback retains payload mappings and lends one activation cookie through descriptor publication"
    )]
    pub unsafe fn submit(
        &mut self,
        transport: &dyn VirtioTransport,
        input: &AbiBlockSubmission,
    ) -> AbiBlockSubmitOutcome {
        let status = transport.status();
        if status & crate::defs::status::VIRTIO_STATUS_DRIVER_OK == 0
            || status
                & (crate::defs::status::VIRTIO_STATUS_FAILED
                    | crate::defs::status::VIRTIO_STATUS_DEVICE_NEEDS_RESET)
                != 0
        {
            return AbiBlockSubmitOutcome::rejected(AbiError::DeviceBusy);
        }
        if let Err(cause) = self.geometry.refresh_capacity(transport) {
            return AbiBlockSubmitOutcome::rejected(match cause {
                super::BlockConfigurationError::ConfigurationChanged => AbiError::DeviceBusy,
                _ => AbiError::IoError,
            });
        }
        let command = match self.geometry.admit(self.identity(), input) {
            Ok(command) => command,
            Err(cause) => return AbiBlockSubmitOutcome::rejected(cause),
        };
        let Some(slot) = self.occupied[..self.capacity()]
            .iter()
            .position(|used| !used)
        else {
            return AbiBlockSubmitOutcome::rejected(AbiError::DeviceBusy);
        };
        let offset = slot * REQUEST_STRIDE;
        let (kind, sector) = command.wire_header();
        let initialize = self
            .metadata
            .window(offset, REQUEST_STRIDE)
            .and_then(|mut window| {
                window.write_u32(0, kind.to_le())?;
                window.write_u32(4, 0)?;
                window.write_u64(8, sector.to_le())?;
                window.write_u8(STATUS_OFFSET, u8::MAX)
            });
        if initialize.is_err() {
            return AbiBlockSubmitOutcome::rejected(AbiError::IoError);
        }
        let header = match segment(self.address, offset, HEADER_BYTES, false) {
            Ok(segment) => segment,
            Err(_) => return AbiBlockSubmitOutcome::rejected(AbiError::InvalidAddress),
        };
        let status = match segment(self.address, offset + STATUS_OFFSET, 1, true) {
            Ok(segment) => segment,
            Err(_) => return AbiBlockSubmitOutcome::rejected(AbiError::InvalidAddress),
        };
        let payload = match command.payload() {
            Some((address, bytes, writable)) => match segment(address, 0, bytes as usize, writable)
            {
                Ok(segment) => Some(segment),
                Err(_) => return AbiBlockSubmitOutcome::rejected(AbiError::InvalidAddress),
            },
            None => None,
        };
        let chain = match payload {
            Some(payload) => [header, payload, status],
            None => [header, status, status],
        };
        let segments = &chain[..if payload.is_some() { 3 } else { 2 }];
        let notification = BlockNotification::new(slot, input, &command);
        let activate = |owner| {
            // SAFETY: submit's caller lends this unique cookie for the call;
            // the split ring calls this closure once after reservation.
            let status = unsafe { (input.activate)(input.activation) };
            if status == AbiError::Success as i32 {
                Ok(owner)
            } else {
                Err(QueueCommandActivationError {
                    owner,
                    cause: AbiError::from_raw(status),
                })
            }
        };
        // SAFETY: protocol RAM is retained and activated; payload admission and
        // cache preparation belong to the caller's synchronous activation. All
        // metadata/descriptor reservations precede that single activation call.
        let result = unsafe { self.ring.publish(segments, notification, activate) };
        match result {
            Ok(QueueSubmitOutcome::Published { .. }) => {
                self.occupied[slot] = true;
                AbiBlockSubmitOutcome::accepted()
            }
            Ok(QueueSubmitOutcome::PublicationUncertain { .. }) => {
                self.occupied[slot] = true;
                AbiBlockSubmitOutcome::outcome_unknown(AbiError::IoError)
            }
            Err(failure) => AbiBlockSubmitOutcome::rejected(match failure.cause {
                QueueSubmitCause::Activation(cause) => cause,
                QueueSubmitCause::Admission(QueueAdmissionError::QueueFull) => AbiError::DeviceBusy,
                QueueSubmitCause::Admission(
                    QueueAdmissionError::EmptyChain | QueueAdmissionError::InvalidSegment,
                ) => AbiError::InvalidParam,
                QueueSubmitCause::Admission(
                    QueueAdmissionError::Faulted(_) | QueueAdmissionError::Dma(_),
                ) => AbiError::IoError,
            }),
        }
    }

    /// Consume one terminal notification only after validating its used entry
    /// and reading status. A failed status read retains this same notification
    /// for retry before any later used entry can be consumed.
    ///
    /// # Errors
    /// Returns ring corruption or status access failure with all unreported
    /// operations retained. Empty output buffers need not call this method.
    pub fn poll_completion(&mut self) -> Result<Option<AbiBlockCompletion>, BlockPollError> {
        if self.unreported.is_none() {
            self.unreported = self.ring.poll_completion().map_err(BlockPollError::Ring)?;
        }
        deliver_completion(&mut self.unreported, &mut self.occupied, |slot| {
            let offset = self.layout.slot_offset(slot)?;
            self.metadata
                .window(offset + STATUS_OFFSET, 1)
                .and_then(|window| window.read_u8(0))
        })
    }

    /// Recover RAM after the lifecycle owner has stopped the device. Accepted
    /// notifications remain available only as reset-aborted operations.
    ///
    /// # Errors
    /// A metadata failure returns the active queue. A later ring failure returns
    /// CPU-owned metadata and the still-live ring as an explicit partial result.
    #[expect(
        clippy::result_large_err,
        reason = "quiescence preserves partial progress and every RAM/notification owner without new allocation"
    )]
    pub fn quiesce(
        self,
        metadata_witness: DmaQuiesceWitness,
        ring_witness: DmaQuiesceWitness,
    ) -> Result<RetiredBlockQueue, BlockQueueRetireError> {
        let Self {
            geometry,
            layout,
            address,
            metadata,
            ring,
            occupied,
            unreported,
        } = self;
        let metadata = match metadata.quiesce(metadata_witness) {
            Ok(metadata) => metadata,
            Err(failure) => {
                let (cause, metadata) = failure.into_parts();
                return Err(BlockQueueRetireError::Metadata {
                    cause,
                    queue: Self {
                        geometry,
                        layout,
                        address,
                        metadata,
                        ring,
                        occupied,
                        unreported,
                    },
                });
            }
        };
        BlockQueueRingRetirement {
            metadata,
            ring,
            unreported,
        }
        .quiesce(ring_witness)
        .map_err(|failure| BlockQueueRetireError::Ring {
            cause: failure.cause,
            retirement: failure.retirement,
        })
    }
}

// Status access is fallible after used-ring consumption. Borrow the retained
// notification for that access; transfer its terminal route only on success.
fn deliver_completion(
    unreported: &mut Option<QueueCompletion<BlockNotification>>,
    occupied: &mut [bool],
    read_status: impl FnOnce(usize) -> Result<u8, DmaLeaseError>,
) -> Result<Option<AbiBlockCompletion>, BlockPollError> {
    let Some(completed) = unreported.as_ref() else {
        return Ok(None);
    };
    let slot = completed.owner.slot;
    if slot >= occupied.len() {
        return Err(BlockPollError::Status(DmaLeaseError::InvalidRange));
    }
    let status = read_status(slot).map_err(BlockPollError::Status)?;
    let Some(completed) = unreported.take() else {
        return Ok(None);
    };
    occupied[slot] = false;
    Ok(Some(
        completed.owner.complete(completed.written_bytes, status),
    ))
}

fn segment(
    address: DmaDeviceAddress,
    offset: usize,
    bytes: usize,
    writable: bool,
) -> Result<QueueSegment, QueueAdmissionError> {
    let address = address
        .checked_add(offset)
        .ok_or(QueueAdmissionError::InvalidSegment)?;
    let bytes = DmaByteCount::new(bytes).ok_or(QueueAdmissionError::InvalidSegment)?;
    QueueSegment::new(address, bytes, writable)
}

#[derive(Debug)]
pub enum BlockQueueRetireError {
    Metadata {
        cause: DmaLeaseError,
        queue: BlockQueue,
    },
    Ring {
        cause: DmaLeaseError,
        retirement: BlockQueueRingRetirement,
    },
}

/// Metadata retirement succeeded; only the ring remains to be quiesced.
#[derive(Debug)]
pub struct BlockQueueRingRetirement {
    pub metadata: CpuDmaLease,
    ring: SplitVirtQueue<BlockNotification>,
    unreported: Option<QueueCompletion<BlockNotification>>,
}

#[derive(Debug)]
pub struct BlockQueueRingRetireError {
    pub cause: DmaLeaseError,
    pub retirement: BlockQueueRingRetirement,
}

impl BlockQueueRingRetirement {
    pub const fn identity(&self) -> DmaQueueIdentity {
        self.ring.identity()
    }
    pub fn ring_lease_id(&self) -> DmaLeaseId {
        self.ring.lease_id()
    }

    /// Retry only ring retirement; metadata remains CPU-owned throughout.
    ///
    /// # Errors
    /// Keeps this partial result if the ring cannot yet return CPU ownership.
    #[expect(
        clippy::result_large_err,
        reason = "retirement retry returns partial progress and every accepted notification"
    )]
    pub fn quiesce(
        self,
        witness: DmaQuiesceWitness,
    ) -> Result<RetiredBlockQueue, BlockQueueRingRetireError> {
        let Self {
            metadata,
            ring,
            unreported,
        } = self;
        match ring.quiesce(witness) {
            Ok(ring) => Ok(RetiredBlockQueue {
                metadata,
                ring,
                unreported,
            }),
            Err(failure) => Err(BlockQueueRingRetireError {
                cause: failure.cause,
                retirement: Self {
                    metadata,
                    ring: failure.queue,
                    unreported,
                },
            }),
        }
    }
}

#[derive(Debug)]
pub struct RetiredBlockQueue {
    pub metadata: CpuDmaLease,
    pub ring: RetiredVirtQueue<BlockNotification>,
    unreported: Option<QueueCompletion<BlockNotification>>,
}

impl RetiredBlockQueue {
    /// Consume a reset-aborted operation for host reconciliation. This does not
    /// synthesize a hardware terminal entry or release its payload lease.
    pub fn next_aborted(&mut self) -> Option<BlockNotification> {
        self.unreported
            .take()
            .map(|completed| completed.owner)
            .or_else(|| self.ring.next_aborted())
    }
}

#[cfg(test)]
mod tests {
    use super::super::protocol::BlockCommand;
    use super::*;

    extern "C" fn unused_activation(_: *mut core::ffi::c_void) -> i32 {
        AbiError::Success as i32
    }

    fn completed_flush(slot: usize) -> QueueCompletion<BlockNotification> {
        let input = AbiBlockSubmission {
            request_id: 7,
            command: kernel_api::abi::driver::AbiBlockCommandKind::Flush as u32,
            lba: 0,
            blocks: 0,
            bytes: 0,
            iova: 0,
            lease_id: 0,
            generation: 41,
            activation: core::ptr::null_mut(),
            activate: unused_activation,
        };
        QueueCompletion {
            head: 3,
            written_bytes: 1,
            owner: BlockNotification::new(slot, &input, &BlockCommand::Flush),
        }
    }

    #[test]
    fn failed_status_read_retains_the_route_and_slot_for_exactly_one_retry() {
        let mut pending = Some(completed_flush(2));
        let mut occupied = [false, false, true, false];
        let failure = deliver_completion(&mut pending, &mut occupied, |slot| {
            assert_eq!(slot, 2);
            Err(DmaLeaseError::IommuFailure)
        });
        assert_eq!(
            failure.err(),
            Some(BlockPollError::Status(DmaLeaseError::IommuFailure))
        );
        assert_eq!(
            pending.as_ref().map(|item| item.owner.request_id()),
            Some(7)
        );
        assert!(occupied[2]);
        let emitted = deliver_completion(&mut pending, &mut occupied, |_| Ok(0))
            .expect("retry can read status")
            .expect("the retained route is emitted");
        assert_eq!((emitted.request_id, emitted.generation), (7, 41));
        assert_eq!(emitted.status, AbiError::Success as i32);
        assert_eq!(emitted.bytes, 0);
        assert!(!occupied[2]);
        assert!(pending.is_none());
        let empty = deliver_completion(&mut pending, &mut occupied, |_| {
            panic!("no entry can be read twice")
        })
        .expect("the second poll is empty");
        assert!(empty.is_none());
    }

    #[test]
    fn device_error_is_terminal_without_payload_success() {
        let mut pending = Some(completed_flush(0));
        let mut occupied = [true];
        let completion = deliver_completion(&mut pending, &mut occupied, |_| Ok(1))
            .expect("status read succeeds")
            .expect("one terminal error");
        assert_eq!(completion.status, AbiError::IoError as i32);
        assert_eq!(completion.bytes, 0);
        assert!(pending.is_none());
        assert!(!occupied[0]);
    }

    #[test]
    fn protocol_slots_match_the_descriptor_admission_bound() {
        let layout = BlockQueueLayout::new(256).expect("supported queue depth");
        assert_eq!(layout.request_capacity(), 85);
        assert_eq!(layout.protocol_byte_count(), 2040);
        assert_eq!(layout.slot_offset(84), Ok(2016));
        assert_eq!(layout.slot_offset(85), Err(DmaLeaseError::InvalidRange));
        let smallest = BlockQueueLayout::new(4).expect("one transfer fits");
        assert_eq!(smallest.request_capacity(), 1);
        assert_eq!(smallest.protocol_byte_count(), 24);
        assert_eq!(BlockQueueLayout::new(2), Err(AbiError::InvalidParam));
        assert_eq!(BlockQueueLayout::new(6), Err(AbiError::InvalidParam));
        assert_eq!(BlockQueueLayout::new(512), Err(AbiError::InvalidParam));
    }
}
