//! Host-owned Block cell and bounded lifecycle observations. Each suspension
//! leaves all DMA and callback resources in this instance. Stop closes admission,
//! drains accepted notifications, observes device reset, then retires RAM.
#![deny(unsafe_code)]

use alloc::boxed::Box;
use core::sync::atomic::{AtomicU64, Ordering};
use exorust_sync::Mutex;
use kernel_api::abi::driver::{
    AbiBlockCompletion, AbiBlockDeviceInfo, AbiBlockDeviceRegistration, AbiBlockQueueInfo,
    AbiBlockSubmission, AbiBlockSubmitOutcome, AbiError, DriverContext, PackedPciLocation,
};
use kernel_api::dma::{
    CpuDmaLease, DmaAllocationRequest, DmaCloseError, DmaDirection, DmaLeaseError,
    DmaQueueIdentity, DmaQuiesceWitness, PreparedSharedDmaLease,
};
use kernel_api::{KapiError, KapiResult};

use crate::blk::*;
use crate::core::{PreparedSplitVirtQueue, QueueBuildError};
use crate::defs::{VirtioDeviceType, common_features, status};
use crate::queue_memory::{QueueInterrupt, QueuePrepareError};
use crate::transport::{PciTransportDiscoveryError, VirtioPciTransport, VirtioTransport};

const RESET_TIMEOUT_MS: u64 = 30_000;
// Allocation identity, not execution identity. Each instantiated queue receives
// a distinct generation within the retained cell image.
static NEXT_QUEUE_GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
struct QueuePlan {
    identity: DmaQueueIdentity,
    geometry: BlockGeometry,
    layout: BlockQueueLayout,
}

enum UnpublishedMemory {
    Cpu(CpuDmaLease),
    Shared(PreparedSharedDmaLease),
    Ring(PreparedSplitVirtQueue<BlockNotification>),
    Metadata(PreparedBlockMetadata),
    CloseFailed(DmaCloseError),
}

struct ReleasePair {
    first: Option<UnpublishedMemory>,
    second: Option<UnpublishedMemory>,
}

enum StopOwner {
    Empty,
    Unpublished(ReleasePair),
    // Only the admission transition below constructs this variant, after
    // pending_count reaches zero. No submit/poll operation exists in this phase.
    IdleQueue(BlockQueue),
    Partial(PartiallyActivatedBlockQueue),
}

enum Phase {
    Resetting { deadline: u64 },
    Negotiating,
    Planned(QueuePlan),
    RingAllocated(QueuePlan, CpuDmaLease),
    Prepared(PreparedBlockQueue),
    PrepareFailed(BlockQueueBuildError),
    Partial(PartiallyActivatedBlockQueue),
    Ready(BlockQueue),
    Draining(BlockQueue),
    Stopping { deadline: u64, owner: StopOwner },
    RetiringRing(BlockQueueRingRetirement),
    Releasing(ReleasePair),
    Closed,
    Transitioning,
}

struct Runtime {
    device: PackedPciLocation,
    transport: VirtioPciTransport,
    phase: Mutex<Phase>,
}

pub(super) struct BlockCell {
    runtime: Option<Box<Runtime>>,
    registration: Option<u64>,
}

impl BlockCell {
    pub(super) const fn new() -> Self {
        Self {
            runtime: None,
            registration: None,
        }
    }

    pub(super) async fn probe(&mut self, context: &DriverContext) -> KapiResult<()> {
        if self.runtime.is_some() {
            return Err(KapiError::AlreadyExists);
        }
        let timer = timer()?;
        let deadline = reset_deadline(timer.current_tick_ms())?;
        let device = context.pci_location();
        let transport = VirtioPciTransport::acquire(device, VirtioDeviceType::Block)
            .map_err(discovery_error)?;
        self.runtime = Some(
            Box::try_new(Runtime {
                device,
                transport,
                phase: Mutex::new(Phase::Resetting { deadline }),
            })
            .map_err(|_| KapiError::OutOfMemory)?,
        );
        let runtime = self.runtime.as_ref().ok_or(KapiError::NotFound)?;
        runtime.transport.request_reset();
        // LOOP_PROOF: mode=event; reason=One bootstrap step is retained before each timer wait, and readiness, failure or the reset deadline ends probe.;
        loop {
            if runtime.advance_boot(timer.current_tick_ms())? {
                return Ok(());
            }
            kernel_api::service::time::SleepFuture::new(timer, 1)
                .await
                .map_err(KapiError::Timer)?;
        }
    }

    pub(super) async fn start(&mut self) -> KapiResult<()> {
        if self.registration.is_some() {
            return Ok(());
        }
        let runtime = self.runtime.as_ref().ok_or(KapiError::NotFound)?;
        let registration = {
            let phase = runtime.phase.lock();
            let Phase::Ready(queue) = &*phase else {
                return Err(KapiError::Busy);
            };
            let geometry = queue.geometry();
            AbiBlockDeviceRegistration {
                abi_size: core::mem::size_of::<AbiBlockDeviceRegistration>() as u64,
                info: AbiBlockDeviceInfo {
                    device_id: runtime.device.raw(),
                    namespace_id: 0,
                    block_size: geometry.block_size(),
                    block_count: geometry.block_count(),
                    max_transfer_blocks: u32::from(geometry.max_transfer_blocks()),
                    transport: kernel_api::abi::driver::AbiBlockTransport::Other as u32,
                    flags: 0,
                    controller_id: 0,
                    port_id: 0,
                },
                queue: AbiBlockQueueInfo {
                    device: runtime.device,
                    index: queue.identity().index(),
                    capacity: queue.capacity() as u16,
                    generation: queue.identity().generation(),
                },
                opaque: core::ptr::from_ref(runtime.as_ref()).expose_provenance() as u64,
                submit,
                poll,
                is_ready,
                stop,
            }
        };
        self.registration =
            Some(kernel_api::service::kernel::instance().register_block_device(&registration)?);
        Ok(())
    }

    pub(super) async fn stop(&mut self) -> KapiResult<()> {
        let Some(runtime) = self.runtime.as_ref() else {
            return Ok(());
        };
        let timer = timer()?;
        let deadline = reset_deadline(timer.current_tick_ms())?;
        // LOOP_PROOF: mode=event; reason=The host drains accepted requests or one retained retirement step precedes each timer wait, with completion or the bounded deadline ending shutdown.;
        loop {
            let result = match self.registration {
                Some(handle) => {
                    kernel_api::service::kernel::instance().unregister_block_device(handle)
                }
                None => runtime.advance_stop(timer.current_tick_ms()),
            };
            match result {
                Ok(()) => {
                    self.registration = None;
                    return Ok(());
                }
                Err(KapiError::Busy) if timer.current_tick_ms() < deadline => {}
                Err(cause) => return Err(cause),
            }
            kernel_api::service::time::SleepFuture::new(timer, 1)
                .await
                .map_err(KapiError::Timer)?;
        }
    }

    pub(super) async fn remove(&mut self) -> KapiResult<()> {
        self.stop().await?;
        self.runtime = None;
        Ok(())
    }
}

impl Runtime {
    #[expect(
        unsafe_code,
        reason = "the lifecycle owner binds an observed hardware reset to each uniquely retained queue allocation"
    )]
    fn advance_stop(&self, now: u64) -> KapiResult<()> {
        let mut phase = self.phase.lock();
        let current = core::mem::replace(&mut *phase, Phase::Transitioning);
        *phase = match current {
            Phase::Ready(queue) | Phase::Draining(queue) if queue.pending_count() != 0 => {
                *phase = Phase::Draining(queue);
                return Err(KapiError::Busy);
            }
            Phase::Stopping { deadline, owner } => {
                if self.transport.status() != 0 {
                    *phase = Phase::Stopping { deadline, owner };
                    return if now < deadline {
                        Err(KapiError::Busy)
                    } else {
                        Err(KapiError::Timeout)
                    };
                }
                match owner {
                    StopOwner::Empty => Phase::Closed,
                    StopOwner::Unpublished(memory) => Phase::Releasing(memory),
                    StopOwner::IdleQueue(queue) => {
                        // SAFETY: status zero acknowledges the device reset and
                        // drains its accesses. These two regions belong only to
                        // this stopped queue, whose admission is closed.
                        let metadata = unsafe {
                            DmaQuiesceWitness::after_queue_quiesced(
                                queue.identity(),
                                queue.metadata_lease_id(),
                            )
                        };
                        // SAFETY: the same reset observation covers this queue's
                        // distinct ring allocation; its owner is consumed once.
                        let ring = unsafe {
                            DmaQuiesceWitness::after_queue_quiesced(
                                queue.identity(),
                                queue.ring_lease_id(),
                            )
                        };
                        match queue.quiesce(metadata, ring) {
                            Ok(retired) => Phase::Releasing(release_idle_retired(retired)),
                            Err(BlockQueueRetireError::Metadata { cause, queue }) => {
                                log::error!("VirtIO block metadata retirement retained: {cause:?}");
                                *phase = Phase::Stopping {
                                    deadline,
                                    owner: StopOwner::IdleQueue(queue),
                                };
                                return Err(KapiError::IoError);
                            }
                            Err(BlockQueueRetireError::Ring { cause, retirement }) => {
                                log::error!("VirtIO block ring retirement retained: {cause:?}");
                                *phase = Phase::RetiringRing(retirement);
                                return Err(KapiError::IoError);
                            }
                        }
                    }
                    StopOwner::Partial(queue) => {
                        // SAFETY: reset has been acknowledged and the prepared
                        // ring exposed no requests to this active metadata RAM.
                        let witness = unsafe {
                            DmaQuiesceWitness::after_queue_quiesced(
                                queue.identity(),
                                queue.metadata_lease_id(),
                            )
                        };
                        match queue.quiesce(witness) {
                            Ok((ring, metadata)) => Phase::Releasing(ReleasePair::new(
                                UnpublishedMemory::Ring(ring),
                                UnpublishedMemory::Cpu(metadata),
                            )),
                            Err(failure) => {
                                log::error!(
                                    "VirtIO block partial activation retained: {:?}",
                                    failure.cause
                                );
                                *phase = Phase::Stopping {
                                    deadline,
                                    owner: StopOwner::Partial(failure.queue),
                                };
                                return Err(KapiError::IoError);
                            }
                        }
                    }
                }
            }
            Phase::RetiringRing(retirement) => {
                if self.transport.status() != 0 {
                    *phase = Phase::RetiringRing(retirement);
                    return Err(KapiError::Busy);
                }
                // SAFETY: the device remains reset and metadata is already CPU
                // owned. This transition retires only the still-active ring.
                let witness = unsafe {
                    DmaQuiesceWitness::after_queue_quiesced(
                        retirement.identity(),
                        retirement.ring_lease_id(),
                    )
                };
                match retirement.quiesce(witness) {
                    Ok(retired) => Phase::Releasing(release_idle_retired(retired)),
                    Err(failure) => {
                        log::error!(
                            "VirtIO block ring retirement retry retained: {:?}",
                            failure.cause
                        );
                        *phase = Phase::RetiringRing(failure.retirement);
                        return Err(KapiError::IoError);
                    }
                }
            }
            Phase::Releasing(mut memory) => match memory.advance() {
                Ok(true) => Phase::Closed,
                Ok(false) => Phase::Releasing(memory),
                Err(cause) => {
                    log::error!("VirtIO block allocation retirement retained: {cause:?}");
                    *phase = Phase::Releasing(memory);
                    return Err(KapiError::IoError);
                }
            },
            Phase::Closed => {
                *phase = Phase::Closed;
                return Ok(());
            }
            Phase::Transitioning => {
                *phase = Phase::Transitioning;
                return Err(KapiError::Busy);
            }
            other => {
                let next_deadline = match reset_deadline(now) {
                    Ok(deadline) => deadline,
                    Err(cause) => {
                        *phase = other;
                        return Err(cause);
                    }
                };
                let owner = match stop_owner(other) {
                    Ok(owner) => owner,
                    Err(retained) => {
                        *phase = retained;
                        return Err(KapiError::Busy);
                    }
                };
                self.transport.request_reset();
                Phase::Stopping {
                    deadline: next_deadline,
                    owner,
                }
            }
        };
        if matches!(*phase, Phase::Closed) {
            Ok(())
        } else {
            Err(KapiError::Busy)
        }
    }

    fn advance_boot(&self, now: u64) -> KapiResult<bool> {
        let mut phase = self.phase.lock();
        let current = core::mem::replace(&mut *phase, Phase::Transitioning);
        *phase = match current {
            Phase::Resetting { deadline } => {
                if self.transport.status() != 0 {
                    *phase = Phase::Resetting { deadline };
                    return if now < deadline {
                        Ok(false)
                    } else {
                        Err(KapiError::Timeout)
                    };
                }
                Phase::Negotiating
            }
            Phase::Negotiating => {
                let plan = match self.negotiate() {
                    Ok(plan) => plan,
                    Err(cause) => {
                        *phase = Phase::Negotiating;
                        return Err(cause);
                    }
                };
                Phase::Planned(plan)
            }
            Phase::Planned(plan) => {
                let ring = match allocate(self.device, plan.layout.ring().byte_count()) {
                    Ok(ring) => ring,
                    Err(cause) => {
                        *phase = Phase::Planned(plan);
                        return Err(cause);
                    }
                };
                Phase::RingAllocated(plan, ring)
            }
            Phase::RingAllocated(plan, ring) => {
                let metadata = match allocate(self.device, plan.layout.protocol_byte_count()) {
                    Ok(metadata) => metadata,
                    Err(cause) => {
                        *phase = Phase::RingAllocated(plan, ring);
                        return Err(cause);
                    }
                };
                match PreparedBlockQueue::prepare(
                    plan.identity,
                    plan.geometry,
                    plan.layout,
                    QueueInterrupt::Polled,
                    ring,
                    metadata,
                ) {
                    Ok(queue) => Phase::Prepared(queue),
                    Err(cause) => {
                        log::error!("VirtIO block preparation retained: {cause:?}");
                        *phase = Phase::PrepareFailed(cause);
                        return Err(KapiError::IoError);
                    }
                }
            }
            Phase::Prepared(queue) => match queue.activate(&self.transport) {
                Ok(queue) => {
                    self.transport.add_status(status::VIRTIO_STATUS_DRIVER_OK);
                    Phase::Ready(queue)
                }
                Err(BlockQueueActivationError::Metadata { cause, queue }) => {
                    log::error!("VirtIO block metadata activation retained: {cause:?}");
                    *phase = Phase::Prepared(queue);
                    return Err(KapiError::IoError);
                }
                Err(BlockQueueActivationError::Ring { cause, queue }) => {
                    log::error!("VirtIO block ring activation retained: {cause:?}");
                    *phase = Phase::Partial(queue);
                    return Err(KapiError::IoError);
                }
            },
            Phase::Ready(queue) => {
                *phase = Phase::Ready(queue);
                return Ok(true);
            }
            other => {
                *phase = other;
                return Err(KapiError::Busy);
            }
        };
        Ok(false)
    }

    fn negotiate(&self) -> KapiResult<QueuePlan> {
        self.transport
            .add_status(status::VIRTIO_STATUS_ACKNOWLEDGE | status::VIRTIO_STATUS_DRIVER);
        let offered = self.transport.device_features();
        let required =
            common_features::VIRTIO_F_VERSION_1 | common_features::VIRTIO_F_ACCESS_PLATFORM;
        if offered & required != required {
            return Err(KapiError::NotSupported);
        }
        let features = offered & BLOCK_SUPPORTED_FEATURES;
        self.transport.set_driver_features(features);
        self.transport.add_status(status::VIRTIO_STATUS_FEATURES_OK);
        let geometry = BlockGeometry::read(&self.transport, features).map_err(|cause| {
            log::error!("VirtIO block configuration rejected: {cause:?}");
            KapiError::IoError
        })?;
        let maximum = self
            .transport
            .queue_capacity(0)
            .map_err(|_| KapiError::IoError)?;
        let layout = select_layout(maximum)?;
        let generation = NEXT_QUEUE_GENERATION
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .map_err(|_| KapiError::ResourceExhausted)?;
        let identity =
            DmaQueueIdentity::new(self.device, 0, generation).ok_or(KapiError::InvalidHandle)?;
        Ok(QueuePlan {
            identity,
            geometry,
            layout,
        })
    }
}

#[expect(
    clippy::result_large_err,
    reason = "a non-admitted shutdown returns its existing resource phase without allocation"
)]
fn stop_owner(phase: Phase) -> Result<StopOwner, Phase> {
    Ok(match phase {
        Phase::Prepared(queue) => {
            let (ring, metadata) = queue.into_unpublished();
            StopOwner::Unpublished(ReleasePair::new(
                UnpublishedMemory::Ring(ring),
                UnpublishedMemory::Metadata(metadata),
            ))
        }
        Phase::RingAllocated(_, ring) => StopOwner::Unpublished(ReleasePair {
            first: Some(UnpublishedMemory::Cpu(ring)),
            second: None,
        }),
        Phase::PrepareFailed(cause) => StopOwner::Unpublished(release_build_failure(cause)),
        Phase::Partial(queue) => StopOwner::Partial(queue),
        Phase::Ready(queue) | Phase::Draining(queue) => {
            if queue.pending_count() != 0 {
                return Err(Phase::Draining(queue));
            }
            StopOwner::IdleQueue(queue)
        }
        Phase::Resetting { .. } | Phase::Negotiating | Phase::Planned(_) => StopOwner::Empty,
        other => return Err(other),
    })
}

fn release_build_failure(cause: BlockQueueBuildError) -> ReleasePair {
    match cause {
        BlockQueueBuildError::Metadata { cause, ring } => {
            let metadata = match cause {
                BlockMetadataPrepareError::Cpu { memory, .. } => UnpublishedMemory::Cpu(memory),
                BlockMetadataPrepareError::Prepared { memory, .. } => {
                    UnpublishedMemory::Shared(memory)
                }
            };
            ReleasePair::new(UnpublishedMemory::Cpu(ring), metadata)
        }
        BlockQueueBuildError::Ring { cause, metadata } => {
            let ring = match cause {
                QueueBuildError::DescriptorLimit { memory }
                | QueueBuildError::MetadataAllocation { memory } => UnpublishedMemory::Cpu(memory),
                QueueBuildError::Memory(
                    QueuePrepareError::InvalidMemory { memory }
                    | QueuePrepareError::Cpu { memory, .. },
                ) => UnpublishedMemory::Cpu(memory),
                QueueBuildError::Memory(QueuePrepareError::Prepared { memory, .. }) => {
                    UnpublishedMemory::Shared(memory)
                }
            };
            ReleasePair::new(ring, UnpublishedMemory::Metadata(metadata))
        }
    }
}

fn release_idle_retired(retired: RetiredBlockQueue) -> ReleasePair {
    // Called only from IdleQueue retirement (including its retained ring retry).
    // Closing that phase excluded further publication, so the retired ring
    // contains no accepted notification or payload reconciliation responsibility.
    ReleasePair::new(
        UnpublishedMemory::Cpu(retired.ring.memory),
        UnpublishedMemory::Cpu(retired.metadata),
    )
}

impl ReleasePair {
    fn new(first: UnpublishedMemory, second: UnpublishedMemory) -> Self {
        Self {
            first: Some(first),
            second: Some(second),
        }
    }

    fn advance(&mut self) -> Result<bool, DmaLeaseError> {
        if self.first.is_none() {
            self.first = self.second.take()
        }
        let Some(memory) = self.first.take() else {
            return Ok(true);
        };
        self.first = match memory {
            UnpublishedMemory::Cpu(memory) => match memory.close() {
                Ok(()) => None,
                Err(cause) => {
                    let error = cause.cause();
                    self.first = Some(UnpublishedMemory::CloseFailed(cause));
                    return Err(error);
                }
            },
            UnpublishedMemory::Shared(memory) => match memory.abort() {
                Ok(memory) => Some(UnpublishedMemory::Cpu(memory)),
                Err(failure) => {
                    let (cause, memory) = failure.into_parts();
                    self.first = Some(UnpublishedMemory::Shared(memory));
                    return Err(cause);
                }
            },
            UnpublishedMemory::Ring(ring) => match ring.abort() {
                Ok(memory) => Some(UnpublishedMemory::Cpu(memory)),
                Err(failure) => {
                    let (cause, memory) = failure.into_parts();
                    self.first = Some(UnpublishedMemory::Shared(memory));
                    return Err(cause);
                }
            },
            UnpublishedMemory::Metadata(metadata) => match metadata.abort() {
                Ok(memory) => Some(UnpublishedMemory::Cpu(memory)),
                Err(failure) => {
                    self.first = Some(UnpublishedMemory::Metadata(failure.metadata));
                    return Err(failure.cause);
                }
            },
            UnpublishedMemory::CloseFailed(failure) => {
                let (_, memory) = failure.into_parts();
                match memory.retry_close() {
                    Ok(()) => None,
                    Err(failure) => {
                        let cause = failure.cause();
                        self.first = Some(UnpublishedMemory::CloseFailed(failure));
                        return Err(cause);
                    }
                }
            }
        };
        Ok(self.first.is_none() && self.second.is_none())
    }
}

fn select_layout(maximum: u16) -> KapiResult<BlockQueueLayout> {
    if maximum < 4 {
        return Err(KapiError::NotSupported);
    }
    let limit = maximum.min(crate::defs::VIRTQUEUE_DEFAULT_SIZE);
    let next = limit.next_power_of_two();
    let depth = if next > limit { next / 2 } else { next };
    BlockQueueLayout::new(depth).map_err(|_| KapiError::NotSupported)
}

fn allocate(device: PackedPciLocation, bytes: usize) -> KapiResult<CpuDmaLease> {
    let request = DmaAllocationRequest::new(bytes, DmaDirection::Bidirectional)
        .ok_or(KapiError::InvalidSize)?;
    kernel_api::service::kernel::instance().alloc_dma_for_device(request, device)
}

fn timer() -> KapiResult<&'static dyn kernel_api::service::time::TimeService> {
    kernel_api::service::time::try_instance().ok_or(KapiError::Timer(
        kernel_api::service::time::TimerError::ServiceUnavailable,
    ))
}

fn reset_deadline(now: u64) -> KapiResult<u64> {
    now.checked_add(RESET_TIMEOUT_MS).ok_or(KapiError::Timer(
        kernel_api::service::time::TimerError::ClockExhausted,
    ))
}

fn discovery_error(cause: PciTransportDiscoveryError) -> KapiError {
    match cause {
        PciTransportDiscoveryError::Mapping(cause) => KapiError::Mmio(cause),
        PciTransportDiscoveryError::Allocation => KapiError::OutOfMemory,
        _ => KapiError::IoError,
    }
}

/// Borrow one runtime retained by the registration's callback owner.
///
/// # Safety
/// The host must retain this exact `Box<Runtime>` and code, and serialize its
/// callbacks/removal for the returned borrow's lifetime.
#[expect(
    unsafe_code,
    reason = "the block registration lends a retained opaque Runtime through each serialized callback"
)]
unsafe fn runtime<'call>(opaque: u64) -> Option<&'call Runtime> {
    let address = usize::try_from(opaque).ok()?;
    if address == 0 || !address.is_multiple_of(core::mem::align_of::<Runtime>()) {
        return None;
    }
    // SAFETY: callback callers must use the live registration's opaque value;
    // exposed provenance originated from its retained Box<Runtime> at start.
    Some(unsafe { &*core::ptr::with_exposed_provenance::<Runtime>(address) })
}

#[expect(
    unsafe_code,
    reason = "the host lends one synchronous publication and activation frame for its retained block runtime"
)]
unsafe extern "C" fn submit(
    opaque: u64,
    input: *const AbiBlockSubmission,
) -> AbiBlockSubmitOutcome {
    if input.is_null()
        || !input
            .addr()
            .is_multiple_of(core::mem::align_of::<AbiBlockSubmission>())
    {
        return AbiBlockSubmitOutcome::rejected(AbiError::InvalidParam);
    }
    // SAFETY: the host owns the registration and serializes this runtime call.
    let Some(runtime) = (unsafe { runtime(opaque) }) else {
        return AbiBlockSubmitOutcome::rejected(AbiError::InvalidParam);
    };
    // SAFETY: the block ABI lends one initialized, aligned submission for this
    // call. Neither the reference nor its activation cookie is retained.
    let input = unsafe { &*input };
    let mut phase = runtime.phase.lock();
    let Phase::Ready(queue) = &mut *phase else {
        return AbiBlockSubmitOutcome::rejected(AbiError::DeviceBusy);
    };
    // SAFETY: the host retains payload DMA for this generation; its activation
    // callback excludes CPU access before our descriptors can be published.
    unsafe { queue.submit(&runtime.transport, input) }
}

#[expect(
    unsafe_code,
    reason = "terminal notifications are written only into the host's borrowed completion array and prefix count"
)]
unsafe extern "C" fn poll(
    opaque: u64,
    output: *mut AbiBlockCompletion,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    if written.is_null()
        || !written
            .addr()
            .is_multiple_of(core::mem::align_of::<usize>())
        || (capacity != 0
            && (output.is_null()
                || !output
                    .addr()
                    .is_multiple_of(core::mem::align_of::<AbiBlockCompletion>())))
    {
        return AbiError::InvalidParam as i32;
    }
    // SAFETY: the host provides one exclusive writable count for this call.
    unsafe { written.write(0) };
    // SAFETY: the callback owner retains runtime/code through acknowledged stop.
    let Some(runtime) = (unsafe { runtime(opaque) }) else {
        return AbiError::InvalidParam as i32;
    };
    let mut phase = runtime.phase.lock();
    let queue = match &mut *phase {
        Phase::Ready(queue) | Phase::Draining(queue) => queue,
        Phase::Closed => return AbiError::Success as i32,
        _ => return AbiError::DeviceBusy as i32,
    };
    for index in 0..capacity.min(queue.capacity()) {
        let completion = match queue.poll_completion() {
            Ok(Some(completion)) => completion,
            Ok(None) => return AbiError::Success as i32,
            Err(cause) => {
                log::error!(
                    "VirtIO block completion retained after {index} notifications: {cause:?}"
                );
                return AbiError::IoError as i32;
            }
        };
        // SAFETY: index < capacity; the host lends an exclusive valid output
        // array. One consumed notification is immediately committed to it.
        unsafe { output.add(index).write(completion) };
        // SAFETY: this count records the exact committed prefix, including when
        // the next iteration fails without consuming another notification.
        unsafe { written.write(index + 1) };
    }
    AbiError::Success as i32
}

#[expect(
    unsafe_code,
    reason = "the registration lends its retained Runtime for a readiness observation"
)]
unsafe extern "C" fn is_ready(opaque: u64) -> bool {
    // SAFETY: the host retains and serializes the registered opaque runtime.
    let Some(runtime) = (unsafe { runtime(opaque) }) else {
        return false;
    };
    let phase = runtime.phase.lock();
    let current = runtime.transport.status();
    matches!(*phase, Phase::Ready(_))
        && current & status::VIRTIO_STATUS_DRIVER_OK != 0
        && current & (status::VIRTIO_STATUS_FAILED | status::VIRTIO_STATUS_DEVICE_NEEDS_RESET) == 0
}

#[expect(
    unsafe_code,
    reason = "the retained callback owner requests one bounded, resource-preserving shutdown observation"
)]
unsafe extern "C" fn stop(opaque: u64) -> i32 {
    // SAFETY: the host owns this registration until stop acknowledges completion.
    let Some(runtime) = (unsafe { runtime(opaque) }) else {
        return AbiError::InvalidParam as i32;
    };
    if matches!(*runtime.phase.lock(), Phase::Closed) {
        return AbiError::Success as i32;
    }
    let timer = match timer() {
        Ok(timer) => timer,
        Err(_) => return AbiError::IoError as i32,
    };
    match runtime.advance_stop(timer.current_tick_ms()) {
        Ok(()) => AbiError::Success as i32,
        Err(cause) => AbiError::from(cause) as i32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_admission_respects_non_power_of_two_device_capacity() {
        assert_eq!(
            select_layout(255)
                .expect("bounded modern queue")
                .ring()
                .size(),
            128
        );
        assert_eq!(
            select_layout(256)
                .expect("bounded modern queue")
                .ring()
                .size(),
            256
        );
        assert_eq!(
            select_layout(u16::MAX).expect("policy bound").ring().size(),
            256
        );
        assert_eq!(select_layout(3), Err(KapiError::NotSupported));
    }

    #[test]
    fn reset_deadline_does_not_wrap() {
        assert_eq!(reset_deadline(7), Ok(30_007));
        assert_eq!(
            reset_deadline(u64::MAX),
            Err(KapiError::Timer(
                kernel_api::service::time::TimerError::ClockExhausted
            ))
        );
    }
}
