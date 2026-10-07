//! Stop acknowledgement precedes packet return, RAM unmapping and IRQ release.
//! Every failed transition retains the same owner at its completed stage.
#![deny(unsafe_code)]

use super::bootstrap::*;
use super::*;
use crate::core::{PreparedSplitVirtQueue, QueueBuildError};
use crate::net::*;
use crate::queue_memory::QueuePrepareError;
use kernel_api::dma::{
    CpuDmaLease, DmaCloseError, DmaLeaseError, DmaQuiesceWitness, PreparedSharedDmaLease,
};

enum Memory {
    Cpu(CpuDmaLease),
    Shared(PreparedSharedDmaLease),
    Protocol(PreparedNetProtocolRam),
    CloseFailed(DmaCloseError),
}

pub(super) struct Release {
    first: Option<Memory>,
    second: Option<Memory>,
}

impl Release {
    fn cpu(memory: CpuDmaLease) -> Self {
        Self {
            first: Some(Memory::Cpu(memory)),
            second: None,
        }
    }
    fn pair(first: Memory, second: Memory) -> Self {
        Self {
            first: Some(first),
            second: Some(second),
        }
    }
    fn ring<T>(ring: PreparedSplitVirtQueue<T>) -> Memory {
        match ring.abort() {
            Ok(memory) => Memory::Cpu(memory),
            Err(failure) => {
                let (cause, memory) = failure.into_parts();
                log::warn!("VirtIO unpublished ring cancellation retained: {cause:?}");
                Memory::Shared(memory)
            }
        }
    }
    fn prepared<T>(queue: PreparedNetCommandQueue<T>) -> Self {
        let (ring, protocol) = queue.into_unpublished();
        Self::pair(Self::ring(ring), Memory::Protocol(protocol))
    }
    fn prepare_error(cause: QueuePrepareError) -> Memory {
        match cause {
            QueuePrepareError::InvalidMemory { memory } | QueuePrepareError::Cpu { memory, .. } => {
                Memory::Cpu(memory)
            }
            QueuePrepareError::Prepared { memory, .. } => Memory::Shared(memory),
        }
    }
    fn ring_error(cause: QueueBuildError) -> Memory {
        match cause {
            QueueBuildError::DescriptorLimit { memory }
            | QueueBuildError::MetadataAllocation { memory } => Memory::Cpu(memory),
            QueueBuildError::Memory(cause) => Self::prepare_error(cause),
        }
    }
    fn command_error(cause: NetCommandBuildError) -> Self {
        match cause {
            NetCommandBuildError::MetadataAllocation { ring, protocol } => {
                Self::pair(Memory::Cpu(ring), Memory::Cpu(protocol))
            }
            NetCommandBuildError::Protocol { cause, ring } => {
                Self::pair(Memory::Cpu(ring), Self::prepare_error(cause))
            }
            NetCommandBuildError::Ring { cause, protocol } => {
                Self::pair(Self::ring_error(cause), Memory::Protocol(protocol))
            }
        }
    }
    fn advance(&mut self) -> Result<bool, DmaLeaseError> {
        let slot = if self.first.is_some() {
            &mut self.first
        } else {
            &mut self.second
        };
        let Some(memory) = slot.take() else {
            return Ok(true);
        };
        match memory {
            Memory::Cpu(memory) => match memory.close() {
                Ok(()) => {}
                Err(cause) => {
                    let error = cause.cause();
                    *slot = Some(Memory::CloseFailed(cause));
                    return Err(error);
                }
            },
            Memory::CloseFailed(failure) => {
                let (_, memory) = failure.into_parts();
                if let Err(cause) = memory.retry_close() {
                    let error = cause.cause();
                    *slot = Some(Memory::CloseFailed(cause));
                    return Err(error);
                }
            }
            Memory::Shared(memory) => match memory.abort() {
                Ok(memory) => *slot = Some(Memory::Cpu(memory)),
                Err(failure) => {
                    let (cause, memory) = failure.into_parts();
                    *slot = Some(Memory::Shared(memory));
                    return Err(cause);
                }
            },
            Memory::Protocol(memory) => match memory.abort() {
                Ok(memory) => *slot = Some(Memory::Cpu(memory)),
                Err(failure) => {
                    *slot = Some(Memory::Protocol(failure.memory));
                    return Err(failure.cause);
                }
            },
        }
        Ok(self.first.is_none() && self.second.is_none())
    }
}

pub(super) struct Stopping {
    network: Option<Network>,
    binding: Option<AbiNetPortRuntime>,
    step: StopStep,
}
enum StopStep {
    Resetting { deadline: u64 },
    Receive(usize),
    Transmit(usize),
    Control,
    Interrupt,
    Finished,
}

impl Runtime {
    pub(super) fn advance_stop(&self, now: u64) -> KapiResult<()> {
        let mut phase = self.phase.write();
        if matches!(*phase, Phase::Closed) {
            return Ok(());
        }
        if !matches!(*phase, Phase::Stopping(_)) {
            let end = deadline(now)?;
            let current = core::mem::replace(&mut *phase, Phase::Transitioning);
            let (network, binding) = match current {
                Phase::Resetting { .. } | Phase::Negotiating => (None, None),
                Phase::Building(build) => (Some(build.network), None),
                Phase::Configured(network) => (Some(network), None),
                Phase::Live { network, binding } => (Some(network), Some(binding)),
                other => {
                    *phase = other;
                    return Err(KapiError::Busy);
                }
            };
            self.transport.request_reset();
            *phase = Phase::Stopping(Stopping {
                network,
                binding,
                step: StopStep::Resetting { deadline: end },
            });
            return Err(KapiError::Busy);
        }
        let Phase::Stopping(stop) = &mut *phase else {
            return Err(KapiError::Busy);
        };
        if stop.advance(self, now)? {
            *phase = Phase::Closed;
            Ok(())
        } else {
            Err(KapiError::Busy)
        }
    }
}

impl Stopping {
    #[expect(
        unsafe_code,
        reason = "packet notifications are finalized only after this state machine observed reset acknowledgement"
    )]
    fn advance(&mut self, runtime: &Runtime, now: u64) -> KapiResult<bool> {
        self.step = match self.step {
            StopStep::Resetting { deadline } => {
                if runtime.transport.status() != 0 {
                    return if now < deadline {
                        Ok(false)
                    } else {
                        Err(KapiError::Timeout)
                    };
                }
                core::sync::atomic::fence(Ordering::Acquire);
                StopStep::Receive(0)
            }
            StopStep::Receive(index) => {
                if let Some(slot) = self
                    .network
                    .as_ref()
                    .and_then(|network| network.rx.get(index))
                {
                    if stop_rx(&mut slot.lock())? {
                        StopStep::Receive(index + 1)
                    } else {
                        StopStep::Receive(index)
                    }
                } else {
                    StopStep::Transmit(0)
                }
            }
            StopStep::Transmit(index) => {
                if let Some(slot) = self
                    .network
                    .as_ref()
                    .and_then(|network| network.tx.get(index))
                {
                    let binding = self.binding;
                    if stop_command(&mut slot.lock(), NetTxQueue::into_stopping, |owner| {
                        let Some(binding) = binding else {
                            return Err((KapiError::NotInitialized, owner));
                        };
                        // SAFETY: reset ended device reads, and this stop owner
                        // retains the issuing runtime until every return succeeds.
                        unsafe { owner.finish_after_stop(binding) }.map_err(|failure| {
                            (
                                failure
                                    .cause
                                    .into_result()
                                    .err()
                                    .unwrap_or(KapiError::IoError),
                                failure.notification,
                            )
                        })
                    })? {
                        StopStep::Transmit(index + 1)
                    } else {
                        StopStep::Transmit(index)
                    }
                } else {
                    StopStep::Control
                }
            }
            StopStep::Control => {
                if let Some(slot) = self
                    .network
                    .as_ref()
                    .and_then(|network| network.control.as_ref())
                {
                    if stop_command(
                        &mut slot.lock(),
                        |queue| {
                            let (queue, notification) = queue.into_stopping();
                            (queue, notification.map(|completion| completion.owner))
                        },
                        |_| Ok(()),
                    )? {
                        StopStep::Interrupt
                    } else {
                        StopStep::Control
                    }
                } else {
                    StopStep::Interrupt
                }
            }
            StopStep::Interrupt => {
                release_interrupt(runtime)?;
                StopStep::Finished
            }
            StopStep::Finished => return Ok(true),
        };
        Ok(false)
    }
}

fn release_interrupt(runtime: &Runtime) -> KapiResult<()> {
    let mut owner = runtime.interrupt.lock();
    if let InterruptOwner::Bound(info) = *owner {
        kernel_api::service::kernel::instance().unbind_irq(info.vector)?;
        *owner = InterruptOwner::Allocated(info);
    }
    if matches!(*owner, InterruptOwner::Allocated(_)) {
        kernel_api::service::kernel::instance().disable_msix(runtime.device)?;
        *owner = InterruptOwner::None;
    }
    Ok(())
}

#[expect(
    unsafe_code,
    reason = "this private transition runs only after acknowledged device reset and a DMA visibility fence"
)]
fn stop_rx(slot: &mut RxSlot) -> KapiResult<bool> {
    let stage = core::mem::replace(&mut slot.stage, RxStage::Transitioning);
    let (next, result) = match stage {
        RxStage::Planned => (RxStage::Closed, Ok(true)),
        RxStage::Allocated(memory) => (RxStage::Releasing(Release::cpu(memory)), Ok(false)),
        RxStage::BuildFailed(cause) => (
            RxStage::Releasing(Release {
                first: Some(Release::ring_error(cause)),
                second: None,
            }),
            Ok(false),
        ),
        RxStage::Prepared(queue) => (
            RxStage::Releasing(Release {
                first: Some(Release::ring(queue)),
                second: None,
            }),
            Ok(false),
        ),
        RxStage::Ready(queue) => {
            // SAFETY: acknowledged reset ends all ring and packet DMA for this
            // retained generation. The witness names only its ring allocation.
            let witness = unsafe {
                DmaQuiesceWitness::after_queue_quiesced(queue.identity(), queue.ring_lease_id())
            };
            match unsafe { queue.quiesce(witness) } {
                Ok(queue) => (RxStage::Retired(queue), Ok(false)),
                Err(failure) => {
                    log::warn!("VirtIO RX RAM retirement retained: {:?}", failure.cause);
                    (RxStage::Ready(failure.queue), Err(KapiError::IoError))
                }
            }
        }
        RxStage::Retired(mut queue) => match queue.next_packet() {
            Some(packet) => (RxStage::Returning { queue, packet }, Ok(false)),
            None => match queue.into_memory() {
                Ok(memory) => (RxStage::Releasing(Release::cpu(memory)), Ok(false)),
                Err(queue) => (RxStage::Retired(queue), Err(KapiError::Busy)),
            },
        },
        RxStage::Returning { queue, packet } => match packet.close() {
            Ok(()) => (RxStage::Retired(queue), Ok(false)),
            Err(failure) => {
                let stage = match failure.retained {
                    Some(packet) => RxStage::Returning { queue, packet },
                    None => RxStage::Retired(queue),
                };
                (
                    stage,
                    Err(failure
                        .cause
                        .into_result()
                        .err()
                        .unwrap_or(KapiError::IoError)),
                )
            }
        },
        RxStage::Releasing(mut memory) => match memory.advance() {
            Ok(true) => (RxStage::Closed, Ok(true)),
            Ok(false) => (RxStage::Releasing(memory), Ok(false)),
            Err(cause) => {
                log::warn!("VirtIO RX allocation close retained: {cause:?}");
                (RxStage::Releasing(memory), Err(KapiError::IoError))
            }
        },
        RxStage::Closed => (RxStage::Closed, Ok(true)),
        RxStage::Transitioning => (RxStage::Transitioning, Err(KapiError::Busy)),
    };
    slot.stage = next;
    result
}

#[expect(
    unsafe_code,
    reason = "only the acknowledged-reset stop state can create quiescence witnesses for these exact retained allocations"
)]
fn stop_command<T, Q>(
    slot: &mut CommandSlot<T, Q>,
    unbind: impl FnOnce(Q) -> (NetCommandQueue<T>, Option<T>),
    finish: impl FnOnce(T) -> Result<(), (KapiError, T)>,
) -> KapiResult<bool> {
    // Return consumed hardware notifications before consuming a later owner.
    if let Some(notification) = slot.notification.take() {
        if let Err((cause, notification)) = finish(notification) {
            slot.notification = Some(notification);
            return Err(cause);
        }
        return Ok(false);
    }
    let stage = core::mem::replace(&mut slot.stage, CommandStage::Transitioning);
    let (next, result) = match stage {
        CommandStage::Planned => (CommandStage::Closed, Ok(true)),
        CommandStage::Allocated(memory) => {
            (CommandStage::Releasing(Release::cpu(memory)), Ok(false))
        }
        CommandStage::BuildFailed(cause) => (
            CommandStage::Releasing(Release::command_error(cause)),
            Ok(false),
        ),
        CommandStage::Prepared(queue) => {
            (CommandStage::Releasing(Release::prepared(queue)), Ok(false))
        }
        CommandStage::Ready(queue) => {
            let (queue, notification) = unbind(queue);
            slot.notification = notification;
            (CommandStage::Active(queue), Ok(false))
        }
        CommandStage::Partial(queue) => {
            // SAFETY: observed reset covers this active protocol allocation;
            // ring publication never succeeded in Partial.
            let witness = unsafe {
                DmaQuiesceWitness::after_queue_quiesced(queue.identity(), queue.protocol_lease_id())
            };
            match queue.quiesce(witness) {
                Ok((protocol, ring)) => (
                    CommandStage::Releasing(Release::pair(
                        Memory::Cpu(protocol),
                        Release::ring(ring),
                    )),
                    Ok(false),
                ),
                Err(failure) => (
                    CommandStage::Partial(failure.queue),
                    Err(KapiError::IoError),
                ),
            }
        }
        CommandStage::Active(queue) => {
            // SAFETY: stop ended all device access to these two allocations.
            let protocol = unsafe {
                DmaQuiesceWitness::after_queue_quiesced(queue.identity(), queue.protocol_lease_id())
            };
            let ring = unsafe {
                DmaQuiesceWitness::after_queue_quiesced(queue.identity(), queue.ring_lease_id())
            };
            match queue.quiesce(protocol, ring) {
                Ok(queue) => (CommandStage::Retired(queue), Ok(false)),
                Err(NetCommandRetireError::Protocol { queue, .. }) => {
                    (CommandStage::Active(queue), Err(KapiError::IoError))
                }
                Err(NetCommandRetireError::Ring(failure)) => (
                    CommandStage::Retiring(failure.retirement),
                    Err(KapiError::IoError),
                ),
            }
        }
        CommandStage::Retiring(retirement) => {
            // SAFETY: reset is still held, protocol retirement succeeded; only
            // this exact ring remains device-shared in the retained owner.
            let witness = unsafe {
                DmaQuiesceWitness::after_queue_quiesced(
                    retirement.identity(),
                    retirement.ring_lease_id(),
                )
            };
            match retirement.quiesce(witness) {
                Ok(queue) => (CommandStage::Retired(queue), Ok(false)),
                Err(failure) => (
                    CommandStage::Retiring(failure.retirement),
                    Err(KapiError::IoError),
                ),
            }
        }
        CommandStage::Retired(mut queue) => match queue.ring.next_aborted() {
            Some(owner) => {
                slot.notification = Some(owner);
                (CommandStage::Retired(queue), Ok(false))
            }
            None => (
                CommandStage::Releasing(Release::pair(
                    Memory::Cpu(queue.protocol),
                    Memory::Cpu(queue.ring.memory),
                )),
                Ok(false),
            ),
        },
        CommandStage::Releasing(mut memory) => match memory.advance() {
            Ok(true) => (CommandStage::Closed, Ok(true)),
            Ok(false) => (CommandStage::Releasing(memory), Ok(false)),
            Err(cause) => {
                log::warn!("VirtIO command allocation close retained: {cause:?}");
                (CommandStage::Releasing(memory), Err(KapiError::IoError))
            }
        },
        CommandStage::Closed => (CommandStage::Closed, Ok(true)),
        CommandStage::Transitioning => (CommandStage::Transitioning, Err(KapiError::Busy)),
    };
    slot.stage = next;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel_api::dma::*;

    struct ClosingAllocation {
        identity: DmaLeaseId,
        state: AtomicU32,
        close_calls: AtomicU32,
        retry_calls: AtomicU32,
        abandoned: AtomicU32,
        fail_retries: AtomicU32,
        bytes: Mutex<[u8; 8]>,
    }
    impl ClosingAllocation {
        fn new(slot: u32, fail_retries: u32) -> Arc<Self> {
            Arc::new(Self {
                identity: DmaLeaseId::from_parts(slot, 1).unwrap(),
                state: AtomicU32::new(0),
                close_calls: AtomicU32::new(0),
                retry_calls: AtomicU32::new(0),
                abandoned: AtomicU32::new(0),
                fail_retries: AtomicU32::new(fail_retries),
                bytes: Mutex::new([0; 8]),
            })
        }
    }
    // SAFETY: this private authority admits only CPU access and final close;
    // every device publication transition is rejected. Backing remains retained
    // in the fixture through quarantine/retry, and visits exclude final close.
    #[expect(
        unsafe_code,
        reason = "the fixture implements the production DMA ownership boundary without admitting any device access"
    )]
    unsafe impl DmaLeaseAuthority for ClosingAllocation {
        fn lease_id(&self) -> DmaLeaseId {
            self.identity
        }
        fn device_address(&self) -> DmaDeviceAddress {
            DmaDeviceAddress::from_abi(4096)
        }
        fn byte_count(&self) -> DmaByteCount {
            DmaByteCount::new(8).unwrap()
        }
        fn direction(&self) -> DmaDirection {
            DmaDirection::Bidirectional
        }
        fn with_cpu_bytes(&self, visitor: &mut dyn FnMut(&[u8])) -> Result<(), DmaLeaseError> {
            let bytes = self.bytes.lock();
            if self.state.load(Ordering::Acquire) != 0 {
                return Err(DmaLeaseError::InvalidState);
            }
            visitor(&*bytes);
            Ok(())
        }
        fn with_cpu_bytes_mut(
            &self,
            visitor: &mut dyn FnMut(&mut [u8]),
        ) -> Result<(), DmaLeaseError> {
            let mut bytes = self.bytes.lock();
            if self.state.load(Ordering::Acquire) != 0 {
                return Err(DmaLeaseError::InvalidState);
            }
            visitor(&mut *bytes);
            Ok(())
        }
        fn prepare(&self, _: DmaQueueIdentity) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::NotSupported)
        }
        fn prepared_queue(&self) -> Result<DmaQueueIdentity, DmaLeaseError> {
            Err(DmaLeaseError::InvalidState)
        }
        fn abort_prepared(&self) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::InvalidState)
        }
        fn arm(&self) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::NotSupported)
        }
        fn complete(&self, _: DmaCompletionWitness) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::InvalidState)
        }
        fn return_to_cpu(&self) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::InvalidState)
        }
        fn mark_outcome_unknown(&self) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::InvalidState)
        }
        fn revoke_after_reset(&self, _: DmaResetWitness) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::InvalidState)
        }
        fn reconcile(&self, _: DmaReconcileWitness) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::InvalidState)
        }
        fn close(&self) -> Result<(), DmaLeaseError> {
            let _bytes = self.bytes.lock();
            self.state
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| DmaLeaseError::InvalidState)?;
            self.close_calls.fetch_add(1, Ordering::Relaxed);
            Err(DmaLeaseError::IommuFailure)
        }
        fn prepare_shared(&self, _: DmaQueueIdentity) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::NotSupported)
        }
        fn activate_shared(&self) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::InvalidState)
        }
        fn read_shared_word(&self, _: usize, _: DmaAccessWidth) -> Result<u64, DmaLeaseError> {
            Err(DmaLeaseError::InvalidState)
        }
        fn write_shared_word(
            &self,
            _: usize,
            _: DmaAccessWidth,
            _: u64,
        ) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::InvalidState)
        }
        fn quiesce_shared(&self, _: DmaQuiesceWitness) -> Result<(), DmaLeaseError> {
            Err(DmaLeaseError::InvalidState)
        }
        fn retry_close(&self) -> Result<(), DmaLeaseError> {
            let _bytes = self.bytes.lock();
            if self.state.load(Ordering::Acquire) != 1 {
                return Err(DmaLeaseError::InvalidState);
            }
            self.retry_calls.fetch_add(1, Ordering::Relaxed);
            if self
                .fail_retries
                .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    count.checked_sub(1)
                })
                .is_ok()
            {
                return Err(DmaLeaseError::IommuFailure);
            }
            self.state.store(2, Ordering::Release);
            Ok(())
        }
        fn abandon(&self, _: DmaLeaseState) {
            self.abandoned.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn failed_unmap_retries_its_allocation_without_reclosing_or_releasing_later_ram() {
        let first = ClosingAllocation::new(1, 1);
        let second = ClosingAllocation::new(2, 0);
        let mut release = Release::pair(
            Memory::Cpu(CpuDmaLease::from_authority(first.clone())),
            Memory::Cpu(CpuDmaLease::from_authority(second.clone())),
        );
        assert_eq!(release.advance(), Err(DmaLeaseError::IommuFailure));
        assert_eq!(release.advance(), Err(DmaLeaseError::IommuFailure));
        assert_eq!(first.close_calls.load(Ordering::Relaxed), 1);
        assert_eq!(second.close_calls.load(Ordering::Relaxed), 0);
        assert_eq!(release.advance(), Ok(false));
        assert_eq!(first.state.load(Ordering::Acquire), 2);
        assert_eq!(release.advance(), Err(DmaLeaseError::IommuFailure));
        assert_eq!(release.advance(), Ok(true));
        assert_eq!(first.retry_calls.load(Ordering::Relaxed), 2);
        assert_eq!(second.close_calls.load(Ordering::Relaxed), 1);
        assert_eq!(second.retry_calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            first.abandoned.load(Ordering::Relaxed) + second.abandoned.load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn stop_notification_failure_retains_the_same_owner_until_acknowledged() {
        let identity = DmaQueueIdentity::new(PackedPciLocation::new(0, 0, 1, 0), 1, 9).unwrap();
        let mut slot = CommandSlot {
            identity,
            layout: NetCommandLayout::new(NetProtocolKind::Transmit, 2).unwrap(),
            stage: CommandStage::<u64, ()>::Planned,
            notification: Some(19),
        };
        assert_eq!(
            stop_command(
                &mut slot,
                |_| unreachable!(),
                |owner| Err((KapiError::Busy, owner))
            ),
            Err(KapiError::Busy)
        );
        assert_eq!(slot.notification, Some(19));
        let mut returned = 0;
        assert_eq!(
            stop_command(
                &mut slot,
                |_| unreachable!(),
                |owner| {
                    assert_eq!(owner, 19);
                    returned += 1;
                    Ok(())
                }
            ),
            Ok(false)
        );
        assert_eq!(returned, 1);
        assert!(slot.notification.is_none());
        assert_eq!(
            stop_command(&mut slot, |_| unreachable!(), |_| unreachable!()),
            Ok(true)
        );
    }
}
