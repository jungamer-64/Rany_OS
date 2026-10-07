//! Every bootstrap step stores its exact RAM stage before yielding to the host.
#![deny(unsafe_code)]

use super::*;
use crate::core::{PreparedSplitVirtQueue, QueueBuildError};
use crate::defs::{common_features, status};
use crate::net::*;
use crate::queue_memory::{QueueInterrupt, SplitQueueLayout};
use alloc::vec::Vec;
use core::num::NonZeroU16;
use kernel_api::abi::driver::{CpuRxLease, PostedRxLease};
use kernel_api::dma::{CpuDmaLease, DmaAllocationRequest, DmaDirection, DmaQueueIdentity};

// Queue allocation identity only. It never identifies an executing task.
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
const MAX_PAIRS: u16 = 4;

pub(super) enum RxStage {
    Planned,
    Allocated(CpuDmaLease),
    Prepared(PreparedSplitVirtQueue<PostedRxLease>),
    BuildFailed(QueueBuildError),
    Ready(NetRxQueue),
    Retired(RetiredNetRxQueue),
    Returning {
        queue: RetiredNetRxQueue,
        packet: CpuRxLease,
    },
    Releasing(retirement::Release),
    Closed,
    Transitioning,
}

pub(super) enum CommandStage<T, Q> {
    Planned,
    Allocated(CpuDmaLease),
    Prepared(PreparedNetCommandQueue<T>),
    BuildFailed(NetCommandBuildError),
    Partial(PartiallyActivatedNetCommandQueue<T>),
    Active(NetCommandQueue<T>),
    Ready(Q),
    Retiring(NetCommandRingRetirement<T>),
    Retired(RetiredNetCommandQueue<T>),
    Releasing(retirement::Release),
    Closed,
    Transitioning,
}

pub(super) struct RxSlot {
    pub identity: DmaQueueIdentity,
    pub layout: SplitQueueLayout,
    pub stage: RxStage,
}

pub(super) struct CommandSlot<T, Q> {
    pub identity: DmaQueueIdentity,
    pub layout: NetCommandLayout,
    pub stage: CommandStage<T, Q>,
    // Retains an already-consumed notification while stop returns later owners.
    pub notification: Option<T>,
}

pub(super) type TxSlot = CommandSlot<NetTxNotification, NetTxQueue>;
pub(super) type ControlSlot = CommandSlot<QueuePairCommand, NetControlQueue>;

pub(super) enum PairEnablement {
    Single,
    Requested(NonZeroU16),
    Enabled(EnabledQueuePairs),
}

pub(super) struct Network {
    pub configuration: NetConfiguration,
    pub rx: Vec<Mutex<RxSlot>>,
    pub tx: Vec<Mutex<TxSlot>>,
    pub control: Option<Mutex<ControlSlot>>,
    pub pairs: PairEnablement,
    pub next_tx: AtomicU32,
    pub reported_link: Mutex<Option<bool>>,
}

impl Network {
    pub fn enabled_pairs(&self) -> KapiResult<u16> {
        match &self.pairs {
            PairEnablement::Single => Ok(1),
            PairEnablement::Enabled(pairs) => Ok(pairs.count().get()),
            PairEnablement::Requested(_) => Err(KapiError::Busy),
        }
    }
}

pub(super) struct Building {
    pub network: Network,
    step: BootStep,
}

enum BootStep {
    Interrupt,
    Receive(usize),
    Transmit(usize),
    Control,
    DriverReady,
    EnablePairs,
    WaitPairs { deadline: u64 },
    Finished,
}

impl Runtime {
    pub(super) fn advance_boot(&self, context: &mut DriverContext, now: u64) -> KapiResult<bool> {
        let mut phase = self.phase.write();
        match &mut *phase {
            Phase::Resetting { deadline } => {
                if self.transport.status() != 0 {
                    return if now < *deadline {
                        Ok(false)
                    } else {
                        Err(KapiError::Timeout)
                    };
                }
                *phase = Phase::Negotiating;
            }
            Phase::Negotiating => {
                *phase = Phase::Building(Building {
                    network: self.negotiate()?,
                    step: BootStep::Interrupt,
                });
            }
            Phase::Building(build) => {
                if build.advance(self, context, now)? {
                    let current = core::mem::replace(&mut *phase, Phase::Transitioning);
                    if let Phase::Building(build) = current {
                        *phase = Phase::Configured(build.network);
                    }
                }
            }
            Phase::Configured(_) => return Ok(true),
            _ => return Err(KapiError::Busy),
        }
        Ok(false)
    }

    fn negotiate(&self) -> KapiResult<Network> {
        self.transport
            .add_status(status::VIRTIO_STATUS_ACKNOWLEDGE | status::VIRTIO_STATUS_DRIVER);
        let offered = self.transport.device_features();
        let required =
            common_features::VIRTIO_F_VERSION_1 | common_features::VIRTIO_F_ACCESS_PLATFORM;
        if offered & required != required {
            return Err(KapiError::NotSupported);
        }
        let features = offered & NET_SUPPORTED_FEATURES;
        self.transport.set_driver_features(features);
        self.transport.add_status(status::VIRTIO_STATUS_FEATURES_OK);
        let raw = self.device.raw().to_le_bytes();
        let configuration = NetConfiguration::read(
            &self.transport,
            features,
            [2, raw[3], raw[2], raw[1], raw[0], 1],
        )
        .map_err(|cause| {
            log::error!("VirtIO net configuration rejected: {cause:?}");
            KapiError::IoError
        })?;
        let count = configuration.offered_pairs().get().min(MAX_PAIRS);
        let pairs = NonZeroU16::new(count).ok_or(KapiError::InvalidSize)?;
        let generation = NEXT_GENERATION
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .map_err(|_| KapiError::ResourceExhausted)?;
        let identity =
            DmaQueueIdentity::new(self.device, 0, generation).ok_or(KapiError::InvalidHandle)?;
        let mut rx = Vec::new();
        let mut tx = Vec::new();
        rx.try_reserve_exact(usize::from(count))
            .map_err(|_| KapiError::OutOfMemory)?;
        tx.try_reserve_exact(usize::from(count))
            .map_err(|_| KapiError::OutOfMemory)?;
        for pair in 0..count {
            let receive = pair * 2;
            let transmit = receive + 1;
            rx.push(Mutex::new(RxSlot {
                identity: identity.with_index(receive),
                layout: split_layout(
                    self.transport
                        .queue_capacity(receive)
                        .map_err(|_| KapiError::IoError)?,
                    1,
                )?,
                stage: RxStage::Planned,
            }));
            tx.push(Mutex::new(CommandSlot {
                identity: identity.with_index(transmit),
                layout: command_layout(&self.transport, transmit, NetProtocolKind::Transmit)?,
                stage: CommandStage::Planned,
                notification: None,
            }));
        }
        let (control, enablement) = if configuration.offered_pairs().get() > 1 {
            let index = configuration
                .control_queue_index()
                .map_err(|_| KapiError::NotSupported)?;
            (
                Some(Mutex::new(CommandSlot {
                    identity: identity.with_index(index),
                    layout: command_layout(&self.transport, index, NetProtocolKind::Control)?,
                    stage: CommandStage::Planned,
                    notification: None,
                })),
                PairEnablement::Requested(pairs),
            )
        } else {
            (None, PairEnablement::Single)
        };
        Ok(Network {
            configuration,
            rx,
            tx,
            control,
            pairs: enablement,
            next_tx: AtomicU32::new(0),
            reported_link: Mutex::new(None),
        })
    }

    fn bind_interrupt(&self, context: &mut DriverContext) -> KapiResult<QueueInterrupt> {
        let mut owner = self.interrupt.lock();
        if matches!(*owner, InterruptOwner::None) {
            let vectors = kernel_api::service::kernel::instance().enable_msix(self.device, 1)?;
            let info = vectors.first().copied().ok_or(KapiError::IoError)?;
            *owner = InterruptOwner::Allocated(info);
        }
        let info = match *owner {
            InterruptOwner::Allocated(info) => {
                kernel_api::service::kernel::instance().bind_irq(info.vector, self.device.raw())?;
                *owner = InterruptOwner::Bound(info);
                info
            }
            InterruptOwner::Bound(info) => info,
            InterruptOwner::None => return Err(KapiError::NotInitialized),
        };
        context.irq = info.vector;
        self.transport
            .configure_configuration_interrupt(QueueInterrupt::Msix(info.table_index))
            .map_err(|_| KapiError::IoError)?;
        Ok(QueueInterrupt::Msix(info.table_index))
    }

    fn queue_interrupt(&self) -> KapiResult<QueueInterrupt> {
        match *self.interrupt.lock() {
            InterruptOwner::Bound(info) => Ok(QueueInterrupt::Msix(info.table_index)),
            _ => Err(KapiError::NotInitialized),
        }
    }
}

impl Building {
    #[expect(
        clippy::result_large_err,
        reason = "queue binding closures return activated RAM inline on rejection; cleanup must not require allocation"
    )]
    #[expect(
        unsafe_code,
        reason = "DRIVER_OK precedes control publication and the retained queue owns its admitted protocol RAM"
    )]
    fn advance(
        &mut self,
        runtime: &Runtime,
        context: &mut DriverContext,
        now: u64,
    ) -> KapiResult<bool> {
        self.step = match self.step {
            BootStep::Interrupt => {
                runtime.bind_interrupt(context)?;
                BootStep::Receive(0)
            }
            BootStep::Receive(index) => {
                if let Some(slot) = self.network.rx.get(index) {
                    if advance_rx(&mut slot.lock(), runtime, self.network.configuration)? {
                        BootStep::Receive(index + 1)
                    } else {
                        BootStep::Receive(index)
                    }
                } else {
                    BootStep::Transmit(0)
                }
            }
            BootStep::Transmit(index) => {
                if let Some(slot) = self.network.tx.get(index) {
                    if advance_command(
                        &mut slot.lock(),
                        runtime,
                        runtime.queue_interrupt()?,
                        |queue| NetTxQueue::bind(self.network.configuration, queue),
                    )? {
                        BootStep::Transmit(index + 1)
                    } else {
                        BootStep::Transmit(index)
                    }
                } else {
                    BootStep::Control
                }
            }
            BootStep::Control => {
                if let Some(slot) = &self.network.control {
                    if advance_command(
                        &mut slot.lock(),
                        runtime,
                        QueueInterrupt::Polled,
                        |queue| NetControlQueue::bind(self.network.configuration, queue),
                    )? {
                        BootStep::DriverReady
                    } else {
                        BootStep::Control
                    }
                } else {
                    BootStep::DriverReady
                }
            }
            BootStep::DriverReady => {
                runtime
                    .transport
                    .add_status(status::VIRTIO_STATUS_DRIVER_OK);
                BootStep::EnablePairs
            }
            BootStep::EnablePairs => {
                if let PairEnablement::Requested(pairs) = self.network.pairs {
                    let end = deadline(now)?;
                    let command = self
                        .network
                        .configuration
                        .queue_pair_command(pairs)
                        .map_err(|_| KapiError::NotSupported)?;
                    let control = self
                        .network
                        .control
                        .as_ref()
                        .ok_or(KapiError::NotInitialized)?;
                    let mut control = control.lock();
                    let CommandStage::Ready(queue) = &mut control.stage else {
                        return Err(KapiError::Busy);
                    };
                    // SAFETY: all queue RAM is retained, this is the negotiated
                    // control queue, and the preceding step established DRIVER_OK.
                    let outcome = unsafe { queue.submit(command) }.map_err(|failure| {
                        log::error!("VirtIO MQ request rejected: {:?}", failure.cause);
                        KapiError::IoError
                    })?;
                    self.step = BootStep::WaitPairs { deadline: end };
                    if matches!(
                        outcome,
                        crate::core::QueueSubmitOutcome::PublicationUncertain { .. }
                    ) {
                        return Err(KapiError::IoError);
                    }
                    BootStep::WaitPairs { deadline: end }
                } else {
                    BootStep::Finished
                }
            }
            BootStep::WaitPairs { deadline } => {
                let control = self
                    .network
                    .control
                    .as_ref()
                    .ok_or(KapiError::NotInitialized)?;
                let mut control = control.lock();
                let CommandStage::Ready(queue) = &mut control.stage else {
                    return Err(KapiError::Busy);
                };
                match queue.poll().map_err(|cause| {
                    log::error!("VirtIO MQ ACK failed: {cause:?}");
                    KapiError::IoError
                })? {
                    Some(enabled) => {
                        self.network.pairs = PairEnablement::Enabled(enabled);
                        BootStep::Finished
                    }
                    None if now < deadline => BootStep::WaitPairs { deadline },
                    None => return Err(KapiError::Timeout),
                }
            }
            BootStep::Finished => return Ok(true),
        };
        Ok(false)
    }
}

fn advance_rx(
    slot: &mut RxSlot,
    runtime: &Runtime,
    configuration: NetConfiguration,
) -> KapiResult<bool> {
    let interrupt = runtime.queue_interrupt()?;
    let stage = core::mem::replace(&mut slot.stage, RxStage::Transitioning);
    let (next, result) = match stage {
        RxStage::Planned => match allocate(runtime.device, slot.layout.byte_count()) {
            Ok(memory) => (RxStage::Allocated(memory), Ok(false)),
            Err(cause) => (RxStage::Planned, Err(cause)),
        },
        RxStage::Allocated(memory) => {
            match PreparedSplitVirtQueue::prepare(slot.identity, slot.layout, interrupt, memory) {
                Ok(queue) => (RxStage::Prepared(queue), Ok(false)),
                Err(cause) => (RxStage::BuildFailed(cause), Err(KapiError::IoError)),
            }
        }
        RxStage::Prepared(queue) => {
            match NetRxQueue::activate(configuration, queue, &runtime.transport) {
                Ok(queue) => (RxStage::Ready(queue), Ok(true)),
                Err(failure) => (RxStage::Prepared(failure.queue), Err(KapiError::IoError)),
            }
        }
        RxStage::Ready(queue) => (RxStage::Ready(queue), Ok(true)),
        other => (other, Err(KapiError::Busy)),
    };
    slot.stage = next;
    result
}

fn advance_command<T, Q>(
    slot: &mut CommandSlot<T, Q>,
    runtime: &Runtime,
    interrupt: QueueInterrupt,
    bind: impl FnOnce(NetCommandQueue<T>) -> Result<Q, NetQueueBindError<T>>,
) -> KapiResult<bool> {
    let stage = core::mem::replace(&mut slot.stage, CommandStage::Transitioning);
    let (next, result) = match stage {
        CommandStage::Planned => match allocate(runtime.device, slot.layout.ring().byte_count()) {
            Ok(memory) => (CommandStage::Allocated(memory), Ok(false)),
            Err(cause) => (CommandStage::Planned, Err(cause)),
        },
        CommandStage::Allocated(ring) => {
            match allocate(runtime.device, slot.layout.protocol_byte_count()) {
                Err(cause) => (CommandStage::Allocated(ring), Err(cause)),
                Ok(protocol) => match PreparedNetCommandQueue::prepare(
                    slot.identity,
                    slot.layout,
                    interrupt,
                    ring,
                    protocol,
                ) {
                    Ok(queue) => (CommandStage::Prepared(queue), Ok(false)),
                    Err(cause) => (CommandStage::BuildFailed(cause), Err(KapiError::IoError)),
                },
            }
        }
        CommandStage::Prepared(queue) => match queue.activate(&runtime.transport) {
            Ok(queue) => (CommandStage::Active(queue), Ok(false)),
            Err(NetCommandActivationError::Protocol { queue, .. }) => {
                (CommandStage::Prepared(queue), Err(KapiError::IoError))
            }
            Err(NetCommandActivationError::Ring { queue, .. }) => {
                (CommandStage::Partial(queue), Err(KapiError::IoError))
            }
        },
        CommandStage::Active(queue) => match bind(queue) {
            Ok(queue) => (CommandStage::Ready(queue), Ok(true)),
            Err(failure) => (CommandStage::Active(failure.queue), Err(KapiError::IoError)),
        },
        CommandStage::Ready(queue) => (CommandStage::Ready(queue), Ok(true)),
        other => (other, Err(KapiError::Busy)),
    };
    slot.stage = next;
    result
}

pub(super) fn allocate(device: PackedPciLocation, bytes: usize) -> KapiResult<CpuDmaLease> {
    let request = DmaAllocationRequest::new(bytes, DmaDirection::Bidirectional)
        .ok_or(KapiError::InvalidSize)?;
    kernel_api::service::kernel::instance().alloc_dma_for_device(request, device)
}
fn command_layout(
    transport: &dyn VirtioTransport,
    index: u16,
    kind: NetProtocolKind,
) -> KapiResult<NetCommandLayout> {
    let split = split_layout(
        transport
            .queue_capacity(index)
            .map_err(|_| KapiError::IoError)?,
        2,
    )?;
    NetCommandLayout::new(kind, split.size()).map_err(|_| KapiError::NotSupported)
}
fn split_layout(maximum: u16, minimum: u16) -> KapiResult<SplitQueueLayout> {
    let limited = maximum.min(256);
    if limited < minimum {
        return Err(KapiError::NotSupported);
    }
    let size = 1u16 << (15 - limited.leading_zeros());
    SplitQueueLayout::new(size).map_err(|_| KapiError::InvalidSize)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn queue_policy_rounds_down_and_rejects_inadequate_command_capacity() {
        assert_eq!(split_layout(255, 2).unwrap().size(), 128);
        assert_eq!(split_layout(u16::MAX, 2).unwrap().size(), 256);
        assert!(matches!(split_layout(1, 2), Err(KapiError::NotSupported)));
        assert!(matches!(split_layout(0, 1), Err(KapiError::NotSupported)));
    }
}
