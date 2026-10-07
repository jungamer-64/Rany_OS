//! The input service owns this device across every async lifecycle wait. Stop
//! retains prepared, partially active and failed-unmap resources for retry.
#![deny(unsafe_code)]

use super::{
    VirtioInputEvent, config_select,
    queue::{InputQueue, QueueRole},
};
use crate::core::QueueSubmitOutcome;
use crate::defs::{VirtioDeviceType, common_features, status};
use crate::queue_memory::QueueInterrupt;
use crate::transport::{PciTransportDiscoveryError, VirtioPciTransport, VirtioTransport};
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::dma::DmaQueueIdentity;
use kernel_api::{KapiError, KapiResult};

const OPERATION_TIMEOUT_MS: u64 = 30_000;
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

enum Phase {
    Acquired,
    Resetting { deadline: u64 },
    Negotiating,
    Receive,
    Status,
    DriverReady,
    Ready,
    Failed,
    Stopping { deadline: u64 },
    RetiringReceive,
    RetiringStatus,
    Closed,
}

/// An accepted status event remains owned by the device until completion or
/// acknowledged reset. Uncertain publication must not be resubmitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputStatusOutcome {
    Submitted,
    PublicationUncertain {
        cause: kernel_api::dma::DmaLeaseError,
    },
}

/// A PCI input function owned by its input service, without a global lookup or
/// detached poller. Polling, status submission and lifecycle require an exclusive
/// borrow; an async caller retains this object and its code through cancellation.
/// Queue interrupt selection must name a vector owned by that same service.
pub struct VirtioInputDevice {
    transport: VirtioPciTransport,
    device: PackedPciLocation,
    interrupt: QueueInterrupt,
    phase: Phase,
    receive: Option<InputQueue>,
    status: Option<InputQueue>,
}

impl VirtioInputDevice {
    /// Acquire retained BAR-relative register authority for the bound function.
    /// # Errors
    /// Preserves mapping/metadata admission failures; rejects absent or foreign
    /// device types before any reset, queue allocation or DMA publication.
    pub fn acquire(device: PackedPciLocation, interrupt: QueueInterrupt) -> KapiResult<Self> {
        let transport =
            VirtioPciTransport::acquire(device, VirtioDeviceType::Input).map_err(|cause| {
                match cause {
                    PciTransportDiscoveryError::Mapping(cause) => KapiError::Mmio(cause),
                    PciTransportDiscoveryError::Allocation => KapiError::OutOfMemory,
                    _ => KapiError::IoError,
                }
            })?;
        Ok(Self {
            transport,
            device,
            interrupt,
            phase: Phase::Acquired,
            receive: None,
            status: None,
        })
    }

    /// Prepare both queues, establish DRIVER_OK, then populate event buffers.
    /// Cancellation retains every completed bootstrap stage in this instance.
    /// # Errors
    /// Returns timer, feature, allocation or hardware failure. Failure does not
    /// acknowledge resource release; the owner must drive `stop` before removal.
    pub async fn initialize(&mut self) -> KapiResult<()> {
        let timer = timer()?;
        if matches!(self.phase, Phase::Acquired) {
            self.phase = Phase::Resetting {
                deadline: deadline(timer.current_tick_ms())?,
            };
            self.transport.request_reset();
        }
        // LOOP_PROOF: mode=event; reason=Each retained bootstrap step precedes a timer wait, and readiness, typed failure or the bounded reset deadline ends initialization.;
        loop {
            if self.advance_boot(timer.current_tick_ms())? {
                return Ok(());
            }
            kernel_api::service::time::SleepFuture::new(timer, 1)
                .await
                .map_err(KapiError::Timer)?;
        }
    }

    fn advance_boot(&mut self, now: u64) -> KapiResult<bool> {
        self.phase = match self.phase {
            Phase::Resetting { deadline } => {
                if self.transport.status() != 0 {
                    return if now < deadline {
                        Ok(false)
                    } else {
                        Err(KapiError::Timeout)
                    };
                }
                Phase::Negotiating
            }
            Phase::Negotiating => {
                self.transport
                    .add_status(status::VIRTIO_STATUS_ACKNOWLEDGE | status::VIRTIO_STATUS_DRIVER);
                let mandatory =
                    common_features::VIRTIO_F_VERSION_1 | common_features::VIRTIO_F_ACCESS_PLATFORM;
                if self.transport.device_features() & mandatory != mandatory {
                    return Err(KapiError::NotSupported);
                }
                self.transport.set_driver_features(mandatory);
                self.transport.add_status(status::VIRTIO_STATUS_FEATURES_OK);
                if self.transport.status() & status::VIRTIO_STATUS_FEATURES_OK == 0 {
                    return Err(KapiError::NotSupported);
                }
                let generation = NEXT_GENERATION
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                        next.checked_add(1)
                    })
                    .map_err(|_| KapiError::ResourceExhausted)?;
                let identity = DmaQueueIdentity::new(self.device, 0, generation)
                    .ok_or(KapiError::InvalidHandle)?;
                // Geometry is validated for both queues before acquiring any RAM.
                let receive = InputQueue::new(
                    identity,
                    self.transport
                        .queue_capacity(0)
                        .map_err(|_| KapiError::IoError)?,
                    QueueRole::Receive,
                    self.interrupt,
                )?;
                let status = InputQueue::new(
                    identity.with_index(1),
                    self.transport
                        .queue_capacity(1)
                        .map_err(|_| KapiError::IoError)?,
                    QueueRole::Status,
                    self.interrupt,
                )?;
                self.receive = Some(receive);
                self.status = Some(status);
                // The selector transaction is serialized by the exclusive device
                // borrow. Both selectors are set; unsupported queries are empty.
                self.query_config(config_select::VIRTIO_INPUT_CFG_EV_BITS, 0)?;
                Phase::Receive
            }
            Phase::Receive => {
                if self
                    .receive
                    .as_mut()
                    .ok_or(KapiError::NotInitialized)?
                    .advance_boot(&self.transport)?
                {
                    Phase::Status
                } else {
                    Phase::Receive
                }
            }
            Phase::Status => {
                if self
                    .status
                    .as_mut()
                    .ok_or(KapiError::NotInitialized)?
                    .advance_boot(&self.transport)?
                {
                    Phase::DriverReady
                } else {
                    Phase::Status
                }
            }
            Phase::DriverReady => {
                self.transport.add_status(status::VIRTIO_STATUS_DRIVER_OK);
                // Ready is established before publication; uncertain publication
                // retains the accepted head for reset instead of repeating init.
                self.phase = Phase::Failed;
                if let Err(cause) = self
                    .receive
                    .as_mut()
                    .ok_or(KapiError::NotInitialized)?
                    .refill()
                {
                    self.transport.add_status(status::VIRTIO_STATUS_FAILED);
                    return Err(cause);
                }
                Phase::Ready
            }
            Phase::Ready => {
                self.admit()?;
                return Ok(true);
            }
            _ => return Err(KapiError::Busy),
        };
        Ok(false)
    }

    /// Read one configuration result without allowing selector interleaving.
    /// A size of zero is a supported empty result, not a missing device.
    /// # Errors
    /// Preserves register, generation and result allocation failures; rejects
    /// device lengths beyond the specification's 128-byte configuration union.
    pub fn query_config(&mut self, select: u8, subsel: u8) -> KapiResult<alloc::vec::Vec<u8>> {
        self.transport
            .write_config_u8(0, select)
            .map_err(|_| KapiError::IoError)?;
        self.transport
            .write_config_u8(1, subsel)
            .map_err(|_| KapiError::IoError)?;
        let generation = self.transport.config_generation();
        let size = usize::from(
            self.transport
                .read_config_u8(2)
                .map_err(|_| KapiError::IoError)?,
        );
        if size > 128 {
            return Err(KapiError::InvalidSize);
        }
        let mut result = alloc::vec::Vec::new();
        result
            .try_reserve_exact(size)
            .map_err(|_| KapiError::OutOfMemory)?;
        for index in 0..size {
            result.push(
                self.transport
                    .read_config_u8(8 + index)
                    .map_err(|_| KapiError::IoError)?,
            );
        }
        if generation != self.transport.config_generation() {
            return Err(KapiError::Busy);
        }
        Ok(result)
    }

    fn admit(&self) -> KapiResult<()> {
        if !matches!(self.phase, Phase::Ready) {
            return Err(KapiError::Busy);
        }
        let status = self.transport.status();
        if status & status::VIRTIO_STATUS_DRIVER_OK == 0
            || status & (status::VIRTIO_STATUS_FAILED | status::VIRTIO_STATUS_DEVICE_NEEDS_RESET)
                != 0
        {
            return Err(KapiError::IoError);
        }
        Ok(())
    }

    /// Return a validated scalar event. RAM reads never lend a device-shared
    /// Rust reference; a failed read retains its consumed completion for retry.
    /// # Errors
    /// Returns hardware/queue failure or inactive admission. A returned event is
    /// consumed exactly once; buffers are refilled at the start of the next call.
    pub fn poll_event(&mut self) -> KapiResult<Option<VirtioInputEvent>> {
        self.admit()?;
        let receive = self.receive.as_mut().ok_or(KapiError::NotInitialized)?;
        if let Err(cause) = receive.refill() {
            self.phase = Phase::Failed;
            self.transport.add_status(status::VIRTIO_STATUS_FAILED);
            return Err(cause);
        }
        match receive.poll() {
            Ok(event) => Ok(event),
            Err(failure) => {
                if !failure.retryable() {
                    self.phase = Phase::Failed;
                    self.transport.add_status(status::VIRTIO_STATUS_FAILED);
                }
                Err(failure.cause())
            }
        }
    }

    /// Submit a status event such as keyboard LED feedback without allocation.
    /// # Errors
    /// Failure rejects this event before acceptance. Uncertain publication is a
    /// success outcome with the retained event and closed further admission.
    pub fn submit_status(&mut self, event: VirtioInputEvent) -> KapiResult<InputStatusOutcome> {
        self.admit()?;
        let status = self.status.as_mut().ok_or(KapiError::NotInitialized)?;
        // Status completions release scalar slots; each step is bounded by the
        // pre-admitted queue size and performs no allocation or Future polling.
        for _ in 0..128 {
            if let Err(failure) = status.poll() {
                self.phase = Phase::Failed;
                self.transport.add_status(status::VIRTIO_STATUS_FAILED);
                return Err(failure.cause());
            }
        }
        match status.submit_status(event)? {
            QueueSubmitOutcome::Published { .. } => Ok(InputStatusOutcome::Submitted),
            QueueSubmitOutcome::PublicationUncertain { cause, .. } => {
                self.phase = Phase::Failed;
                self.transport.add_status(status::VIRTIO_STATUS_FAILED);
                Ok(InputStatusOutcome::PublicationUncertain { cause })
            }
        }
    }

    /// Change completion policy and recheck for an input event after enabling.
    /// A returned event is consumed and belongs to the caller, which must process
    /// it before waiting for an interrupt and continue draining `poll_event`.
    /// # Errors
    /// Shared RAM failure retains the queue and its current partial policy.
    pub fn set_interrupts_enabled(
        &mut self,
        enabled: bool,
    ) -> KapiResult<Option<VirtioInputEvent>> {
        self.admit()?;
        self.receive
            .as_mut()
            .ok_or(KapiError::NotInitialized)?
            .set_interrupts_enabled(enabled)?;
        self.status
            .as_mut()
            .ok_or(KapiError::NotInitialized)?
            .set_interrupts_enabled(enabled)?;
        if enabled { self.poll_event() } else { Ok(None) }
    }

    /// Request reset and retain every owner until reset, RAM retirement and
    /// translation invalidation finish. A later call resumes the exact stage.
    /// # Errors
    /// Timer, hardware and unmap failures preserve this instance's resources.
    pub async fn stop(&mut self) -> KapiResult<()> {
        if matches!(self.phase, Phase::Closed) {
            return Ok(());
        }
        let timer = timer()?;
        if !matches!(
            self.phase,
            Phase::Stopping { .. } | Phase::RetiringReceive | Phase::RetiringStatus
        ) {
            self.phase = Phase::Stopping {
                deadline: deadline(timer.current_tick_ms())?,
            };
            self.transport.request_reset();
        }
        // LOOP_PROOF: mode=event; reason=Each reset observation or retained RAM release step precedes a timer wait, with Closed, failure or the reset deadline ending stop.;
        loop {
            if self.advance_stop(timer.current_tick_ms())? {
                return Ok(());
            }
            kernel_api::service::time::SleepFuture::new(timer, 1)
                .await
                .map_err(KapiError::Timer)?;
        }
    }

    #[expect(
        unsafe_code,
        reason = "only acknowledged device reset authorizes event/status and ring RAM quiescence for this instance"
    )]
    fn advance_stop(&mut self, now: u64) -> KapiResult<bool> {
        self.phase = match self.phase {
            Phase::Stopping { deadline } => {
                if self.transport.status() != 0 {
                    return if now < deadline {
                        Ok(false)
                    } else {
                        Err(KapiError::Timeout)
                    };
                }
                core::sync::atomic::fence(Ordering::Acquire);
                Phase::RetiringReceive
            }
            Phase::RetiringReceive => {
                // SAFETY: the preceding state observed reset and fenced every
                // DMA of this retained function. Admission remains closed.
                let done = match self.receive.as_mut() {
                    Some(queue) => unsafe { queue.advance_stop()? },
                    None => true,
                };
                if done {
                    Phase::RetiringStatus
                } else {
                    Phase::RetiringReceive
                }
            }
            Phase::RetiringStatus => {
                // SAFETY: reset remains held and receive retirement completed;
                // this step retires only the exact retained status queue owners.
                let done = match self.status.as_mut() {
                    Some(queue) => unsafe { queue.advance_stop()? },
                    None => true,
                };
                if done {
                    Phase::Closed
                } else {
                    Phase::RetiringStatus
                }
            }
            Phase::Closed => return Ok(true),
            _ => return Err(KapiError::Busy),
        };
        Ok(false)
    }
}

fn timer() -> KapiResult<&'static dyn kernel_api::service::time::TimeService> {
    kernel_api::service::time::try_instance().ok_or(KapiError::Timer(
        kernel_api::service::time::TimerError::ServiceUnavailable,
    ))
}
fn deadline(now: u64) -> KapiResult<u64> {
    now.checked_add(OPERATION_TIMEOUT_MS)
        .ok_or(KapiError::Timer(
            kernel_api::service::time::TimerError::ClockExhausted,
        ))
}
