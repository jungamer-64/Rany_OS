//! Exclusive service ownership serializes lifecycle and byte I/O. Await points
//! retain both queues; observed reset precedes every RAM retirement transition.
#![deny(unsafe_code)]

use super::{
    features,
    queue::{Direction, SLOT_BYTES, StreamQueue},
};
use crate::core::QueueSubmitOutcome;
use crate::defs::{VirtioDeviceType, common_features, status};
use crate::queue_memory::QueueInterrupt;
use crate::transport::{PciTransportDiscoveryError, VirtioPciTransport, VirtioTransport};
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::dma::{DmaLeaseError, DmaQueueIdentity};
use kernel_api::{KapiError, KapiResult};

const OPERATION_TIMEOUT_MS: u64 = 30_000;
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

enum Phase {
    Acquired,
    Resetting { deadline: u64 },
    Negotiating,
    Receive,
    Transmit,
    DriverReady,
    Ready,
    Failed,
    Stopping { deadline: u64 },
    RetiringReceive,
    RetiringTransmit,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsoleDimensions {
    pub columns: u16,
    pub rows: u16,
}

/// Publication consumed the entire supplied chunk in either outcome. An
/// uncertain chunk remains owned until completion/reset and must not be retried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsoleWriteOutcome {
    Accepted {
        byte_count: usize,
    },
    PublicationUncertain {
        byte_count: usize,
        cause: DmaLeaseError,
    },
}

/// `output[..copied]` is already delivered. A retry resumes at the next byte;
/// the owner retains the completion, cursor and DMA allocation on failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsoleReadError {
    pub copied: usize,
    pub cause: KapiError,
}

/// One modern console port, owned by its console service through removal.
/// Interrupt selection must name a vector retained by that service. Operations
/// use exclusive borrows; the service keeps this instance and its code lease
/// while any async lifecycle operation or queue allocation remains unfinished.
pub struct VirtioConsoleDevice {
    transport: VirtioPciTransport,
    device: PackedPciLocation,
    interrupt: QueueInterrupt,
    phase: Phase,
    features: u64,
    receive: Option<StreamQueue>,
    transmit: Option<StreamQueue>,
}

impl VirtioConsoleDevice {
    pub const MAX_WRITE_SIZE: usize = SLOT_BYTES;

    /// Acquire retained BAR authority before reset or device publication.
    /// # Errors
    /// Returns discovery, mapping or metadata failure without acquiring DMA.
    pub fn acquire(device: PackedPciLocation, interrupt: QueueInterrupt) -> KapiResult<Self> {
        let transport =
            VirtioPciTransport::acquire(device, VirtioDeviceType::Console).map_err(|cause| {
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
            features: 0,
            receive: None,
            transmit: None,
        })
    }

    /// Allocate both rings and fixed byte slots before DRIVER_OK, then publish
    /// receive buffers. No multiport feature/control protocol is negotiated.
    /// Cancellation retains completed stages in this same owner.
    /// # Errors
    /// Timer, geometry, feature, allocation and publication failures retain all
    /// acquired resources. Drive `stop` before removing an incomplete instance.
    pub async fn initialize(&mut self) -> KapiResult<()> {
        let timer = timer()?;
        if matches!(self.phase, Phase::Acquired) {
            self.phase = Phase::Resetting {
                deadline: deadline(timer.current_tick_ms())?,
            };
            self.transport.request_reset();
        }
        // LOOP_PROOF: mode=event; reason=Each retained bootstrap step precedes a timer wait, with readiness, failure or the reset deadline ending initialization.;
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
                self.features = select_features(self.transport.device_features())?;
                self.transport.set_driver_features(self.features);
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
                let receive = StreamQueue::new(
                    identity,
                    self.transport
                        .queue_capacity(0)
                        .map_err(|_| KapiError::IoError)?,
                    Direction::Receive,
                    self.interrupt,
                )?;
                let transmit = StreamQueue::new(
                    identity.with_index(1),
                    self.transport
                        .queue_capacity(1)
                        .map_err(|_| KapiError::IoError)?,
                    Direction::Transmit,
                    self.interrupt,
                )?;
                self.receive = Some(receive);
                self.transmit = Some(transmit);
                Phase::Receive
            }
            Phase::Receive => {
                if self
                    .receive
                    .as_mut()
                    .ok_or(KapiError::NotInitialized)?
                    .advance_boot(&self.transport)?
                {
                    Phase::Transmit
                } else {
                    Phase::Receive
                }
            }
            Phase::Transmit => {
                if self
                    .transmit
                    .as_mut()
                    .ok_or(KapiError::NotInitialized)?
                    .advance_boot(&self.transport)?
                {
                    Phase::DriverReady
                } else {
                    Phase::Transmit
                }
            }
            Phase::DriverReady => {
                self.transport.add_status(status::VIRTIO_STATUS_DRIVER_OK);
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

    fn admit(&self) -> KapiResult<()> {
        if !matches!(self.phase, Phase::Ready) {
            return Err(KapiError::Busy);
        }
        let current = self.transport.status();
        if current & status::VIRTIO_STATUS_DRIVER_OK == 0
            || current & (status::VIRTIO_STATUS_FAILED | status::VIRTIO_STATUS_DEVICE_NEEDS_RESET)
                != 0
        {
            return Err(KapiError::IoError);
        }
        Ok(())
    }
    fn fail(&mut self) {
        self.phase = Phase::Failed;
        self.transport.add_status(status::VIRTIO_STATUS_FAILED);
    }

    /// Copy one bounded chunk into a free, preallocated transmit slot. No DMA
    /// allocation or queue metadata growth occurs during submission.
    /// # Errors
    /// Busy and invalid size reject before acceptance. Every `Err` leaves this
    /// chunk unaccepted; uncertain publication returns its consumed byte count.
    pub fn write_bytes(&mut self, bytes: &[u8]) -> KapiResult<ConsoleWriteOutcome> {
        self.admit()?;
        if bytes.len() > SLOT_BYTES {
            return Err(KapiError::InvalidSize);
        }
        if bytes.is_empty() {
            return Ok(ConsoleWriteOutcome::Accepted { byte_count: 0 });
        }
        self.poll_transmit()?;
        match self
            .transmit
            .as_mut()
            .ok_or(KapiError::NotInitialized)?
            .submit(bytes)?
        {
            QueueSubmitOutcome::Published { .. } => Ok(ConsoleWriteOutcome::Accepted {
                byte_count: bytes.len(),
            }),
            QueueSubmitOutcome::PublicationUncertain { cause, .. } => {
                self.fail();
                Ok(ConsoleWriteOutcome::PublicationUncertain {
                    byte_count: bytes.len(),
                    cause,
                })
            }
        }
    }

    /// Copy a completed receive prefix into caller storage. Short buffers keep
    /// the unreturned suffix; empty output consumes nothing. `Some(0)` represents
    /// a completed empty device buffer and differs from an empty receive queue.
    /// # Errors
    /// The error reports the committed prefix in this call. Scalar read failure
    /// preserves the cursor for retry; malformed completion closes admission.
    pub fn read_bytes(&mut self, output: &mut [u8]) -> Result<Option<usize>, ConsoleReadError> {
        self.admit()
            .map_err(|cause| ConsoleReadError { copied: 0, cause })?;
        let receive = self.receive.as_mut().ok_or(ConsoleReadError {
            copied: 0,
            cause: KapiError::NotInitialized,
        })?;
        if let Err(cause) = receive.refill() {
            self.fail();
            return Err(ConsoleReadError { copied: 0, cause });
        }
        match receive.read(output) {
            Ok(copied) => Ok(copied),
            Err(super::queue::ReadFailure::Queue(cause)) => {
                self.fail();
                Err(ConsoleReadError { copied: 0, cause })
            }
            Err(super::queue::ReadFailure::Data { copied, cause }) => {
                Err(ConsoleReadError { copied, cause })
            }
        }
    }

    /// Reclaim validated transmit completions in ordinary service context.
    /// # Errors
    /// Ring corruption retains all accepted slots and closes new admission.
    pub fn poll_transmit(&mut self) -> KapiResult<()> {
        self.admit()?;
        if let Err(cause) = self
            .transmit
            .as_mut()
            .ok_or(KapiError::NotInitialized)?
            .drain_transmit()
        {
            self.fail();
            return Err(cause);
        }
        Ok(())
    }

    /// Enable/disable completion interrupts. On enable, a store/load fence and
    /// used-ring recheck preserve a pending receive cursor; `true` means the
    /// service must drain input before waiting for another interrupt.
    /// # Errors
    /// RAM/policy failure retains both queues and forbids assuming idle state.
    pub fn set_interrupts_enabled(&mut self, enabled: bool) -> KapiResult<bool> {
        self.admit()?;
        if enabled
            && let Err(cause) = self
                .receive
                .as_mut()
                .ok_or(KapiError::NotInitialized)?
                .refill()
        {
            self.fail();
            return Err(cause);
        }
        self.receive
            .as_mut()
            .ok_or(KapiError::NotInitialized)?
            .set_interrupts_enabled(enabled)?;
        self.transmit
            .as_mut()
            .ok_or(KapiError::NotInitialized)?
            .set_interrupts_enabled(enabled)?;
        if !enabled {
            return Ok(false);
        }
        self.poll_transmit()?;
        let pending = self
            .receive
            .as_mut()
            .ok_or(KapiError::NotInitialized)?
            .has_input();
        if pending.is_err() {
            self.fail();
        }
        pending
    }

    /// Read a coherent size when the device offers negotiated size reporting.
    /// # Errors
    /// Configuration access or a concurrent generation change returns failure
    /// without publishing a mixed pair of columns and rows.
    pub fn dimensions(&self) -> KapiResult<Option<ConsoleDimensions>> {
        self.admit()?;
        if self.features & features::VIRTIO_CONSOLE_F_SIZE == 0 {
            return Ok(None);
        }
        let generation = self.transport.config_generation();
        let columns = self
            .transport
            .read_config_u16(0)
            .map_err(|_| KapiError::IoError)?;
        let rows = self
            .transport
            .read_config_u16(2)
            .map_err(|_| KapiError::IoError)?;
        if generation != self.transport.config_generation() {
            return Err(KapiError::Busy);
        }
        Ok(Some(ConsoleDimensions { columns, rows }))
    }

    /// Issue the specification's 32-bit emergency register write, including
    /// before queue initialization. Success reports the register operation only.
    /// # Errors
    /// An absent emergency-write feature or failed register access rejects.
    pub fn emergency_write(&mut self, byte: u8) -> KapiResult<()> {
        if self.transport.device_features() & features::VIRTIO_CONSOLE_F_EMERG_WRITE == 0 {
            return Err(KapiError::NotSupported);
        }
        self.transport
            .write_config_u32(8, u32::from(byte))
            .map_err(|_| KapiError::IoError)
    }

    /// Hold the device in acknowledged reset while retiring both rings and byte
    /// allocations. Failed retirement/unmap remains in its exact stage for retry.
    /// # Errors
    /// Timer, reset deadline or finalization failure leaves this owner incomplete.
    pub async fn stop(&mut self) -> KapiResult<()> {
        if matches!(self.phase, Phase::Closed) {
            return Ok(());
        }
        let timer = timer()?;
        if !matches!(
            self.phase,
            Phase::Stopping { .. } | Phase::RetiringReceive | Phase::RetiringTransmit
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
        reason = "the exclusive device owner observes reset before quiescing its exact queue generation"
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
                // SAFETY: the preceding phase observed reset and fenced DMA;
                // this owner keeps reset asserted throughout all retries.
                let done = match self.receive.as_mut() {
                    Some(queue) => unsafe { queue.advance_stop()? },
                    None => true,
                };
                if done {
                    Phase::RetiringTransmit
                } else {
                    Phase::RetiringReceive
                }
            }
            Phase::RetiringTransmit => {
                // SAFETY: receive retirement is complete and acknowledged reset
                // remains held for the exact retained transmit generation.
                let done = match self.transmit.as_mut() {
                    Some(queue) => unsafe { queue.advance_stop()? },
                    None => true,
                };
                if done {
                    Phase::Closed
                } else {
                    Phase::RetiringTransmit
                }
            }
            Phase::Closed => return Ok(true),
            _ => return Err(KapiError::Busy),
        };
        Ok(false)
    }
}

pub(super) fn select_features(offered: u64) -> KapiResult<u64> {
    let mandatory = common_features::VIRTIO_F_VERSION_1 | common_features::VIRTIO_F_ACCESS_PLATFORM;
    if offered & mandatory != mandatory {
        return Err(KapiError::NotSupported);
    }
    Ok(mandatory
        | (offered & (features::VIRTIO_CONSOLE_F_SIZE | features::VIRTIO_CONSOLE_F_EMERG_WRITE)))
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
