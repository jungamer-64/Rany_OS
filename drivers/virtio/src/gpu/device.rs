//! The service advances one accepted graphics operation without locking across
//! waits. Framebuffer ownership, command progress and code lifetime remain in
//! this instance until completion or acknowledged reset and finalization.
#![deny(unsafe_code)]

use super::defs::{DisplayInfo, GpuCmd, PixelFormat, Rect};
use super::protocol::{GpuDeviceError, Reply, ReplyError, Response, WireCommand};
use super::queue::{CommandQueue, PollError};
use crate::core::QueueSubmitOutcome;
use crate::defs::{VirtioDeviceType, common_features, status};
use crate::queue_memory::QueueInterrupt;
use crate::queue_memory::{SharedAllocation, dma_error};
use crate::transport::{PciTransportDiscoveryError, VirtioPciTransport, VirtioTransport};
use core::num::NonZeroU32;
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::dma::{DmaLeaseError, DmaQueueIdentity};
use kernel_api::{KapiError, KapiResult};

const OPERATION_TIMEOUT_MS: u64 = 30_000;
const RESOURCE_LIMIT: usize = 16;
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Observation of a resource in one device generation. This value grants no
/// DMA access; operations validate it against the device's retained owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpuResourceId {
    generation: u64,
    serial: NonZeroU32,
}

#[derive(Clone, Copy, Debug)]
pub enum GpuRequest {
    DisplayInfo,
    CreateFramebuffer {
        width: u32,
        height: u32,
        format: PixelFormat,
    },
    Present {
        resource: GpuResourceId,
        rect: Rect,
    },
    SetScanout {
        scanout: u32,
        resource: GpuResourceId,
        rect: Rect,
    },
    DisableScanout {
        scanout: u32,
    },
    DestroyResource {
        resource: GpuResourceId,
    },
    UpdateCursor {
        scanout: u32,
        resource: GpuResourceId,
        x: u32,
        y: u32,
        hot_x: u32,
        hot_y: u32,
    },
    MoveCursor {
        scanout: u32,
        x: u32,
        y: u32,
    },
}

#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "fixed display information is returned without allocating after a hardware completion"
)]
pub enum GpuSuccess {
    DisplayInfo(DisplayInfo),
    FramebufferCreated(GpuResourceId),
    Presented(GpuResourceId),
    ScanoutChanged(u32),
    ResourceDestroyed(GpuResourceId),
    CursorChanged(u32),
}

/// Only acknowledged fenced commands advance these externally meaningful
/// resource states. Failure can leave a later accepted command unconfirmed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpuResourceStatus {
    Reserved,
    Allocated,
    Created,
    Attached,
    Detached,
    Destroyed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpuFailureCause {
    Device(GpuDeviceError),
    Protocol,
    CommandTimeout,
    PublicationUncertain(DmaLeaseError),
    Kernel(KapiError),
}
#[derive(Debug)]
pub struct GpuOperationFailure {
    pub request: GpuRequest,
    pub cause: GpuFailureCause,
    pub last_confirmed_resource: Option<(GpuResourceId, GpuResourceStatus)>,
}
/// Failure closes device admission and retains accepted commands and backing
/// allocations. The owner must drive stop before attempting device replacement.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "terminal outcomes preserve bounded display data and failure progress without a fallible completion allocation"
)]
pub enum GpuOutcome {
    Completed(GpuSuccess),
    Failed(GpuOperationFailure),
}

/// The packed color writes before a RAM failure remain in backing storage.
/// `pixels_written` counts the committed row-major prefix of this rectangle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpuDrawError {
    pub pixels_written: usize,
    pub cause: KapiError,
}

#[derive(Clone, Copy)]
enum Action {
    Display,
    Create,
    Attach,
    Transfer,
    Flush,
    Scanout,
    Disable,
    Detach,
    Unref,
    UpdateCursor,
    MoveCursor,
}
enum OperationStage {
    PrepareFramebuffer,
    Submit(Action),
    Wait { action: Action, deadline: u64 },
    ReleaseFramebuffer,
}
struct Operation {
    request: GpuRequest,
    resource: Option<usize>,
    stage: OperationStage,
}
enum AdvanceError {
    Retry(KapiError),
    Terminal(GpuFailureCause),
}

#[derive(Clone, Copy)]
pub(super) struct FrameLayout {
    width: u32,
    height: u32,
    stride: u32,
    bytes: u32,
}
impl FrameLayout {
    pub(super) fn new(width: u32, height: u32) -> KapiResult<Self> {
        if width == 0 || height == 0 {
            return Err(KapiError::InvalidSize);
        }
        let stride = width.checked_mul(4).ok_or(KapiError::InvalidSize)?;
        let bytes = stride.checked_mul(height).ok_or(KapiError::InvalidSize)?;
        Ok(Self {
            width,
            height,
            stride,
            bytes,
        })
    }
    pub(super) fn validate_rect(self, rect: Rect) -> KapiResult<()> {
        if rect.width == 0
            || rect.height == 0
            || rect
                .x
                .checked_add(rect.width)
                .is_none_or(|end| end > self.width)
            || rect
                .y
                .checked_add(rect.height)
                .is_none_or(|end| end > self.height)
        {
            return Err(KapiError::InvalidSize);
        }
        Ok(())
    }
    fn offset(self, x: u32, y: u32) -> KapiResult<usize> {
        if x >= self.width || y >= self.height {
            return Err(KapiError::InvalidSize);
        }
        let offset = y
            .checked_mul(self.stride)
            .and_then(|offset| x.checked_mul(4).and_then(|x| offset.checked_add(x)))
            .ok_or(KapiError::InvalidSize)?;
        usize::try_from(offset).map_err(|_| KapiError::InvalidSize)
    }
}

enum HostContents {
    Uninitialized,
    Transferred,
}
struct Framebuffer {
    id: GpuResourceId,
    layout: FrameLayout,
    format: PixelFormat,
    memory: SharedAllocation,
    host: GpuResourceStatus,
    contents: HostContents,
}
enum Phase {
    Acquired,
    Resetting { deadline: u64 },
    Negotiating,
    Control,
    Cursor,
    Ready,
    Failed,
    Stopping { deadline: u64 },
    RetiringResources { index: usize },
    RetiringControl,
    RetiringCursor,
    Closed,
}

/// The graphics service retains this instance and its code through accepted
/// operations and unfinished stop. There is no global lookup, detached worker
/// or Future poll while holding a graphics lock. Only 2D protocols are admitted.
/// Interrupt selection names a vector owned by that same service.
pub struct VirtioGpu {
    transport: VirtioPciTransport,
    device: PackedPciLocation,
    interrupt: QueueInterrupt,
    phase: Phase,
    identity: Option<DmaQueueIdentity>,
    control: Option<CommandQueue>,
    cursor: Option<CommandQueue>,
    frames: [Option<Framebuffer>; RESOURCE_LIMIT],
    operation: Option<Operation>,
    next_resource: u32,
    next_fence: u64,
    scanouts: u32,
}

impl VirtioGpu {
    /// Acquire retained BAR-relative register authority for a graphics function.
    /// # Errors
    /// Mapping, discovery and metadata admission failures precede reset and DMA.
    pub fn acquire(device: PackedPciLocation, interrupt: QueueInterrupt) -> KapiResult<Self> {
        let transport = VirtioPciTransport::acquire(device, VirtioDeviceType::Gpu).map_err(
            |cause| match cause {
                PciTransportDiscoveryError::Mapping(cause) => KapiError::Mmio(cause),
                PciTransportDiscoveryError::Allocation => KapiError::OutOfMemory,
                _ => KapiError::IoError,
            },
        )?;
        Ok(Self {
            transport,
            device,
            interrupt,
            phase: Phase::Acquired,
            identity: None,
            control: None,
            cursor: None,
            frames: core::array::from_fn(|_| None),
            operation: None,
            next_resource: 1,
            next_fence: 1,
            scanouts: 0,
        })
    }

    /// Prepare both queues before DRIVER_OK. Lifecycle cancellation retains all
    /// completed stages; initial display discovery is an ordinary `GpuRequest`.
    /// # Errors
    /// Timer, feature, geometry, allocation and hardware failures keep resources
    /// in this owner. Incomplete initialization must finish stop before removal.
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
                let mandatory = select_features(self.transport.device_features())?;
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
                let scanouts = self
                    .transport
                    .read_config_u32(8)
                    .map_err(|_| KapiError::IoError)?;
                if !(1..=16).contains(&scanouts) {
                    return Err(KapiError::InvalidSize);
                }
                let control = CommandQueue::new(
                    identity,
                    self.transport
                        .queue_capacity(0)
                        .map_err(|_| KapiError::IoError)?,
                    self.interrupt,
                )?;
                let cursor = CommandQueue::new(
                    identity.with_index(1),
                    self.transport
                        .queue_capacity(1)
                        .map_err(|_| KapiError::IoError)?,
                    self.interrupt,
                )?;
                self.identity = Some(identity);
                self.scanouts = scanouts;
                self.control = Some(control);
                self.cursor = Some(cursor);
                Phase::Control
            }
            Phase::Control => {
                if self
                    .control
                    .as_mut()
                    .ok_or(KapiError::NotInitialized)?
                    .advance_boot(&self.transport)?
                {
                    Phase::Cursor
                } else {
                    Phase::Control
                }
            }
            Phase::Cursor => {
                if self
                    .cursor
                    .as_mut()
                    .ok_or(KapiError::NotInitialized)?
                    .advance_boot(&self.transport)?
                {
                    self.transport.add_status(status::VIRTIO_STATUS_DRIVER_OK);
                    Phase::Ready
                } else {
                    Phase::Cursor
                }
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
    fn resource_index(&self, id: GpuResourceId) -> KapiResult<usize> {
        self.frames
            .iter()
            .position(|frame| frame.as_ref().is_some_and(|frame| frame.id == id))
            .ok_or(KapiError::InvalidHandle)
    }
    fn attached_index(&self, id: GpuResourceId) -> KapiResult<usize> {
        let index = self.resource_index(id)?;
        if self.frames[index]
            .as_ref()
            .is_none_or(|frame| frame.host != GpuResourceStatus::Attached)
        {
            return Err(KapiError::Busy);
        }
        Ok(index)
    }
    fn scanout(&self, scanout: u32) -> KapiResult<()> {
        if scanout < self.scanouts {
            Ok(())
        } else {
            Err(KapiError::InvalidSize)
        }
    }

    /// Accept one operation after validating resource identity, placement and
    /// finite framebuffer admission. The service advances it with `poll_operation`.
    /// # Errors
    /// Busy or invalid requests reject without hardware publication. Resource
    /// slots and identifiers are reserved before accepting framebuffer creation.
    pub fn submit(&mut self, request: GpuRequest) -> KapiResult<()> {
        self.admit()?;
        if self.operation.is_some() {
            return Err(KapiError::Busy);
        }
        let (resource, stage) = match request {
            GpuRequest::DisplayInfo => (None, OperationStage::Submit(Action::Display)),
            GpuRequest::CreateFramebuffer {
                width,
                height,
                format,
            } => {
                let layout = FrameLayout::new(width, height)?;
                let index = self
                    .frames
                    .iter()
                    .position(Option::is_none)
                    .ok_or(KapiError::ResourceExhausted)?;
                let identity = self.identity.ok_or(KapiError::NotInitialized)?;
                let serial =
                    NonZeroU32::new(self.next_resource).ok_or(KapiError::ResourceExhausted)?;
                let next = self
                    .next_resource
                    .checked_add(1)
                    .ok_or(KapiError::ResourceExhausted)?;
                let id = GpuResourceId {
                    generation: identity.generation(),
                    serial,
                };
                let memory = SharedAllocation::new(
                    identity,
                    usize::try_from(layout.bytes).map_err(|_| KapiError::InvalidSize)?,
                )?;
                self.frames[index] = Some(Framebuffer {
                    id,
                    layout,
                    format,
                    memory,
                    host: GpuResourceStatus::Reserved,
                    contents: HostContents::Uninitialized,
                });
                self.next_resource = next;
                (Some(index), OperationStage::PrepareFramebuffer)
            }
            GpuRequest::Present { resource, rect } => {
                let index = self.attached_index(resource)?;
                self.frame(index)?.layout.validate_rect(rect)?;
                (Some(index), OperationStage::Submit(Action::Transfer))
            }
            GpuRequest::SetScanout {
                scanout,
                resource,
                rect,
            } => {
                self.scanout(scanout)?;
                let index = self.attached_index(resource)?;
                self.frame(index)?.layout.validate_rect(rect)?;
                (Some(index), OperationStage::Submit(Action::Scanout))
            }
            GpuRequest::DisableScanout { scanout } => {
                self.scanout(scanout)?;
                (None, OperationStage::Submit(Action::Disable))
            }
            GpuRequest::DestroyResource { resource } => (
                Some(self.attached_index(resource)?),
                OperationStage::Submit(Action::Detach),
            ),
            GpuRequest::UpdateCursor {
                scanout,
                resource,
                hot_x,
                hot_y,
                ..
            } => {
                self.scanout(scanout)?;
                let index = self.attached_index(resource)?;
                let frame = self.frame(index)?;
                if frame.layout.width != 64
                    || frame.layout.height != 64
                    || hot_x >= 64
                    || hot_y >= 64
                    || !matches!(frame.contents, HostContents::Transferred)
                {
                    return Err(KapiError::InvalidSize);
                }
                (Some(index), OperationStage::Submit(Action::UpdateCursor))
            }
            GpuRequest::MoveCursor { scanout, .. } => {
                self.scanout(scanout)?;
                (None, OperationStage::Submit(Action::MoveCursor))
            }
        };
        self.operation = Some(Operation {
            request,
            resource,
            stage,
        });
        Ok(())
    }
    fn frame(&self, index: usize) -> KapiResult<&Framebuffer> {
        self.frames
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(KapiError::InvalidHandle)
    }
    fn frame_mut(&mut self, index: usize) -> KapiResult<&mut Framebuffer> {
        self.frames
            .get_mut(index)
            .and_then(Option::as_mut)
            .ok_or(KapiError::InvalidHandle)
    }

    /// Advance a bounded command/RAM step in ordinary service context. A terminal
    /// outcome consumes this operation once; resources remain owned by the GPU.
    /// # Errors
    /// Retryable timer/RAM access and finalization errors keep the exact accepted
    /// operation and cursor. Protocol faults and unknown effects return `Failed`.
    pub fn poll_operation(&mut self) -> KapiResult<Option<GpuOutcome>> {
        self.admit()?;
        let now = timer()?.current_tick_ms();
        let Some(mut operation) = self.operation.take() else {
            return Ok(None);
        };
        match self.advance_operation(&mut operation, now) {
            Ok(Some(success)) => Ok(Some(GpuOutcome::Completed(success))),
            Ok(None) => {
                self.operation = Some(operation);
                Ok(None)
            }
            Err(AdvanceError::Retry(cause)) => {
                self.operation = Some(operation);
                Err(cause)
            }
            Err(AdvanceError::Terminal(cause)) => {
                let last_confirmed_resource = operation.resource.and_then(|index| {
                    self.frames[index]
                        .as_ref()
                        .map(|frame| (frame.id, frame.host))
                });
                self.phase = Phase::Failed;
                self.transport.add_status(status::VIRTIO_STATUS_FAILED);
                Ok(Some(GpuOutcome::Failed(GpuOperationFailure {
                    request: operation.request,
                    cause,
                    last_confirmed_resource,
                })))
            }
        }
    }

    #[expect(
        unsafe_code,
        reason = "only matching fenced detach and unref responses authorize backing retirement without a whole-device reset"
    )]
    fn advance_operation(
        &mut self,
        operation: &mut Operation,
        now: u64,
    ) -> Result<Option<GpuSuccess>, AdvanceError> {
        let retry = AdvanceError::Retry;
        let terminal = |cause| AdvanceError::Terminal(GpuFailureCause::Kernel(cause));
        match operation.stage {
            OperationStage::PrepareFramebuffer => {
                let index = operation
                    .resource
                    .ok_or_else(|| terminal(KapiError::InvalidHandle))?;
                if self
                    .frame_mut(index)
                    .map_err(terminal)?
                    .memory
                    .advance_boot()
                    .map_err(terminal)?
                {
                    self.frame_mut(index).map_err(terminal)?.host = GpuResourceStatus::Allocated;
                    operation.stage = OperationStage::Submit(Action::Create);
                }
            }
            OperationStage::Submit(action) => {
                let deadline = deadline(now).map_err(retry)?;
                let cursor = matches!(action, Action::UpdateCursor | Action::MoveCursor);
                let fence = self.next_fence;
                self.next_fence = fence
                    .checked_add(1)
                    .ok_or_else(|| terminal(KapiError::ResourceExhausted))?;
                let wire = self.encode(action, operation, fence).map_err(terminal)?;
                let queue = if cursor {
                    &mut self.cursor
                } else {
                    &mut self.control
                };
                match queue
                    .as_mut()
                    .ok_or_else(|| terminal(KapiError::NotInitialized))?
                    .submit(wire)
                    .map_err(terminal)?
                {
                    QueueSubmitOutcome::Published { .. } => {
                        operation.stage = OperationStage::Wait { action, deadline }
                    }
                    QueueSubmitOutcome::PublicationUncertain { cause, .. } => {
                        return Err(AdvanceError::Terminal(
                            GpuFailureCause::PublicationUncertain(cause),
                        ));
                    }
                }
            }
            OperationStage::Wait { action, deadline } => {
                let queue = if matches!(action, Action::UpdateCursor | Action::MoveCursor) {
                    &mut self.cursor
                } else {
                    &mut self.control
                };
                let reply = queue
                    .as_mut()
                    .ok_or_else(|| terminal(KapiError::NotInitialized))?
                    .poll()
                    .map_err(|failure| match failure {
                        PollError::Access(cause) if now < deadline => retry(dma_error(cause)),
                        PollError::Access(_) => {
                            AdvanceError::Terminal(GpuFailureCause::CommandTimeout)
                        }
                        PollError::Ring | PollError::Response(ReplyError::Protocol) => {
                            AdvanceError::Terminal(GpuFailureCause::Protocol)
                        }
                        PollError::Response(ReplyError::Device(cause)) => {
                            AdvanceError::Terminal(GpuFailureCause::Device(cause))
                        }
                    })?;
                let Some(reply) = reply else {
                    return if now < deadline {
                        Ok(None)
                    } else {
                        Err(AdvanceError::Terminal(GpuFailureCause::CommandTimeout))
                    };
                };
                if matches!(action, Action::Display) {
                    return match reply {
                        Reply::Display(info) => Ok(Some(GpuSuccess::DisplayInfo(info))),
                        _ => Err(AdvanceError::Terminal(GpuFailureCause::Protocol)),
                    };
                }
                if !matches!(reply, Reply::Done) {
                    return Err(AdvanceError::Terminal(GpuFailureCause::Protocol));
                }
                match action {
                    Action::Create => {
                        self.operation_frame(operation).map_err(terminal)?.host =
                            GpuResourceStatus::Created;
                        operation.stage = OperationStage::Submit(Action::Attach);
                    }
                    Action::Attach => {
                        let frame = self.operation_frame(operation).map_err(terminal)?;
                        frame.host = GpuResourceStatus::Attached;
                        return Ok(Some(GpuSuccess::FramebufferCreated(frame.id)));
                    }
                    Action::Transfer => {
                        self.operation_frame(operation).map_err(terminal)?.contents =
                            HostContents::Transferred;
                        operation.stage = OperationStage::Submit(Action::Flush);
                    }
                    Action::Flush => {
                        return Ok(Some(GpuSuccess::Presented(
                            self.operation_frame(operation).map_err(terminal)?.id,
                        )));
                    }
                    Action::Scanout | Action::Disable => {
                        let scanout = match operation.request {
                            GpuRequest::SetScanout { scanout, .. }
                            | GpuRequest::DisableScanout { scanout } => scanout,
                            _ => return Err(AdvanceError::Terminal(GpuFailureCause::Protocol)),
                        };
                        return Ok(Some(GpuSuccess::ScanoutChanged(scanout)));
                    }
                    Action::Detach => {
                        self.operation_frame(operation).map_err(terminal)?.host =
                            GpuResourceStatus::Detached;
                        operation.stage = OperationStage::Submit(Action::Unref);
                    }
                    Action::Unref => {
                        self.operation_frame(operation).map_err(terminal)?.host =
                            GpuResourceStatus::Destroyed;
                        operation.stage = OperationStage::ReleaseFramebuffer;
                    }
                    Action::UpdateCursor | Action::MoveCursor => {
                        let scanout = match operation.request {
                            GpuRequest::UpdateCursor { scanout, .. }
                            | GpuRequest::MoveCursor { scanout, .. } => scanout,
                            _ => return Err(AdvanceError::Terminal(GpuFailureCause::Protocol)),
                        };
                        return Ok(Some(GpuSuccess::CursorChanged(scanout)));
                    }
                    Action::Display => {
                        return Err(AdvanceError::Terminal(GpuFailureCause::Protocol));
                    }
                }
            }
            OperationStage::ReleaseFramebuffer => {
                let index = operation
                    .resource
                    .ok_or_else(|| terminal(KapiError::InvalidHandle))?;
                let frame = self.frame_mut(index).map_err(terminal)?;
                // SAFETY: matching fenced DETACH_BACKING and RESOURCE_UNREF have
                // both completed. No other accepted operation exists, and the
                // destroyed host resource cannot access this retained backing.
                if unsafe { frame.memory.advance_retirement().map_err(retry)? } {
                    let id = frame.id;
                    self.frames[index] = None;
                    return Ok(Some(GpuSuccess::ResourceDestroyed(id)));
                }
            }
        }
        Ok(None)
    }
    fn operation_frame(&mut self, operation: &Operation) -> KapiResult<&mut Framebuffer> {
        self.frame_mut(operation.resource.ok_or(KapiError::InvalidHandle)?)
    }

    fn encode(&self, action: Action, operation: &Operation, fence: u64) -> KapiResult<WireCommand> {
        let (command, response) = match action {
            Action::Display => (GpuCmd::GetDisplayInfo, Response::Display),
            Action::Create => (GpuCmd::ResourceCreate2D, Response::Header),
            Action::Attach => (GpuCmd::ResourceAttachBacking, Response::Header),
            Action::Transfer => (GpuCmd::TransferToHost2D, Response::Header),
            Action::Flush => (GpuCmd::ResourceFlush, Response::Header),
            Action::Scanout | Action::Disable => (GpuCmd::SetScanout, Response::Header),
            Action::Detach => (GpuCmd::ResourceDetachBacking, Response::Header),
            Action::Unref => (GpuCmd::ResourceUnref, Response::Header),
            Action::UpdateCursor => (GpuCmd::UpdateCursor, Response::Header),
            Action::MoveCursor => (GpuCmd::MoveCursor, Response::Header),
        };
        let mut wire = WireCommand::new(command, fence, response);
        let frame = operation
            .resource
            .map(|index| self.frame(index))
            .transpose()?;
        match (action, operation.request) {
            (Action::Display, GpuRequest::DisplayInfo) => {}
            (Action::Create, GpuRequest::CreateFramebuffer { .. }) => {
                let frame = frame.ok_or(KapiError::InvalidHandle)?;
                wire.u32(frame.id.serial.get())?;
                wire.u32(frame.format as u32)?;
                wire.u32(frame.layout.width)?;
                wire.u32(frame.layout.height)?;
            }
            (Action::Attach, GpuRequest::CreateFramebuffer { .. }) => {
                let frame = frame.ok_or(KapiError::InvalidHandle)?;
                wire.u32(frame.id.serial.get())?;
                wire.u32(1)?;
                wire.u64(frame.memory.address()?.get())?;
                wire.u32(frame.layout.bytes)?;
                wire.u32(0)?;
            }
            (Action::Transfer, GpuRequest::Present { rect, .. }) => {
                let frame = frame.ok_or(KapiError::InvalidHandle)?;
                wire.rect(rect)?;
                wire.u64(frame.layout.offset(rect.x, rect.y)? as u64)?;
                wire.u32(frame.id.serial.get())?;
                wire.u32(0)?;
            }
            (Action::Flush, GpuRequest::Present { resource, rect }) => {
                wire.rect(rect)?;
                wire.u32(resource.serial.get())?;
                wire.u32(0)?;
            }
            (
                Action::Scanout,
                GpuRequest::SetScanout {
                    scanout,
                    resource,
                    rect,
                },
            ) => {
                wire.rect(rect)?;
                wire.u32(scanout)?;
                wire.u32(resource.serial.get())?;
            }
            (Action::Disable, GpuRequest::DisableScanout { scanout }) => {
                wire.rect(Rect::default())?;
                wire.u32(scanout)?;
                wire.u32(0)?;
            }
            (Action::Detach | Action::Unref, GpuRequest::DestroyResource { resource }) => {
                wire.u32(resource.serial.get())?;
                wire.u32(0)?;
            }
            (
                Action::UpdateCursor,
                GpuRequest::UpdateCursor {
                    scanout,
                    resource,
                    x,
                    y,
                    hot_x,
                    hot_y,
                },
            ) => {
                wire.u32(scanout)?;
                wire.u32(x)?;
                wire.u32(y)?;
                wire.u32(0)?;
                wire.u32(resource.serial.get())?;
                wire.u32(hot_x)?;
                wire.u32(hot_y)?;
                wire.u32(0)?;
            }
            (Action::MoveCursor, GpuRequest::MoveCursor { scanout, x, y }) => {
                wire.u32(scanout)?;
                wire.u32(x)?;
                wire.u32(y)?;
                wire.u32(0)?;
                wire.u32(0)?;
                wire.u32(0)?;
                wire.u32(0)?;
                wire.u32(0)?;
            }
            _ => return Err(KapiError::InvalidHandle),
        }
        Ok(wire)
    }

    /// Render one checked rectangle into retained backing using scalar accesses.
    /// `color` is the packed 32-bit value in the framebuffer's selected format.
    /// No allocation or payload copy is performed, and accepted operations exclude
    /// drawing until their fenced completion has been delivered.
    /// # Errors
    /// Identity/range/admission failure precedes writes. RAM failure may leave a
    /// partially drawn rectangle; it publishes no transfer or presentation.
    pub fn fill_rect(
        &mut self,
        resource: GpuResourceId,
        rect: Rect,
        color: u32,
    ) -> Result<(), GpuDrawError> {
        let before_write = |cause| GpuDrawError {
            pixels_written: 0,
            cause,
        };
        self.admit().map_err(before_write)?;
        if self.operation.is_some() {
            return Err(before_write(KapiError::Busy));
        }
        let index = self.attached_index(resource).map_err(before_write)?;
        let frame = self.frame_mut(index).map_err(before_write)?;
        frame.layout.validate_rect(rect).map_err(before_write)?;
        let memory = frame
            .memory
            .memory()
            .map_err(|cause| before_write(dma_error(cause)))?;
        let mut pixels_written = 0;
        for y in rect.y..rect.y + rect.height {
            let offset = frame
                .layout
                .offset(rect.x, y)
                .map_err(|cause| GpuDrawError {
                    pixels_written,
                    cause,
                })?;
            let mut row = memory
                .window(offset, rect.width as usize * 4)
                .map_err(|cause| GpuDrawError {
                    pixels_written,
                    cause: dma_error(cause),
                })?;
            for x in 0..rect.width as usize {
                row.write_u32(x * 4, color).map_err(|cause| GpuDrawError {
                    pixels_written,
                    cause: dma_error(cause),
                })?;
                pixels_written += 1;
            }
        }
        Ok(())
    }

    /// Observe pending display-change notification without consuming it.
    /// # Errors
    /// Configuration access failure leaves the notification pending.
    pub fn display_changed(&self) -> KapiResult<bool> {
        self.admit()?;
        Ok(self
            .transport
            .read_config_u32(0)
            .map_err(|_| KapiError::IoError)?
            & 1
            != 0)
    }
    /// Acknowledge a display notification after consuming fresh display info.
    /// # Errors
    /// Register failure leaves notification consumption unconfirmed.
    pub fn acknowledge_display_change(&mut self) -> KapiResult<()> {
        self.admit()?;
        self.transport
            .write_config_u32(4, 1)
            .map_err(|_| KapiError::IoError)
    }

    /// Hold acknowledged reset through resource and queue retirement. Pending
    /// operations are discarded only after every DMA owner completes release.
    /// # Errors
    /// Reset deadlines, timer failures and failed unmap keep exact retry progress.
    pub async fn stop(&mut self) -> KapiResult<()> {
        if matches!(self.phase, Phase::Closed) {
            return Ok(());
        }
        let timer = timer()?;
        if !matches!(
            self.phase,
            Phase::Stopping { .. }
                | Phase::RetiringResources { .. }
                | Phase::RetiringControl
                | Phase::RetiringCursor
        ) {
            self.phase = Phase::Stopping {
                deadline: deadline(timer.current_tick_ms())?,
            };
            self.transport.request_reset();
        }
        // LOOP_PROOF: mode=event; reason=Each reset observation or retained allocation retirement step precedes a timer wait, with Closed, failure or the reset deadline ending stop.;
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
        reason = "the exclusive device owner observes reset before retiring exact-generation backing and queue allocations"
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
                Phase::RetiringResources { index: 0 }
            }
            Phase::RetiringResources { index } if index < RESOURCE_LIMIT => {
                // SAFETY: reset remains held after the preceding observation;
                // every outstanding framebuffer/queue DMA has stopped.
                let done = match self.frames[index].as_mut() {
                    Some(frame) => unsafe { frame.memory.advance_retirement()? },
                    None => true,
                };
                if done {
                    self.frames[index] = None;
                    Phase::RetiringResources { index: index + 1 }
                } else {
                    Phase::RetiringResources { index }
                }
            }
            Phase::RetiringResources { .. } => Phase::RetiringControl,
            Phase::RetiringControl => {
                // SAFETY: observed reset is held throughout retained retirement.
                let done = match self.control.as_mut() {
                    Some(queue) => unsafe { queue.advance_stop()? },
                    None => true,
                };
                if done {
                    Phase::RetiringCursor
                } else {
                    Phase::RetiringControl
                }
            }
            Phase::RetiringCursor => {
                // SAFETY: same acknowledged reset covers this exact cursor queue.
                let done = match self.cursor.as_mut() {
                    Some(queue) => unsafe { queue.advance_stop()? },
                    None => true,
                };
                if done {
                    self.operation = None;
                    Phase::Closed
                } else {
                    Phase::RetiringCursor
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
    Ok(mandatory)
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
