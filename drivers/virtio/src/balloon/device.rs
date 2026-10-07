//! The memory service drives bounded ordinary-context steps. Work state retains
//! consumed queue acknowledgements through page-transition/reporting failures.
//! Reset recovery releases pages before declaring device removal complete.
#![deny(unsafe_code)]

use super::{
    features,
    queue::{PfnQueue, SubmitError},
};
use crate::core::QueueSubmitOutcome;
use crate::defs::{VirtioDeviceType, common_features, status};
use crate::queue_memory::QueueInterrupt;
use crate::transport::{PciTransportDiscoveryError, VirtioPciTransport, VirtioTransport};
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::balloon::*;
use kernel_api::dma::{DmaLeaseError, DmaQueueIdentity};
use kernel_api::{KapiError, KapiResult};

const PAGE_LIMIT: usize = 256;
const OPERATION_TIMEOUT_MS: u64 = 30_000;
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BalloonError {
    Kernel(KapiError),
    Page(BalloonPageError),
    PublicationUncertain(DmaLeaseError),
    Protocol,
    CommandTimeout,
}
impl From<KapiError> for BalloonError {
    fn from(cause: KapiError) -> Self {
        Self::Kernel(cause)
    }
}
impl From<BalloonPageError> for BalloonError {
    fn from(cause: BalloonPageError) -> Self {
        Self::Page(cause)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BalloonProgress {
    Progress,
    TargetSatisfied {
        actual_pages: u32,
    },
    CapacityLimited {
        actual_pages: u32,
        target_pages: u32,
    },
}

enum Page {
    Reserved(ReservedBalloonPage),
    Inflating(InflatingBalloonPage),
    Inflated(InflatedBalloonPage),
    Deflating(DeflatingBalloonPage),
    Transitioning,
}
impl Page {
    fn pfn(&self) -> Result<BalloonPageNumber, BalloonError> {
        match self {
            Self::Reserved(page) => Ok(page.pfn()),
            Self::Inflating(page) => Ok(page.pfn()),
            Self::Inflated(page) => Ok(page.pfn()),
            Self::Deflating(page) => Ok(page.pfn()),
            Self::Transitioning => Err(BalloonError::Protocol),
        }
    }
}
#[derive(Clone, Copy)]
enum Direction {
    Inflate,
    Deflate,
}
#[derive(Clone, Copy)]
enum Work {
    Idle,
    Submitting {
        direction: Direction,
        slot: usize,
    },
    Waiting {
        direction: Direction,
        slot: usize,
        deadline: u64,
    },
    Acknowledging {
        direction: Direction,
        slot: usize,
    },
    Reporting {
        direction: Direction,
        slot: usize,
    },
    Returning {
        slot: usize,
    },
}
enum Phase {
    Acquired,
    Resetting { deadline: u64 },
    Negotiating,
    Inflate,
    Deflate,
    Ready,
    Failed,
    Stopping { deadline: u64 },
    RecoveringPages { slot: usize },
    RetiringInflate,
    RetiringDeflate,
    ReportingZero,
    Closed,
}

/// A memory service retains this function, physical page leases and code through
/// every accepted command and incomplete stop. IOMMU-protected queue RAM is
/// independent of guest physical pages supplied to the balloon protocol.
/// Interrupt selection names a vector retained by that service.
pub struct VirtioBalloonDevice {
    transport: VirtioPciTransport,
    device: PackedPciLocation,
    interrupt: QueueInterrupt,
    identity: Option<DmaQueueIdentity>,
    phase: Phase,
    inflate: Option<PfnQueue>,
    deflate: Option<PfnQueue>,
    pages: [Option<Page>; PAGE_LIMIT],
    work: Work,
}
impl VirtioBalloonDevice {
    /// Acquire retained register authority before reset or page reservation.
    /// # Errors
    /// Returns mapping/discovery failure without publishing queue or page state.
    pub fn acquire(device: PackedPciLocation, interrupt: QueueInterrupt) -> KapiResult<Self> {
        let transport =
            VirtioPciTransport::acquire(device, VirtioDeviceType::Balloon).map_err(|cause| {
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
            identity: None,
            phase: Phase::Acquired,
            inflate: None,
            deflate: None,
            pages: core::array::from_fn(|_| None),
            work: Work::Idle,
        })
    }
    /// Prepare both queues before DRIVER_OK. Page reservation is deferred to the
    /// memory service's normal work steps and never occurs in interrupt context.
    /// # Errors
    /// Incomplete preparation and timer/reset failures retain exact owned stages.
    pub async fn initialize(&mut self) -> KapiResult<()> {
        let timer = timer()?;
        if matches!(self.phase, Phase::Acquired) {
            self.phase = Phase::Resetting {
                deadline: deadline(timer.current_tick_ms())?,
            };
            self.transport.request_reset();
        }
        // LOOP_PROOF: mode=event; reason=Each retained bootstrap step precedes a timer wait, with readiness, typed failure or the reset deadline ending initialization.;
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
                let selected = select_features(self.transport.device_features())?;
                self.transport.set_driver_features(selected);
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
                let inflate = PfnQueue::new(
                    identity,
                    self.transport
                        .queue_capacity(0)
                        .map_err(|_| KapiError::IoError)?,
                    self.interrupt,
                )?;
                let deflate = PfnQueue::new(
                    identity.with_index(1),
                    self.transport
                        .queue_capacity(1)
                        .map_err(|_| KapiError::IoError)?,
                    self.interrupt,
                )?;
                self.identity = Some(identity);
                self.inflate = Some(inflate);
                self.deflate = Some(deflate);
                Phase::Inflate
            }
            Phase::Inflate => {
                if self
                    .inflate
                    .as_mut()
                    .ok_or(KapiError::NotInitialized)?
                    .advance_boot(&self.transport)?
                {
                    Phase::Deflate
                } else {
                    Phase::Inflate
                }
            }
            Phase::Deflate => {
                if self
                    .deflate
                    .as_mut()
                    .ok_or(KapiError::NotInitialized)?
                    .advance_boot(&self.transport)?
                {
                    self.transport
                        .write_config_u32(4, 0)
                        .map_err(|_| KapiError::IoError)?;
                    self.transport.add_status(status::VIRTIO_STATUS_DRIVER_OK);
                    Phase::Ready
                } else {
                    Phase::Deflate
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
    fn actual_pages(&self) -> u32 {
        self.pages
            .iter()
            .filter(|page| matches!(page, Some(Page::Inflated(_) | Page::Deflating(_))))
            .count() as u32
    }

    /// Advance one memory-policy or completion step toward the current device
    /// target. Consumed acknowledgement, actual reporting and page return are
    /// retained as separate retry stages; no completion is consumed twice.
    /// # Errors
    /// Page admission distinguishes quota, physical RAM and reservation capacity.
    /// Response/reporting/return failures retain ownership. Unknown publication
    /// and protocol corruption close admission and require acknowledged stop.
    #[expect(
        unsafe_code,
        reason = "only a matching validated used entry may authorize this exact page's acknowledgement"
    )]
    pub fn poll(&mut self) -> Result<BalloonProgress, BalloonError> {
        self.admit()?;
        let now = timer()?.current_tick_ms();
        match self.work {
            Work::Idle => {
                let target = self
                    .transport
                    .read_config_u32(0)
                    .map_err(|_| KapiError::IoError)?;
                let actual = self.actual_pages();
                if actual == target {
                    return Ok(BalloonProgress::TargetSatisfied {
                        actual_pages: actual,
                    });
                }
                if actual < target {
                    let Some(slot) = self.pages.iter().position(Option::is_none) else {
                        return Ok(BalloonProgress::CapacityLimited {
                            actual_pages: actual,
                            target_pages: target,
                        });
                    };
                    let page = kernel_api::service::kernel::instance()
                        .reserve_balloon_page(self.device)?;
                    self.pages[slot] = Some(Page::Reserved(page));
                    self.work = Work::Submitting {
                        direction: Direction::Inflate,
                        slot,
                    };
                } else {
                    let slot = self
                        .pages
                        .iter()
                        .position(|page| matches!(page, Some(Page::Inflated(_))))
                        .ok_or(BalloonError::Protocol)?;
                    self.work = Work::Submitting {
                        direction: Direction::Deflate,
                        slot,
                    };
                }
            }
            Work::Submitting { direction, slot } => {
                let identity = self.identity.ok_or(BalloonError::Protocol)?;
                let pfn = self.pages[slot]
                    .as_ref()
                    .ok_or(BalloonError::Protocol)?
                    .pfn()?;
                let deadline = deadline(now)?;
                let queue = match direction {
                    Direction::Inflate => &mut self.inflate,
                    Direction::Deflate => &mut self.deflate,
                };
                let page = self.pages[slot].as_mut().ok_or(BalloonError::Protocol)?;
                match queue
                    .as_mut()
                    .ok_or(BalloonError::Protocol)?
                    .submit(pfn, slot, || arm(page, identity, direction))
                {
                    Ok(QueueSubmitOutcome::Published { .. }) => {
                        self.work = Work::Waiting {
                            direction,
                            slot,
                            deadline,
                        }
                    }
                    Ok(QueueSubmitOutcome::PublicationUncertain { cause, .. }) => {
                        return self.fail(BalloonError::PublicationUncertain(cause));
                    }
                    Err(SubmitError::Page(cause)) => return Err(BalloonError::Page(cause)),
                    Err(SubmitError::Queue(cause)) => {
                        return self.fail(BalloonError::Kernel(cause));
                    }
                }
            }
            Work::Waiting {
                direction,
                slot,
                deadline,
            } => {
                let queue = match direction {
                    Direction::Inflate => &mut self.inflate,
                    Direction::Deflate => &mut self.deflate,
                };
                let completed = queue.as_mut().ok_or(BalloonError::Protocol)?.poll();
                match completed {
                    Ok(Some(completed)) if completed == slot => {
                        self.work = Work::Acknowledging { direction, slot }
                    }
                    Ok(Some(_)) => return self.fail(BalloonError::Protocol),
                    Ok(None) if now < deadline => {}
                    Ok(None) => return self.fail(BalloonError::CommandTimeout),
                    Err(cause) => return self.fail(BalloonError::Kernel(cause)),
                }
            }
            Work::Acknowledging { direction, slot } => {
                let identity = self.identity.ok_or(BalloonError::Protocol)?;
                let page = self.pages[slot].as_mut().ok_or(BalloonError::Protocol)?;
                // SAFETY: the preceding exclusive work state consumed a matching
                // validated used entry for this exact page-owning command/slot.
                unsafe { acknowledge(page, identity, direction)? };
                self.work = Work::Reporting { direction, slot };
            }
            Work::Reporting { direction, slot } => {
                self.transport
                    .write_config_u32(4, self.actual_pages())
                    .map_err(|_| KapiError::IoError)?;
                self.work = match direction {
                    Direction::Inflate => Work::Idle,
                    Direction::Deflate => Work::Returning { slot },
                };
            }
            Work::Returning { slot } => {
                close_page(&mut self.pages[slot])?;
                self.work = Work::Idle;
            }
        }
        Ok(BalloonProgress::Progress)
    }
    fn fail<T>(&mut self, cause: BalloonError) -> Result<T, BalloonError> {
        self.phase = Phase::Failed;
        self.transport.add_status(status::VIRTIO_STATUS_FAILED);
        Err(cause)
    }

    /// Request reset, recover all physical page reservations and then retire
    /// list/ring RAM. Failed return preserves the page and current recovery slot.
    /// # Errors
    /// Hardware/timer/page/unmap failures retain all unfinished resource owners.
    pub async fn stop(&mut self) -> Result<(), BalloonError> {
        if matches!(self.phase, Phase::Closed) {
            return Ok(());
        }
        let timer = timer()?;
        if !matches!(
            self.phase,
            Phase::Stopping { .. }
                | Phase::RecoveringPages { .. }
                | Phase::RetiringInflate
                | Phase::RetiringDeflate
                | Phase::ReportingZero
        ) {
            self.phase = Phase::Stopping {
                deadline: deadline(timer.current_tick_ms())?,
            };
            self.transport.request_reset();
        }
        // LOOP_PROOF: mode=event; reason=Each reset observation or retained page/RAM release step precedes a timer wait, with Closed, failure or the reset deadline ending stop.;
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
        reason = "the unique device owner observes reset before recovering its physical pages and queue generation"
    )]
    fn advance_stop(&mut self, now: u64) -> Result<bool, BalloonError> {
        self.phase = match self.phase {
            Phase::Stopping { deadline } => {
                if self.transport.status() != 0 {
                    return if now < deadline {
                        Ok(false)
                    } else {
                        Err(BalloonError::CommandTimeout)
                    };
                }
                core::sync::atomic::fence(Ordering::Acquire);
                Phase::RecoveringPages { slot: 0 }
            }
            Phase::RecoveringPages { slot } if slot < PAGE_LIMIT => {
                if let Some(page) = self.pages[slot].as_mut() {
                    let identity = self.identity.ok_or(BalloonError::Protocol)?;
                    // SAFETY: reset is held after status-zero observation and
                    // fencing. This retained generation has no host page use.
                    unsafe { recover_page(page, identity)? };
                    close_page(&mut self.pages[slot])?;
                }
                Phase::RecoveringPages { slot: slot + 1 }
            }
            Phase::RecoveringPages { .. } => Phase::RetiringInflate,
            Phase::RetiringInflate => {
                // SAFETY: held acknowledged reset covers list and ring DMA.
                let done = match self.inflate.as_mut() {
                    Some(queue) => unsafe { queue.advance_stop()? },
                    None => true,
                };
                if done {
                    Phase::RetiringDeflate
                } else {
                    Phase::RetiringInflate
                }
            }
            Phase::RetiringDeflate => {
                // SAFETY: the same held reset covers this retained deflate queue.
                let done = match self.deflate.as_mut() {
                    Some(queue) => unsafe { queue.advance_stop()? },
                    None => true,
                };
                if done {
                    Phase::ReportingZero
                } else {
                    Phase::RetiringDeflate
                }
            }
            Phase::ReportingZero => {
                self.transport
                    .write_config_u32(4, 0)
                    .map_err(|_| KapiError::IoError)?;
                self.work = Work::Idle;
                Phase::Closed
            }
            Phase::Closed => return Ok(true),
            _ => return Err(BalloonError::Protocol),
        };
        Ok(false)
    }
}

fn arm(
    page: &mut Page,
    queue: DmaQueueIdentity,
    direction: Direction,
) -> Result<(), BalloonPageError> {
    let previous = core::mem::replace(page, Page::Transitioning);
    let (next, result) = match (previous, direction) {
        (Page::Reserved(page), Direction::Inflate) => match page.arm(queue) {
            Ok(page) => (Page::Inflating(page), Ok(())),
            Err(failure) => (Page::Reserved(failure.page), Err(failure.cause)),
        },
        (Page::Inflated(page), Direction::Deflate) => match page.deflate(queue.with_index(1)) {
            Ok(page) => (Page::Deflating(page), Ok(())),
            Err(failure) => (Page::Inflated(failure.page), Err(failure.cause)),
        },
        (other, _) => (other, Err(BalloonPageError::InvalidTransition)),
    };
    *page = next;
    result
}
/// # Safety
/// The exact queue generation's matching used entry owns this retained page.
#[expect(
    unsafe_code,
    reason = "this private transition binds observed acknowledgement to the retained page lease"
)]
unsafe fn acknowledge(
    page: &mut Page,
    queue: DmaQueueIdentity,
    direction: Direction,
) -> Result<(), BalloonPageError> {
    let previous = core::mem::replace(page, Page::Transitioning);
    let (next, result) = match (previous, direction) {
        (Page::Inflating(page), Direction::Inflate) => {
            // SAFETY: the caller observed the matching inflate command's used entry.
            let witness =
                unsafe { BalloonAcknowledgement::after_acknowledged(queue, page.lease_id()) };
            match page.acknowledge(witness) {
                Ok(page) => (Page::Inflated(page), Ok(())),
                Err(failure) => (Page::Inflating(failure.page), Err(failure.cause)),
            }
        }
        (Page::Deflating(page), Direction::Deflate) => {
            // SAFETY: the caller observed the matching deflate command's used entry.
            let witness = unsafe {
                BalloonAcknowledgement::after_acknowledged(queue.with_index(1), page.lease_id())
            };
            match page.acknowledge(witness) {
                Ok(page) => (Page::Reserved(page), Ok(())),
                Err(failure) => (Page::Deflating(failure.page), Err(failure.cause)),
            }
        }
        (other, _) => (other, Err(BalloonPageError::InvalidTransition)),
    };
    *page = next;
    result
}
/// # Safety
/// Reset is observed and held for every page of this exact queue generation.
#[expect(
    unsafe_code,
    reason = "only acknowledged function reset can restore return authority for unconfirmed host page use"
)]
unsafe fn recover_page(page: &mut Page, queue: DmaQueueIdentity) -> Result<(), BalloonPageError> {
    let previous = core::mem::replace(page, Page::Transitioning);
    // SAFETY: caller holds reset after observing status zero for this generation.
    let witness = unsafe { BalloonResetWitness::after_reset(queue) };
    let (next, result) = match previous {
        Page::Reserved(page) => (Page::Reserved(page), Ok(())),
        Page::Inflating(page) => match page.recover(witness) {
            Ok(page) => (Page::Reserved(page), Ok(())),
            Err(failure) => (Page::Inflating(failure.page), Err(failure.cause)),
        },
        Page::Inflated(page) => match page.recover(witness) {
            Ok(page) => (Page::Reserved(page), Ok(())),
            Err(failure) => (Page::Inflated(failure.page), Err(failure.cause)),
        },
        Page::Deflating(page) => match page.recover(witness) {
            Ok(page) => (Page::Reserved(page), Ok(())),
            Err(failure) => (Page::Deflating(failure.page), Err(failure.cause)),
        },
        Page::Transitioning => (
            Page::Transitioning,
            Err(BalloonPageError::InvalidTransition),
        ),
    };
    *page = next;
    result
}
fn close_page(page: &mut Option<Page>) -> Result<(), BalloonPageError> {
    match page.take() {
        Some(Page::Reserved(reserved)) => match reserved.close() {
            Ok(()) => Ok(()),
            Err(failure) => {
                *page = Some(Page::Reserved(failure.page));
                Err(failure.cause)
            }
        },
        None => Ok(()),
        Some(other) => {
            *page = Some(other);
            Err(BalloonPageError::InvalidTransition)
        }
    }
}
pub(super) fn select_features(offered: u64) -> KapiResult<u64> {
    let mandatory = common_features::VIRTIO_F_VERSION_1 | common_features::VIRTIO_F_ACCESS_PLATFORM;
    if offered & mandatory != mandatory {
        return Err(KapiError::NotSupported);
    }
    Ok(mandatory | (offered & features::VIRTIO_BALLOON_F_MUST_TELL_HOST))
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

#[cfg(test)]
mod tests {
    use super::*;
    use exorust_sync::Mutex;
    struct Provider {
        stage: u8,
        acknowledgements: u32,
        returns: u32,
        abandons: u32,
    }
    static PROVIDER: Mutex<Provider> = Mutex::new(Provider {
        stage: 0,
        acknowledgements: 0,
        returns: 0,
        abandons: 0,
    });

    #[expect(
        unsafe_code,
        reason = "the private provider retains synthetic page ownership and records transitions without exposing any physical memory to hardware"
    )]
    unsafe extern "C" fn command(_id: u64, command: u8, _device: u64, _generation: u64) -> i32 {
        let mut provider = PROVIDER.lock();
        match command {
            1 => provider.stage = 1,
            2 => {
                provider.acknowledgements += 1;
                if provider.acknowledgements == 1 {
                    return BalloonPageError::Busy as i32;
                }
                provider.stage = 2;
            }
            3 => provider.stage = 3,
            4 => provider.stage = 0,
            6 => {
                provider.returns += 1;
                if provider.returns == 1 {
                    return BalloonPageError::Busy as i32;
                }
                provider.stage = 4;
            }
            7 => provider.abandons += 1,
            _ => return BalloonPageError::InvalidTransition as i32,
        }
        0
    }
    #[test]
    #[expect(
        unsafe_code,
        reason = "the private fixture has no hardware page access; its observed acknowledgement is held across transition retries"
    )]
    fn acknowledgement_and_return_failure_preserve_the_same_page_without_abandonment() {
        let device = PackedPciLocation::new(0, 0, 1, 0);
        let queue = DmaQueueIdentity::new(device, 0, 7).unwrap();
        // SAFETY: the permanent private provider owns one synthetic reservation,
        // cannot expose it to hardware, and retains it across every failure.
        let page = unsafe {
            ReservedBalloonPage::from_allocator(
                AbiBalloonPage {
                    lease_id: (1 << 32) | 1,
                    physical_address: 4096,
                    device: device.raw(),
                },
                device,
                command,
            )
        }
        .unwrap();
        let mut page = Page::Reserved(page);
        assert_eq!(arm(&mut page, queue, Direction::Inflate), Ok(()));
        // SAFETY: this synthetic provider's exact inflate acknowledgement is
        // observed once and remains the same during the following retry.
        assert_eq!(
            unsafe { acknowledge(&mut page, queue, Direction::Inflate) },
            Err(BalloonPageError::Busy)
        );
        assert!(matches!(page, Page::Inflating(_)));
        // SAFETY: retry uses that same page and already-observed acknowledgement.
        assert_eq!(
            unsafe { acknowledge(&mut page, queue, Direction::Inflate) },
            Ok(())
        );
        assert_eq!(arm(&mut page, queue, Direction::Deflate), Ok(()));
        // SAFETY: the synthetic deflate acknowledgement corresponds to this
        // exact reservation and generation; no physical DMA can exist here.
        assert_eq!(
            unsafe { acknowledge(&mut page, queue, Direction::Deflate) },
            Ok(())
        );
        let mut page = Some(page);
        assert_eq!(close_page(&mut page), Err(BalloonPageError::Busy));
        assert!(matches!(page, Some(Page::Reserved(_))));
        assert_eq!(close_page(&mut page), Ok(()));
        assert!(page.is_none());
        let provider = PROVIDER.lock();
        assert_eq!(provider.acknowledgements, 2);
        assert_eq!(provider.returns, 2);
        assert_eq!(provider.abandons, 0);
    }
}
