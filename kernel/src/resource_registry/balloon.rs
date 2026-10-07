//! Physical page reservations are distinct from translated DMA allocations.
//! Publication is serialized with domain termination, and memory credit stays
//! owned until acknowledged deflation/reset permits explicit allocator return.

use crate::domain::{
    DomainId,
    quota::{MemoryCredit, QuotaError, quota_manager},
};
use crate::mm::phys::frame_allocator::{FrameAllocError, PhysicalAllocation};
use crate::sync::PoisonLock;
use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::balloon::{
    AbiBalloonPage, BALLOON_PAGE_BYTES, BalloonLeaseId, BalloonPageError, BalloonPageNumber,
    ReservedBalloonPage,
};
use kernel_api::resource::memory::PhysicalAddress;

const PAGE_RESERVATION_CAPACITY: usize = 4096;
mod registry;
use registry::{Entry, PageState, PageTable};
struct Backing {
    allocation: PhysicalAllocation,
    _credit: Option<MemoryCredit>,
}
impl Backing {
    fn release(self) {
        self.allocation.release();
    }
}
static PAGES: PoisonLock<PageTable<Backing, PAGE_RESERVATION_CAPACITY>> =
    PoisonLock::new(PageTable::new());

pub(crate) fn reserve(
    owner: DomainId,
    device: PackedPciLocation,
) -> Result<ReservedBalloonPage, BalloonPageError> {
    let binding = quota_manager().bind_memory(owner).map_err(quota_error)?;
    let credit = binding.reserve(BALLOON_PAGE_BYTES).map_err(quota_error)?;
    let allocation = crate::mm::phys::frame_allocator::alloc_frame().map_err(physical_error)?;
    let address = PhysicalAddress::new(allocation.as_u64());
    if BalloonPageNumber::from_physical(address).is_err() {
        allocation.release();
        return Err(BalloonPageError::InvalidPhysicalAddress);
    }
    let entry = Entry {
        owner,
        device,
        address,
        state: PageState::Reserved,
        backing: Backing {
            allocation,
            _credit: credit,
        },
    };
    let registered = crate::domain::with_resource_admission(owner, entry, |admission, entry| {
        debug_assert_eq!(admission.domain(), entry.owner);
        let mut pages = PAGES.lock().unwrap_or_else(|error| error.into_inner());
        pages.insert(entry)
    })
    .map_err(|(_, entry)| {
        entry.backing.release();
        BalloonPageError::OwnerUnavailable
    })?;
    let raw = registered.map_err(|entry| {
        entry.backing.release();
        BalloonPageError::SlotExhausted
    })?;
    // SAFETY: the published entry uniquely owns an aligned exclusive physical
    // allocation and quota credit. The permanent callback retains both through
    // accepted page use, abandonment, owner termination and return failure.
    unsafe { ReservedBalloonPage::from_allocator(raw, device, command) }
}

/// # Safety
/// Confirm/reset commands require the same exact hardware evidence as their
/// lease witness constructors. Possession of numeric metadata is insufficient.
pub(crate) unsafe extern "C" fn command(
    raw: u64,
    command: u8,
    device: u64,
    generation: u64,
) -> i32 {
    let result = (|| {
        let command = kernel_api::balloon::BalloonPageCommand::from_abi(command)?;
        let id = BalloonLeaseId::from_abi(raw).ok_or(BalloonPageError::StaleLease)?;
        let owner = crate::task::current_subject().domain;
        let device = PackedPciLocation::from_raw(device);
        let mut pages = PAGES.lock().map_err(|_| BalloonPageError::Unavailable)?;
        if command == kernel_api::balloon::BalloonPageCommand::Release {
            let backing = pages.release(id, owner, device)?;
            drop(pages);
            backing.release();
        } else {
            let entry = pages.entry_mut(id, owner, device)?;
            entry.state = entry.state.advance(command, generation)?;
        }
        Ok::<_, BalloonPageError>(())
    })();
    match result {
        Ok(()) => 0,
        Err(cause) => cause as i32,
    }
}
pub(crate) fn owner_count(owner: DomainId) -> usize {
    PAGES
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .owner_count(owner)
}
fn quota_error(cause: QuotaError) -> BalloonPageError {
    match cause {
        QuotaError::MemoryExceeded { .. } => BalloonPageError::MemoryQuota,
        QuotaError::Unregistered { .. } | QuotaError::Retired { .. } => {
            BalloonPageError::OwnerUnavailable
        }
        _ => BalloonPageError::Unavailable,
    }
}
fn physical_error(cause: FrameAllocError) -> BalloonPageError {
    match cause {
        FrameAllocError::Exhausted | FrameAllocError::MetadataAllocation => {
            BalloonPageError::PhysicalMemory
        }
        FrameAllocError::Alignment | FrameAllocError::InvalidRange => {
            BalloonPageError::InvalidPhysicalAddress
        }
        _ => BalloonPageError::Unavailable,
    }
}
