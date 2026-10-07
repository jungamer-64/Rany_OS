//! Balloon reservation excludes ordinary CPU allocation reuse. Page coordinates
//! identify host physical memory, never an IOMMU address. Accepted pages remain
//! reserved until validated deflation or observed device reset.
#![deny(unsafe_code)]

use crate::abi::driver::PackedPciLocation;
use crate::dma::DmaQueueIdentity;
use crate::resource::memory::PhysicalAddress;
use core::cell::Cell;
use core::marker::PhantomData;

pub const BALLOON_PAGE_BYTES: u64 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BalloonPageNumber(u32);
impl BalloonPageNumber {
    /// Convert a checked host physical page coordinate to the wire PFN.
    /// # Errors
    /// Rejects unaligned addresses and pages outside the 32-bit PFN space.
    pub fn from_physical(address: PhysicalAddress) -> Result<Self, BalloonPageError> {
        if !address.as_u64().is_multiple_of(BALLOON_PAGE_BYTES) {
            return Err(BalloonPageError::InvalidPhysicalAddress);
        }
        u32::try_from(address.as_u64() / BALLOON_PAGE_BYTES)
            .map(Self)
            .map_err(|_| BalloonPageError::InvalidPhysicalAddress)
    }
    pub const fn wire_pfn(self) -> u32 {
        self.0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BalloonLeaseId(u64);
impl BalloonLeaseId {
    pub const fn from_abi(raw: u64) -> Option<Self> {
        if raw as u32 == 0 || (raw >> 32) == 0 {
            None
        } else {
            Some(Self(raw))
        }
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BalloonPageError {
    SlotExhausted = 1,
    MemoryQuota = 2,
    PhysicalMemory = 3,
    InvalidPhysicalAddress = 4,
    Unavailable = 5,
    NotAuthorized = 6,
    OwnerUnavailable = 7,
    StaleLease = 8,
    DeviceMismatch = 9,
    Busy = 10,
    InvalidTransition = 11,
    MalformedAbi = 12,
}
impl BalloonPageError {
    /// # Errors
    /// Returns the provider's page admission/transition cause; unknown status
    /// encodings are malformed and grant no ownership transition.
    pub fn from_status(raw: i32) -> Result<(), Self> {
        Err(match raw {
            0 => return Ok(()),
            1 => Self::SlotExhausted,
            2 => Self::MemoryQuota,
            3 => Self::PhysicalMemory,
            4 => Self::InvalidPhysicalAddress,
            5 => Self::Unavailable,
            6 => Self::NotAuthorized,
            7 => Self::OwnerUnavailable,
            8 => Self::StaleLease,
            9 => Self::DeviceMismatch,
            10 => Self::Busy,
            11 => Self::InvalidTransition,
            _ => Self::MalformedAbi,
        })
    }
}

/// A command requests the same ownership transition as the corresponding safe
/// lease method. Confirm/reset commands require its stated hardware evidence.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BalloonPageCommand {
    Inflate = 1,
    Inflated = 2,
    Deflate = 3,
    Deflated = 4,
    Reset = 5,
    Release = 6,
    Abandon = 7,
}
impl BalloonPageCommand {
    /// # Errors
    /// Rejects an unknown command before applying any ownership transition.
    pub fn from_abi(raw: u8) -> Result<Self, BalloonPageError> {
        match raw {
            1 => Ok(Self::Inflate),
            2 => Ok(Self::Inflated),
            3 => Ok(Self::Deflate),
            4 => Ok(Self::Deflated),
            5 => Ok(Self::Reset),
            6 => Ok(Self::Release),
            7 => Ok(Self::Abandon),
            _ => Err(BalloonPageError::MalformedAbi),
        }
    }
}

/// Fixed foreign representation. Only an allocator publication may issue this
/// identity, address and device relation; numeric observations are not authority.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AbiBalloonPage {
    pub lease_id: u64,
    pub physical_address: u64,
    pub device: u64,
}

pub type BalloonPageCommandFn =
    unsafe extern "C" fn(lease: u64, command: u8, device: u64, generation: u64) -> i32;

struct PageCore {
    id: BalloonLeaseId,
    pfn: BalloonPageNumber,
    device: PackedPciLocation,
    command: BalloonPageCommandFn,
}
impl core::fmt::Debug for PageCore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BalloonPage")
            .field("lease", &self.id)
            .field("pfn", &self.pfn)
            .field("device", &self.device)
            .finish()
    }
}
impl PageCore {
    #[expect(
        unsafe_code,
        reason = "the lease binds its immutable identity and device to the allocator's permanent callback; callers establish completion/reset evidence before requesting those transitions"
    )]
    fn apply(&self, command: BalloonPageCommand, generation: u64) -> Result<(), BalloonPageError> {
        // SAFETY: this live owner was issued by that allocator callback. Every
        // transition is serialized, and confirm/reset methods consume validated
        // hardware witnesses before reaching this private invocation.
        BalloonPageError::from_status(unsafe {
            (self.command)(self.id.raw(), command as u8, self.device.raw(), generation)
        })
    }
}
impl Drop for PageCore {
    fn drop(&mut self) {
        if let Err(cause) = self.apply(BalloonPageCommand::Abandon, 0) {
            log::error!("balloon page abandonment retained: {cause:?}");
        }
    }
}

macro_rules! page_state {
    ($name:ident) => {
        #[derive(Debug)]
        pub struct $name {
            core: PageCore,
            _not_sync: PhantomData<Cell<()>>,
        }
        impl $name {
            pub fn lease_id(&self) -> BalloonLeaseId {
                self.core.id
            }
            pub fn pfn(&self) -> BalloonPageNumber {
                self.core.pfn
            }
            pub fn device(&self) -> PackedPciLocation {
                self.core.device
            }
        }
    };
}
page_state!(ReservedBalloonPage);
page_state!(InflatingBalloonPage);
page_state!(InflatedBalloonPage);
page_state!(DeflatingBalloonPage);

#[derive(Debug)]
pub struct BalloonPageTransitionError<P> {
    pub cause: BalloonPageError,
    pub page: P,
}

/// Proof of one matching queue acknowledgement, retained only for this page.
#[derive(Debug)]
pub struct BalloonAcknowledgement {
    queue: DmaQueueIdentity,
    lease: BalloonLeaseId,
}
impl BalloonAcknowledgement {
    /// # Safety
    /// A validated used entry on this exact generation acknowledges the inflate
    /// or deflate command owning this page. A timer or reset is not completion.
    #[expect(
        unsafe_code,
        reason = "the queue owner must establish matching hardware completion before issuing this page-specific witness"
    )]
    pub unsafe fn after_acknowledged(queue: DmaQueueIdentity, lease: BalloonLeaseId) -> Self {
        Self { queue, lease }
    }
}
#[derive(Debug)]
pub struct BalloonResetWitness {
    device: PackedPciLocation,
    generation: u64,
}
impl BalloonResetWitness {
    /// # Safety
    /// Reset of this device has been acknowledged and fenced; all page use
    /// through this queue generation stopped. Hold reset throughout recovery.
    #[expect(
        unsafe_code,
        reason = "only observed function reset authorizes recovery of pages still owned by its old queue generation"
    )]
    pub unsafe fn after_reset(queue: DmaQueueIdentity) -> Self {
        Self {
            device: queue.device(),
            generation: queue.generation(),
        }
    }
}

impl ReservedBalloonPage {
    /// # Safety
    /// The allocator published exactly one live, aligned page reservation for
    /// `expected`. Callback code and reservation backing outlive every state;
    /// failure, abandonment and failed return retain the allocation.
    /// # Errors
    /// Rejects foreign device identity, malformed reservation identity and
    /// physical coordinates outside the supported wire PFN space.
    #[expect(
        unsafe_code,
        reason = "the allocation publisher must establish unique retained ownership and callback lifetime before importing its reservation"
    )]
    pub unsafe fn from_allocator(
        raw: AbiBalloonPage,
        expected: PackedPciLocation,
        command: BalloonPageCommandFn,
    ) -> Result<Self, BalloonPageError> {
        if raw.device != expected.raw() || expected.is_null() {
            return Err(BalloonPageError::DeviceMismatch);
        }
        Ok(Self {
            core: PageCore {
                id: BalloonLeaseId::from_abi(raw.lease_id).ok_or(BalloonPageError::MalformedAbi)?,
                pfn: BalloonPageNumber::from_physical(PhysicalAddress::new(raw.physical_address))?,
                device: expected,
                command,
            },
            _not_sync: PhantomData,
        })
    }
    /// Transfer an unpublished reservation to the foreign allocator output.
    /// The receiving boundary must keep the same unique reservation contract.
    pub fn into_abi(self) -> AbiBalloonPage {
        let raw = AbiBalloonPage {
            lease_id: self.core.id.raw(),
            physical_address: u64::from(self.core.pfn.wire_pfn()) * BALLOON_PAGE_BYTES,
            device: self.core.device.raw(),
        };
        core::mem::forget(self.core);
        raw
    }
    /// Arm the page before publishing its PFN on inflateq.
    /// # Errors
    /// Rejection preserves the same unaccepted page reservation.
    pub fn arm(
        self,
        queue: DmaQueueIdentity,
    ) -> Result<InflatingBalloonPage, BalloonPageTransitionError<Self>> {
        if queue.device() != self.core.device || queue.index() != 0 {
            return Err(BalloonPageTransitionError {
                cause: BalloonPageError::DeviceMismatch,
                page: self,
            });
        }
        if let Err(cause) = self
            .core
            .apply(BalloonPageCommand::Inflate, queue.generation())
        {
            return Err(BalloonPageTransitionError { cause, page: self });
        }
        Ok(InflatingBalloonPage {
            core: self.core,
            _not_sync: PhantomData,
        })
    }
    /// Return a never-published or acknowledged-deflated page to its allocator.
    /// # Errors
    /// Return failure leaves the same reservation available for an exact retry.
    pub fn close(self) -> Result<(), BalloonPageTransitionError<Self>> {
        if let Err(cause) = self.core.apply(BalloonPageCommand::Release, 0) {
            return Err(BalloonPageTransitionError { cause, page: self });
        }
        // Registry release consumed the reservation. Suppress abandonment after
        // successful return; the core contains metadata and no owned backing.
        core::mem::forget(self.core);
        Ok(())
    }
}
impl InflatingBalloonPage {
    /// Record matching inflate completion without allowing allocator reuse.
    /// # Errors
    /// Invalid/stale evidence or failed transition retains the inflating page.
    pub fn acknowledge(
        self,
        witness: BalloonAcknowledgement,
    ) -> Result<InflatedBalloonPage, BalloonPageTransitionError<Self>> {
        if witness.lease != self.core.id
            || witness.queue.device() != self.core.device
            || witness.queue.index() != 0
        {
            return Err(BalloonPageTransitionError {
                cause: BalloonPageError::DeviceMismatch,
                page: self,
            });
        }
        if let Err(cause) = self
            .core
            .apply(BalloonPageCommand::Inflated, witness.queue.generation())
        {
            return Err(BalloonPageTransitionError { cause, page: self });
        }
        Ok(InflatedBalloonPage {
            core: self.core,
            _not_sync: PhantomData,
        })
    }
}
impl InflatedBalloonPage {
    /// Arm withdrawal before publishing the page on deflateq.
    /// # Errors
    /// Rejection preserves the same inflated page; it cannot return to CPU yet.
    pub fn deflate(
        self,
        queue: DmaQueueIdentity,
    ) -> Result<DeflatingBalloonPage, BalloonPageTransitionError<Self>> {
        if queue.device() != self.core.device || queue.index() != 1 {
            return Err(BalloonPageTransitionError {
                cause: BalloonPageError::DeviceMismatch,
                page: self,
            });
        }
        if let Err(cause) = self
            .core
            .apply(BalloonPageCommand::Deflate, queue.generation())
        {
            return Err(BalloonPageTransitionError { cause, page: self });
        }
        Ok(DeflatingBalloonPage {
            core: self.core,
            _not_sync: PhantomData,
        })
    }
}
impl DeflatingBalloonPage {
    /// Restore reservation return authority after matching deflate completion.
    /// # Errors
    /// Failure retains the deflating page and excludes allocator reuse.
    pub fn acknowledge(
        self,
        witness: BalloonAcknowledgement,
    ) -> Result<ReservedBalloonPage, BalloonPageTransitionError<Self>> {
        if witness.lease != self.core.id
            || witness.queue.device() != self.core.device
            || witness.queue.index() != 1
        {
            return Err(BalloonPageTransitionError {
                cause: BalloonPageError::DeviceMismatch,
                page: self,
            });
        }
        if let Err(cause) = self
            .core
            .apply(BalloonPageCommand::Deflated, witness.queue.generation())
        {
            return Err(BalloonPageTransitionError { cause, page: self });
        }
        Ok(ReservedBalloonPage {
            core: self.core,
            _not_sync: PhantomData,
        })
    }
}
macro_rules! reset_recovery {
    ($name:ident) => {
        impl $name {
            /// Restore return authority after observed reset, without claiming
            /// that a pending inflate/deflate completed successfully.
            /// # Errors
            /// Stale/foreign evidence or failed transition retains this page.
            pub fn recover(
                self,
                witness: BalloonResetWitness,
            ) -> Result<ReservedBalloonPage, BalloonPageTransitionError<Self>> {
                if witness.device != self.core.device {
                    return Err(BalloonPageTransitionError {
                        cause: BalloonPageError::DeviceMismatch,
                        page: self,
                    });
                }
                if let Err(cause) = self
                    .core
                    .apply(BalloonPageCommand::Reset, witness.generation)
                {
                    return Err(BalloonPageTransitionError { cause, page: self });
                }
                Ok(ReservedBalloonPage {
                    core: self.core,
                    _not_sync: PhantomData,
                })
            }
        }
    };
}
reset_recovery!(InflatingBalloonPage);
reset_recovery!(InflatedBalloonPage);
reset_recovery!(DeflatingBalloonPage);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_pfn_is_a_checked_physical_coordinate() {
        assert_eq!(
            BalloonPageNumber::from_physical(PhysicalAddress::new(0x3000))
                .unwrap()
                .wire_pfn(),
            3
        );
        assert_eq!(
            BalloonPageNumber::from_physical(PhysicalAddress::new(4097)),
            Err(BalloonPageError::InvalidPhysicalAddress)
        );
        assert_eq!(
            BalloonPageNumber::from_physical(PhysicalAddress::new(1u64 << 44)),
            Err(BalloonPageError::InvalidPhysicalAddress)
        );
        assert_eq!(
            BalloonPageNumber::from_physical(PhysicalAddress::new((u32::MAX as u64) * 4096))
                .unwrap()
                .wire_pfn(),
            u32::MAX
        );
    }
}
