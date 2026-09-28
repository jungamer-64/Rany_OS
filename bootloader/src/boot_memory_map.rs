//! Owns the normalized memory-map allocation across ExitBootServices.
//!
//! Pages are runtime-services data, not allocator pool storage. Abandoning this
//! owner leaves the allocation reserved: Drop never calls firmware, especially
//! after ExitBootServices. Only an unpublished buffer has an explicit release
//! boundary; completed snapshots are immutable and retained for kernel handoff.

#![deny(unsafe_code)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::missing_safety_doc)]

use core::mem::MaybeUninit;
use core::ptr::NonNull;
use uefi::Status;
use uefi::boot::{self, AllocateType};
use uefi::mem::memory_map::{MemoryMap, MemoryMapOwned, MemoryType};

use crate::memory_map_copy::{self, CopyError, MemoryMapLayout};

#[derive(Debug)]
pub(crate) enum ReserveError {
    Geometry(CopyError),
    Firmware(Status),
}

impl core::fmt::Display for ReserveError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Geometry(cause) => write!(formatter, "invalid memory-map allocation: {cause:?}"),
            Self::Firmware(cause) => {
                write!(formatter, "UEFI memory-map allocation failed: {cause:?}")
            }
        }
    }
}

/// Exclusive ownership of one exact UEFI page allocation. No raw-parts
/// constructor or Clone can manufacture a second writer or reclaimer.
#[derive(Debug)]
pub(crate) struct MemoryMapBuffer {
    base: NonNull<u8>,
    layout: MemoryMapLayout,
}

#[derive(Debug)]
pub(crate) struct SnapshotFailure {
    pub(crate) cause: CopyError,
    pub(crate) retained: MemoryMapBuffer,
}

impl core::fmt::Display for SnapshotFailure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "memory-map copy failed: {:?}; retained allocation {:?}",
            self.cause, self.retained
        )
    }
}

#[derive(Debug)]
pub(crate) struct ReleaseFailure {
    pub(crate) cause: Status,
    // Firmware finalization may have consumed authority. Keep this allocation
    // opaque: an error is not permission to initialize or retry freeing it.
    retained: MemoryMapBuffer,
}

impl core::fmt::Display for ReleaseFailure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "UEFI release outcome unknown: {:?}; retained allocation {:?}",
            self.cause, self.retained
        )
    }
}

/// An entirely copied snapshot. Its initialized count cannot be independently
/// changed, and its backing allocation has no release or mutable-access API.
#[derive(Debug)]
pub(crate) struct MemoryMapSnapshot {
    backing: MemoryMapBuffer,
    initialized: usize,
}

impl MemoryMapBuffer {
    /// # Errors
    /// Geometry failure allocates nothing. A firmware allocation failure is
    /// returned without constructing an owner.
    ///
    /// # Panics
    /// Like the underlying UEFI allocator, requires active boot services.
    pub(crate) fn reserve(capacity: usize) -> Result<Self, ReserveError> {
        let layout = MemoryMapLayout::new(capacity).map_err(ReserveError::Geometry)?;
        let base = boot::allocate_pages(
            AllocateType::AnyPages,
            MemoryType::RUNTIME_SERVICES_DATA,
            layout.pages(),
        )
        .map_err(|error| ReserveError::Firmware(error.status()))?;
        Ok(Self { base, layout })
    }

    /// # Errors
    /// Returns the original allocation and the copy failure, including written
    /// prefix progress. Failure never publishes a descriptor table or frees RAM.
    #[expect(
        unsafe_code,
        reason = "only this allocation owner creates an exclusive view of its uninitialized descriptor storage"
    )]
    pub(crate) fn initialize(
        self,
        map: &MemoryMapOwned,
    ) -> Result<MemoryMapSnapshot, SnapshotFailure> {
        let records = map.entries().map(|desc| boot_proto::MemoryDescriptor {
            r#type: desc.ty.0,
            pad: 0,
            phys_start: desc.phys_start,
            virt_start: desc.virt_start,
            page_count: desc.page_count,
            attribute: desc.att.bits(),
        });
        // SAFETY: allocate_pages supplies one exclusively owned, page-aligned
        // allocation. The checked layout contains capacity descriptor slots and
        // bounds its byte extent by isize::MAX. MaybeUninit needs no initialized
        // bytes; the temporary borrow cannot outlive or alias this moved owner.
        let slots = unsafe {
            core::slice::from_raw_parts_mut(
                self.base
                    .cast::<MaybeUninit<boot_proto::MemoryDescriptor>>()
                    .as_ptr(),
                self.layout.capacity(),
            )
        };
        match memory_map_copy::copy_records(records, slots) {
            Ok(initialized) => Ok(MemoryMapSnapshot {
                backing: self,
                initialized,
            }),
            Err(cause) => Err(SnapshotFailure {
                cause,
                retained: self,
            }),
        }
    }

    /// # Safety
    /// Boot services must still be active; ExitBootServices must not run during
    /// this call. This unpublished buffer must not have been handed to firmware
    /// or kernel consumers outside this owner.
    ///
    /// # Errors
    /// Firmware failure quarantines the allocation and its exact release layout.
    /// The error cannot recover writing or reclamation authority: it must not be
    /// interpreted as proof that the firmware left the allocation unchanged.
    #[expect(
        unsafe_code,
        reason = "UEFI page reclamation consumes this unique allocation before boot services exit"
    )]
    pub(crate) unsafe fn close(self) -> Result<(), ReleaseFailure> {
        // SAFETY: the caller ensures active boot services. Consuming self ends
        // all owner borrows; only this path frees the original allocation with
        // its unchanged page count. No automatic destructor also frees it.
        match unsafe { boot::free_pages(self.base, self.layout.pages()) } {
            Ok(()) => Ok(()),
            Err(error) => Err(ReleaseFailure {
                cause: error.status(),
                retained: self,
            }),
        }
    }
}

impl MemoryMapSnapshot {
    #[expect(
        unsafe_code,
        reason = "completed bounded initialization and retained allocation establish the immutable descriptor slice"
    )]
    pub(crate) fn records(&self) -> &[boot_proto::MemoryDescriptor] {
        // SAFETY: initialize returns success only after writing exactly this
        // prefix, within the checked allocation capacity. The backing pages
        // remain reserved through this borrow; no snapshot API mutates or frees
        // them. Zero records still use the nonnull aligned allocation pointer.
        unsafe { core::slice::from_raw_parts(self.backing.base.cast().as_ptr(), self.initialized) }
    }

    /// Physical geometry for allocator reservation, not dereference authority.
    pub(crate) fn allocation_range(&self) -> (u64, u64) {
        (
            self.backing.base.as_ptr().addr() as u64,
            self.backing.layout.bytes() as u64,
        )
    }

    /// Creates ABI metadata only; dereferencing it still requires the boot
    /// handoff's installed HHDM and retained-storage contract.
    ///
    /// # Errors
    /// Rejects HHDM addition or extent overflow before changing boot info.
    pub(crate) fn handoff(&self, hhdm_start: u64) -> Result<boot_proto::MemoryMap, &'static str> {
        let address = hhdm_start
            .checked_add(self.allocation_range().0)
            .ok_or("memory-map HHDM address overflowed")?;
        boot_proto::MemoryMap::from_hhdm_addr(address, self.initialized)
    }
}
