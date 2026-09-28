//! Owns the copied artifact table and bytes across the kernel handoff.
//!
//! The one page allocation is a completed, immutable snapshot. It is retained
//! after ExitBootServices; Drop cannot call firmware. Only an unpublished,
//! incomplete allocation may be explicitly returned to firmware.

#![deny(unsafe_code)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::missing_safety_doc)]

use core::ptr::NonNull;
use uefi::Status;
use uefi::boot::{self, AllocateType};
use uefi::mem::memory_map::MemoryType;

use crate::boot_artifact_copy::{ArtifactLayout, ArtifactPlan, BootArtifactFile, CopyError};

#[derive(Debug)]
pub(crate) enum BuildFailure {
    Geometry(CopyError),
    Firmware(Status),
    Unpublished {
        cause: InitializationError,
        retained: ArtifactStorage,
    },
}

impl core::fmt::Display for BuildFailure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Geometry(cause) => write!(formatter, "invalid artifact geometry: {cause:?}"),
            Self::Unpublished { cause, .. } => {
                write!(formatter, "unpublished artifact handoff: {cause}")
            }
            Self::Firmware(status) => write!(formatter, "artifact allocation failed: {status:?}"),
        }
    }
}

impl BuildFailure {
    /// Returns the failed build's status after trying to release any allocation
    /// still unpublished. Firmware release failure keeps opaque ownership in
    /// the error; it cannot be used as permission to retry or publish.
    ///
    /// # Safety
    /// Boot services must still be active and no concurrent ExitBootServices
    /// may occur.
    ///
    /// # Errors
    /// Firmware release failure retains the allocation and its exact layout.
    #[expect(
        unsafe_code,
        reason = "unpublished firmware pages have an explicit release boundary"
    )]
    pub(crate) unsafe fn release(self) -> Result<Status, ReleaseFailure> {
        match self {
            Self::Geometry(_) => Ok(Status::INVALID_PARAMETER),
            Self::Firmware(status) => Ok(status),
            Self::Unpublished { retained, .. } => {
                // SAFETY: the caller guarantees boot services remain active;
                // this failed build never published a table or lent its pages.
                unsafe { retained.close() }.map(|()| Status::INVALID_PARAMETER)
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct ReleaseFailure {
    cause: Status,
    retained: ArtifactStorage,
}

#[derive(Debug)]
pub(crate) enum InitializationError {
    OutsideHhdm,
    Copy(CopyError),
}

impl core::fmt::Display for InitializationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OutsideHhdm => formatter.write_str("allocation is outside installed HHDM"),
            Self::Copy(cause) => write!(formatter, "copy failed: {cause:?}"),
        }
    }
}

impl core::fmt::Display for ReleaseFailure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "artifact release outcome unknown: {:?}; retained {:?}",
            self.cause, self.retained
        )
    }
}

#[derive(Debug)]
pub(crate) struct ArtifactStorage {
    base: NonNull<u8>,
    layout: ArtifactLayout,
}

impl ArtifactStorage {
    fn allocation_range(&self) -> (u64, u64) {
        (self.base.as_ptr().addr() as u64, self.layout.bytes() as u64)
    }

    /// # Safety
    /// Boot services must still be active; the allocation must remain
    /// unpublished, and no outstanding borrow may refer to its bytes.
    ///
    /// # Errors
    /// Firmware release failure retains the original allocation and layout.
    #[expect(
        unsafe_code,
        reason = "UEFI page release is confined to the unique unpublished owner"
    )]
    unsafe fn close(self) -> Result<(), ReleaseFailure> {
        // SAFETY: the caller keeps boot services active and this consuming
        // operation is the only reclaimer of this unpublished allocation.
        match unsafe { boot::free_pages(self.base, self.layout.pages()) } {
            Ok(()) => Ok(()),
            Err(error) => Err(ReleaseFailure {
                cause: error.status(),
                retained: self,
            }),
        }
    }

    #[expect(
        unsafe_code,
        reason = "the unique page owner initializes disjoint table and byte ranges"
    )]
    fn initialize(
        &mut self,
        plan: &ArtifactPlan<'_>,
        hhdm_start: u64,
    ) -> Result<boot_proto::BootArtifactTable, CopyError> {
        let (base_phys, _) = self.allocation_range();
        let slab_hhdm = hhdm_start
            .checked_add(base_phys)
            .ok_or(CopyError::InvalidSpan(
                "artifact slab HHDM address overflowed",
            ))?;
        // SAFETY: UEFI supplied one exclusive page-aligned RAM allocation of
        // exactly layout.pages(). The checked Layout bounds its extent by
        // isize::MAX and contains both nonoverlapping ranges. Zero is valid for
        // u8 and every integer field of BootArtifactEntry. The views stay local
        // to this borrow and cannot outlive the retained owner.
        unsafe {
            core::ptr::write_bytes(self.base.as_ptr(), 0, self.layout.bytes());
            let entries = core::slice::from_raw_parts_mut(
                self.base.cast::<boot_proto::BootArtifactEntry>().as_ptr(),
                self.layout.entry_count(),
            );
            let payload = core::slice::from_raw_parts_mut(
                self.base.as_ptr().add(self.layout.entries_bytes()),
                self.layout.payload_bytes(),
            );
            plan.initialize(entries, payload, slab_hhdm)
        }
    }
}

/// Completed immutable handoff. The ABI table is only a projection of this
/// owner. Loader consumers use allocation geometry, not a raw metadata reborrow;
/// the kernel's ABI view still requires its explicit unsafe handoff contract.
#[derive(Debug)]
pub(crate) struct BootArtifactHandoff {
    storage: Option<ArtifactStorage>,
    table: boot_proto::BootArtifactTable,
}

impl BootArtifactHandoff {
    /// # Errors
    /// Rejects invalid sizes or spans before publication. A post-allocation
    /// failure retains the unpublished owner for explicit release.
    pub(crate) fn build(
        artifacts: &[BootArtifactFile],
        hhdm_start: u64,
        mapped_physical_limit: u64,
    ) -> Result<Self, BuildFailure> {
        let Some(plan) = ArtifactPlan::new(artifacts).map_err(BuildFailure::Geometry)? else {
            return Ok(Self {
                storage: None,
                table: boot_proto::BootArtifactTable::default(),
            });
        };
        let layout = plan.layout();
        let base = boot::allocate_pages(
            AllocateType::AnyPages,
            MemoryType::LOADER_DATA,
            layout.pages(),
        )
        .map_err(|error| BuildFailure::Firmware(error.status()))?;
        let mut storage = ArtifactStorage { base, layout };
        let (physical, bytes) = storage.allocation_range();
        if physical
            .checked_add(bytes)
            .is_none_or(|end| end > mapped_physical_limit)
        {
            return Err(BuildFailure::Unpublished {
                cause: InitializationError::OutsideHhdm,
                retained: storage,
            });
        }
        let table = match storage.initialize(&plan, hhdm_start) {
            Ok(table) => table,
            Err(cause) => {
                return Err(BuildFailure::Unpublished {
                    cause: InitializationError::Copy(cause),
                    retained: storage,
                });
            }
        };
        Ok(Self {
            storage: Some(storage),
            table,
        })
    }

    pub(crate) fn table(&self) -> boot_proto::BootArtifactTable {
        self.table
    }

    /// Physical geometry for RAM exclusion, not independent dereference or
    /// release authority. The entire slab, including padding, stays reserved.
    pub(crate) fn allocation_range(&self) -> Option<(u64, u64)> {
        self.storage.as_ref().map(ArtifactStorage::allocation_range)
    }
}
