//! Unique firmware owner of the kernel and exchange bootstrap RAM. Neither
//! Drop nor an ABI descriptor can release or reacquire this slab.
#![deny(unsafe_code)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::missing_safety_doc)]

use boot_proto::{BootstrapHeapGeometry, BootstrapHeapLayout, BootstrapMemoryError};
use core::ptr::NonNull;
use uefi::Status;
use uefi::boot::{self, AllocateType};
use uefi::mem::memory_map::MemoryType;

#[derive(Debug)]
pub(crate) struct BootstrapHeapAllocation {
    base: NonNull<u8>,
    layout: BootstrapHeapLayout,
}

#[derive(Debug)]
pub(crate) enum ReservationFailure {
    Geometry(BootstrapMemoryError),
    Firmware(Status),
    Unpublished {
        cause: BootstrapMemoryError,
        retained: BootstrapHeapAllocation,
    },
}

#[derive(Debug)]
pub(crate) struct ReleaseFailure {
    status: Status,
    retained: BootstrapHeapAllocation,
}

impl core::fmt::Display for ReleaseFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "bootstrap heap release outcome unknown: {:?}; retained {:?}",
            self.status, self.retained
        )
    }
}

impl ReservationFailure {
    /// # Safety
    /// Boot services must remain active; no descriptor from this failed build
    /// was published. No retry/reuse follows a failed firmware release.
    /// # Errors
    /// Release failure keeps the only allocation owner in the error.
    #[expect(
        unsafe_code,
        reason = "only unpublished firmware allocation ownership can be released"
    )]
    pub(crate) unsafe fn release(self) -> Result<Status, ReleaseFailure> {
        match self {
            Self::Geometry(cause) => {
                log::error!("invalid bootstrap heap layout: {cause:?}");
                Ok(Status::INVALID_PARAMETER)
            }
            Self::Firmware(status) => Ok(status),
            Self::Unpublished { cause, retained } => {
                log::error!("bootstrap heap geometry rejected: {cause:?}");
                // SAFETY: consumed unpublished owner; caller keeps firmware
                // services active. Exact page layout is retained on failure.
                match unsafe { boot::free_pages(retained.base, retained.layout.pages()) } {
                    Ok(()) => Ok(Status::INVALID_PARAMETER),
                    Err(error) => Err(ReleaseFailure {
                        status: error.status(),
                        retained,
                    }),
                }
            }
        }
    }
}

/// Retained across ExitBootServices and consumed at kernel entry. The loader
/// never lends mutable storage; allocator metadata is initialized by the kernel.
#[derive(Debug)]
pub(crate) struct BootstrapHeapHandoff {
    allocation: BootstrapHeapAllocation,
    geometry: BootstrapHeapGeometry,
}

impl BootstrapHeapHandoff {
    /// # Errors
    /// Pre-admission failure owns no RAM. Post-admission geometry failure
    /// retains the unpublished allocation for explicit fallible release.
    pub(crate) fn reserve(hhdm_start: u64, mapped_limit: u64) -> Result<Self, ReservationFailure> {
        let layout = BootstrapHeapLayout::for_kernel().map_err(ReservationFailure::Geometry)?;
        let base = boot::allocate_pages(
            AllocateType::AnyPages,
            MemoryType::LOADER_DATA,
            layout.pages(),
        )
        .map_err(|error| ReservationFailure::Firmware(error.status()))?;
        let allocation = BootstrapHeapAllocation { base, layout };
        let geometry = match layout.at(base.as_ptr().addr() as u64, hhdm_start, mapped_limit) {
            Ok(geometry) => geometry,
            Err(cause) => {
                return Err(ReservationFailure::Unpublished {
                    cause,
                    retained: allocation,
                });
            }
        };
        Ok(Self {
            allocation,
            geometry,
        })
    }

    pub(crate) fn descriptor(&self) -> boot_proto::BootstrapHeapDescriptor {
        self.geometry.descriptor()
    }
    pub(crate) fn allocation_range(&self) -> (u64, u64) {
        (
            self.allocation.base.as_ptr().addr() as u64,
            self.allocation.layout.allocation().size() as u64,
        )
    }
}
