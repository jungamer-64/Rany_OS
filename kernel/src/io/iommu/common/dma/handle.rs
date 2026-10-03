// ============================================================================
// kernel/src/io/iommu/common/dma/handle.rs
// ============================================================================

//! DMA ownership moves with its translation lease. Mapping rejection returns
//! the `RRef`; publication followed by synchronization failure returns a DMA
//! handle instead. A finite retirement slot is admitted before publication.
//! Retirement retains progress and backing until IOTLB/ATS completion.
//! Drop transfers both into its reserved reclamation slot and never
//! performs blocking hardware operations.

use crate::io::iommu::types::{DeviceId, IommuError};
use crate::ipc::RRef;
use crate::mm::value::DmaElement;

#[path = "handle/bytes.rs"]
mod bytes;
pub(crate) use bytes::{DmaBytes, DmaBytesUnmapError};

// ============================================================================
// DMA Direction
// ============================================================================

/// DMA transfer direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDirection {
    /// CPU writes, device reads (e.g., TX buffer)
    ToDevice,
    /// Device writes, CPU reads (e.g., RX buffer)
    FromDevice,
    /// Bidirectional access
    Bidirectional,
}

// ============================================================================
// Error Types
// ============================================================================

/// Map operation error kind
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapErrorKind {
    /// No IOVA space available
    OutOfIova,
    /// The finite retirement-slot budget cannot admit this mapping.
    RetirementCapacity,
    /// Page table is full
    PageTableFull,
    /// The logical range is empty or exceeds its owned backing.
    InvalidSize,
    /// Buffer is not properly aligned
    InvalidAlignment,
    /// Domain not found
    DomainNotFound,
    /// IOMMU error
    IommuError(IommuError),
}

/// A rejected map returns ordinary ownership. Once a data leaf may have been
/// published, the error retains a DMA handle instead; its backing cannot be
/// accessed or returned to an allocator until explicit unmap completes.
#[derive(Debug)]
pub enum MapError<T: Send + ?Sized + 'static> {
    Unmapped {
        rref: RRef<T>,
        kind: MapErrorKind,
    },
    TranslationPending {
        handle: DmaHandle<T>,
        kind: MapErrorKind,
    },
}
impl<T: Send + ?Sized + 'static> MapError<T> {
    pub fn unmapped(rref: RRef<T>, kind: MapErrorKind) -> Self {
        Self::Unmapped { rref, kind }
    }
    pub fn kind(&self) -> MapErrorKind {
        match self {
            Self::Unmapped { kind, .. } | Self::TranslationPending { kind, .. } => *kind,
        }
    }
}

/// Unmap operation error kind
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnmapErrorKind {
    /// Invalid IOVA address
    InvalidIova,
    /// IOTLB invalidation timed out
    IoTlbTimeout,
    /// Domain not found
    DomainNotFound,
    /// IOMMU error
    IommuError(IommuError),
    /// Called from ISR context where blocking operations are forbidden
    ///
    /// Hardware completion may block; use async retirement from task context.
    CalledFromIsr,
    /// Blocking safety cannot be established without validated CPU-local state.
    CpuLocalUnavailable,
}

/// Unmap operation error (returns ownership on failure)
///
/// # Critical Safety
///
/// This error type returns the `DmaHandle<T>` so that ownership is not lost.
/// The caller can retry the unmap or take other recovery action.
#[derive(Debug)]
pub struct UnmapError<T: Send + ?Sized + 'static> {
    /// The handle - returned so caller can retry
    pub handle: DmaHandle<T>,
    /// Error kind
    pub kind: UnmapErrorKind,
}

impl<T: Send + ?Sized + 'static> UnmapError<T> {
    /// Create a new unmap error
    pub fn new(handle: DmaHandle<T>, kind: UnmapErrorKind) -> Self {
        Self { handle, kind }
    }
}

// ============================================================================
// DmaHandle<T>
// ============================================================================

/// The CPU cannot access the `RRef` while this handle owns its DMA mapping.
/// Unmap errors retain both the backing and the exact unfinished phase.
#[derive(Debug)]
pub struct DmaHandle<T: Send + ?Sized + 'static> {
    rref: Option<RRef<T>>,
    range: Option<super::mapping_outcome::DeviceMappedRange>,
    direction: DmaDirection,
    retirement: Option<crate::io::iommu::runtime::zombie::DmaRetirementReservation>,
}
impl<T: Send + ?Sized + 'static> DmaHandle<T> {
    fn from_mapping(
        rref: RRef<T>,
        range: super::mapping_outcome::DeviceMappedRange,
        direction: DmaDirection,
        retirement: crate::io::iommu::runtime::zombie::DmaRetirementReservation,
    ) -> Self {
        Self {
            rref: Some(rref),
            range: Some(range),
            direction,
            retirement: Some(retirement),
        }
    }
    fn range(&self) -> &super::mapping_outcome::DeviceMappedRange {
        self.range
            .as_ref()
            .expect("DMA handle retains translation ownership")
    }
    pub fn iova(&self) -> u64 {
        self.range().iova()
    }
    pub fn phys_addr(&self) -> u64 {
        self.range().phys_addr()
    }
    pub fn size(&self) -> u64 {
        self.range().size()
    }
    pub fn domain_id(&self) -> u16 {
        self.range().domain_id()
    }
    pub fn direction(&self) -> DmaDirection {
        self.direction
    }
    pub fn retirement_stage(&self) -> super::mapping_outcome::DmaRetirementStage {
        self.range().retirement_stage()
    }
    pub fn unmap(self) -> Result<RRef<T>, UnmapError<T>> {
        self.unmap_sync()
    }
    pub fn unmap_sync(mut self) -> Result<RRef<T>, UnmapError<T>> {
        let Some(current) = crate::cpu::CurrentCpu::acquire() else {
            return Err(UnmapError::new(self, UnmapErrorKind::CpuLocalUnavailable));
        };
        if current.in_interrupt() {
            return Err(UnmapError::new(self, UnmapErrorKind::CalledFromIsr));
        }
        if let Err(cause) = self
            .range
            .as_mut()
            .expect("live translation")
            .resume_retirement()
        {
            return Err(UnmapError::new(self, UnmapErrorKind::IommuError(cause)));
        }
        self.range.take();
        Ok(self.rref.take().expect("live DMA backing"))
    }
    /// Cancellation drops this handle into reclamation with the same progress.
    /// No CPU ownership is returned at submission, timeout or cancellation.
    pub async fn unmap_async(mut self) -> Result<RRef<T>, UnmapError<T>> {
        if let Err(cause) = self
            .range
            .as_mut()
            .expect("live translation")
            .resume_retirement_async()
            .await
        {
            return Err(UnmapError::new(self, UnmapErrorKind::IommuError(cause)));
        }
        self.range.take();
        Ok(self.rref.take().expect("live DMA backing"))
    }
}
impl<T: Send + ?Sized + 'static> Drop for DmaHandle<T> {
    fn drop(&mut self) {
        if let Some(rref) = self.rref.take() {
            // SAFETY: construction mapped this exact exclusive Exchange backing
            // with DmaElement validity. The handle exposes no CPU borrow and
            // uniquely retains both owners through each retirement phase.
            let payload = unsafe {
                crate::io::iommu::runtime::zombie::DroppedDma::new(
                    self.range.take().expect("DMA backing retains translation"),
                    rref,
                )
            };
            self.retirement
                .take()
                .expect("DMA backing retains reclamation admission")
                .publish(payload);
        }
    }
}
impl<T: DmaElement> DmaHandle<[T]> {
    pub(super) fn dma_direction_to_perms(direction: DmaDirection) -> (bool, bool) {
        match direction {
            DmaDirection::ToDevice => (true, false),
            DmaDirection::FromDevice => (false, true),
            DmaDirection::Bidirectional => (true, true),
        }
    }
    pub fn map_rref_slice_for_device(
        rref: RRef<[T]>,
        device: &DeviceId,
        direction: DmaDirection,
    ) -> Result<Self, MapError<[T]>> {
        let size = match rref.len().checked_mul(core::mem::size_of::<T>()) {
            Some(size) if size > 0 && size & 4095 == 0 => size as u64,
            _ => return Err(MapError::unmapped(rref, MapErrorKind::InvalidAlignment)),
        };
        let virt = x86_64::VirtAddr::new(rref.as_ptr() as u64);
        let phys = crate::mm::virt::mapping::virt_to_phys(virt);
        if phys.as_u64() & 4095 != 0 {
            return Err(MapError::unmapped(rref, MapErrorKind::InvalidAlignment));
        }
        let (read, write) = Self::dma_direction_to_perms(direction);
        let Some(retirement) = crate::io::iommu::runtime::zombie::reserve_retirement() else {
            return Err(MapError::unmapped(rref, MapErrorKind::RetirementCapacity));
        };
        // SAFETY: the exclusive page-exact Exchange allocation remains retained
        // by this handle. DmaElement permits arbitrary device-written bytes and
        // fully initialized reads; CPU access is suspended until retirement.
        let result = unsafe {
            crate::io::iommu::api::map_for_device_with_perms(device, phys, size, read, write)
        };
        match result {
            Ok(mapping) => Ok(Self::from_mapping(rref, mapping, direction, retirement)),
            Err(super::mapping_outcome::DeviceMapFailure::Unpublished(cause)) => {
                Err(MapError::unmapped(rref, MapErrorKind::IommuError(cause)))
            }
            Err(super::mapping_outcome::DeviceMapFailure::TranslationPending {
                cause,
                mapping,
            }) => Err(MapError::TranslationPending {
                handle: Self::from_mapping(rref, mapping, direction, retirement),
                kind: MapErrorKind::IommuError(cause),
            }),
        }
    }
}
impl<T: DmaElement> DmaHandle<T> {
    pub fn map_rref_for_device(
        rref: RRef<T>,
        device: &DeviceId,
        direction: DmaDirection,
    ) -> Result<Self, MapError<T>> {
        let size = core::mem::size_of::<T>() as u64;
        if size == 0 || size & 4095 != 0 {
            return Err(MapError::unmapped(rref, MapErrorKind::InvalidAlignment));
        }
        let virt = x86_64::VirtAddr::new((&*rref as *const T) as u64);
        let phys = crate::mm::virt::mapping::virt_to_phys(virt);
        if phys.as_u64() & 4095 != 0 {
            return Err(MapError::unmapped(rref, MapErrorKind::InvalidAlignment));
        }
        let (read, write) = DmaHandle::<[T]>::dma_direction_to_perms(direction);
        let Some(retirement) = crate::io::iommu::runtime::zombie::reserve_retirement() else {
            return Err(MapError::unmapped(rref, MapErrorKind::RetirementCapacity));
        };
        // SAFETY: the exclusive page-exact Exchange allocation remains retained
        // by this handle. DmaElement permits arbitrary device-written bytes and
        // fully initialized reads; CPU access is suspended until retirement.
        let result = unsafe {
            crate::io::iommu::api::map_for_device_with_perms(device, phys, size, read, write)
        };
        match result {
            Ok(mapping) => Ok(Self::from_mapping(rref, mapping, direction, retirement)),
            Err(super::mapping_outcome::DeviceMapFailure::Unpublished(cause)) => {
                Err(MapError::unmapped(rref, MapErrorKind::IommuError(cause)))
            }
            Err(super::mapping_outcome::DeviceMapFailure::TranslationPending {
                cause,
                mapping,
            }) => Err(MapError::TranslationPending {
                handle: Self::from_mapping(rref, mapping, direction, retirement),
                kind: MapErrorKind::IommuError(cause),
            }),
        }
    }
}
