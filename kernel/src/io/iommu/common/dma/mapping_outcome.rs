//! A DMA translation owner retains its exact domain, hardware source, IOVA
//! allocator and retirement progress. Addresses are observations. Rejection
//! before data-leaf publication returns ordinary ownership; synchronization
//! failure retains this owner until the hardware completion can be retried.

use super::iova_allocator::IovaAllocator;
use super::page_table_pool::DetachedTables;
use crate::io::iommu::common::domain::{InvalidateRequest, IommuDomain, IommuInvalidator};
use crate::io::iommu::types::IommuError;
use alloc::sync::Arc;

/// Hardware lifetime is captured at admission, never rediscovered from a
/// current device binding during retirement. Only invalidation is exposed.
pub(in crate::io::iommu) enum DmaInvalidationSource {
    Intel(Arc<crate::io::iommu::vendors::intel::controller::IommuController>),
    Amd(Arc<crate::io::iommu::vendors::amd::AmdIommuDriver>),
}
impl core::fmt::Debug for DmaInvalidationSource {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Intel(_) => "Intel",
            Self::Amd(_) => "AMD",
        })
    }
}
impl DmaInvalidationSource {
    fn invalidate(&self, request: InvalidateRequest) -> Result<(), IommuError> {
        match self {
            Self::Intel(controller) => controller.invalidate(request),
            Self::Amd(driver) => driver.invalidate(request),
        }
    }
    async fn invalidate_async(&self, request: InvalidateRequest) -> Result<(), IommuError> {
        match self {
            Self::Intel(controller) => controller.invalidate_async(request).await,
            Self::Amd(driver) => driver.invalidate_async(request).await,
        }
    }
}

#[derive(Debug)]
enum Retirement {
    Mapped,
    DataDetached,
    TranslationPending(DetachedTables),
    IovaPending,
}

/// A failure's remaining work. The returned owner, rather than this observation,
/// carries the authority and cohort needed to resume it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaRetirementStage {
    Mapped,
    /// Data leaves are gone; table-cohort capture is still pending.
    DataDetached,
    TranslationPending,
    IovaPending,
}

#[derive(Debug)]
struct TranslationOwner {
    domain: Arc<IommuDomain>,
    source: DmaInvalidationSource,
    allocator: Arc<IovaAllocator>,
    retirement: Retirement,
}

/// Unique release authority for one published DMA range. Dropping it retains
/// the domain/hardware lifetime and IOVA reservation; a backing owner must keep
/// its RAM until `unmap` completes. This type never releases backing RAM itself.
#[derive(Debug)]
pub struct DeviceMappedRange {
    iova: u64,
    phys: u64,
    size: u64,
    owner: Option<TranslationOwner>,
}
impl DeviceMappedRange {
    /// Prepare the lifetime dependencies before the first data leaf is written.
    pub(in crate::io::iommu) fn admitted(
        domain: Arc<IommuDomain>,
        source: DmaInvalidationSource,
        allocator: Arc<IovaAllocator>,
        iova: u64,
        phys: u64,
        size: u64,
    ) -> Self {
        Self {
            iova,
            phys,
            size,
            owner: Some(TranslationOwner {
                domain,
                source,
                allocator,
                retirement: Retirement::Mapped,
            }),
        }
    }
    pub fn iova(&self) -> u64 {
        self.iova
    }
    pub fn phys_addr(&self) -> u64 {
        self.phys
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn domain_id(&self) -> u16 {
        self.owner
            .as_ref()
            .expect("live translation owner")
            .domain
            .id()
    }
    pub fn retirement_stage(&self) -> DmaRetirementStage {
        match self
            .owner
            .as_ref()
            .expect("live translation owner")
            .retirement
        {
            Retirement::Mapped => DmaRetirementStage::Mapped,
            Retirement::DataDetached => DmaRetirementStage::DataDetached,
            Retirement::TranslationPending(_) => DmaRetirementStage::TranslationPending,
            Retirement::IovaPending => DmaRetirementStage::IovaPending,
        }
    }
    /// No data leaf was published. A failed reservation release stays retained.
    pub(in crate::io::iommu) fn reject_unpublished(mut self) {
        let owner = self.owner.take().expect("admitted owner");
        if let Err(error) = owner.allocator.free_immediate(self.iova, self.size) {
            log::error!("unpublished IOVA reservation retained: {error:?}");
            core::mem::forget(owner);
        }
    }
    pub(in crate::io::iommu) fn synchronize_map(&self) -> Result<(), IommuError> {
        let owner = self.owner.as_ref().expect("live translation owner");
        owner.source.invalidate(
            InvalidateRequest::domain(owner.domain.id())
                .with_ats()
                .with_drain(),
        )
    }
    pub(in crate::io::iommu) async fn synchronize_map_async(&self) -> Result<(), IommuError> {
        let owner = self.owner.as_ref().expect("live translation owner");
        owner
            .source
            .invalidate_async(
                InvalidateRequest::domain(owner.domain.id())
                    .with_ats()
                    .with_drain(),
            )
            .await
    }
    fn prepare_retirement(&mut self) -> Result<Option<InvalidateRequest>, IommuError> {
        let owner = self.owner.as_mut().expect("live translation owner");
        if matches!(owner.retirement, Retirement::Mapped) {
            owner
                .domain
                .detach_owned_range(self.iova, self.phys, self.size)?;
            owner.retirement = Retirement::DataDetached;
        }
        if matches!(owner.retirement, Retirement::DataDetached) {
            let tables = owner.domain.capture_detached_tables()?;
            owner.retirement = Retirement::TranslationPending(tables);
        }
        match &owner.retirement {
            Retirement::TranslationPending(tables) => {
                let request = if tables.is_empty() {
                    InvalidateRequest::pages(owner.domain.id(), self.iova, self.size)
                } else {
                    InvalidateRequest::domain(owner.domain.id())
                };
                Ok(Some(request.with_ats().with_drain()))
            }
            Retirement::IovaPending => Ok(None),
            Retirement::Mapped | Retirement::DataDetached => {
                unreachable!("capture advances retirement")
            }
        }
    }
    fn confirm_translation(&mut self) {
        let owner = self.owner.as_mut().expect("live translation owner");
        if let Retirement::TranslationPending(tables) =
            core::mem::replace(&mut owner.retirement, Retirement::IovaPending)
        {
            // SAFETY: the source completed the request issued after this cohort
            // was captured, including paging structures, ATS and DMA drain.
            unsafe { owner.domain.release_detached_tables(tables) };
        }
    }
    fn release_iova(&mut self) -> Result<(), IommuError> {
        let owner = self.owner.as_ref().expect("live translation owner");
        assert!(matches!(owner.retirement, Retirement::IovaPending));
        owner.allocator.free_immediate(self.iova, self.size)?;
        self.owner.take();
        crate::io::iommu::runtime::stats::inc_unmap_count();
        Ok(())
    }
    /// Retry resumes from the retained phase; it never clears the same mapping
    /// twice or retires an IOVA through a subsequently assigned device domain.
    pub(in crate::io::iommu) fn resume_retirement(&mut self) -> Result<(), IommuError> {
        if let Some(request) = self.prepare_retirement()? {
            self.owner
                .as_ref()
                .expect("live translation owner")
                .source
                .invalidate(request)?;
            self.confirm_translation();
        }
        self.release_iova()
    }
    pub(in crate::io::iommu) async fn resume_retirement_async(&mut self) -> Result<(), IommuError> {
        if let Some(request) = self.prepare_retirement()? {
            self.owner
                .as_ref()
                .expect("live translation owner")
                .source
                .invalidate_async(request)
                .await?;
            self.confirm_translation();
        }
        self.release_iova()
    }
    pub fn unmap(mut self) -> Result<(), DeviceUnmapFailure> {
        self.resume_retirement()
            .map_err(|cause| DeviceUnmapFailure {
                cause,
                mapping: self,
            })
    }
    pub async fn unmap_async(mut self) -> Result<(), DeviceUnmapFailure> {
        self.resume_retirement_async()
            .await
            .map_err(|cause| DeviceUnmapFailure {
                cause,
                mapping: self,
            })
    }
}
impl Drop for DeviceMappedRange {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            // Drop is not a hardware completion boundary. Retain all origin
            // dependencies, including the detached tables, without blocking.
            core::mem::forget(owner);
        }
    }
}

#[derive(Debug)]
pub struct DeviceUnmapFailure {
    pub cause: IommuError,
    pub mapping: DeviceMappedRange,
}

#[derive(Debug)]
pub enum DeviceMapFailure {
    Unpublished(IommuError),
    TranslationPending {
        cause: IommuError,
        mapping: DeviceMappedRange,
    },
}
impl From<IommuError> for DeviceMapFailure {
    fn from(error: IommuError) -> Self {
        Self::Unpublished(error)
    }
}
