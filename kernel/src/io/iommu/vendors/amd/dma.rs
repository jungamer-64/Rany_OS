// ============================================================================
// kernel/src/io/iommu/vendors/amd/dma.rs
// ============================================================================

//! AMD-Vi DMA mapping, IOVA allocation, and command queue dispatch.

use crate::io::iommu::common::dma::mapping_outcome::{DeviceMapFailure, DeviceMappedRange};
use x86_64::PhysAddr;

use crate::io::iommu::common::dma::iova_allocator::PageGranularity;
use crate::io::iommu::runtime::command::queue::{IommuCommandKind, RESULT_POISONED};
use crate::io::iommu::types::{DeviceId, IommuError};

use super::AmdIommuDriver;

// ---------------------------------------------------------------------------
// DMA mapping methods on AmdIommuDriver
// ---------------------------------------------------------------------------

impl AmdIommuDriver {
    #[inline]
    fn cq_submit_error(&self) -> IommuError {
        match self.command_queue.as_ref() {
            Some(cq) if cq.is_poisoned() => IommuError::Poisoned,
            _ => IommuError::HardwareError,
        }
    }

    #[inline]
    fn cq_completion_error(rc: i32) -> IommuError {
        if rc == RESULT_POISONED {
            IommuError::Poisoned
        } else {
            IommuError::HardwareError
        }
    }

    /// Allocate an IOVA address
    ///
    /// The IovaAllocator is lock-free internally with per-CPU magazine caching.
    pub(super) fn allocate_iova(&self, size: u64, mask: Option<u64>) -> Result<u64, IommuError> {
        let iova = match mask {
            Some(limit) => {
                self.iova_allocator
                    .allocate_with_limit(size, PageGranularity::Page4K, limit)
            }
            None => self.iova_allocator.allocate(size, PageGranularity::Page4K),
        };
        iova.ok_or(IommuError::OutOfMemory)
    }

    /// Fast path IOVA allocation (4KB pages)
    ///
    /// IovaAllocator already provides O(1) allocation with per-CPU magazine,
    /// so this just delegates to allocate_iova.
    pub(super) fn allocate_iova_fast(
        &self,
        size: u64,
        mask: Option<u64>,
    ) -> Result<u64, IommuError> {
        self.allocate_iova(size, mask)
    }

    /// Free an IOVA address
    pub(super) fn free_iova(&self, iova: u64, size: u64) -> Result<(), IommuError> {
        self.iova_allocator.free(iova, size)
    }

    /// Fast path IOVA free (4KB pages)
    ///
    /// IovaAllocator already provides O(1) free with per-CPU magazine,
    /// so this just delegates to free_iova.
    pub(super) fn free_iova_fast(&self, iova: u64, size: u64) -> Result<(), IommuError> {
        self.free_iova(iova, size)
    }

    pub(crate) unsafe fn map_for_device(
        &self,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
    ) -> Result<DeviceMappedRange, DeviceMapFailure> {
        unsafe { self.map_for_device_with_perms(device, phys_addr, size, true, true) }
    }

    /// 共通: アライメント検証 + IVMDチェック + IOVA 割り当て
    fn validate_and_allocate_device_iova(
        &self,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
    ) -> Result<(u16, u64), IommuError> {
        let align = crate::mm::types::PAGE_SIZE_4K as u64;
        if size == 0 || (phys_addr.as_u64() & (align - 1) != 0) || (size & (align - 1) != 0) {
            return Err(IommuError::InvalidAlignment);
        }

        // Security: Validate that the physical range does not overlap with the kernel image.
        crate::io::iommu::runtime::security::validate_dma_region(phys_addr.as_u64(), size)?;

        let domain_id = self.domain_id_for_device(*device)?;
        self.reject_excluded_ivmd_range(*device, phys_addr.as_u64(), size)?;
        let mask = crate::io::iommu::api::get_device_dma_mask(device);
        let iova = self.allocate_iova_fast(size, mask)?;
        Ok((domain_id, iova))
    }

    pub(crate) unsafe fn map_for_device_with_perms(
        &self,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<DeviceMappedRange, DeviceMapFailure> {
        let (domain_id, iova) = self.validate_and_allocate_device_iova(device, phys_addr, size)?;
        let domain = self.domain_for_id(domain_id)?;
        if let Some(ref cq) = self.command_queue {
            let cmd = IommuCommandKind::MapRegionDevice {
                device: *device,
                iova,
                phys: phys_addr.as_u64(),
                size,
                read,
                write,
            };
            let comp = match cq.submit(cmd) {
                Ok(comp) => comp,
                Err(_) => {
                    let _ = self.free_iova_fast(iova, size);
                    return Err(self.cq_submit_error().into());
                }
            };
            let rc = comp.wait_blocking();
            let mapping = DeviceMappedRange { iova, domain };
            if rc == 0 {
                return Ok(mapping);
            }
            return Err(DeviceMapFailure::TranslationPending {
                cause: Self::cq_completion_error(rc),
                mapping,
            });
        }
        self.direct_map_device(domain, device, iova, phys_addr.as_u64(), size, read, write)
    }

    pub(crate) async unsafe fn map_for_device_with_perms_async(
        &self,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<DeviceMappedRange, DeviceMapFailure> {
        let (domain_id, iova) = self.validate_and_allocate_device_iova(device, phys_addr, size)?;
        let domain = self.domain_for_id(domain_id)?;
        if let Some(ref cq) = self.command_queue {
            let cmd = IommuCommandKind::MapRegionDevice {
                device: *device,
                iova,
                phys: phys_addr.as_u64(),
                size,
                read,
                write,
            };
            let comp = match cq.submit_async(cmd).await {
                Ok(comp) => comp,
                Err(_) => {
                    let _ = self.free_iova_fast(iova, size);
                    return Err(self.cq_submit_error().into());
                }
            };
            let rc = comp.await;
            let mapping = DeviceMappedRange { iova, domain };
            if rc == 0 {
                return Ok(mapping);
            }
            return Err(DeviceMapFailure::TranslationPending {
                cause: Self::cq_completion_error(rc),
                mapping,
            });
        }
        self.direct_map_device_async(domain, device, iova, phys_addr.as_u64(), size, read, write)
            .await
    }

    fn direct_map_device(
        &self,
        domain: alloc::sync::Arc<super::DomainState>,
        device: &DeviceId,
        iova: u64,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<DeviceMappedRange, DeviceMapFailure> {
        if let Err(cause) = domain.map(iova, phys, size, read, write) {
            if let Err(error) = self.free_iova_fast(iova, size) {
                log::error!("unpublished IOVA retirement failed: {error:?}");
            }
            return Err(cause.into());
        }
        let mapping = DeviceMappedRange { iova, domain };
        if let Err(cause) = self
            .invalidate_iommu_pages(*device, mapping.domain.id(), iova, size)
            .and_then(|_| self.invalidate_iotlb_pages(*device, iova, size))
        {
            return Err(DeviceMapFailure::TranslationPending { cause, mapping });
        }
        Ok(mapping)
    }

    async fn direct_map_device_async(
        &self,
        domain: alloc::sync::Arc<super::DomainState>,
        device: &DeviceId,
        iova: u64,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<DeviceMappedRange, DeviceMapFailure> {
        if let Err(cause) = domain.map(iova, phys, size, read, write) {
            if let Err(error) = self.free_iova_fast(iova, size) {
                log::error!("unpublished IOVA retirement failed: {error:?}");
            }
            return Err(cause.into());
        }
        let mapping = DeviceMappedRange { iova, domain };
        if let Err(cause) = self
            .invalidate_iommu_pages_async(*device, mapping.domain.id(), iova, size)
            .await
        {
            return Err(DeviceMapFailure::TranslationPending { cause, mapping });
        }
        if let Err(cause) = self.invalidate_iotlb_pages_async(*device, iova, size).await {
            return Err(DeviceMapFailure::TranslationPending { cause, mapping });
        }
        Ok(mapping)
    }

    pub(crate) async unsafe fn map_for_device_async(
        &self,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
    ) -> Result<DeviceMappedRange, DeviceMapFailure> {
        unsafe {
            self.map_for_device_with_perms_async(device, phys_addr, size, true, true)
                .await
        }
    }

}
