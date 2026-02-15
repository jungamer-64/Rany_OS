// ============================================================================
// kernel/src/io/iommu/amd/dma.rs
// ============================================================================

//! AMD-Vi DMA mapping, IOVA allocation, and command queue dispatch.

use x86_64::PhysAddr;

use crate::io::iommu::cmdqueue::IommuCommandKind;
use crate::io::iommu::types::{DeviceId, IommuError};
use crate::io::iommu::IovaGranularity;

use super::AmdIommuDriver;

// ---------------------------------------------------------------------------
// DMA mapping methods on AmdIommuDriver
// ---------------------------------------------------------------------------

impl AmdIommuDriver {
    /// Allocate an IOVA address
    ///
    /// The IovaAllocatorFast is lock-free internally with per-CPU magazine caching.
    pub(super) fn allocate_iova(&self, size: u64, mask: Option<u64>) -> Result<u64, IommuError> {
        let iova = match mask {
            Some(limit) => self.iova_allocator.allocate_with_limit(size, IovaGranularity::Page4K, limit),
            None => self.iova_allocator.allocate(size, IovaGranularity::Page4K),
        };
        iova.ok_or(IommuError::OutOfMemory)
    }

    /// Fast path IOVA allocation (4KB pages)
    ///
    /// IovaAllocatorFast already provides O(1) allocation with per-CPU magazine,
    /// so this just delegates to allocate_iova.
    pub(super) fn allocate_iova_fast(&self, size: u64, mask: Option<u64>) -> Result<u64, IommuError> {
        self.allocate_iova(size, mask)
    }

    /// Free an IOVA address
    pub(super) fn free_iova(&self, iova: u64, size: u64) -> Result<(), IommuError> {
        self.iova_allocator.free(iova, size)
    }

    /// Fast path IOVA free (4KB pages)
    ///
    /// IovaAllocatorFast already provides O(1) free with per-CPU magazine,
    /// so this just delegates to free_iova.
    pub(super) fn free_iova_fast(&self, iova: u64, size: u64) -> Result<(), IommuError> {
        self.free_iova(iova, size)
    }

    pub(crate) unsafe fn map_for_dma(
        &self,
        phys_addr: PhysAddr,
        size: u64,
    ) -> Result<u64, IommuError> {
        unsafe { self.map_for_dma_with_perms(phys_addr, size, true, true) }
    }

    pub(crate) unsafe fn map_for_dma_with_perms(
        &self,
        phys_addr: PhysAddr,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<u64, IommuError> {
        let align = crate::mm::PAGE_SIZE_4K as u64;
        if size == 0 || (phys_addr.as_u64() & (align - 1) != 0) || (size & (align - 1) != 0) {
            return Err(IommuError::InvalidAlignment);
        }

        let iova = self.allocate_iova_fast(size, None)?;
        let domain = self.domain_for_id(0)?;
        if let Err(err) = domain.map(iova, phys_addr.as_u64(), size, read, write) {
            let _ = self.free_iova_fast(iova, size);
            return Err(err);
        }
        if let Err(err) = self.invalidate_domain_pages(0, iova, size) {
            if err != IommuError::NotSupported {
                return Err(err);
            }
        }
        Ok(iova)
    }

    pub(crate) fn unmap_dma(&self, iova: u64, _size: u64) -> Result<(), IommuError> {
        let domain = self.domain_for_id(0)?;
        let mapping = domain.unmap(iova)?;
        let mapped_size = mapping.size;
        if let Err(err) = self.invalidate_domain_pages(0, iova, mapped_size) {
            if err != IommuError::NotSupported {
                return Err(err);
            }
        }
        let _ = self.free_iova_fast(iova, mapped_size);
        Ok(())
    }

    pub(crate) unsafe fn map_for_device(
        &self,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
    ) -> Result<u64, IommuError> {
        unsafe { self.map_for_device_with_perms(device, phys_addr, size, true, true) }
    }

    pub(crate) unsafe fn map_for_device_with_perms(
        &self,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<u64, IommuError> {
        let align = crate::mm::PAGE_SIZE_4K as u64;
        if size == 0 || (phys_addr.as_u64() & (align - 1) != 0) || (size & (align - 1) != 0) {
            return Err(IommuError::InvalidAlignment);
        }

        let domain_id = self.domain_id_for_device(*device)?;
        self.reject_excluded_ivmd_range(*device, phys_addr.as_u64(), size)?;
        let mask = crate::io::iommu::api::get_device_dma_mask(device);
        let iova = self.allocate_iova_fast(size, mask)?;
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
                    return Err(IommuError::HardwareError);
                }
            };
            let rc = comp.wait_blocking();
            if rc == 0 {
                return Ok(iova);
            }
            return Err(IommuError::HardwareError);
        }

        let domain = self.domain_for_id(domain_id)?;

        if let Err(err) = domain.map(iova, phys_addr.as_u64(), size, read, write) {
            let _ = self.free_iova_fast(iova, size);
            return Err(err);
        }

        self.invalidate_iommu_pages(*device, domain_id, iova, size)?;
        self.invalidate_iotlb_pages(*device, iova, size)?;
        Ok(iova)
    }

    pub(crate) async unsafe fn map_for_device_with_perms_async(
        &self,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<u64, IommuError> {
        let align = crate::mm::PAGE_SIZE_4K as u64;
        if size == 0 || (phys_addr.as_u64() & (align - 1) != 0) || (size & (align - 1) != 0) {
            return Err(IommuError::InvalidAlignment);
        }

        let domain_id = self.domain_id_for_device(*device)?;
        self.reject_excluded_ivmd_range(*device, phys_addr.as_u64(), size)?;
        let mask = crate::io::iommu::api::get_device_dma_mask(device);
        let iova = self.allocate_iova_fast(size, mask)?;
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
                    return Err(IommuError::HardwareError);
                }
            };
            let rc = comp.await;
            if rc == 0 {
                return Ok(iova);
            }
            return Err(IommuError::HardwareError);
        }

        let domain = self.domain_for_id(domain_id)?;

        if let Err(err) = domain.map(iova, phys_addr.as_u64(), size, read, write) {
            let _ = self.free_iova_fast(iova, size);
            return Err(err);
        }

        self.invalidate_iommu_pages_async(*device, domain_id, iova, size)
            .await?;
        self.invalidate_iotlb_pages_async(*device, iova, size).await?;
        Ok(iova)
    }

    pub(crate) async unsafe fn map_for_device_async(
        &self,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
    ) -> Result<u64, IommuError> {
        unsafe { self.map_for_device_with_perms_async(device, phys_addr, size, true, true).await }
    }

    pub(crate) fn unmap_for_device(
        &self,
        device: &DeviceId,
        iova: u64,
        _size: u64,
    ) -> Result<(), IommuError> {
        let domain_id = self.domain_id_for_device(*device)?;
        let domain = self.domain_for_id(domain_id)?;
        if let Some(ref cq) = self.command_queue {
            let mapping = domain.mapping(iova).ok_or(IommuError::NotMapped)?;
            let cmd = IommuCommandKind::UnmapRegionDevice {
                device: *device,
                iova,
                size: mapping.size,
            };
            let comp = cq
                .submit(cmd)
                .map_err(|_| IommuError::HardwareError)?;
            let rc = comp.wait_blocking();
            if rc == 0 {
                return Ok(());
            }
            return Err(IommuError::HardwareError);
        }
        let mapping = domain.unmap(iova)?;

        self.invalidate_iommu_pages(*device, domain_id, iova, mapping.size)?;
        self.invalidate_iotlb_pages(*device, iova, mapping.size)?;
        let _ = self.free_iova_fast(iova, mapping.size);
        Ok(())
    }

    pub(crate) async fn unmap_for_device_async(
        &self,
        device: &DeviceId,
        iova: u64,
        _size: u64,
    ) -> Result<(), IommuError> {
        let domain_id = self.domain_id_for_device(*device)?;
        let domain = self.domain_for_id(domain_id)?;
        if let Some(ref cq) = self.command_queue {
            let mapping = domain.mapping(iova).ok_or(IommuError::NotMapped)?;
            let cmd = IommuCommandKind::UnmapRegionDevice {
                device: *device,
                iova,
                size: mapping.size,
            };
            let comp = cq
                .submit_async(cmd)
                .await
                .map_err(|_| IommuError::HardwareError)?;
            let rc = comp.await;
            if rc == 0 {
                return Ok(());
            }
            return Err(IommuError::HardwareError);
        }
        let mapping = domain.unmap(iova)?;

        self.invalidate_iommu_pages_async(*device, domain_id, iova, mapping.size)
            .await?;
        self.invalidate_iotlb_pages_async(*device, iova, mapping.size)
            .await?;
        let _ = self.free_iova_fast(iova, mapping.size);
        Ok(())
    }

    pub(crate) fn handle_command_queue_entry(&self, kind: &IommuCommandKind) -> Result<i32, ()> {
        match kind {
            IommuCommandKind::MapRegionDevice {
                device,
                iova,
                phys,
                size,
                read,
                write,
            } => {
                let size = *size;
                if size == 0 {
                    return Err(());
                }
                let align = crate::mm::PAGE_SIZE_4K as u64;
                if (iova & (align - 1) != 0)
                    || (phys & (align - 1) != 0)
                    || (size & (align - 1) != 0)
                {
                    let _ = self.free_iova_fast(*iova, size);
                    return Err(());
                }

                if self
                    .reject_excluded_ivmd_range(*device, *phys, size)
                    .is_err()
                {
                    let _ = self.free_iova_fast(*iova, size);
                    return Err(());
                }

                let domain_id = match self.domain_id_for_device(*device) {
                    Ok(domain_id) => domain_id,
                    Err(_) => {
                        let _ = self.free_iova_fast(*iova, size);
                        return Err(());
                    }
                };

                let domain = match self.domain_for_id(domain_id) {
                    Ok(domain) => domain,
                    Err(_) => {
                        let _ = self.free_iova_fast(*iova, size);
                        return Err(());
                    }
                };

                match domain.map(*iova, *phys, size, *read, *write) {
                    Ok(()) => {}
                    Err(err) => {
                        if err != IommuError::AlreadyMapped && err != IommuError::Poisoned {
                            let _ = self.free_iova_fast(*iova, size);
                        }
                        return Err(());
                    }
                }

                if self
                    .invalidate_iommu_pages(*device, domain_id, *iova, size)
                    .is_err()
                {
                    return Err(());
                }
                if self.invalidate_iotlb_pages(*device, *iova, size).is_err() {
                    return Err(());
                }

                Ok(0)
            }
            IommuCommandKind::UnmapRegionDevice { device, iova, size: _ } => {
                let domain_id = match self.domain_id_for_device(*device) {
                    Ok(domain_id) => domain_id,
                    Err(_) => return Err(()),
                };
                let domain = match self.domain_for_id(domain_id) {
                    Ok(domain) => domain,
                    Err(_) => return Err(()),
                };
                let mapping = match domain.unmap(*iova) {
                    Ok(mapping) => mapping,
                    Err(_) => return Err(()),
                };

                if self
                    .invalidate_iommu_pages(*device, domain_id, *iova, mapping.size)
                    .is_err()
                {
                    return Err(());
                }
                if self
                    .invalidate_iotlb_pages(*device, *iova, mapping.size)
                    .is_err()
                {
                    return Err(());
                }
                let _ = self.free_iova_fast(*iova, mapping.size);
                Ok(0)
            }
            IommuCommandKind::InvalidateIotlbGlobal => {
                if self.invalidate_all_entries().is_ok() {
                    Ok(0)
                } else {
                    Err(())
                }
            }
            IommuCommandKind::InvalidateIotlbDomain { .. } => Err(()),
            IommuCommandKind::MapRegion { .. } => Err(()),
            IommuCommandKind::UnmapRegion { .. } => Err(()),
        }
    }
}
