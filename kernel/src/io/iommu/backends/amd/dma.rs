// ============================================================================
// kernel/src/io/iommu/amd/dma.rs
// ============================================================================

//! AMD-Vi DMA mapping, IOVA allocation, and command queue dispatch.

use x86_64::PhysAddr;

use crate::io::iommu::runtime::command::queue::IommuCommandKind;
use crate::io::iommu::types::{DeviceId, IommuError};
use crate::io::iommu::core::dma::iova_allocator::{PageGranularity, IovaGranularity};

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
            Some(limit) => self.iova_allocator.allocate_with_limit(size, PageGranularity::Page4K, limit),
            None => self.iova_allocator.allocate(size, PageGranularity::Page4K),
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

    /// Validate that physical address and size are 4K-page aligned and non-zero.
    fn validate_dma_alignment(phys_addr: PhysAddr, size: u64) -> Result<(), IommuError> {
        let align = crate::mm::types::PAGE_SIZE_4K as u64;
        if size == 0 || (phys_addr.as_u64() & (align - 1) != 0) || (size & (align - 1) != 0) {
            return Err(IommuError::InvalidAlignment);
        }
        Ok(())
    }

    pub(crate) unsafe fn map_for_dma_with_perms(
        &self,
        phys_addr: PhysAddr,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<u64, IommuError> {
        Self::validate_dma_alignment(phys_addr, size)?;

        // Security: Validate that the physical range does not overlap with the kernel image.
        crate::io::iommu::runtime::security::validate_dma_region(phys_addr.as_u64(), size)?;

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
        
        // Invalidate domain pages across all units
        if let Err(err) = self.invalidate_domain_pages(0, iova, mapped_size) {
            if err != IommuError::NotSupported {
                return Err(err);
            }
        }

        // Free IOVA back to allocator. 
        // Note: invalidate_domain_pages already advanced and completed the epoch.
        if let Err(IommuError::OutOfMemory) = self.free_iova_fast(iova, mapped_size) {
            // Quarantine still full or per-CPU magazine full: 
            // Force global invalidation and retry.
            log::warn!("[IOMMU][AMD-Vi] IOVA quarantine full in unmap_dma, forcing global flush");
            let _ = self.invalidate_all_entries();
            let _ = self.free_iova(iova, mapped_size);
        }
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
    ) -> Result<u64, IommuError> {
        let (domain_id, iova) = self.validate_and_allocate_device_iova(device, phys_addr, size)?;
        if let Some(ref cq) = self.command_queue {
            let cmd = IommuCommandKind::MapRegionDevice {
                device: *device, iova, phys: phys_addr.as_u64(), size, read, write,
            };
            let comp = match cq.submit(cmd) {
                Ok(comp) => comp,
                Err(_) => {
                    let _ = self.free_iova_fast(iova, size);
                    return Err(IommuError::HardwareError);
                }
            };
            let rc = comp.wait_blocking();
            if rc == 0 { return Ok(iova); }
            return Err(IommuError::HardwareError);
        }
        self.direct_map_device(domain_id, device, iova, phys_addr.as_u64(), size, read, write)
    }

    /// コマンドキューなしでの直接 DMA マッピング (同期)
    fn direct_map_device(
        &self,
        domain_id: u16,
        device: &DeviceId,
        iova: u64,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<u64, IommuError> {
        let domain = self.domain_for_id(domain_id)?;
        if let Err(err) = domain.map(iova, phys, size, read, write) {
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
        let (domain_id, iova) = self.validate_and_allocate_device_iova(device, phys_addr, size)?;
        if let Some(ref cq) = self.command_queue {
            let cmd = IommuCommandKind::MapRegionDevice {
                device: *device, iova, phys: phys_addr.as_u64(), size, read, write,
            };
            let comp = match cq.submit_async(cmd).await {
                Ok(comp) => comp,
                Err(_) => {
                    let _ = self.free_iova_fast(iova, size);
                    return Err(IommuError::HardwareError);
                }
            };
            let rc = comp.await;
            if rc == 0 { return Ok(iova); }
            return Err(IommuError::HardwareError);
        }
        self.direct_map_device_async(domain_id, device, iova, phys_addr.as_u64(), size, read, write).await
    }

    /// コマンドキューなしでの直接 DMA マッピング (非同期)
    async fn direct_map_device_async(
        &self,
        domain_id: u16,
        device: &DeviceId,
        iova: u64,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<u64, IommuError> {
        let domain = self.domain_for_id(domain_id)?;
        if let Err(err) = domain.map(iova, phys, size, read, write) {
            let _ = self.free_iova_fast(iova, size);
            return Err(err);
        }
        self.invalidate_iommu_pages_async(*device, domain_id, iova, size).await?;
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

    /// コマンドキュー経由で同期アンマップを実行する
    fn unmap_via_command_queue(
        &self,
        cq: &crate::io::iommu::runtime::command::queue::CommandQueue,
        device: &DeviceId,
        domain: &crate::io::iommu::core::domain::IommuDomain,
        iova: u64,
    ) -> Result<(), IommuError> {
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
        Err(IommuError::HardwareError)
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
            return self.unmap_via_command_queue(cq, device, &domain, iova);
        }
        let mapping = domain.unmap(iova)?;

        self.invalidate_iommu_pages(*device, domain_id, iova, mapping.size)?;
        self.invalidate_iotlb_pages(*device, iova, mapping.size)?;
        
        if let Err(IommuError::OutOfMemory) = self.free_iova_fast(iova, mapping.size) {
            let _ = self.invalidate_all_entries();
            let _ = self.free_iova(iova, mapping.size);
        }
        Ok(())
    }

    /// コマンドキュー経由で非同期アンマップを実行する
    async fn unmap_via_command_queue_async(
        &self,
        cq: &crate::io::iommu::runtime::command::queue::CommandQueue,
        device: &DeviceId,
        domain: &crate::io::iommu::core::domain::IommuDomain,
        iova: u64,
    ) -> Result<(), IommuError> {
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
        Err(IommuError::HardwareError)
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
            return self.unmap_via_command_queue_async(cq, device, &domain, iova).await;
        }
        let mapping = domain.unmap(iova)?;

        self.invalidate_iommu_pages_async(*device, domain_id, iova, mapping.size)
            .await?;
        self.invalidate_iotlb_pages_async(*device, iova, mapping.size)
            .await?;
        
        if let Err(IommuError::OutOfMemory) = self.free_iova_fast(iova, mapping.size) {
            let _ = self.invalidate_all_entries();
            let _ = self.free_iova(iova, mapping.size);
        }
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
            } => self.handle_map_region_device(*device, *iova, *phys, *size, *read, *write),
            IommuCommandKind::UnmapRegionDevice { device, iova, size: _ } => {
                self.handle_unmap_region_device(*device, *iova)
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

    /// Validate alignment and excluded ranges for a map region request.
    /// On failure, frees the IOVA and returns Err.
    fn validate_map_region_params(
        &self,
        device: DeviceId,
        iova: u64,
        phys: u64,
        size: u64,
    ) -> Result<(), ()> {
        let align = crate::mm::types::PAGE_SIZE_4K as u64;
        if (iova & (align - 1) != 0)
            || (phys & (align - 1) != 0)
            || (size & (align - 1) != 0)
        {
            let _ = self.free_iova_fast(iova, size);
            return Err(());
        }

        // Security: Validate that the physical range does not overlap with the kernel image.
        if crate::io::iommu::runtime::security::validate_dma_region(phys, size).is_err() {
            let _ = self.free_iova_fast(iova, size);
            return Err(());
        }

        if self.reject_excluded_ivmd_range(device, phys, size).is_err() {
            let _ = self.free_iova_fast(iova, size);
            return Err(());
        }
        Ok(())
    }

    /// マップと無効化を実行する
    fn execute_map_and_invalidate(
        &self,
        device: DeviceId,
        domain_id: u16,
        iova: u64,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<i32, ()> {
        let domain = self.domain_for_id(domain_id).map_err(|_| {
            let _ = self.free_iova_fast(iova, size);
        })?;

        if let Err(err) = domain.map(iova, phys, size, read, write) {
            if err != IommuError::AlreadyMapped && err != IommuError::Poisoned {
                let _ = self.free_iova_fast(iova, size);
            }
            return Err(());
        }

        self.invalidate_iommu_pages(device, domain_id, iova, size).map_err(|_| ())?;
        self.invalidate_iotlb_pages(device, iova, size).map_err(|_| ())?;

        Ok(0)
    }

    /// Handle MapRegionDevice: validate, map, and invalidate.
    fn handle_map_region_device(
        &self,
        device: DeviceId,
        iova: u64,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<i32, ()> {
        if size == 0 {
            return Err(());
        }
        self.validate_map_region_params(device, iova, phys, size)?;

        let domain_id = self.domain_id_for_device(device).map_err(|_| {
            let _ = self.free_iova_fast(iova, size);
        })?;

        self.execute_map_and_invalidate(device, domain_id, iova, phys, size, read, write)
    }

    /// Handle UnmapRegionDevice: unmap, invalidate, and free IOVA.
    fn handle_unmap_region_device(
        &self,
        device: DeviceId,
        iova: u64,
    ) -> Result<i32, ()> {
        let domain_id = self.domain_id_for_device(device).map_err(|_| ())?;
        let domain = self.domain_for_id(domain_id).map_err(|_| ())?;
        let mapping = domain.unmap(iova).map_err(|_| ())?;

        self.invalidate_iommu_pages(device, domain_id, iova, mapping.size).map_err(|_| ())?;
        self.invalidate_iotlb_pages(device, iova, mapping.size).map_err(|_| ())?;
        let _ = self.free_iova_fast(iova, mapping.size);
        Ok(0)
    }
}
