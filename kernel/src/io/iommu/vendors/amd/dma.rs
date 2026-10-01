// ============================================================================
// kernel/src/io/iommu/vendors/amd/dma.rs
// ============================================================================

//! AMD-Vi DMA mapping, IOVA allocation, and command queue dispatch.

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
                    return Err(self.cq_submit_error());
                }
            };
            let rc = comp.wait_blocking();
            if rc == 0 {
                return Ok(iova);
            }
            return Err(Self::cq_completion_error(rc));
        }
        self.direct_map_device(
            domain_id,
            device,
            iova,
            phys_addr.as_u64(),
            size,
            read,
            write,
        )
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
                    return Err(self.cq_submit_error());
                }
            };
            let rc = comp.await;
            if rc == 0 {
                return Ok(iova);
            }
            return Err(Self::cq_completion_error(rc));
        }
        self.direct_map_device_async(
            domain_id,
            device,
            iova,
            phys_addr.as_u64(),
            size,
            read,
            write,
        )
        .await
    }

    pub(crate) async unsafe fn map_for_device_async(
        &self,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
    ) -> Result<u64, IommuError> {
        unsafe {
            self.map_for_device_with_perms_async(device, phys_addr, size, true, true)
                .await
        }
    }

    /// コマンドキュー経由で同期アンマップを実行する
    fn unmap_via_command_queue(
        &self,
        cq: &crate::io::iommu::runtime::command::queue::CommandQueue,
        device: &DeviceId,
        domain: &crate::io::iommu::common::domain::IommuDomain,
        iova: u64,
    ) -> Result<(), IommuError> {
        let mapping = domain.mapping(iova).ok_or(IommuError::NotMapped)?;
        let cmd = IommuCommandKind::UnmapRegionDevice {
            device: *device,
            iova,
            size: mapping.size,
        };
        let comp = cq.submit(cmd).map_err(|_| self.cq_submit_error())?;
        let rc = comp.wait_blocking();
        if rc == 0 {
            return Ok(());
        }
        log::error!(
            "[IOMMU][AMD-Vi] unmap_via_command_queue failed (rc={}). Poisoning domain.",
            rc
        );
        domain.poison();
        Err(Self::cq_completion_error(rc))
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

        // 1. Monitor page table releases

        let mapping = domain.unmap(iova)?;

        let pt_removed = domain
            .pending_pt_release
            .lock()
            .map(|pending| pending.has_pending())
            .unwrap_or(true);

        if pt_removed {
            // SECURITY: Domain-wide invalidation to clear paging-structure caches
            if let Err(err) = self.invalidate_domain_pages(domain_id, 0, u64::MAX) {
                log::error!(
                    "[IOMMU][AMD-Vi] unmap_for_device domain-wide invalidation failed: {:?}. Poisoning domain.",
                    err
                );
                domain.poison();
                return Err(err);
            }
        } else {
            if let Err(err) = self.invalidate_iommu_pages(*device, domain_id, iova, mapping.size) {
                log::error!(
                    "[IOMMU][AMD-Vi] unmap_for_device IOMMU invalidation failed: {:?}. Poisoning domain.",
                    err
                );
                domain.poison();
                return Err(err);
            }
        }

        if let Err(err) = self.invalidate_iotlb_pages(*device, iova, mapping.size) {
            log::error!(
                "[IOMMU][AMD-Vi] unmap_for_device IOTLB invalidation failed: {:?}. Poisoning domain.",
                err
            );
            domain.poison();
            return Err(err);
        }

        // 3. Reclaim released page tables
        if pt_removed {
            domain.flush(self, self)?;
        }

        // Rejected retirement remains allocated. Do not bypass quarantine after
        // a failed flush, nor re-free a range whose prefix may already be queued.
        self.free_iova_fast(iova, mapping.size)?;
        Ok(())
    }

    /// コマンドキュー経由で非同期アンマップを実行する
    async fn unmap_via_command_queue_async(
        &self,
        cq: &crate::io::iommu::runtime::command::queue::CommandQueue,
        device: &DeviceId,
        domain: &crate::io::iommu::common::domain::IommuDomain,
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
            .map_err(|_| self.cq_submit_error())?;
        let rc = comp.await;
        if rc == 0 {
            return Ok(());
        }
        log::error!(
            "[IOMMU][AMD-Vi] unmap_via_command_queue_async failed (rc={}). Poisoning domain.",
            rc
        );
        domain.poison();
        Err(Self::cq_completion_error(rc))
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
            return self
                .unmap_via_command_queue_async(cq, device, &domain, iova)
                .await;
        }

        // 1. Monitor page table releases

        let mapping = domain.unmap(iova)?;

        let pt_removed = domain
            .pending_pt_release
            .lock()
            .map(|pending| pending.has_pending())
            .unwrap_or(true);

        if pt_removed {
            // SECURITY: Domain-wide invalidation (async)
            if let Err(err) = self
                .invalidate_domain_pages_async(domain_id, 0, u64::MAX)
                .await
            {
                log::error!(
                    "[IOMMU][AMD-Vi] unmap_for_device_async domain-wide invalidation failed: {:?}. Poisoning domain.",
                    err
                );
                domain.poison();
                return Err(err);
            }
        } else {
            if let Err(err) = self
                .invalidate_iommu_pages_async(*device, domain_id, iova, mapping.size)
                .await
            {
                log::error!(
                    "[IOMMU][AMD-Vi] unmap_for_device_async IOMMU invalidation failed: {:?}. Poisoning domain.",
                    err
                );
                domain.poison();
                return Err(err);
            }
        }

        if let Err(err) = self
            .invalidate_iotlb_pages_async(*device, iova, mapping.size)
            .await
        {
            log::error!(
                "[IOMMU][AMD-Vi] unmap_for_device_async IOTLB invalidation failed: {:?}. Poisoning domain.",
                err
            );
            domain.poison();
            return Err(err);
        }

        // 3. Reclaim released page tables
        if pt_removed {
            domain.flush(self, self)?;
        }

        // Failure must reach the DMA owner; no immediate-free fallback is valid.
        self.free_iova_fast(iova, mapping.size)?;
        Ok(())
    }
}
