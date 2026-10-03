// ============================================================================
// kernel/src/io/iommu/vendors/amd/dma.rs
// ============================================================================

//! AMD-Vi DMA mapping, IOVA allocation, and command queue dispatch.

use crate::io::iommu::common::dma::mapping_outcome::{DeviceMapFailure, DeviceMappedRange};
use x86_64::PhysAddr;

use crate::io::iommu::common::dma::iova_allocator::PageGranularity;
use crate::io::iommu::types::{DeviceId, IommuError};

use super::AmdIommuDriver;

// ---------------------------------------------------------------------------
// DMA mapping methods on AmdIommuDriver
// ---------------------------------------------------------------------------

impl AmdIommuDriver {
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

    fn prepare_device_mapping(
        self: &alloc::sync::Arc<Self>,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<DeviceMappedRange, DeviceMapFailure> {
        let align = crate::mm::types::PAGE_SIZE_4K as u64;
        if size == 0 || (phys_addr.as_u64() | size) & (align - 1) != 0 {
            return Err(IommuError::InvalidAlignment.into());
        }
        crate::io::iommu::runtime::security::validate_dma_region(phys_addr.as_u64(), size)?;
        self.reject_excluded_ivmd_range(*device, phys_addr.as_u64(), size)?;
        let domain = self.domain_for_id(self.domain_id_for_device(*device)?)?;
        let mask = crate::io::iommu::api::get_device_dma_mask(device);
        let iova = self.allocate_iova_fast(size, mask)?;
        let mapping = DeviceMappedRange::admitted(
            alloc::sync::Arc::clone(&domain),
            crate::io::iommu::common::dma::mapping_outcome::DmaInvalidationSource::Amd(
                alloc::sync::Arc::clone(self),
            ),
            alloc::sync::Arc::clone(&self.iova_allocator),
            iova,
            phys_addr.as_u64(),
            size,
        );
        if let Err(cause) = domain.map(iova, phys_addr.as_u64(), size, read, write) {
            mapping.reject_unpublished();
            return Err(cause.into());
        }
        Ok(mapping)
    }
    pub(crate) unsafe fn map_for_device(
        self: &alloc::sync::Arc<Self>,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
    ) -> Result<DeviceMappedRange, DeviceMapFailure> {
        unsafe { self.map_for_device_with_perms(device, phys_addr, size, true, true) }
    }
    pub(crate) unsafe fn map_for_device_with_perms(
        self: &alloc::sync::Arc<Self>,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<DeviceMappedRange, DeviceMapFailure> {
        let mapping = self.prepare_device_mapping(device, phys_addr, size, read, write)?;
        if let Err(cause) = mapping.synchronize_map() {
            return Err(DeviceMapFailure::TranslationPending { cause, mapping });
        }
        Ok(mapping)
    }
    pub(crate) async unsafe fn map_for_device_with_perms_async(
        self: &alloc::sync::Arc<Self>,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<DeviceMappedRange, DeviceMapFailure> {
        let mapping = self.prepare_device_mapping(device, phys_addr, size, read, write)?;
        if let Err(cause) = mapping.synchronize_map_async().await {
            return Err(DeviceMapFailure::TranslationPending { cause, mapping });
        }
        Ok(mapping)
    }
    pub(crate) async unsafe fn map_for_device_async(
        self: &alloc::sync::Arc<Self>,
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
