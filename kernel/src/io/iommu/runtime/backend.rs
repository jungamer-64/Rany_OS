// ============================================================================
// kernel/src/io/iommu/runtime/backend.rs
// ============================================================================

//! IOMMU backend enum dispatch (static, zero-allocation).

use alloc::sync::Arc;
use x86_64::PhysAddr;

use crate::io::iommu::vendors::amd::AmdIommuDriver;
use crate::io::iommu::common::domain::IommuDomain;
use crate::io::iommu::vendors::intel::IntelIommuDriver;
use super::security::SecurityNotifier;
use crate::io::iommu::types::{DeviceId, IommuDomainType, IommuError};

/// IOMMU backend implementation selected at init time.
pub enum IommuBackend {
    Intel(IntelIommuDriver),
    Amd(AmdIommuDriver),
}

impl IommuBackend {
    pub fn is_enabled(&self) -> bool {
        match self {
            Self::Intel(driver) => driver.is_enabled(),
            Self::Amd(driver) => driver.is_enabled(),
        }
    }

    pub fn enable(&self) -> Result<(), IommuError> {
        match self {
            Self::Intel(driver) => driver.enable(),
            Self::Amd(driver) => driver.enable(),
        }
    }

    pub fn disable(&self) -> Result<(), IommuError> {
        match self {
            Self::Intel(driver) => driver.disable(),
            Self::Amd(driver) => driver.disable(),
        }
    }

    pub fn handle_fault(&self) {
        match self {
            Self::Intel(driver) => driver.handle_fault(),
            Self::Amd(driver) => driver.handle_fault(),
        }
    }

    pub fn wake_invalidation_waiters(&self) {
        match self {
            Self::Intel(driver) => driver.wake_invalidation_waiters(),
            Self::Amd(driver) => driver.wake_invalidation_waiters(),
        }
    }

    pub fn set_security_notifier(&self, notifier: Arc<dyn SecurityNotifier>) -> bool {
        match self {
            Self::Intel(driver) => driver.set_security_notifier(notifier),
            Self::Amd(driver) => driver.set_security_notifier(notifier),
        }
    }

    pub fn map_interrupt(
        &self,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        vector: u8,
        dest_id: u32,
        logical: bool,
    ) -> Result<u16, IommuError> {
        match self {
            Self::Intel(driver) => driver.map_interrupt(
                segment, bus, device, function, vector, dest_id, logical,
            ),
            Self::Amd(driver) => driver.map_interrupt(
                segment, bus, device, function, vector, dest_id, logical,
            ),
        }
    }

    pub fn get_remap_msi_message(&self, handle: u16) -> (u64, u32) {
        match self {
            Self::Intel(driver) => driver.get_remap_msi_message(handle),
            Self::Amd(driver) => driver.get_remap_msi_message(handle),
        }
    }

    /// # Safety
    /// Caller must uphold DMA safety invariants for the backing memory.
    pub unsafe fn map_for_dma(&self, phys_addr: PhysAddr, size: u64) -> Result<u64, IommuError> {
        match self {
            Self::Intel(driver) => unsafe { driver.map_for_dma(phys_addr, size) },
            Self::Amd(driver) => unsafe { driver.map_for_dma(phys_addr, size) },
        }
    }

    /// # Safety
    /// Caller must uphold DMA safety invariants for the backing memory.
    pub unsafe fn map_for_dma_with_perms(
        &self,
        phys_addr: PhysAddr,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<u64, IommuError> {
        match self {
            Self::Intel(driver) => unsafe { driver.map_for_dma_with_perms(phys_addr, size, read, write) },
            Self::Amd(driver) => unsafe { driver.map_for_dma_with_perms(phys_addr, size, read, write) },
        }
    }

    pub fn unmap_dma(&self, iova: u64, size: u64) -> Result<(), IommuError> {
        match self {
            Self::Intel(driver) => driver.unmap_dma(iova, size),
            Self::Amd(driver) => driver.unmap_dma(iova, size),
        }
    }

    /// # Safety
    /// Caller must uphold DMA safety invariants for the backing memory.
    pub unsafe fn map_for_device(
        &self,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
    ) -> Result<u64, IommuError> {
        match self {
            Self::Intel(driver) => unsafe { driver.map_for_device(device, phys_addr, size) },
            Self::Amd(driver) => unsafe { driver.map_for_device(device, phys_addr, size) },
        }
    }

    /// # Safety
    /// Caller must uphold DMA safety invariants for the backing memory.
    pub unsafe fn map_for_device_with_perms(
        &self,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<u64, IommuError> {
        match self {
            Self::Intel(driver) => unsafe {
                driver.map_for_device_with_perms(device, phys_addr, size, read, write)
            },
            Self::Amd(driver) => unsafe {
                driver.map_for_device_with_perms(device, phys_addr, size, read, write)
            },
        }
    }

    /// # Safety
    /// Caller must uphold DMA safety invariants for the backing memory.
    pub async unsafe fn map_for_device_async(
        &self,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
    ) -> Result<u64, IommuError> {
        match self {
            Self::Intel(driver) => unsafe { driver.map_for_device_async(device, phys_addr, size) }
                .await,
            Self::Amd(driver) => unsafe { driver.map_for_device_async(device, phys_addr, size) }
                .await,
        }
    }

    pub fn unmap_for_device(
        &self,
        device: &DeviceId,
        iova: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        match self {
            Self::Intel(driver) => driver.unmap_for_device(device, iova, size),
            Self::Amd(driver) => driver.unmap_for_device(device, iova, size),
        }
    }

    pub async fn unmap_for_device_async(
        &self,
        device: &DeviceId,
        iova: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        match self {
            Self::Intel(driver) => driver.unmap_for_device_async(device, iova, size).await,
            Self::Amd(driver) => driver.unmap_for_device_async(device, iova, size).await,
        }
    }

    pub fn domain_id_for_device(&self, device: &DeviceId) -> Result<u16, IommuError> {
        match self {
            Self::Intel(driver) => driver.domain_id_for_device(device),
            Self::Amd(driver) => driver.domain_id_for_device(*device),
        }
    }

    pub fn create_domain(
        &self,
        numa_node: Option<usize>,
        domain_type: IommuDomainType,
    ) -> Result<u16, IommuError> {
        match self {
            Self::Intel(driver) => driver.create_domain(numa_node, domain_type),
            Self::Amd(driver) => driver.create_domain(numa_node, domain_type),
        }
    }

    pub fn attach_device(&self, device: DeviceId, domain_id: u16) -> Result<(), IommuError> {
        match self {
            Self::Intel(driver) => driver.attach_device(device, domain_id),
            Self::Amd(driver) => driver.attach_device(device, domain_id),
        }
    }

    pub fn detach_device(&self, device: DeviceId) -> Result<(), IommuError> {
        match self {
            Self::Intel(driver) => driver.detach_device(device),
            Self::Amd(driver) => driver.detach_device(device),
        }
    }

    pub fn destroy_domain(&self, domain_id: u16) -> Result<(), IommuError> {
        match self {
            Self::Intel(driver) => driver.destroy_domain(domain_id),
            Self::Amd(driver) => driver.destroy_domain(domain_id),
        }
    }

    pub fn set_domain_numa(
        &self,
        domain_id: u16,
        numa_node: Option<usize>,
    ) -> Result<(), IommuError> {
        match self {
            Self::Intel(driver) => driver.set_domain_numa(domain_id, numa_node),
            Self::Amd(driver) => driver.set_domain_numa(domain_id, numa_node),
        }
    }

    pub fn get_domain_numa(&self, domain_id: u16) -> Result<Option<usize>, IommuError> {
        match self {
            Self::Intel(driver) => driver.get_domain_numa(domain_id),
            Self::Amd(driver) => driver.get_domain_numa(domain_id),
        }
    }

    /// Get domain by ID
    pub fn get_domain(&self, domain_id: u16) -> Result<Arc<IommuDomain>, IommuError> {
        match self {
            Self::Intel(driver) => driver.get_domain(domain_id),
            Self::Amd(driver) => driver.get_domain(domain_id),
        }
    }

    pub fn dump_diagnostics(&self) {
        match self {
            Self::Intel(driver) => driver.dump_diagnostics(),
            Self::Amd(driver) => driver.dump_diagnostics(),
        }
    }

    // ========================================================================
    // Flush Operations (for emergency isolation)
    // ========================================================================

    /// Invalidate IOTLB entries for a specific domain.
    ///
    /// If `iova` is `Some`, invalidates only that page; otherwise domain-wide.
    pub fn invalidate_iotlb(
        &self,
        domain_id: u16,
        iova: Option<u64>,
        any_ats: bool,
    ) -> Result<(), IommuError> {
        match self {
            Self::Intel(driver) => driver.invalidate_iotlb(domain_id, iova, any_ats),
            Self::Amd(driver) => driver.invalidate_iotlb(domain_id, iova, any_ats),
        }
    }

    /// Invalidate all IOTLB entries globally.
    pub fn invalidate_iotlb_global(&self) -> Result<(), IommuError> {
        match self {
            Self::Intel(driver) => driver.invalidate_iotlb_global(),
            Self::Amd(driver) => driver.invalidate_iotlb_global(),
        }
    }

    /// Invalidate context cache globally.
    pub fn invalidate_context_global(&self) -> Result<(), IommuError> {
        match self {
            Self::Intel(driver) => driver.invalidate_context_global(),
            Self::Amd(driver) => driver.invalidate_context_global(),
        }
    }

    /// Lookup the domain ID for a device.
    ///
    /// Returns `None` if the device is not assigned to any domain.
    pub fn lookup_device_domain(&self, source_id: u16) -> Option<u16> {
        match self {
            Self::Intel(driver) => driver.lookup_device_domain(source_id),
            Self::Amd(driver) => driver.lookup_device_domain(source_id),
        }
    }

    /// Isolate a device from accessing any more memory via DMA.
    ///
    /// This should be called when a device is detected to be malicious or
    /// malfunctioning.
    pub fn isolate_device(&self, device: DeviceId) -> Result<(), IommuError> {
        match self {
            Self::Intel(driver) => driver.isolate_device(device),
            Self::Amd(driver) => driver.isolate_device(device),
        }
    }
}
