// ============================================================================
// kernel/src/io/iommu/vendors/intel/mod.rs
// ============================================================================

//! Intel VT-d backend driver (adapter over existing implementation).

use alloc::sync::Arc;

use x86_64::PhysAddr;

// Declaring submodules moved here
pub mod controller;
pub mod driver;
pub mod qi;
pub mod registers;
pub mod registry; // Intel-specific registry
pub mod tables;

use self::controller::dma::DomainManager;
use self::controller::fault::FaultHandler;
use self::controller::iova::IovaManager;
use self::controller::ir::InterruptRemapper;
use self::controller::qi_ops::InvalidationOps;

use crate::io::iommu::common::domain::IommuDomain;
use crate::io::iommu::runtime::backend::IommuBackend;
// Generic registry for registering the driver
use crate::io::iommu::runtime::registry::init_driver;
use crate::io::iommu::runtime::security::SecurityNotifier;

use crate::io::iommu::common::dma::mapping_outcome::{DeviceMapFailure, DeviceMappedRange};
use crate::io::iommu::types::{DeviceId, IommuDomainType, IommuError};

// Intel-specific registry access
use self::registry::get_iommu_registry;

mod diagnostics;
/// Intel VT-d driver wrapper.
mod driver_ops;

#[derive(Default, Clone)]
pub struct IntelIommuDriver {
    /// Optional specific controller (used for tests/mocking)
    controller: Option<Arc<controller::IommuController>>,
}

impl IntelIommuDriver {
    pub fn new() -> Self {
        Self { controller: None }
    }

    pub fn with_controller(controller: Arc<controller::IommuController>) -> Self {
        Self {
            controller: Some(controller),
        }
    }

    pub fn register_driver() {
        // Always register the global driver pointer.
        // Previously this checked !is_iommu_enabled(), but that function
        // already returns true via the Intel registry fallback path,
        // causing IOMMU_DRIVER to never be initialized. This broke
        // handle_fault(), map_for_device(), and other driver-dependent paths.
        init_driver(Arc::new(IommuBackend::Intel(IntelIommuDriver::new())));
    }

    fn registry(&self) -> Result<&'static self::registry::IommuRegistry, IommuError> {
        get_iommu_registry().ok_or(IommuError::NotInitialized)
    }
}

// ---------------------------------------------------------------------------
// DMA mapping helpers (shared by sync and async paths)
// ---------------------------------------------------------------------------

fn validate_dma_params(phys_addr: PhysAddr, size: u64) -> Result<(), IommuError> {
    let align = crate::mm::types::PAGE_SIZE_4K as u64;
    if size == 0 || (phys_addr.as_u64() & (align - 1) != 0) || (size & (align - 1) != 0) {
        return Err(IommuError::InvalidAlignment);
    }

    // Security: Validate that the physical range does not overlap with the kernel image.
    crate::io::iommu::runtime::security::validate_dma_region(phys_addr.as_u64(), size)?;

    Ok(())
}

fn admit_mapping(
    controller: &Arc<controller::IommuController>,
    domain: &Arc<IommuDomain>,
    device: &DeviceId,
    phys: u64,
    size: u64,
) -> Result<DeviceMappedRange, IommuError> {
    let allocator = controller
        .iova_allocator
        .lock()
        .map_err(|_| IommuError::Poisoned)?
        .as_ref()
        .cloned()
        .ok_or(IommuError::NotInitialized)?;
    // Capture the exact return authority before allocating. No fallible
    // configuration lookup can strand a reservation after this point.
    let domain = Arc::clone(domain);
    let source = crate::io::iommu::common::dma::mapping_outcome::DmaInvalidationSource::Intel(
        Arc::clone(controller),
    );
    let iova = match crate::io::iommu::api::get_device_dma_mask(device) {
        Some(mask) => allocator.allocate_with_limit(
            size,
            crate::io::iommu::common::dma::iova_allocator::PageGranularity::Page4K,
            mask,
        ),
        None => allocator.allocate_contiguous(size, crate::mm::types::PAGE_SIZE_4K as u64),
    }
    .ok_or(IommuError::OutOfIova)?;
    Ok(DeviceMappedRange::admitted(
        domain, source, allocator, iova, phys, size,
    ))
}
unsafe fn apply_mapping_sync(
    controller: &Arc<controller::IommuController>,
    domain: &Arc<IommuDomain>,
    device: &DeviceId,
    phys: u64,
    size: u64,
    read: bool,
    write: bool,
) -> Result<DeviceMappedRange, DeviceMapFailure> {
    let mapping = admit_mapping(controller, domain, device, phys, size)?;
    let iova = mapping.iova();
    if let Err(cause) = domain.map(iova, phys, size, read, write) {
        mapping.reject_unpublished();
        return Err(cause.into());
    }
    if let Err(cause) = mapping.synchronize_map() {
        return Err(DeviceMapFailure::TranslationPending { cause, mapping });
    }
    Ok(mapping)
}
async unsafe fn apply_mapping_async(
    controller: &Arc<controller::IommuController>,
    domain: &Arc<IommuDomain>,
    device: &DeviceId,
    phys: u64,
    size: u64,
) -> Result<DeviceMappedRange, DeviceMapFailure> {
    // Metadata and leaf publication finish before awaiting hardware completion.
    // The future retains the domain and reservation through cancellation.
    let mapping = admit_mapping(controller, domain, device, phys, size)?;
    let iova = mapping.iova();
    if let Err(cause) = domain.map(iova, phys, size, true, true) {
        mapping.reject_unpublished();
        return Err(cause.into());
    }
    if let Err(cause) = mapping.synchronize_map_async().await {
        return Err(DeviceMapFailure::TranslationPending { cause, mapping });
    }
    Ok(mapping)
}
