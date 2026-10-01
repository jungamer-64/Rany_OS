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

use crate::io::iommu::runtime::command::queue::{IommuCommandKind, RESULT_POISONED};
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

#[inline]
fn controller_cq_submit_error(controller: &controller::IommuController) -> IommuError {
    match controller.command_queue_ref() {
        Some(cq) if cq.is_poisoned() => IommuError::Poisoned,
        _ => IommuError::HardwareError,
    }
}

#[inline]
fn controller_cq_completion_error(rc: i32) -> IommuError {
    if rc == RESULT_POISONED {
        IommuError::Poisoned
    } else {
        IommuError::HardwareError
    }
}

fn allocate_iova_for_device(
    controller: &Arc<controller::IommuController>,
    device: &DeviceId,
    size: u64,
) -> Result<u64, IommuError> {
    use crate::io::iommu::common::interface::IommuHardwareContext;
    let mask = crate::io::iommu::api::get_device_dma_mask(device);
    match mask {
        Some(limit) => <controller::IommuController as IommuHardwareContext>::allocate_iova_masked(
            controller, size, 4096, limit,
        ),
        None => <controller::IommuController as IommuHardwareContext>::allocate_iova_aligned(
            controller, size, 4096,
        ),
    }
}

