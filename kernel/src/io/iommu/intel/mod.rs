// ============================================================================
// kernel/src/io/iommu/intel/mod.rs
// ============================================================================

//! Intel VT-d backend driver (adapter over existing implementation).

use alloc::sync::Arc;

use x86_64::PhysAddr;

// Declaring submodules moved here
pub mod controller;
pub mod qi;
pub mod registers;
pub mod registry; // Intel-specific registry
pub mod tables;
pub mod driver;

use self::controller::dma::DomainManager;
use self::controller::fault::FaultHandler;
use self::controller::iova::IovaManager;
use self::controller::ir::InterruptRemapper;
use self::controller::qi_ops::InvalidationOps;

use super::domain::IommuDomain;
use super::IommuBackend;
// Generic registry for registering the driver
use super::registry::{init_driver, is_iommu_enabled};
use super::security::SecurityNotifier;

use super::cmdqueue::IommuCommandKind;
use super::types::{DeviceId, IommuDomainType, IommuError};

// Intel-specific registry access
use self::registry::get_iommu_registry;

/// Intel VT-d driver wrapper.


mod _split_1;
use _split_1::*;
#[derive(Default)]
pub struct IntelIommuDriver;

impl IntelIommuDriver {
    pub fn new() -> Self {
        Self
    }

    pub fn register_driver() {
        if !is_iommu_enabled() {
            init_driver(Arc::new(IommuBackend::Intel(IntelIommuDriver::new())));
        }
    }

    fn registry(&self) -> Result<&'static self::registry::IommuRegistry, IommuError> {
        get_iommu_registry().ok_or(IommuError::NotInitialized)
    }
}

// ---------------------------------------------------------------------------
// DMA mapping helpers (shared by sync and async paths)
// ---------------------------------------------------------------------------

fn validate_dma_params(phys_addr: PhysAddr, size: u64) -> Result<(), IommuError> {
    let align = crate::mm::PAGE_SIZE_4K as u64;
    if size == 0 || (phys_addr.as_u64() & (align - 1) != 0) || (size & (align - 1) != 0) {
        return Err(IommuError::InvalidAlignment);
    }
    Ok(())
}

fn allocate_iova_for_device(
    controller: &Arc<controller::IommuController>,
    device: &DeviceId,
    size: u64,
) -> Result<u64, IommuError> {
    let mask = crate::io::iommu::api::get_device_dma_mask(device);
    match mask {
        Some(limit) => controller.allocate_iova_masked(size, limit),
        None if size == crate::mm::PAGE_SIZE_4K as u64 => controller.allocate_iova_fast(size),
        None => controller.allocate_iova(size),
    }
}

unsafe fn apply_mapping_sync(
    controller: &Arc<controller::IommuController>,
    domain_arc: &Arc<IommuDomain>,
    iova: u64,
    phys: u64,
    size: u64,
    read: bool,
    write: bool,
) -> Result<u64, IommuError> {
    let domain_id = domain_arc.id();
    if let Some(ref cq) = controller.command_queue {
        let cmd = IommuCommandKind::MapRegion {
            domain: domain_id,
            iova,
            phys,
            size,
            read,
            write,
        };
        if cq.submit_sync(cmd).is_err() {
            let _ = controller.free_iova(iova, size);
            return Err(IommuError::HardwareError);
        }
        return Ok(iova);
    }
    if let Err(err) = domain_arc.map(iova, phys, size, read, write) {
        let _ = controller.free_iova(iova, size);
        return Err(err);
    }
    Ok(iova)
}

async unsafe fn apply_mapping_async(
    controller: &Arc<controller::IommuController>,
    domain_arc: &Arc<IommuDomain>,
    iova: u64,
    phys: u64,
    size: u64,
) -> Result<u64, IommuError> {
    let domain_id = domain_arc.id();
    if let Some(ref cq) = controller.command_queue {
        let cmd = IommuCommandKind::MapRegion {
            domain: domain_id,
            iova,
            phys,
            size,
            read: true,
            write: true,
        };
        let comp = match cq.submit_async(cmd).await {
            Ok(comp) => comp,
            Err(_) => {
                let _ = controller.free_iova(iova, size);
                return Err(IommuError::HardwareError);
            }
        };
        let rc = comp.await;
        if rc == 0 {
            return Ok(iova);
        }
        let _ = controller.free_iova(iova, size);
        return Err(IommuError::HardwareError);
    }
    if let Err(err) = domain_arc.map(iova, phys, size, true, true) {
        let _ = controller.free_iova(iova, size);
        return Err(err);
    }
    Ok(iova)
}
