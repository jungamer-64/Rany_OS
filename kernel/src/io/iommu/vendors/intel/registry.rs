// ============================================================================
// kernel/src/io/iommu/vendors/intel/registry.rs
// ============================================================================

//! Intel IOMMU Registry
//!
//! Manages Intel VT-d controllers and RMRR (Reserved Memory Region Reporting).

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::controller::IommuController;
pub use crate::io::iommu::runtime::config::ReservedMemoryRegion;

/// Intel IOMMU Registry
pub struct IommuRegistry {
    /// List of IOMMU controllers
    pub controllers: Vec<Arc<IommuController>>,
    /// Reserved memory regions (ACPI RMRR)
    pub(crate) reserved_regions: Vec<ReservedMemoryRegion>,
}

impl IommuRegistry {
    pub fn find_controller_index_for_device(
        &self,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
    ) -> Option<usize> {
        for (i, controller) in self.controllers.iter().enumerate() {
            if controller.segment != segment {
                continue;
            }
            if controller.include_all {
                continue;
            }
            if controller.device_in_scope(bus, device, function) {
                return Some(i);
            }
        }

        for (i, controller) in self.controllers.iter().enumerate() {
            if controller.segment == segment && controller.include_all {
                return Some(i);
            }
        }

        None
    }

    pub fn reserved_regions(&self) -> &[ReservedMemoryRegion] {
        &self.reserved_regions
    }
}

/// Global Intel IOMMU Registry stored in a lock-free crate::sync::InitOnce.
/// Written exactly once during boot via init_registry(), then read-only.
/// This avoids deadlocks when IOMMU fault interrupts fire while
/// the boot context is reading the registry.
static IOMMU_REGISTRY: crate::sync::InitOnce<IommuRegistry> = crate::sync::InitOnce::new();

pub fn get_iommu_registry() -> Option<&'static IommuRegistry> {
    IOMMU_REGISTRY.get()
}

pub fn init_registry(
    registry: IommuRegistry,
) -> Result<&'static IommuRegistry, crate::io::iommu::types::IommuError> {
    let mut installed = false;
    let published = IOMMU_REGISTRY.call_once(|| {
        installed = true;
        registry
    });
    if installed {
        Ok(published)
    } else {
        Err(crate::io::iommu::types::IommuError::AlreadyInitialized)
    }
}
