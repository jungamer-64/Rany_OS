// ============================================================================
// kernel/src/io/iommu/vendors/intel/registry.rs
// ============================================================================

//! Intel IOMMU Registry
//!
//! Manages Intel VT-d controllers and RMRR (Reserved Memory Region Reporting).

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::controller::IommuController;
pub use crate::io::iommu::runtime::config::ReservedMemoryRegion; // Will be moved? RMRR is defined in mod?

/// Intel IOMMU Registry
pub struct IommuRegistry {
    /// List of IOMMU controllers
    pub controllers: Vec<Arc<IommuController>>,
    /// Default IOMMU index
    pub(crate) default_iommu_idx: Option<usize>,
    /// Reserved memory regions (ACPI RMRR)
    pub(crate) reserved_regions: Vec<ReservedMemoryRegion>,
}

unsafe impl Send for IommuRegistry {}
unsafe impl Sync for IommuRegistry {}

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

        self.default_iommu_idx
    }

    pub fn reserved_regions(&self) -> &[ReservedMemoryRegion] {
        &self.reserved_regions
    }
}

/// Global Intel IOMMU Registry stored in a lock-free spin::Once.
/// Written exactly once during boot via init_registry(), then read-only.
/// This avoids deadlocks when IOMMU fault interrupts fire while
/// the boot context is reading the registry.
static IOMMU_REGISTRY: spin::Once<IommuRegistry> = spin::Once::new();

pub fn get_iommu_registry() -> Option<&'static IommuRegistry> {
    IOMMU_REGISTRY.get()
}

pub fn init_registry(registry: IommuRegistry) {
    IOMMU_REGISTRY.call_once(|| registry);
}
