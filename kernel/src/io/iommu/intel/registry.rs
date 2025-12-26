// ============================================================================
// kernel/src/io/iommu/intel/registry.rs
// ============================================================================

//! Intel IOMMU Registry
//!
//! Manages Intel VT-d controllers and RMRR (Reserved Memory Region Reporting).

use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Once;

use crate::io::iommu::IommuConfig;
pub use crate::io::iommu::ReservedMemoryRegion; // Will be moved? RMRR is defined in mod?
// use crate::io::iommu::IommuController; // Temporarily pointing to mod.rs, will change to super::controller::IommuController

// Needs to point to the location of IommuController.
// Since we are moving IommuController to intel/controller, we can assume it will be there.
// But for now, let's use the one in mod.rs and fix imports later, OR move IommuController simultaneously.
// Actually, if I write this file now, it won't compile until IommuController is available.

use super::controller::IommuController;

/// Intel IOMMU Registry
pub struct IommuRegistry {
    /// List of IOMMU controllers
    pub controllers: Vec<Arc<IommuController>>,
    /// Default IOMMU index
    pub(crate) default_iommu_idx: Option<usize>,
    /// Reserved memory regions (ACPI RMRR)
    pub(crate) reserved_regions: Vec<ReservedMemoryRegion>,
    /// Global Configuration
    pub config: IommuConfig,
}

unsafe impl Send for IommuRegistry {}
unsafe impl Sync for IommuRegistry {}

impl IommuRegistry {
    pub fn new(
        controllers: Vec<Arc<IommuController>>,
        reserved_regions: Vec<ReservedMemoryRegion>,
        config: IommuConfig,
    ) -> Self {
        let default_iommu_idx = if controllers.is_empty() {
            None
        } else {
            Some(0)
        };
        Self {
            controllers,
            default_iommu_idx,
            reserved_regions,
            config,
        }
    }

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

    pub fn default_controller(&self) -> Option<&Arc<IommuController>> {
        self.default_iommu_idx
            .and_then(|idx| self.controllers.get(idx))
    }

    pub fn reserved_regions(&self) -> &[ReservedMemoryRegion] {
        &self.reserved_regions
    }
}

/// Global Intel IOMMU Registry
static IOMMU_REGISTRY: Once<IommuRegistry> = Once::new();

pub fn get_iommu_registry() -> Option<&'static IommuRegistry> {
    IOMMU_REGISTRY.get()
}

pub fn init_registry(registry: IommuRegistry) {
    IOMMU_REGISTRY.call_once(|| registry);
}
