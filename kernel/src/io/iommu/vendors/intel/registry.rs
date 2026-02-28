// ============================================================================
// kernel/src/io/iommu/backends/intel/registry.rs
// ============================================================================

//! Intel IOMMU Registry
//!
//! Manages Intel VT-d controllers and RMRR (Reserved Memory Region Reporting).

use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

use crate::io::iommu::runtime::config::IommuConfig;
pub use crate::io::iommu::runtime::config::ReservedMemoryRegion; // Will be moved? RMRR is defined in mod?
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
        for (idx, controller) in controllers.iter().enumerate() {
            controller.set_controller_idx(idx);
        }
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

/// Global Intel IOMMU Registry guarded by a spin mutex.
static IOMMU_REGISTRY: Mutex<Option<IommuRegistry>> = Mutex::new(None);

pub fn get_iommu_registry() -> Option<&'static IommuRegistry> {
    let guard = IOMMU_REGISTRY.lock();
    guard.as_ref().map(|r| unsafe { &*(r as *const IommuRegistry) })
}

pub fn init_registry(registry: IommuRegistry) {
    let mut guard = IOMMU_REGISTRY.lock();
    if guard.is_some() {
        panic!("IOMMU registry already initialized");
    }
    *guard = Some(registry);
}
