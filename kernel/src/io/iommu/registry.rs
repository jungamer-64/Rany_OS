//! IOMMU Registry and Global State
//!
//! This module contains the global IOMMU registry which manages controller
//! instances and provides lookup functions for device-to-controller mapping.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::interface::IommuDriver;
use super::{IommuConfig, IommuController, ReservedMemoryRegion};

// ============================================================================
// IOMMU Registry
// ============================================================================

/// IOMMU Registry (Immutable container after initialization)
///
/// The registry holds references to all IOMMU controllers and provides
/// lookup methods to find the appropriate controller for a given device.
pub struct IommuRegistry {
    /// List of IOMMU controllers (Arc for shared access, fine-grained locking internally)
    pub controllers: Vec<Arc<IommuController>>,
    /// Default IOMMU index
    pub(crate) default_iommu_idx: Option<usize>,
    /// Reserved memory regions (from ACPI RMRR structures)
    pub(crate) reserved_regions: Vec<ReservedMemoryRegion>,
    /// Global Configuration
    pub config: IommuConfig,
}

unsafe impl Send for IommuRegistry {}
unsafe impl Sync for IommuRegistry {}

impl IommuRegistry {
    /// Create a new registry
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

    /// Find controller index using proper scope matching
    ///
    /// Returns the index of the controller that should handle the given device,
    /// using the following priority:
    /// 1. Controller with explicit scope match for this device
    /// 2. Controller with INCLUDE_PCI_ALL for this segment
    /// 3. Default controller (fallback)
    pub fn find_controller_index_for_device(
        &self,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
    ) -> Option<usize> {
        // First pass: Find controller with explicit scope match
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

        // Second pass: Find include_all controller for this segment
        for (i, controller) in self.controllers.iter().enumerate() {
            if controller.segment == segment && controller.include_all {
                return Some(i);
            }
        }

        // Fallback to default
        self.default_iommu_idx
    }

    /// Get the default controller
    pub fn default_controller(&self) -> Option<&Arc<IommuController>> {
        self.default_iommu_idx
            .and_then(|idx| self.controllers.get(idx))
    }

    /// Get reserved memory regions
    pub fn reserved_regions(&self) -> &[ReservedMemoryRegion] {
        &self.reserved_regions
    }

    /// Get controller by index
    pub fn controller(&self, index: usize) -> Option<&Arc<IommuController>> {
        self.controllers.get(index)
    }

    /// Number of controllers
    pub fn controller_count(&self) -> usize {
        self.controllers.len()
    }
}

// ============================================================================
// Global Registry Static
// ============================================================================

/// Global IOMMU Registry (initialized once during boot)
static IOMMU_REGISTRY: spin::Once<IommuRegistry> = spin::Once::new();

/// Global IOMMU Driver (backend abstraction, initialized once during boot)
static IOMMU_DRIVER: spin::Once<Arc<dyn IommuDriver>> = spin::Once::new();

/// Get reference to the IOMMU registry
pub fn get_iommu_registry() -> Option<&'static IommuRegistry> {
    IOMMU_REGISTRY.get()
}

/// Get reference to the registered IOMMU driver (backend abstraction)
pub fn get_iommu_driver() -> Option<&'static Arc<dyn IommuDriver>> {
    IOMMU_DRIVER.get()
}

/// Check if IOMMU is enabled (driver registered and backend available)
pub fn is_iommu_enabled() -> bool {
    IOMMU_DRIVER.get().map_or(false, |d| d.is_enabled())
}

/// Initialize the global registry (call once during boot)
///
/// # Panics
/// Panics if called more than once.
pub fn init_registry(registry: IommuRegistry) {
    IOMMU_REGISTRY.call_once(|| registry);
}

/// Initialize the global driver (call once during boot)
///
/// # Panics
/// Panics if called more than once.
pub fn init_driver(driver: Arc<dyn IommuDriver>) {
    IOMMU_DRIVER.call_once(|| driver);
}

/// Get the registry, calling `init_once` for late initialization if needed
#[allow(dead_code)]
pub(crate) fn get_or_init_registry<F>(init_once: F) -> &'static IommuRegistry
where
    F: FnOnce() -> IommuRegistry,
{
    IOMMU_REGISTRY.call_once(init_once)
}
