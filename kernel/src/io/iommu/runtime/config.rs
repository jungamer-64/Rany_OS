// ============================================================================
// kernel/src/io/iommu/runtime/config.rs
// ============================================================================

//! IOMMU Configuration
//!
//! Configuration structures for IOMMU initialization and runtime behavior.

use alloc::vec::Vec;

use crate::io::iommu::types::IommuDeviceScope;

// ============================================================================
// Configuration
// ============================================================================

/// IOMMU Configuration from Kernel Command Line
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IommuConfig {
    /// Force enable even if ACPI says no (not used yet)
    pub force: bool,
    /// Enable scalable mode translation (Intel VT-d SMTS)
    pub scalable_mode: bool,
}

impl IommuConfig {
    /// Create a new default configuration
    pub const fn new() -> Self {
        Self {
            force: false,
            scalable_mode: false,
        }
    }
}

impl Default for IommuConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Reserved Memory Region
// ============================================================================

/// Reserved Memory Region (from RMRR)
///
/// Represents a region of physical memory that must remain identity-mapped
/// for certain devices (e.g., legacy USB controllers).
pub struct ReservedMemoryRegion {
    /// PCI segment number
    pub segment: u16,
    /// Base physical address of the reserved region
    pub base: u64,
    /// Limit (end) physical address of the reserved region
    pub limit: u64,
    pub(crate) scopes: Vec<IommuDeviceScope>,
    /// Pins keep the resolved bridge bus numbers valid until registry retirement.
    pub(crate) _resources: Vec<alloc::sync::Arc<crate::drivers::pci::resource::FunctionResources>>,
}
