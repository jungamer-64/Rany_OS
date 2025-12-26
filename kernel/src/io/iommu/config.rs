//! IOMMU Configuration
//!
//! Configuration structures for IOMMU initialization and runtime behavior.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::types::DeviceId;

// ============================================================================
// Configuration
// ============================================================================

/// IOMMU Configuration from Kernel Command Line
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IommuConfig {
    /// Enable IOMMU
    pub enabled: bool,
    /// Passthrough mode (disable translation for most devices)
    pub passthrough: bool,
    /// Force enable even if ACPI says no (not used yet)
    pub force: bool,
}

impl IommuConfig {
    /// Create a new default configuration
    pub const fn new() -> Self {
        Self {
            enabled: true,
            passthrough: false,
            force: false,
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
#[derive(Debug, Clone)]
pub struct ReservedMemoryRegion {
    /// PCI segment number
    pub segment: u16,
    /// Base physical address of the reserved region
    pub base: u64,
    /// Limit (end) physical address of the reserved region
    pub limit: u64,
    /// Devices this region applies to (Segment, Bus, Device, Function)
    /// If empty, might apply to all? (Spec usually says explicit scope)
    pub devices: Vec<DeviceId>,
}
