// ============================================================================
// kernel/src/io/iommu/runtime/registry.rs
// ============================================================================

//! Global IOMMU Driver Registration
//!
//! This module manages the active IOMMU backend (Intel VT-d or AMD-Vi).
//! It provides a singleton accessor for the enum-dispatch backend.

use alloc::sync::Arc;

use crate::io::iommu::runtime::backend::IommuBackend;
pub use crate::io::iommu::vendors::intel::registry::get_iommu_registry;

// Global IOMMU driver stored in a lock-free spin::Once.
// Written exactly once during boot via init_driver(), then read-only.
// This avoids deadlocks when IOMMU fault interrupts fire while
// the boot context is reading the driver pointer.
static IOMMU_DRIVER: spin::Once<Arc<IommuBackend>> = spin::Once::new();

/// Get reference to the registered IOMMU driver (backend abstraction)
pub fn get_iommu_driver() -> Option<&'static Arc<IommuBackend>> {
    IOMMU_DRIVER.get()
}

/// Check if IOMMU is enabled (driver registered and backend available)
///
/// This checks the global driver pointer first.  If that is unavailable
/// (e.g. due to spin-lock ordering issues during early boot), it falls
/// back to querying the Intel-specific registry directly.
pub fn is_iommu_enabled() -> bool {
    if let Some(d) = get_iommu_driver() {
        if d.is_enabled() {
            return true;
        }
    }
    // Fallback: check Intel registry directly (set by init_registry during
    // init_iommu_from_acpi, before the global driver pointer is published).
    if let Some(registry) = get_iommu_registry() {
        if !registry.controllers.is_empty() {
            // Check if at least one controller has translation enabled
            return registry
                .controllers
                .iter()
                .any(|c| c.is_translation_enabled());
        }
    }
    false
}

/// Initialize the global driver. Must be called exactly once during boot.
///
/// # Panics
/// Panics if `init_driver` is called more than once.
pub fn init_driver(driver: Arc<IommuBackend>) {
    IOMMU_DRIVER.call_once(|| driver);
}

// ========================================================================
// Device DMA Address Mask Registry
// ========================================================================

use crate::io::iommu::types::{DeviceId, IommuError};
use crate::sync::PoisonRwLock;
use alloc::collections::BTreeMap;

// Per-device DMA address masks (inclusive).
static DEVICE_DMA_MASKS: PoisonRwLock<BTreeMap<DeviceId, u64>> = PoisonRwLock::new(BTreeMap::new());

/// Register or update a device DMA mask (inclusive).
///
/// Example: 32-bit DMA mask => 0xFFFF_FFFF.
pub fn register_device_dma_mask(device: DeviceId, mask: u64) {
    DEVICE_DMA_MASKS
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .insert(device, mask);
}

/// Register a device DMA mask using a bit width (1..=64).
pub fn register_device_dma_width(device: DeviceId, bits: u8) -> Result<(), IommuError> {
    if bits == 0 || bits > 64 {
        return Err(IommuError::InvalidAddress);
    }

    let mask = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    register_device_dma_mask(device, mask);
    Ok(())
}

/// Clear a previously registered DMA mask for a device.
pub fn clear_device_dma_mask(device: DeviceId) {
    DEVICE_DMA_MASKS
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&device);
}

/// Get a device DMA mask if registered.
pub fn get_device_dma_mask(device: &DeviceId) -> Option<u64> {
    DEVICE_DMA_MASKS
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(device)
        .copied()
}

// ============================================================================
// DMA Mask Pre-Validation (TOCTOU-safe)
// ============================================================================

/// Pre-validate that a mapping size can fit within the device's DMA mask.
///
/// # TOCTOU-Safety
///
/// This validation is performed **before** any IOVA allocation or page table
/// modification. Combined with `allocate_iova_masked()`, this ensures that
/// an invalid mapping is never created, eliminating the time-of-check
/// time-of-use vulnerability window.
///
/// # Returns
/// * `Ok(Some(mask))` - Device has a DMA mask, returned for use in allocation
/// * `Ok(None)` - No mask registered, no constraint
/// * `Err(IommuError::InvalidAddress)` - Size exceeds maximum addressable range
pub(crate) fn validate_dma_mask_pre_allocation(
    device: &DeviceId,
    size: u64,
) -> Result<Option<u64>, IommuError> {
    let Some(mask) = get_device_dma_mask(device) else {
        return Ok(None);
    };

    // Check if the size alone exceeds the mask's addressable range
    // (i.e., there exists no IOVA where `iova + size <= mask + 1`)
    let max_addressable = (mask as u128) + 1;
    if (size as u128) > max_addressable {
        log::warn!(
            "[IOMMU] DMA mapping size {} exceeds device {:?} mask limit {}",
            size,
            device,
            max_addressable
        );
        return Err(IommuError::InvalidAddress);
    }

    Ok(Some(mask))
}
