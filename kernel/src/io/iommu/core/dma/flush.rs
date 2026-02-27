// ============================================================================
// kernel/src/io/iommu/flush.rs
// ============================================================================
//!
//! IOTLB and Context Cache Flush Operations
//!
//! Provides high-level flush operations for emergency device isolation.
//! These functions wrap the backend-specific invalidation mechanisms.
//!
//! # Thread Safety
//!
//! All functions are thread-safe. However, for ISR context, only the
//! `request_*` variants should be used (which queue the request for
//! later processing).
//!
//! # Emergency Isolation
//!
//! When isolating a device due to fault storm:
//! 1. Call `invalidate_iotlb_device()` to flush device's IOTLB entries
//! 2. Call `invalidate_context_device()` to invalidate context cache
//!
//! This ensures the device cannot use any cached translations.

use crate::io::iommu::runtime::registry::get_iommu_driver;
use crate::io::iommu::types::IommuError;

/// Invalidate IOTLB entries for a specific device.
///
/// This performs device-selective (or domain-based) IOTLB invalidation
/// to ensure the device cannot use any cached translations.
///
/// # Arguments
///
/// * `source_id` - Device source ID (BDF: Bus/Device/Function)
///
/// # Thread Safety
///
/// This function is NOT ISR-safe (may acquire locks). For ISR context,
/// use `emergency_isolate_device()` which queues the request.
pub fn invalidate_iotlb_device(source_id: u16) -> Result<(), IommuError> {
    // Try to find the domain for this device
    let domain_id = lookup_device_domain(source_id);

    match domain_id {
        Some(did) => {
            // Domain-selective invalidation
            invalidate_iotlb_domain(did)
        }
        None => {
            // Device not found in any domain - perform global invalidation
            // This is conservative but ensures no cached entries remain
            log::warn!(
                "[IOMMU][Flush] Device 0x{:x} domain unknown, performing global IOTLB flush",
                source_id
            );
            invalidate_iotlb_global()
        }
    }
}

/// Invalidate context cache for a specific device.
///
/// This ensures the device's context entry is re-read from memory.
///
/// # Arguments
///
/// * `source_id` - Device source ID (BDF: Bus/Device/Function)
pub fn invalidate_context_device(source_id: u16) -> Result<(), IommuError> {
    // Context invalidation is typically global or per-device
    // For now, we perform global invalidation for maximum safety
    let _ = source_id; // suppress unused warning
    invalidate_context_global()
}

/// Invalidate IOTLB entries for a specific domain.
pub fn invalidate_iotlb_domain(domain_id: u16) -> Result<(), IommuError> {
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    driver.invalidate_iotlb(domain_id, None)?;

    log::debug!("[IOMMU][Flush] Domain {} IOTLB invalidated", domain_id);

    Ok(())
}

/// Invalidate all IOTLB entries globally.
pub fn invalidate_iotlb_global() -> Result<(), IommuError> {
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    driver.invalidate_iotlb_global()?;

    log::debug!("[IOMMU][Flush] Global IOTLB invalidated");

    Ok(())
}

/// Invalidate all context cache entries globally.
pub fn invalidate_context_global() -> Result<(), IommuError> {
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    driver.invalidate_context_global()?;

    log::debug!("[IOMMU][Flush] Global context cache invalidated");

    Ok(())
}

/// Lookup the domain ID for a device.
///
/// Returns `None` if the device is not assigned to any domain.
fn lookup_device_domain(source_id: u16) -> Option<u16> {
    let driver = get_iommu_driver()?;

    // Query backend for device's domain assignment
    driver.lookup_device_domain(source_id)
}
