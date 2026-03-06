// ============================================================================
// kernel/src/io/iommu/api/mgmt.rs
// ============================================================================

//! IOMMU Management & Configuration API
//!
//! Initialization, domain management, and global operations.

use core::sync::atomic::Ordering;

use crate::io::iommu::IOMMU_REQUIRED;
use crate::io::iommu::runtime::backend::IommuBackend;
use crate::io::iommu::runtime::registry::{get_iommu_driver, is_iommu_enabled};
use crate::io::iommu::types::{DeviceId, IommuDomainType, IommuError};

/// IOMMUを必須に設定する
///
/// 起動初期（IOMMU初期化前）に呼び出すこと
pub fn set_iommu_required(required: bool) {
    IOMMU_REQUIRED.store(required, Ordering::Release);
}

/// IOMMUが必須かどうかを確認
pub fn is_iommu_required() -> bool {
    IOMMU_REQUIRED.load(Ordering::Acquire)
}

/// IOMMU要件をチェックし、必要なら停止
///
/// この関数はIOMMU初期化後に呼び出すべき
pub fn enforce_iommu_requirement() {
    if is_iommu_required() && !is_iommu_enabled() {
        // IOMMUが必須だが検出されなかった
        panic!(
            "[SECURITY] IOMMU is required but not detected. \
             DMA attacks are possible without IOMMU protection. \
             To boot without IOMMU, set IOMMU_REQUIRED=false."
        );
    }
}

/// Enable IOMMU translation (on all controllers)
pub fn enable_iommu() -> Result<(), IommuError> {
    // If IOMMU translation was already enabled during finalize_iommu_setup,
    // return success immediately.
    if is_iommu_enabled() {
        return Ok(());
    }

    let driver = match get_iommu_driver() {
        Some(d) => d,
        None => {
            // Global driver pointer not available – fall back to the
            // Intel registry which is populated before the pointer.
            if let Some(registry) = crate::io::iommu::vendors::intel::registry::get_iommu_registry()
            {
                for controller in &registry.controllers {
                    unsafe {
                        controller.enable()?;
                    }
                }
                return Ok(());
            }
            return Err(IommuError::NotInitialized);
        }
    };
    driver.enable()
}

/// Disable IOMMU translation (on all controllers)
pub fn disable_iommu() -> Result<(), IommuError> {
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    driver.disable()
}

/// Execute with the active IOMMU backend.
///
/// This passes a `&IommuBackend` to the closure. Backend selection is handled
/// by the driver registry.
pub fn with_iommu<F, R>(f: F) -> Result<R, IommuError>
where
    F: FnOnce(&IommuBackend) -> R,
{
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    Ok(f(driver.as_ref()))
}

// ============================================================================
// Domain Management Helpers
// ============================================================================

/// Create a new domain using the active IOMMU backend.
pub fn create_domain(
    numa_node: Option<usize>,
    domain_type: IommuDomainType,
) -> Result<u16, IommuError> {
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    driver.create_domain(numa_node, domain_type)
}

/// Attach a device to a domain using the active IOMMU backend.
pub fn attach_device(device: DeviceId, domain_id: u16) -> Result<(), IommuError> {
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    driver.attach_device(device, domain_id)
}

/// Detach a device from a domain using the active IOMMU backend.
pub fn detach_device(device: DeviceId) -> Result<(), IommuError> {
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    driver.detach_device(device)
}

/// Set NUMA hint for a domain (best-effort)
/// Note: Since domains are per-controller, this finds the first controller with the domain.
pub fn set_domain_numa(domain_id: u16, numa_node: Option<usize>) -> Result<(), IommuError> {
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    driver.set_domain_numa(domain_id, numa_node)
}

/// Get NUMA hint for a domain
pub fn get_domain_numa(domain_id: u16) -> Result<Option<usize>, IommuError> {
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    driver.get_domain_numa(domain_id)
}

/// Handle IOMMU Faults (Called from ISR)
///
/// Iterates all controllers and processes pending faults.
pub fn handle_fault() {
    if let Some(driver) = get_iommu_driver() {
        driver.handle_fault();
    }
}

/// Wake all pending async invalidation waiters (Called from ISR)
pub fn wake_invalidation_waiters() {
    if let Some(driver) = get_iommu_driver() {
        driver.wake_invalidation_waiters();
    }
}
