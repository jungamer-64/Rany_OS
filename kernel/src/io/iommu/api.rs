// ============================================================================
// kernel/src/io/iommu/api.rs
// ============================================================================
//! IOMMU Public API
//!
//! Global API functions for IOMMU initialization, device protection,
//! and interrupt remapping.

use core::sync::atomic::Ordering;
use x86_64::PhysAddr;

use super::interface::IommuDriver;
use super::{
    DeviceId, IOMMU_REQUIRED, IommuDomainType, IommuError, get_iommu_driver, is_iommu_enabled,
};

// ============================================================================
// IOMMU Requirement Functions
// ============================================================================

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

// ============================================================================
// Global Interrupt Remapping Interface
// ============================================================================

/// Map an interrupt for a device using Interrupt Remapping
///
/// Returns the IRTE handle (index) to be used for generating the MSI message.
pub fn map_interrupt(
    segment: u16,
    bus: u8,
    device: u8,
    function: u8,
    vector: u8,
    dest_id: u32,
    logical: bool,
) -> Result<u16, IommuError> {
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    driver.map_interrupt(segment, bus, device, function, vector, dest_id, logical)
}

/// Generate MSI Address and Data for a Remapped Interrupt
///
/// # Arguments
/// * `handle` - IRTE handle returned by `map_interrupt`
///
/// # Returns
/// (Address, Data) tuple for MSI/MSI-X configuration
pub fn get_remap_msi_message(handle: u16) -> (u64, u32) {
    if let Some(driver) = get_iommu_driver() {
        return driver.get_remap_msi_message(handle);
    }

    // Fallback to Intel VT-d MSI/MSI-X format if no driver is registered.
    let handle = handle as u64;
    let index_14_0 = handle & 0x7FFF;
    let index_15 = (handle >> 15) & 1;
    let address = 0xFEE0_0000 | (index_14_0 << 5) | (index_15 << 3);
    let data = 0;
    (address, data)
}

// ============================================================================
// Global DMA Mapping Interface
// ============================================================================

/// Map a physical address range for DMA access
///
/// Returns the IOVA (I/O Virtual Address) that devices should use.
///
/// # Safety
///
/// The caller must guarantee:
/// - `phys_addr` points to memory owned by the caller
/// - The memory will remain valid for the duration of DMA operations
/// - The memory is not part of kernel code, page tables, or other critical structures
/// - Concurrent access by the device is safe (proper synchronization if needed)
///
/// **ExoRust Guideline**: Prefer safe wrappers like `map_rref()` over this raw API.
pub unsafe fn map_for_dma(phys_addr: PhysAddr, size: u64) -> Result<u64, IommuError> {
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    unsafe { driver.map_for_dma(phys_addr, size) }
}

/// Unmap a DMA address range
pub fn unmap_dma(iova: u64, _size: u64) -> Result<(), IommuError> {
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    driver.unmap_dma(iova, _size)
}

/// Map a physical address range for a specific device (Device-Aware)
///
/// Uses the optimized `get_domain_for_device` path to map only in the
/// device's assigned domain.
///
/// # Safety
///
/// Same requirements as `map_for_dma`. The caller must guarantee the physical
/// address is owned, valid for DMA, and not a critical system structure.
pub unsafe fn map_for_device(
    device: &DeviceId,
    phys_addr: PhysAddr,
    size: u64,
) -> Result<u64, IommuError> {
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    // SAFETY: Caller must uphold safety requirements of map_for_device.
    unsafe { driver.map_for_device(device, phys_addr, size) }
}

/// Async variant of `map_for_device` that offloads to the controller's CommandQueue
/// and `await`s completion when configured.
///
/// # Safety
///
/// Same requirements as `map_for_dma`. The caller must guarantee the physical
/// address is owned, valid for DMA, and not a critical system structure.
pub async unsafe fn map_for_device_async(
    device: &DeviceId,
    phys_addr: PhysAddr,
    size: u64,
) -> Result<u64, IommuError> {
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    unsafe { driver.map_for_device_async(device, phys_addr, size).await }
}

/// Unmap a DMA address range for a specific device
pub fn unmap_for_device(device: &DeviceId, iova: u64, _size: u64) -> Result<(), IommuError> {
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    driver.unmap_for_device(device, iova, _size)
}

/// Async variant of `unmap_for_device` that offloads to CQ and awaits completion
pub async fn unmap_for_device_async(
    device: &DeviceId,
    iova: u64,
    _size: u64,
) -> Result<(), IommuError> {
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    driver.unmap_for_device_async(device, iova, _size).await
}

/// Execute with the active IOMMU backend.
///
/// This passes a `&dyn IommuDriver` to the closure. Backend selection is handled
/// by the driver registry.
pub fn with_iommu<F, R>(f: F) -> Result<R, IommuError>
where
    F: FnOnce(&dyn IommuDriver) -> R,
{
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    Ok(f(driver.as_ref()))
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

/// Enable IOMMU translation (on all controllers)
pub fn enable_iommu() -> Result<(), IommuError> {
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    driver.enable()
}

/// Disable IOMMU translation (on all controllers)
pub fn disable_iommu() -> Result<(), IommuError> {
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    driver.disable()
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
