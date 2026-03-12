// ============================================================================
// kernel/src/io/iommu/api/dma.rs
// ============================================================================

//! DMA Mapping API
//!
//! Functions for mapping/unmapping memory for DMA access.

use x86_64::PhysAddr;

use crate::io::iommu::common::dma::handle::{DmaDirection, DmaHandle, MapError};
use crate::io::iommu::runtime::registry::{
    get_iommu_driver, is_iommu_enabled, validate_dma_mask_pre_allocation,
};
use crate::io::iommu::runtime::security::is_global_dma_mapping_allowed;
use crate::io::iommu::runtime::stats::{inc_global_map_count, inc_map_count, inc_unmap_count};
use crate::io::iommu::types::{DeviceId, IommuError};
use crate::ipc::RRef;

/// Map an `RRef<T>` for DMA access scoped to a specific device.
///
/// Returns a `DmaHandle<T>` that must be explicitly unmapped to recover the `RRef<T>`.
///
/// # Alignment
/// When IOMMU is enabled, the buffer must be 4K-aligned in address and size.
pub fn map_rref_for_device<T>(
    rref: RRef<T>,
    device: &DeviceId,
    direction: DmaDirection,
) -> Result<DmaHandle<T>, MapError<T>> {
    DmaHandle::map_rref_for_device(rref, device, direction)
}

/// Map an `RRef<[T]>` slice for DMA access scoped to a specific device.
///
/// # Alignment
/// When IOMMU is enabled, the buffer must be 4K-aligned in address and size.
pub fn map_rref_slice_for_device<T>(
    rref: RRef<[T]>,
    device: &DeviceId,
    direction: DmaDirection,
) -> Result<DmaHandle<[T]>, MapError<[T]>> {
    DmaHandle::map_rref_slice_for_device(rref, device, direction)
}

/// Map an `RRef<T>` for DMA access scoped to a specific IOMMU domain.
pub(crate) fn map_rref_for_domain<T>(
    rref: RRef<T>,
    domain_id: u16,
    direction: DmaDirection,
) -> Result<DmaHandle<T>, MapError<T>> {
    DmaHandle::map_rref(rref, domain_id, direction)
}

/// Map an `RRef<[T]>` slice for DMA access scoped to a specific IOMMU domain.
pub(crate) fn map_rref_slice_for_domain<T>(
    rref: RRef<[T]>,
    domain_id: u16,
    direction: DmaDirection,
) -> Result<DmaHandle<[T]>, MapError<[T]>> {
    DmaHandle::map_rref_slice(rref, domain_id, direction)
}

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
/// - `phys_addr` and `size` are 4K-aligned when IOMMU translation is enabled
///
/// **ExoRust Guideline**: Prefer safe wrappers like `map_rref()` over this raw API.
pub(crate) unsafe fn map_for_dma(phys_addr: PhysAddr, size: u64) -> Result<u64, IommuError> {
    if is_iommu_enabled() && !is_global_dma_mapping_allowed() {
        return Err(IommuError::NotSupported);
    }
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    let res = unsafe { driver.map_for_dma(phys_addr, size) };
    if res.is_ok() {
        inc_map_count();
        inc_global_map_count();
    }
    res
}

pub(crate) unsafe fn map_for_dma_with_perms(
    phys_addr: PhysAddr,
    size: u64,
    read: bool,
    write: bool,
) -> Result<u64, IommuError> {
    if is_iommu_enabled() && !is_global_dma_mapping_allowed() {
        return Err(IommuError::NotSupported);
    }
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    let res = unsafe { driver.map_for_dma_with_perms(phys_addr, size, read, write) };
    if res.is_ok() {
        inc_map_count();
        inc_global_map_count();
    }
    res
}

/// Unmap a DMA address range
pub fn unmap_dma(iova: u64, _size: u64) -> Result<(), IommuError> {
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    let res = driver.unmap_dma(iova, _size);
    if res.is_ok() {
        inc_unmap_count();
    }
    res
}

/// Map a physical address range for a specific device (Device-Aware)
///
/// Uses the optimized `get_domain_for_device` path to map only in the
/// device's assigned domain.
///
/// # TOCTOU Safety
///
/// This function is TOCTOU-safe: the backend applies DMA mask constraints
/// during IOVA allocation via `allocate_iova_masked()`, ensuring no
/// invalid mapping ever exists in the page tables.
///
/// # Safety
///
/// Same requirements as `map_for_dma`. The caller must guarantee the physical
/// address is owned, valid for DMA, and not a critical system structure.
pub(crate) unsafe fn map_for_device(
    device: &DeviceId,
    phys_addr: PhysAddr,
    size: u64,
) -> Result<u64, IommuError> {
    // Pre-validate that size can fit within device's DMA mask
    let _ = validate_dma_mask_pre_allocation(device, size)?;

    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    // SAFETY: Caller must uphold safety requirements of map_for_device.
    // Note: Backend applies DMA mask during IOVA allocation (TOCTOU-safe).
    let iova = unsafe { driver.map_for_device(device, phys_addr, size) }?;
    inc_map_count();
    Ok(iova)
}

pub(crate) unsafe fn map_for_device_with_perms(
    device: &DeviceId,
    phys_addr: PhysAddr,
    size: u64,
    read: bool,
    write: bool,
) -> Result<u64, IommuError> {
    // Pre-validate that size can fit within device's DMA mask
    let _ = validate_dma_mask_pre_allocation(device, size)?;

    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    // SAFETY: Caller must uphold safety requirements of map_for_device_with_perms.
    // Note: Backend applies DMA mask during IOVA allocation (TOCTOU-safe).
    let iova = unsafe { driver.map_for_device_with_perms(device, phys_addr, size, read, write) }?;
    inc_map_count();
    Ok(iova)
}

/// Async variant of `map_for_device` that offloads to the controller's CommandQueue
/// and `await`s completion when configured.
///
/// # Async Behavior
/// This method does not busy-wait. It submits the mapping request to the hardware's
/// Command Queue and yields execution. The hardware generates an MSI/interrupt upon
/// completion, which invokes an ISR that pushes an event to a lock-free queue and
/// wakes the executor. The executor then resumes this Future, adhering to the
/// ExoRust async-first guidelines.
///
/// # TOCTOU Safety
///
/// This function is TOCTOU-safe: the backend applies DMA mask constraints
/// during IOVA allocation via `allocate_iova_masked()`.
///
/// # Safety
///
/// Same requirements as `map_for_dma`. The caller must guarantee the physical
/// address is owned, valid for DMA, and not a critical system structure.
pub(crate) async unsafe fn map_for_device_async(
    device: &DeviceId,
    phys_addr: PhysAddr,
    size: u64,
) -> Result<u64, IommuError> {
    // Pre-validate that size can fit within device's DMA mask
    let _ = validate_dma_mask_pre_allocation(device, size)?;

    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    // Note: Backend applies DMA mask during IOVA allocation (TOCTOU-safe).
    let iova = unsafe { driver.map_for_device_async(device, phys_addr, size).await }?;
    inc_map_count();
    Ok(iova)
}

/// Unmap a DMA address range for a specific device
pub fn unmap_for_device(device: &DeviceId, iova: u64, _size: u64) -> Result<(), IommuError> {
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    driver.unmap_for_device(device, iova, _size)
}

pub(crate) fn domain_id_for_device(device: &DeviceId) -> Result<u16, IommuError> {
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    driver.domain_id_for_device(device)
}

/// Async variant of `unmap_for_device` that offloads to CQ and awaits completion
///
/// # Async Behavior
/// Similar to `map_for_device_async`, this method submits the unmap/invalidate
/// requests to the hardware Command Queue and resolves via interrupt-driven wakers,
/// avoiding busy-waiting on the CPU.
pub async fn unmap_for_device_async(
    device: &DeviceId,
    iova: u64,
    _size: u64,
) -> Result<(), IommuError> {
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    let res = driver.unmap_for_device_async(device, iova, _size).await;
    if res.is_ok() {
        inc_unmap_count();
    }
    res
}
