// ============================================================================
// kernel/src/io/iommu/api.rs
// ============================================================================
//! IOMMU Public API
//!
//! Global API functions for IOMMU initialization, device protection,
//! and interrupt remapping.

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::RwLock;
use x86_64::PhysAddr;

use super::IommuBackend;
use super::registry::get_iommu_driver;
use super::types::{DeviceId, IommuDomainType, IommuError};
use super::IOMMU_REQUIRED;
use crate::ipc::RRef;

pub use super::dma_handle::{
    DmaDirection, DmaHandle, MapError, MapErrorKind, UnmapError, UnmapErrorKind,
};
pub use super::registry::is_iommu_enabled;

/// Identity mapping fallback gate (default: false).
///
/// WARNING: Enabling this allows identity mapping when IOMMU is unavailable.
/// Use only for early boot or controlled bring-up paths.
#[cfg(any(feature = "unsafe_iommu_bypass", debug_assertions))]
static UNSAFE_ALLOW_IDENTITY_MAPPING: AtomicBool = AtomicBool::new(false);

/// Global DMA mapping gate (device-scoped mappings remain allowed).
static ALLOW_GLOBAL_MAPPINGS: AtomicBool = AtomicBool::new(cfg!(debug_assertions));

// Instrumentation counters for testing / diagnostics
static MAP_COUNT: AtomicU64 = AtomicU64::new(0);
static UNMAP_COUNT: AtomicU64 = AtomicU64::new(0);

// Per-device DMA address masks (inclusive).
static DEVICE_DMA_MASKS: RwLock<BTreeMap<DeviceId, u64>> = RwLock::new(BTreeMap::new());

// ============================================================================
// IOMMU Requirement Functions
// ============================================================================

/// Enable/disable identity mapping fallback.
///
/// # Safety
/// This weakens memory protection and must only be set during trusted early init.
#[cfg(any(feature = "unsafe_iommu_bypass", debug_assertions))]
pub unsafe fn set_unsafe_identity_mapping_allowed(allowed: bool) {
    UNSAFE_ALLOW_IDENTITY_MAPPING.store(allowed, Ordering::Release);
}

/// Enable/disable identity mapping fallback.
///
/// # Safety
/// This weakens memory protection and must only be set during trusted early init.
#[cfg(not(any(feature = "unsafe_iommu_bypass", debug_assertions)))]
pub unsafe fn set_unsafe_identity_mapping_allowed(_allowed: bool) {
    log::warn!(
        "[IOMMU] identity mapping bypass is disabled; ignoring unsafe override"
    );
}

/// Check whether identity mapping fallback is allowed.
#[cfg(any(feature = "unsafe_iommu_bypass", debug_assertions))]
pub fn is_unsafe_identity_mapping_allowed() -> bool {
    UNSAFE_ALLOW_IDENTITY_MAPPING.load(Ordering::Acquire)
}

/// Check whether identity mapping fallback is allowed.
#[cfg(not(any(feature = "unsafe_iommu_bypass", debug_assertions)))]
pub fn is_unsafe_identity_mapping_allowed() -> bool {
    false
}

/// Enable/disable global DMA mappings (non device-scoped).
pub fn set_global_dma_mapping_allowed(allowed: bool) {
    ALLOW_GLOBAL_MAPPINGS.store(allowed, Ordering::Release);
}

/// Check whether global DMA mappings are allowed.
pub fn is_global_dma_mapping_allowed() -> bool {
    ALLOW_GLOBAL_MAPPINGS.load(Ordering::Acquire)
}

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

// ========================================================================
// Device DMA Address Mask Registry
// ========================================================================

/// Register or update a device DMA mask (inclusive).
///
/// Example: 32-bit DMA mask => 0xFFFF_FFFF.
pub fn register_device_dma_mask(device: DeviceId, mask: u64) {
    DEVICE_DMA_MASKS.write().insert(device, mask);
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
    DEVICE_DMA_MASKS.write().remove(&device);
}

/// Get a device DMA mask if registered.
pub fn get_device_dma_mask(device: &DeviceId) -> Option<u64> {
    DEVICE_DMA_MASKS.read().get(device).copied()
}

fn dma_mask_allows_range(mask: u64, addr: u64, size: u64) -> bool {
    if size == 0 {
        return true;
    }

    let end = match addr.checked_add(size) {
        Some(end) => end,
        None => return false,
    };

    let limit = (mask as u128) + 1;
    (addr as u128) <= (mask as u128) && (end as u128) <= limit
}

fn validate_device_dma_mask(device: &DeviceId, addr: u64, size: u64) -> Result<(), IommuError> {
    let Some(mask) = get_device_dma_mask(device) else {
        return Ok(());
    };

    if dma_mask_allows_range(mask, addr, size) {
        Ok(())
    } else {
        Err(IommuError::InvalidAddress)
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

/// Map an `RRef<T>` for DMA access using the global IOMMU backend.
///
/// Returns a `DmaHandle<T>` that must be explicitly unmapped to recover the `RRef<T>`.
///
/// # Alignment
/// When IOMMU is enabled, the buffer must be 4K-aligned in address and size.
#[deprecated(note = "Use map_rref_for_device; global mappings can be disabled (iommu_global=off).")]
pub fn map_rref<T>(
    rref: RRef<T>,
    domain_id: u16,
    direction: DmaDirection,
) -> Result<DmaHandle<T>, MapError<T>> {
    DmaHandle::map_rref(rref, domain_id, direction)
}

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

/// Map an `RRef<[T]>` slice for DMA access using the global IOMMU backend.
///
/// # Alignment
/// When IOMMU is enabled, the buffer must be 4K-aligned in address and size.
#[deprecated(note = "Use map_rref_slice_for_device; global mappings can be disabled (iommu_global=off).")]
pub fn map_rref_slice<T>(
    rref: RRef<[T]>,
    domain_id: u16,
    direction: DmaDirection,
) -> Result<DmaHandle<[T]>, MapError<[T]>> {
    DmaHandle::map_rref_slice(rref, domain_id, direction)
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
pub unsafe fn map_for_dma(phys_addr: PhysAddr, size: u64) -> Result<u64, IommuError> {
    if is_iommu_enabled() && !is_global_dma_mapping_allowed() {
        return Err(IommuError::NotSupported);
    }
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    let res = unsafe { driver.map_for_dma(phys_addr, size) };
    if res.is_ok() {
        MAP_COUNT.fetch_add(1, Ordering::SeqCst);
    }
    res
}

/// Unmap a DMA address range
pub fn unmap_dma(iova: u64, _size: u64) -> Result<(), IommuError> {
    let driver = get_iommu_driver().ok_or(IommuError::NotInitialized)?;
    let res = driver.unmap_dma(iova, _size);
    if res.is_ok() {
        UNMAP_COUNT.fetch_add(1, Ordering::SeqCst);
    }
    res
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
    let iova = unsafe { driver.map_for_device(device, phys_addr, size) }?;
    if let Err(err) = validate_device_dma_mask(device, iova, size) {
        if let Err(unmap_err) = driver.unmap_for_device(device, iova, size) {
            log::error!(
                "[IOMMU] failed to unmap invalid device DMA mapping: {:?}",
                unmap_err
            );
        }
        return Err(err);
    }
    MAP_COUNT.fetch_add(1, Ordering::SeqCst);
    Ok(iova)
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
    let iova = unsafe { driver.map_for_device_async(device, phys_addr, size).await }?;
    if let Err(err) = validate_device_dma_mask(device, iova, size) {
        if let Err(unmap_err) = driver.unmap_for_device_async(device, iova, size).await {
            log::error!(
                "[IOMMU] failed to unmap invalid async device DMA mapping: {:?}",
                unmap_err
            );
        }
        return Err(err);
    }
    MAP_COUNT.fetch_add(1, Ordering::SeqCst);
    Ok(iova)
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
    let res = driver.unmap_for_device_async(device, iova, _size).await;
    if res.is_ok() {
        UNMAP_COUNT.fetch_add(1, Ordering::SeqCst);
    }
    res
}

/// Reset map/unmap counters (for tests)
pub fn reset_map_unmap_counts() {
    MAP_COUNT.store(0, Ordering::SeqCst);
    UNMAP_COUNT.store(0, Ordering::SeqCst);
}

/// Get number of successful map operations recorded
pub fn get_map_count() -> u64 {
    MAP_COUNT.load(Ordering::SeqCst)
}

/// Get number of successful unmap operations recorded
pub fn get_unmap_count() -> u64 {
    UNMAP_COUNT.load(Ordering::SeqCst)
}

/// Emit IOMMU diagnostics to the log.
pub fn dump_iommu_diagnostics() {
    log::info!("=== IOMMU Diagnostics ===");
    log::info!("Global map count: {}", get_map_count());
    log::info!("Global unmap count: {}", get_unmap_count());

    if let Some(driver) = get_iommu_driver() {
        driver.dump_diagnostics();
    } else {
        log::warn!("IOMMU driver not initialized");
    }
    log::info!("=========================");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_unmap_counters() {
        // Reset to a known state
        reset_map_unmap_counts();
        assert_eq!(get_map_count(), 0);
        assert_eq!(get_unmap_count(), 0);
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
