// ============================================================================
// kernel/src/io/iommu/api.rs
// ============================================================================
//! IOMMU Public API
//!
//! Global API functions for IOMMU initialization, device protection,
//! and interrupt remapping.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use x86_64::PhysAddr;

use super::controller::{init::CapabilityManager, iova::IovaManager, qi_ops::InvalidationOps};
use super::{
    DeviceId, IOMMU_REQUIRED, IommuController, IommuError, ecap_bits, get_iommu_registry,
    is_iommu_enabled,
};
use crate::io::iommu::controller::{
    dma::DomainManager, fault::FaultHandler, ir::InterruptRemapper,
};
use crate::io::iommu_cmdqueue::IommuCommandKind;

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
    let registry = get_iommu_registry().ok_or(IommuError::NotInitialized)?;

    // Find the controller index for this device using proper scope matching
    let controller_idx = registry
        .find_controller_index_for_device(segment, bus, device, function)
        .ok_or(IommuError::NotPresent)?;

    let controller = registry
        .controllers
        .get(controller_idx)
        .ok_or(IommuError::NotPresent)?;

    // Check if IR is enabled
    if !controller.is_interrupt_remapping_enabled() {
        return Err(IommuError::NotSupported);
    }

    // Allocate IRTE
    controller.allocate_irte(vector, dest_id, logical)
}

/// Generate MSI Address and Data for a Remapped Interrupt
///
/// # Arguments
/// * `handle` - IRTE handle returned by `map_interrupt`
///
/// # Returns
/// (Address, Data) tuple for MSI/MSI-X configuration
pub fn get_remap_msi_message(handle: u16) -> (u64, u32) {
    // Intel VT-d Spec 5.1.5.1 MSI / MSI-X Address Format
    // 31:20 = 0xFEE (Fixed)
    // 19:5  = Handle[14:0] (Interrupt Index)
    // 4     = SHV (SubHandle Valid) - Set to 0 here
    // 3     = Handle[15] (Interrupt Index MSB)
    // 2     = XX (Guest Mode / Ignored)

    let handle = handle as u64;
    let index_14_0 = handle & 0x7FFF;
    let index_15 = (handle >> 15) & 1;

    let address = 0xFEE0_0000 | (index_14_0 << 5) | (index_15 << 3);
    let data = 0; // Data is 0 when SHV=0

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
    let registry = get_iommu_registry().ok_or(IommuError::NotInitialized)?;

    if registry.controllers.is_empty() {
        return Err(IommuError::NotPresent);
    }

    let iova = phys_addr.as_u64();

    for controller in &registry.controllers {
        let domain_arc = {
            let domains_guard = controller
                .domains
                .lock()
                .map_err(|_| IommuError::HardwareError)?;
            domains_guard
                .get(&0) // Default domain
                .cloned()
                .ok_or(IommuError::DomainNotFound)?
        };
        let mut domain = domain_arc.lock().map_err(|_| IommuError::HardwareError)?;
        domain.map(iova, phys_addr.as_u64(), size, true, true)?;
    }

    Ok(iova)
}

/// Unmap a DMA address range
pub fn unmap_dma(iova: u64, _size: u64) -> Result<(), IommuError> {
    let registry = get_iommu_registry().ok_or(IommuError::NotInitialized)?;
    if registry.controllers.is_empty() {
        return Err(IommuError::NotPresent);
    }

    for controller in &registry.controllers {
        let domain_arc = {
            let domains_guard = controller
                .domains
                .lock()
                .map_err(|_| IommuError::HardwareError)?;
            domains_guard
                .get(&0)
                .cloned()
                .ok_or(IommuError::DomainNotFound)?
        };
        let mut domain = domain_arc.lock().map_err(|_| IommuError::HardwareError)?;
        domain.unmap(iova)?;
    }
    Ok(())
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
    // Backwards-compatible blocking wrapper over the async variant
    // SAFETY: Caller must uphold safety requirements of map_for_device
    crate::task::block_on(async { unsafe { map_for_device_async(device, phys_addr, size).await } })
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
    let registry = get_iommu_registry().ok_or(IommuError::NotInitialized)?;
    if registry.controllers.is_empty() {
        return Err(IommuError::NotPresent);
    }

    let iova = phys_addr.as_u64();

    // Iterate controllers to find the one managing this device
    for controller in &registry.controllers {
        if let Ok(Some(domain_id)) = controller.get_domain_for_device(*device) {
            if let Some(domain_arc) = controller.domain(domain_id) {
                // Read domain id under lock, but do NOT hold the domain lock while submitting to CQ
                let domain_id = {
                    let d = domain_arc.lock().map_err(|_| IommuError::HardwareError)?;
                    d.id
                };

                // If a command queue is configured, offload the mapping to it and await completion.
                if let Some(ref cq) = controller.command_queue {
                    let cmd = IommuCommandKind::MapRegion {
                        domain: domain_id,
                        iova,
                        phys: phys_addr.as_u64(),
                        size,
                        read: true,
                        write: true,
                    };
                    let comp = cq.submit(cmd).map_err(|_| IommuError::HardwareError)?;
                    let rc = comp.await;
                    if rc == 0 {
                        return Ok(iova);
                    } else {
                        return Err(IommuError::HardwareError);
                    }
                }

                // No CQ configured: perform mapping inline
                let mut domain = domain_arc.lock().map_err(|_| IommuError::HardwareError)?;
                domain.map(iova, phys_addr.as_u64(), size, true, true)?;
                return Ok(iova);
            }
        }
    }

    Err(IommuError::DomainNotFound)
}

/// Unmap a DMA address range for a specific device
pub fn unmap_for_device(device: &DeviceId, iova: u64, _size: u64) -> Result<(), IommuError> {
    crate::task::block_on(async { unmap_for_device_async(device, iova, _size).await })
}

/// Async variant of `unmap_for_device` that offloads to CQ and awaits completion
pub async fn unmap_for_device_async(
    device: &DeviceId,
    iova: u64,
    _size: u64,
) -> Result<(), IommuError> {
    let registry = get_iommu_registry().ok_or(IommuError::NotInitialized)?;
    if registry.controllers.is_empty() {
        return Err(IommuError::NotPresent);
    }

    for controller in &registry.controllers {
        if let Ok(Some(domain_id)) = controller.get_domain_for_device(*device) {
            if let Some(domain_arc) = controller.domain(domain_id) {
                // Read domain id under lock, then drop lock before submitting to CQ
                let domain_id = {
                    let d = domain_arc.lock().map_err(|_| IommuError::HardwareError)?;
                    d.id
                };

                // If CQ is configured, offload unmap to CQ and await
                if let Some(ref cq) = controller.command_queue {
                    let cmd = IommuCommandKind::UnmapRegion {
                        domain: domain_id,
                        iova,
                        size: _size,
                    };
                    let comp = cq.submit(cmd).map_err(|_| IommuError::HardwareError)?;
                    let rc = comp.await;
                    if rc == 0 {
                        return Ok(());
                    } else {
                        return Err(IommuError::HardwareError);
                    }
                }

                // No CQ: perform unmap inline then invalidate
                let mut domain = domain_arc.lock().map_err(|_| IommuError::HardwareError)?;
                domain.unmap(iova)?;
                // Capture domain id while we still hold the domain lock
                let domain_id = domain.id();
                drop(domain); // Release lock before invalidating

                // SAFETY: We hold no locks on domain, controller logic handles hardware safety
                if let Some(ref cq) = controller.command_queue {
                    let comp = cq
                        .submit(IommuCommandKind::InvalidateIotlbDomain { domain: domain_id })
                        .map_err(|_| IommuError::HardwareError)?;
                    let rc = comp.await;
                    if rc == 0 {
                        return Ok(());
                    } else {
                        return Err(IommuError::HardwareError);
                    }
                } else {
                    unsafe {
                        controller.invalidate_iotlb(domain_id);
                    }
                }

                return Ok(());
            }
        }
    }

    Err(IommuError::DomainNotFound)
}

/// Execute with default IOMMU controller (mutable access)
///
/// This acquires a write lock on the chosen controller and passes a `&mut` to the
/// provided closure. Many operations (attach/detach/create_domain) require mutation,
/// so take `&mut` here for convenience. If only read access is needed in the future,
/// consider adding a read-only helper.
pub fn with_iommu<F, R>(f: F) -> Result<R, IommuError>
where
    F: FnOnce(&IommuController) -> R,
{
    let registry = get_iommu_registry().ok_or(IommuError::NotInitialized)?;
    let idx = registry.default_iommu_idx.ok_or(IommuError::NotPresent)?;
    let controller = registry
        .controllers
        .get(idx)
        .ok_or(IommuError::NotPresent)?;
    Ok(f(controller))
}

/// Handle IOMMU Faults (Called from ISR)
///
/// Iterates all controllers and processes pending faults.
pub fn handle_fault() {
    if let Some(registry) = get_iommu_registry() {
        for (_i, controller) in registry.controllers.iter().enumerate() {
            // Process faults directly (thread-safe)
            controller.process_faults();
        }
    }
}

/// Wake all pending async invalidation waiters (Called from ISR)
pub fn wake_invalidation_waiters() {
    if let Some(registry) = get_iommu_registry() {
        // Use try_read to avoid deadlock in ISR if main thread holds write lock
        for controller in &registry.controllers {
            controller.wake_invalidation_waiter();
        }
    }
}

/// Enable IOMMU translation (on all controllers)
pub fn enable_iommu() -> Result<(), IommuError> {
    if let Some(registry) = get_iommu_registry() {
        for controller in &registry.controllers {
            unsafe {
                controller.enable()?;
            }
        }
        Ok(())
    } else {
        Err(IommuError::NotInitialized)
    }
}

/// Disable IOMMU translation (on all controllers)
pub fn disable_iommu() -> Result<(), IommuError> {
    if let Some(registry) = get_iommu_registry() {
        for controller in &registry.controllers {
            unsafe {
                controller.disable()?;
            }
        }
        Ok(())
    } else {
        Err(IommuError::NotInitialized)
    }
}

/// Set NUMA hint for a domain (best-effort)
/// Note: Since domains are per-controller, this finds the first controller with the domain.
pub fn set_domain_numa(domain_id: u16, numa_node: Option<usize>) -> Result<(), IommuError> {
    let registry = get_iommu_registry().ok_or(IommuError::NotInitialized)?;
    // Try to find the domain in any controller
    for controller in &registry.controllers {
        if controller.domain(domain_id).is_some() {
            return controller.set_domain_numa(domain_id, numa_node);
        }
    }
    Err(IommuError::DomainNotFound)
}

/// Get NUMA hint for a domain
pub fn get_domain_numa(domain_id: u16) -> Result<Option<usize>, IommuError> {
    let registry = get_iommu_registry().ok_or(IommuError::NotInitialized)?;
    for controller in &registry.controllers {
        if let Some(domain_arc) = controller.domain(domain_id) {
            match domain_arc.lock() {
                Ok(guard) => return Ok(guard.numa_node),
                Err(_) => {
                    log::error!("[IOMMU] Domain lock poisoned in get_domain_numa - returning None");
                    return Ok(None);
                }
            }
        }
    }

    Err(IommuError::DomainNotFound)
}
