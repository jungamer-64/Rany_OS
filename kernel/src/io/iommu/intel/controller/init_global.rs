// ============================================================================
// kernel/src/io/iommu/intel/controller/init_global.rs
// ============================================================================

//! Global Initialization (from ACPI)
//!
//! This module contains functions to initialize the IOMMU subsystem
//! from ACPI DMAR tables or manually.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::io::iommu::config::{IommuConfig, ReservedMemoryRegion};
use crate::io::iommu::tables::phys_to_virt_usize;
use crate::io::iommu::types::{DeviceId, IommuDomainType, IommuError};
// Intel-specific imports
use super::super::registry::{IommuRegistry, init_registry};
use super::IommuController;

#[cfg(not(test))]
use crate::io::iommu::groups::{IOMMU_GROUP_MANAGER, IommuGroupManager};

use super::fault::FaultHandler;
use super::init::CapabilityManager;
use super::iova::IovaManager;
use super::qi_init::QIManager;
#[cfg(not(test))]
use super::dma::DomainManager;
// use crate::io::acpi::dmar; // For parse_dmar - verified this path exists in kernel/src/io/acpi/dmar.rs

fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

#[cfg(not(test))]
const COMMAND_QUEUE_BATCH: usize = 64;

#[cfg(not(test))]
async fn command_queue_worker(controller: Arc<IommuController>) {
    loop {
        let cq = match controller.command_queue.as_ref() {
            Some(cq) => cq,
            None => break,
        };
        let processed = cq.process_up_to(
            |kind| controller.handle_command_queue_entry(kind).map_err(|_| ()),
            COMMAND_QUEUE_BATCH,
        );
        if processed == 0 {
            cq.wait_for_work().await;
        }
    }
}

#[cfg(not(test))]
fn spawn_command_queue_worker(controller: Arc<IommuController>) {
    crate::task::per_core_executor::spawn(command_queue_worker(controller));
}

/// Initialize IOMMU using ACPI DMAR table at `dmar_addr`
pub unsafe fn init_iommu_from_acpi(
    dmar_addr: usize,
    config: IommuConfig,
) -> Result<(), IommuError> {
    if !config.enabled {
        log::info!("IOMMU disabled by kernel configuration");
        return Err(IommuError::NotPresent);
    }

    // Parse DMAR using canonical ACPI parser from drivers/acpi
    let dmar_info = match unsafe { crate::io::acpi::dmar::parse_dmar(dmar_addr) } {
        Ok(info) => info,
        Err(e) => {
            log::error!("Failed to parse DMAR: {}", e);
            return Err(IommuError::HardwareError);
        }
    };

    // Prepare controllers list
    let mut controllers = Vec::new();
    let mut default_idx = None;

    // 3. Initialize Controllers (DRHD)
    for unit in dmar_info.drhd_units {
        log::info!(
            "Initializing IOMMU Controller at {:#x} (Segment: {}, All: {})",
            unit.register_base,
            unit.segment,
            unit.include_all
        );

        let mmio_virt = phys_to_virt_usize(unit.register_base) as u64;
        log::info!(
            "Mapped IOMMU Base: Phys {:#x} -> Virt {:#x}",
            unit.register_base,
            mmio_virt
        );

        let mut controller = IommuController::new(mmio_virt, unit.segment);

        unsafe {
            if let Err(e) = controller.init(config.scalable_mode) {
                log::error!("Failed to initialize IOMMU controller: {:?}", e);
                continue;
            }

            let iova_bits = controller.max_guest_address_width().min(48).max(12);
            let iova_base = crate::io::iommu::PAGE_SIZE_4K;
            let iova_limit = 1u64 << iova_bits;
            let iova_size = iova_limit.saturating_sub(iova_base);
            if iova_size == 0 {
                log::warn!("[IOMMU] Skipping IOVA allocator init: invalid size");
            } else if let Err(e) = controller.init_iova(iova_base, iova_size) {
                log::warn!("[IOMMU] Failed to init IOVA allocator: {:?}", e);
            }

            // Enable Fault Interrupts (Vector 0x50 - IommuFault)
            controller.enable_fault_interrupt(0x50);

            // Setup Queued Invalidation if supported
            if controller.supports_queued_invalidation() {
                if let Err(e) = controller.init_queued_invalidation(8) {
                    log::warn!("Failed to init Queued Invalidation: {:?}", e);
                } else {
                    if let Err(e) = controller.enable_queued_invalidation() {
                        log::warn!("Failed to enable Queued Invalidation: {:?}", e);
                    } else {
                        log::info!("Queued Invalidation enabled for controller");
                    }
                }
            }
        }

        controller.command_queue =
            Some(crate::io::iommu::cmdqueue::CommandQueue::new_with_numa(None));

        controllers.push(Arc::new(controller));
        if unit.include_all {
            default_idx = Some(controllers.len() - 1);
        }
    }

    if controllers.is_empty() {
        return Err(IommuError::NotPresent);
    }

    for (idx, controller) in controllers.iter().enumerate() {
        controller.set_controller_idx(idx);
    }

    // Set default controller (or first one)
    let default_iommu_idx = default_idx.or(Some(0));

    // 4. Register RMRR regions
    let dmar_rmrr_regions = dmar_info.rmrr_regions.clone();
    let mut reserved_regions = Vec::new();

    for region in &dmar_rmrr_regions {
        let mut devices = Vec::new();
        for scope in &region.devices {
            let bus = scope.start_bus;
            // Simplification: Assume flat bus or simple path for now
            if let Some(last_path) = scope.path.last() {
                let device_id =
                    DeviceId::new(region.segment, bus, last_path.device, last_path.function);
                devices.push(device_id);
            }
        }

        reserved_regions.push(ReservedMemoryRegion {
            segment: region.segment,
            base: region.base,
            limit: region.limit,
            devices,
        });
    }

    // Build the registry
    let registry = IommuRegistry {
        controllers,
        default_iommu_idx,
        reserved_regions,
        config,
    };

    #[cfg(not(test))]
    {
        for controller in &registry.controllers {
            if controller.command_queue.is_some() {
                spawn_command_queue_worker(Arc::clone(controller));
            }
        }
    }

    // Apply Reserved Regions (RMRR)
    // Need to do this before publishing registry because we need mutable access to controllers
    for region in &registry.reserved_regions {
        let page_size = crate::io::iommu::PAGE_SIZE_4K;
        let start = align_down(region.base, page_size);
        let end = align_up(region.limit.saturating_add(1), page_size);
        if end <= start {
            continue;
        }

        for controller in &registry.controllers {
            if controller.segment != region.segment {
                continue;
            }

            let guard = match controller.iova_allocator.lock() {
                Ok(guard) => guard,
                Err(_) => {
                    log::warn!(
                        "[IOMMU] iova_allocator lock poisoned while reserving RMRR: seg={}",
                        region.segment
                    );
                    continue;
                }
            };

            let alloc = match guard.as_ref() {
                Some(alloc) => alloc,
                None => {
                    log::warn!(
                        "[IOMMU] iova_allocator not initialized while reserving RMRR: seg={}",
                        region.segment
                    );
                    continue;
                }
            };

            let alloc_base = alloc.base();
            let alloc_end = alloc_base.saturating_add(alloc.size());
            let clamped_start = start.max(alloc_base);
            let clamped_end = end.min(alloc_end);
            if clamped_end <= clamped_start {
                continue;
            }

            let reserve_size = clamped_end - clamped_start;
            match alloc.reserve(clamped_start, reserve_size) {
                Ok(()) | Err(IommuError::AlreadyMapped) => {}
                Err(IommuError::InvalidAddress) => {
                    log::warn!(
                        "[IOMMU] RMRR reservation outside IOVA window: seg={}, range={:#x}-{:#x}",
                        region.segment,
                        clamped_start,
                        clamped_end
                    );
                }
                Err(err) => {
                    log::warn!(
                        "[IOMMU] Failed to reserve RMRR IOVA: seg={}, err={:?}",
                        region.segment,
                        err
                    );
                }
            }
        }
    }

    init_registry(registry);

    #[cfg(not(test))]
    {
        // Register Intel VT-d driver backend (Phase 1 abstraction hook).
        super::super::IntelIommuDriver::register_driver();
        crate::io::iommu::api::set_global_dma_mapping_allowed(config.allow_global_mappings);

        // Create default domain 0 for generic DMA mappings (used by panic DMA pool, etc.)
        if let Some(driver) = crate::io::iommu::registry::get_iommu_driver() {
            match driver.create_domain(None, IommuDomainType::Translated) {
                Ok(id) => log::info!("IOMMU default domain created: ID={}", id),
                Err(e) => log::warn!("Failed to create default IOMMU domain: {:?}", e),
            }
        }

        // Initialize IOMMU Group Manager
        IOMMU_GROUP_MANAGER.call_once(|| IommuGroupManager::new());
    }

    Ok(())
}

/// Initialize the global IOMMU (legacy wrapper)
pub unsafe fn init_iommu(mmio_base: u64) -> Result<(), IommuError> {
    // Legacy initialization for single IOMMU (segment 0) with default config
    let config = IommuConfig::default();
    let mmio_virt = phys_to_virt_usize(mmio_base) as u64;

    let mut controller = IommuController::new(mmio_virt, 0);
    unsafe {
        controller.init(config.scalable_mode)?;
    }

    let iova_bits = controller.max_guest_address_width().min(48).max(12);
    let iova_base = crate::io::iommu::PAGE_SIZE_4K;
    let iova_limit = 1u64 << iova_bits;
    let iova_size = iova_limit.saturating_sub(iova_base);
    if iova_size == 0 {
        log::warn!("[IOMMU] Skipping IOVA allocator init: invalid size");
    } else {
        let _ = controller.init_iova(iova_base, iova_size);
    }

    log::info!("IOMMU initialized at 0x{:X}\n", mmio_base);

    controller.command_queue =
        Some(crate::io::iommu::cmdqueue::CommandQueue::new_with_numa(None));
    let controller = Arc::new(controller);

    #[cfg(not(test))]
    {
        if controller.command_queue.is_some() {
            spawn_command_queue_worker(Arc::clone(&controller));
        }
    }

    let registry = IommuRegistry::new(
        alloc::vec![Arc::clone(&controller)],
        Vec::new(),
        IommuConfig::default(),
    );

    init_registry(registry);
    super::super::IntelIommuDriver::register_driver();
    crate::io::iommu::api::set_global_dma_mapping_allowed(cfg!(debug_assertions));
    Ok(())
}
