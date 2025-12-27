// ============================================================================
// kernel/src/io/iommu/intel/controller/init_global.rs
// ============================================================================

//! Global Initialization (from ACPI)
//!
//! This module contains functions to initialize the IOMMU subsystem
//! from ACPI DMAR tables or manually.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::io::iommu::tables::phys_to_virt_usize;
use crate::io::iommu::config::{IommuConfig, ReservedMemoryRegion};
use crate::io::iommu::types::{DeviceId, IommuError};
// Intel-specific imports
use super::super::registry::{IommuRegistry, init_registry};
use super::IommuController;

#[cfg(not(test))]
use crate::io::iommu::groups::{IOMMU_GROUP_MANAGER, IommuGroupManager};

use super::fault::FaultHandler;
use super::init::CapabilityManager;
use super::qi_init::QIManager;
// use crate::io::acpi::dmar; // For parse_dmar - verified this path exists in kernel/src/io/acpi/dmar.rs

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

        let mut controller = IommuController::new(mmio_virt, unit.segment);

        unsafe {
            if let Err(e) = controller.init() {
                log::error!("Failed to initialize IOMMU controller: {:?}", e);
                continue;
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

        controllers.push(Arc::new(controller));
        if unit.include_all {
            default_idx = Some(controllers.len() - 1);
        }
    }

    if controllers.is_empty() {
        return Err(IommuError::NotPresent);
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

    // Apply Reserved Regions (RMRR)
    // Need to do this before publishing registry because we need mutable access to controllers
    for region in &registry.reserved_regions {
        for device_id in &region.devices {
            let mut target_idx = None;

            // First pass
            for (i, c) in registry.controllers.iter().enumerate() {
                if c.segment != region.segment {
                    continue;
                }
                if c.include_all {
                    continue;
                }
                let (bus, dev, func) = (device_id.bus, device_id.device, device_id.function);
                if c.device_in_scope(bus, dev, func) {
                    target_idx = Some(i);
                    break;
                }
            }
            // Second pass
            if target_idx.is_none() {
                for (i, c) in registry.controllers.iter().enumerate() {
                    if c.segment == region.segment && c.include_all {
                        target_idx = Some(i);
                        break;
                    }
                }
            }
            // Fallback
            let _ = target_idx;
        }
    }

    init_registry(registry);

    #[cfg(not(test))]
    {
        // Register Intel VT-d driver backend (Phase 1 abstraction hook).
        super::super::IntelIommuDriver::register_driver();

        // Initialize IOMMU Group Manager
        IOMMU_GROUP_MANAGER.call_once(|| IommuGroupManager::new());
    }

    Ok(())
}

/// Initialize the global IOMMU (legacy wrapper)
pub unsafe fn init_iommu(mmio_base: u64) -> Result<(), IommuError> {
    // Legacy initialization for single IOMMU (segment 0) with default config
    let mmio_virt = phys_to_virt_usize(mmio_base) as u64;

    let mut controller = IommuController::new(mmio_virt, 0);
    unsafe {
        controller.init()?;
    }

    log::info!("IOMMU initialized at 0x{:X}\n", mmio_base);

    let registry = IommuRegistry::new(
        alloc::vec![Arc::new(controller)],
        Vec::new(),
        IommuConfig::default(),
    );

    init_registry(registry);
    super::super::IntelIommuDriver::register_driver();
    Ok(())
}
