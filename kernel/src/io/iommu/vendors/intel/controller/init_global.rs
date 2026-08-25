// ============================================================================
// kernel/src/io/iommu/vendors/intel/controller/init_global.rs
// ============================================================================

//! Global Initialization (from ACPI)
//!
//! This module contains functions to initialize the IOMMU subsystem
//! from ACPI DMAR tables or manually.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::io::iommu::common::tables::phys_to_virt_usize;
use crate::io::iommu::runtime::config::{IommuConfig, ReservedMemoryRegion};
use crate::io::iommu::types::{DeviceId, IommuError};
// Intel-specific imports
use super::super::registry::{IommuRegistry, init_registry};
use super::IommuController;

#[cfg(not(test))]
use super::dma::DomainManager;
use super::fault::FaultHandler;
use super::init::CapabilityManager;
use super::iova::IovaManager;
use super::ir::InterruptRemapMode;
use super::qi_init::QIManager;
use super::qi_ops::InvalidationOps;

fn align_down(value: u64, align: usize) -> u64 {
    crate::util::align_down_u64(value, align as u64)
}

fn align_up(value: u64, align: usize) -> u64 {
    crate::util::align_up_u64(value, align as u64)
}

#[cfg(not(test))]
const COMMAND_QUEUE_BATCH: usize = 64;

const RUNTIME_INTERRUPT_VECTOR: u8 = 0x50;

#[cfg(not(test))]
fn early_stage_marker(stage: &str) {
    crate::io::log::early_print("[IOMMU][BOOT] ");
    crate::io::log::early_print(stage);
    crate::io::log::early_print("\n");
}

#[cfg(not(test))]
fn early_stage_marker_controller(stage: &str, idx: usize) {
    crate::io::log::early_print("[IOMMU][BOOT] ");
    crate::io::log::early_print(stage);
    crate::io::log::early_print(" controller ");
    crate::io::log::early_print_dec(idx as u64);
    crate::io::log::early_print("\n");
}

#[cfg(not(test))]
async fn command_queue_worker(controller: Arc<IommuController>) {
    // LOOP_PROOF: mode=event; reason=Command worker exits when queue is unavailable and otherwise awaits new work after finite processing.;
    loop {
        let cq = match controller.command_queue_ref() {
            Some(cq) => cq,
            None => break,
        };
        let processed = cq.process_up_to(
            |kind| controller.handle_command_queue_entry(kind).map_err(|_| ()),
            COMMAND_QUEUE_BATCH,
        );
        if processed == 0 {
            cq.wait_for_work().await;
            if cq.is_poisoned() {
                break;
            }
        }
    }
}

#[cfg(not(test))]
fn spawn_command_queue_worker(controller: Arc<IommuController>) -> Result<(), IommuError> {
    let future = command_queue_worker(controller);
    crate::task::spawn(future, crate::task::TaskPlacement::Any)
        .map(|_| ())
        .map_err(|_| IommuError::RuntimeUnavailable)
}

fn activate_runtime_services_for_controller(
    controller: &Arc<IommuController>,
) -> Result<bool, IommuError> {
    if controller.runtime_services_started() {
        return Ok(false);
    }

    controller.ensure_command_queue();

    #[cfg(not(test))]
    spawn_command_queue_worker(Arc::clone(controller))?;

    controller.enable_fault_interrupt(RUNTIME_INTERRUPT_VECTOR);

    if controller.is_queued_invalidation_enabled() {
        controller.enable_queued_invalidation_interrupt(RUNTIME_INTERRUPT_VECTOR);
    }

    controller.mark_runtime_services_started();
    Ok(true)
}

#[cfg(not(test))]
pub(crate) fn start_runtime_services() -> Result<usize, IommuError> {
    let Some(registry) = super::super::registry::get_iommu_registry() else {
        return Ok(0);
    };

    super::fault::spawn_fault_handler_task().map_err(|_| IommuError::RuntimeUnavailable)?;

    let mut started = 0;
    for controller in &registry.controllers {
        if activate_runtime_services_for_controller(controller)? {
            started += 1;
        }
    }

    Ok(started)
}

/// Initializes IOMMU controllers from owned ACPI DMAR bytes.
pub fn init_iommu_from_dmar(dmar: &[u8], config: IommuConfig) -> Result<(), IommuError> {
    // Initialize security subsystem (protected regions like APIC)
    crate::io::iommu::runtime::security::init();

    // Parse DMAR using canonical ACPI parser from drivers/acpi
    let dmar_info = match acpi_driver::dmar::parse(dmar) {
        Ok(info) => info,
        Err(e) => {
            log::error!("Failed to parse DMAR: {:?}", e);
            return Err(IommuError::HardwareError);
        }
    };

    // Initialize controllers from DRHD units
    let (controllers, default_idx) = unsafe { init_controllers_from_drhd(&dmar_info, &config) }?;

    let default_iommu_idx = default_idx.or(Some(0));

    // Build reserved region list from RMRR
    let reserved_regions = build_rmrr_regions(&dmar_info);

    let registry = IommuRegistry {
        controllers,
        default_iommu_idx,
        reserved_regions,
    };

    // Apply Reserved Regions (RMRR) before publishing registry
    apply_rmrr_reservations(&registry);

    #[cfg(not(test))]
    early_stage_marker("publishing registry");
    init_registry(registry);

    #[cfg(not(test))]
    finalize_iommu_setup();

    Ok(())
}

/// Initialize IOMMU controllers from DRHD units parsed from the DMAR table.
unsafe fn init_controllers_from_drhd(
    dmar_info: &acpi_driver::dmar::DmarInfo,
    config: &IommuConfig,
) -> Result<(Vec<Arc<IommuController>>, Option<usize>), IommuError> {
    let mut controllers = Vec::new();
    let mut default_idx = None;

    for unit in &dmar_info.drhd_units {
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

        // Security: Register IOMMU register range as protected to prevent DMA access
        crate::io::iommu::runtime::security::register_protected_region(
            unit.register_base,
            8192, // VT-d registers are at least 4KB, but can be 8KB with extended caps
            "Intel VT-d IOMMU",
        );

        unsafe {
            if let Err(e) = controller.init(config.scalable_mode) {
                log::error!("Failed to initialize IOMMU controller: {:?}", e);
                continue;
            }

            init_controller_iova(&mut controller);
            init_controller_qi(&mut controller);
            init_controller_interrupt_remapping(&mut controller, &dmar_info);
        }

        controllers.push(Arc::new(controller));
        if unit.include_all {
            default_idx = Some(controllers.len() - 1);
        }
    }

    if controllers.is_empty() {
        return Err(IommuError::NotPresent);
    }

    Ok((controllers, default_idx))
}

/// Initialize IOVA allocator for a single controller (cap at 36 bits).
unsafe fn init_controller_iova(controller: &mut IommuController) {
    let iova_bits = controller.max_guest_address_width().min(36).max(12);
    let iova_base: u64 = crate::mm::types::PAGE_SIZE_4K as u64;
    let iova_limit = 1u64 << iova_bits;
    let iova_size = iova_limit.saturating_sub(iova_base);
    if iova_size == 0 {
        log::warn!("[IOMMU] Skipping IOVA allocator init: invalid size");
    } else if let Err(e) = controller.init_iova(iova_base, iova_size) {
        log::warn!("[IOMMU] Failed to init IOVA allocator: {:?}", e);
    }
}

/// Setup Queued Invalidation if the controller supports it.
unsafe fn init_controller_qi(controller: &mut IommuController) {
    if controller.supports_queued_invalidation() {
        if let Err(e) = controller.init_queued_invalidation(8) {
            log::warn!("Failed to init Queued Invalidation: {:?}", e);
        } else if let Err(e) = unsafe { controller.enable_queued_invalidation() } {
            log::warn!("Failed to enable Queued Invalidation: {:?}", e);
        } else {
            log::info!("Queued Invalidation enabled for controller");
        }
    }
}

unsafe fn init_controller_interrupt_remapping(
    controller: &mut IommuController,
    dmar: &acpi_driver::dmar::DmarInfo,
) {
    if !dmar.supports_interrupt_remapping() {
        log::info!("DMAR does not advertise interrupt remapping");
        return;
    }
    if !controller.supports_interrupt_remapping() {
        log::warn!("DMAR advertises interrupt remapping but the VT-d unit does not support it");
        return;
    }
    if !controller.is_queued_invalidation_enabled() {
        log::warn!("VT-d interrupt remapping requires queued invalidation; leaving it disabled");
        return;
    }

    let apic_mode = match crate::drivers::apic::local_apic() {
        Ok(apic) => apic.mode(),
        Err(error) => {
            log::warn!("local APIC mode is unavailable for VT-d interrupt remapping: {error:?}");
            return;
        }
    };
    let mode = match apic_mode {
        crate::drivers::apic::ApicMode::XApic => InterruptRemapMode::XApic,
        crate::drivers::apic::ApicMode::X2Apic => {
            if !controller.supports_extended_interrupt_mode() {
                log::warn!(
                    "x2APIC is active but the VT-d unit cannot interpret full-width destinations"
                );
                return;
            }
            InterruptRemapMode::X2Apic
        }
    };

    if let Err(error) = controller.prepare_interrupt_remapping(mode) {
        log::warn!("failed to prepare VT-d interrupt remapping: {error:?}");
        return;
    }
    if let Err(error) = unsafe { controller.enable_interrupt_remapping() } {
        log::warn!("failed to enable VT-d interrupt remapping: {error:?}");
        return;
    }
    log::info!("VT-d interrupt remapping enabled in {mode:?} mode");
}

/// Build reserved memory regions from the DMAR RMRR entries.
fn build_rmrr_regions(dmar_info: &acpi_driver::dmar::DmarInfo) -> Vec<ReservedMemoryRegion> {
    let mut reserved_regions = Vec::new();

    for region in &dmar_info.rmrr_regions {
        let mut devices = Vec::new();
        for scope in &region.devices {
            let bus = scope.start_bus;
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

    reserved_regions
}

/// Apply RMRR reservations to IOVA allocators on all controllers.
fn apply_rmrr_reservations(registry: &IommuRegistry) {
    let page_size = crate::mm::types::PAGE_SIZE_4K;

    for region in &registry.reserved_regions {
        let start = align_down(region.base, page_size);
        let end = align_up(region.limit.saturating_add(1), page_size);
        if end <= start {
            continue;
        }

        for controller in &registry.controllers {
            if controller.segment != region.segment {
                continue;
            }
            reserve_rmrr_on_controller(controller, region.segment, start, end);
        }
    }
}

/// Reserve a single RMRR range on a controller's IOVA allocator.
fn reserve_rmrr_on_controller(
    controller: &Arc<IommuController>,
    segment: u16,
    start: u64,
    end: u64,
) {
    let guard = match controller.iova_allocator.lock() {
        Ok(guard) => guard,
        Err(_) => {
            log::warn!(
                "[IOMMU] iova_allocator lock poisoned while reserving RMRR: seg={}",
                segment
            );
            return;
        }
    };

    let alloc = match guard.as_ref() {
        Some(alloc) => alloc,
        None => {
            log::warn!(
                "[IOMMU] iova_allocator not initialized while reserving RMRR: seg={}",
                segment
            );
            return;
        }
    };

    let alloc_base = alloc.base();
    let alloc_end = alloc_base.saturating_add(alloc.size());
    let clamped_start = start.max(alloc_base);
    let clamped_end = end.min(alloc_end);
    if clamped_end <= clamped_start {
        return;
    }

    let reserve_size = clamped_end - clamped_start;
    match alloc.reserve(clamped_start, reserve_size) {
        Ok(()) | Err(IommuError::AlreadyMapped) => {}
        Err(IommuError::InvalidAddress) => {
            log::warn!(
                "[IOMMU] RMRR reservation outside IOVA window: seg={}, range={:#x}-{:#x}",
                segment,
                clamped_start,
                clamped_end
            );
        }
        Err(err) => {
            log::warn!(
                "[IOMMU] Failed to reserve RMRR IOVA: seg={}, err={:?}",
                segment,
                err
            );
        }
    }
}

/// Final setup: register driver and synchronously enable translation.
#[cfg(not(test))]
fn finalize_iommu_setup() {
    super::super::IntelIommuDriver::register_driver();

    // Enable IOMMU translation directly via the Intel registry.
    // This avoids reliance on the global driver pointer (IOMMU_DRIVER)
    // which may not be accessible from enable_iommu() in some configurations.
    if let Some(registry) = super::super::registry::get_iommu_registry() {
        for (idx, controller) in registry.controllers.iter().enumerate() {
            early_stage_marker_controller("translation enable start", idx);
            match unsafe { controller.enable() } {
                Ok(()) => {
                    early_stage_marker_controller("translation enable done", idx);
                }
                Err(_e) => {
                    crate::io::log::early_print("[IOMMU] Controller ");
                    crate::io::log::early_print_dec(idx as u64);
                    crate::io::log::early_print(" enable FAILED\n");
                }
            }
        }
        early_stage_marker("runtime services deferred");
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::io::iommu::vendors::intel::registers::ecap_bits;
    use core::sync::atomic::Ordering;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn controller_boot_phase_keeps_runtime_services_deferred() {
        let controller = IommuController::new(0x1000, 0);

        assert!(controller.command_queue_ref().is_none());
        assert!(!controller.runtime_services_started());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn runtime_activation_is_idempotent() {
        let mut controller = IommuController::new(0x1000, 0);
        controller.ecap = ecap_bits::ECAP_QI;
        controller.qi_enabled.store(true, Ordering::Release);
        let controller = Arc::new(controller);

        assert!(activate_runtime_services_for_controller(&controller).unwrap());
        let first_queue = controller
            .command_queue_ref()
            .map(|cq| cq as *const _)
            .expect("command queue should be installed");
        assert!(controller.runtime_services_started());

        assert!(!activate_runtime_services_for_controller(&controller).unwrap());
        let second_queue = controller
            .command_queue_ref()
            .map(|cq| cq as *const _)
            .expect("command queue should stay installed");
        assert_eq!(first_queue, second_queue);
    }
}
