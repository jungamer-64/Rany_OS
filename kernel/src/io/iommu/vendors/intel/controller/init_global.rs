// ============================================================================
// kernel/src/io/iommu/vendors/intel/controller/init_global.rs
// ============================================================================

//! Global Initialization (from ACPI)
//!
//! This module contains functions to initialize the IOMMU subsystem
//! from owned, checksum-validated ACPI DMAR catalog tables.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::io::iommu::runtime::config::{IommuConfig, ReservedMemoryRegion};
use crate::io::iommu::types::IommuError;
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

pub(crate) async fn command_queue_worker() -> Result<(), IommuError> {
    use core::future::{Future, poll_fn};
    use core::task::Poll;
    let registry =
        super::super::registry::get_iommu_registry().ok_or(IommuError::NotInitialized)?;
    // LOOP_PROOF: mode=event; reason=The service host owns the worker, each finite pass yields and then awaits work on the immutable set of owned controller queues.;
    loop {
        // LOOP_PROOF: mode=bounded; reason=One pass handles at most COMMAND_QUEUE_BATCH requests per firmware controller.;
        for controller in &registry.controllers {
            let cq = controller
                .command_queue_ref()
                .ok_or(IommuError::NotInitialized)?;
            if cq.is_poisoned() {
                return Err(IommuError::Poisoned);
            }
            cq.process_up_to(
                |kind| controller.handle_command_queue_entry(kind).map_err(|_| ()),
                COMMAND_QUEUE_BATCH,
            );
        }
        crate::task::yield_now().await;
        poll_fn(|cx| {
            // LOOP_PROOF: mode=bounded; reason=Each queue is checked once, with notification registration and the queue's own second check closing the sleep race.;
            for controller in &registry.controllers {
                let Some(cq) = controller.command_queue_ref() else {
                    return Poll::Ready(());
                };
                let wait = cq.wait_for_work();
                let mut wait = core::pin::pin!(wait);
                if wait.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(());
                }
            }
            Poll::Pending
        })
        .await;
    }
}

#[cfg(not(test))]
pub(crate) fn start_runtime_services() -> Result<usize, IommuError> {
    let Some(registry) = super::super::registry::get_iommu_registry() else {
        return Ok(0);
    };
    // Queue backing is admitted before tasks and before interrupts can publish
    // notifications. The host retains each successful admission on partial failure.
    // LOOP_PROOF: mode=bounded; reason=The registry's firmware controller list is immutable and finite.;
    for controller in &registry.controllers {
        controller.ensure_command_queue()?;
    }
    let apic = crate::drivers::apic::local_apic().map_err(|_| IommuError::RuntimeUnavailable)?;
    let destination = u8::try_from(apic.id()).map_err(|_| IommuError::NotSupported)?;
    crate::services::start_intel_services()?;
    let mut started = 0;
    // LOOP_PROOF: mode=bounded; reason=Each controller's interrupt source is armed at most once after both host-owned workers were admitted.;
    for controller in &registry.controllers {
        if controller.runtime_services_started() {
            continue;
        }
        controller.enable_fault_interrupt(RUNTIME_INTERRUPT_VECTOR, destination);
        if controller.is_queued_invalidation_enabled() {
            controller.enable_queued_invalidation_interrupt(RUNTIME_INTERRUPT_VECTOR, destination);
        }
        controller.mark_runtime_services_started();
        started += 1;
    }
    Ok(started)
}

/// Initializes IOMMU controllers from owned ACPI DMAR bytes.
pub fn init_iommu_from_dmar(dmar: &[u8], config: IommuConfig) -> Result<(), IommuError> {
    if super::super::registry::get_iommu_registry().is_some() {
        return Err(IommuError::AlreadyInitialized);
    }
    // Initialize security subsystem (protected regions like APIC)
    crate::io::iommu::runtime::security::init();

    let catalogued = crate::platform::firmware::tables()
        .and_then(|catalog| catalog.first(crate::drivers::acpi::TableSignature::DMAR))
        .ok_or(IommuError::NotPresent)?;
    if catalogued.bytes() != dmar {
        return Err(IommuError::RegisterMapping(
            kernel_api::mmio::MmioAcquireError::PermissionDenied,
        ));
    }
    // Parse DMAR using canonical ACPI parser from drivers/acpi
    let dmar_info = match crate::drivers::acpi::dmar::parse(dmar) {
        Ok(info) => info,
        Err(e) => {
            log::error!("Failed to parse DMAR: {:?}", e);
            return Err(IommuError::HardwareError);
        }
    };

    // Initialize controllers from DRHD units
    let controllers = init_controllers_from_drhd(&dmar_info)?;

    // Build reserved region list from RMRR
    let reserved_regions = build_rmrr_regions(&dmar_info)?;

    let registry = IommuRegistry {
        controllers,
        reserved_regions,
    };

    #[cfg(not(test))]
    early_stage_marker("publishing registry");
    let registry = init_registry(registry)?;

    // The registry retains all mappings and hardware tables before the first
    // register publication. Timeout/error never destroys an uncertain hardware
    // reference. Boot observes failure and cannot admit dependent devices.
    // LOOP_PROOF: mode=bounded; reason=Every published controller is initialized once from its immutable firmware unit.;
    for controller in &registry.controllers {
        unsafe {
            controller.init(config.scalable_mode)?;
            init_controller_iova(controller)?;
            init_controller_qi(controller)?;
            init_controller_interrupt_remapping(controller, &dmar_info);
        }
    }
    apply_rmrr_reservations(registry)?;
    #[cfg(not(test))]
    finalize_iommu_setup()?;

    Ok(())
}

/// Initialize IOMMU controllers from DRHD units parsed from the DMAR table.
fn init_controllers_from_drhd(
    dmar_info: &crate::drivers::acpi::dmar::DmarInfo,
) -> Result<Vec<Arc<IommuController>>, IommuError> {
    let mut controllers = Vec::new();
    controllers
        .try_reserve_exact(dmar_info.drhd_units.len())
        .map_err(|_| IommuError::MetadataAllocation)?;

    // LOOP_PROOF: mode=bounded; reason=The checksum-validated DMAR contains a finite DRHD list, all metadata is admitted before hardware publication.;
    for unit in &dmar_info.drhd_units {
        log::info!(
            "Initializing IOMMU Controller at {:#x} (Segment: {}, All: {})",
            unit.register_base,
            unit.segment,
            unit.include_all
        );

        let registers = crate::resource_registry::mmio::acquire_intel_iommu(unit)
            .map_err(IommuError::RegisterMapping)?;
        let extent = registers.len() as u64;
        let mut controller = IommuController::new(registers, unit.segment)?;
        let scopes = super::scope::resolve(unit.segment, &unit.devices)?;
        controller.device_scopes = scopes.scopes;
        controller.scope_resources = scopes.resources;
        controller.include_all = unit.include_all;
        crate::io::iommu::runtime::security::register_protected_region(
            unit.register_base,
            extent,
            "Intel VT-d IOMMU",
        );
        controllers.push(Arc::try_new(controller).map_err(|_| IommuError::MetadataAllocation)?);
    }

    if controllers.is_empty() {
        return Err(IommuError::NotPresent);
    }

    Ok(controllers)
}

/// Initialize IOVA allocator for a single controller (cap at 36 bits).
unsafe fn init_controller_iova(controller: &IommuController) -> Result<(), IommuError> {
    let iova_bits = controller.max_guest_address_width().clamp(12, 36);
    let iova_base = crate::mm::types::PAGE_SIZE_4K as u64;
    controller.init_iova(iova_base, (1u64 << iova_bits) - iova_base)
}

unsafe fn init_controller_qi(controller: &IommuController) -> Result<(), IommuError> {
    if controller.supports_queued_invalidation() {
        controller.init_queued_invalidation(8)?;
        unsafe {
            controller.enable_queued_invalidation()?;
        }
    }
    Ok(())
}

unsafe fn init_controller_interrupt_remapping(
    controller: &IommuController,
    dmar: &crate::drivers::acpi::dmar::DmarInfo,
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

/// RMRR addresses and PCI scopes are validated before any hardware pointer
/// publication. The registry retains all resources used to resolve the paths.
fn build_rmrr_regions(
    dmar: &crate::drivers::acpi::dmar::DmarInfo,
) -> Result<Vec<ReservedMemoryRegion>, IommuError> {
    let mut regions = Vec::new();
    regions
        .try_reserve_exact(dmar.rmrr_regions.len())
        .map_err(|_| IommuError::MetadataAllocation)?;
    // LOOP_PROOF: mode=bounded; reason=Every checksum-validated RMRR descriptor is resolved once.;
    for region in &dmar.rmrr_regions {
        let end = region
            .limit
            .checked_add(1)
            .ok_or(IommuError::InvalidAddress)?;
        if !region.base.is_multiple_of(4096) || !end.is_multiple_of(4096) || end <= region.base {
            return Err(IommuError::InvalidAlignment);
        }
        let scopes = super::scope::resolve(region.segment, &region.devices)?;
        if scopes.scopes.is_empty() {
            return Err(IommuError::FirmwareScope);
        }
        regions.push(ReservedMemoryRegion {
            segment: region.segment,
            base: region.base,
            limit: region.limit,
            scopes: scopes.scopes,
            _resources: scopes.resources,
        });
    }
    Ok(regions)
}

/// Reserve each identity-mapped RMRR portion inside the allocator's window
/// before any ordinary DMA address is admitted. Regions outside the window
/// cannot overlap addresses allocated from it and need no bitmap reservation.
fn apply_rmrr_reservations(registry: &IommuRegistry) -> Result<(), IommuError> {
    // LOOP_PROOF: mode=bounded; reason=The published registry contains finite immutable RMRR and controller lists.;
    for region in &registry.reserved_regions {
        let end = region
            .limit
            .checked_add(1)
            .ok_or(IommuError::InvalidAddress)?;
        // LOOP_PROOF: mode=bounded; reason=Each controller in the region's segment reserves the applicable finite interval exactly once.;
        for controller in &registry.controllers {
            if controller.segment != region.segment {
                continue;
            }
            let guard = controller
                .iova_allocator
                .lock()
                .map_err(|_| IommuError::Poisoned)?;
            let allocator = guard.as_ref().ok_or(IommuError::NotInitialized)?;
            let allocator_end = allocator
                .base()
                .checked_add(allocator.size())
                .ok_or(IommuError::InvalidAddress)?;
            let start = region.base.max(allocator.base());
            let end = end.min(allocator_end);
            if start < end {
                allocator.reserve(start, end - start)?;
            }
        }
    }
    Ok(())
}

/// Final setup: register driver and synchronously enable translation.
#[cfg(not(test))]
fn finalize_iommu_setup() -> Result<(), IommuError> {
    super::super::IntelIommuDriver::register_driver();

    // Enable IOMMU translation directly via the Intel registry.
    // This avoids reliance on the global driver pointer (IOMMU_DRIVER)
    // which may not be accessible from enable_iommu() in some configurations.
    if let Some(registry) = super::super::registry::get_iommu_registry() {
        for (idx, controller) in registry.controllers.iter().enumerate() {
            early_stage_marker_controller("translation enable start", idx);
            unsafe {
                controller.enable()?;
            }
            early_stage_marker_controller("translation enable done", idx);
        }
        early_stage_marker("runtime services deferred");
    }
    Ok(())
}
