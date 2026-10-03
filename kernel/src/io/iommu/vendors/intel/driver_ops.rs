// ============================================================================
// kernel/src/io/iommu/vendors/intel/driver_ops.rs
// ============================================================================

use super::*;
use crate::io::iommu::common::dma::mapping_outcome::{DeviceMapFailure, DeviceMappedRange};

mod domain_query;
mod invalidation;

#[inline]
fn controller_cq_submit_error(controller: &controller::IommuController) -> IommuError {
    match controller.command_queue_ref() {
        Some(cq) if cq.is_poisoned() => IommuError::Poisoned,
        _ => IommuError::HardwareError,
    }
}

#[inline]
fn controller_cq_completion_error(rc: i32) -> IommuError {
    if rc == crate::io::iommu::runtime::command::queue::RESULT_POISONED {
        IommuError::Poisoned
    } else {
        IommuError::HardwareError
    }
}

impl IntelIommuDriver {
    pub(crate) fn is_enabled(&self) -> bool {
        if self.controller.is_some() {
            return true;
        }
        get_iommu_registry().map_or(false, |r| !r.controllers.is_empty())
    }

    pub(crate) fn enable(&self) -> Result<(), IommuError> {
        if let Some(ref controller) = self.controller {
            unsafe {
                return controller.enable();
            }
        }
        let registry = self.registry()?;
        for (_idx, controller) in registry.controllers.iter().enumerate() {
            unsafe {
                controller.enable()?;
            }
        }
        Ok(())
    }

    pub(crate) fn disable(&self) -> Result<(), IommuError> {
        if let Some(ref controller) = self.controller {
            unsafe {
                return controller.disable();
            }
        }
        let registry = self.registry()?;
        for (_idx, controller) in registry.controllers.iter().enumerate() {
            unsafe {
                controller.disable()?;
            }
        }
        Ok(())
    }

    pub(crate) fn handle_fault(&self) {
        if let Some(ref controller) = self.controller {
            controller.process_faults();
            return;
        }
        if let Ok(registry) = self.registry() {
            for controller in &registry.controllers {
                controller.process_faults();
            }
        }
    }

    pub(crate) fn wake_invalidation_waiters(&self) {
        if let Ok(registry) = self.registry() {
            for controller in &registry.controllers {
                controller.wake_invalidation_waiter();
            }
        }
    }

    pub(crate) fn set_security_notifier(&self, notifier: Arc<dyn SecurityNotifier>) -> bool {
        let registry = match self.registry() {
            Ok(registry) => registry,
            Err(_) => return false,
        };

        let mut any_set = false;
        for controller in &registry.controllers {
            if controller.set_security_notifier(Arc::clone(&notifier)) {
                any_set = true;
            }
        }
        any_set
    }

    pub(crate) fn map_interrupt(
        &self,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        vector: u8,
        destination: crate::cpu::ApicId,
        logical: bool,
    ) -> Result<u16, IommuError> {
        let registry = self.registry()?;
        let controller_idx = registry
            .find_controller_index_for_device(segment, bus, device, function)
            .ok_or(IommuError::NotPresent)?;
        let controller = registry
            .controllers
            .get(controller_idx)
            .ok_or(IommuError::NotPresent)?;

        if !controller.is_interrupt_remapping_enabled() {
            return Err(IommuError::NotSupported);
        }

        controller.allocate_irte(segment, bus, device, function, vector, destination, logical)
    }

    pub(crate) fn get_remap_msi_message(&self, handle: u16) -> (u64, u32) {
        crate::io::iommu::runtime::irq::encode_remappable_msi_message(handle)
    }

    pub(crate) fn domain_id_for_device(&self, device: &DeviceId) -> Result<u16, IommuError> {
        if let Some(ref controller) = self.controller {
            return controller
                .get_domain_for_device(*device)
                .map(|d| d.unwrap_or(0));
        }
        let registry = self.registry()?;
        if registry.controllers.is_empty() {
            return Err(IommuError::NotPresent);
        }

        for controller in &registry.controllers {
            match controller.get_domain_for_device(*device) {
                Ok(Some(domain_id)) => return Ok(domain_id),
                Ok(None) => continue,
                Err(_) => continue,
            }
        }

        Err(IommuError::DomainNotFound)
    }

    pub(crate) unsafe fn map_for_device(
        &self,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
    ) -> Result<DeviceMappedRange, DeviceMapFailure> {
        unsafe { self.map_for_device_with_perms(device, phys_addr, size, true, true) }
    }

    pub(crate) unsafe fn map_for_device_with_perms(
        &self,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<DeviceMappedRange, DeviceMapFailure> {
        validate_dma_params(phys_addr, size)?;

        if let Some(ref controller) = self.controller {
            if let Ok(Some(domain_id)) = controller.get_domain_for_device(*device) {
                if let Some(domain_arc) = controller.domain(domain_id) {
                    return unsafe {
                        apply_mapping_sync(
                            controller,
                            &domain_arc,
                            device,
                            phys_addr.as_u64(),
                            size,
                            read,
                            write,
                        )
                    };
                }
            }
            return Err(IommuError::DomainNotFound.into());
        }

        let registry = self.registry()?;
        if registry.controllers.is_empty() {
            return Err(IommuError::NotPresent.into());
        }

        for controller in &registry.controllers {
            if let Ok(Some(domain_id)) = controller.get_domain_for_device(*device) {
                if let Some(domain_arc) = controller.domain(domain_id) {
                    return unsafe {
                        apply_mapping_sync(
                            controller,
                            &domain_arc,
                            device,
                            phys_addr.as_u64(),
                            size,
                            read,
                            write,
                        )
                    };
                }
            }
        }

        Err(IommuError::DomainNotFound.into())
    }

    pub(crate) async unsafe fn map_for_device_async(
        &self,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
    ) -> Result<DeviceMappedRange, DeviceMapFailure> {
        validate_dma_params(phys_addr, size)?;

        if let Some(controller) = &self.controller {
            let domain_id = controller
                .get_domain_for_device(*device)?
                .ok_or(IommuError::DomainNotFound)?;
            let domain = controller
                .domain(domain_id)
                .ok_or(IommuError::DomainNotFound)?;
            // SAFETY: this unsafe boundary inherits the caller's exclusive RAM
            // lifetime obligation until the returned mapping is retired.
            return unsafe {
                apply_mapping_async(controller, &domain, device, phys_addr.as_u64(), size).await
            };
        }

        let registry = self.registry()?;
        if registry.controllers.is_empty() {
            return Err(IommuError::NotPresent.into());
        }

        for controller in &registry.controllers {
            if let Ok(Some(domain_id)) = controller.get_domain_for_device(*device) {
                if let Some(domain_arc) = controller.domain(domain_id) {
                    return unsafe {
                        apply_mapping_async(
                            controller,
                            &domain_arc,
                            device,
                            phys_addr.as_u64(),
                            size,
                        )
                    }
                    .await;
                }
            }
        }

        Err(IommuError::DomainNotFound.into())
    }

    pub(crate) fn create_domain(
        &self,
        numa_node: Option<usize>,
        domain_type: IommuDomainType,
    ) -> Result<u16, IommuError> {
        if let Some(ref controller) = self.controller {
            return controller.create_domain(numa_node, domain_type);
        }
        let registry = self.registry()?;
        if registry.controllers.is_empty() {
            return Err(IommuError::NotPresent);
        }

        // SECURITY: Create the domain on ALL controllers to ensure Domain ID consistency
        // across the entire IOMMU topology. This is critical for global DMA (Domain 0)
        // to function correctly on multi-controller systems.
        let mut first_id = None;
        for (idx, controller) in registry.controllers.iter().enumerate() {
            let id = controller.create_domain(numa_node, domain_type)?;
            if first_id.is_none() {
                first_id = Some(id);
            } else if first_id != Some(id) {
                log::error!(
                    "[IOMMU][SECURITY] Domain ID mismatch during creation on controller {}: expected {}, got {}. Consistency broken.",
                    idx,
                    first_id.unwrap(),
                    id
                );
                // SECURITY: Refuse to proceed with inconsistent domain IDs across controllers.
                // This prevents subtle isolation bypasses on multi-IOMMU systems.
                return Err(IommuError::HardwareError);
            }
        }

        first_id.ok_or(IommuError::NotPresent)
    }

    pub(crate) fn destroy_domain(&self, domain_id: u16) -> Result<(), IommuError> {
        if let Some(ref controller) = self.controller {
            return controller.destroy_domain(domain_id);
        }
        let registry = self.registry()?;
        // Try all controllers as the domain could be on any of them
        let mut found = false;
        for controller in &registry.controllers {
            if controller.domain(domain_id).is_some() {
                controller.destroy_domain(domain_id)?;
                found = true;
            }
        }
        if found {
            Ok(())
        } else {
            Err(IommuError::DomainNotFound)
        }
    }

    pub(crate) fn attach_device(&self, device: DeviceId, domain_id: u16) -> Result<(), IommuError> {
        if let Some(ref controller) = self.controller {
            return controller.attach_device(device, domain_id);
        }
        let registry = self.registry()?;
        let controller_idx = registry
            .find_controller_index_for_device(
                device.segment,
                device.bus,
                device.device,
                device.function,
            )
            .ok_or(IommuError::DeviceNotFound)?;
        let controller = registry
            .controllers
            .get(controller_idx)
            .ok_or(IommuError::DeviceNotFound)?;
        controller.attach_device(device, domain_id)
    }

    pub(crate) fn detach_device(&self, device: DeviceId) -> Result<(), IommuError> {
        if let Some(ref controller) = self.controller {
            return controller.detach_device(device);
        }
        let registry = self.registry()?;
        let controller_idx = registry
            .find_controller_index_for_device(
                device.segment,
                device.bus,
                device.device,
                device.function,
            )
            .ok_or(IommuError::DeviceNotFound)?;
        let controller = registry
            .controllers
            .get(controller_idx)
            .ok_or(IommuError::DeviceNotFound)?;
        controller.detach_device(device)
    }

    pub(crate) fn set_domain_numa(
        &self,
        domain_id: u16,
        numa_node: Option<usize>,
    ) -> Result<(), IommuError> {
        let registry = self.registry()?;
        for controller in &registry.controllers {
            if controller.domain(domain_id).is_some() {
                return controller.set_domain_numa(domain_id, numa_node);
            }
        }
        Err(IommuError::DomainNotFound)
    }

    pub fn isolate_device(&self, device: DeviceId) -> Result<(), IommuError> {
        let registry = self.registry()?;
        let controller_idx = registry
            .find_controller_index_for_device(
                device.segment,
                device.bus,
                device.device,
                device.function,
            )
            .unwrap_or(0);

        if let Some(controller) = registry.controllers.get(controller_idx) {
            // Disable context entry in hardware tables
            let (need_invalidation, domain_id) =
                controller.disable_device_context_entry(device.bus, device.device, device.function);

            if need_invalidation {
                // Perform necessary invalidations (IOTLB, context cache) and notify security
                controller.perform_isolation_invalidation(
                    device.requester_id(),
                    domain_id,
                    crate::io::iommu::runtime::security::IsolationReason::PolicyViolation,
                );
            }
            Ok(())
        } else {
            Err(IommuError::HardwareError)
        }
    }
}
