// ============================================================================
// kernel/src/io/iommu/vendors/intel/driver_ops.rs
// ============================================================================

use super::*;

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
        dest_id: u32,
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

        controller.allocate_irte(segment, bus, device, function, vector, dest_id, logical)
    }

    pub(crate) fn get_remap_msi_message(&self, handle: u16) -> (u64, u32) {
        // Intel VT-d MSI/MSI-X format for Interrupt Remapping.
        // Spec Section 5.1.2.1: MSI and MSI-X Register Programming
        let handle_val = handle as u64;

        if handle_val < 0x8000 {
            // Standard case: Index fits in 15 bits of address (bits 19:5).
            // SHV=0 (Sub-handle Valid is bit 3).
            let address = 0xFEE0_0000 | (handle_val << 5);
            let data = 0;
            (address, data)
        } else {
            // High index case: Use SHV=1 (bit 3) and sub-handle in Data register.
            // Intel VT-d Spec §5.1.2.2:
            //   Effective Index = Address[19:5] (Interrupt Index) + Data[15:0] (Sub-handle)
            // Split handle: put high 15 bits in Address, low bit in Data sub-handle.
            let index_hi = (handle_val >> 1) & 0x7FFF;
            let sub_handle = handle_val & 1;
            let address = 0xFEE0_0000 | (1u64 << 3) | (index_hi << 5); // SHV=1 + Index
            let data = sub_handle as u32;
            (address, data)
        }
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
    ) -> Result<u64, IommuError> {
        unsafe { self.map_for_device_with_perms(device, phys_addr, size, true, true) }
    }

    pub(crate) unsafe fn map_for_device_with_perms(
        &self,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<u64, IommuError> {
        validate_dma_params(phys_addr, size)?;

        if let Some(ref controller) = self.controller {
            if let Ok(Some(domain_id)) = controller.get_domain_for_device(*device) {
                if let Some(domain_arc) = controller.domain(domain_id) {
                    let iova = allocate_iova_for_device(controller, device, size)?;
                    return unsafe {
                        apply_mapping_sync(
                            controller,
                            &domain_arc,
                            iova,
                            phys_addr.as_u64(),
                            size,
                            read,
                            write,
                        )
                    };
                }
            }
            return Err(IommuError::DomainNotFound);
        }

        let registry = self.registry()?;
        if registry.controllers.is_empty() {
            return Err(IommuError::NotPresent);
        }

        for controller in &registry.controllers {
            if let Ok(Some(domain_id)) = controller.get_domain_for_device(*device) {
                if let Some(domain_arc) = controller.domain(domain_id) {
                    let iova = allocate_iova_for_device(controller, device, size)?;
                    return unsafe {
                        apply_mapping_sync(
                            controller,
                            &domain_arc,
                            iova,
                            phys_addr.as_u64(),
                            size,
                            read,
                            write,
                        )
                    };
                }
            }
        }

        Err(IommuError::DomainNotFound)
    }

    pub(crate) async unsafe fn map_for_device_async(
        &self,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
    ) -> Result<u64, IommuError> {
        validate_dma_params(phys_addr, size)?;

        let registry = self.registry()?;
        if registry.controllers.is_empty() {
            return Err(IommuError::NotPresent);
        }

        for controller in &registry.controllers {
            if let Ok(Some(domain_id)) = controller.get_domain_for_device(*device) {
                if let Some(domain_arc) = controller.domain(domain_id) {
                    let iova = allocate_iova_for_device(controller, device, size)?;
                    return unsafe {
                        apply_mapping_async(
                            controller,
                            &domain_arc,
                            iova,
                            phys_addr.as_u64(),
                            size,
                        )
                    }
                    .await;
                }
            }
        }

        Err(IommuError::DomainNotFound)
    }

    pub(crate) fn unmap_for_device(
        &self,
        device: &DeviceId,
        iova: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        if let Some(ref controller) = self.controller {
            if let Ok(Some(domain_id)) = controller.get_domain_for_device(*device) {
                if let Some(domain_arc) = controller.domain(domain_id) {
                    return Self::perform_unmap(controller, device, &domain_arc, iova, size);
                }
            }
            return Err(IommuError::DomainNotFound);
        }

        let registry = self.registry()?;
        if registry.controllers.is_empty() {
            return Err(IommuError::NotPresent);
        }

        for controller in &registry.controllers {
            if let Ok(Some(domain_id)) = controller.get_domain_for_device(*device) {
                if let Some(domain_arc) = controller.domain(domain_id) {
                    return Self::perform_unmap(controller, device, &domain_arc, iova, size);
                }
            }
        }

        Err(IommuError::DomainNotFound)
    }

    /// Execute the actual unmap on a resolved domain on the caller thread.
    pub(super) fn perform_unmap(
        controller: &controller::IommuController,
        device: &DeviceId,
        domain_arc: &Arc<IommuDomain>,
        iova: u64,
        _size: u64,
    ) -> Result<(), IommuError> {
        // 1. Monitor page table releases to detect if paging-structure caches need clearing
        let pts_before = domain_arc
            .pending_pt_release
            .lock()
            .map(|p| p.len())
            .unwrap_or(0);

        let mapping = domain_arc.unmap(iova)?;
        let domain_id = domain_arc.id();

        let pts_after = domain_arc
            .pending_pt_release
            .lock()
            .map(|p| p.len())
            .unwrap_or(0);
        let pt_removed = pts_after > pts_before;

        if pt_removed {
            // SECURITY: Domain-wide invalidation to clear paging-structure caches.
            controller.invalidate_iotlb(domain_id, true)?;
            let _ = domain_arc.flush(controller, controller);
        } else {
            // Page-selective invalidation with ATS awareness
            controller.qi_invalidate_unmap(domain_id, device, iova, mapping.size as u64)?;
        }

        if let Err(IommuError::OutOfMemory) = controller.free_iova(iova, mapping.size) {
            // Quarantine full: Force global flush and immediate free.
            // This is safe because the global flush ensures no stale entries remain.
            if let Ok(_) = controller.invalidate_iotlb_global_sync() {
                let _ =
                    crate::io::iommu::common::interface::IommuHardwareContext::free_iova_immediate(
                        controller,
                        iova,
                        mapping.size,
                    );
            }
        }
        Ok(())
    }

    /// コマンドキュー経由で非同期 UnmapRegionDevice を実行する
    pub(super) async fn try_cq_unmap_device_async(
        cq: &crate::io::iommu::runtime::command::queue::CommandQueue,
        domain_arc: &Arc<IommuDomain>,
        controller: &controller::IommuController,
        device: &DeviceId,
        iova: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        let mapping = domain_arc.mapping(iova).ok_or(IommuError::NotMapped)?;
        let mapping_size = mapping.size;
        let cmd = IommuCommandKind::UnmapRegionDevice {
            device: *device,
            iova,
            size,
        };
        let comp = cq
            .submit_async(cmd)
            .await
            .map_err(|_| controller_cq_submit_error(controller))?;
        let rc = comp.await;
        if rc != 0 {
            return Err(controller_cq_completion_error(rc));
        }
        if let Err(IommuError::OutOfMemory) = controller.free_iova(iova, mapping_size) {
            if let Ok(_) = controller.invalidate_iotlb_global_sync() {
                let _ =
                    crate::io::iommu::common::interface::IommuHardwareContext::free_iova_immediate(
                        controller,
                        iova,
                        mapping_size,
                    );
            }
        }
        Ok(())
    }

    /// 直接 unmap + IOTLB 無効化 (非同期)
    pub(super) async fn direct_unmap_invalidate_async(
        domain_arc: &Arc<IommuDomain>,
        controller: &controller::IommuController,
        device: &DeviceId,
        iova: u64,
    ) -> Result<(), IommuError> {
        // 1. Monitor page table releases
        let pts_before = domain_arc
            .pending_pt_release
            .lock()
            .map(|p| p.len())
            .unwrap_or(0);

        let mapping = domain_arc.unmap(iova)?;
        let domain_id = domain_arc.id();

        let pts_after = domain_arc
            .pending_pt_release
            .lock()
            .map(|p| p.len())
            .unwrap_or(0);
        let pt_removed = pts_after > pts_before;

        if pt_removed {
            // Domain-level invalidation needed to clear paging-structure caches.
            // Use CQ path if available for async benefits.
            if let Some(cq) = controller.command_queue_ref() {
                let kind = IommuCommandKind::InvalidateIotlbDomain { domain: domain_id };
                let comp = cq
                    .submit_async(kind)
                    .await
                    .map_err(|_| controller_cq_submit_error(controller))?;
                let rc = comp.await;
                if rc != 0 {
                    return Err(controller_cq_completion_error(rc));
                }
            } else {
                controller.invalidate_iotlb(domain_id, true)?;
            }
        } else {
            // Page-selective invalidation with ATS awareness.
            // Always use the direct QI path which supports page-level granularity.
            controller.qi_invalidate_unmap(domain_id, device, iova, mapping.size as u64)?;
        }

        if pt_removed {
            let _ = domain_arc.flush(controller, controller);
        }

        if let Err(IommuError::OutOfMemory) = controller.free_iova(iova, mapping.size) {
            // Quarantine full: Force global flush and immediate free.
            // This is safe because the global flush ensures no stale entries remain.
            if let Ok(_) = controller.invalidate_iotlb_global_sync() {
                let _ =
                    crate::io::iommu::common::interface::IommuHardwareContext::free_iova_immediate(
                        controller,
                        iova,
                        mapping.size,
                    );
            }
        }
        Ok(())
    }

    pub(crate) async fn unmap_for_device_async(
        &self,
        device: &DeviceId,
        iova: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        let registry = self.registry()?;
        if registry.controllers.is_empty() {
            return Err(IommuError::NotPresent);
        }

        for controller in &registry.controllers {
            let domain_id = match controller.get_domain_for_device(*device) {
                Ok(Some(id)) => id,
                _ => continue,
            };
            let domain_arc = match controller.domain(domain_id) {
                Some(d) => d,
                None => continue,
            };
            if let Some(cq) = controller.command_queue_ref() {
                return Self::try_cq_unmap_device_async(
                    cq,
                    &domain_arc,
                    controller,
                    device,
                    iova,
                    size,
                )
                .await;
            }
            return Self::direct_unmap_invalidate_async(&domain_arc, controller, device, iova)
                .await;
        }

        Err(IommuError::DomainNotFound)
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
