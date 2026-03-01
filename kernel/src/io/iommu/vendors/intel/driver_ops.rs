// ============================================================================
// kernel/src/io/iommu/vendors/intel/driver_ops.rs
// ============================================================================

use super::*;

mod domain_query;
mod invalidation;
impl IntelIommuDriver {
    pub(crate) fn is_enabled(&self) -> bool {
        if self.controller.is_some() {
            return true;
        }
        get_iommu_registry().map_or(false, |r| !r.controllers.is_empty())
    }

    pub(crate) fn enable(&self) -> Result<(), IommuError> {
        if let Some(ref controller) = self.controller {
            unsafe { return controller.enable(); }
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
            unsafe { return controller.disable(); }
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
        // Intel VT-d MSI/MSI-X format (same as previous implementation).
        let handle = handle as u64;
        let index_14_0 = handle & 0x7FFF;
        let index_15 = (handle >> 15) & 1;

        let address = 0xFEE0_0000 | (index_14_0 << 5) | (index_15 << 3);
        let data = 0;

        (address, data)
    }

    pub(crate) fn domain_id_for_device(&self, device: &DeviceId) -> Result<u16, IommuError> {
        if let Some(ref controller) = self.controller {
            return controller.get_domain_for_device(*device).map(|d| d.unwrap_or(0));
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

    pub(crate) unsafe fn map_for_dma(
        &self,
        phys_addr: PhysAddr,
        size: u64,
    ) -> Result<u64, IommuError> {
        unsafe { self.map_for_dma_with_perms(phys_addr, size, true, true) }
    }

    pub(super) fn validate_dma_alignment(phys_addr: PhysAddr, size: u64) -> Result<(), IommuError> {
        let align = crate::mm::types::PAGE_SIZE_4K as u64;
        if size == 0 || (phys_addr.as_u64() & (align - 1) != 0) || (size & (align - 1) != 0) {
            return Err(IommuError::InvalidAlignment);
        }

        // Security: Validate that the physical range does not overlap with the kernel image.
        crate::io::iommu::runtime::security::validate_dma_region(phys_addr.as_u64(), size)?;

        Ok(())
    }

    /// Reserve IOVA on all non-default controllers. On error, free all already-reserved.
    unsafe fn reserve_iova_on_secondary(
        &self,
        registry: &'static self::registry::IommuRegistry,
        default_controller: &Arc<controller::IommuController>,
        iova: u64,
        size: u64,
    ) -> Result<alloc::vec::Vec<usize>, IommuError> {
        let default_ptr = Arc::as_ptr(default_controller) as *const ();
        let mut reserved_indices: alloc::vec::Vec<usize> = alloc::vec::Vec::new();
        for (idx, controller) in registry.controllers.iter().enumerate() {
            if (Arc::as_ptr(controller) as *const ()) == default_ptr {
                continue;
            }
            if let Err(err) = controller.reserve_iova(iova, size) {
                Self::free_reserved_iovas(registry, &reserved_indices, iova, size);
                return Err(err);
            }
            reserved_indices.push(idx);
        }
        Ok(reserved_indices)
    }

    /// Map on all controllers, rolling back on failure.
    unsafe fn map_on_all_controllers(
        &self,
        registry: &'static self::registry::IommuRegistry,
        reserved_indices: &[usize],
        iova: u64,
        phys_addr: PhysAddr,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        let mut mapped_indices: alloc::vec::Vec<usize> = alloc::vec::Vec::new();
        for (idx, controller) in registry.controllers.iter().enumerate() {
            let domain_arc = controller
                .domain(0)
                .ok_or(IommuError::DomainNotFound)?;
            if let Err(err) = domain_arc.map(iova, phys_addr.as_u64(), size, read, write) {
                let unmap_ok = Self::rollback_dma_mappings(registry, &mapped_indices, iova);
                if unmap_ok {
                    Self::free_reserved_iovas(registry, reserved_indices, iova, size);
                }
                return Err(err);
            }
            mapped_indices.push(idx);
        }
        Ok(())
    }

    pub(super) fn rollback_dma_mappings(
        registry: &'static self::registry::IommuRegistry,
        mapped_indices: &[usize],
        iova: u64,
    ) -> bool {
        let mut ok = true;
        for mapped in mapped_indices {
            let Some(ctrl) = registry.controllers.get(*mapped) else {
                ok = false;
                continue;
            };
            let Some(domain) = ctrl.domain(0) else {
                ok = false;
                continue;
            };
            if domain.unmap(iova).is_ok() {
                // SECURITY: Invalidate IOTLB after rollback to ensure no stale entries remain
                if let Err(e) = ctrl.invalidate_iotlb(0, true) {
                    log::error!(
                        "[IOMMU][SECURITY] IOTLB invalidation failed during rollback on controller {}: {:?}",
                        mapped,
                        e
                    );
                    ok = false;
                }
            } else {
                ok = false;
            }
        }
        ok
    }

    pub(super) fn free_reserved_iovas(
        registry: &'static self::registry::IommuRegistry,
        reserved_indices: &[usize],
        iova: u64,
        size: u64,
    ) {
        for reserved_idx in reserved_indices {
            let ctrl = &registry.controllers[*reserved_idx];
            let _ = ctrl.free_iova(iova, size);
        }
    }

    pub(crate) unsafe fn map_for_dma_with_perms(
        &self,
        phys_addr: PhysAddr,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<u64, IommuError> {
        Self::validate_dma_alignment(phys_addr, size)?;

        let registry = self.registry()?;
        if registry.controllers.is_empty() {
            return Err(IommuError::NotPresent);
        }

        let default_controller = registry
            .default_controller()
            .ok_or(IommuError::NotPresent)?;
        let iova = default_controller.allocate_iova(size)?;

        let reserved_indices = unsafe {
            self.reserve_iova_on_secondary(registry, default_controller, iova, size)?
        };

        if let Err(err) = unsafe {
            self.map_on_all_controllers(registry, &reserved_indices, iova, phys_addr, size, read, write)
        } {
            let _ = default_controller.free_iova(iova, size);
            return Err(err);
        }

        Ok(iova)
    }

    pub(crate) fn unmap_dma(&self, iova: u64, _size: u64) -> Result<(), IommuError> {
        let registry = self.registry()?;
        if registry.controllers.is_empty() {
            return Err(IommuError::NotPresent);
        }

        let mut mapping_size = 0;
        let mut first_err = None;
        let mut unmapped_controllers = alloc::vec::Vec::with_capacity(registry.controllers.len());
        let mut success_count = 0;

        // SECURITY: Unmap from ALL controllers that have Domain 0.
        // Failing to unmap from any controller while freeing the IOVA would leave a 
        // stale mapping that could be exploited for DMA Use-After-Free.
        for (idx, controller) in registry.controllers.iter().enumerate() {
            if let Some(domain_arc) = controller.domain(0) {
                match domain_arc.unmap(iova) {
                    Ok(mapping) => {
                        mapping_size = mapping.size;
                        if let Err(err) = controller.invalidate_iotlb(0, true) {
                            log::error!(
                                "[IOMMU][SECURITY] unmap_dma invalidation failed on controller {}: {:?}. Poisoning domain.",
                                idx, err
                            );
                            domain_arc.poison();
                            if first_err.is_none() {
                                first_err = Some(err);
                            }
                        } else {
                            unmapped_controllers.push(idx);
                            success_count += 1;
                        }
                    }
                    Err(IommuError::NotMapped) => {
                        // Already unmapped or not present on this controller, count as success
                        unmapped_controllers.push(idx);
                        success_count += 1;
                    }
                    Err(err) => {
                        if first_err.is_none() {
                            first_err = Some(err);
                        }
                    }
                }
            } else {
                // Controller doesn't have Domain 0, it couldn't have had this mapping
                unmapped_controllers.push(idx);
                success_count += 1;
            }
        }

        if let Some(err) = first_err {
            return Err(err);
        }

        // SECURITY: Only free the IOVA if ALL controllers unmapped and invalidated successfully.
        // If some controllers failed, we leak the IOVA (it remains "zombie") to prevent UAF.
        if success_count == registry.controllers.len() && mapping_size > 0 {
            for idx in unmapped_controllers {
                let controller = &registry.controllers[idx];
                if let Err(IommuError::OutOfMemory) = controller.free_iova(iova, mapping_size) {
                    // Quarantine full: Force a global IOTLB flush and then use immediate free.
                    if let Ok(_) = self.invalidate_iotlb_global() {
                        let _ = crate::io::iommu::common::interface::IommuHardwareContext::free_iova_immediate(
                            &**controller,
                            iova,
                            mapping_size,
                        );
                    }
                }
            }
        } else if mapping_size > 0 {
            log::warn!(
                "[IOMMU][SECURITY] Partial unmap success ({}/{}); IOVA 0x{:x} (size {}) will NOT be freed to prevent UAF.",
                success_count, registry.controllers.len(), iova, mapping_size
            );
        }

        Ok(())
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
                    let iova = allocate_iova_for_device(&domain_arc, device, size)?;
                    return apply_mapping_sync(
                        controller, &domain_arc, iova, phys_addr.as_u64(), size, read, write,
                    );
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
                    crate::io::log::early_print("[DMA] map_for_device: calling allocate_iova\n");
                    let iova = allocate_iova_for_device(&domain_arc, device, size)?;
                    crate::io::log::early_print("[DMA] map_for_device: iova allocated, calling apply_mapping_sync\n");
                    return apply_mapping_sync(
                        controller, &domain_arc, iova, phys_addr.as_u64(), size, read, write,
                    );
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
                    let iova = allocate_iova_for_device(&domain_arc, device, size)?;
                    return apply_mapping_async(
                        controller, &domain_arc, iova, phys_addr.as_u64(), size,
                    )
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

    /// Execute the actual unmap on a resolved domain, using CQ fast-path when available.
    pub(super) fn perform_unmap(
        controller: &controller::IommuController,
        device: &DeviceId,
        domain_arc: &Arc<IommuDomain>,
        iova: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        // 1. Monitor page table releases to detect if paging-structure caches need clearing
        let pts_before = domain_arc.pending_pt_release.lock().map(|p| p.len()).unwrap_or(0);

        if let Some(ref _cq) = controller.command_queue {
            let cmd = IommuCommandKind::UnmapRegionDevice {
                device: *device,
                iova,
                size,
            };
            controller.execute_sync_command(cmd).map_err(|_| IommuError::HardwareError)?;
            
            // Check if unmap removed a PT (via mapping lookups since CQ is used)
            let pts_after = domain_arc.pending_pt_release.lock().map(|p| p.len()).unwrap_or(0);
            if pts_after > pts_before {
                // SECURITY: If a page table was removed, we MUST perform a domain-wide
                // invalidation. CQ UnmapRegionDevice only does page-level invalidation.
                controller.execute_sync_command(IommuCommandKind::InvalidateIotlbDomain { domain: domain_arc.id() })
                    .map_err(|_| IommuError::HardwareError)?;
                let _ = domain_arc.flush(controller, controller);
            }
            return Ok(())
        }

        let mapping = domain_arc.unmap(iova)?;
        let domain_id = domain_arc.id();

        let pts_after = domain_arc.pending_pt_release.lock().map(|p| p.len()).unwrap_or(0);
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
                let _ = crate::io::iommu::common::interface::IommuHardwareContext::free_iova_immediate(
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
        let cmd = IommuCommandKind::UnmapRegionDevice { device: *device, iova, size };
        let comp = cq.submit_async(cmd).await.map_err(|_| IommuError::HardwareError)?;
        let rc = comp.await;
        if rc != 0 {
            return Err(IommuError::HardwareError);
        }
        if let Err(IommuError::OutOfMemory) = controller.free_iova(iova, mapping_size) {
            if let Ok(_) = controller.invalidate_iotlb_global_sync() {
                let _ = crate::io::iommu::common::interface::IommuHardwareContext::free_iova_immediate(
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
        let pts_before = domain_arc.pending_pt_release.lock().map(|p| p.len()).unwrap_or(0);

        let mapping = domain_arc.unmap(iova)?;
        let domain_id = domain_arc.id();

        let pts_after = domain_arc.pending_pt_release.lock().map(|p| p.len()).unwrap_or(0);
        let pt_removed = pts_after > pts_before;

        if let Some(ref cq) = controller.command_queue {
            let kind = if pt_removed {
                IommuCommandKind::InvalidateIotlbDomain { domain: domain_id }
            } else {
                IommuCommandKind::InvalidateIotlbDomain { domain: domain_id } // FIXME: should be page invalidation if possible
            };
            let comp = cq
                .submit_async(kind)
                .await
                .map_err(|_| IommuError::HardwareError)?;
            let rc = comp.await;
            if rc != 0 {
                return Err(IommuError::HardwareError);
            }
        } else {
            if pt_removed {
                controller.invalidate_iotlb(domain_id, true)?;
            } else {
                // ATS-aware invalidation
                controller.qi_invalidate_unmap(domain_id, device, iova, mapping.size as u64)?;
            }
        }
        
        if pt_removed {
            let _ = domain_arc.flush(controller, controller);
        }

        if let Err(IommuError::OutOfMemory) = controller.free_iova(iova, mapping.size) {
            // Quarantine full: Force global flush and immediate free.
            // This is safe because the global flush ensures no stale entries remain.
            if let Ok(_) = controller.invalidate_iotlb_global_sync() {
                let _ = crate::io::iommu::common::interface::IommuHardwareContext::free_iova_immediate(
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
            if let Some(ref cq) = controller.command_queue {
                return Self::try_cq_unmap_device_async(cq, &domain_arc, controller, device, iova, size).await;
            }
            return Self::direct_unmap_invalidate_async(&domain_arc, controller, device, iova).await;
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
                    idx, first_id.unwrap(), id
                );
                // We proceed but consistency is now compromised for this domain ID.
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
