// ============================================================================
// kernel/src/io/iommu/intel/mod.rs
// ============================================================================

//! Intel VT-d backend driver (adapter over existing implementation).

use alloc::sync::Arc;

use x86_64::PhysAddr;

// Declaring submodules moved here
pub mod controller;
pub mod qi;
pub mod registers;
pub mod registry; // Intel-specific registry
pub mod tables;
pub mod driver;

use self::controller::dma::DomainManager;
use self::controller::fault::FaultHandler;
use self::controller::iova::IovaManager;
use self::controller::ir::InterruptRemapper;
use self::controller::qi_ops::InvalidationOps;

use super::domain::IommuDomain;
use super::IommuBackend;
// Generic registry for registering the driver
use super::registry::{init_driver, is_iommu_enabled};
use super::security::SecurityNotifier;

use super::cmdqueue::IommuCommandKind;
use super::types::{DeviceId, IommuDomainType, IommuError};

// Intel-specific registry access
use self::registry::get_iommu_registry;

/// Intel VT-d driver wrapper.


#[derive(Default)]
pub struct IntelIommuDriver;

impl IntelIommuDriver {
    pub fn new() -> Self {
        Self
    }

    pub fn register_driver() {
        if !is_iommu_enabled() {
            init_driver(Arc::new(IommuBackend::Intel(IntelIommuDriver::new())));
        }
    }

    fn registry(&self) -> Result<&'static self::registry::IommuRegistry, IommuError> {
        get_iommu_registry().ok_or(IommuError::NotInitialized)
    }
}

// ---------------------------------------------------------------------------
// DMA mapping helpers (shared by sync and async paths)
// ---------------------------------------------------------------------------

fn validate_dma_params(phys_addr: PhysAddr, size: u64) -> Result<(), IommuError> {
    let align = crate::mm::PAGE_SIZE_4K as u64;
    if size == 0 || (phys_addr.as_u64() & (align - 1) != 0) || (size & (align - 1) != 0) {
        return Err(IommuError::InvalidAlignment);
    }
    Ok(())
}

fn allocate_iova_for_device(
    controller: &Arc<controller::IommuController>,
    device: &DeviceId,
    size: u64,
) -> Result<u64, IommuError> {
    let mask = crate::io::iommu::api::get_device_dma_mask(device);
    match mask {
        Some(limit) => controller.allocate_iova_masked(size, limit),
        None if size == crate::mm::PAGE_SIZE_4K as u64 => controller.allocate_iova_fast(size),
        None => controller.allocate_iova(size),
    }
}

unsafe fn apply_mapping_sync(
    controller: &Arc<controller::IommuController>,
    domain_arc: &Arc<IommuDomain>,
    iova: u64,
    phys: u64,
    size: u64,
    read: bool,
    write: bool,
) -> Result<u64, IommuError> {
    let domain_id = domain_arc.id();
    if let Some(ref cq) = controller.command_queue {
        let cmd = IommuCommandKind::MapRegion {
            domain: domain_id,
            iova,
            phys,
            size,
            read,
            write,
        };
        if cq.submit_sync(cmd).is_err() {
            let _ = controller.free_iova(iova, size);
            return Err(IommuError::HardwareError);
        }
        return Ok(iova);
    }
    if let Err(err) = domain_arc.map(iova, phys, size, read, write) {
        let _ = controller.free_iova(iova, size);
        return Err(err);
    }
    Ok(iova)
}

async unsafe fn apply_mapping_async(
    controller: &Arc<controller::IommuController>,
    domain_arc: &Arc<IommuDomain>,
    iova: u64,
    phys: u64,
    size: u64,
) -> Result<u64, IommuError> {
    let domain_id = domain_arc.id();
    if let Some(ref cq) = controller.command_queue {
        let cmd = IommuCommandKind::MapRegion {
            domain: domain_id,
            iova,
            phys,
            size,
            read: true,
            write: true,
        };
        let comp = match cq.submit_async(cmd).await {
            Ok(comp) => comp,
            Err(_) => {
                let _ = controller.free_iova(iova, size);
                return Err(IommuError::HardwareError);
            }
        };
        let rc = comp.await;
        if rc == 0 {
            return Ok(iova);
        }
        let _ = controller.free_iova(iova, size);
        return Err(IommuError::HardwareError);
    }
    if let Err(err) = domain_arc.map(iova, phys, size, true, true) {
        let _ = controller.free_iova(iova, size);
        return Err(err);
    }
    Ok(iova)
}

impl IntelIommuDriver {
    pub(crate) fn is_enabled(&self) -> bool {
        get_iommu_registry().map_or(false, |r| !r.controllers.is_empty())
    }

    pub(crate) fn enable(&self) -> Result<(), IommuError> {
        let registry = self.registry()?;
        for (_idx, controller) in registry.controllers.iter().enumerate() {
            unsafe {
                controller.enable()?;
            }
        }
        Ok(())
    }

    pub(crate) fn disable(&self) -> Result<(), IommuError> {
        let registry = self.registry()?;
        for (_idx, controller) in registry.controllers.iter().enumerate() {
            unsafe {
                controller.disable()?;
            }
        }
        Ok(())
    }

    pub(crate) fn handle_fault(&self) {
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

        controller.allocate_irte(vector, dest_id, logical)
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

    fn validate_dma_alignment(phys_addr: PhysAddr, size: u64) -> Result<(), IommuError> {
        let align = crate::mm::PAGE_SIZE_4K as u64;
        if size == 0 || (phys_addr.as_u64() & (align - 1) != 0) || (size & (align - 1) != 0) {
            return Err(IommuError::InvalidAlignment);
        }
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

    fn rollback_dma_mappings(
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
            if domain.unmap(iova).is_err() {
                ok = false;
            }
        }
        ok
    }

    fn free_reserved_iovas(
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

        let mut last_err = None;
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
            match domain_arc.unmap(iova) {
                Ok(mapping) => {
                    let _ = controller.free_iova(iova, mapping.size);
                }
                Err(err) => {
                    last_err = Some(err);
                }
            }
        }

        if let Some(err) = last_err {
            Err(err)
        } else {
            Ok(())
        }
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

        let registry = self.registry()?;
        if registry.controllers.is_empty() {
            return Err(IommuError::NotPresent);
        }

        for controller in &registry.controllers {
            if let Ok(Some(domain_id)) = controller.get_domain_for_device(*device) {
                if let Some(domain_arc) = controller.domain(domain_id) {
                    let iova = allocate_iova_for_device(controller, device, size)?;
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
                    let iova = allocate_iova_for_device(controller, device, size)?;
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
        let registry = self.registry()?;
        if registry.controllers.is_empty() {
            return Err(IommuError::NotPresent);
        }

        for controller in &registry.controllers {
            if let Ok(Some(domain_id)) = controller.get_domain_for_device(*device) {
                if let Some(domain_arc) = controller.domain(domain_id) {
                    return Self::perform_unmap(controller, &domain_arc, iova, size);
                }
            }
        }

        Err(IommuError::DomainNotFound)
    }

    /// Execute the actual unmap on a resolved domain, using CQ fast-path when available.
    fn perform_unmap(
        controller: &controller::IommuController,
        domain_arc: &Arc<IommuDomain>,
        iova: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        if let Some(ref cq) = controller.command_queue {
            let domain_id = domain_arc.id();
            let mapping = domain_arc
                .mapping(iova)
                .ok_or(IommuError::NotMapped)?;
            let mapping_size = mapping.size;
            let cmd = IommuCommandKind::UnmapRegion {
                domain: domain_id,
                iova,
                size,
            };
            cq.submit_sync(cmd).map_err(|_| IommuError::HardwareError)?;
            let _ = controller.free_iova(iova, mapping_size);
            return Ok(());
        }

        let mapping = domain_arc.unmap(iova)?;
        let domain_id = domain_arc.id();

        if let Some(ref cq) = controller.command_queue {
            cq.submit_sync(IommuCommandKind::InvalidateIotlbDomain { domain: domain_id })
                .map_err(|_| IommuError::HardwareError)?;
        } else {
            controller.invalidate_iotlb(domain_id);
        }

        let _ = controller.free_iova(iova, mapping.size);
        Ok(())
    }

    /// コマンドキュー経由で非同期 UnmapRegion を実行する
    async fn try_cq_unmap_async(
        cq: &crate::io::iommu::cmdqueue::CommandQueue,
        domain_arc: &Arc<IommuDomain>,
        controller: &controller::IommuController,
        iova: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        let domain_id = domain_arc.id();
        let mapping = domain_arc.mapping(iova).ok_or(IommuError::NotMapped)?;
        let mapping_size = mapping.size;
        let cmd = IommuCommandKind::UnmapRegion { domain: domain_id, iova, size };
        let comp = cq.submit_async(cmd).await.map_err(|_| IommuError::HardwareError)?;
        let rc = comp.await;
        if rc != 0 {
            return Err(IommuError::HardwareError);
        }
        let _ = controller.free_iova(iova, mapping_size);
        Ok(())
    }

    /// 直接 unmap + IOTLB 無効化 (非同期)
    async fn direct_unmap_invalidate_async(
        domain_arc: &Arc<IommuDomain>,
        controller: &controller::IommuController,
        iova: u64,
    ) -> Result<(), IommuError> {
        let mapping = domain_arc.unmap(iova)?;
        let domain_id = domain_arc.id();
        if let Some(ref cq) = controller.command_queue {
            let comp = cq
                .submit_async(IommuCommandKind::InvalidateIotlbDomain { domain: domain_id })
                .await
                .map_err(|_| IommuError::HardwareError)?;
            let rc = comp.await;
            if rc != 0 {
                return Err(IommuError::HardwareError);
            }
        } else {
            controller.invalidate_iotlb(domain_id);
        }
        let _ = controller.free_iova(iova, mapping.size);
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
                return Self::try_cq_unmap_async(cq, &domain_arc, controller, iova, size).await;
            }
            return Self::direct_unmap_invalidate_async(&domain_arc, controller, iova).await;
        }

        Err(IommuError::DomainNotFound)
    }

    pub(crate) fn create_domain(
        &self,
        numa_node: Option<usize>,
        domain_type: IommuDomainType,
    ) -> Result<u16, IommuError> {
        let registry = self.registry()?;
        let idx = registry.default_iommu_idx.ok_or(IommuError::NotPresent)?;
        let controller = registry
            .controllers
            .get(idx)
            .ok_or(IommuError::NotPresent)?;
        controller.create_domain(numa_node, domain_type)
    }

    pub(crate) fn attach_device(&self, device: DeviceId, domain_id: u16) -> Result<(), IommuError> {
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

    /// Get domain by ID
    pub(crate) fn get_domain(&self, domain_id: u16) -> Result<Arc<IommuDomain>, IommuError> {
        let registry = self.registry()?;
        for controller in &registry.controllers {
            if let Some(domain_arc) = controller.domain(domain_id) {
                return Ok(domain_arc);
            }
        }
        Err(IommuError::DomainNotFound)
    }

    pub(crate) fn get_domain_numa(&self, domain_id: u16) -> Result<Option<usize>, IommuError> {
        let registry = self.registry()?;
        for controller in &registry.controllers {
            if let Some(domain_arc) = controller.domain(domain_id) {
                return Ok(domain_arc.numa_node());
            }
        }

        Err(IommuError::DomainNotFound)
    }

    // ========================================================================
    // Flush Operations (for emergency isolation)
    // ========================================================================

    /// Invalidate IOTLB entries for a specific domain.
    pub(crate) fn invalidate_iotlb(
        &self,
        domain_id: u16,
        _iova: Option<u64>,
    ) -> Result<(), IommuError> {
        let registry = self.registry()?;

        for controller in &registry.controllers {
            controller.invalidate_iotlb(domain_id);
        }

        Ok(())
    }

    /// Invalidate all IOTLB entries globally.
    pub(crate) fn invalidate_iotlb_global(&self) -> Result<(), IommuError> {
        let registry = self.registry()?;

        for controller in &registry.controllers {
            // Use global invalidation - domain_id 0 with special flag
            // The controller's invalidate_iotlb_global handles this
            if let Err(e) = controller.invalidate_iotlb_global_sync() {
                log::warn!(
                    "[IOMMU] Global IOTLB invalidation failed on controller seg={}: {:?}",
                    controller.segment,
                    e
                );
            }
        }

        Ok(())
    }

    /// Invalidate context cache globally.
    pub(crate) fn invalidate_context_global(&self) -> Result<(), IommuError> {
        let registry = self.registry()?;

        for controller in &registry.controllers {
            if let Err(e) = controller.invalidate_context_global_sync() {
                log::warn!(
                    "[IOMMU] Global context cache invalidation failed on controller seg={}: {:?}",
                    controller.segment,
                    e
                );
            }
        }

        Ok(())
    }

    /// Lookup the domain ID for a device.
    pub(crate) fn lookup_device_domain(&self, source_id: u16) -> Option<u16> {
        let registry = self.registry().ok()?;

        // Parse source_id into bus/dev/func
        let bus = ((source_id >> 8) & 0xFF) as u8;
        let devfn = (source_id & 0xFF) as u8;

        for controller in &registry.controllers {
            if let Some(domain_id) = controller.device_to_domain(bus, devfn) {
                return Some(domain_id);
            }
        }

        None
    }

    pub(crate) fn dump_diagnostics(&self) {
        let registry = match self.registry() {
            Ok(r) => r,
            Err(e) => {
                log::warn!("[IOMMU] diagnostics skipped: registry unavailable ({:?})", e);
                return;
            }
        };

        for (idx, controller) in registry.controllers.iter().enumerate() {
            match controller.qi_stats() {
                Ok(Some(stats)) => {
                    log::info!(
                        "[IOMMU] Ctrl #{} seg={} QI: submits={} full_checks={} head_refreshes={} waits={} wait_timeouts={}",
                        idx,
                        controller.segment,
                        stats.submits,
                        stats.full_checks,
                        stats.head_refreshes,
                        stats.waits,
                        stats.wait_timeouts
                    );
                    if stats.full_checks > 0 || stats.waits > 0 {
                        log::warn!(
                            "[IOMMU] Ctrl #{} seg={} QI pressure detected (full_checks={}, waits={})",
                            idx,
                            controller.segment,
                            stats.full_checks,
                            stats.waits
                        );
                    }
                }
                Ok(None) => {
                    log::info!(
                        "[IOMMU] Ctrl #{} seg={} QI not initialized",
                        idx,
                        controller.segment
                    );
                }
                Err(e) => {
                    log::warn!(
                        "[IOMMU] Ctrl #{} seg={} QI stats unavailable ({:?})",
                        idx,
                        controller.segment,
                        e
                    );
                }
            }
        }
    }
}
