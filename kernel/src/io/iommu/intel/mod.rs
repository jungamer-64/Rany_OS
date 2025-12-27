// ============================================================================
// kernel/src/io/iommu/intel/mod.rs
// ============================================================================

//! Intel VT-d backend driver (adapter over existing implementation).

use alloc::boxed::Box;
use alloc::sync::Arc;

use x86_64::PhysAddr;

// Declaring submodules moved here
pub mod controller;
pub mod qi;
pub mod registers;
pub mod registry; // Intel-specific registry
pub mod tables;

use self::controller::dma::DomainManager;
use self::controller::fault::FaultHandler;
use self::controller::ir::InterruptRemapper;
use self::controller::qi_ops::InvalidationOps;

use super::interface::{IommuDriver, IommuFuture};
// Generic registry for registering the driver
use super::registry::{get_iommu_driver, init_driver, is_iommu_enabled};

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
            init_driver(Arc::new(IntelIommuDriver::new()));
        }
    }

    fn registry(&self) -> Result<&'static self::registry::IommuRegistry, IommuError> {
        get_iommu_registry().ok_or(IommuError::NotInitialized)
    }
}

impl IommuDriver for IntelIommuDriver {
    fn is_enabled(&self) -> bool {
        get_iommu_registry().map_or(false, |r| !r.controllers.is_empty())
    }

    fn enable(&self) -> Result<(), IommuError> {
        let registry = self.registry()?;
        for controller in &registry.controllers {
            unsafe {
                controller.enable()?;
            }
        }
        Ok(())
    }

    fn disable(&self) -> Result<(), IommuError> {
        let registry = self.registry()?;
        for controller in &registry.controllers {
            unsafe {
                controller.disable()?;
            }
        }
        Ok(())
    }

    fn handle_fault(&self) {
        if let Ok(registry) = self.registry() {
            for controller in &registry.controllers {
                controller.process_faults();
            }
        }
    }

    fn wake_invalidation_waiters(&self) {
        if let Ok(registry) = self.registry() {
            for controller in &registry.controllers {
                controller.wake_invalidation_waiter();
            }
        }
    }

    fn map_interrupt(
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

    fn get_remap_msi_message(&self, handle: u16) -> (u64, u32) {
        // Intel VT-d MSI/MSI-X format (same as previous implementation).
        let handle = handle as u64;
        let index_14_0 = handle & 0x7FFF;
        let index_15 = (handle >> 15) & 1;

        let address = 0xFEE0_0000 | (index_14_0 << 5) | (index_15 << 3);
        let data = 0;

        (address, data)
    }

    unsafe fn map_for_dma(&self, phys_addr: PhysAddr, size: u64) -> Result<u64, IommuError> {
        let align = crate::mm::PAGE_SIZE_4K as u64;
        if size == 0 || (phys_addr.as_u64() & (align - 1) != 0) || (size & (align - 1) != 0) {
            return Err(IommuError::InvalidAlignment);
        }

        let registry = self.registry()?;
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
                    .get(&0)
                    .cloned()
                    .ok_or(IommuError::DomainNotFound)?
            };
            let mut domain = domain_arc.lock().map_err(|_| IommuError::HardwareError)?;
            domain.map(iova, phys_addr.as_u64(), size, true, true)?;
        }

        Ok(iova)
    }

    fn unmap_dma(&self, iova: u64, _size: u64) -> Result<(), IommuError> {
        let registry = self.registry()?;
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

    unsafe fn map_for_device(
        &self,
        device: &DeviceId,
        phys_addr: PhysAddr,
        size: u64,
    ) -> Result<u64, IommuError> {
        crate::task::block_on(async {
            unsafe { self.map_for_device_async(device, phys_addr, size).await }
        })
    }

    unsafe fn map_for_device_async<'a>(
        &'a self,
        device: &'a DeviceId,
        phys_addr: PhysAddr,
        size: u64,
    ) -> IommuFuture<'a, Result<u64, IommuError>> {
        Box::pin(async move {
            let align = crate::mm::PAGE_SIZE_4K as u64;
            if size == 0 || (phys_addr.as_u64() & (align - 1) != 0) || (size & (align - 1) != 0) {
                return Err(IommuError::InvalidAlignment);
            }

            let registry = self.registry()?;
            if registry.controllers.is_empty() {
                return Err(IommuError::NotPresent);
            }

            let iova = phys_addr.as_u64();

            for controller in &registry.controllers {
                if let Ok(Some(domain_id)) = controller.get_domain_for_device(*device) {
                    if let Some(domain_arc) = controller.domain(domain_id) {
                        let domain_id = {
                            let d = domain_arc.lock().map_err(|_| IommuError::HardwareError)?;
                            d.id
                        };

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

                        let mut domain =
                            domain_arc.lock().map_err(|_| IommuError::HardwareError)?;
                        domain.map(iova, phys_addr.as_u64(), size, true, true)?;
                        return Ok(iova);
                    }
                }
            }

            Err(IommuError::DomainNotFound)
        })
    }

    fn unmap_for_device(&self, device: &DeviceId, iova: u64, size: u64) -> Result<(), IommuError> {
        crate::task::block_on(async { self.unmap_for_device_async(device, iova, size).await })
    }

    fn unmap_for_device_async<'a>(
        &'a self,
        device: &'a DeviceId,
        iova: u64,
        size: u64,
    ) -> IommuFuture<'a, Result<(), IommuError>> {
        Box::pin(async move {
            let registry = self.registry()?;
            if registry.controllers.is_empty() {
                return Err(IommuError::NotPresent);
            }

            for controller in &registry.controllers {
                if let Ok(Some(domain_id)) = controller.get_domain_for_device(*device) {
                    if let Some(domain_arc) = controller.domain(domain_id) {
                        let domain_id = {
                            let d = domain_arc.lock().map_err(|_| IommuError::HardwareError)?;
                            d.id
                        };

                        if let Some(ref cq) = controller.command_queue {
                            let cmd = IommuCommandKind::UnmapRegion {
                                domain: domain_id,
                                iova,
                                size,
                            };
                            let comp = cq.submit(cmd).map_err(|_| IommuError::HardwareError)?;
                            let rc = comp.await;
                            if rc == 0 {
                                return Ok(());
                            } else {
                                return Err(IommuError::HardwareError);
                            }
                        }

                        let mut domain =
                            domain_arc.lock().map_err(|_| IommuError::HardwareError)?;
                        domain.unmap(iova)?;
                        let domain_id = domain.id();
                        drop(domain);

                        if let Some(ref cq) = controller.command_queue {
                            let comp = cq
                                .submit(IommuCommandKind::InvalidateIotlbDomain {
                                    domain: domain_id,
                                })
                                .map_err(|_| IommuError::HardwareError)?;
                            let rc = comp.await;
                            if rc == 0 {
                                return Ok(());
                            } else {
                                return Err(IommuError::HardwareError);
                            }
                        } else {
                            controller.invalidate_iotlb(domain_id);
                        }

                        return Ok(());
                    }
                }
            }

            Err(IommuError::DomainNotFound)
        })
    }

    fn create_domain(
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

    fn attach_device(&self, device: DeviceId, domain_id: u16) -> Result<(), IommuError> {
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

    fn detach_device(&self, device: DeviceId) -> Result<(), IommuError> {
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

    fn set_domain_numa(&self, domain_id: u16, numa_node: Option<usize>) -> Result<(), IommuError> {
        let registry = self.registry()?;
        for controller in &registry.controllers {
            if controller.domain(domain_id).is_some() {
                return controller.set_domain_numa(domain_id, numa_node);
            }
        }
        Err(IommuError::DomainNotFound)
    }

    fn get_domain_numa(&self, domain_id: u16) -> Result<Option<usize>, IommuError> {
        let registry = self.registry()?;
        for controller in &registry.controllers {
            if let Some(domain_arc) = controller.domain(domain_id) {
                match domain_arc.lock() {
                    Ok(guard) => return Ok(guard.numa_node),
                    Err(_) => {
                        log::error!(
                            "[IOMMU] Domain lock poisoned in get_domain_numa - returning None"
                        );
                        return Ok(None);
                    }
                }
            }
        }

        Err(IommuError::DomainNotFound)
    }

    fn dump_diagnostics(&self) {
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
