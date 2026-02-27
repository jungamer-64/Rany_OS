use super::*;
use crate::io::iommu::api::IommuDomain;
use crate::io::iommu::intel::controller::init::CapabilityManager;


impl DomainManager for IommuController {
    fn create_domain(
        &self,
        numa_node: Option<usize>,
        domain_type: IommuDomainType,
    ) -> Result<u16, IommuError> {
        let id = self.next_domain_id.fetch_add(1, Ordering::Relaxed) as u16;

        let supports_2mb = self.supports_2mb_pages();
        let supports_1gb = self.supports_1gb_pages();
        let max_addr_bits = self.max_guest_address_width().min(48);

        let domain = IommuDomain::new(
            id,
            numa_node,
            supports_2mb,
            supports_1gb,
            max_addr_bits,
            domain_type,
            self.page_table_pool.clone(),
            PteFormat::Intel,
        );
        let domain_arc = Arc::new(domain);
        if let Some(notifier) = self.security_notifier.get() {
            let _ = domain_arc.set_security_notifier(Arc::clone(notifier));
        }

        match self.domains.lock() {
            Ok(mut domains) => {
                domains.insert(id, domain_arc.clone());
            }
            Err(_) => {
                return Err(IommuError::HardwareError);
            }
        }
        Ok(id)
    }

    fn set_domain_numa(&self, domain_id: u16, numa_node: Option<usize>) -> Result<(), IommuError> {
        let domain_arc = match self.domains.lock() {
            Ok(domains) => domains.get(&domain_id).cloned().ok_or(IommuError::DomainNotFound)?,
            Err(_) => return Err(IommuError::HardwareError),
        };
        domain_arc.set_numa_node(numa_node);
        Ok(())
    }

    fn get_domain_numa(&self, domain_id: u16) -> Option<usize> {
        match self.domains.lock() {
            Ok(domains) => domains.get(&domain_id).and_then(|d| d.numa_node()),
            Err(_) => None,
        }
    }

    fn domain(&self, id: u16) -> Option<Arc<IommuDomain>> {
        match self.domains.lock() {
            Ok(domains) => domains.get(&id).cloned(),
            Err(_) => None,
        }
    }

    fn attach_device(&self, device: DeviceId, domain_id: u16) -> Result<(), IommuError> {
        {
            let device_domains = self.device_domains.lock().map_err(|_| IommuError::HardwareError)?;
            if let Some(&existing_domain_id) = device_domains.get(&device) {
                if existing_domain_id != domain_id {
                    return Err(IommuError::AlreadyMapped);
                }
                return Ok(());
            }
        }

        let (domain_type, page_table_addr, bus, devfn) = self.resolve_domain_for_attach(domain_id, device)?;
        let mut hw_guard = self.hardware.lock().map_err(|_| IommuError::HardwareError)?;
        
        if self.is_scalable_mode_enabled() {
            self.attach_device_scalable(&mut *hw_guard, bus, devfn, domain_type, page_table_addr, domain_id, device)?;
        } else {
            Self::attach_device_legacy(&mut *hw_guard, bus, devfn, domain_type, page_table_addr, domain_id)?;
        }

        let _ = self.qi_invalidate_context_global();
        self.invalidate_iotlb(domain_id);

        self.device_domains.lock().map_err(|_| IommuError::HardwareError)?.insert(device, domain_id);
        Ok(())
    }

    fn detach_device(&self, device: DeviceId) -> Result<(), IommuError> {
        self.check_and_clear_ats(device);
        let bus = device.bus as usize;
        let devfn = ((device.device as usize) << 3) | (device.function as usize);

        let domain_id = self.device_domains.lock().map_err(|_| IommuError::HardwareError)?.get(&device).copied();
        self.clear_hw_context_entry(bus, devfn, device)?;

        let _ = self.qi_invalidate_context_global();
        if let Some(did) = domain_id {
            self.invalidate_iotlb(did);
        }

        self.device_domains.lock().map_err(|_| IommuError::HardwareError)?.remove(&device);
        Ok(())
    }

    fn get_domain_for_device(&self, device: DeviceId) -> Result<Option<u16>, IommuError> {
        Ok(self.device_domains.lock().map_err(|_| IommuError::HardwareError)?.get(&device).copied())
    }

    fn map_dma(&self, device: &DeviceId, iova: u64, phys: u64, size: u64, read: bool, write: bool) -> Result<(), IommuError> {
        crate::io::iommu::security::validate_dma_region(phys, size)?;
        let (_domain_id, domain_arc) = self.resolve_device_domain(device)?;
        domain_arc.map(iova, phys, size, read, write)
    }

    fn unmap_dma(&self, device: &DeviceId, iova: u64) -> Result<DmaMapping, IommuError> {
        let (domain_id, domain_arc) = self.resolve_device_domain(device)?;
        let mapping = domain_arc.unmap(iova)?;
        self.qi_invalidate_unmap(domain_id, device, iova, mapping.size as u64)?;
        Ok(mapping)
    }

    async fn unmap_dma_async(&self, device: &DeviceId, iova: u64) -> Result<DmaMapping, IommuError> {
        let (domain_id, domain_arc) = self.resolve_device_domain(device)?;
        let mapping = domain_arc.unmap(iova)?;
        if self.is_queued_invalidation_enabled() {
            self.qi_invalidate_unmap(domain_id, device, iova, mapping.size as u64)?;
            self.qi_wait_async().await?;
        } else {
            unsafe { self.invalidate_iotlb_direct(domain_id) };
        }
        Ok(mapping)
    }

    fn handle_command_queue_entry(&self, kind: &crate::io::iommu::cmdqueue::IommuCommandKind) -> Result<i32, ()> {
        use crate::io::iommu::cmdqueue::IommuCommandKind;
        match kind {
            IommuCommandKind::MapRegion { domain, iova, phys, size, read, write } => {
                if crate::io::iommu::security::validate_dma_region(*phys, *size).is_err() { return Err(()); }
                let domain_arc = self.domain(*domain).ok_or(())?;
                domain_arc.map(*iova, *phys, *size, *read, *write).map_err(|_| ())?;
                self.invalidate_iotlb(*domain);
                Ok(0)
            },
            IommuCommandKind::MapRegionDevice { device, iova, phys, size, read, write } => {
                if crate::io::iommu::security::validate_dma_region(*phys, *size).is_err() { return Err(()); }
                let (domain_id, domain_arc) = self.resolve_device_domain(device).map_err(|_| ())?;
                domain_arc.map(*iova, *phys, *size, *read, *write).map_err(|_| ())?;
                self.invalidate_iotlb(domain_id);
                if self.should_invalidate_device_tlb(device) {
                    let _ = self.qi_invalidate_device_tlb_all(device.requester_id());
                }
                Ok(0)
            },
            IommuCommandKind::UnmapRegion { domain, iova, .. } => {
                let domain_arc = self.domain(*domain).ok_or(())?;
                domain_arc.unmap(*iova).map_err(|_| ())?;
                self.invalidate_iotlb(*domain);
                Ok(0)
            },
            IommuCommandKind::UnmapRegionDevice { device, iova, .. } => {
                let (domain_id, domain_arc) = self.resolve_device_domain(device).map_err(|_| ())?;
                let mapping = domain_arc.unmap(*iova).map_err(|_| ())?;
                self.qi_invalidate_unmap(domain_id, device, *iova, mapping.size as u64).map_err(|_| ())?;
                Ok(0)
            },
            IommuCommandKind::InvalidateIotlbDomain { domain } => {
                self.invalidate_iotlb(*domain);
                Ok(0)
            },
            IommuCommandKind::InvalidateIotlbGlobal => {
                let _ = self.invalidate_iotlb_global_sync();
                Ok(0)
            }
        }
    }
}
