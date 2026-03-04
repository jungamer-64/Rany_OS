// ============================================================================
// kernel/src/io/iommu/vendors/intel/controller/dma/domain_manager_impl.rs
// ============================================================================

use super::*;
use crate::io::iommu::common::domain::IommuDomain;
use crate::io::iommu::vendors::intel::controller::init::CapabilityManager;
use crate::io::iommu::vendors::intel::controller::iova::IovaManager;


impl DomainManager for IommuController {
    fn create_domain(
        &self,
        numa_node: Option<usize>,
        domain_type: IommuDomainType,
    ) -> Result<u16, IommuError> {
        let mut domains = self.domains.lock().map_err(|_| IommuError::HardwareError)?;
        
        // Security: Respect hardware domain ID limits (ND field in CAP register)
        let nd_bits = (self.cap & 0x7) as u8;
        let max_ids = match nd_bits {
            0b000 => 16,
            0b001 => 64,
            0b010 => 256,
            0b011 => 1024,
            0b100 => 4096,
            0b101 => 16384,
            0b110 => 65536,
            _ => 65536,
        };

        // Find a free domain ID starting from next_domain_id hint
        let mut id = (self.next_domain_id.load(Ordering::Relaxed) % max_ids as u64) as u16;
        let mut found = false;
        for _ in 0..max_ids {
            if !domains.contains_key(&id) {
                found = true;
                break;
            }
            id = ((id as u64 + 1) % max_ids as u64) as u16;
        }

        if !found {
            log::error!("[IOMMU] Out of Domain IDs (max {})", max_ids);
            return Err(IommuError::OutOfMemory);
        }
        self.next_domain_id.store((id as u64 + 1) % max_ids as u64, Ordering::Relaxed);

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

        domains.insert(id, domain_arc.clone());
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

    fn destroy_domain(&self, id: u16) -> Result<(), IommuError> {
        // SECURITY: Check if any devices are still attached to this domain
        {
            let device_domains = self.device_domains.lock().map_err(|_| IommuError::HardwareError)?;
            if device_domains.values().any(|&did| did == id) {
                log::error!("[IOMMU] Attempted to destroy domain {} while devices are still attached", id);
                return Err(IommuError::AlreadyMapped);
            }
        }

        let domain_arc = match self.domains.lock() {
            Ok(mut domains) => domains.remove(&id).ok_or(IommuError::DomainNotFound)?,
            Err(_) => return Err(IommuError::HardwareError),
        };

        // SECURITY: Force-unmap all remaining DMA mappings tracked in the registry.
        // This prevents DMA-after-free and IOTLB inconsistency if some handles were leaked.
        if let Ok(leaked_entries) = domain_arc.force_unmap_all_dma() {
            for entry in leaked_entries {
                // Free the IOVA in the controller context to ensure it can be reused later
                let _ = self.free_iova(entry.iova, entry.size);
            }
        }

        // Invalidate IOTLB for this domain to ensure hardware no longer has cached entries
        if let Err(err) = self.invalidate_iotlb(id, true) {
            log::error!("[IOMMU] Critical: Failed to invalidate IOTLB during domain {} destruction: {:?}", id, err);
            domain_arc.poison();
            return Err(err);
        }

        Ok(())
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

        self.invalidate_context_global_sync()?;
        self.invalidate_iotlb(domain_id, true)?;

        self.device_domains.lock().map_err(|_| IommuError::HardwareError)?.insert(device, domain_id);
        Ok(())
    }

    fn detach_device(&self, device: DeviceId) -> Result<(), IommuError> {
        self.check_and_clear_ats(device);
        let bus = device.bus as usize;
        let devfn = ((device.device as usize) << 3) | (device.function as usize);

        let domain_id = self.device_domains.lock().map_err(|_| IommuError::HardwareError)?.get(&device).copied();
        self.clear_hw_context_entry(bus, devfn, device)?;

        self.invalidate_context_global_sync()?;
        if let Some(did) = domain_id {
            self.invalidate_iotlb(did, true)?;
        }

        self.device_domains.lock().map_err(|_| IommuError::HardwareError)?.remove(&device);
        Ok(())
    }

    fn get_domain_for_device(&self, device: DeviceId) -> Result<Option<u16>, IommuError> {
        Ok(self.device_domains.lock().map_err(|_| IommuError::HardwareError)?.get(&device).copied())
    }

    fn map_dma(&self, device: &DeviceId, iova: u64, phys: u64, size: u64, read: bool, write: bool) -> Result<(), IommuError> {
        crate::io::iommu::runtime::security::validate_dma_region(phys, size)?;
        let (domain_id, domain_arc) = self.resolve_device_domain(device)?;
        domain_arc.map(iova, phys, size, read, write)?;
        self.invalidate_iotlb(domain_id, false)
    }

    fn unmap_dma(&self, device: &DeviceId, iova: u64) -> Result<DmaMapping, IommuError> {
        let (domain_id, domain_arc) = self.resolve_device_domain(device)?;
        let pts_before = domain_arc.pending_pt_release.lock().map(|p| p.len()).unwrap_or(0);
        let mapping = domain_arc.unmap(iova)?;
        let pts_after = domain_arc.pending_pt_release.lock().map(|p| p.len()).unwrap_or(0);
        let pt_removed = pts_after > pts_before;

        if pt_removed {
            // SECURITY: If a page table was removed, we MUST perform a domain-wide
            // invalidation to clear cached paging-structure entries.
            self.invalidate_iotlb(domain_id, true)?;
            let _ = domain_arc.flush(self, self);
        } else {
            self.qi_invalidate_unmap(domain_id, device, iova, mapping.size as u64)?;
        }
        Ok(mapping)
    }

    async fn unmap_dma_async(&self, device: &DeviceId, iova: u64) -> Result<DmaMapping, IommuError> {
        let (domain_id, domain_arc) = self.resolve_device_domain(device)?;
        let pts_before = domain_arc.pending_pt_release.lock().map(|p| p.len()).unwrap_or(0);
        let mapping = domain_arc.unmap(iova)?;
        let pts_after = domain_arc.pending_pt_release.lock().map(|p| p.len()).unwrap_or(0);
        let pt_removed = pts_after > pts_before;

        if pt_removed {
            self.invalidate_iotlb(domain_id, true)?;
            let _ = domain_arc.flush(self, self);
        } else {
            if self.is_queued_invalidation_enabled() {
                self.qi_invalidate_unmap(domain_id, device, iova, mapping.size as u64)?;
                self.qi_wait_async().await?;
            } else {
                unsafe { self.invalidate_iotlb_direct(domain_id) };
            }
        }
        Ok(mapping)
    }

    fn handle_command_queue_entry(&self, kind: &crate::io::iommu::runtime::command::queue::IommuCommandKind) -> Result<i32, ()> {
        use crate::io::iommu::runtime::command::queue::IommuCommandKind;
        match kind {
            IommuCommandKind::MapRegion { domain, iova, phys, size, read, write } => {
                if crate::io::iommu::runtime::security::validate_dma_region(*phys, *size).is_err() { return Err(()); }
                let domain_arc = self.domain(*domain).ok_or(())?;
                domain_arc.map(*iova, *phys, *size, *read, *write).map_err(|_| ())?;
                self.invalidate_iotlb(*domain, false).map_err(|_| ())?;
                Ok(0)
            },
            IommuCommandKind::MapRegionDevice { device, iova, phys, size, read, write } => {
                if crate::io::iommu::runtime::security::validate_dma_region(*phys, *size).is_err() { return Err(()); }
                let (domain_id, domain_arc) = self.resolve_device_domain(device).map_err(|_| ())?;
                domain_arc.map(*iova, *phys, *size, *read, *write).map_err(|_| ())?;
                self.invalidate_iotlb(domain_id, false).map_err(|_| ())?;
                if self.should_invalidate_device_tlb(device) {
                    self.qi_invalidate_device_tlb_all(device.requester_id()).map_err(|_| ())?;
                    self.qi_wait_sync().map_err(|_| ())?;
                }
                Ok(0)
            },
            IommuCommandKind::UnmapRegion { domain, iova, size } => {
                let domain_arc = self.domain(*domain).ok_or(())?;
                let pts_before = domain_arc.pending_pt_release.lock().map(|p| p.len()).unwrap_or(0);
                let mapping = domain_arc.unmap(*iova).map_err(|_| ())?;
                let pts_after = domain_arc.pending_pt_release.lock().map(|p| p.len()).unwrap_or(0);
                let pt_removed = pts_after > pts_before;

                self.invalidate_iotlb(*domain, true).map_err(|_| ())?;
                if pt_removed {
                    let _ = domain_arc.flush(self, self);
                }

                // Free the IOVA to prevent allocator leaks
                if let Err(IommuError::OutOfMemory) = self.free_iova(*iova, mapping.size) {
                    let _ = self.invalidate_iotlb_global_sync();
                    let _ = crate::io::iommu::common::interface::IommuHardwareContext::free_iova_immediate(
                        self, *iova, mapping.size,
                    );
                }
                Ok(0)
            },
            IommuCommandKind::UnmapRegionDevice { device, iova, .. } => {
                let (domain_id, domain_arc) = self.resolve_device_domain(device).map_err(|_| ())?;
                let pts_before = domain_arc.pending_pt_release.lock().map(|p| p.len()).unwrap_or(0);
                let mapping = domain_arc.unmap(*iova).map_err(|_| ())?;
                let pts_after = domain_arc.pending_pt_release.lock().map(|p| p.len()).unwrap_or(0);
                let pt_removed = pts_after > pts_before;

                if pt_removed {
                    self.invalidate_iotlb(domain_id, true).map_err(|_| ())?;
                    let _ = domain_arc.flush(self, self);
                } else {
                    self.qi_invalidate_unmap(domain_id, device, *iova, mapping.size as u64).map_err(|_| ())?;
                }

                // Free the IOVA to prevent allocator leaks
                if let Err(IommuError::OutOfMemory) = self.free_iova(*iova, mapping.size) {
                    let _ = self.invalidate_iotlb_global_sync();
                    let _ = crate::io::iommu::common::interface::IommuHardwareContext::free_iova_immediate(
                        self, *iova, mapping.size,
                    );
                }
                Ok(0)
            },
            IommuCommandKind::InvalidateIotlbDomain { domain } => {
                self.invalidate_iotlb(*domain, true).map(|_| 0).map_err(|_| ())
            },
            IommuCommandKind::InvalidateIotlbGlobal => {
                self.invalidate_iotlb_global_sync().map(|_| 0).map_err(|_| ())
            }
        }
    }
}
