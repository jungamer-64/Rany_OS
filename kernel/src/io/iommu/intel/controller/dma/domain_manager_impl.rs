use super::*;


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

        #[cfg(test)]
        log::info!("[IOMMU TEST] create_domain inserting id = {}", id);

        crate::io::log::early_print("[IOMMU] domain_manager_impl.create_domain: acquired lock, inserting domain\n");
        match self.domains.lock() {
            Ok(mut domains) => {
                #[cfg(test)]
                log::info!("[IOMMU TEST] domains.lock() acquired (Ok)");
                domains.insert(id, domain_arc.clone());
            }
            Err(_) => {
                log::error!("[IOMMU] Domains map poisoned in create_domain - cannot create domain");
                crate::io::log::early_print("[IOMMU] domain_manager_impl.create_domain: lock poisoned\n");
                return Err(IommuError::HardwareError);
            }
        }

        #[cfg(test)]
        log::info!("[IOMMU TEST] create_domain done id = {}", id);
        crate::io::log::early_print("[IOMMU] domain_manager_impl.create_domain: returning Ok\n");
        Ok(id)
    }

    fn set_domain_numa(&self, domain_id: u16, numa_node: Option<usize>) -> Result<(), IommuError> {
        let domain_arc = match self.domains.lock() {
            Ok(domains) => domains
                .get(&domain_id)
                .cloned()
                .ok_or(IommuError::DomainNotFound)?,
            Err(_) => {
                log::error!("[IOMMU] Domains map poisoned in set_domain_numa - cannot set NUMA");
                return Err(IommuError::HardwareError);
            }
        };

        domain_arc.set_numa_node(numa_node);
        Ok(())
    }

    fn get_domain_numa(&self, domain_id: u16) -> Option<usize> {
        match self.domains.lock() {
            Ok(domains) => domains.get(&domain_id).and_then(|d| d.numa_node()),
            Err(_) => {
                log::error!("[IOMMU] Domains map poisoned in get_domain_numa - returning None");
                None
            }
        }
    }

    fn domain(&self, id: u16) -> Option<Arc<IommuDomain>> {
        match self.domains.lock() {
            Ok(domains) => domains.get(&id).cloned(),
            Err(_) => {
                log::error!("[IOMMU] Domains map poisoned (domain) - returning None");
                None
            }
        }
    }

    fn attach_device(&self, device: DeviceId, domain_id: u16) -> Result<(), IommuError> {
        let (domain_type, page_table_addr, bus, devfn) =
            self.resolve_domain_for_attach(domain_id, device)?;

        let mut hw_guard = self
            .hardware
            .lock()
            .map_err(|_| IommuError::HardwareError)?;
        let hw = &mut *hw_guard;

        if self.is_scalable_mode_enabled() {
            self.attach_device_scalable(hw, bus, devfn, domain_type, page_table_addr, domain_id, device)?;
        } else {
            Self::attach_device_legacy(hw, bus, devfn, domain_type, page_table_addr, domain_id)?;
        }

        let mut device_domains = self
            .device_domains
            .lock()
            .map_err(|_| IommuError::HardwareError)?;
        device_domains.insert(device, domain_id);

        Ok(())
    }

    fn detach_device(&self, device: DeviceId) -> Result<(), IommuError> {
        self.check_and_clear_ats(device);

        let bus = device.bus as usize;
        let devfn = ((device.device as usize) << 3) | (device.function as usize);

        let mut device_domains = self
            .device_domains
            .lock()
            .map_err(|_| IommuError::HardwareError)?;
        device_domains.remove(&device);

        self.clear_hw_context_entry(bus, devfn, device)
    }

    fn get_domain_for_device(&self, device: DeviceId) -> Result<Option<u16>, IommuError> {
        let domain_id = match self.device_domains.lock() {
            Ok(guard) => guard.get(&device).copied(),
            Err(_) => {
                log::error!(
                    "[IOMMU] device_domains lock poisoned (get_domain_for_device) - returning None"
                );
                return Err(IommuError::HardwareError);
            }
        };
        Ok(domain_id)
    }

    fn map_dma(
        &self,
        device: &DeviceId,
        iova: u64,
        phys: u64,
        size: u64,
        read: bool,
        write: bool,
    ) -> Result<(), IommuError> {
        let domain_id = {
            let guard = self
                .device_domains
                .lock()
                .map_err(|_| IommuError::HardwareError)?;
            guard
                .get(device)
                .copied()
                .ok_or(IommuError::DeviceNotFound)?
        };

        let domain_arc = {
            let domains_guard = self.domains.lock().map_err(|_| IommuError::HardwareError)?;
            domains_guard
                .get(&domain_id)
                .cloned()
                .ok_or(IommuError::DomainNotFound)?
        };
        domain_arc.map(iova, phys, size, read, write)
    }

    fn unmap_dma(&self, device: &DeviceId, iova: u64) -> Result<DmaMapping, IommuError> {
        let (domain_id, domain_arc) = self.resolve_device_domain(device)?;
        domain_arc.unmap(iova).map(|mapping| {
            self.invalidate_iotlb_for_sync_unmap(domain_id, iova, mapping.size as usize);
            self.invalidate_device_tlb_for_sync_unmap(device, domain_id, iova, mapping.size as usize);
            mapping
        })
    }

    async fn unmap_dma_async(
        &self,
        device: &DeviceId,
        iova: u64,
    ) -> Result<DmaMapping, IommuError> {
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

    fn handle_command_queue_entry(
        &self,
        kind: &crate::io::iommu::cmdqueue::IommuCommandKind,
    ) -> Result<i32, ()> {
        use crate::io::iommu::cmdqueue::IommuCommandKind;
        use crate::io::iommu::intel::controller::qi_ops::InvalidationOps;

        crate::io::log::early_print("[DMA] handle_command_queue_entry called\n");
        let res = match kind {
            IommuCommandKind::MapRegion {
                domain,
                iova,
                phys,
                size,
                read,
                write,
            } => {
                crate::io::log::early_print("[DMA] handle_command_queue_entry: about to lock domains\n");
                match self.domains.lock() {
                Ok(dom_map) => {
                    crate::io::log::early_print("[DMA] handle_command_queue_entry: locked domains\n");
                    let domain_arc = dom_map.get(domain).cloned();
                    drop(dom_map);
                    crate::io::log::early_print("[DMA] handle_command_queue_entry: dropped domains lock\n");
                    if let Some(domain_arc) = domain_arc {
                        crate::io::log::early_print("[DMA] handle_command_queue_entry: about to call domain.map()\n");
                        match domain_arc.map(*iova, *phys, *size, *read, *write) {
                            Ok(_) => {
                                crate::io::log::early_print("[DMA] handle_command_queue_entry: domain.map() OK, calling invalidate\n");
                                self.invalidate_iotlb(*domain);
                                crate::io::log::early_print("[DMA] handle_command_queue_entry: invalidate OK\n");
                                Ok(0)
                            }
                            Err(_) => {
                                crate::io::log::early_print("[DMA] handle_command_queue_entry: domain.map() FAILED\n");
                                Err(())
                            }
                        }
                    } else {
                        crate::io::log::early_print("[DMA] handle_command_queue_entry MapRegion No Domain\n");
                        Err(())
                    }
                }
                Err(_) => {
                    crate::io::log::early_print("[DMA] handle_command_queue_entry MapRegion Domain lock poisoned\n");
                    Err(())
                }
            }},
            IommuCommandKind::MapRegionDevice { .. } => Err(()),
            IommuCommandKind::UnmapRegion {
                domain,
                iova,
                size: _,
            } => match self.domains.lock() {
                Ok(dom_map) => {
                    let domain_arc = dom_map.get(domain).cloned();
                    drop(dom_map);
                    if let Some(domain_arc) = domain_arc {
                        match domain_arc.unmap(*iova) {
                            Ok(_) => {
                                self.invalidate_iotlb(*domain);
                                Ok(0)
                            }
                            Err(_) => Err(()),
                        }
                    } else {
                        Err(())
                    }
                }
                Err(_) => Err(()),
            },
            IommuCommandKind::UnmapRegionDevice { .. } => Err(()),
            IommuCommandKind::InvalidateIotlbDomain { domain } => {
                self.invalidate_iotlb(*domain);
                Ok(0)
            }
            IommuCommandKind::InvalidateIotlbGlobal => {
                let _ = self.invalidate_iotlb_global_sync();
                Ok(0)
            }
        };

        if self.is_queued_invalidation_enabled() {
            let _ = self.qi_wait_sync();
        }
        res
    }
}
