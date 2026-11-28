// ============================================================================
// kernel/src/io/iommu/vendors/intel/controller/dma/domain_manager_impl.rs
// ============================================================================

use super::*;
use crate::io::iommu::common::domain::IommuDomain;
use crate::io::iommu::vendors::intel::controller::init::CapabilityManager;

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
        // CAP.CM reserves DID 0 for cache entries that produce faults.
        let first = u64::from(self.cap & (1 << 7) != 0);
        let count = max_ids as u64 - first;
        let mut offset = self.next_domain_id.load(Ordering::Relaxed) % count;
        let mut id = (first + offset) as u16;
        let mut found = false;
        for _ in 0..count {
            if !domains.contains_key(&id) {
                found = true;
                break;
            }
            offset = (offset + 1) % count;
            id = (first + offset) as u16;
        }

        if !found {
            log::error!("[IOMMU] Out of Domain IDs (max {})", max_ids);
            return Err(IommuError::OutOfMemory);
        }
        self.next_domain_id
            .store((offset + 1) % count, Ordering::Relaxed);

        let supports_2mb = self.supports_2mb_pages();
        let supports_1gb = self.supports_1gb_pages();
        let max_addr_bits = self.selected_addr_bits();
        let pt_levels = self.selected_levels();

        let domain = IommuDomain::try_new(
            id,
            numa_node,
            supports_2mb,
            supports_1gb,
            max_addr_bits,
            pt_levels,
            domain_type,
            self.page_table_pool.clone(),
            PteFormat::Intel,
        )?;
        let domain_arc = Arc::new(domain);

        domains.insert(id, domain_arc.clone());
        Ok(id)
    }

    fn set_domain_numa(&self, domain_id: u16, numa_node: Option<usize>) -> Result<(), IommuError> {
        let domain_arc = match self.domains.lock() {
            Ok(domains) => domains
                .get(&domain_id)
                .cloned()
                .ok_or(IommuError::DomainNotFound)?,
            Err(_) => return Err(IommuError::HardwareError),
        };
        domain_arc.set_numa_node(numa_node);
        Ok(())
    }

    fn domain(&self, id: u16) -> Option<Arc<IommuDomain>> {
        match self.domains.lock() {
            Ok(domains) => domains.get(&id).cloned(),
            Err(_) => None,
        }
    }

    fn destroy_domain(&self, id: u16) -> Result<(), IommuError> {
        let mut domains = self.domains.lock().map_err(|_| IommuError::Poisoned)?;
        let domain = domains.get(&id).ok_or(IommuError::DomainNotFound)?;
        if Arc::strong_count(domain) != 1 || domain.active_dma_count() != 0 {
            return Err(IommuError::InUse);
        }

        // Failure retains the registry's owner and every retirement cohort for
        // retry. Mapping owners retain their backend's IOVA allocation through
        // completion and keep this domain busy until they return it.
        crate::io::iommu::common::domain::IommuInvalidator::invalidate(
            self,
            crate::io::iommu::common::domain::InvalidateRequest::domain(id).with_ats(),
        )?;
        let owner = domains.remove(&id).ok_or(IommuError::DomainNotFound)?;
        let domain = match Arc::try_unwrap(owner) {
            Ok(domain) => domain,
            Err(owner) => {
                domains.insert(id, owner);
                return Err(IommuError::InUse);
            }
        };
        drop(domains);
        // SAFETY: admission was excluded, all attached contexts were removed
        // with ATS closure, and domain paging-structure invalidation completed.
        unsafe { domain.retire_after_invalidation() };
        Ok(())
    }

    fn attach_device(&self, device: DeviceId, domain_id: u16) -> Result<(), IommuError> {
        if device.segment != self.segment || device.device >= 32 || device.function >= 8 {
            return Err(IommuError::InvalidAddress);
        }
        let (domain, bus, devfn) = self.resolve_domain_for_attach(domain_id, device)?;
        let mut bindings = self
            .device_bindings
            .lock()
            .map_err(|_| IommuError::Poisoned)?;
        match bindings.get(&device) {
            Some(DeviceBinding::Attached(context)) if context.domain.id() == domain_id => {
                return Ok(());
            }
            Some(DeviceBinding::Publishing(context)) if context.domain.id() == domain_id => {}
            Some(_) => return Err(IommuError::AlreadyMapped),
            None => {
                map_rmrr_for_device(&domain, device)?;
                bindings
                    .try_reserve(1)
                    .map_err(|_| IommuError::MetadataAllocation)?;
                let mut hardware = self.hardware.lock().map_err(|_| IommuError::Poisoned)?;
                let pasid = self
                    .is_scalable_mode_enabled()
                    .then(|| self.prepare_pasid(&domain))
                    .transpose()?;
                let context = PublishedContext::new(domain, pasid);
                bindings.insert(device, DeviceBinding::Publishing(context));
                let Some(DeviceBinding::Publishing(context)) = bindings.get(&device) else {
                    unreachable!("freshly admitted context");
                };
                if let Err(error) = self.publish_context(&mut hardware, bus, devfn, context) {
                    if let Some(DeviceBinding::Publishing(context)) = bindings.remove(&device) {
                        // SAFETY: publication validates every table before writing a context.
                        unsafe { context.retire() };
                    }
                    return Err(error);
                }
            }
        }

        let flush_domain = (self.cap & (1 << 7) == 0).then_some(domain_id);
        self.invalidate_context_translations(flush_domain)?;
        let Some(DeviceBinding::Publishing(context)) = bindings.remove(&device) else {
            unreachable!("the binding lock protects publication");
        };
        bindings.insert(device, DeviceBinding::Attached(context));
        Ok(())
    }

    fn detach_device(&self, device: DeviceId) -> Result<(), IommuError> {
        self.revoke_device_context(device, ContextRevocation::Detach)
    }

    fn get_domain_for_device(&self, device: DeviceId) -> Result<Option<u16>, IommuError> {
        let bindings = self
            .device_bindings
            .lock()
            .map_err(|_| IommuError::Poisoned)?;
        Ok(bindings.get(&device).and_then(DeviceBinding::domain_id))
    }

    fn handle_command_queue_entry(
        &self,
        kind: &crate::io::iommu::runtime::command::queue::IommuCommandKind,
    ) -> Result<i32, ()> {
        use crate::io::iommu::runtime::command::queue::IommuCommandKind;
        match kind {
            IommuCommandKind::InvalidateIotlbDomain { domain } => self
                .invalidate_iotlb(*domain, true)
                .map(|_| 0)
                .map_err(|_| ()),
            IommuCommandKind::InvalidateIotlbGlobal => self
                .invalidate_iotlb_global_sync()
                .map(|_| 0)
                .map_err(|_| ()),
        }
    }
}
